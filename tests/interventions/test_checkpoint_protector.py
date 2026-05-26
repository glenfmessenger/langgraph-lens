from __future__ import annotations

import pickle

from langgraph_lens import Lens, LensConfig


def _lens(*, mode: str = "enforce", require_hmac: bool = False, key: str = "k") -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    cfg.tier2.checkpoint_protector.enabled = True
    cfg.tier2.checkpoint_protector.mode = mode  # type: ignore[assignment]
    cfg.tier2.checkpoint_protector.require_hmac = require_hmac
    cfg.tier2.checkpoint_protector.signing_key = key
    return Lens(cfg)


def test_pickle_opcode_blocked() -> None:
    class Evil:
        def __reduce__(self):  # noqa: D401, ANN001
            return (print, ("pwn",))

    lens = _lens()
    decision, _ = lens.decide_checkpoint(
        blob=pickle.dumps(Evil()),
        metadata={},
        thread_id="t",
        checkpoint_id="c",
        direction="read",
    )
    assert decision.action == "block"
    assert decision.status_code == 503
    assert "checkpoint_protector.unsafe_pickle_opcode" in decision.triggered_by


def test_log_mode_passes_through() -> None:
    class Evil:
        def __reduce__(self):  # noqa: D401, ANN001
            return (print, ("pwn",))

    lens = _lens(mode="log")
    decision, _ = lens.decide_checkpoint(
        blob=pickle.dumps(Evil()),
        metadata={},
        thread_id="t",
        checkpoint_id="c",
        direction="read",
    )
    assert decision.action == "allow"
    assert "checkpoint_protector.unsafe_pickle_opcode" in decision.triggered_by


def test_clean_blob_no_block() -> None:
    lens = _lens()
    decision, _ = lens.decide_checkpoint(
        blob=b'{"v": 1, "ts": "2026-05-25T00:00:00Z", "channel_values": {}}',
        metadata={},
        thread_id="t",
        checkpoint_id="c",
        direction="read",
    )
    assert decision.action == "allow"


def test_hmac_signing_roundtrip() -> None:
    lens = _lens(require_hmac=True, key="secret")
    blob = b'{"v": 1, "ts": "2026-05-25T00:00:00Z", "channel_values": {}}'
    sig = lens.checkpoint_protector.sign(blob)
    assert isinstance(sig, str) and sig

    # Correct HMAC -> allow.
    decision, _ = lens.decide_checkpoint(
        blob=blob,
        metadata={"lens_hmac": sig},
        thread_id="t",
        checkpoint_id="c",
        direction="read",
    )
    assert decision.action == "allow"

    # Mismatched HMAC -> block.
    decision2, _ = lens.decide_checkpoint(
        blob=blob,
        metadata={"lens_hmac": "deadbeef"},
        thread_id="t",
        checkpoint_id="c",
        direction="read",
    )
    assert decision2.action == "block"
    assert "checkpoint_protector.hmac_mismatch" in decision2.triggered_by


def test_hmac_skipped_on_write() -> None:
    lens = _lens(require_hmac=True, key="secret")
    blob = b'{"v": 1, "ts": "x", "channel_values": {}}'
    # On write, no HMAC is expected on the incoming metadata.
    decision, _ = lens.decide_checkpoint(
        blob=blob, metadata={}, thread_id="t", direction="write"
    )
    assert decision.action == "allow"
