from __future__ import annotations

import pickle

from langgraph_lens import Lens


def test_unsafe_pickle_opcode_critical(lens: Lens) -> None:
    class Evil:
        def __reduce__(self):  # noqa: D401, ANN001
            return (print, ("pwn",))

    blob = pickle.dumps(Evil())
    event = lens.inspect_checkpoint(
        blob=blob, thread_id="t", checkpoint_id="c", direction="write"
    )
    rules = [(d.detector, d.rule, d.severity.value) for d in event.detections]
    assert any(
        d == ("checkpoint", "unsafe_pickle_opcode", "critical") for d in rules
    )


def test_clean_json_blob_no_detection(lens: Lens) -> None:
    blob = b'{"v": 1, "ts": "2026-05-25T00:00:00Z", "channel_values": {}}'
    event = lens.inspect_checkpoint(
        blob=blob, thread_id="t", checkpoint_id="c", direction="write"
    )
    assert not any(
        d.detector == "checkpoint" and d.severity.value in ("high", "critical")
        for d in event.detections
    )


def test_missing_thread_id_flagged(lens: Lens) -> None:
    blob = b'{"v": 1, "ts": "x", "channel_values": {}}'
    event = lens.inspect_checkpoint(blob=blob, direction="write")
    assert any(
        d.detector == "checkpoint" and d.rule == "missing_thread_id"
        for d in event.detections
    )


def test_schema_drift_on_decoded_dict(lens: Lens) -> None:
    event = lens.inspect_checkpoint(
        blob={"only": "a_random_key"},
        thread_id="t",
        direction="write",
    )
    assert any(
        d.detector == "checkpoint" and d.rule == "schema_drift"
        for d in event.detections
    )
