"""Checkpoint integrity protection.

Two responsibilities:

  1. **Refuse-on-load** — when a checkpoint blob about to be deserialised
     contains unsafe pickle opcodes or an unknown serializer kind, raise
     a terminal decision instead of allowing the saver to call
     `pickle.loads()`. This is the direct mitigation for CVE-2026-27794
     / 4181.
  2. **HMAC signing** — on write, attach a SHA-256 HMAC of the blob
     under `metadata["lens_hmac"]`. On read, verify the HMAC against the
     configured `signing_key` and reject blobs that don't match.

Mode:
  - `enforce` (default) — block on any failure.
  - `log`              — emit a triggered_by entry but pass through.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from ..config import CheckpointProtectorConfig
from ..detectors.checkpoint import CheckpointDetector
from ..events import Detection
from .decisions import LensDecision

_HMAC_KEY = "lens_hmac"


class CheckpointProtectorIntervention:
    def __init__(
        self,
        config: CheckpointProtectorConfig,
        *,
        t1_detector: CheckpointDetector,
    ) -> None:
        self.config = config
        self._t1 = t1_detector

    def evaluate(
        self,
        *,
        blob: bytes | dict[str, Any],
        metadata: dict[str, Any] | None,
        direction: str,
        thread_id: str | None = None,
    ) -> tuple[LensDecision, list[Detection]]:
        if not self.config.enabled:
            return LensDecision(), []

        triggered: list[str] = []
        detections: list[Detection] = []
        metadata = metadata or {}

        # Re-use the Tier 1 detector — only the *critical* opcode rule is
        # treated as a block signal by default; lower-severity findings
        # remain Tier 1 observations.
        t1 = self._t1.scan(blob=blob, metadata=metadata, thread_id=thread_id)
        for d in t1:
            if d.rule in self.config.block_on_rules:
                triggered.append(f"checkpoint_protector.{d.rule}")
                detections.append(d)

        # HMAC verification on read.
        if (
            self.config.require_hmac
            and direction == "read"
            and isinstance(blob, (bytes, bytearray))
        ):
            expected = metadata.get(_HMAC_KEY)
            if not isinstance(expected, str) or not _verify_hmac(
                bytes(blob), expected, self.config.signing_key
            ):
                triggered.append("checkpoint_protector.hmac_mismatch")

        if not triggered:
            return LensDecision(), []

        if self.config.mode == "log":
            return LensDecision(triggered_by=triggered), detections

        return (
            LensDecision(
                action="block",
                reason="checkpoint_rejected",
                triggered_by=triggered,
                status_code=503,
            ),
            detections,
        )

    def sign(self, blob: bytes) -> str | None:
        """Return the HMAC to attach to `metadata[lens_hmac]` for this blob.

        Returns None if `require_hmac` is off — callers should not stamp
        an empty HMAC.
        """
        if not self.config.enabled or not self.config.require_hmac:
            return None
        return _compute_hmac(blob, self.config.signing_key)


def _compute_hmac(blob: bytes, key: str) -> str:
    return hmac.new(key.encode("utf-8"), blob, hashlib.sha256).hexdigest()


def _verify_hmac(blob: bytes, expected: str, key: str) -> bool:
    return hmac.compare_digest(_compute_hmac(blob, key), expected)
