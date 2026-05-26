"""Checkpoint anomaly detector.

Runs on every checkpoint write and read. The most important signals here
relate to **CVE-2026-27794 / 28277**: pickle-fallback deserialisation in
`JsonPlusSerializer` when an attacker controls a previously-stored
checkpoint blob. The detector flags unsafe pickle opcodes structurally —
it does **not** load the pickle, only inspects the byte stream.
"""

from __future__ import annotations

from typing import Any

from ..config import CheckpointConfig
from ..events import Detection, Severity

# Pickle opcodes that, taken together, are sufficient to execute arbitrary
# Python on deserialisation. Documented in PEP 3154 and CPython's pickle
# module. We flag presence — not all uses are malicious, but in a
# LangGraph checkpoint they should be the rare exception.
_DANGEROUS_OPCODES: dict[bytes, str] = {
    b"R": "REDUCE",
    b"c": "GLOBAL",
    b"\x93": "STACK_GLOBAL",
    b"b": "BUILD",
    b"i": "INST",
    b"o": "OBJ",
}

# Serializer kind markers we expect to see at the start of a JsonPlus blob.
# Anything else is "unknown" until added to this list.
_KNOWN_SERIALIZER_KINDS = {
    "json",
    "msgpack",
    "json+",
    "json_plus",
    "JsonPlusSerializer",
    "EncryptedSerializer",
}


class CheckpointDetector:
    def __init__(self, config: CheckpointConfig) -> None:
        self.config = config

    def scan(
        self,
        *,
        blob: bytes | dict[str, Any],
        metadata: dict[str, Any] | None = None,
        thread_id: str | None = None,
    ) -> list[Detection]:
        if not self.config.enabled:
            return []
        out: list[Detection] = []
        rules = set(self.config.rules)
        metadata = metadata or {}

        if "missing_thread_id" in rules and not thread_id:
            out.append(
                Detection(
                    detector="checkpoint",
                    rule="missing_thread_id",
                    severity=Severity.MEDIUM,
                    extra={
                        "advisory": "Checkpoint emitted without thread_id — cannot tie back to a user-facing run.",
                    },
                )
            )

        # Byte-level scans run only on raw bytes (most production saver
        # paths). When the caller already has a decoded dict, those rules
        # don't apply.
        if isinstance(blob, (bytes, bytearray, memoryview)):
            raw = bytes(blob)

            if "oversized_blob" in rules and len(raw) > self.config.max_blob_bytes:
                out.append(
                    Detection(
                        detector="checkpoint",
                        rule="oversized_blob",
                        severity=Severity.MEDIUM,
                        extra={
                            "bytes": len(raw),
                            "max_bytes": self.config.max_blob_bytes,
                        },
                    )
                )

            if "unsafe_pickle_opcode" in rules and _looks_like_pickle(raw):
                hits: list[str] = []
                for opcode, name in _DANGEROUS_OPCODES.items():
                    if opcode in raw:
                        hits.append(name)
                if hits:
                    out.append(
                        Detection(
                            detector="checkpoint",
                            rule="unsafe_pickle_opcode",
                            severity=Severity.CRITICAL,
                            extra={
                                "opcodes": sorted(set(hits)),
                                "advisory": "Pickle opcodes that can execute arbitrary code on deserialisation. CVE-2026-27794/28277.",
                            },
                        )
                    )

            if "unknown_serializer_kind" in rules:
                kind = _peek_serializer_kind(raw)
                if kind is not None and kind not in _KNOWN_SERIALIZER_KINDS:
                    out.append(
                        Detection(
                            detector="checkpoint",
                            rule="unknown_serializer_kind",
                            severity=Severity.MEDIUM,
                            extra={"kind": kind},
                        )
                    )

        if "schema_drift" in rules and isinstance(blob, dict):
            # Heuristic — modern LangGraph checkpoints always carry these.
            expected = {"v", "ts", "channel_values"}
            present = set(blob.keys())
            if not expected.issubset(present):
                out.append(
                    Detection(
                        detector="checkpoint",
                        rule="schema_drift",
                        severity=Severity.LOW,
                        extra={
                            "missing": sorted(expected - present),
                            "present": sorted(present),
                        },
                    )
                )

        return out


def _looks_like_pickle(raw: bytes) -> bool:
    """Cheap structural check: does this blob look like a pickle stream?

    Modern pickle streams start with the PROTO opcode (`\\x80`) followed by
    a single byte for the protocol version (0..5) and end with the STOP
    opcode (`.`). Plain JSON and msgpack blobs don't match either marker,
    so we can scan them for opcodes without lighting up the dangerous-
    opcode rule on every legitimate string.
    """
    if not raw:
        return False
    if raw[0:1] == b"\x80" and len(raw) > 2 and raw[1] in (0, 1, 2, 3, 4, 5):
        return True
    # Legacy text-mode pickle starts with one of these opcodes at the
    # very first byte. JSON / msgpack don't.
    return raw[0:1] in (b"(", b"]", b"d", b"}")


def _peek_serializer_kind(raw: bytes) -> str | None:
    """Cheap structural peek at the first few bytes of a checkpoint blob.

    Recognises the canonical JsonPlus framing — a length-prefixed kind
    string. Returns None if the blob doesn't match the expected shape;
    that's fine, the unsafe-pickle-opcode rule will catch the dangerous
    cases separately.
    """
    head = raw[:64]
    # JSON or msgpack — both safe markers, treated as known.
    if head.startswith(b"{") or head.startswith(b"\x82") or head.startswith(b"\x83"):
        return "json" if head.startswith(b"{") else "msgpack"
    # JsonPlus often emits `kind:json|<payload>` framing.
    if b"|" in head:
        first = head.split(b"|", 1)[0]
        if first.startswith(b"kind:"):
            return first[5:].decode("ascii", errors="replace")
    return None
