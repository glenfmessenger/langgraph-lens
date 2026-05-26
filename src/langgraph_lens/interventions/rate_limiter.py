"""Token-bucket rate limiter for tool calls.

Bucket key is `(tenant|thread|tool)` with each component optional via
the YAML. A call that finds an empty bucket either:

  - returns a `throttle` decision with `retry_after` set to the time
    until the bucket refills enough for the requested cost (mode:
    `throttle`), or
  - returns a terminal `block` with HTTP 429 (mode: `block`).

The cost of a call defaults to 1 token; if the tool args serialise to a
string longer than `size_divisor`, an extra token is charged per
`size_divisor` characters.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from ..config import RateLimitConfig
from ..events import Detection, Severity
from .decisions import LensDecision


@dataclass(slots=True)
class _Bucket:
    tokens: float
    last_refill: float


class RateLimiterIntervention:
    def __init__(self, config: RateLimitConfig) -> None:
        self.config = config
        self._buckets: dict[str, _Bucket] = {}

    def evaluate(
        self,
        *,
        tool: str,
        args: dict[str, Any] | str,
        thread_id: str | None = None,
        tenant: str | None = None,
    ) -> tuple[LensDecision, list[Detection]]:
        if not self.config.enabled:
            return LensDecision(), []

        key = self._make_key(tool=tool, thread_id=thread_id, tenant=tenant)
        cost = self._cost(args)
        now = time.time()

        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=float(self.config.capacity), last_refill=now)
            self._buckets[key] = bucket
        else:
            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                float(self.config.capacity),
                bucket.tokens + elapsed * self.config.refill_per_second,
            )
            bucket.last_refill = now

        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return LensDecision(), []

        shortfall = cost - bucket.tokens
        retry_after = shortfall / max(self.config.refill_per_second, 1e-9)

        det = Detection(
            detector="rate_limit",
            rule="bucket_empty",
            severity=Severity.MEDIUM,
            extra={"key": key, "cost": cost, "retry_after": retry_after},
        )

        if self.config.mode == "block":
            return (
                LensDecision(
                    action="block",
                    reason="rate_limited",
                    triggered_by=["rate_limit.bucket_empty"],
                    status_code=429,
                    retry_after=retry_after,
                ),
                [det],
            )

        return (
            LensDecision(
                action="throttle",
                reason="rate_limited",
                triggered_by=["rate_limit.bucket_empty"],
                retry_after=retry_after,
            ),
            [det],
        )

    def _make_key(self, *, tool: str, thread_id: str | None, tenant: str | None) -> str:
        parts: list[str] = []
        if self.config.key_by_tenant and tenant:
            parts.append(f"t={tenant}")
        if self.config.key_by_thread and thread_id:
            parts.append(f"th={thread_id}")
        if self.config.key_by_tool:
            parts.append(f"tl={tool}")
        return "|".join(parts) or "global"

    def _cost(self, args: dict[str, Any] | str) -> float:
        text = args if isinstance(args, str) else _safe_json(args)
        extra = len(text) // max(self.config.size_divisor, 1)
        return 1.0 + float(extra)


def _safe_json(x: Any) -> str:
    try:
        return json.dumps(x, default=str)
    except (TypeError, ValueError):
        return repr(x)
