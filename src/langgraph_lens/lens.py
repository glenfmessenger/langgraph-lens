"""Top-level orchestrator.

`Lens` owns the detectors, the event sink, the alert sender, and the
metrics. Both the global `LANGGRAPH_LENS=1` callback handler and any
per-graph `LensCallback(lens)` delegate to the same instance.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .alerts import AlertSender
from .config import LensConfig
from .detectors import (
    AttackSurfaceDetector,
    CheckpointDetector,
    CommsDetector,
    GoalHijackDetector,
    MemoryDetector,
    PIIDetector,
    SQLInjectionDetector,
    SupplyChainDetector,
    ToolDetector,
)
from .detectors.attack_surface import RuntimeInfo
from .events import (
    Detection,
    Event,
    EventKind,
    hash_state,
    new_correlation_id,
    write_event,
)
from .interventions import (
    AuditSignalingIntervention,
    CheckpointProtectorIntervention,
    CircuitBreakerIntervention,
    GoalGuardIntervention,
    LensDecision,
    PIIRedactorIntervention,
    RateLimiterIntervention,
    ToolAllowlistIntervention,
)
from .metrics import (
    CHECKPOINTS_INSPECTED,
    CIRCUIT_STATE,
    INSPECTION_DURATION,
    NODES_INSPECTED,
    TIER2_BLOCKED,
    TIER2_REDACTED,
    TIER2_THROTTLED,
    maybe_start_server,
    record_detection,
)
from .otel import OtelBridge

_MAX_EVENTS_PER_THREAD = 256


class Lens:
    """Top-level orchestrator. Thread-safe at the level of CPython's GIL
    for the operations exercised by LangGraph's synchronous callback
    handler — concurrent invocations of `inspect_node` from different
    threads will not corrupt state, but per-thread event buffers may
    interleave on Python implementations without atomic dict ops.
    """

    def __init__(self, config: LensConfig | None = None) -> None:
        self.config = config or LensConfig.default()

        self.pii = PIIDetector(self.config.pii)
        self.checkpoint = CheckpointDetector(self.config.checkpoint)
        self.supply_chain = SupplyChainDetector(self.config.supply_chain)
        self.tool = ToolDetector(self.config.tool)
        self.memory = MemoryDetector(self.config.memory)
        self.goal_hijack = GoalHijackDetector(self.config.goal_hijack)
        self.comms = CommsDetector(self.config.comms)
        self.sql_injection = SQLInjectionDetector(self.config.sql_injection)
        self.attack_surface = AttackSurfaceDetector(self.config.attack_surface)
        self.alerts = AlertSender(self.config.alerts)
        self.otel = OtelBridge(self.config.otel)

        # Tier 2 interventions. Each one is a no-op until its config
        # block has `enabled: true`.
        t2 = self.config.tier2
        self.pii_redactor = PIIRedactorIntervention(t2.pii_redaction)
        self.tool_allowlist = ToolAllowlistIntervention(
            t2.tool_allowlist, t1_detector=self.tool
        )
        self.checkpoint_protector = CheckpointProtectorIntervention(
            t2.checkpoint_protector, t1_detector=self.checkpoint
        )
        self.goal_guard = GoalGuardIntervention(
            t2.goal_guard, t1_detector=self.goal_hijack
        )
        self.rate_limiter = RateLimiterIntervention(t2.rate_limit)
        self.circuit_breaker = CircuitBreakerIntervention(t2.circuit_breaker)
        self.audit = AuditSignalingIntervention(t2.audit_signaling)

        # Correlation IDs are stable per (run_id, thread_id) pair so that
        # every event from one invocation joins on a single id.
        self._correlation_pairs: dict[tuple[str | None, str | None], str] = {}
        # Per-thread ring buffer of recent events, for `events_for_thread`.
        self._thread_events: dict[str, deque[Event]] = defaultdict(
            lambda: deque(maxlen=_MAX_EVENTS_PER_THREAD)
        )
        # Per-thread originating user intent, used by the goal-hijack detector.
        self._thread_user_intent: dict[str, str] = {}
        # Per-thread initial state size, used by the comms detector.
        self._thread_initial_state_size: dict[str, int] = {}

        if self.config.prometheus.enabled:
            maybe_start_server(self.config.prometheus.port)

    # -- node inspection ---------------------------------------------------

    def inspect_node(
        self,
        *,
        node: str,
        state: dict[str, Any],
        run_id: str | None = None,
        thread_id: str | None = None,
        declared_edges: list[tuple[str, str]] | None = None,
        declared_tools: list[str] | None = None,
        recursion_limit: int | None = None,
        recursion_depth: int | None = None,
    ) -> Event:
        start = time.perf_counter()
        correlation_id = self._correlation_for(run_id, thread_id)
        detections: list[Detection] = []

        # Capture originating user intent on first node, for goal-hijack.
        if thread_id and thread_id not in self._thread_user_intent:
            intent = _extract_user_intent(state)
            if intent:
                self._thread_user_intent[thread_id] = intent
        if thread_id and thread_id not in self._thread_initial_state_size:
            self._thread_initial_state_size[thread_id] = _state_size(state)

        # PII at node ingress.
        if self.config.pii.scan_ingress:
            text = _stringify_state(state)
            if text:
                detections.extend(self.pii.scan(text, direction="ingress"))

        # Goal-hijack — compare current state to originating intent.
        if thread_id:
            detections.extend(
                self.goal_hijack.scan(
                    state=state,
                    originating_intent=self._thread_user_intent.get(thread_id),
                )
            )

        # Graph-communication anomalies.
        detections.extend(
            self.comms.scan(
                node=node,
                state=state,
                declared_edges=declared_edges,
                recursion_limit=recursion_limit,
                recursion_depth=recursion_depth,
                initial_state_size=self._thread_initial_state_size.get(thread_id or ""),
                thread_id=thread_id,
            )
        )

        event = Event(
            event=EventKind.NODE_INSPECTED,
            correlation_id=correlation_id,
            run_id=run_id,
            thread_id=thread_id,
            node=node,
            state_hash=hash_state(state),
            detections=detections,
        )

        INSPECTION_DURATION.labels(stage="node_ingress").observe(time.perf_counter() - start)
        NODES_INSPECTED.inc()
        self._emit(event)
        return event

    # -- checkpoint inspection --------------------------------------------

    def inspect_checkpoint(
        self,
        *,
        blob: bytes | dict[str, Any],
        metadata: dict[str, Any] | None = None,
        run_id: str | None = None,
        thread_id: str | None = None,
        checkpoint_id: str | None = None,
        direction: str = "write",
    ) -> Event:
        """Inspect a checkpoint at write or read time.

        `blob` can be the raw serialised bytes (preferred — catches unsafe
        pickle opcodes) or the already-decoded dict. `direction` is
        "write" or "read" and gates which rules fire.
        """
        start = time.perf_counter()
        correlation_id = self._correlation_for(run_id, thread_id)

        if direction == "write" and not self.config.checkpoint.scan_on_write:
            CHECKPOINTS_INSPECTED.inc()
            return Event(
                event=EventKind.CHECKPOINT_INSPECTED,
                correlation_id=correlation_id,
                run_id=run_id,
                thread_id=thread_id,
                checkpoint_id=checkpoint_id,
            )
        if direction == "read" and not self.config.checkpoint.scan_on_read:
            CHECKPOINTS_INSPECTED.inc()
            return Event(
                event=EventKind.CHECKPOINT_INSPECTED,
                correlation_id=correlation_id,
                run_id=run_id,
                thread_id=thread_id,
                checkpoint_id=checkpoint_id,
            )

        detections: list[Detection] = list(
            self.checkpoint.scan(blob=blob, metadata=metadata, thread_id=thread_id)
        )

        # PII inside checkpoint contents.
        if self.config.pii.scan_checkpoints:
            text = _stringify_state(blob if isinstance(blob, dict) else {})
            if text:
                detections.extend(self.pii.scan(text, direction="checkpoint"))

        # SQL injection in checkpoint metadata.
        for field_name in self.config.sql_injection.fields:
            value = (metadata or {}).get(field_name)
            if isinstance(value, str):
                detections.extend(self.sql_injection.scan(field=field_name, value=value))

        event = Event(
            event=EventKind.CHECKPOINT_INSPECTED,
            correlation_id=correlation_id,
            run_id=run_id,
            thread_id=thread_id,
            checkpoint_id=checkpoint_id,
            detections=detections,
        )

        INSPECTION_DURATION.labels(stage="checkpoint").observe(time.perf_counter() - start)
        CHECKPOINTS_INSPECTED.inc()
        self._emit(event)
        return event

    # -- tool calls --------------------------------------------------------

    def inspect_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, Any] | str,
        run_id: str | None = None,
        thread_id: str | None = None,
        allowed_tools: list[str] | None = None,
    ) -> Event:
        start = time.perf_counter()
        correlation_id = self._correlation_for(run_id, thread_id)

        detections = list(
            self.tool.scan(
                tool=tool,
                args=args,
                allowed_tools=allowed_tools,
                thread_id=thread_id,
            )
        )
        event = Event(
            event=EventKind.TOOL_CALL_INSPECTED,
            correlation_id=correlation_id,
            run_id=run_id,
            thread_id=thread_id,
            detections=detections,
        )
        # Stash tool name on the event extras of the first detection so it
        # shows up in logs; keep the top-level Event schema stable.
        for d in detections:
            d.extra.setdefault("tool", tool)

        INSPECTION_DURATION.labels(stage="tool").observe(time.perf_counter() - start)
        self._emit(event)
        return event

    # -- memory writes -----------------------------------------------------

    def inspect_memory_write(
        self,
        *,
        key: str,
        value: Any,
        owner: str | None = None,
        run_id: str | None = None,
        thread_id: str | None = None,
    ) -> Event:
        start = time.perf_counter()
        correlation_id = self._correlation_for(run_id, thread_id)
        detections = list(self.memory.scan(key=key, value=value, owner=owner))
        event = Event(
            event=EventKind.MEMORY_INSPECTED,
            correlation_id=correlation_id,
            run_id=run_id,
            thread_id=thread_id,
            detections=detections,
        )
        for d in detections:
            d.extra.setdefault("key", key)
        INSPECTION_DURATION.labels(stage="memory").observe(time.perf_counter() - start)
        self._emit(event)
        return event

    # -- boot-time scans ---------------------------------------------------

    def scan_attack_surface(self, info: RuntimeInfo) -> Event:
        detections = self.attack_surface.scan(info)
        event = Event(
            event=EventKind.ATTACK_SURFACE_SCAN,
            correlation_id=new_correlation_id(prefix="boot-"),
            detections=detections,
        )
        self._emit(event)
        return event

    def scan_prompt(self, path: str | Path) -> Event:
        detections = self.supply_chain.scan_path(path)
        event = Event(
            event=EventKind.PROMPT_SCAN,
            correlation_id=new_correlation_id(prefix="load-"),
            detections=detections,
        )
        for d in detections:
            d.extra.setdefault("prompt_path", str(path))
        self._emit(event)
        return event

    # -- Tier 2 decision paths --------------------------------------------

    def decide_node(
        self,
        *,
        node: str,
        state: dict[str, Any],
        run_id: str | None = None,
        thread_id: str | None = None,
        declared_edges: list[tuple[str, str]] | None = None,
        recursion_limit: int | None = None,
        recursion_depth: int | None = None,
    ) -> tuple[LensDecision, Event]:
        """Run Tier 1 inspection *and* Tier 2 interventions on a node.

        Always runs every detector — Tier 2 interventions are layered on
        top and may modify the state or terminate the call. The returned
        Event reflects the combined detections; the LensDecision tells
        the caller what to do.
        """
        decision = LensDecision()
        extra_detections: list[Detection] = []

        # 1. Circuit breaker.
        cb_decision, cb_dets = self.circuit_breaker.evaluate_request()
        extra_detections.extend(cb_dets)
        decision = decision.merge(cb_decision)

        # 2. Goal guard.
        if not decision.is_terminal and thread_id:
            gg_decision, gg_dets = self.goal_guard.evaluate(
                state=state,
                originating_intent=self._thread_user_intent.get(thread_id),
            )
            extra_detections.extend(gg_dets)
            decision = decision.merge(gg_decision)
            for d in gg_dets:
                self.circuit_breaker.record_attack_signal(d.severity)

        # 3. PII redactor (last — may rewrite state for downstream).
        if not decision.is_terminal:
            pr_decision, pr_dets = self.pii_redactor.evaluate(state)
            extra_detections.extend(pr_dets)
            decision = decision.merge(pr_decision)

        # Run Tier 1 inspection against the state the caller will
        # actually forward (the redacted one if PII redactor fired).
        state_for_inspection = decision.modified_state or state
        event = self.inspect_node(
            node=node,
            state=state_for_inspection,
            run_id=run_id,
            thread_id=thread_id,
            declared_edges=declared_edges,
            recursion_limit=recursion_limit,
            recursion_depth=recursion_depth,
        )
        if extra_detections:
            event.detections.extend(extra_detections)
            for d in extra_detections:
                record_detection(d)

        self._record_tier2_outcome(decision)
        if self.config.tier2.audit_signaling.stamp_state and isinstance(
            state_for_inspection, dict
        ):
            self.audit.stamp_state(state_for_inspection, decision)
        return self.audit.stamp(decision), event

    def decide_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, Any] | str,
        run_id: str | None = None,
        thread_id: str | None = None,
        tenant: str | None = None,
    ) -> tuple[LensDecision, Event]:
        decision = LensDecision()
        extra_detections: list[Detection] = []

        cb_decision, cb_dets = self.circuit_breaker.evaluate_request()
        extra_detections.extend(cb_dets)
        decision = decision.merge(cb_decision)

        if not decision.is_terminal:
            ta_decision, ta_dets = self.tool_allowlist.evaluate(
                tool=tool, args=args, thread_id=thread_id
            )
            extra_detections.extend(ta_dets)
            decision = decision.merge(ta_decision)
            for d in ta_dets:
                self.circuit_breaker.record_attack_signal(d.severity)

        if not decision.is_terminal:
            rl_decision, rl_dets = self.rate_limiter.evaluate(
                tool=tool, args=args, thread_id=thread_id, tenant=tenant
            )
            extra_detections.extend(rl_dets)
            decision = decision.merge(rl_decision)

        event = self.inspect_tool_call(
            tool=tool, args=args, run_id=run_id, thread_id=thread_id
        )
        if extra_detections:
            event.detections.extend(extra_detections)
            for d in extra_detections:
                record_detection(d)

        self._record_tier2_outcome(decision)
        return self.audit.stamp(decision), event

    def decide_checkpoint(
        self,
        *,
        blob: bytes | dict[str, Any],
        metadata: dict[str, Any] | None = None,
        run_id: str | None = None,
        thread_id: str | None = None,
        checkpoint_id: str | None = None,
        direction: str = "write",
    ) -> tuple[LensDecision, Event]:
        decision = LensDecision()
        extra_detections: list[Detection] = []

        cp_decision, cp_dets = self.checkpoint_protector.evaluate(
            blob=blob, metadata=metadata, direction=direction, thread_id=thread_id
        )
        extra_detections.extend(cp_dets)
        decision = decision.merge(cp_decision)
        for d in cp_dets:
            self.circuit_breaker.record_attack_signal(d.severity)

        event = self.inspect_checkpoint(
            blob=blob,
            metadata=metadata,
            run_id=run_id,
            thread_id=thread_id,
            checkpoint_id=checkpoint_id,
            direction=direction,
        )
        if extra_detections:
            event.detections.extend(extra_detections)
            for d in extra_detections:
                record_detection(d)

        self._record_tier2_outcome(decision)
        return self.audit.stamp(decision), event

    def record_upstream_result(self, *, error: bool) -> None:
        """Feed an upstream success/error into the circuit breaker.

        Call this after `graph.invoke(...)` (or any external dependency
        the lens guards) returns or raises. With no Tier 2 interventions
        enabled this is a no-op.
        """
        self.circuit_breaker.record_response(error=error)
        CIRCUIT_STATE.set(self.circuit_breaker.state_value)

    # -- API for tests / dashboards ---------------------------------------

    def events_for_thread(self, thread_id: str) -> list[Event]:
        return list(self._thread_events.get(thread_id, ()))

    # -- internal sink -----------------------------------------------------

    def _correlation_for(
        self, run_id: str | None, thread_id: str | None
    ) -> str:
        key = (run_id, thread_id)
        cid = self._correlation_pairs.get(key)
        if cid is None:
            cid = new_correlation_id()
            self._correlation_pairs[key] = cid
        return cid

    def _record_tier2_outcome(self, decision: LensDecision) -> None:
        if decision.action == "block":
            TIER2_BLOCKED.labels(reason=decision.reason or "unknown").inc()
        elif decision.action == "redact":
            reasons = sorted({t.split(".", 1)[0] for t in decision.triggered_by})
            TIER2_REDACTED.labels(reason=",".join(reasons) or "unknown").inc()
        elif decision.action == "throttle":
            TIER2_THROTTLED.labels(reason=decision.reason or "unknown").inc()
        CIRCUIT_STATE.set(self.circuit_breaker.state_value)

    def _emit(self, event: Event) -> None:
        for d in event.detections:
            record_detection(d)
        if self.config.logging.enabled:
            write_event(
                event,
                destination=self.config.logging.destination,
                file_path=self.config.logging.file_path,
                include_match_text=self.config.logging.include_match_text,
            )
        if event.thread_id:
            self._thread_events[event.thread_id].append(event)
        if event.detections:
            self.alerts.maybe_send(event)
        if self.config.otel.enabled:
            self.otel.export(event)


def _stringify_state(state: dict[str, Any]) -> str:
    """Best-effort flatten of a LangGraph state dict into inspectable text.

    Handles the common shapes:
      - `messages: [BaseMessage | dict]`
      - `input: str`
      - free-form dict of str values
    """
    if not isinstance(state, dict):
        return ""
    parts: list[str] = []
    msgs = state.get("messages")
    if isinstance(msgs, list):
        for m in msgs:
            content = _message_content(m)
            if content:
                parts.append(content)
    for key in ("input", "question", "query", "prompt", "output", "answer"):
        v = state.get(key)
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def _message_content(m: Any) -> str:
    c = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        out: list[str] = []
        for sub in c:
            if isinstance(sub, dict) and "text" in sub:
                out.append(str(sub["text"]))
            elif isinstance(sub, str):
                out.append(sub)
        return "\n".join(out)
    return ""


def _extract_user_intent(state: dict[str, Any]) -> str | None:
    msgs = state.get("messages") if isinstance(state, dict) else None
    if isinstance(msgs, list):
        for m in msgs:
            role = m.get("role") if isinstance(m, dict) else getattr(m, "type", None)
            if role in ("user", "human"):
                c = _message_content(m)
                if c:
                    return c
    if isinstance(state, dict):
        for k in ("input", "question", "query", "prompt"):
            v = state.get(k)
            if isinstance(v, str) and v:
                return v
    return None


def _state_size(state: Any) -> int:
    try:
        import json

        return len(json.dumps(state, default=str))
    except (TypeError, ValueError):
        return len(repr(state))
