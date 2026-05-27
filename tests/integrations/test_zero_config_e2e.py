"""End-to-end test that LANGGRAPH_LENS=1 plus a typical multi-node
LangGraph with `MemorySaver` auto-fires every detector the runtime
surface can expose.

Covers the integration claims in the README's "What you actually get
with LANGGRAPH_LENS=1" matrix. No real LLM call — we use a stub node
function so the test runs deterministically in CI.
"""

from __future__ import annotations

from typing import TypedDict

import pytest

from langgraph_lens import Lens, LensConfig

pytest.importorskip("langgraph")

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.graph import END, StateGraph  # noqa: E402


class _State(TypedDict):
    messages: list
    counter: int


def _make_lens(monkeypatch: pytest.MonkeyPatch) -> Lens:
    # Install a lens via the global path so auto-integrations fire.
    from langgraph_lens import middleware
    from langgraph_lens.integrations import install_saver_auto_protection

    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    lens = Lens(cfg)
    monkeypatch.setattr(middleware, "_GLOBAL_LENS", lens)
    install_saver_auto_protection(lens)
    return lens


def _build_graph() -> object:
    def plan(state: _State) -> _State:
        return {"messages": state["messages"], "counter": state.get("counter", 0) + 1}

    def act(state: _State) -> _State:
        return {"messages": state["messages"], "counter": state["counter"] + 1}

    g = StateGraph(_State)
    g.add_node("plan", plan)
    g.add_node("act", act)
    g.set_entry_point("plan")
    g.add_edge("plan", "act")
    g.add_edge("act", END)
    return g.compile(checkpointer=MemorySaver())


def test_zero_config_pii_fires_through_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real StateGraph + LensCallback + a state with PII triggers a
    `pii/ssn` detection on node ingress.
    """
    from langgraph_lens import LensCallback

    lens = _make_lens(monkeypatch)
    app = _build_graph()
    lens.attach_graph(app)

    app.invoke(
        {"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}], "counter": 0},
        config={
            "configurable": {"thread_id": "e2e-1"},
            "callbacks": [LensCallback(lens)],
        },
    )
    events = lens.events_for_thread("e2e-1")
    rules = [(d.detector, d.rule) for e in events for d in e.detections]
    assert ("pii", "ssn") in rules, f"pii/ssn missing from {rules}"


def test_zero_config_checkpoint_inspection_fires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auto-protected MemorySaver triggers `lens.decide_checkpoint`
    on every put. We verify by counting the Prometheus
    `langgraph_lens_checkpoints_inspected_total` delta.
    """
    from langgraph_lens import LensCallback
    from langgraph_lens.metrics import CHECKPOINTS_INSPECTED

    lens = _make_lens(monkeypatch)
    app = _build_graph()

    before = sum(s.value for s in list(CHECKPOINTS_INSPECTED.collect())[0].samples)
    app.invoke(
        {"messages": [{"role": "user", "content": "ok"}], "counter": 0},
        config={
            "configurable": {"thread_id": "e2e-cp-1"},
            "callbacks": [LensCallback(lens)],
        },
    )
    after = sum(s.value for s in list(CHECKPOINTS_INSPECTED.collect())[0].samples)
    assert after > before, (
        f"checkpoints_inspected did not increment (before={before}, after={after}); "
        "saver auto-protection probably did not engage"
    )


def test_zero_config_attack_surface_fires_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Attack-surface scan auto-fires on the first node inspection per
    process and never again.
    """
    from langgraph_lens import LensCallback

    lens = _make_lens(monkeypatch)
    app = _build_graph()
    assert not lens._attack_surface_scanned
    app.invoke(
        {"messages": [], "counter": 0},
        config={
            "configurable": {"thread_id": "e2e-as-1"},
            "callbacks": [LensCallback(lens)],
        },
    )
    assert lens._attack_surface_scanned, "attack surface should have auto-fired"
    # And it's idempotent — a second invoke doesn't re-fire.
    app.invoke(
        {"messages": [], "counter": 0},
        config={
            "configurable": {"thread_id": "e2e-as-2"},
            "callbacks": [LensCallback(lens)],
        },
    )
    # _attack_surface_scanned remains True; no exception.


def test_zero_config_undeclared_edge_via_attached_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`lens.attach_graph(app)` makes the comms `undeclared_edge`
    rule usable through the zero-config callback path.
    """
    from langgraph_lens import LensCallback

    lens = _make_lens(monkeypatch)
    app = _build_graph()
    lens.attach_graph(app)

    cb = LensCallback(lens)
    app.invoke(
        {"messages": [], "counter": 0},
        config={"configurable": {"thread_id": "e2e-edge-1"}, "callbacks": [cb]},
    )
    # Now manually drive a node that isn't on the declared topology.
    # This simulates a buggy / compromised path that bypassed the
    # normal graph traversal. Without attach_graph this would silently
    # pass; with attach_graph the comms detector fires.
    event = lens.inspect_node(
        node="exfiltrate", state={"messages": [], "counter": 99}, thread_id="e2e-edge-1"
    )
    rules = [(d.detector, d.rule) for d in event.detections]
    assert ("comms", "undeclared_edge") in rules, f"undeclared_edge missing from {rules}"
