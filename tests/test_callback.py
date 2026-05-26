"""Tests for the LangChain callback bridge.

These run only when langchain-core is importable; they exercise the
real callback dispatch path with a compiled LangGraph + MemorySaver.
"""

from __future__ import annotations

from typing import Any

import pytest

from langgraph_lens import Lens, LensCallback, LensConfig

pytest.importorskip("langgraph")

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.graph import END, StateGraph  # noqa: E402


def _make_graph() -> Any:
    def node(state: dict) -> dict:
        return {**state, "counter": state.get("counter", 0) + 1}

    g = StateGraph(dict)
    for i in range(5):
        g.add_node(f"n{i}", node)
    g.set_entry_point("n0")
    for i in range(4):
        g.add_edge(f"n{i}", f"n{i+1}")
    g.add_edge("n4", END)
    return g.compile(checkpointer=MemorySaver())


def _counting_lens() -> tuple[Lens, dict[str, list[str]]]:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    lens = Lens(cfg)
    state: dict[str, list[str]] = {"nodes": []}
    orig = lens.inspect_node

    def counted(**kwargs: Any) -> Any:
        state["nodes"].append(kwargs.get("node", "?"))
        return orig(**kwargs)

    lens.inspect_node = counted  # type: ignore[method-assign]
    return lens, state


def test_callback_fires_once_per_real_node_plus_one_egress() -> None:
    """The callback should not pay the cost of inspecting LangChain's
    outer wrappers, internal Runnable transforms, or per-node `<exit>`
    events. For a 5-node graph that's 5 ingress + 1 final egress = 6.
    """
    lens, seen = _counting_lens()
    app = _make_graph()
    app.invoke(
        {"counter": 0, "payload": "x" * 200},
        config={
            "configurable": {"thread_id": "t-filter"},
            "callbacks": [LensCallback(lens)],
        },
    )
    nodes = seen["nodes"]
    assert nodes.count("n0") == 1
    assert nodes.count("n4") == 1
    assert "LangGraph" not in nodes  # outer wrapper filtered
    assert nodes.count("<exit>") == 1  # only the outer end
    assert len(nodes) == 6


def test_callback_does_not_fire_when_metadata_absent() -> None:
    """Direct LensCallback usage outside a LangGraph context (no
    langgraph_node metadata) is a no-op for chain events.
    """
    lens, seen = _counting_lens()
    cb = LensCallback(lens)
    cb.on_chain_start({"name": "Foo"}, {"x": 1}, run_id="r1", metadata={})
    assert seen["nodes"] == []


def test_callback_egress_only_fires_at_top_level() -> None:
    lens, seen = _counting_lens()
    cb = LensCallback(lens)
    # Inner chain end (has a parent) — should NOT fire egress.
    cb.on_chain_end({"output": "x"}, run_id="r2", parent_run_id="r1")
    assert seen["nodes"] == []
    # Outer chain end (parent_run_id is None) — fires once.
    cb.on_chain_end({"output": "x"}, run_id="r2", parent_run_id=None)
    assert seen["nodes"] == ["<exit>"]
