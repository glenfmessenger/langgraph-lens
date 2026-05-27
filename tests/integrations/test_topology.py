"""Tests for `langgraph_lens.integrations.topology.extract_topology`.

The helper walks a compiled StateGraph's metadata to recover the
declared (from, to) edge list. The comms detector's `undeclared_edge`
rule depends on this list being available at runtime.
"""

from __future__ import annotations

from typing import TypedDict

import pytest

from langgraph_lens import Lens, LensConfig
from langgraph_lens.integrations import extract_topology

pytest.importorskip("langgraph")

from langgraph.graph import END, StateGraph  # noqa: E402


class _S(TypedDict):
    counter: int


def _make_graph() -> object:
    def n(state: _S) -> _S:
        return state

    g = StateGraph(_S)
    g.add_node("a", n)
    g.add_node("b", n)
    g.add_node("c", n)
    g.set_entry_point("a")
    g.add_edge("a", "b")
    g.add_edge("b", "c")
    g.add_edge("c", END)
    return g.compile()


def test_extract_topology_recovers_simple_edges() -> None:
    app = _make_graph()
    edges = extract_topology(app)
    # Must contain at least the explicit a→b and b→c edges.
    assert ("a", "b") in edges
    assert ("b", "c") in edges


def test_extract_topology_on_unknown_object_returns_empty() -> None:
    edges = extract_topology(object())
    assert edges == []


def test_attach_graph_enables_undeclared_edge_rule() -> None:
    """End-to-end: lens.attach_graph(app) populates declared_edges so
    the comms detector's `undeclared_edge` rule fires when traversal
    leaves the declared topology.
    """
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    lens = Lens(cfg)
    app = _make_graph()
    lens.attach_graph(app)

    # First node fires — no previous node, no undeclared_edge event.
    lens.inspect_node(node="a", state={"counter": 0}, thread_id="t")
    # Next node is "b" — declared a→b edge — no comms detection.
    e1 = lens.inspect_node(node="b", state={"counter": 1}, thread_id="t")
    assert not any(
        d.detector == "comms" and d.rule == "undeclared_edge" for d in e1.detections
    )
    # Now jump to "exfiltrate" — NOT in the declared topology.
    e2 = lens.inspect_node(node="exfiltrate", state={"counter": 2}, thread_id="t")
    assert any(
        d.detector == "comms" and d.rule == "undeclared_edge" for d in e2.detections
    ), f"undeclared_edge did not fire; detections were {[(d.detector, d.rule) for d in e2.detections]}"
