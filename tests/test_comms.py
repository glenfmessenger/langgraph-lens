from __future__ import annotations

from langgraph_lens import Lens


def test_undeclared_edge_detected(lens: Lens) -> None:
    # Establish the previous node.
    lens.inspect_node(
        node="plan",
        state={"input": "x"},
        thread_id="t",
        declared_edges=[("plan", "act")],
    )
    # Now go to a node that wasn't a declared target.
    event = lens.inspect_node(
        node="exfiltrate",
        state={"input": "x"},
        thread_id="t",
        declared_edges=[("plan", "act")],
    )
    assert any(
        d.detector == "comms" and d.rule == "undeclared_edge"
        for d in event.detections
    )


def test_recursion_exceeded_detected(lens: Lens) -> None:
    event = lens.inspect_node(
        node="act",
        state={"input": "x"},
        thread_id="t",
        declared_edges=[],
        recursion_limit=10,
        recursion_depth=15,
    )
    assert any(
        d.detector == "comms" and d.rule == "recursion_exceeded"
        for d in event.detections
    )
