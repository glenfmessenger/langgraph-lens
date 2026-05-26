from __future__ import annotations

from langgraph_lens import Lens


def test_correlation_id_stable_per_thread(lens: Lens) -> None:
    e1 = lens.inspect_node(
        node="plan", state={"input": "hi"}, run_id="r1", thread_id="t1"
    )
    e2 = lens.inspect_node(
        node="act", state={"input": "hi"}, run_id="r1", thread_id="t1"
    )
    assert e1.correlation_id == e2.correlation_id


def test_state_hash_is_stable(lens: Lens) -> None:
    e1 = lens.inspect_node(node="n", state={"a": 1, "b": 2}, thread_id="t")
    e2 = lens.inspect_node(node="n", state={"b": 2, "a": 1}, thread_id="t")
    assert e1.state_hash == e2.state_hash


def test_events_for_thread_buffers_recent_events(lens: Lens) -> None:
    lens.inspect_node(node="a", state={"input": "x"}, thread_id="abc")
    lens.inspect_node(node="b", state={"input": "x"}, thread_id="abc")
    events = lens.events_for_thread("abc")
    assert len(events) == 2
    assert [e.node for e in events] == ["a", "b"]
