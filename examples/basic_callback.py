"""Minimal example: wire langgraph-lens into a LangGraph agent via callback."""

from __future__ import annotations

from typing import TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from langgraph_lens import Lens, LensCallback, LensConfig


class AgentState(TypedDict):
    input: str
    output: str


def plan(state: AgentState) -> AgentState:
    return {"input": state["input"], "output": f"plan({state['input']})"}


def act(state: AgentState) -> AgentState:
    return {"input": state["input"], "output": f"act({state['output']})"}


def build() -> object:
    g = StateGraph(AgentState)
    g.add_node("plan", plan)
    g.add_node("act", act)
    g.set_entry_point("plan")
    g.add_edge("plan", "act")
    g.add_edge("act", END)
    return g.compile(checkpointer=MemorySaver())


if __name__ == "__main__":
    lens = Lens(LensConfig.default())
    app = build()
    result = app.invoke(
        {"input": "summarise this PDF"},
        config={
            "configurable": {"thread_id": "demo-thread-1"},
            "callbacks": [LensCallback(lens)],
        },
    )
    print("agent result:", result)
    print("detections for thread:", lens.events_for_thread("demo-thread-1"))
