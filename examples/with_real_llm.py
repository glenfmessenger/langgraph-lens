"""Real-LLM end-to-end demo for langgraph-lens.

Builds a minimal LangGraph agent that calls OpenAI via langchain-openai,
attaches the lens via the global `LANGGRAPH_LENS=1` callback path,
enables Tier 2 PII redaction, and demonstrates three claims the README
makes:

  1. Tier 1 events fire automatically on every real node entry / exit
     when LANGGRAPH_LENS=1 is set — no decorator, no per-graph wiring.
  2. A PII-bearing user message produces a Tier 1 `pii/ssn` detection
     on node ingress.
  3. With Tier 2 `pii_redaction` enabled via `wrap_node`, the message
     the LLM actually receives has the SSN replaced with
     `[REDACTED:ssn]` — the model never sees the raw value, so it can
     no longer echo it back even if asked.

Run with:

    export OPENAI_API_KEY=$(cat /path/to/your/key)
    LANGGRAPH_LENS=1 python examples/with_real_llm.py

Requires the optional dependencies:

    pip install "langgraph-lens[langgraph]" langchain-openai
"""

from __future__ import annotations

import os
import sys
from typing import Any, TypedDict

from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from langgraph_lens import Lens, LensConfig, wrap_node


class State(TypedDict):
    messages: list[Any]


def build_lens() -> Lens:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False  # keep stdout clean for the demo
    cfg.tier2.pii_redaction.enabled = True
    cfg.tier2.audit_signaling.enabled = True
    return Lens(cfg)


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY"):
        print("error: set OPENAI_API_KEY in the environment first", file=sys.stderr)
        return 1

    lens = build_lens()
    model = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    captured_what_llm_saw: list[str] = []

    def chat(state: State, config: RunnableConfig | None = None) -> State:
        # `config` is accepted so LangGraph passes it through, which lets
        # `wrap_node` extract thread_id and bucket events correctly.
        # Capture what the LLM actually receives — Tier 2 redaction
        # should have rewritten the state before we got here.
        captured_what_llm_saw.append(state["messages"][0].get("content", ""))
        response = model.invoke(state["messages"])
        return {"messages": [*state["messages"], response]}

    g = StateGraph(State)
    # wrap_node is what makes Tier 2 redaction actually take effect
    # before the wrapped node runs. Callbacks alone can't rewrite
    # state.
    g.add_node("chat", wrap_node(lens, chat, node="chat"))
    g.set_entry_point("chat")
    g.add_edge("chat", END)
    app = g.compile(checkpointer=MemorySaver())

    raw_user = "My SSN is 123-45-6789. Please respond with the SSN you received."
    result = app.invoke(
        {"messages": [{"role": "user", "content": raw_user}]},
        config={"configurable": {"thread_id": "real-llm-demo"}},
    )

    print("\n--- demo: real OpenAI call with langgraph-lens attached ---\n")

    print(f"original user message:\n  {raw_user!r}\n")
    print(f"what the LLM actually received (after Tier 2 redaction):\n  {captured_what_llm_saw[0]!r}\n")
    print(f"model response:\n  {result['messages'][-1].content!r}\n")

    print("lens events for this thread (run_id stripped for brevity):")
    for evt in lens.events_for_thread("real-llm-demo"):
        rules = [(d.detector, d.rule) for d in evt.detections] or "—"
        print(f"  {evt.event.value:25s} node={evt.node!r:14s} detections={rules}")

    # Assertions so a CI-style run can verify behaviour, not just print.
    assert "[REDACTED:ssn]" in captured_what_llm_saw[0], (
        "Tier 2 redaction did not run before the LLM saw the message"
    )
    assert "123-45-6789" not in captured_what_llm_saw[0], (
        "raw SSN leaked to the model"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
