"""Integration helpers that wire the Lens into specific LangGraph
runtime surfaces the BaseCallbackHandler doesn't expose.

The LangChain callback interface only fires for chain entry / exit,
tool calls, and LLM calls. Checkpoints, memory-store writes, and
prompt loads happen outside that surface, so detectors that scan
those things have to be wired in explicitly.

This module provides both:

  - **Explicit wrappers** (`protect_saver`, `protect_store`) that
    operators can drop in around a real saver or store instance.
  - **Auto-protect installers** (`install_saver_auto_protection`,
    `install_store_auto_protection`) that walk existing
    BaseCheckpointSaver / BaseStore subclasses and instrument them in
    place. The global `LANGGRAPH_LENS=1` install runs both
    auto-protect installers, so users with existing
    `graph.compile(checkpointer=PostgresSaver(...))` code get
    checkpoint inspection without changing a line.

Auto-protect uses class-method monkey-patching. It is opt-out: set
`LANGGRAPH_LENS_AUTO_PROTECT=0` in the env to disable.
"""

from .checkpoint import (
    install_saver_auto_protection,
    is_saver_protected,
    protect_saver,
)
from .store import (
    install_store_auto_protection,
    is_store_protected,
    protect_store,
)
from .topology import extract_topology

__all__ = [
    "protect_saver",
    "install_saver_auto_protection",
    "is_saver_protected",
    "protect_store",
    "install_store_auto_protection",
    "is_store_protected",
    "extract_topology",
]
