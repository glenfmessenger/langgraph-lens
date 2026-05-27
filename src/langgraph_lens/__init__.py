"""langgraph-lens — zero-config runtime observability for LangGraph agents.

Importing this package with the env var `LANGGRAPH_LENS=1` set installs a
process-wide callback handler on LangChain Core's global callback manager.
Any LangGraph compiled in that process picks it up automatically.

Set `LANGGRAPH_LENS_CONFIG=/path/to/lens.yaml` to override defaults.
"""

from __future__ import annotations

import os

from .config import LensConfig
from .events import Detection, Event, EventKind
from .interventions import LensBlockedError, LensDecision
from .lens import Lens
from .middleware import LensCallback, install_global_callback, wrap_node

__all__ = [
    "Lens",
    "LensConfig",
    "LensCallback",
    "LensDecision",
    "LensBlockedError",
    "Event",
    "EventKind",
    "Detection",
    "install_global_callback",
    "wrap_node",
]

__version__ = "0.3.0"


if os.environ.get("LANGGRAPH_LENS") == "1":
    # Best-effort: never raise during package import.
    try:
        install_global_callback(LensConfig.from_env())
    except Exception:  # noqa: BLE001 -- intentional broad except at import time
        import sys
        import traceback

        print("[langgraph-lens] failed to install global callback:", file=sys.stderr)
        traceback.print_exc()
