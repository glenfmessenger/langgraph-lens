"""LangGraph / LangChain callback handler.

The lens hooks into LangGraph by way of LangChain Core's
`BaseCallbackHandler` interface, which LangGraph re-uses for every node,
checkpoint, tool, and chain event. The handler runs synchronously between
nodes and must never raise — anything that goes wrong inside a detector
is swallowed and logged to stderr, never re-thrown into the agent loop.

Two attachment paths:

  1. Global. Importing `langgraph_lens` with `LANGGRAPH_LENS=1` set
     installs a single shared `LensCallback` on LangChain Core's global
     callback manager. Every compiled graph picks it up.
  2. Per-graph. Build a `Lens(config)` explicitly and pass
     `LensCallback(lens)` as a callback on `graph.invoke(..., config=...)`.
"""

from __future__ import annotations

import sys
import traceback
from typing import TYPE_CHECKING, Any

from .config import LensConfig

if TYPE_CHECKING:
    from .lens import Lens


# Try to import the real BaseCallbackHandler. If LangChain isn't installed
# (the lens can still be used directly, without callbacks), fall back to a
# minimal stub that exposes the same interface so callers always get a
# consistent shape.
try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    _LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover -- fallback for envs without langchain
    _LANGCHAIN_AVAILABLE = False

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub used when langchain-core is not installed."""

        raise_error: bool = False
        run_inline: bool = True


_GLOBAL_LENS: Lens | None = None


def install_global_callback(config: LensConfig) -> Lens:
    """Install a process-wide `LensCallback` on LangChain's global handler.

    Returns the underlying `Lens` so callers can introspect events or
    invoke the inspection methods directly.
    """
    # Import lazily to avoid a circular import at package init.
    from .lens import Lens

    global _GLOBAL_LENS
    if _GLOBAL_LENS is not None:
        return _GLOBAL_LENS

    lens = Lens(config)
    _GLOBAL_LENS = lens

    if not _LANGCHAIN_AVAILABLE:
        # Still useful — direct `lens.inspect_*` calls work without
        # langchain installed. The callback just won't auto-fire.
        return lens

    try:
        # LangChain ≥ 0.3 exposes `register_configure_hook` and a global
        # callback manager via `langchain_core.tracers.context`. We use a
        # configure hook so every new RunnableConfig in the process gets
        # the lens callback merged in.
        from langchain_core.tracers.context import (
            register_configure_hook,
        )

        handler = LensCallback(lens)
        # `register_configure_hook(ctx_var, inheritable, handle_class, env_var)`
        # signatures vary across langchain-core versions; the safe path is
        # to attach via a context var that langchain reads.
        from contextvars import ContextVar

        _lens_handler_var: ContextVar[Any] = ContextVar(
            "langgraph_lens_handler", default=handler
        )
        register_configure_hook(_lens_handler_var, True)
    except Exception:  # noqa: BLE001 -- fallback path is acceptable
        # If the configure-hook surface changed, we still expose the
        # `Lens` for direct use and per-graph `LensCallback`.
        traceback.print_exc(file=sys.stderr)

    return lens


class LensCallback(BaseCallbackHandler):
    """LangChain callback handler that forwards every event to a `Lens`.

    Constructed with an existing `Lens` so multiple graphs in the same
    process can share metrics, alerts, and the per-thread event buffer.
    """

    raise_error = False
    run_inline = True

    def __init__(self, lens: Lens) -> None:
        super().__init__()
        self.lens = lens
        self._tool_allowlist: list[str] | None = None

    # -- LangChain hooks. All wrapped in `_safe` so detector errors never
    # escape into the agent loop. --

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._safe(
            lambda: self.lens.inspect_node(
                node=_node_name(serialized, kwargs, metadata),
                state=inputs if isinstance(inputs, dict) else {"input": inputs},
                run_id=_stringify(run_id),
                thread_id=_thread_id_from(metadata, kwargs),
                recursion_limit=_recursion_limit_from(metadata, kwargs),
                recursion_depth=_recursion_depth_from(kwargs),
            )
        )

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        if not isinstance(outputs, dict) or not self.lens.config.pii.scan_egress:
            return
        # Egress PII scan; piggy-backs on `inspect_node` with the node
        # marked as "<exit>" so the event stays joinable.
        self._safe(
            lambda: self.lens.inspect_node(
                node="<exit>",
                state=outputs,
                run_id=_stringify(run_id),
                thread_id=_thread_id_from(kwargs.get("metadata"), kwargs),
            )
        )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = (serialized or {}).get("name", "<unknown>")
        args: dict[str, Any] | str = inputs if isinstance(inputs, dict) else input_str
        self._safe(
            lambda: self.lens.inspect_tool_call(
                tool=tool_name,
                args=args,
                run_id=_stringify(run_id),
                thread_id=_thread_id_from(metadata, kwargs),
                allowed_tools=self._tool_allowlist,
            )
        )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        # Cheap entry point for the supply-chain detector — flags
        # SSTI-shaped substrings that survived into the rendered prompt.
        self._safe(
            lambda: self.lens.inspect_node(
                node="<llm>",
                state={"prompt": "\n".join(prompts)},
                run_id=_stringify(run_id),
                thread_id=_thread_id_from(kwargs.get("metadata"), kwargs),
            )
        )

    # -- helpers --

    def set_tool_allowlist(self, tools: list[str]) -> None:
        self._tool_allowlist = list(tools)

    @staticmethod
    def _safe(fn: Any) -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001 -- intentional: never raise into the agent loop
            print("[langgraph-lens] detector error (suppressed):", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


def _node_name(
    serialized: dict[str, Any] | None,
    kwargs: dict[str, Any],
    metadata: dict[str, Any] | None,
) -> str:
    if metadata:
        n = metadata.get("langgraph_node")
        if isinstance(n, str):
            return n
    if serialized:
        # LangChain serializes as {"id": [...], "name": "..."}
        n = serialized.get("name")
        if isinstance(n, str):
            return n
        if isinstance(serialized.get("id"), list) and serialized["id"]:
            return str(serialized["id"][-1])
    name = kwargs.get("name")
    return name if isinstance(name, str) else "<unknown>"


def _thread_id_from(metadata: dict[str, Any] | None, kwargs: dict[str, Any]) -> str | None:
    if metadata:
        for k in ("thread_id", "langgraph_thread_id"):
            v = metadata.get(k)
            if isinstance(v, str):
                return v
    cfg = kwargs.get("configurable") or {}
    if isinstance(cfg, dict):
        v = cfg.get("thread_id")
        if isinstance(v, str):
            return v
    return None


def _recursion_limit_from(
    metadata: dict[str, Any] | None, kwargs: dict[str, Any]
) -> int | None:
    if metadata:
        v = metadata.get("recursion_limit")
        if isinstance(v, int):
            return v
    v = kwargs.get("recursion_limit")
    return v if isinstance(v, int) else None


def _recursion_depth_from(kwargs: dict[str, Any]) -> int | None:
    v = kwargs.get("recursion_depth")
    return v if isinstance(v, int) else None


def _stringify(x: Any) -> str | None:
    if x is None:
        return None
    return str(x)
