"""Topology extraction from a compiled LangGraph `StateGraph`.

The comms detector has `undeclared_edge` and `send_to_undeclared_target`
rules that need a list of `(from, to)` edge tuples to compare against
the runtime traversal. Without that list those rules can never fire.

`extract_topology(compiled_graph)` walks the compiled graph's internal
metadata and returns the static edges. It tolerates the graph not
exposing what we expect (the langgraph internals shift between
minor versions) and returns an empty list in that case.

This is intentionally best-effort. If it can't find the edges, the
comms rules that depend on them stay silent — they don't false-fire.
"""

from __future__ import annotations

from typing import Any


def extract_topology(compiled_graph: Any) -> list[tuple[str, str]]:
    """Return declared edges as a list of (from, to) tuples.

    Accepts the object returned by `StateGraph.compile(...)`. Returns
    `[]` if the structure can't be parsed (different langgraph version,
    custom subclass, etc.) — never raises.
    """
    edges: list[tuple[str, str]] = []

    # langgraph compiled graphs expose `.builder` (the StateGraph)
    # which holds the declared edges. The attribute name has been
    # stable across 0.2/1.x but we guard defensively.
    builder = getattr(compiled_graph, "builder", None)
    if builder is None:
        builder = compiled_graph  # maybe we were passed the StateGraph directly

    # `.edges` is a set/list of (start, end) tuples in modern langgraph.
    raw_edges = getattr(builder, "edges", None)
    if raw_edges is not None:
        for item in raw_edges:
            pair = _coerce_pair(item)
            if pair is not None:
                edges.append(pair)

    # Conditional branches live under `.branches` as a nested dict
    # `{node: {branch_name: Branch(...)}}`. The Branch usually carries
    # an `.ends` mapping of possible next nodes.
    branches = getattr(builder, "branches", None)
    if isinstance(branches, dict):
        for src, by_branch in branches.items():
            if not isinstance(by_branch, dict):
                continue
            for branch in by_branch.values():
                ends = getattr(branch, "ends", None)
                if isinstance(ends, dict):
                    for dst in ends.values():
                        if isinstance(dst, str):
                            edges.append((str(src), dst))
                elif isinstance(ends, (list, set, tuple)):
                    for dst in ends:
                        if isinstance(dst, str):
                            edges.append((str(src), dst))

    return _dedupe(edges)


def _coerce_pair(item: Any) -> tuple[str, str] | None:
    if isinstance(item, tuple) and len(item) == 2:
        a, b = item
        if isinstance(a, str) and isinstance(b, str):
            return (a, b)
    if isinstance(item, list) and len(item) == 2:
        a, b = item
        if isinstance(a, str) and isinstance(b, str):
            return (a, b)
    return None


def _dedupe(edges: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for e in edges:
        if e in seen:
            continue
        seen.add(e)
        out.append(e)
    return out
