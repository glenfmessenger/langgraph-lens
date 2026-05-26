"""Reproducible benchmark for langgraph-lens.

Measures the overhead of Tier 1 observability and each Tier 2
intervention. Three independent benchmark groups:

  1. **Whole-graph invoke** — 5-node graph + ~4 KB state. Compares
     baseline (no lens) to (a) Tier 1 callback handler, (b) Tier 1
     direct `lens.inspect_node` calls inside each node body, and
     (c) Tier 2 features mounted via `wrap_node`. Latency and
     throughput deltas vs baseline are meaningful here because the
     baseline is non-trivial.
  2. **Single tool call** — measures the standalone cost of
     `lens.inspect_tool_call` / `lens.decide_tool_call`. We report
     absolute p50 latency in microseconds; there is no meaningful
     baseline because a tool call without the lens is a no-op.
  3. **Single checkpoint** — same shape as (2) but for
     `inspect_checkpoint` / `decide_checkpoint`.

Run as:

    python bench/bench.py                 # default: 2000 iterations
    python bench/bench.py --iterations N
    python bench/bench.py --markdown      # paste-ready Markdown tables
    python bench/bench.py --quick         # 200 iterations (smoke)

Numbers are wall-clock latencies measured with `time.perf_counter()`
after a 200-iteration warm-up, with GC disabled inside the timed loop.
No claim of cross-machine portability — re-run on your own hardware
before quoting.
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from langgraph_lens import Lens, LensCallback, LensConfig, wrap_node

WARMUP = 200


class S(TypedDict, total=False):
    messages: list[dict[str, Any]]
    counter: int
    payload: str


def _build_4kb_state() -> S:
    return {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "summarise this document"},
        ],
        "counter": 0,
        "payload": "x" * 3700,
    }


def _node(state: S) -> S:
    return {**state, "counter": state.get("counter", 0) + 1}


def _build_graph(
    *,
    lens: Lens | None = None,
    wrap_for_redact: bool = False,
    direct_inspect: bool = False,
) -> Any:
    g = StateGraph(S)
    names = [f"n{i}" for i in range(5)]
    for n in names:
        if lens and wrap_for_redact:
            fn = wrap_node(lens, _node, node=n)
        elif lens and direct_inspect:
            # Inside-node direct inspection — what a power user would
            # do who doesn't want to go through the callback at all.
            def _direct(state: S, _name: str = n, _lens: Lens = lens) -> S:
                _lens.inspect_node(node=_name, state=state, thread_id="b")
                return _node(state)

            fn = _direct
        else:
            fn = _node
        g.add_node(n, fn)
    g.set_entry_point(names[0])
    for a, b in zip(names, names[1:], strict=False):
        g.add_edge(a, b)
    g.add_edge(names[-1], END)
    return g.compile(checkpointer=MemorySaver())


def _quiet_cfg() -> LensConfig:
    cfg = LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    return cfg


@dataclass
class Result:
    label: str
    samples: list[float]

    @property
    def p50_ms(self) -> float:
        return statistics.median(self.samples) * 1000

    @property
    def mean_ms(self) -> float:
        return statistics.mean(self.samples) * 1000

    @property
    def throughput_per_s(self) -> float:
        return 1.0 / statistics.mean(self.samples)


def _time(label: str, fn: Callable[[], Any], iterations: int) -> Result:
    for _ in range(WARMUP):
        fn()
    gc.collect()
    gc.disable()
    try:
        samples = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - t0)
    finally:
        gc.enable()
    return Result(label=label, samples=samples)


# ---------- 1. whole-graph invoke ----------


def bench_graph_baseline(iterations: int) -> Result:
    app = _build_graph()
    state = _build_4kb_state()

    def fn() -> None:
        app.invoke(state, config={"configurable": {"thread_id": "b"}})

    return _time("baseline (no lens)", fn, iterations)


def bench_graph_t1_callback(iterations: int) -> Result:
    lens = Lens(_quiet_cfg())
    app = _build_graph()
    state = _build_4kb_state()
    cb = LensCallback(lens)

    def fn() -> None:
        app.invoke(
            state,
            config={"configurable": {"thread_id": "b"}, "callbacks": [cb]},
        )

    return _time("Tier 1 — callback handler", fn, iterations)


def bench_graph_t1_direct(iterations: int) -> Result:
    lens = Lens(_quiet_cfg())
    app = _build_graph(lens=lens, direct_inspect=True)
    state = _build_4kb_state()

    def fn() -> None:
        app.invoke(state, config={"configurable": {"thread_id": "b"}})

    return _time("Tier 1 — direct Lens.inspect_node in each node", fn, iterations)


def _bench_graph_t2(
    label: str, mutate: Callable[[LensConfig], None], iterations: int
) -> Result:
    cfg = _quiet_cfg()
    mutate(cfg)
    lens = Lens(cfg)
    app = _build_graph(lens=lens, wrap_for_redact=True)
    state = _build_4kb_state()

    def fn() -> None:
        app.invoke(state, config={"configurable": {"thread_id": "b"}})

    return _time(label, fn, iterations)


def bench_graph_t2_audit(iterations: int) -> Result:
    return _bench_graph_t2(
        "Tier 2 — audit_signaling only",
        lambda c: setattr(c.tier2.audit_signaling, "enabled", True),
        iterations,
    )


def bench_graph_t2_goal(iterations: int) -> Result:
    return _bench_graph_t2(
        "Tier 2 — goal_guard",
        lambda c: setattr(c.tier2.goal_guard, "enabled", True),
        iterations,
    )


def bench_graph_t2_pii(iterations: int) -> Result:
    return _bench_graph_t2(
        "Tier 2 — pii_redaction",
        lambda c: setattr(c.tier2.pii_redaction, "enabled", True),
        iterations,
    )


def bench_graph_t2_all(iterations: int) -> Result:
    def m(c: LensConfig) -> None:
        c.tier2.goal_guard.enabled = True
        c.tier2.pii_redaction.enabled = True
        c.tier2.audit_signaling.enabled = True
        c.tier2.circuit_breaker.enabled = True

    return _bench_graph_t2("Tier 2 — all node-path features", m, iterations)


# ---------- 2. single tool call ----------


def bench_tool_t1(iterations: int) -> Result:
    lens = Lens(_quiet_cfg())
    args = {"q": "summarise"}

    def fn() -> None:
        lens.inspect_tool_call(tool="search", args=args, thread_id="b")

    return _time("Tier 1 — inspect_tool_call", fn, iterations)


def bench_tool_t2_allowlist(iterations: int) -> Result:
    cfg = _quiet_cfg()
    cfg.tier2.tool_allowlist.enabled = True
    cfg.tier2.tool_allowlist.allowed_tools = ["search"]
    lens = Lens(cfg)
    args = {"q": "summarise"}

    def fn() -> None:
        lens.decide_tool_call(tool="search", args=args, thread_id="b")

    return _time("Tier 2 — tool_allowlist", fn, iterations)


def bench_tool_t2_rate(iterations: int) -> Result:
    cfg = _quiet_cfg()
    cfg.tier2.rate_limit.enabled = True
    cfg.tier2.rate_limit.capacity = 1e12
    cfg.tier2.rate_limit.refill_per_second = 1e12
    lens = Lens(cfg)
    args = {"q": "summarise"}

    def fn() -> None:
        lens.decide_tool_call(tool="search", args=args, thread_id="b")

    return _time("Tier 2 — rate_limit", fn, iterations)


def bench_tool_t2_all(iterations: int) -> Result:
    cfg = _quiet_cfg()
    cfg.tier2.tool_allowlist.enabled = True
    cfg.tier2.tool_allowlist.allowed_tools = ["search"]
    cfg.tier2.rate_limit.enabled = True
    cfg.tier2.rate_limit.capacity = 1e12
    cfg.tier2.rate_limit.refill_per_second = 1e12
    cfg.tier2.circuit_breaker.enabled = True
    cfg.tier2.audit_signaling.enabled = True
    lens = Lens(cfg)
    args = {"q": "summarise"}

    def fn() -> None:
        lens.decide_tool_call(tool="search", args=args, thread_id="b")

    return _time("Tier 2 — all tool-path features", fn, iterations)


# ---------- 3. single checkpoint ----------


def bench_cp_t1(iterations: int) -> Result:
    lens = Lens(_quiet_cfg())
    blob = json.dumps({"v": 1, "ts": "x", "channel_values": {"counter": 1}}).encode()

    def fn() -> None:
        lens.inspect_checkpoint(blob=blob, thread_id="b", direction="write")

    return _time("Tier 1 — inspect_checkpoint", fn, iterations)


def bench_cp_t2(iterations: int) -> Result:
    cfg = _quiet_cfg()
    cfg.tier2.checkpoint_protector.enabled = True
    lens = Lens(cfg)
    blob = json.dumps({"v": 1, "ts": "x", "channel_values": {"counter": 1}}).encode()

    def fn() -> None:
        lens.decide_checkpoint(blob=blob, thread_id="b", direction="write")

    return _time("Tier 2 — checkpoint_protector", fn, iterations)


def bench_cp_t2_hmac(iterations: int) -> Result:
    cfg = _quiet_cfg()
    cfg.tier2.checkpoint_protector.enabled = True
    cfg.tier2.checkpoint_protector.require_hmac = True
    cfg.tier2.checkpoint_protector.signing_key = "k" * 32
    lens = Lens(cfg)
    blob = json.dumps({"v": 1, "ts": "x", "channel_values": {"counter": 1}}).encode()
    sig = lens.checkpoint_protector.sign(blob)
    metadata = {"lens_hmac": sig}

    def fn() -> None:
        lens.decide_checkpoint(
            blob=blob, metadata=metadata, thread_id="b", direction="read"
        )

    return _time("Tier 2 — checkpoint_protector + require_hmac", fn, iterations)


# ---------- output ----------


def _delta(measured: Result, baseline: Result) -> tuple[float, float]:
    lat = measured.p50_ms - baseline.p50_ms
    drop = (1.0 - measured.throughput_per_s / baseline.throughput_per_s) * 100.0
    return lat, drop


def _print_graph_section(
    baseline: Result, rows: list[Result], *, markdown: bool
) -> None:
    title = "5-node graph, ~4 KB state — one full `app.invoke(...)`"
    if markdown:
        print(f"\n### {title}\n")
        print("| Configuration | p50 latency | Overhead (p50) | Throughput drop |")
        print("|---|---|---|---|")
        print(f"| {baseline.label} | {baseline.p50_ms:.2f} ms | — | — |")
        for r in rows:
            lat, drop = _delta(r, baseline)
            print(
                f"| {r.label} | {r.p50_ms:.2f} ms | +{lat:.2f} ms | {drop:+.1f}% |"
            )
    else:
        print(f"\n== {title} ==")
        print(
            f"  {baseline.label:50s}  p50={baseline.p50_ms:.4f} ms  "
            f"tp={baseline.throughput_per_s:.0f}/s"
        )
        for r in rows:
            lat, drop = _delta(r, baseline)
            print(
                f"  {r.label:50s}  p50={r.p50_ms:.4f} ms  "
                f"+{lat:.4f} ms ({drop:+.1f}% tp)"
            )


def _print_micro_section(
    title: str, rows: list[Result], *, unit: str, markdown: bool
) -> None:
    if markdown:
        print(f"\n### {title}\n")
        print(f"| Configuration | p50 latency / {unit} |")
        print("|---|---|")
        for r in rows:
            print(f"| {r.label} | {r.p50_ms * 1000:.1f} µs |")
    else:
        print(f"\n== {title} ==")
        for r in rows:
            print(
                f"  {r.label:50s}  p50={r.p50_ms * 1000:.2f} µs  "
                f"({r.throughput_per_s:,.0f}/s)"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args(argv)
    iters = 200 if args.quick else args.iterations

    print(
        f"# bench: iterations={iters} warmup={WARMUP} "
        f"python={sys.version.split()[0]} "
        f"platform={platform.system()} {platform.release()} {platform.machine()}",
        file=sys.stderr,
    )

    base = bench_graph_baseline(iters)
    graph_rows = [
        bench_graph_t1_callback(iters),
        bench_graph_t1_direct(iters),
        bench_graph_t2_audit(iters),
        bench_graph_t2_goal(iters),
        bench_graph_t2_pii(iters),
        bench_graph_t2_all(iters),
    ]
    _print_graph_section(base, graph_rows, markdown=args.markdown)

    tool_rows = [
        bench_tool_t1(iters),
        bench_tool_t2_allowlist(iters),
        bench_tool_t2_rate(iters),
        bench_tool_t2_all(iters),
    ]
    _print_micro_section(
        "Single tool call — standalone Lens cost",
        tool_rows,
        unit="call",
        markdown=args.markdown,
    )

    cp_rows = [
        bench_cp_t1(iters),
        bench_cp_t2(iters),
        bench_cp_t2_hmac(iters),
    ]
    _print_micro_section(
        "Single checkpoint (≈60-byte JSON blob) — standalone Lens cost",
        cp_rows,
        unit="checkpoint",
        markdown=args.markdown,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
