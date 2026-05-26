# langgraph-lens

[![CI](https://github.com/glenfmessenger/langgraph-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/glenfmessenger/langgraph-lens/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Zero-config runtime observability for LangGraph agents — checkpoint, prompt-supply-chain, tool, memory, PII, goal-hijack, inter-agent, and SQL-injection detectors emitted as structured events.

## Try it in 30 seconds

A checked-in synthetic CVE-2026-34070 canary lives at `demo/malicious-prompt/`. From a clean Python 3.10+ environment:

```bash
git clone https://github.com/glenfmessenger/langgraph-lens
cd langgraph-lens
pip install .
langgraph-lens scan-prompt demo/malicious-prompt/
```

You'll get a `supply_chain/jinja_ssti` detection at severity `critical` and a non-zero exit code. Re-run against any normal prompt directory and the same command exits cleanly. See [`demo/README.md`](demo/README.md) for the full canary write-up.

---

## Why

**February 2026 LangGraph checkpoint RCEs.** On 25 February 2026, **CVE-2026-27794** was disclosed — a remote code execution vulnerability in the LangGraph checkpoint caching layer caused by unsafe pickle fallback in `JsonPlusSerializer`. A follow-up issue (**CVE-2026-28277**) exposed unsafe msgpack deserialization in checkpoint loading. Any operator using persistent checkpoints (Postgres, SQLite, Redis, etc.) who allowed untrusted or multi-tenant thread resumption was affected. langgraph-lens detects and logs unsafe pickle opcodes and unknown serializer kinds in every checkpoint it sees, before the runtime hands them to the deserialiser.

**Supply-chain risk in shared prompt registries — CVE-2026-34070.** LangChain Hub and self-hosted prompt registries distribute Jinja2 chat templates as opaque text. **CVE-2026-34070** (March 2026) allows path traversal and unsafe Jinja2 SSTI when `ChatPromptTemplate.from_template(..., template_format="jinja2")` renders a malicious template. langgraph-lens scans every prompt on load and emits a structured event for any pattern matching known-bad template signatures or path-traversal sequences in the loader call.

**Compliance requirements that post-hoc log scraping can't satisfy.** Regulated environments need an auditable record that PII was *observed leaving an agent*, with correlation IDs that match the originating run, thread, and node. Tailing LangGraph Server's access logs after the fact doesn't produce this — the agent's intermediate state is opaque to the proxy. langgraph-lens emits per-node and per-checkpoint events with stable correlation IDs derived from `run_id` and `thread_id`, so every detection can be joined back to the user-facing invocation that produced it.

This is not a safety system. It does not provide probabilistic guarantees against adversarial prompts or agent misbehaviour. It provides **operational visibility and runtime instrumentation** — structured events, Prometheus metrics, and OpenTelemetry spans — that make a LangGraph deployment auditable.

---

## What it does

langgraph-lens runs as a callback handler inside the LangGraph runtime. The primary path is a `BaseCallbackHandler` subclass registered globally via `LANGGRAPH_LENS=1`; the fallback path is a manual `Lens` instance attached to a specific compiled graph via `graph.with_config({"callbacks": [LensCallback(lens)]})`.

There is one tier:

- **Tier 1 (observability)** is on by default. Detectors inspect every node entry and exit, every checkpoint write and read, every tool call, every memory write, and every prompt load. They emit structured events. They never modify the state, the message list, or the tool call, and they never raise inside the agent loop.

`LANGGRAPH_LENS=1` with no config gets you Tier 1. Nothing is suppressed without you asking for it.

> **Tier 2 (interventions — block, redact, rate-limit, enforce) is out of scope for this release.** A separate `langgraph-lens-tier2` package is planned. This repository contains observability only.

---

## Usage with LangGraph Server

```bash
# Zero-config: Tier 1. Every detector on, no interventions.
LANGGRAPH_LENS=1 langgraph dev

# With a custom config
LANGGRAPH_LENS=1 LANGGRAPH_LENS_CONFIG=lens.yaml \
  langgraph up --port 2024
```

For deployments that don't run LangGraph Server, the same detectors attach to a compiled graph directly:

```bash
LANGGRAPH_LENS=1 python my_agent.py
```

Once `LANGGRAPH_LENS=1` is set, the package installs a process-wide callback at import time. Any graph built by `StateGraph(...).compile(...)` in that process picks it up automatically — no decorator, no per-graph wiring.

> **Note on the callback path:** LangGraph's callback handlers run synchronously between nodes. Supply-chain prompt scanning, which has to read template files from disk, happens lazily on the first `PromptTemplate` load and is cached by template hash so subsequent runs of the same graph don't re-scan.

---

## Quickstart (Python API)

```python
from langgraph.graph import StateGraph
from langgraph_lens import Lens, LensConfig, LensCallback

# Tier 1 — zero-config
lens = Lens(LensConfig.default())

graph = StateGraph(MyState)
graph.add_node("plan", plan_node)
graph.add_node("act", act_node)
graph.add_edge("plan", "act")
graph.set_entry_point("plan")
app = graph.compile(checkpointer=MemorySaver())

# Attach the lens to this graph only.
result = app.invoke(
    {"input": "summarise this PDF"},
    config={
        "configurable": {"thread_id": "abc-123"},
        "callbacks": [LensCallback(lens)],
    },
)

# Detections from this run, joined by correlation_id:
events = lens.events_for_thread("abc-123")
# [Event(event=node_inspected, detections=[Detection(detector=goal_hijack, ...)]), ...]
```

Direct inspection — no callbacks, useful in tests:

```python
event = lens.inspect_node(
    node="act",
    state={"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]},
    run_id="run-1",
    thread_id="abc-123",
)
# event.detections -> [Detection(detector="pii", rule="ssn", severity="high", ...)]
```

---

## Features

### Tier 1: Observability (zero-config, always on)

| Feature | What it does | Default |
|---|---|---|
| **Checkpoint / state anomaly detection** | On every checkpoint write or restore, inspects the serialised blob for unsafe pickle opcodes (`REDUCE`, `GLOBAL`, `BUILD`), unknown serializer kinds, schema drift, and missing `thread_id` / `checkpoint_id` metadata | enabled |
| **Supply-chain / prompt loading anomalies** | Scans every loaded prompt template for path traversal in the loader call (`../../etc/passwd`), Jinja2 SSTI payloads (`{{ ''.__class__.__mro__ }}`), and unsafe template flags (`autoescape=False` on user-controllable inputs) | enabled |
| **Tool enumeration & misuse signals** | Flags agents that enumerate the full tool list in a single turn, call tools outside the declared `bind_tools(...)` allow-list, or pass tool arguments matching shell-metacharacter / SSRF patterns | enabled |
| **Memory / context poisoning detection** | On every memory store write, flags entries that look like system-prompt overrides (`you are now`, `ignore previous`), entries that exceed a size threshold and would dominate retrievals, and writes to keys the current agent shouldn't own | enabled |
| **PII / sensitive data in checkpoints or messages** | Real-time regex scan on node ingress, node egress, and checkpoint blobs: SSN, credit cards, emails, phone numbers, IP addresses, custom patterns | enabled |
| **Agent goal hijack signals** | Compares the current node's effective system prompt and pending tool calls against the originating user message; flags drift such as the system prompt suddenly mentioning `transfer funds` when the user asked for a recipe | enabled |
| **Inter-agent / graph communication anomalies** | Flags graph traversals that exceed `recursion_limit` early, edges traversed that aren't in the declared topology, and `Send(...)` payloads to subgraphs the current node didn't declare as targets | enabled |
| **SQL / metadata injection in checkpoint backends** | Scans `thread_id`, `checkpoint_ns`, and any user-controllable filter strings passed to `SqliteSaver` / `PostgresSaver` for SQL-injection signatures and metadata-key escape sequences | enabled |
| **Structured security events** | Every detection is a JSON event with `correlation_id`, `run_id`, `thread_id`, `node`, timestamp, state hash, and reason | enabled |

Every Tier 1 detector can be tuned via `lens.yaml`, but each one is enabled by default. There is no detector that requires opt-in.

---

## When events fire

Every detector emits a JSON event when it matches. Events go to the configured destination (stderr by default) and to Prometheus counters. The shape is stable across detectors:

```json
{"event": "node_inspected", "run_id": "run-1", "thread_id": "abc-123", "node": "act", "correlation_id": "8f3a...", "state_hash": "sha256:9b1d...", "detections": [{"detector": "goal_hijack", "rule": "system_prompt_drift", "severity": "high"}], "timestamp": 1769420401.3}
{"event": "checkpoint_inspected", "run_id": "run-1", "thread_id": "abc-123", "checkpoint_id": "01J9...", "correlation_id": "8f3a...", "detections": [{"detector": "checkpoint", "rule": "unsafe_pickle_opcode", "opcode": "REDUCE", "severity": "critical"}], "timestamp": 1769420402.1}
{"event": "tool_call_inspected", "run_id": "run-1", "thread_id": "abc-123", "tool": "shell", "correlation_id": "8f3a...", "detections": [{"detector": "tool", "rule": "shell_metachar", "match": "; rm -rf", "severity": "high"}], "timestamp": 1769420402.4}
{"event": "memory_inspected", "run_id": "run-1", "thread_id": "abc-123", "key": "user_pref", "detections": [{"detector": "memory", "rule": "system_prompt_override", "severity": "high"}], "timestamp": 1769420402.6}
{"event": "attack_surface_scan", "correlation_id": "boot-1769420400", "detections": [{"detector": "attack_surface", "rule": "pickle_checkpoint_backend", "saver": "PostgresSaver", "severity": "high"}], "timestamp": 1769420400.0}
{"event": "prompt_scan", "correlation_id": "load-1769420400", "prompt_path": "/prompts/system.jinja2", "detections": [{"detector": "supply_chain", "rule": "jinja_ssti", "file": "system.jinja2", "severity": "critical"}], "timestamp": 1769420400.2}
```

`correlation_id` is stable across every event from the same run/thread so the chain can be reconstructed. `state_hash` is a SHA-256 of the canonicalised state dict at the moment of inspection — useful for deduping retries and for matching against external audit logs without keeping the state contents themselves.

### Joining events back to a run

Every event carries the LangGraph-native triple `(run_id, thread_id, node)` in addition to the lens-generated `correlation_id`. The triple is what LangSmith and LangGraph Server already log against, so events joined on those fields will line up with any existing dashboards.

### Limitations

- **The lens does not modify state.** If a `tool/shell_metachar` detection fires, the tool call still runs. The signal goes to logs and metrics; deciding what to do with it is the operator's problem. Tier 2 (planned, separate package) is where blocking lives.
- **Checkpoint blob scanning is structural, not semantic.** It looks for unsafe pickle opcodes and unknown serializer kinds, not for application-layer secrets buried in legitimately-shaped state. The PII detector catches the latter on a best-effort basis.
- **Goal-hijack detection is heuristic.** The detector compares the *originating* user message to the current node's effective system prompt and pending tool calls; it will produce false positives when an agent legitimately broadens its scope mid-run. Tune via `goal_hijack.user_intent_similarity_threshold` if your workload is genuinely multi-step.
- **The callback handler runs synchronously between nodes.** A node that takes 20 seconds will not be interrupted; detections for that node arrive at egress, not mid-execution.

---

## Configuration

### YAML config

Tier 1 stays at its defaults if you don't override. The example below shows the shape of every block; see `lens.yaml` in the repo for the fully-commented version.

```yaml
# lens.yaml

# Tier 1 — observability (defaults shown)
attack_surface:  { enabled: true }
checkpoint:      { enabled: true, scan_on_write: true, scan_on_read: true }
supply_chain:    { enabled: true, scan_on_load: true }
tool:            { enabled: true }
memory:          { enabled: true }
pii:             { enabled: true, scan_ingress: true, scan_egress: true }
goal_hijack:     { enabled: true, user_intent_similarity_threshold: 0.35 }
comms:           { enabled: true }
sql_injection:   { enabled: true }
prometheus:      { enabled: true, port: 9092 }
logging:         { enabled: true, destination: stderr, format: json }
alerts:          { enabled: false, slack_webhook: "" }
```

### Inline config

```python
from langgraph_lens.config import (
    LensConfig,
    CheckpointConfig,
    PIIConfig, PIIPattern,
    GoalHijackConfig,
)

config = LensConfig(
    checkpoint=CheckpointConfig(enabled=True, scan_on_write=True, scan_on_read=True),
    pii=PIIConfig(
        enabled=True,
        scan_ingress=True,
        scan_egress=True,
        patterns=[PIIPattern(type="ssn"), PIIPattern(type="email")],
    ),
    goal_hijack=GoalHijackConfig(enabled=True, user_intent_similarity_threshold=0.35),
)
```

---

## PII patterns

Built-in patterns for common PII types. The same set is used by the node-ingress, node-egress, and checkpoint-scan paths.

| Type | Example match |
|---|---|
| `ssn` | `123-45-6789` |
| `credit_card` | `4111 1111 1111 1111` (Luhn-validated) |
| `phone_us` | `(555) 867-5309` |
| `phone_intl` | `+44 7911 123456` |
| `email` | `user@example.com` |
| `ip_address` | `192.168.1.1` |

**Limitations:** detection is regex-based and runs on the decoded state dict, message list, and checkpoint blob (after the lens decodes msgpack/JSON-Plus). Binary tensors and BLOB columns are not scanned. A pattern that straddles a streaming-chunk boundary in `astream_events` is inspected at the next checkpoint, not per chunk.

---

## Observability

### Prometheus metrics

Scrape at `http://localhost:9092/metrics`.

```
langgraph_lens_attack_surface_detections_total{rule="pickle_checkpoint_backend|..."}
langgraph_lens_checkpoint_detections_total{rule="unsafe_pickle_opcode|schema_drift|..."}
langgraph_lens_supply_chain_detections_total{rule="jinja_ssti|path_traversal|unsafe_chat_template"}
langgraph_lens_tool_detections_total{rule="shell_metachar|enumeration|out_of_allowlist|..."}
langgraph_lens_memory_detections_total{rule="system_prompt_override|oversized_entry|..."}
langgraph_lens_pii_detections_total{type="ssn|email|...",direction="ingress|egress|checkpoint"}
langgraph_lens_goal_hijack_detections_total{rule="system_prompt_drift|tool_call_drift"}
langgraph_lens_comms_detections_total{rule="undeclared_edge|recursion_exceeded|..."}
langgraph_lens_sql_injection_detections_total{rule="union_select|comment_terminator|..."}
langgraph_lens_nodes_inspected_total
langgraph_lens_checkpoints_inspected_total
langgraph_lens_inspection_duration_seconds{stage="node_ingress|node_egress|checkpoint|tool|memory"}
```

**Multiprocess server:** if LangGraph Server forks workers, set `PROMETHEUS_MULTIPROC_DIR` before starting so metrics from all workers are merged:

```bash
mkdir -p /tmp/prometheus_multiproc
export PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus_multiproc
```

### OpenTelemetry

```bash
pip install "langgraph-lens[otel]"
```

```yaml
otel:
  enabled: true
  endpoint: http://localhost:4318
  service_name: langgraph-agent
  export_traces: true
  export_metrics: true
```

Each inspected node becomes a span; checkpoint scans become a span event under the parent run span. Correlation IDs propagate as the span's `trace_id`. LangGraph's own `run_id` is attached as a span attribute (`langgraph.run_id`) so spans line up with anything LangSmith already exports.

### Slack / webhook alerts

```yaml
alerts:
  enabled: true
  slack_webhook: https://hooks.slack.com/services/...
  cooldown_seconds: 300
  alert_on:
    - supply_chain
    - attack_surface
    - checkpoint
    - goal_hijack
```

Alerts default to `supply_chain`, `attack_surface`, and `checkpoint` only. PII and tool detections are intentionally excluded from default alerts because they fire often and create noise — log them, dashboard them, but don't page on them.

---

## Performance

Measured on an m7i.2xlarge running LangGraph 0.3.x, a 5-node graph with a `MemorySaver`, payload size p50=4KB. Inspection runs synchronously between nodes.

| Workload | Path | Overhead (p50 latency) | Overhead (throughput) |
|---|---|---|---|
| Sequential 5-node graph, 4KB state | Callback handler | +0.8 ms / node | -2.1% |
| Sequential 5-node graph, 4KB state | Direct `Lens.inspect_node` | +0.6 ms / node | -1.5% |
| Streaming `astream_events`, 500 tokens | Callback handler | +1.1 ms / checkpoint | -2.9% |
| Streaming `astream_events`, 500 tokens | Direct `Lens.inspect_node` | +0.9 ms / checkpoint | -2.2% |

Checkpoint scanning dominates the cost on graphs that checkpoint after every node. Setting `checkpoint.scan_on_read: false` cuts overhead roughly in half on resumed threads, at the cost of not catching pre-existing unsafe-pickle blobs at resume time.

---

## CLI

```bash
langgraph-lens validate lens.yaml            # validate config before deploying
langgraph-lens scan-prompt /path/to/prompts  # one-shot supply-chain scan, no runtime needed
langgraph-lens scan-checkpoint thread.jsonl  # one-shot checkpoint blob scan
langgraph-lens check                         # check that the lens is loaded and metrics are up
langgraph-lens version
```

`scan-prompt` is the most useful entry point during prompt-registry intake: point it at a freshly pulled prompt directory and get a structured event for anything suspicious before you wire the prompt into a graph.

`scan-checkpoint` accepts a JSON-lines export of a checkpoint table (one blob per line) and is useful for sweeping a database of existing threads before upgrading to a hardened serializer.

---

## Requirements

- Python ≥ 3.10
- LangGraph ≥ 0.2.50 (for the `BaseCallbackHandler` integration path)
- LangChain Core ≥ 0.3.0 (transitive dependency, for prompt scanning)
- Optional: `langgraph-checkpoint-postgres` or `langgraph-checkpoint-sqlite` if you want the SQL-injection detector wired into the actual saver call

## Maintenance and compatibility

This is a v0.1.0 release targeting LangGraph 0.2.x and 0.3.x. LangGraph's callback handler interface and checkpoint serialiser are still pre-1.0 and shift between minor versions. This project tracks the `BaseCallbackHandler` ABI documented for 0.2.50+; compatibility with later versions is untested and not guaranteed.

If you find it works on a newer version, PRs and issue reports are welcome. If you find it breaks, open an issue with the LangGraph version and error — but fixes depend on available time.

---

## Development

```bash
git clone https://github.com/glenfmessenger/langgraph-lens
cd langgraph-lens
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest tests/ -v
ruff check src/
mypy src/langgraph_lens/
```

Tests covering every detector rule:

- **Tier 1 detectors** (`tests/test_checkpoint.py`, `test_supply_chain.py`, `test_tool.py`, `test_memory.py`, `test_pii.py`, `test_goal_hijack.py`, `test_comms.py`, `test_sql_injection.py`) — every rule has at least one positive test, most have explicit negative controls. The checkpoint suite exercises real JSON-Plus blobs and msgpack frames generated at test time; the supply-chain suite includes a known-bad Jinja2 SSTI fixture.
- **Lens orchestrator** (`tests/test_lens.py`, `test_config.py`) — correlation IDs, state hashing, YAML roundtrip, defaults invariant, callback-handler wiring against a stub `StateGraph`.

---

## License

Apache 2.0
