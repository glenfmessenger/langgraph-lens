# langgraph-lens

[![CI](https://github.com/glenfmessenger/langgraph-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/glenfmessenger/langgraph-lens/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Zero-config runtime observability for LangGraph agents, with opt-in interventions for teams that need to block, redact, or rate-limit.

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

**Compliance requirements that post-hoc log scraping can't satisfy.** Regulated environments need an auditable record that PII was *observed leaving an agent*, with correlation IDs that match the originating run, thread, and node. Tailing LangGraph Server's access logs after the fact doesn't produce this — the agent's intermediate state is opaque to the proxy. langgraph-lens emits per-node and per-checkpoint events with stable correlation IDs derived from `run_id` and `thread_id`, and Tier 2 attaches `X-Lens-Triggered: true` + `X-Lens-Reason` headers (or a `state["__lens__"]` annotation) so downstream callers know inline.

This is not a safety system. It does not provide probabilistic guarantees against adversarial prompts or agent misbehaviour. It provides **operational visibility and runtime instrumentation**, plus a small number of opt-in hard controls for teams that need them.

---

## What it does

langgraph-lens runs as a callback handler inside the LangGraph runtime. The primary path is a `BaseCallbackHandler` subclass registered globally via `LANGGRAPH_LENS=1`; the fallback path is a manual `Lens` instance attached to a specific compiled graph via `graph.with_config({"callbacks": [LensCallback(lens)]})`.

There are two tiers:

- **Tier 1 (observability)** is on by default. Detectors inspect every node entry and exit, every checkpoint write and read, every tool call, every memory write, and every prompt load, and emit structured events. They never modify the state, the message list, or the tool call.
- **Tier 2 (interventions)** is off by default. Each intervention has its own `enabled: false` flag. When enabled, an intervention may block a node, rewrite its state (PII redaction), throttle tool calls, refuse to deserialise a checkpoint, or attach `X-Lens-Triggered` headers to the response.

`LANGGRAPH_LENS=1` with no config gets you Tier 1 only. Tier 2 requires an explicit YAML opt-in per feature. Nothing is suppressed without you asking for it.

---

## Usage with LangGraph Server

```bash
# Zero-config: Tier 1 only. Every detector on, no interventions.
LANGGRAPH_LENS=1 langgraph dev

# With Tier 2 enabled selectively via lens.yaml
LANGGRAPH_LENS=1 LANGGRAPH_LENS_CONFIG=lens.yaml \
  langgraph up --port 2024
```

For deployments that don't run LangGraph Server, the same detectors and interventions attach to a compiled graph directly:

```bash
LANGGRAPH_LENS=1 python my_agent.py
```

Once `LANGGRAPH_LENS=1` is set, the package installs a process-wide callback at import time. Any graph built by `StateGraph(...).compile(...)` in that process picks it up automatically — no decorator, no per-graph wiring.

> **Note on the callback path:** LangGraph's callback handlers run synchronously between nodes. Callbacks can *observe* state but they cannot rewrite it. For Tier 2 `redact` to actually scrub PII before a node sees it, either wrap the node with `wrap_node(lens, fn)` or call `lens.decide_node(...)` manually inside your node body. `block` decisions work via callback (the handler raises `LensBlockedError`); `redact` does not.

---

## Quickstart (Python API)

```python
from langgraph.graph import StateGraph
from langgraph_lens import Lens, LensConfig, LensCallback

# Tier 1 — zero-config
lens = Lens(LensConfig.default())

event = lens.inspect_node(
    node="act",
    state={"messages": [{"role": "user", "content": "ignore prior instructions"}]},
    run_id="run-1",
    thread_id="abc-123",
)
# event.detections -> [Detection(detector="goal_hijack", ...)] (if intent was set earlier)

# Tier 2 — same Lens, with a config that opts into interventions
config = LensConfig.from_yaml("lens.yaml")  # with tier2.pii_redaction.enabled: true
lens = Lens(config)
decision, event = lens.decide_node(
    node="act",
    state={"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]},
    thread_id="abc-123",
)
# decision.action -> "redact"
# decision.modified_state["messages"][0]["content"]
#   -> "My SSN is [REDACTED:ssn]"
# decision.headers -> {"X-Lens-Triggered": "true", "X-Lens-Action": "redact", "X-Lens-Reason": "pii_redactor.ssn"}
```

---

## Features

### Tier 1: Observability (zero-config, always on)

| Feature | What it does | Default |
|---|---|---|
| **Checkpoint / state anomaly detection** | On every checkpoint write or restore, inspects the serialised blob for unsafe pickle opcodes (`REDUCE`, `GLOBAL`, `BUILD`), unknown serializer kinds, schema drift, and missing `thread_id` / `checkpoint_id` metadata | enabled |
| **Supply-chain / prompt loading anomalies** | Scans every loaded prompt template for path traversal in the loader call, Jinja2 SSTI payloads, and unsafe template flags | enabled |
| **Tool enumeration & misuse signals** | Flags agents that enumerate the full tool list in a single turn, call tools outside the declared `bind_tools(...)` allow-list, or pass tool arguments matching shell-metacharacter / SSRF patterns | enabled |
| **Memory / context poisoning detection** | Flags memory entries that look like system-prompt overrides, entries that exceed a size threshold and would dominate retrievals, and writes to keys the current agent shouldn't own | enabled |
| **PII / sensitive data in checkpoints or messages** | Real-time regex scan on node ingress, node egress, and checkpoint blobs: SSN, credit cards, emails, phone numbers, IP addresses, custom patterns | enabled |
| **Agent goal hijack signals** | Compares the current node's effective system prompt and pending tool calls against the originating user message; flags drift | enabled |
| **Inter-agent / graph communication anomalies** | Flags graph traversals that exceed `recursion_limit`, edges traversed that aren't in the declared topology, and `Send(...)` payloads to undeclared subgraphs | enabled |
| **SQL / metadata injection in checkpoint backends** | Scans `thread_id`, `checkpoint_ns`, and any user-controllable filter strings for SQL-injection signatures | enabled |
| **Structured security events** | Every detection is a JSON event with `correlation_id`, `run_id`, `thread_id`, `node`, timestamp, state hash, and reason | enabled |

### Tier 2: Interventions (off by default, opt-in per feature)

| Feature | What it does | Default |
|---|---|---|
| **Hard PII redaction** | Replaces matched PII in the state's message list and string fields with `[REDACTED:<type>]` before forwarding to the next node. Mode: `redact` or `block`. | disabled |
| **Tool allow-list / misuse defense** | Per-graph allow-list of permitted tools + hard block on Tier 1 `shell_metachar` / `ssrf_pattern` / `oversized_args` matches. Mode: `block` (raises `LensBlockedError`) or `log`. | disabled |
| **Checkpoint integrity protection** | Refuses to load a checkpoint blob containing unsafe pickle opcodes. Optionally HMAC-signs blobs on write and verifies on read. Mode: `enforce` (raises) or `log`. | disabled |
| **Agent goal / prompt guard** | Turns Tier 1 `system_prompt_drift` / `tool_call_drift` detections into a terminal `block`. Mode: `block` or `log`. | disabled |
| **Rate limiting on tool calls** | Token-bucket per `tenant \| thread \| tool`, args-size-aware cost. Mode: `throttle` (returns `retry_after`) or `block` (returns 429-equivalent). | disabled |
| **Circuit breaker for cascading failures** | Auto-opens on upstream error rate; optionally opens preemptively when an attack is in progress. | disabled |
| **Audit-proof signaling** | Stamps `X-Lens-Triggered`, `X-Lens-Reason`, `X-Lens-Action` headers on every Tier 2 decision, and optionally writes the same fields into `state["__lens__"]` for downstream nodes. | disabled |

Every Tier 2 block in the YAML carries its own `enabled` flag. Turning on one does not turn on any other. Run any new intervention in `log` / `throttle` mode against production traffic before flipping to `block` / `enforce`.

---

## When events fire

Every detector emits a JSON event when it matches. Events go to the configured destination (stderr by default) and to Prometheus counters. The shape is stable across detectors:

```json
{"event": "node_inspected", "run_id": "run-1", "thread_id": "abc-123", "node": "act", "correlation_id": "8f3a...", "state_hash": "sha256:9b1d...", "detections": [{"detector": "goal_hijack", "rule": "system_prompt_drift", "severity": "high"}], "timestamp": 1769420401.3}
{"event": "checkpoint_inspected", "run_id": "run-1", "thread_id": "abc-123", "checkpoint_id": "01J9...", "correlation_id": "8f3a...", "detections": [{"detector": "checkpoint", "rule": "unsafe_pickle_opcode", "opcode": "REDUCE", "severity": "critical"}], "timestamp": 1769420402.1}
{"event": "tool_call_inspected", "run_id": "run-1", "thread_id": "abc-123", "tool": "shell", "correlation_id": "8f3a...", "detections": [{"detector": "tool", "rule": "shell_metachar", "match": "; rm -rf", "severity": "high"}], "timestamp": 1769420402.4}
{"event": "attack_surface_scan", "correlation_id": "boot-1769420400", "detections": [{"detector": "attack_surface", "rule": "pickle_checkpoint_backend", "saver": "PostgresSaver", "severity": "high"}], "timestamp": 1769420400.0}
{"event": "prompt_scan", "correlation_id": "load-1769420400", "prompt_path": "/prompts/system.jinja2", "detections": [{"detector": "supply_chain", "rule": "jinja_ssti", "file": "system.jinja2", "severity": "critical"}], "timestamp": 1769420400.2}
```

`correlation_id` is stable across every event from the same `(run_id, thread_id)` so the chain can be reconstructed. `state_hash` is a SHA-256 of the canonicalised state dict at the moment of inspection — useful for deduping retries and for matching against external audit logs without keeping the state contents themselves.

### Inline signaling — Tier 2

When a Tier 2 intervention fires, the lens also signals to the caller inline:

| Action | Behaviour | Headers set on the decision |
|---|---|---|
| `allow` (Tier 1 detection only) | Pass through | `X-Lens-Triggered: true`, `X-Lens-Reason: <detector>.<rule>,...` (if `audit_signaling.enabled`) |
| `redact` (PII redactor) | `decision.modified_state` is the scrubbed state; caller forwards that instead | `X-Lens-Triggered: true`, `X-Lens-Action: redact`, `X-Lens-Reason: pii_redactor.<type>` |
| `throttle` (rate limiter) | `decision.retry_after` is set; caller sleeps and retries, or returns it to the user | `X-Lens-Triggered: true`, `X-Lens-Action: throttle`, `Retry-After: <s>` |
| `block` (allowlist, goal guard, circuit, checkpoint protector, rate limit in `block` mode) | `LensBlockedError` raised through the callback; `decision.status_code` is the HTTP-equivalent | `X-Lens-Triggered: true`, `X-Lens-Action: block`, `X-Lens-Reason: <rule>`, `Retry-After: <s>` (for rate limit / circuit) |

From a plain Python entry point, the headers live on `decision.headers` for the caller to use however they want — there is no built-in HTTP middleware in this release, so the caller is responsible for relaying them onto the outgoing response if they want HTTP-level signaling. With `audit_signaling.stamp_state: true`, the same fields are written into `state["__lens__"]` so downstream nodes can read them programmatically without HTTP at all.

### Limitations

- **Callbacks observe, they don't rewrite.** Tier 2 `redact` requires `wrap_node(lens, fn)` or a manual `lens.decide_node(...)` call inside the node body; the `LensCallback` alone can't substitute a modified state.
- **Checkpoint protection is structural.** It refuses unsafe pickle opcodes and (optionally) HMAC-mismatched blobs. It does not validate the *content* of an otherwise-well-formed checkpoint against any schema beyond what Tier 1 already inspects.
- **Goal-guard is heuristic.** The underlying Tier 1 goal-hijack detector compares the originating user message to the current node's effective system prompt; it will produce false positives when an agent legitimately broadens its scope mid-run. The Tier 2 wrapper only blocks on `system_prompt_drift` and `tool_call_drift` by default — `off_topic_subgoal` (medium severity) is intentionally excluded.
- **Rate limiting is in-process.** The token bucket lives in the lens instance. In a multi-worker LangGraph Server deployment, each worker has its own bucket. For a shared limiter, run the lens behind a single ingress.

---

## Configuration

### YAML config

Tier 1 stays at its defaults if you don't override. Tier 2 stays off if you don't override. The example below shows the shape of every block; see `lens.yaml` in the repo for the fully-commented version.

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

# Tier 2 — interventions (every block defaults to disabled)
tier2:
  pii_redaction:
    enabled: false
    mode: redact                       # redact | block
    patterns:
      - type: ssn
      - type: credit_card
      - type: email

  tool_allowlist:
    enabled: false
    mode: block                        # block | log
    allowed_tools: ["search", "calculator"]
    block_on_rules: ["shell_metachar", "ssrf_pattern", "oversized_args"]

  checkpoint_protector:
    enabled: false
    mode: enforce                      # enforce | log
    block_on_rules: ["unsafe_pickle_opcode"]
    require_hmac: false
    signing_key: ""

  goal_guard:
    enabled: false
    mode: block                        # block | log
    block_on_rules: ["system_prompt_drift", "tool_call_drift"]

  rate_limit:
    enabled: false
    mode: throttle                     # throttle | block
    capacity: 60
    refill_per_second: 1.0
    key_by_tenant: true
    key_by_thread: true
    key_by_tool: false

  circuit_breaker:
    enabled: false
    window_seconds: 30
    min_samples: 20
    error_rate_threshold: 0.5
    cooldown_seconds: 30
    fail_closed_on_attack: false

  audit_signaling:
    enabled: false
    stamp_state: false
```

### Inline config

```python
from langgraph_lens.config import (
    LensConfig, Tier2Config,
    PIIRedactionConfig, PIIPattern,
    ToolAllowlistConfig,
    GoalGuardConfig,
)

config = LensConfig(
    tier2=Tier2Config(
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            mode="redact",
            patterns=[PIIPattern(type="ssn"), PIIPattern(type="email")],
        ),
        tool_allowlist=ToolAllowlistConfig(
            enabled=True,
            mode="block",
            allowed_tools=["search", "calculator"],
        ),
        goal_guard=GoalGuardConfig(enabled=True, mode="block"),
    ),
)
```

### One-line launches

```bash
# Zero-config Tier 1 only.
LANGGRAPH_LENS=1 langgraph dev

# Tier 2 enabled — every flag stays where you put it in lens.yaml.
LANGGRAPH_LENS=1 LANGGRAPH_LENS_CONFIG=lens.yaml langgraph up --port 2024

# Same lens.yaml for a script-mode agent.
LANGGRAPH_LENS=1 LANGGRAPH_LENS_CONFIG=lens.yaml python my_agent.py
```

Python — Tier 2 around a compiled graph:

```python
from langgraph_lens import Lens, LensCallback, LensConfig, wrap_node, LensBlockedError

lens = Lens(LensConfig.from_yaml("lens.yaml"))

graph.add_node("act", wrap_node(lens, act_node, node="act"))   # for redaction
app = graph.compile(checkpointer=MemorySaver())

try:
    result = app.invoke(
        state,
        config={
            "configurable": {"thread_id": "abc-123"},
            "callbacks": [LensCallback(lens, enforce_blocks=True)],
        },
    )
except LensBlockedError as e:
    print(f"blocked: {e.decision.reason}", e.decision.headers)
```

---

## PII patterns

Built-in patterns for common PII types. The same set is used by the Tier 1 detector and the Tier 2 redactor.

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

Tier 1:

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

Tier 2 (stays at zero unless an intervention is enabled):

```
langgraph_lens_tier2_blocked_total{reason="tool_blocked|rate_limited|goal_hijack|checkpoint_rejected|circuit_open|..."}
langgraph_lens_tier2_redacted_total{reason="pii_redactor|..."}
langgraph_lens_tier2_throttled_total{reason="rate_limited"}
langgraph_lens_circuit_state                     # 0=closed, 1=half_open, 2=open
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

Each emitted event becomes its own span (`node_inspected`, `checkpoint_inspected`, `tool_call_inspected`, `prompt_scan`, `attack_surface_scan`). Detections within an event are attached as span events on that span. The lens's `correlation_id`, `run_id`, `thread_id`, and `node` are set as span attributes (`langgraph.correlation_id`, `langgraph.run_id`, `langgraph.thread_id`, `langgraph.node`). OpenTelemetry's `trace_id` is generated by the SDK independently of the lens's correlation_id — use the attribute to join with the lens's structured-event log.

> **Verified at:** import time only. The OTel bridge initialises cleanly when `pip install "langgraph-lens[otel]"` is satisfied, but no end-to-end test in this release points it at a real OTLP collector. Treat it as alpha until you've smoke-tested against your own collector.

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

> **Verified at:** message-construction time only. The Slack POST goes through `urllib.request.urlopen` to whatever URL you configure, but no end-to-end test in this release delivers a real message to a real Slack webhook. The format-and-cooldown logic is unit-tested; the network path is not.

---

## Performance

All numbers below are measured by `bench/bench.py` — no estimates. To reproduce, run:

```bash
pip install -e ".[dev]"
python bench/bench.py --markdown
```

**Test rig:** Apple M2 (8 cores), 8 GiB RAM, macOS 26.5, Python 3.13.7, LangGraph 1.2.1, LangChain Core 1.4.0. 2000 iterations per row, 200-iteration warm-up, GC disabled inside the timed loop. Single-threaded. Local laptop, not a production-class box — your absolute numbers will differ, but the *relative* costs (callback vs direct, with/without each Tier 2 feature) should be representative.

### Whole-graph invoke — 5-node graph, ~4 KB state

One full `app.invoke(...)` on a `StateGraph` with five sequential nodes and a `MemorySaver`. Baseline is the same graph with no lens at all.

| Configuration | p50 latency | Overhead (p50) | Throughput drop |
|---|---|---|---|
| baseline (no lens) | 1.38 ms | — | — |
| Tier 1 — callback handler | 1.74 ms | +0.36 ms | +19.1% |
| Tier 1 — direct `Lens.inspect_node` in each node | 1.62 ms | +0.24 ms | +12.9% |
| Tier 2 — `audit_signaling` only | 1.61 ms | +0.23 ms | +14.1% |
| Tier 2 — `goal_guard` | 1.58 ms | +0.20 ms | +10.2% |
| Tier 2 — `pii_redaction` | 2.29 ms | +0.92 ms | +38.4% |
| Tier 2 — all node-path features (`audit + goal + pii + circuit`) | 2.31 ms | +0.94 ms | +39.7% |

The callback path is slightly more expensive than direct inspection because LangChain's callback manager dispatches a `RunManager` per node — the lens itself runs the same code in both cases. The callback handler filters to real LangGraph nodes (via the `langgraph_node` metadata key) and only emits the egress event once at the outer run boundary, which avoids 7 of the 12 callback fires LangChain would otherwise dispatch for a 5-node graph; that filter is what closes the gap to the direct path.

`pii_redaction` is the most expensive Tier 2 feature on the node path: it deep-copies the state, walks the message list, runs every configured pattern, and re-serialises the modified copy. If you don't need redaction, leaving it off is the single biggest perf win.

### Standalone Tier 1 / Tier 2 cost — single tool call

These rows are the absolute cost of one `lens.inspect_tool_call(...)` or `lens.decide_tool_call(...)`. There is no meaningful "baseline" — a tool call without the lens is a no-op — so latencies are reported in microseconds rather than as a percentage delta.

| Configuration | p50 latency / call |
|---|---|
| Tier 1 — `inspect_tool_call` | 22.0 µs |
| Tier 2 — `tool_allowlist` (via `decide_tool_call`) | 78.8 µs |
| Tier 2 — `rate_limit` (via `decide_tool_call`) | 26.0 µs |
| Tier 2 — all tool-path features (`allowlist + rate_limit + circuit + audit`) | 83.0 µs |

`tool_allowlist` is the most expensive tool-path intervention because it re-runs the entire Tier 1 misuse-detection set (shell-metachar, SSRF, oversized args) against the args. `rate_limit` is essentially free.

### Standalone Tier 1 / Tier 2 cost — single checkpoint

A 60-byte JSON checkpoint blob (no pickle, no large state). The cost scales with blob size for the opcode scan; this is the floor.

| Configuration | p50 latency / checkpoint |
|---|---|
| Tier 1 — `inspect_checkpoint` | 3.6 µs |
| Tier 2 — `checkpoint_protector` | 5.4 µs |
| Tier 2 — `checkpoint_protector + require_hmac` | 7.0 µs |

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

- Python ≥ 3.10 (tested locally on 3.13; CI runs 3.10 / 3.11 / 3.12)
- LangGraph ≥ 0.2.50 declared as the minimum, but verified against LangGraph 1.2.1 + LangChain Core 1.4.0 only. Older versions may work — the `BaseCallbackHandler` interface has been stable since 0.2.50 — but are untested.
- Optional: `langgraph-checkpoint-postgres` or `langgraph-checkpoint-sqlite` if you want the SQL-injection detector wired into the actual saver call. The detector is unit-tested against synthetic metadata; the real-saver path is not tested.

## Maintenance and compatibility

This is a v0.2.0 release. The end-to-end paths verified are: the global `LANGGRAPH_LENS=1` callback install on LangChain Core 1.4.0, the per-graph `LensCallback(lens)` attachment, and the `wrap_node(lens, fn)` redaction helper against a compiled `StateGraph` + `MemorySaver`. The Postgres/SQLite/Redis savers, LangGraph Server (`langgraph dev`, `langgraph up`), and multi-worker deployments are not exercised in CI or the benchmark.

If you find it works on other versions, PRs and issue reports are welcome. If you find it breaks, open an issue with the LangGraph version and error — but fixes depend on available time.

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

68 pytest cases in total. Coverage is *uneven across rules* — every detector has at least one positive test, but not every rule within a detector does. The honest breakdown:

- **Tier 1 detectors** — every detector module has positive tests for its most-load-bearing rules. Some lower-severity or harder-to-trigger rules (e.g. `unsafe_chat_template`, `unsigned_hub_pull`, `oversized_blob`, `unknown_serializer_kind`, `off_topic_subgoal`, `tool_call_drift`, `send_to_undeclared_target`, `oversized_state_growth`, three of four SQL-injection rules) ship without an explicit positive test. They're exercised through the static rule list in the detector code, but a contribution adding direct tests is welcome.
- **Lens orchestrator** (`tests/test_lens.py`, `test_config.py`) — correlation IDs, state hashing, YAML roundtrip, defaults invariant.
- **Tier 2 interventions** (`tests/interventions/`) — every intervention has positive tests for both modes (`block`/`log` or `redact`/`throttle`) and the disabled-passthrough case. The PII redactor specifically verifies multi-pattern messages and the deep-copy property (caller's state is not mutated). The checkpoint protector exercises the HMAC sign/verify roundtrip plus the mismatched-HMAC block path.
- **Decision composition** (`tests/test_decide.py`) — the orchestration path through `Lens.decide_node` / `decide_tool_call` / `decide_checkpoint`: short-circuit on block, header merging, audit-headers-absent-when-nothing-fires, `wrap_node` redaction round-trip, `wrap_node` raising `LensBlockedError`, and the attack-signal feed into the circuit breaker.
- **Real-graph end-to-end** — `bench/bench.py` builds an actual compiled `StateGraph` with `MemorySaver` and exercises the callback path, the direct `inspect_node` path, and the `wrap_node` redaction path for every Tier 2 feature. It runs ~6.8 k iterations of `app.invoke(...)` per full benchmark pass.

---

## License

Apache 2.0
