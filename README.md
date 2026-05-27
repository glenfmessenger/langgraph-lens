# langgraph-lens

[![CI](https://github.com/glenfmessenger/langgraph-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/glenfmessenger/langgraph-lens/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/langgraph-lens.svg)](https://pypi.org/project/langgraph-lens/)
[![Python](https://img.shields.io/pypi/pyversions/langgraph-lens.svg)](https://pypi.org/project/langgraph-lens/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/glenfmessenger/langgraph-lens/blob/main/LICENSE)

Zero-config runtime observability for LangGraph agents, with opt-in interventions for teams that need to block, redact, or rate-limit.

## Try it in 30 seconds

A checked-in synthetic CVE-2026-34070 canary lives at `demo/malicious-prompt/`. From a clean Python 3.10+ environment:

```bash
git clone https://github.com/glenfmessenger/langgraph-lens
cd langgraph-lens
pip install .
langgraph-lens scan-prompt demo/malicious-prompt/
```

You'll get a `supply_chain/jinja_ssti` detection at severity `critical` and a non-zero exit code. Re-run against any normal prompt directory and the same command exits cleanly. See [`demo/README.md`](https://github.com/glenfmessenger/langgraph-lens/blob/main/demo/README.md) for the full canary write-up.

---

## What it does

langgraph-lens runs as a callback handler inside the LangGraph runtime. The primary path is a `BaseCallbackHandler` subclass registered globally via `LANGGRAPH_LENS=1`; the fallback path is a manual `Lens` instance attached to a specific compiled graph via `graph.with_config({"callbacks": [LensCallback(lens)]})`.

There are two tiers:

- **Tier 1 (observability)** is on by default. Detectors inspect every node entry and exit, every checkpoint write and read, every tool call, every memory write, and every prompt load, and emit structured events. They never modify the state, the message list, or the tool call.
- **Tier 2 (interventions)** is off by default. Each intervention has its own `enabled: false` flag. When enabled, an intervention may block a node, rewrite its state (PII redaction), throttle tool calls, refuse to deserialise a checkpoint, or attach `X-Lens-Triggered` headers to the response.

`LANGGRAPH_LENS=1` with no config gets you Tier 1 only. Tier 2 requires an explicit YAML opt-in per feature. Nothing is suppressed without you asking for it.

---

## Why

**February 2026 LangGraph checkpoint RCEs.** On 25 February 2026, **CVE-2026-27794** was disclosed — a remote code execution vulnerability in the LangGraph checkpoint caching layer caused by unsafe pickle fallback in `JsonPlusSerializer`. A follow-up issue (**CVE-2026-28277**) exposed unsafe msgpack deserialization in checkpoint loading. Any operator using persistent checkpoints (Postgres, SQLite, Redis, etc.) who allowed untrusted or multi-tenant thread resumption was affected. langgraph-lens detects and logs unsafe pickle opcodes and unknown serializer kinds in every checkpoint it sees, before the runtime hands them to the deserialiser.

**Supply-chain risk in shared prompt registries — CVE-2026-34070.** LangChain Hub and self-hosted prompt registries distribute Jinja2 chat templates as opaque text. **CVE-2026-34070** (March 2026) allows path traversal and unsafe Jinja2 SSTI when `ChatPromptTemplate.from_template(..., template_format="jinja2")` renders a malicious template. langgraph-lens scans every prompt on load and emits a structured event for any pattern matching known-bad template signatures or path-traversal sequences in the loader call.

**Compliance requirements that post-hoc log scraping can't satisfy.** Regulated environments need an auditable record that PII was *observed leaving an agent*, with correlation IDs that match the originating run, thread, and node. Tailing LangGraph Server's access logs after the fact doesn't produce this — the agent's intermediate state is opaque to the proxy. langgraph-lens emits per-node and per-checkpoint events with stable correlation IDs derived from `run_id` and `thread_id`, and Tier 2 attaches `X-Lens-Triggered: true` + `X-Lens-Reason` headers (or a `state["__lens__"]` annotation) so downstream callers know inline.

This is not a safety system. It does not provide probabilistic guarantees against adversarial prompts or agent misbehaviour. It provides **operational visibility and runtime instrumentation**, plus a small number of opt-in hard controls for teams that need them.

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

> **Verified end-to-end** against a mock OTLP HTTP collector — the collector receives the POST, the protobuf parses to a `node_inspected` span with `langgraph.correlation_id` / `run_id` / `thread_id` / `node` attributes set. Reproduce with the script in [`bench/verify_otel.py`](https://github.com/glenfmessenger/langgraph-lens/blob/main/bench/verify_otel.py).

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

> **Verified end-to-end** against a mock incoming webhook — the lens POSTs a Slack-shaped JSON body (`{"text": "[langgraph-lens] supply_chain detection — rules: jinja_ssti | correlation_id: ..."}`) to the configured URL, the cooldown logic suppresses repeats within `cooldown_seconds`. Reproduce with [`bench/verify_slack.py`](https://github.com/glenfmessenger/langgraph-lens/blob/main/bench/verify_slack.py). Whether Slack accepts the message is between you and your workspace's webhook configuration.

---

## Performance

The lens cost is roughly fixed at **~0.4 ms / `invoke` for Tier 1** and **~1 ms with all Tier 2 node-path features**. Percentage impact scales inversely with how much real work the nodes do:

| Per-node work | Approx. invoke time | Tier 1 drop | All Tier 2 drop |
|---|---|---|---|
| Counter bump (synthetic) | ~1.4 ms | ~22% | ~40% |
| 10 ms (cached lookup, tiny model) — **measured** | ~67 ms | ~2% | ~4% |
| 100 ms (DB query, embedding) | ~500 ms | ~0.3% | ~1% |
| 1 s (LLM call) | ~5 s | ~0.03% | ~0.1% |

A real LangGraph deployment — anything that calls an LLM — sees the lens overhead disappear into the LLM round-trip. The synthetic worst case (`+22%`) measures the lens against nodes that do nothing.

Full per-rule numbers, microbenchmarks, and the test-rig spec are in [`bench/RESULTS.md`](https://github.com/glenfmessenger/langgraph-lens/blob/main/bench/RESULTS.md). Reproduce with:

```bash
pip install -e ".[dev]"
python bench/bench.py --markdown
```

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
- Verified against **LangGraph 1.2.x + LangChain Core 1.4.0** on Python 3.10 / 3.11 / 3.12 / 3.13. The `pyproject.toml` constraint of `langgraph>=1.0` reflects the tested range, not a verified compatibility floor — older 1.0 / 1.1 versions may work but are not exercised in CI.
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

88 pytest cases in total. Coverage is *uneven across rules* — every detector has at least one positive test, but not every rule within a detector does. The honest breakdown:

- **Tier 1 detectors** — every detector module has positive tests for its most-load-bearing rules. The following rules ship without an explicit positive test, exercised only via the static rule list in the detector code: `unsafe_chat_template`, `unsigned_hub_pull`, `oversized_blob`, `unknown_serializer_kind`, `tool_call_drift`, `send_to_undeclared_target`, `oversized_state_growth`, and three of the four SQL-injection rules (`comment_terminator`, `stacked_query`, `metadata_escape`). A contribution adding direct tests is welcome.
- **Lens orchestrator** (`tests/test_lens.py`, `test_config.py`) — correlation IDs, state hashing, YAML roundtrip, defaults invariant.
- **CLI surface** (`tests/test_cli.py`) — every subcommand: `validate`, `version`, `scan-prompt` (clean directory + the canary), `scan-checkpoint` (clean + pickle-tainted JSONL), `check` (live HTTP stub + metrics-absent + unreachable-port).
- **Tier 2 interventions** (`tests/interventions/`) — every intervention has positive tests for both modes (`block`/`log` or `redact`/`throttle`) and the disabled-passthrough case. The PII redactor specifically verifies multi-pattern messages and the deep-copy property (caller's state is not mutated). The checkpoint protector exercises the HMAC sign/verify roundtrip plus the mismatched-HMAC block path.
- **Decision composition** (`tests/test_decide.py`) — the orchestration path through `Lens.decide_node` / `decide_tool_call` / `decide_checkpoint`: short-circuit on block, header merging, audit-headers-absent-when-nothing-fires, `wrap_node` redaction round-trip (including the context-var thread_id fallback), `wrap_node` raising `LensBlockedError`, and the attack-signal feed into the circuit breaker.
- **Real-graph end-to-end** — `bench/bench.py` builds an actual compiled `StateGraph` with `MemorySaver` and exercises the callback path, the direct `inspect_node` path, and the `wrap_node` redaction path for every Tier 2 feature. A full pass runs ~16 k `app.invoke(...)` calls (2000 timed + 200 warmup per synthetic row across 7 rows, plus 200 + 200 per realistic row across 3 rows).
- **Real-LLM end-to-end** — `examples/with_real_llm.py` verified against live OpenAI `gpt-4o-mini`: a user message containing an SSN reaches the wrapped `chat` node as `[REDACTED:ssn]`, the model's response confirms it could not see or echo the original value. Not in CI (no API key); reproducible with `OPENAI_API_KEY=... python examples/with_real_llm.py`.

---

## License

Apache 2.0
