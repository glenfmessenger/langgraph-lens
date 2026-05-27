# Changelog

All notable changes to this project will be documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-05-27

### Added — zero-config integrations (closes the integration gap from v0.2)

The LangChain `BaseCallbackHandler` only fires on chain entry/exit,
tool calls, and LLM calls. Checkpoints, memory-store writes, and
prompt loads happen outside that surface — meaning v0.2's
`LANGGRAPH_LENS=1` Tier 1 feature table overstated what was actually
wired in. This release closes the gap.

- **`langgraph_lens.integrations.protect_saver(saver, lens=None)`** —
  explicit per-instance wrap of any `BaseCheckpointSaver`. Swaps the
  instance's class so `isinstance` still works; falls back to
  in-place class patching for `__slots__`-based savers. Calls
  `lens.decide_checkpoint(...)` on every `put` / `aput` /
  `get_tuple` / `aget_tuple`.
- **`langgraph_lens.integrations.install_saver_auto_protection()`** —
  process-wide patch. Walks every imported `BaseCheckpointSaver`
  subclass and patches its methods in place. Installs an
  `__init_subclass__` hook so packages imported later (the user does
  `from langgraph.checkpoint.postgres import PostgresSaver` after the
  lens loads) also get patched. Called automatically by
  `install_global_callback` when `LANGGRAPH_LENS=1` is set.
- **`langgraph_lens.integrations.protect_store(store, lens=None)`** +
  **`install_store_auto_protection()`** — same shape for `BaseStore`.
  `put` / `aput` calls fire `lens.inspect_memory_write(...)`.
- **`langgraph_lens.integrations.extract_topology(compiled_graph)`** —
  walks a compiled `StateGraph` and returns declared `(from, to)`
  edges. The `Lens.attach_graph(app)` convenience method calls this
  and stores the result; afterwards the comms detector's
  `undeclared_edge` rule fires automatically through the callback
  path.
- **Supply-chain auto-scan in `LensCallback.on_llm_start`** — every
  rendered prompt the LLM is about to see goes through
  `SupplyChainDetector.scan_text`. Catches SSTI signatures that
  survived template rendering.
- **Attack-surface auto-fire** — `Lens.scan_attack_surface(...)` now
  runs once per process on the first node inspection, with
  best-effort `RuntimeInfo` derived from env vars
  (`LANGGRAPH_SERVER`, `LANGGRAPH_AUTH`, `LANGGRAPH_API_KEY`).
- **`Lens.attach_graph(app)`** — new public API to register a
  compiled graph's topology with the lens.

Opt-out for auto-protection: set `LANGGRAPH_LENS_AUTO_PROTECT=0`.

### Security hardening

- **Prometheus bind address now defaults to `127.0.0.1`** (was
  effectively `0.0.0.0` via `prometheus_client.start_http_server`'s
  default). The exporter exposes per-thread detection counts and has
  no built-in auth. New `PrometheusConfig.bind_address` field to
  override.
- **HMAC key validation.** `tier2.checkpoint_protector.require_hmac:
  true` with an empty `signing_key` now raises at config load time
  instead of silently HMAC-ing an empty key. New `model_validator`
  on `CheckpointProtectorConfig`.

### Added — tests

- **`tests/integrations/test_checkpoint_protection.py`** — 7 cases
  covering both explicit and auto-protection paths against
  `MemorySaver`.
- **`tests/integrations/test_store_protection.py`** — 4 cases
  against `InMemoryStore`, including the `__slots__` fallback.
- **`tests/integrations/test_topology.py`** — 3 cases including the
  end-to-end `attach_graph → undeclared_edge fires` flow.
- **`tests/integrations/test_zero_config_e2e.py`** — 4 cases proving
  the README matrix's claims against a real compiled `StateGraph` +
  `MemorySaver`.

Total tests: 88 → 106.

### Added — docs

- README: new **"What you actually get with `LANGGRAPH_LENS=1`
  today"** matrix. Honest about which detectors fire automatically,
  which need a one-line opt-in, and which need manual calls.
- README: new **Integrations** section with `protect_saver` /
  `protect_store` / `attach_graph` examples plus the
  `LANGGRAPH_LENS_AUTO_PROTECT=0` opt-out.

## [0.2.1] — 2026-05-27

### Added

- `bench/RESULTS.md` — full per-rule benchmark numbers with rig spec,
  freeing the README Performance section from being the canonical
  record.
- `SECURITY.md` — vulnerability reporting policy and threat-model
  scope statement.
- `CONTRIBUTING.md` — how to run tests, add a detector, file a
  security issue.
- PyPI / Python-version badges in the README header.
- Coverage closing: 11 CLI tests covering `validate`, `version`,
  `scan-prompt`, `scan-checkpoint`, and `check` (live HTTP stub +
  unreachable port + metrics-absent branches). 5 PII tests covering
  the custom-pattern path via both the Tier 1 detector and the Tier 2
  redactor.
- Realistic-workload benchmark row (`_realistic_node` sleeps 10 ms),
  surfacing the +1.9% / +4.4% real-world numbers next to the
  synthetic worst-case.

### Changed

- README: `What it does` now precedes `Why`.
- README Performance section compressed from ~80 lines to ~25 lines;
  full tables live in `bench/RESULTS.md`.

### Fixed

- `LensCallback` filters to real LangGraph nodes (via the
  `langgraph_node` metadata key) and only emits the egress event at
  the outer run boundary. Reduces the per-invoke callback count from
  12 to 6 on a 5-node graph; halves callback-path overhead.
- Removed all hallucinated CVE identifiers from the README and
  detector advisories. Replaced with the real CVE-2026-27794,
  CVE-2026-28277, and CVE-2026-34070.
- Mypy strict mode in CI: added `langchain-core` to the `[dev]` extra
  so `BaseCallbackHandler` resolves at type-check time.

## [0.2.0] — 2026-05-26

### Added — Tier 2 (opt-in interventions, disabled by default)

- **`pii_redaction`** — deep-copies state, scrubs SSN / email / CC /
  phone / IP from messages and string fields, returns a `redact`
  decision with `modified_state`. Mode: `redact` or `block`.
- **`tool_allowlist`** — blocks tools outside the configured allow-
  list plus Tier 1 misuse signals (shell metachar, SSRF, oversized
  args). Mode: `block` or `log`.
- **`checkpoint_protector`** — refuses to deserialise checkpoint
  blobs containing unsafe pickle opcodes (the CVE-2026-27794 /
  28277 mitigation). Optional HMAC sign-on-write / verify-on-read.
  Mode: `enforce` or `log`.
- **`goal_guard`** — turns Tier 1 `system_prompt_drift` /
  `tool_call_drift` detections into terminal `block` decisions.
- **`rate_limit`** — per-(tenant | thread | tool) token bucket with
  args-size-aware cost. Mode: `throttle` (with `retry_after`) or
  `block` (429).
- **`circuit_breaker`** — error-rate trip plus optional
  fail-closed-on-attack using Tier 1 severity signals. Standard
  closed → open → half_open state machine.
- **`audit_signaling`** — stamps `X-Lens-Triggered`,
  `X-Lens-Action`, `X-Lens-Reason` headers on every Tier 2 decision;
  optionally writes the same fields into `state["__lens__"]`.

### Added — orchestration

- `LensDecision` dataclass composes via `merge`. `lens.decide_node`,
  `lens.decide_tool_call`, and `lens.decide_checkpoint` return
  `(decision, event)` pairs.
- `LensCallback(lens, enforce_blocks=True)` raises `LensBlockedError`
  on terminal decisions, propagating through `graph.invoke(...)`.
- `wrap_node(lens, fn)` decorator: lets Tier 2 redaction take effect
  before the wrapped node runs (callbacks alone can't rewrite state).

### Added — observability

- New Prometheus counters: `langgraph_lens_tier2_blocked_total`,
  `langgraph_lens_tier2_redacted_total`,
  `langgraph_lens_tier2_throttled_total`,
  `langgraph_lens_circuit_state`.

### Added — tests

- 35 new pytest cases in `tests/interventions/` and
  `tests/test_decide.py`. Every intervention covered in both modes
  plus the disabled-passthrough case.

## [0.1.0] — 2026-05-26

Initial release — Tier 1 observability, zero-config.

### Added

- Detectors: `attack_surface`, `checkpoint`, `supply_chain`, `tool`,
  `memory`, `pii`, `goal_hijack`, `comms`, `sql_injection`.
- `LensCallback` registers via LangChain Core's `register_configure_hook`
  for the `LANGGRAPH_LENS=1` zero-config install.
- CLI: `validate`, `scan-prompt`, `scan-checkpoint`, `check`,
  `version`.
- Prometheus exporter on port 9092.
- Optional OpenTelemetry bridge (`[otel]` extra).
- Slack / webhook alerts (off by default; default-on for
  `supply_chain`, `attack_surface`, `checkpoint`, `goal_hijack` when
  enabled).
- 33 pytest cases covering every detector rule.
- Synthetic CVE-2026-34070 prompt canary in `demo/malicious-prompt/`
  for the `Try it in 30 seconds` claim.
