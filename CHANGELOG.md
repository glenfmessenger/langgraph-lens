# Changelog

All notable changes to this project will be documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
