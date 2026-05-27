# Security policy

## Reporting a vulnerability

If you've found a vulnerability in langgraph-lens itself — not a missed
detection, but a flaw in the lens code that could be exploited (e.g., a
deserialisation bug in the checkpoint scanner, a ReDoS in a detector
regex, a privilege issue in the HMAC verification, an event-log
injection path) — please **do not file a public issue**.

Email **glen.messenger@gmail.com** with:

- The affected version (or commit SHA)
- A minimal reproducer
- Your assessment of impact
- Whether you'd like credit in the advisory

Expect an acknowledgement within 72 hours and a fix or written
disposition within 14 days.

## In scope

- The lens detector / intervention code itself (`src/langgraph_lens/`)
- The CLI (`langgraph_lens.cli`)
- The bundled YAML config parser
- The HMAC sign/verify path in `checkpoint_protector`
- Any code path reachable via `langgraph-lens scan-prompt`,
  `scan-checkpoint`, or the `LANGGRAPH_LENS=1` global install

## Out of scope

- **Missed detections.** If the lens fails to flag a known prompt-
  injection pattern or PII shape, that's a coverage gap, not a
  vulnerability. File a regular issue with an example payload.
- **Vulnerabilities in LangGraph, LangChain, or their dependencies.**
  Report those upstream. langgraph-lens does not patch those
  projects.
- **Vulnerabilities in the model the agent calls.** Model-layer
  safety (prompt-injection resistance, jailbreak handling) is the
  model vendor's responsibility, not the lens's.
- **False positives.** The lens is heuristic; some false positives
  are expected by design. Tune via `lens.yaml` or file an issue with
  the misfiring rule.

## Disclosure

Once a fix is ready we'll publish:

1. A patched release on PyPI (`langgraph-lens` package).
2. A GitHub Security Advisory (GHSA) with the CVE if assigned.
3. An entry in `CHANGELOG.md` under a `### Security` heading.

If you reported the issue and consented to credit, you'll be named in
the advisory.

## Threat model

langgraph-lens defends against three categories of risk at the
graph-orchestration layer:

1. **Supply-chain risk in checkpoint blobs and prompt files** —
   pickle-fallback deserialisation (the CVE-2026-27794 / 28277
   surface), Jinja2 SSTI in prompt registries (CVE-2026-34070),
   path traversal in loader calls.
2. **Indirect injection via memory and tool outputs** — content
   written into the agent's persistent memory or returned by a tool
   that overrides the agent's effective system prompt on a later
   turn.
3. **Operational misuse** — tool calls outside the declared allow-
   list, SQL injection in checkpoint-saver identifiers, graph
   traversals that violate the declared topology, runaway recursion.

The lens **does not** defend against:

- Direct prompt-injection at the model layer (use Rebuff, Lakera
  Guard, or your model vendor's content filters)
- Model hallucination
- Network-layer attacks on LangGraph Server (use a reverse proxy
  and standard WAF)
- Resource exhaustion at the LLM-billing layer
