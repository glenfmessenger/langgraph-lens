# Demo: synthetic CVE-2026-34070 prompt canary

This directory contains a synthetic malicious Jinja2 prompt designed to trip
the `supply_chain/jinja_ssti` detector. It is **not** a real exploit — it
contains a sentinel string instead of an effective payload — but it matches
the same signatures the detector uses to flag the canonical CVE-2026-34070
SSTI shape.

## What's in here

- `malicious-prompt/system.jinja2` — a chat-template fragment containing
  `{{ ''.__class__.__mro__[1].__subclasses__() }}`, the canonical Jinja2
  sandbox-escape pattern.
- `malicious-prompt/prompt.yaml` — the LangChain Hub-style metadata that
  ordinarily ships alongside the template.

## How to run it

From the repo root:

```bash
pip install .
langgraph-lens scan-prompt demo/malicious-prompt/
```

Expected output (single JSON event on stdout, non-zero exit code):

```json
{"event": "prompt_scan", "prompt_path": "demo/malicious-prompt/", "detections": [{"detector": "supply_chain", "rule": "jinja_ssti", "severity": "critical", "file": "system.jinja2"}], ...}
```

To verify the detector doesn't fire on benign prompts, point it at any
ordinary Jinja2 template in your project. The same command should exit 0
with no detections.

## Why this exists

The `Try it in 30 seconds` block in the top-level README points at this
directory. It exists so that a first-time reader can verify, without
deploying anything, that the lens actually fires on a known-bad pattern.
