# Contributing

Thanks for taking an interest. This project is small and the bar for
contributions is "make the code better, don't break the tests."

## Running the test suite

```bash
git clone https://github.com/glenfmessenger/langgraph-lens
cd langgraph-lens
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest tests/ -v
ruff check src/ tests/ bench/
mypy src/langgraph_lens/
```

All three must pass before you open a PR. CI runs the same commands on
Python 3.10 / 3.11 / 3.12.

## Adding a detector

A Tier 1 detector is a small class with a `scan(...)` method that
returns `list[Detection]`. Conventions:

- One file under `src/langgraph_lens/detectors/`.
- One config class under `src/langgraph_lens/config.py`, defaulting
  to `enabled = True`.
- Wire it into `Lens.__init__` in `src/langgraph_lens/lens.py`.
- Add a metrics counter under `src/langgraph_lens/metrics.py` and a
  branch in `record_detection(...)`.
- Add a default block to `lens.yaml`.
- Tests under `tests/test_<name>.py` — at minimum one positive case
  per rule plus one negative control. Aim for parity with the other
  detectors.

A Tier 2 intervention is similar, but returns `LensDecision`. Conventions:

- One file under `src/langgraph_lens/interventions/`.
- Config class defaults to `enabled = False`.
- Wire it into `Lens.__init__` and into the relevant
  `Lens.decide_*(...)` method.
- Tests under `tests/interventions/test_<name>.py`. Cover both modes
  (`block` / `log` or `redact` / `throttle`) plus the
  disabled-passthrough case.

## Filing a security issue

See [`SECURITY.md`](SECURITY.md). Do not file public issues for
vulnerabilities in the lens itself.

## Style

- Type-annotate everything; mypy runs in strict mode.
- Don't add comments that re-state the code. Add a comment only when
  the *why* is non-obvious — a hidden constraint, a workaround for a
  specific bug, behaviour that would surprise a reader.
- Match the surrounding code's tone. The README and module
  docstrings aim for "professional but approachable" — direct,
  uncluttered, no marketing language.
- Don't claim something is "measured" if it isn't.

## Commit messages

One-line subject, blank line, paragraph(s) explaining *why* the
change was needed. Reference any issue or PR number at the end of
the body, not the subject. No trailing co-author lines unless you
actually co-authored with someone.

## Releases

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [SemVer](https://semver.org/). New entries go under
`## [Unreleased]`; the release process moves them to a versioned
heading.
