"""langgraph-lens CLI."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from . import __version__
from .config import LensConfig
from .lens import Lens


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="langgraph-lens")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate a config file")
    validate.add_argument("path")

    scan_p = sub.add_parser(
        "scan-prompt", help="one-shot supply-chain scan of a prompt directory or file"
    )
    scan_p.add_argument("path")
    scan_p.add_argument("--config", default=None)

    scan_c = sub.add_parser(
        "scan-checkpoint",
        help="one-shot checkpoint blob scan (JSON-lines, one blob per line)",
    )
    scan_c.add_argument("path")
    scan_c.add_argument("--config", default=None)

    check = sub.add_parser("check", help="check that the metrics server is up")
    check.add_argument("--port", type=int, default=9092)

    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _cmd_validate(args.path)
    if args.command == "scan-prompt":
        return _cmd_scan_prompt(args.path, args.config)
    if args.command == "scan-checkpoint":
        return _cmd_scan_checkpoint(args.path, args.config)
    if args.command == "check":
        return _cmd_check(args.port)
    if args.command == "version":
        print(__version__)
        return 0
    parser.print_help()
    return 2


def _quiet_config(path: str | None) -> LensConfig:
    cfg = LensConfig.from_yaml(path) if path else LensConfig.default()
    cfg.prometheus.enabled = False
    cfg.logging.enabled = False
    return cfg


def _cmd_validate(path: str) -> int:
    try:
        LensConfig.from_yaml(path)
    except Exception as e:  # noqa: BLE001 -- CLI surface
        print(f"invalid config: {e}", file=sys.stderr)
        return 1
    print("ok")
    return 0


def _cmd_scan_prompt(path: str, config_path: str | None) -> int:
    lens = Lens(_quiet_config(config_path))
    event = lens.scan_prompt(path)
    print(json.dumps(event.to_dict()))
    if not event.detections:
        return 0
    return 0 if all(d.severity.value in ("low", "medium") for d in event.detections) else 1


def _cmd_scan_checkpoint(path: str, config_path: str | None) -> int:
    lens = Lens(_quiet_config(config_path))
    rc = 0
    with open(path, "rb") as fh:
        for i, line in enumerate(fh):
            blob = line.rstrip(b"\n")
            if not blob:
                continue
            event = lens.inspect_checkpoint(
                blob=blob,
                metadata={"checkpoint_id": f"line-{i}"},
                checkpoint_id=f"line-{i}",
                direction="read",
            )
            print(json.dumps(event.to_dict()))
            if event.detections and any(
                d.severity.value in ("high", "critical") for d in event.detections
            ):
                rc = 1
    return rc


def _cmd_check(port: int) -> int:
    url = f"http://127.0.0.1:{port}/metrics"
    try:
        resp = urllib.request.urlopen(url, timeout=2)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"metrics server not reachable at {url}: {e}", file=sys.stderr)
        return 1
    body = resp.read().decode("utf-8", errors="replace")
    if "langgraph_lens_" in body:
        print("ok")
        return 0
    print("metrics server is up but langgraph_lens_ metrics are absent", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
