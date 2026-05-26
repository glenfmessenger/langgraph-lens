"""Tests for the CLI surface.

Covers every subcommand: `validate`, `scan-prompt`, `scan-checkpoint`,
`check`, `version`. `check` is exercised against both a live HTTP
endpoint and a deliberately-unreachable port; `scan-checkpoint` is
exercised against both clean and pickle-tainted JSON-lines inputs.
"""

from __future__ import annotations

import http.server
import json
import pickle
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from langgraph_lens import cli


def _capture(capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
    captured = capsys.readouterr()
    return captured.out, captured.err


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


# -- validate / version --------------------------------------------------


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["version"])
    out, _err = _capture(capsys)
    assert rc == 0
    assert out.strip()  # non-empty


def test_validate_ok(capsys: pytest.CaptureFixture[str]) -> None:
    repo_root = Path(__file__).parent.parent
    rc = cli.main(["validate", str(repo_root / "lens.yaml")])
    out, _err = _capture(capsys)
    assert rc == 0
    assert out.strip() == "ok"


def test_validate_bad_path(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli.main(["validate", "/no/such/path.yaml"])
    _out, err = _capture(capsys)
    assert rc == 1
    assert "invalid config" in err


# -- scan-prompt (already covered indirectly, but lock it in) ------------


def test_scan_prompt_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "ok.jinja2"
    p.write_text("You are a helpful assistant.")
    rc = cli.main(["scan-prompt", str(p)])
    out, _err = _capture(capsys)
    assert rc == 0
    event = json.loads(out.strip())
    assert event["event"] == "prompt_scan"
    assert event["detections"] == []


def test_scan_prompt_canary_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    repo_root = Path(__file__).parent.parent
    rc = cli.main(["scan-prompt", str(repo_root / "demo" / "malicious-prompt")])
    out, _err = _capture(capsys)
    assert rc == 1  # critical detection -> non-zero exit
    event = json.loads(out.strip())
    assert any(d["rule"] == "jinja_ssti" for d in event["detections"])


# -- scan-checkpoint -----------------------------------------------------


def test_scan_checkpoint_all_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "threads.jsonl"
    clean_blobs = [
        b'{"v": 1, "ts": "2026-05-26T00:00:00Z", "channel_values": {}}',
        b'{"v": 1, "ts": "2026-05-26T00:01:00Z", "channel_values": {"counter": 1}}',
    ]
    f.write_bytes(b"\n".join(clean_blobs) + b"\n")
    rc = cli.main(["scan-checkpoint", str(f)])
    out, _err = _capture(capsys)
    assert rc == 0
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        event = json.loads(line)
        assert event["event"] == "checkpoint_inspected"
        assert not any(
            d["severity"] in ("high", "critical")
            for d in event.get("detections", [])
        )


def test_scan_checkpoint_tainted_returns_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Evil:
        def __reduce__(self) -> tuple:
            return (print, ("pwn",))

    f = tmp_path / "threads.jsonl"
    f.write_bytes(b'{"v": 1, "ts": "x", "channel_values": {}}\n' + pickle.dumps(Evil()) + b"\n")
    rc = cli.main(["scan-checkpoint", str(f)])
    out, _err = _capture(capsys)
    assert rc == 1
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 2
    second = json.loads(lines[1])
    assert any(
        d["detector"] == "checkpoint" and d["rule"] == "unsafe_pickle_opcode"
        for d in second["detections"]
    )


def test_scan_checkpoint_skips_blank_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "threads.jsonl"
    f.write_bytes(
        b"\n"
        b'{"v": 1, "ts": "x", "channel_values": {}}\n'
        b"\n"
        b'{"v": 1, "ts": "y", "channel_values": {}}\n'
    )
    rc = cli.main(["scan-checkpoint", str(f)])
    out, _err = _capture(capsys)
    assert rc == 0
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 2  # blank lines were skipped


# -- check ---------------------------------------------------------------


@pytest.fixture()
def metrics_server() -> Iterator[tuple[int, list[str]]]:
    """Spin up a stub /metrics HTTP server. The fixture yields the port
    and a mutable list — set list[0] to the body the next request should
    return.
    """
    state = {"body": "langgraph_lens_nodes_inspected_total 42\n"}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(state["body"].encode())

        def log_message(self, *_a: object, **_kw: object) -> None:
            return  # silence access log

    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port, state  # type: ignore[misc]
    finally:
        server.shutdown()
        server.server_close()


def test_check_ok(
    metrics_server: tuple[int, dict[str, str]], capsys: pytest.CaptureFixture[str]
) -> None:
    port, _state = metrics_server
    rc = cli.main(["check", "--port", str(port)])
    out, _err = _capture(capsys)
    assert rc == 0
    assert out.strip() == "ok"


def test_check_metrics_absent(
    metrics_server: tuple[int, dict[str, str]], capsys: pytest.CaptureFixture[str]
) -> None:
    port, state = metrics_server
    state["body"] = "some_other_metric 1\n"
    rc = cli.main(["check", "--port", str(port)])
    _out, err = _capture(capsys)
    assert rc == 1
    assert "langgraph_lens_" in err


def test_check_unreachable_port(capsys: pytest.CaptureFixture[str]) -> None:
    # Pick a free port and don't bind anything; urlopen should refuse.
    port = _free_port()
    rc = cli.main(["check", "--port", str(port)])
    _out, err = _capture(capsys)
    assert rc == 1
    assert "not reachable" in err
