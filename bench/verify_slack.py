"""Mock Slack-incoming-webhook + Lens alert round-trip.

Starts a localhost HTTP server that captures POSTs (the shape Slack
incoming webhooks expect — POST application/json with a top-level
`text` field), constructs a Lens with `alerts.enabled=True` pointed
at it, fires a supply-chain detection (which is in the default
`alert_on` list), and asserts the collector received a well-formed
Slack-shaped payload.

Verifies the lens-side path. Whether Slack accepts the message is
between the operator and their workspace.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
import time

received: list[dict] = []


class Collector(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            received.append(json.loads(body))
        except Exception:
            received.append({"_raw": body.decode("utf-8", errors="replace")})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_a: object, **_k: object) -> None:
        return


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


port = _free_port()
server = http.server.HTTPServer(("127.0.0.1", port), Collector)
threading.Thread(target=server.serve_forever, daemon=True).start()
print(f"mock Slack webhook listening on 127.0.0.1:{port}")

from langgraph_lens import Lens, LensConfig  # noqa: E402

cfg = LensConfig.default()
cfg.prometheus.enabled = False
cfg.logging.enabled = False
cfg.alerts.enabled = True
cfg.alerts.slack_webhook = f"http://127.0.0.1:{port}/services/T000/B000/secret"
cfg.alerts.cooldown_seconds = 0
# Default alert_on includes supply_chain; we will fire a supply_chain
# detection via scan_prompt against the demo canary.

lens = Lens(cfg)
event = lens.scan_prompt("demo/malicious-prompt/")
print(f"event detections: {[(d.detector, d.rule, d.severity.value) for d in event.detections]}")

# urllib.request.urlopen is synchronous so the POST should already
# have landed, but allow a brief grace window.
for _ in range(20):
    if received:
        break
    time.sleep(0.05)

server.shutdown()

assert received, "no POSTs reached the mock webhook"
payload = received[0]
print(f"captured payload: {json.dumps(payload, indent=2)}")
assert isinstance(payload, dict), "payload was not JSON"
assert "text" in payload, "missing top-level `text` field that Slack requires"
text = payload["text"]
assert "langgraph-lens" in text, "alert text should mention the tool"
assert "supply_chain" in text, "alert text should mention the detector kind"
assert "correlation_id" in text, "alert text should mention correlation_id"
print("SLACK VERIFY: OK")
