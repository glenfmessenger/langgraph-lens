"""Mock OTLP HTTP collector + Lens otel export round-trip.

Starts a localhost HTTP server that captures POSTs to /v1/traces (the
canonical OTLP HTTP path), constructs a Lens with otel.enabled=True
pointed at it, fires a node inspection that emits a span, and asserts
the collector received a non-empty trace payload.
"""

from __future__ import annotations

import http.server
import socket
import threading
import time

received: list[bytes] = []


class Collector(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        received.append(body)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.end_headers()
        self.wfile.write(b"")

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
print(f"mock OTLP collector listening on 127.0.0.1:{port}")

from langgraph_lens import Lens, LensConfig  # noqa: E402

cfg = LensConfig.default()
cfg.prometheus.enabled = False
cfg.logging.enabled = False
cfg.otel.enabled = True
cfg.otel.endpoint = f"http://127.0.0.1:{port}"
cfg.otel.service_name = "langgraph-lens-verify"
cfg.otel.export_traces = True

lens = Lens(cfg)
print(f"otel bridge initialised: tracer={lens.otel._tracer is not None}")

# Trigger a node inspection that emits a span with a detection.
event = lens.inspect_node(
    node="verify",
    state={"messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]},
    run_id="verify-run-1",
    thread_id="verify-thread-1",
)
print(f"event emitted: detections={[(d.detector, d.rule) for d in event.detections]}")

# Force flush so the BatchSpanProcessor sends now, not on the default
# 5-second batching tick.
from opentelemetry import trace  # noqa: E402

provider = trace.get_tracer_provider()
if hasattr(provider, "force_flush"):
    provider.force_flush(timeout_millis=2000)

# Wait briefly for the HTTP POST to land.
for _ in range(20):
    if received:
        break
    time.sleep(0.1)

print(f"collector captured {len(received)} POST(s), total bytes={sum(len(r) for r in received)}")
server.shutdown()

assert lens.otel._tracer is not None, "OTel tracer was not initialised"
assert received, "no OTLP POSTs reached the mock collector"
assert sum(len(r) for r in received) > 100, "captured payload is suspiciously small"

# Try to parse the first POST as protobuf and inspect span names.
try:
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

    req = trace_service_pb2.ExportTraceServiceRequest()
    req.ParseFromString(received[0])
    span_names = [
        s.name for rs in req.resource_spans for ss in rs.scope_spans for s in ss.spans
    ]
    print(f"parsed spans: {span_names}")
    assert "node_inspected" in span_names, "expected node_inspected span"
    # Inspect attributes to confirm correlation_id, run_id, etc. plumbed through.
    first = req.resource_spans[0].scope_spans[0].spans[0]
    attrs = {kv.key: kv.value.string_value for kv in first.attributes}
    print(f"span attributes: {attrs}")
    assert attrs.get("langgraph.run_id") == "verify-run-1"
    assert attrs.get("langgraph.thread_id") == "verify-thread-1"
    assert attrs.get("langgraph.node") == "verify"
except ImportError:
    print("note: opentelemetry-proto not installed; skipped payload-parse assertions")

print("OTEL VERIFY: OK")
