"""Prometheus metrics exporter.

The metric names are part of the public contract; downstream Grafana
dashboards depend on them.
"""

from __future__ import annotations

import contextlib
import os

from prometheus_client import Counter, Histogram, start_http_server

from .events import Detection

ATTACK_SURFACE = Counter(
    "langgraph_lens_attack_surface_detections_total",
    "Attack-surface rules that fired at startup.",
    ["rule"],
)
CHECKPOINT_DET = Counter(
    "langgraph_lens_checkpoint_detections_total",
    "Checkpoint-anomaly rules that fired.",
    ["rule"],
)
SUPPLY_CHAIN = Counter(
    "langgraph_lens_supply_chain_detections_total",
    "Supply-chain rules that fired during prompt load.",
    ["rule"],
)
TOOL_DET = Counter(
    "langgraph_lens_tool_detections_total",
    "Tool-misuse rules that fired.",
    ["rule"],
)
MEMORY_DET = Counter(
    "langgraph_lens_memory_detections_total",
    "Memory / context-poisoning rules that fired.",
    ["rule"],
)
PII = Counter(
    "langgraph_lens_pii_detections_total",
    "PII detections per type and direction.",
    ["type", "direction"],
)
GOAL_HIJACK = Counter(
    "langgraph_lens_goal_hijack_detections_total",
    "Goal-hijack rules that fired.",
    ["rule"],
)
COMMS = Counter(
    "langgraph_lens_comms_detections_total",
    "Inter-agent / graph-communication rules that fired.",
    ["rule"],
)
SQL_INJ = Counter(
    "langgraph_lens_sql_injection_detections_total",
    "SQL / metadata-injection rules that fired.",
    ["rule"],
)
NODES_INSPECTED = Counter(
    "langgraph_lens_nodes_inspected_total",
    "Nodes inspected at ingress.",
)
CHECKPOINTS_INSPECTED = Counter(
    "langgraph_lens_checkpoints_inspected_total",
    "Checkpoints inspected (writes + reads).",
)
INSPECTION_DURATION = Histogram(
    "langgraph_lens_inspection_duration_seconds",
    "Wall-clock cost of one inspection pass.",
    ["stage"],
)


def record_detection(det: Detection) -> None:
    if det.detector == "attack_surface":
        ATTACK_SURFACE.labels(rule=det.rule).inc()
    elif det.detector == "checkpoint":
        CHECKPOINT_DET.labels(rule=det.rule).inc()
    elif det.detector == "supply_chain":
        SUPPLY_CHAIN.labels(rule=det.rule).inc()
    elif det.detector == "tool":
        TOOL_DET.labels(rule=det.rule).inc()
    elif det.detector == "memory":
        MEMORY_DET.labels(rule=det.rule).inc()
    elif det.detector == "pii":
        pii_type = det.extra.get("type", det.rule)
        direction = det.extra.get("direction", "unknown")
        PII.labels(type=pii_type, direction=direction).inc()
    elif det.detector == "goal_hijack":
        GOAL_HIJACK.labels(rule=det.rule).inc()
    elif det.detector == "comms":
        COMMS.labels(rule=det.rule).inc()
    elif det.detector == "sql_injection":
        SQL_INJ.labels(rule=det.rule).inc()


_server_started = False


def maybe_start_server(port: int) -> None:
    """Start the Prometheus exporter if it isn't already up.

    In multiprocess servers, set PROMETHEUS_MULTIPROC_DIR before this
    is called so workers share metric files.
    """
    global _server_started
    if _server_started:
        return
    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        # Multiprocess: the metrics file directory is shared and the
        # server is expected to expose /metrics itself. Don't bind.
        _server_started = True
        return
    # Port already bound (e.g. another lens instance in the same process
    # tree) is treated as success — first one wins.
    with contextlib.suppress(OSError):
        start_http_server(port)
    _server_started = True
