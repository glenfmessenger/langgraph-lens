"""Optional OpenTelemetry bridge.

Imported only when `otel.enabled: true` in lens.yaml. The opentelemetry
packages are an optional dependency — install with `pip install
"langgraph-lens[otel]"`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .config import OtelConfig
from .events import Event

if TYPE_CHECKING:
    # Avoid hard import at module load — otel is optional.
    pass


class OtelBridge:
    def __init__(self, config: OtelConfig) -> None:
        self.config = config
        self._tracer: Any = None
        if config.enabled:
            self._init()

    def _init(self) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError:
            # Optional dep missing — silently disable.
            return

        provider = TracerProvider(
            resource=Resource.create({"service.name": self.config.service_name}),
        )
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=self.config.endpoint))
        )
        trace.set_tracer_provider(provider)
        self._tracer = trace.get_tracer("langgraph-lens")

    def export(self, event: Event) -> None:
        if self._tracer is None:
            return
        with self._tracer.start_as_current_span(event.event.value) as span:
            span.set_attribute("langgraph.correlation_id", event.correlation_id)
            if event.run_id:
                span.set_attribute("langgraph.run_id", event.run_id)
            if event.thread_id:
                span.set_attribute("langgraph.thread_id", event.thread_id)
            if event.node:
                span.set_attribute("langgraph.node", event.node)
            for d in event.detections:
                span.add_event(
                    f"{d.detector}.{d.rule}",
                    attributes={
                        "detector": d.detector,
                        "rule": d.rule,
                        "severity": d.severity.value,
                    },
                )
