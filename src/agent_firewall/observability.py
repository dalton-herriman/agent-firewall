from __future__ import annotations

import logging
from dataclasses import dataclass, field

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from agent_firewall.config import Settings

LOGGER = logging.getLogger("agent_firewall")


@dataclass(slots=True)
class ObservabilityManager:
    tracer_name: str = "agent_firewall.firewall"
    meter_name: str = "agent_firewall.firewall"
    tracer: object = field(init=False)
    evaluation_counter: object = field(init=False)
    denied_counter: object = field(init=False)
    rate_limited_counter: object = field(init=False)
    execution_counter: object = field(init=False)

    def __post_init__(self) -> None:
        meter = metrics.get_meter(self.meter_name)
        self.tracer = trace.get_tracer(self.tracer_name)
        self.evaluation_counter = meter.create_counter("agent_firewall.evaluations", unit="1")
        self.denied_counter = meter.create_counter("agent_firewall.denies", unit="1")
        self.rate_limited_counter = meter.create_counter("agent_firewall.rate_limits", unit="1")
        self.execution_counter = meter.create_counter("agent_firewall.executions", unit="1")

    def record_evaluation(self, *, tenant_id: str, tool_name: str, allowed: bool, reason: str) -> None:
        attributes = {"tenant_id": tenant_id, "tool_name": tool_name, "allowed": allowed, "reason": reason}
        self.evaluation_counter.add(1, attributes)
        if not allowed:
            self.denied_counter.add(1, attributes)
        LOGGER.info(
            "tool_evaluation",
            extra={"tenant_id": tenant_id, "tool_name": tool_name, "allowed": allowed, "reason": reason},
        )

    def record_rate_limit(self, *, tenant_id: str, tool_name: str) -> None:
        self.rate_limited_counter.add(1, {"tenant_id": tenant_id, "tool_name": tool_name})
        LOGGER.warning("tool_rate_limited", extra={"tenant_id": tenant_id, "tool_name": tool_name})

    def record_execution(self, *, tenant_id: str, tool_name: str, status: str) -> None:
        self.execution_counter.add(1, {"tenant_id": tenant_id, "tool_name": tool_name, "status": status})
        LOGGER.info("tool_executed", extra={"tenant_id": tenant_id, "tool_name": tool_name, "status": status})


def configure_telemetry(settings: Settings) -> None:
    resource = Resource.create({"service.name": settings.otel_service_name, "deployment.environment": settings.app_env})
    tracer_provider = TracerProvider(resource=resource)
    if settings.otel_exporter_otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
        tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(MeterProvider(resource=resource))


def instrument_fastapi(app) -> None:
    FastAPIInstrumentor.instrument_app(app)


def get_observability() -> ObservabilityManager:
    return ObservabilityManager()
