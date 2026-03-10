from __future__ import annotations

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from agent_firewall.config import Settings


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

