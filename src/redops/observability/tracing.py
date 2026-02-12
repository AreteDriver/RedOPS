"""
Distributed tracing for RedOPS.

Provides OpenTelemetry-based tracing for pipelines, modules, and API calls.
"""

from typing import Any, Callable, TypeVar
from dataclasses import dataclass
import os
import functools
from contextlib import contextmanager

# Try to import OpenTelemetry
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Status, StatusCode
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    # Optional exporters
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        HAS_OTLP = True
    except ImportError:
        HAS_OTLP = False

    try:
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter

        HAS_JAEGER = True
    except ImportError:
        HAS_JAEGER = False

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False
    trace = None


F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class TracingConfig:
    """Tracing configuration."""

    enabled: bool = True
    service_name: str = "redops"
    service_version: str = "1.0.0"
    environment: str = "development"
    exporter: str = "console"  # console, otlp, jaeger
    otlp_endpoint: str = "http://localhost:4317"
    jaeger_host: str = "localhost"
    jaeger_port: int = 6831
    sample_rate: float = 1.0

    @classmethod
    def from_env(cls) -> "TracingConfig":
        """Create config from environment variables."""
        return cls(
            enabled=os.environ.get("TRACING_ENABLED", "true").lower() == "true",
            service_name=os.environ.get("OTEL_SERVICE_NAME", "redops"),
            service_version=os.environ.get("REDOPS_VERSION", "1.0.0"),
            environment=os.environ.get("ENVIRONMENT", "development"),
            exporter=os.environ.get("TRACING_EXPORTER", "console"),
            otlp_endpoint=os.environ.get(
                "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
            ),
            jaeger_host=os.environ.get("JAEGER_HOST", "localhost"),
            jaeger_port=int(os.environ.get("JAEGER_PORT", "6831")),
            sample_rate=float(os.environ.get("TRACING_SAMPLE_RATE", "1.0")),
        )


class TracingProvider:
    """
    Provides distributed tracing for RedOPS.

    Supports multiple exporters:
    - Console (for debugging)
    - OTLP (OpenTelemetry Collector)
    - Jaeger
    """

    _instance: "TracingProvider | None" = None

    def __init__(self, config: TracingConfig | None = None):
        """
        Initialize the tracing provider.

        Args:
            config: Tracing configuration
        """
        self.config = config or TracingConfig.from_env()
        self._initialized = False
        self._tracer = None
        self._propagator = None

        if self.config.enabled and HAS_OTEL:
            self._initialize_otel()

    def _initialize_otel(self) -> None:
        """Initialize OpenTelemetry tracing."""
        resource = Resource.create(
            {
                "service.name": self.config.service_name,
                "service.version": self.config.service_version,
                "deployment.environment": self.config.environment,
            }
        )

        provider = TracerProvider(resource=resource)

        # Add exporter based on config
        exporter = self._create_exporter()
        if exporter:
            processor = BatchSpanProcessor(exporter)
            provider.add_span_processor(processor)

        trace.set_tracer_provider(provider)
        self._tracer = trace.get_tracer(
            self.config.service_name,
            self.config.service_version,
        )
        self._propagator = TraceContextTextMapPropagator()
        self._initialized = True

    def _create_exporter(self):
        """Create the trace exporter based on config."""
        exporter_type = self.config.exporter.lower()

        if exporter_type == "otlp" and HAS_OTLP:
            return OTLPSpanExporter(endpoint=self.config.otlp_endpoint)

        if exporter_type == "jaeger" and HAS_JAEGER:
            return JaegerExporter(
                agent_host_name=self.config.jaeger_host,
                agent_port=self.config.jaeger_port,
            )

        # Default to console
        return ConsoleSpanExporter()

    def get_tracer(self):
        """Get the tracer instance."""
        return self._tracer

    @contextmanager
    def start_span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
        kind: Any | None = None,
    ):
        """
        Start a new span.

        Args:
            name: Span name
            attributes: Span attributes
            kind: Span kind (client, server, internal, etc.)

        Yields:
            The active span
        """
        if not self._initialized or not self._tracer:
            yield None
            return

        span_kind = kind or trace.SpanKind.INTERNAL
        with self._tracer.start_as_current_span(
            name,
            kind=span_kind,
            attributes=attributes or {},
        ) as span:
            try:
                yield span
            except Exception as e:
                if span:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                raise

    def inject_context(self, carrier: dict[str, str]) -> dict[str, str]:
        """
        Inject trace context into a carrier (e.g., HTTP headers).

        Args:
            carrier: Dictionary to inject context into

        Returns:
            The carrier with injected context
        """
        if self._propagator:
            self._propagator.inject(carrier)
        return carrier

    def extract_context(self, carrier: dict[str, str]):
        """
        Extract trace context from a carrier.

        Args:
            carrier: Dictionary containing trace context

        Returns:
            The extracted context
        """
        if self._propagator:
            return self._propagator.extract(carrier)
        return None


# Global tracing provider
_tracing_provider: TracingProvider | None = None


def get_tracer():
    """Get the global tracer instance."""
    global _tracing_provider
    if _tracing_provider is None:
        _tracing_provider = TracingProvider()
    return _tracing_provider


def trace_function(
    name: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """
    Decorator to trace a function.

    Args:
        name: Span name (defaults to function name)
        attributes: Additional span attributes

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        span_name = name or func.__name__

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            provider = get_tracer()
            with provider.start_span(span_name, attributes) as span:
                if span:
                    span.set_attribute("function.name", func.__name__)
                    span.set_attribute("function.module", func.__module__)
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            provider = get_tracer()
            with provider.start_span(span_name, attributes) as span:
                if span:
                    span.set_attribute("function.name", func.__name__)
                    span.set_attribute("function.module", func.__module__)
                return func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return sync_wrapper  # type: ignore

    return decorator


def trace_pipeline(pipeline_name: str):
    """
    Decorator to trace a pipeline execution.

    Args:
        pipeline_name: Name of the pipeline

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            provider = get_tracer()
            attributes = {
                "pipeline.name": pipeline_name,
                "pipeline.type": "security_scan",
            }

            # Try to get target from kwargs or context
            target = kwargs.get("target", "unknown")
            if target != "unknown":
                attributes["pipeline.target"] = str(target)

            with provider.start_span(f"pipeline:{pipeline_name}", attributes) as span:
                try:
                    result = func(*args, **kwargs)
                    if span and hasattr(result, "data"):
                        # Add finding count to span
                        findings = sum(
                            1 for k in result.data if k.startswith("finding_")
                        )
                        span.set_attribute("pipeline.findings_count", findings)
                    return result
                except Exception as e:
                    if span:
                        span.set_attribute("pipeline.error", str(e))
                    raise

        return wrapper  # type: ignore

    return decorator


def trace_module(module_name: str):
    """
    Decorator to trace a module execution.

    Args:
        module_name: Name of the module

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(ctx, params=None):
            provider = get_tracer()
            attributes = {
                "module.name": module_name,
                "module.function": func.__name__,
            }

            if ctx and hasattr(ctx, "target"):
                attributes["module.target"] = str(ctx.target)

            with provider.start_span(f"module:{module_name}", attributes) as span:
                try:
                    result = func(ctx, params)
                    return result
                except Exception as e:
                    if span:
                        span.set_attribute("module.error", str(e))
                    raise

        return wrapper  # type: ignore

    return decorator
