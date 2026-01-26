"""
Observability module for RedOPS.

Provides metrics, tracing, and logging instrumentation using OpenTelemetry.
"""

from redops.observability.metrics import (
    MetricsCollector,
    get_metrics_collector,
    record_scan_duration,
    record_finding_count,
    record_api_request,
)
from redops.observability.tracing import (
    TracingProvider,
    get_tracer,
    trace_function,
    trace_pipeline,
    trace_module,
)
from redops.observability.logging import (
    setup_structured_logging,
    get_logger,
    LogContext,
)

__all__ = [
    # Metrics
    "MetricsCollector",
    "get_metrics_collector",
    "record_scan_duration",
    "record_finding_count",
    "record_api_request",
    # Tracing
    "TracingProvider",
    "get_tracer",
    "trace_function",
    "trace_pipeline",
    "trace_module",
    # Logging
    "setup_structured_logging",
    "get_logger",
    "LogContext",
]
