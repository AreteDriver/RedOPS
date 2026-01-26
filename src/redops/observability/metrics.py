"""
Metrics collection and export for RedOPS.

Provides Prometheus-compatible metrics using OpenTelemetry SDK.
"""

from typing import Optional, Dict, Any, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field
import os
import time
import threading
from functools import wraps

# Try to import OpenTelemetry
try:
    from opentelemetry import metrics
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        PeriodicExportingMetricReader,
        ConsoleMetricExporter,
    )
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    from opentelemetry.sdk.resources import Resource
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False
    metrics = None


@dataclass
class MetricsConfig:
    """Metrics configuration."""

    enabled: bool = True
    service_name: str = "redops"
    service_version: str = "1.0.0"
    environment: str = "development"
    prometheus_port: int = 9090
    export_interval_ms: int = 60000
    console_export: bool = False

    @classmethod
    def from_env(cls) -> "MetricsConfig":
        """Create config from environment variables."""
        return cls(
            enabled=os.environ.get("METRICS_ENABLED", "true").lower() == "true",
            service_name=os.environ.get("OTEL_SERVICE_NAME", "redops"),
            service_version=os.environ.get("REDOPS_VERSION", "1.0.0"),
            environment=os.environ.get("ENVIRONMENT", "development"),
            prometheus_port=int(os.environ.get("PROMETHEUS_PORT", "9090")),
            export_interval_ms=int(os.environ.get("METRICS_INTERVAL_MS", "60000")),
            console_export=os.environ.get("METRICS_CONSOLE", "false").lower() == "true",
        )


class MetricsCollector:
    """
    Collects and exports metrics for RedOPS.

    Provides counters, gauges, and histograms for monitoring:
    - Scan operations (count, duration, status)
    - Finding statistics (count by severity, module)
    - API requests (count, latency, status codes)
    - Pipeline execution metrics
    """

    _instance: Optional["MetricsCollector"] = None
    _lock = threading.Lock()

    def __init__(self, config: Optional[MetricsConfig] = None):
        """
        Initialize the metrics collector.

        Args:
            config: Metrics configuration
        """
        self.config = config or MetricsConfig.from_env()
        self._initialized = False
        self._meter = None
        self._counters: Dict[str, Any] = {}
        self._histograms: Dict[str, Any] = {}
        self._gauges: Dict[str, Callable] = {}
        self._gauge_values: Dict[str, float] = {}

        if self.config.enabled and HAS_OTEL:
            self._initialize_otel()

    def _initialize_otel(self) -> None:
        """Initialize OpenTelemetry metrics."""
        resource = Resource.create({
            "service.name": self.config.service_name,
            "service.version": self.config.service_version,
            "deployment.environment": self.config.environment,
        })

        readers = []

        # Add Prometheus exporter
        try:
            prometheus_reader = PrometheusMetricReader()
            readers.append(prometheus_reader)
        except Exception:
            pass

        # Add console exporter for debugging
        if self.config.console_export:
            console_reader = PeriodicExportingMetricReader(
                ConsoleMetricExporter(),
                export_interval_millis=self.config.export_interval_ms,
            )
            readers.append(console_reader)

        if readers:
            provider = MeterProvider(resource=resource, metric_readers=readers)
            metrics.set_meter_provider(provider)
            self._meter = metrics.get_meter(self.config.service_name, self.config.service_version)
            self._create_instruments()
            self._initialized = True

    def _create_instruments(self) -> None:
        """Create metric instruments."""
        if not self._meter:
            return

        # Counters
        self._counters["scans_total"] = self._meter.create_counter(
            name="redops_scans_total",
            description="Total number of scans executed",
            unit="1",
        )

        self._counters["findings_total"] = self._meter.create_counter(
            name="redops_findings_total",
            description="Total number of findings discovered",
            unit="1",
        )

        self._counters["api_requests_total"] = self._meter.create_counter(
            name="redops_api_requests_total",
            description="Total API requests",
            unit="1",
        )

        self._counters["pipeline_steps_total"] = self._meter.create_counter(
            name="redops_pipeline_steps_total",
            description="Total pipeline steps executed",
            unit="1",
        )

        self._counters["errors_total"] = self._meter.create_counter(
            name="redops_errors_total",
            description="Total errors encountered",
            unit="1",
        )

        # Histograms
        self._histograms["scan_duration"] = self._meter.create_histogram(
            name="redops_scan_duration_seconds",
            description="Scan duration in seconds",
            unit="s",
        )

        self._histograms["api_request_duration"] = self._meter.create_histogram(
            name="redops_api_request_duration_seconds",
            description="API request duration in seconds",
            unit="s",
        )

        self._histograms["step_duration"] = self._meter.create_histogram(
            name="redops_step_duration_seconds",
            description="Pipeline step duration in seconds",
            unit="s",
        )

        # Observable gauges (using callbacks)
        self._meter.create_observable_gauge(
            name="redops_active_scans",
            description="Number of currently active scans",
            unit="1",
            callbacks=[lambda options: [metrics.Observation(self._gauge_values.get("active_scans", 0))]],
        )

        self._meter.create_observable_gauge(
            name="redops_queue_size",
            description="Number of items in job queue",
            unit="1",
            callbacks=[lambda options: [metrics.Observation(self._gauge_values.get("queue_size", 0))]],
        )

    def record_scan(
        self,
        pipeline: str,
        target: str,
        status: str,
        duration_seconds: float,
    ) -> None:
        """
        Record a scan execution.

        Args:
            pipeline: Pipeline name
            target: Scan target
            status: Scan status (success, failure, timeout)
            duration_seconds: Scan duration
        """
        if not self._initialized:
            return

        attributes = {
            "pipeline": pipeline,
            "status": status,
        }

        self._counters["scans_total"].add(1, attributes)
        self._histograms["scan_duration"].record(duration_seconds, attributes)

    def record_finding(
        self,
        module: str,
        severity: str,
        finding_type: str = "general",
    ) -> None:
        """
        Record a finding.

        Args:
            module: Module that produced the finding
            severity: Finding severity
            finding_type: Type of finding
        """
        if not self._initialized:
            return

        attributes = {
            "module": module,
            "severity": severity,
            "type": finding_type,
        }

        self._counters["findings_total"].add(1, attributes)

    def record_api_request(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        """
        Record an API request.

        Args:
            method: HTTP method
            endpoint: Request endpoint
            status_code: Response status code
            duration_seconds: Request duration
        """
        if not self._initialized:
            return

        attributes = {
            "method": method,
            "endpoint": endpoint,
            "status_code": str(status_code),
        }

        self._counters["api_requests_total"].add(1, attributes)
        self._histograms["api_request_duration"].record(duration_seconds, attributes)

    def record_step(
        self,
        step_name: str,
        module: str,
        status: str,
        duration_seconds: float,
    ) -> None:
        """
        Record a pipeline step execution.

        Args:
            step_name: Step name
            module: Module path
            status: Step status
            duration_seconds: Step duration
        """
        if not self._initialized:
            return

        attributes = {
            "step": step_name,
            "module": module,
            "status": status,
        }

        self._counters["pipeline_steps_total"].add(1, attributes)
        self._histograms["step_duration"].record(duration_seconds, attributes)

    def record_error(
        self,
        error_type: str,
        module: str = "unknown",
        message: str = "",
    ) -> None:
        """
        Record an error.

        Args:
            error_type: Type of error
            module: Module where error occurred
            message: Error message (truncated)
        """
        if not self._initialized:
            return

        attributes = {
            "type": error_type,
            "module": module,
        }

        self._counters["errors_total"].add(1, attributes)

    def set_gauge(self, name: str, value: float) -> None:
        """
        Set a gauge value.

        Args:
            name: Gauge name (active_scans, queue_size)
            value: Gauge value
        """
        self._gauge_values[name] = value

    def increment_gauge(self, name: str, delta: float = 1) -> None:
        """Increment a gauge value."""
        self._gauge_values[name] = self._gauge_values.get(name, 0) + delta

    def decrement_gauge(self, name: str, delta: float = 1) -> None:
        """Decrement a gauge value."""
        self._gauge_values[name] = max(0, self._gauge_values.get(name, 0) - delta)


# Global metrics collector
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def record_scan_duration(pipeline: str, target: str, status: str = "success"):
    """
    Decorator to record scan duration.

    Args:
        pipeline: Pipeline name
        target: Scan target
        status: Default status (can be overridden)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start = time.time()
            scan_status = status
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                scan_status = "failure"
                raise
            finally:
                duration = time.time() - start
                collector.record_scan(pipeline, target, scan_status, duration)
        return wrapper
    return decorator


def record_finding_count(module: str, severity: str):
    """
    Record a finding from a decorator.

    Args:
        module: Module name
        severity: Finding severity
    """
    collector = get_metrics_collector()
    collector.record_finding(module, severity)


def record_api_request(method: str, endpoint: str):
    """
    Decorator to record API request metrics.

    Args:
        method: HTTP method
        endpoint: Endpoint path
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start = time.time()
            status_code = 500
            try:
                result = await func(*args, **kwargs)
                status_code = getattr(result, "status_code", 200)
                return result
            except Exception as e:
                status_code = 500
                raise
            finally:
                duration = time.time() - start
                collector.record_api_request(method, endpoint, status_code, duration)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            start = time.time()
            status_code = 500
            try:
                result = func(*args, **kwargs)
                status_code = getattr(result, "status_code", 200)
                return result
            except Exception as e:
                status_code = 500
                raise
            finally:
                duration = time.time() - start
                collector.record_api_request(method, endpoint, status_code, duration)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator
