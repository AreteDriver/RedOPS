"""
Metrics and Telemetry Module for RedOPS.

Provides counters, gauges, histograms, and exporters
for monitoring and observability.
"""

import json
import socket
import threading
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Sequence


class MetricType(Enum):
    """Types of metrics."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TIMER = "timer"


@dataclass(frozen=True)
class Labels:
    """Immutable labels for metrics."""

    _labels: tuple[tuple[str, str], ...]

    def __init__(self, **kwargs):
        """Initialize labels from keyword arguments."""
        object.__setattr__(self, "_labels", tuple(sorted(kwargs.items())))

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        return dict(self._labels)

    def __hash__(self) -> int:
        """Hash for use as dict key."""
        return hash(self._labels)

    def __eq__(self, other) -> bool:
        """Equality check."""
        if isinstance(other, Labels):
            return self._labels == other._labels
        return False

    def __repr__(self) -> str:
        """String representation."""
        return f"Labels({dict(self._labels)})"

    def merge(self, other: "Labels") -> "Labels":
        """Merge with another Labels, other takes precedence."""
        merged = dict(self._labels)
        merged.update(other.to_dict())
        return Labels(**merged)


# Empty labels singleton
EMPTY_LABELS = Labels()


@dataclass
class MetricValue:
    """A single metric value with timestamp."""

    value: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    labels: Labels = field(default_factory=lambda: EMPTY_LABELS)


class Metric(ABC):
    """Base class for all metrics."""

    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Labels | None = None,
        unit: str = "",
    ):
        """Initialize metric."""
        self._name = name
        self._description = description
        self._labels = labels or EMPTY_LABELS
        self._unit = unit
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        """Get metric name."""
        return self._name

    @property
    def description(self) -> str:
        """Get metric description."""
        return self._description

    @property
    def labels(self) -> Labels:
        """Get metric labels."""
        return self._labels

    @property
    def unit(self) -> str:
        """Get metric unit."""
        return self._unit

    @property
    @abstractmethod
    def metric_type(self) -> MetricType:
        """Get metric type."""
        pass

    @abstractmethod
    def get_value(self) -> float:
        """Get current metric value."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the metric."""
        pass

    def to_dict(self) -> dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "name": self._name,
            "type": self.metric_type.value,
            "description": self._description,
            "labels": self._labels.to_dict(),
            "unit": self._unit,
            "value": self.get_value(),
        }


class Counter(Metric):
    """A counter that only increments."""

    def __init__(self, name: str, description: str = "", **kwargs):
        """Initialize counter."""
        super().__init__(name, description, **kwargs)
        self._value = 0.0
        self._labeled: dict[Labels, float] = {}

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.COUNTER

    def inc(self, amount: float = 1.0, labels: Labels | None = None) -> None:
        """Increment the counter."""
        if amount < 0:
            raise ValueError("Counter can only be incremented by non-negative values")
        with self._lock:
            if labels:
                self._labeled[labels] = self._labeled.get(labels, 0.0) + amount
            else:
                self._value += amount

    def get_value(self, labels: Labels | None = None) -> float:
        """Get current counter value."""
        with self._lock:
            if labels:
                return self._labeled.get(labels, 0.0)
            return self._value

    def get_all_values(self) -> dict[Labels, float]:
        """Get all labeled values."""
        with self._lock:
            result = {EMPTY_LABELS: self._value} if self._value > 0 else {}
            result.update(self._labeled)
            return result

    def reset(self) -> None:
        """Reset counter to zero."""
        with self._lock:
            self._value = 0.0
            self._labeled.clear()


class Gauge(Metric):
    """A gauge that can go up and down."""

    def __init__(self, name: str, description: str = "", **kwargs):
        """Initialize gauge."""
        super().__init__(name, description, **kwargs)
        self._value = 0.0
        self._labeled: dict[Labels, float] = {}

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.GAUGE

    def set(self, value: float, labels: Labels | None = None) -> None:
        """Set gauge value."""
        with self._lock:
            if labels:
                self._labeled[labels] = value
            else:
                self._value = value

    def inc(self, amount: float = 1.0, labels: Labels | None = None) -> None:
        """Increment gauge."""
        with self._lock:
            if labels:
                self._labeled[labels] = self._labeled.get(labels, 0.0) + amount
            else:
                self._value += amount

    def dec(self, amount: float = 1.0, labels: Labels | None = None) -> None:
        """Decrement gauge."""
        with self._lock:
            if labels:
                self._labeled[labels] = self._labeled.get(labels, 0.0) - amount
            else:
                self._value -= amount

    def get_value(self, labels: Labels | None = None) -> float:
        """Get current gauge value."""
        with self._lock:
            if labels:
                return self._labeled.get(labels, 0.0)
            return self._value

    def get_all_values(self) -> dict[Labels, float]:
        """Get all labeled values."""
        with self._lock:
            result = {EMPTY_LABELS: self._value}
            result.update(self._labeled)
            return result

    def reset(self) -> None:
        """Reset gauge to zero."""
        with self._lock:
            self._value = 0.0
            self._labeled.clear()

    @contextmanager
    def track_inprogress(self, labels: Labels | None = None):
        """Context manager to track in-progress operations."""
        self.inc(labels=labels)
        try:
            yield
        finally:
            self.dec(labels=labels)


class Histogram(Metric):
    """A histogram for measuring distributions."""

    DEFAULT_BUCKETS = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
        float("inf"),
    )

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Sequence[float] | None = None,
        **kwargs,
    ):
        """Initialize histogram."""
        super().__init__(name, description, **kwargs)
        self._buckets = tuple(sorted(buckets or self.DEFAULT_BUCKETS))
        if self._buckets[-1] != float("inf"):
            self._buckets = self._buckets + (float("inf"),)
        self._bucket_counts: dict[Labels, dict[float, int]] = {}
        self._sums: dict[Labels, float] = {}
        self._counts: dict[Labels, int] = {}
        self._init_buckets(EMPTY_LABELS)

    def _init_buckets(self, labels: Labels) -> None:
        """Initialize bucket counts for labels."""
        self._bucket_counts[labels] = {b: 0 for b in self._buckets}
        self._sums[labels] = 0.0
        self._counts[labels] = 0

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.HISTOGRAM

    @property
    def buckets(self) -> tuple[float, ...]:
        """Get bucket boundaries."""
        return self._buckets

    def observe(self, value: float, labels: Labels | None = None) -> None:
        """Observe a value."""
        key = labels or EMPTY_LABELS
        with self._lock:
            if key not in self._bucket_counts:
                self._init_buckets(key)

            self._sums[key] += value
            self._counts[key] += 1

            for bucket in self._buckets:
                if value <= bucket:
                    self._bucket_counts[key][bucket] += 1

    def get_value(self, labels: Labels | None = None) -> float:
        """Get sum of observed values."""
        key = labels or EMPTY_LABELS
        with self._lock:
            return self._sums.get(key, 0.0)

    def get_count(self, labels: Labels | None = None) -> int:
        """Get count of observations."""
        key = labels or EMPTY_LABELS
        with self._lock:
            return self._counts.get(key, 0)

    def get_bucket_counts(self, labels: Labels | None = None) -> dict[float, int]:
        """Get bucket counts."""
        key = labels or EMPTY_LABELS
        with self._lock:
            return dict(self._bucket_counts.get(key, {}))

    def get_mean(self, labels: Labels | None = None) -> float:
        """Get mean of observed values."""
        key = labels or EMPTY_LABELS
        with self._lock:
            count = self._counts.get(key, 0)
            if count == 0:
                return 0.0
            return self._sums.get(key, 0.0) / count

    def reset(self) -> None:
        """Reset histogram."""
        with self._lock:
            self._bucket_counts.clear()
            self._sums.clear()
            self._counts.clear()
            self._init_buckets(EMPTY_LABELS)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        with self._lock:
            base["buckets"] = list(self._buckets)
            base["bucket_counts"] = {
                str(k): dict(v) for k, v in self._bucket_counts.items()
            }
            base["count"] = self._counts.get(EMPTY_LABELS, 0)
            base["sum"] = self._sums.get(EMPTY_LABELS, 0.0)
        return base


class Summary(Metric):
    """A summary for calculating quantiles."""

    DEFAULT_QUANTILES = (0.5, 0.9, 0.95, 0.99)

    def __init__(
        self,
        name: str,
        description: str = "",
        quantiles: Sequence[float] | None = None,
        max_age_seconds: float = 600.0,
        **kwargs,
    ):
        """Initialize summary."""
        super().__init__(name, description, **kwargs)
        self._quantiles = tuple(quantiles or self.DEFAULT_QUANTILES)
        self._max_age = max_age_seconds
        self._observations: dict[
            Labels, list[tuple[float, float]]
        ] = {}  # (value, timestamp)
        self._sums: dict[Labels, float] = {}
        self._counts: dict[Labels, int] = {}

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.SUMMARY

    @property
    def quantiles(self) -> tuple[float, ...]:
        """Get quantile targets."""
        return self._quantiles

    def _cleanup_old(self, labels: Labels) -> None:
        """Remove observations older than max_age."""
        if labels not in self._observations:
            return
        now = time.time()
        cutoff = now - self._max_age
        self._observations[labels] = [
            (v, t) for v, t in self._observations[labels] if t >= cutoff
        ]

    def observe(self, value: float, labels: Labels | None = None) -> None:
        """Observe a value."""
        key = labels or EMPTY_LABELS
        now = time.time()
        with self._lock:
            if key not in self._observations:
                self._observations[key] = []
                self._sums[key] = 0.0
                self._counts[key] = 0

            self._observations[key].append((value, now))
            self._sums[key] += value
            self._counts[key] += 1
            self._cleanup_old(key)

    def get_value(self, labels: Labels | None = None) -> float:
        """Get sum of observed values."""
        key = labels or EMPTY_LABELS
        with self._lock:
            return self._sums.get(key, 0.0)

    def get_count(self, labels: Labels | None = None) -> int:
        """Get count of observations."""
        key = labels or EMPTY_LABELS
        with self._lock:
            return self._counts.get(key, 0)

    def get_quantile(self, quantile: float, labels: Labels | None = None) -> float:
        """Get a specific quantile value."""
        key = labels or EMPTY_LABELS
        with self._lock:
            self._cleanup_old(key)
            observations = self._observations.get(key, [])
            if not observations:
                return 0.0
            values = sorted([v for v, _ in observations])
            idx = int(quantile * (len(values) - 1))
            return values[idx]

    def get_quantiles(self, labels: Labels | None = None) -> dict[float, float]:
        """Get all configured quantile values."""
        return {q: self.get_quantile(q, labels) for q in self._quantiles}

    def reset(self) -> None:
        """Reset summary."""
        with self._lock:
            self._observations.clear()
            self._sums.clear()
            self._counts.clear()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        with self._lock:
            base["quantiles"] = self.get_quantiles()
            base["count"] = self._counts.get(EMPTY_LABELS, 0)
            base["sum"] = self._sums.get(EMPTY_LABELS, 0.0)
        return base


class Timer(Metric):
    """A timer for measuring durations."""

    def __init__(
        self,
        name: str,
        description: str = "",
        buckets: Sequence[float] | None = None,
        **kwargs,
    ):
        """Initialize timer."""
        kwargs["unit"] = kwargs.get("unit", "seconds")
        super().__init__(name, description, **kwargs)
        self._histogram = Histogram(
            name=name,
            description=description,
            buckets=buckets,
        )

    @property
    def metric_type(self) -> MetricType:
        """Get metric type."""
        return MetricType.TIMER

    def observe(self, duration: float, labels: Labels | None = None) -> None:
        """Record a duration."""
        self._histogram.observe(duration, labels)

    def get_value(self, labels: Labels | None = None) -> float:
        """Get sum of recorded durations."""
        return self._histogram.get_value(labels)

    def get_count(self, labels: Labels | None = None) -> int:
        """Get count of recordings."""
        return self._histogram.get_count(labels)

    def get_mean(self, labels: Labels | None = None) -> float:
        """Get mean duration."""
        return self._histogram.get_mean(labels)

    def reset(self) -> None:
        """Reset timer."""
        self._histogram.reset()

    @contextmanager
    def time(self, labels: Labels | None = None):
        """Context manager to time a block of code."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.observe(duration, labels)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return self._histogram.to_dict()


class MetricExporter(ABC):
    """Base class for metric exporters."""

    @abstractmethod
    def export(self, metrics: list[Metric]) -> str:
        """Export metrics to string format."""
        pass


class PrometheusExporter(MetricExporter):
    """Export metrics in Prometheus text format."""

    def export(self, metrics: list[Metric]) -> str:
        """Export metrics in Prometheus format."""
        lines = []

        for metric in metrics:
            name = self._sanitize_name(metric.name)

            # Add HELP and TYPE
            if metric.description:
                lines.append(f"# HELP {name} {metric.description}")
            lines.append(f"# TYPE {name} {self._prometheus_type(metric.metric_type)}")

            # Add values
            if isinstance(metric, Counter):
                for labels, value in metric.get_all_values().items():
                    lines.append(f"{name}{self._format_labels(labels)} {value}")

            elif isinstance(metric, Gauge):
                for labels, value in metric.get_all_values().items():
                    lines.append(f"{name}{self._format_labels(labels)} {value}")

            elif isinstance(metric, Histogram):
                for labels_key in metric._bucket_counts:
                    labels_str = self._format_labels(labels_key)
                    bucket_counts = metric.get_bucket_counts(labels_key)
                    cumulative = 0
                    for bucket in sorted(bucket_counts.keys()):
                        cumulative += bucket_counts[bucket]
                        le = "+Inf" if bucket == float("inf") else str(bucket)
                        if labels_key == EMPTY_LABELS:
                            lines.append(f'{name}_bucket{{le="{le}"}} {cumulative}')
                        else:
                            label_dict = labels_key.to_dict()
                            label_dict["le"] = le
                            labels_formatted = ",".join(
                                f'{k}="{v}"' for k, v in label_dict.items()
                            )
                            lines.append(
                                f"{name}_bucket{{{labels_formatted}}} {cumulative}"
                            )

                    lines.append(
                        f"{name}_sum{labels_str} {metric.get_value(labels_key)}"
                    )
                    lines.append(
                        f"{name}_count{labels_str} {metric.get_count(labels_key)}"
                    )

            elif isinstance(metric, Summary):
                quantiles = metric.get_quantiles()
                for q, v in quantiles.items():
                    lines.append(f'{name}{{quantile="{q}"}} {v}')
                lines.append(f"{name}_sum {metric.get_value()}")
                lines.append(f"{name}_count {metric.get_count()}")

            elif isinstance(metric, Timer):
                # Timer wraps Histogram
                hist = metric._histogram
                for labels_key in hist._bucket_counts:
                    bucket_counts = hist.get_bucket_counts(labels_key)
                    cumulative = 0
                    for bucket in sorted(bucket_counts.keys()):
                        cumulative += bucket_counts[bucket]
                        le = "+Inf" if bucket == float("inf") else str(bucket)
                        lines.append(f'{name}_seconds_bucket{{le="{le}"}} {cumulative}')
                    lines.append(f"{name}_seconds_sum {hist.get_value(labels_key)}")
                    lines.append(f"{name}_seconds_count {hist.get_count(labels_key)}")

        return "\n".join(lines) + "\n"

    def _sanitize_name(self, name: str) -> str:
        """Sanitize metric name for Prometheus."""
        return name.replace(".", "_").replace("-", "_")

    def _format_labels(self, labels: Labels) -> str:
        """Format labels for Prometheus."""
        if labels == EMPTY_LABELS:
            return ""
        label_dict = labels.to_dict()
        return "{" + ",".join(f'{k}="{v}"' for k, v in sorted(label_dict.items())) + "}"

    def _prometheus_type(self, metric_type: MetricType) -> str:
        """Convert metric type to Prometheus type."""
        mapping = {
            MetricType.COUNTER: "counter",
            MetricType.GAUGE: "gauge",
            MetricType.HISTOGRAM: "histogram",
            MetricType.SUMMARY: "summary",
            MetricType.TIMER: "histogram",
        }
        return mapping.get(metric_type, "untyped")


class StatsDExporter(MetricExporter):
    """Export metrics in StatsD format."""

    def __init__(self, prefix: str = ""):
        """Initialize StatsD exporter."""
        self._prefix = prefix

    def export(self, metrics: list[Metric]) -> str:
        """Export metrics in StatsD format."""
        lines = []

        for metric in metrics:
            name = self._format_name(metric.name)

            if isinstance(metric, Counter):
                for labels, value in metric.get_all_values().items():
                    tag_str = self._format_tags(labels)
                    lines.append(f"{name}:{value}|c{tag_str}")

            elif isinstance(metric, Gauge):
                for labels, value in metric.get_all_values().items():
                    tag_str = self._format_tags(labels)
                    lines.append(f"{name}:{value}|g{tag_str}")

            elif isinstance(metric, (Histogram, Timer)):
                count = metric.get_count() if hasattr(metric, "get_count") else 0
                mean = metric.get_mean() if hasattr(metric, "get_mean") else 0
                lines.append(f"{name}.count:{count}|c")
                lines.append(f"{name}.mean:{mean}|g")

            elif isinstance(metric, Summary):
                for q, v in metric.get_quantiles().items():
                    q_name = f"p{int(q * 100)}"
                    lines.append(f"{name}.{q_name}:{v}|g")

        return "\n".join(lines)

    def _format_name(self, name: str) -> str:
        """Format metric name for StatsD."""
        full_name = f"{self._prefix}.{name}" if self._prefix else name
        return full_name.replace("-", "_")

    def _format_tags(self, labels: Labels) -> str:
        """Format labels as StatsD tags."""
        if labels == EMPTY_LABELS:
            return ""
        tag_dict = labels.to_dict()
        return "|#" + ",".join(f"{k}:{v}" for k, v in sorted(tag_dict.items()))


class JSONExporter(MetricExporter):
    """Export metrics as JSON."""

    def __init__(self, pretty: bool = False):
        """Initialize JSON exporter."""
        self._pretty = pretty

    def export(self, metrics: list[Metric]) -> str:
        """Export metrics as JSON."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": [m.to_dict() for m in metrics],
        }
        if self._pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)


class MetricsRegistry:
    """Registry for managing metrics."""

    _instance: "MetricsRegistry | None" = None
    _lock = threading.Lock()

    def __init__(self):
        """Initialize registry."""
        self._metrics: dict[str, Metric] = {}
        self._registry_lock = threading.Lock()
        self._default_labels = EMPTY_LABELS

    @classmethod
    def get_instance(cls) -> "MetricsRegistry":
        """Get singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance."""
        with cls._lock:
            cls._instance = None

    def set_default_labels(self, labels: Labels) -> None:
        """Set default labels for all metrics."""
        self._default_labels = labels

    def register(self, metric: Metric) -> Metric:
        """Register a metric."""
        with self._registry_lock:
            if metric.name in self._metrics:
                raise ValueError(f"Metric {metric.name} already registered")
            self._metrics[metric.name] = metric
            return metric

    def unregister(self, name: str) -> None:
        """Unregister a metric."""
        with self._registry_lock:
            if name in self._metrics:
                del self._metrics[name]

    def get(self, name: str) -> Metric | None:
        """Get a metric by name."""
        with self._registry_lock:
            return self._metrics.get(name)

    def get_all(self) -> list[Metric]:
        """Get all registered metrics."""
        with self._registry_lock:
            return list(self._metrics.values())

    def counter(self, name: str, description: str = "", **kwargs) -> Counter:
        """Create and register a counter."""
        metric = Counter(name, description, **kwargs)
        return self.register(metric)

    def gauge(self, name: str, description: str = "", **kwargs) -> Gauge:
        """Create and register a gauge."""
        metric = Gauge(name, description, **kwargs)
        return self.register(metric)

    def histogram(self, name: str, description: str = "", **kwargs) -> Histogram:
        """Create and register a histogram."""
        metric = Histogram(name, description, **kwargs)
        return self.register(metric)

    def summary(self, name: str, description: str = "", **kwargs) -> Summary:
        """Create and register a summary."""
        metric = Summary(name, description, **kwargs)
        return self.register(metric)

    def timer(self, name: str, description: str = "", **kwargs) -> Timer:
        """Create and register a timer."""
        metric = Timer(name, description, **kwargs)
        return self.register(metric)

    def export(self, exporter: MetricExporter) -> str:
        """Export all metrics using the given exporter."""
        return exporter.export(self.get_all())

    def clear(self) -> None:
        """Clear all metrics."""
        with self._registry_lock:
            self._metrics.clear()


class StatsDClient:
    """Client for sending metrics to StatsD server."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8125,
        prefix: str = "",
        max_buffer_size: int = 50,
    ):
        """Initialize StatsD client."""
        self._host = host
        self._port = port
        self._prefix = prefix
        self._max_buffer_size = max_buffer_size
        self._buffer: list[str] = []
        self._socket: socket.socket | None = None
        self._lock = threading.Lock()

    def _get_socket(self) -> socket.socket:
        """Get or create UDP socket."""
        if self._socket is None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._socket

    def _format_name(self, name: str) -> str:
        """Format metric name with prefix."""
        if self._prefix:
            return f"{self._prefix}.{name}"
        return name

    def _send(self, data: str) -> None:
        """Send data to StatsD server."""
        try:
            sock = self._get_socket()
            sock.sendto(data.encode("utf-8"), (self._host, self._port))
        except (OSError, ConnectionError, RuntimeError):
            pass  # StatsD is fire-and-forget

    def _flush_buffer(self) -> None:
        """Flush buffered metrics."""
        if self._buffer:
            data = "\n".join(self._buffer)
            self._send(data)
            self._buffer.clear()

    def _buffer_and_send(self, line: str) -> None:
        """Buffer a line and send if buffer is full."""
        with self._lock:
            self._buffer.append(line)
            if len(self._buffer) >= self._max_buffer_size:
                self._flush_buffer()

    def incr(self, name: str, value: int = 1, rate: float = 1.0) -> None:
        """Increment a counter."""
        line = f"{self._format_name(name)}:{value}|c"
        if rate < 1.0:
            line += f"|@{rate}"
        self._buffer_and_send(line)

    def decr(self, name: str, value: int = 1, rate: float = 1.0) -> None:
        """Decrement a counter."""
        self.incr(name, -value, rate)

    def gauge(self, name: str, value: float, delta: bool = False) -> None:
        """Set a gauge value."""
        if delta:
            prefix = "+" if value >= 0 else ""
            line = f"{self._format_name(name)}:{prefix}{value}|g"
        else:
            line = f"{self._format_name(name)}:{value}|g"
        self._buffer_and_send(line)

    def timing(self, name: str, value: float) -> None:
        """Record a timing in milliseconds."""
        line = f"{self._format_name(name)}:{value}|ms"
        self._buffer_and_send(line)

    def histogram(self, name: str, value: float) -> None:
        """Record a histogram value."""
        line = f"{self._format_name(name)}:{value}|h"
        self._buffer_and_send(line)

    @contextmanager
    def timer(self, name: str):
        """Context manager to time a block of code."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            self.timing(name, duration_ms)

    def flush(self) -> None:
        """Flush any buffered metrics."""
        with self._lock:
            self._flush_buffer()

    def close(self) -> None:
        """Close the client."""
        self.flush()
        if self._socket:
            self._socket.close()
            self._socket = None


# Convenience functions
def get_registry() -> MetricsRegistry:
    """Get the global metrics registry."""
    return MetricsRegistry.get_instance()


def counter(name: str, description: str = "", **kwargs) -> Counter:
    """Create and register a counter."""
    return get_registry().counter(name, description, **kwargs)


def gauge(name: str, description: str = "", **kwargs) -> Gauge:
    """Create and register a gauge."""
    return get_registry().gauge(name, description, **kwargs)


def histogram(name: str, description: str = "", **kwargs) -> Histogram:
    """Create and register a histogram."""
    return get_registry().histogram(name, description, **kwargs)


def timer(name: str, description: str = "", **kwargs) -> Timer:
    """Create and register a timer."""
    return get_registry().timer(name, description, **kwargs)


def timed(name: str | None = None, labels: Labels | None = None):
    """Decorator to time function execution."""

    def decorator(func: Callable) -> Callable:
        metric_name = name or f"{func.__module__}.{func.__name__}"
        timer_metric = get_registry().get(metric_name)
        if timer_metric is None:
            timer_metric = get_registry().timer(
                metric_name, f"Timer for {func.__name__}"
            )

        def wrapper(*args, **kwargs):
            with timer_metric.time(labels):
                return func(*args, **kwargs)

        return wrapper

    return decorator


def counted(name: str | None = None, labels: Labels | None = None):
    """Decorator to count function calls."""

    def decorator(func: Callable) -> Callable:
        metric_name = name or f"{func.__module__}.{func.__name__}.calls"
        counter_metric = get_registry().get(metric_name)
        if counter_metric is None:
            counter_metric = get_registry().counter(
                metric_name, f"Call count for {func.__name__}"
            )

        def wrapper(*args, **kwargs):
            counter_metric.inc(labels=labels)
            return func(*args, **kwargs)

        return wrapper

    return decorator
