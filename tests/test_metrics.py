"""Tests for the Metrics and Telemetry module."""

import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from redops.core.metrics import (
    Counter,
    EMPTY_LABELS,
    Gauge,
    Histogram,
    JSONExporter,
    Labels,
    MetricType,
    MetricValue,
    MetricsRegistry,
    PrometheusExporter,
    StatsDClient,
    StatsDExporter,
    Summary,
    Timer,
    counted,
    counter,
    gauge,
    get_registry,
    histogram,
    timed,
    timer,
)


class TestLabels:
    """Tests for Labels class."""

    def test_empty_labels(self):
        """Test empty labels."""
        labels = Labels()
        assert labels.to_dict() == {}
        assert labels == EMPTY_LABELS

    def test_labels_with_values(self):
        """Test labels with values."""
        labels = Labels(method="GET", path="/api")
        d = labels.to_dict()
        assert d["method"] == "GET"
        assert d["path"] == "/api"

    def test_labels_hashable(self):
        """Test labels are hashable for use as dict keys."""
        labels1 = Labels(a="1", b="2")
        labels2 = Labels(a="1", b="2")
        labels3 = Labels(a="1", b="3")

        d = {labels1: "value1"}
        assert d[labels2] == "value1"
        assert labels3 not in d

    def test_labels_equality(self):
        """Test labels equality."""
        labels1 = Labels(x="1", y="2")
        labels2 = Labels(y="2", x="1")  # Different order
        assert labels1 == labels2

    def test_labels_merge(self):
        """Test merging labels."""
        labels1 = Labels(a="1", b="2")
        labels2 = Labels(b="3", c="4")
        merged = labels1.merge(labels2)

        d = merged.to_dict()
        assert d["a"] == "1"
        assert d["b"] == "3"  # Overridden
        assert d["c"] == "4"


class TestMetricValue:
    """Tests for MetricValue."""

    def test_basic_value(self):
        """Test basic metric value."""
        value = MetricValue(value=42.0)
        assert value.value == 42.0
        assert value.labels == EMPTY_LABELS

    def test_value_with_labels(self):
        """Test metric value with labels."""
        labels = Labels(host="server1")
        value = MetricValue(value=100.0, labels=labels)
        assert value.labels == labels


class TestCounter:
    """Tests for Counter metric."""

    def test_initial_value(self):
        """Test counter starts at zero."""
        c = Counter("test_counter")
        assert c.get_value() == 0.0

    def test_increment(self):
        """Test counter increment."""
        c = Counter("test_counter")
        c.inc()
        assert c.get_value() == 1.0
        c.inc(5)
        assert c.get_value() == 6.0

    def test_negative_increment_fails(self):
        """Test that negative increment raises error."""
        c = Counter("test_counter")
        with pytest.raises(ValueError):
            c.inc(-1)

    def test_labeled_counter(self):
        """Test counter with labels."""
        c = Counter("requests")
        labels1 = Labels(method="GET")
        labels2 = Labels(method="POST")

        c.inc(labels=labels1)
        c.inc(labels=labels1)
        c.inc(labels=labels2)

        assert c.get_value(labels1) == 2.0
        assert c.get_value(labels2) == 1.0

    def test_get_all_values(self):
        """Test getting all labeled values."""
        c = Counter("test")
        c.inc()
        c.inc(labels=Labels(a="1"))

        values = c.get_all_values()
        assert len(values) == 2

    def test_reset(self):
        """Test counter reset."""
        c = Counter("test")
        c.inc(10)
        c.reset()
        assert c.get_value() == 0.0

    def test_metric_type(self):
        """Test metric type."""
        c = Counter("test")
        assert c.metric_type == MetricType.COUNTER


class TestGauge:
    """Tests for Gauge metric."""

    def test_initial_value(self):
        """Test gauge starts at zero."""
        g = Gauge("test_gauge")
        assert g.get_value() == 0.0

    def test_set_value(self):
        """Test setting gauge value."""
        g = Gauge("test_gauge")
        g.set(42.0)
        assert g.get_value() == 42.0

    def test_increment_decrement(self):
        """Test gauge inc/dec."""
        g = Gauge("test_gauge")
        g.inc(10)
        assert g.get_value() == 10.0
        g.dec(3)
        assert g.get_value() == 7.0

    def test_labeled_gauge(self):
        """Test gauge with labels."""
        g = Gauge("memory")
        labels = Labels(host="server1")
        g.set(1024, labels=labels)
        assert g.get_value(labels) == 1024

    def test_track_inprogress(self):
        """Test tracking in-progress operations."""
        g = Gauge("in_progress")

        with g.track_inprogress():
            assert g.get_value() == 1.0

        assert g.get_value() == 0.0

    def test_reset(self):
        """Test gauge reset."""
        g = Gauge("test")
        g.set(100)
        g.reset()
        assert g.get_value() == 0.0

    def test_metric_type(self):
        """Test metric type."""
        g = Gauge("test")
        assert g.metric_type == MetricType.GAUGE


class TestHistogram:
    """Tests for Histogram metric."""

    def test_default_buckets(self):
        """Test default buckets are created."""
        h = Histogram("latency")
        assert len(h.buckets) > 0
        assert h.buckets[-1] == float("inf")

    def test_custom_buckets(self):
        """Test custom buckets."""
        buckets = [0.1, 0.5, 1.0]
        h = Histogram("latency", buckets=buckets)
        assert h.buckets == (0.1, 0.5, 1.0, float("inf"))

    def test_observe(self):
        """Test observing values."""
        h = Histogram("latency", buckets=[0.1, 0.5, 1.0])
        h.observe(0.05)
        h.observe(0.3)
        h.observe(0.8)

        assert h.get_count() == 3
        assert h.get_value() == pytest.approx(1.15)

    def test_bucket_counts(self):
        """Test bucket counts."""
        h = Histogram("latency", buckets=[0.1, 0.5, 1.0])
        h.observe(0.05)  # <= 0.1
        h.observe(0.3)   # <= 0.5
        h.observe(0.8)   # <= 1.0

        counts = h.get_bucket_counts()
        assert counts[0.1] == 1
        assert counts[0.5] == 2
        assert counts[1.0] == 3

    def test_mean(self):
        """Test mean calculation."""
        h = Histogram("latency")
        h.observe(1.0)
        h.observe(2.0)
        h.observe(3.0)

        assert h.get_mean() == pytest.approx(2.0)

    def test_labeled_histogram(self):
        """Test histogram with labels."""
        h = Histogram("latency")
        labels = Labels(endpoint="/api")
        h.observe(0.5, labels=labels)

        assert h.get_count(labels) == 1

    def test_reset(self):
        """Test histogram reset."""
        h = Histogram("test")
        h.observe(1.0)
        h.reset()
        assert h.get_count() == 0

    def test_metric_type(self):
        """Test metric type."""
        h = Histogram("test")
        assert h.metric_type == MetricType.HISTOGRAM


class TestSummary:
    """Tests for Summary metric."""

    def test_default_quantiles(self):
        """Test default quantiles."""
        s = Summary("latency")
        assert 0.5 in s.quantiles
        assert 0.99 in s.quantiles

    def test_custom_quantiles(self):
        """Test custom quantiles."""
        s = Summary("latency", quantiles=[0.5, 0.75, 0.95])
        assert s.quantiles == (0.5, 0.75, 0.95)

    def test_observe(self):
        """Test observing values."""
        s = Summary("latency")
        for i in range(100):
            s.observe(float(i))

        assert s.get_count() == 100
        assert s.get_value() == sum(range(100))

    def test_quantile_calculation(self):
        """Test quantile calculation."""
        s = Summary("latency")
        for i in range(1, 101):  # 1 to 100
            s.observe(float(i))

        # 50th percentile should be around 50
        p50 = s.get_quantile(0.5)
        assert 45 <= p50 <= 55

    def test_get_quantiles(self):
        """Test getting all quantiles."""
        s = Summary("latency", quantiles=[0.5, 0.9])
        for i in range(100):
            s.observe(float(i))

        quantiles = s.get_quantiles()
        assert 0.5 in quantiles
        assert 0.9 in quantiles

    def test_reset(self):
        """Test summary reset."""
        s = Summary("test")
        s.observe(1.0)
        s.reset()
        assert s.get_count() == 0

    def test_metric_type(self):
        """Test metric type."""
        s = Summary("test")
        assert s.metric_type == MetricType.SUMMARY


class TestTimer:
    """Tests for Timer metric."""

    def test_observe(self):
        """Test observing durations."""
        t = Timer("request_duration")
        t.observe(0.5)
        t.observe(1.0)

        assert t.get_count() == 2
        assert t.get_value() == pytest.approx(1.5)

    def test_time_context_manager(self):
        """Test timing context manager."""
        t = Timer("operation")

        with t.time():
            time.sleep(0.01)

        assert t.get_count() == 1
        assert t.get_value() >= 0.01

    def test_mean(self):
        """Test mean duration."""
        t = Timer("test")
        t.observe(1.0)
        t.observe(2.0)

        assert t.get_mean() == pytest.approx(1.5)

    def test_unit(self):
        """Test timer unit defaults to seconds."""
        t = Timer("test")
        assert t.unit == "seconds"

    def test_reset(self):
        """Test timer reset."""
        t = Timer("test")
        t.observe(1.0)
        t.reset()
        assert t.get_count() == 0

    def test_metric_type(self):
        """Test metric type."""
        t = Timer("test")
        assert t.metric_type == MetricType.TIMER


class TestPrometheusExporter:
    """Tests for PrometheusExporter."""

    def test_export_counter(self):
        """Test exporting counter."""
        c = Counter("http_requests_total", "Total HTTP requests")
        c.inc(100)

        exporter = PrometheusExporter()
        output = exporter.export([c])

        assert "# HELP http_requests_total" in output
        assert "# TYPE http_requests_total counter" in output
        assert "http_requests_total 100" in output

    def test_export_gauge(self):
        """Test exporting gauge."""
        g = Gauge("temperature", "Current temperature")
        g.set(23.5)

        exporter = PrometheusExporter()
        output = exporter.export([g])

        assert "# TYPE temperature gauge" in output
        assert "temperature 23.5" in output

    def test_export_histogram(self):
        """Test exporting histogram."""
        h = Histogram("request_latency", buckets=[0.1, 0.5, 1.0])
        h.observe(0.3)

        exporter = PrometheusExporter()
        output = exporter.export([h])

        assert "request_latency_bucket" in output
        assert "request_latency_sum" in output
        assert "request_latency_count" in output

    def test_export_with_labels(self):
        """Test exporting metrics with labels."""
        c = Counter("requests")
        c.inc(labels=Labels(method="GET", path="/api"))

        exporter = PrometheusExporter()
        output = exporter.export([c])

        assert 'method="GET"' in output
        assert 'path="/api"' in output

    def test_sanitize_name(self):
        """Test name sanitization."""
        exporter = PrometheusExporter()
        assert exporter._sanitize_name("my.metric-name") == "my_metric_name"


class TestStatsDExporter:
    """Tests for StatsDExporter."""

    def test_export_counter(self):
        """Test exporting counter."""
        c = Counter("requests")
        c.inc(5)

        exporter = StatsDExporter()
        output = exporter.export([c])

        assert "requests:5" in output and "|c" in output

    def test_export_gauge(self):
        """Test exporting gauge."""
        g = Gauge("memory")
        g.set(1024)

        exporter = StatsDExporter()
        output = exporter.export([g])

        assert "memory:1024|g" in output

    def test_export_with_prefix(self):
        """Test exporting with prefix."""
        c = Counter("requests")
        c.inc()

        exporter = StatsDExporter(prefix="myapp")
        output = exporter.export([c])

        assert "myapp.requests:" in output

    def test_export_with_tags(self):
        """Test exporting with tags."""
        c = Counter("requests")
        c.inc(labels=Labels(env="prod"))

        exporter = StatsDExporter()
        output = exporter.export([c])

        assert "|#env:prod" in output


class TestJSONExporter:
    """Tests for JSONExporter."""

    def test_export_basic(self):
        """Test basic JSON export."""
        c = Counter("test", "Test counter")
        c.inc(10)

        exporter = JSONExporter()
        output = exporter.export([c])

        data = json.loads(output)
        assert "timestamp" in data
        assert "metrics" in data
        assert len(data["metrics"]) == 1

    def test_export_pretty(self):
        """Test pretty JSON export."""
        c = Counter("test")
        c.inc()

        exporter = JSONExporter(pretty=True)
        output = exporter.export([c])

        assert "\n" in output  # Pretty printing


class TestMetricsRegistry:
    """Tests for MetricsRegistry."""

    def setup_method(self):
        """Reset registry before each test."""
        MetricsRegistry.reset()

    def test_singleton(self):
        """Test singleton pattern."""
        r1 = MetricsRegistry.get_instance()
        r2 = MetricsRegistry.get_instance()
        assert r1 is r2

    def test_register_metric(self):
        """Test registering metrics."""
        registry = MetricsRegistry.get_instance()
        c = Counter("test_counter")
        registry.register(c)

        assert registry.get("test_counter") is c

    def test_duplicate_registration_fails(self):
        """Test that duplicate registration raises error."""
        registry = MetricsRegistry.get_instance()
        registry.register(Counter("test"))

        with pytest.raises(ValueError):
            registry.register(Counter("test"))

    def test_unregister(self):
        """Test unregistering metrics."""
        registry = MetricsRegistry.get_instance()
        registry.register(Counter("test"))
        registry.unregister("test")

        assert registry.get("test") is None

    def test_convenience_methods(self):
        """Test convenience methods for creating metrics."""
        registry = MetricsRegistry.get_instance()

        c = registry.counter("my_counter")
        g = registry.gauge("my_gauge")
        h = registry.histogram("my_histogram")
        s = registry.summary("my_summary")
        t = registry.timer("my_timer")

        assert isinstance(c, Counter)
        assert isinstance(g, Gauge)
        assert isinstance(h, Histogram)
        assert isinstance(s, Summary)
        assert isinstance(t, Timer)

    def test_get_all(self):
        """Test getting all metrics."""
        registry = MetricsRegistry.get_instance()
        registry.counter("c1")
        registry.gauge("g1")

        all_metrics = registry.get_all()
        assert len(all_metrics) == 2

    def test_export(self):
        """Test exporting all metrics."""
        registry = MetricsRegistry.get_instance()
        registry.counter("test").inc(5)

        exporter = JSONExporter()
        output = registry.export(exporter)

        data = json.loads(output)
        assert len(data["metrics"]) == 1

    def test_clear(self):
        """Test clearing all metrics."""
        registry = MetricsRegistry.get_instance()
        registry.counter("test")
        registry.clear()

        assert len(registry.get_all()) == 0


class TestStatsDClient:
    """Tests for StatsDClient."""

    def test_incr(self):
        """Test increment."""
        with patch.object(StatsDClient, '_send') as mock_send:
            client = StatsDClient()
            client.incr("requests", 5)
            client.flush()

            mock_send.assert_called()
            call_arg = mock_send.call_args[0][0]
            assert "requests:5|c" in call_arg

    def test_gauge(self):
        """Test gauge."""
        with patch.object(StatsDClient, '_send') as mock_send:
            client = StatsDClient()
            client.gauge("memory", 1024)
            client.flush()

            mock_send.assert_called()
            call_arg = mock_send.call_args[0][0]
            assert "memory:1024|g" in call_arg

    def test_timing(self):
        """Test timing."""
        with patch.object(StatsDClient, '_send') as mock_send:
            client = StatsDClient()
            client.timing("response_time", 150)
            client.flush()

            mock_send.assert_called()
            call_arg = mock_send.call_args[0][0]
            assert "response_time:150|ms" in call_arg

    def test_timer_context_manager(self):
        """Test timer context manager."""
        with patch.object(StatsDClient, '_send') as mock_send:
            client = StatsDClient()

            with client.timer("operation"):
                time.sleep(0.01)

            client.flush()
            mock_send.assert_called()

    def test_prefix(self):
        """Test metric prefix."""
        with patch.object(StatsDClient, '_send') as mock_send:
            client = StatsDClient(prefix="myapp")
            client.incr("requests")
            client.flush()

            mock_send.assert_called()
            call_arg = mock_send.call_args[0][0]
            assert "myapp.requests" in call_arg

    def test_buffering(self):
        """Test metric buffering."""
        with patch.object(StatsDClient, '_send') as mock_send:
            client = StatsDClient(max_buffer_size=3)

            client.incr("m1")
            client.incr("m2")
            assert mock_send.call_count == 0

            client.incr("m3")  # Should trigger flush
            assert mock_send.call_count == 1


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def setup_method(self):
        """Reset registry before each test."""
        MetricsRegistry.reset()

    def test_get_registry(self):
        """Test getting global registry."""
        r = get_registry()
        assert isinstance(r, MetricsRegistry)

    def test_counter_function(self):
        """Test counter convenience function."""
        c = counter("my_counter", "A counter")
        assert isinstance(c, Counter)
        assert get_registry().get("my_counter") is c

    def test_gauge_function(self):
        """Test gauge convenience function."""
        g = gauge("my_gauge", "A gauge")
        assert isinstance(g, Gauge)

    def test_histogram_function(self):
        """Test histogram convenience function."""
        h = histogram("my_histogram", "A histogram")
        assert isinstance(h, Histogram)

    def test_timer_function(self):
        """Test timer convenience function."""
        t = timer("my_timer", "A timer")
        assert isinstance(t, Timer)


class TestTimedDecorator:
    """Tests for @timed decorator."""

    def setup_method(self):
        """Reset registry before each test."""
        MetricsRegistry.reset()

    def test_basic_timing(self):
        """Test basic function timing."""
        @timed("test_function")
        def my_function():
            time.sleep(0.01)
            return 42

        result = my_function()
        assert result == 42

        timer_metric = get_registry().get("test_function")
        assert timer_metric.get_count() == 1
        assert timer_metric.get_value() >= 0.01

    def test_auto_naming(self):
        """Test automatic metric naming."""
        @timed()
        def another_function():
            return "hello"

        another_function()

        # Should use module.function_name
        metrics = get_registry().get_all()
        assert len(metrics) == 1


class TestCountedDecorator:
    """Tests for @counted decorator."""

    def setup_method(self):
        """Reset registry before each test."""
        MetricsRegistry.reset()

    def test_basic_counting(self):
        """Test basic function counting."""
        @counted("my_function_calls")
        def my_function():
            return 42

        my_function()
        my_function()
        my_function()

        counter_metric = get_registry().get("my_function_calls")
        assert counter_metric.get_value() == 3

    def test_with_labels(self):
        """Test counting with labels."""
        labels = Labels(version="1.0")

        @counted("api_calls", labels=labels)
        def api_handler():
            return "ok"

        api_handler()

        counter_metric = get_registry().get("api_calls")
        assert counter_metric.get_value(labels) == 1


class TestThreadSafety:
    """Tests for thread safety."""

    def setup_method(self):
        """Reset registry before each test."""
        MetricsRegistry.reset()

    def test_concurrent_counter_increment(self):
        """Test concurrent counter increments."""
        c = Counter("concurrent_counter")

        def increment_many():
            for _ in range(1000):
                c.inc()

        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert c.get_value() == 10000

    def test_concurrent_gauge_updates(self):
        """Test concurrent gauge updates."""
        g = Gauge("concurrent_gauge")

        def update_gauge(thread_id):
            for i in range(100):
                g.set(float(thread_id * 100 + i))

        threads = [threading.Thread(target=update_gauge, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Gauge should have some value (not checking specific due to race)
        assert isinstance(g.get_value(), (int, float))

    def test_concurrent_histogram_observations(self):
        """Test concurrent histogram observations."""
        h = Histogram("concurrent_histogram")

        def observe_many():
            for i in range(100):
                h.observe(float(i) / 100)

        threads = [threading.Thread(target=observe_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert h.get_count() == 1000


class TestMetricProperties:
    """Tests for metric properties."""

    def test_name_property(self):
        """Test name property."""
        c = Counter("test_name", "Description")
        assert c.name == "test_name"

    def test_description_property(self):
        """Test description property."""
        c = Counter("test", "My description")
        assert c.description == "My description"

    def test_unit_property(self):
        """Test unit property."""
        c = Counter("test", unit="bytes")
        assert c.unit == "bytes"

    def test_labels_property(self):
        """Test labels property."""
        labels = Labels(env="prod")
        c = Counter("test", labels=labels)
        assert c.labels == labels

    def test_to_dict(self):
        """Test to_dict method."""
        c = Counter("test_counter", "A test counter")
        c.inc(5)

        d = c.to_dict()
        assert d["name"] == "test_counter"
        assert d["type"] == "counter"
        assert d["description"] == "A test counter"
        assert d["value"] == 5.0
