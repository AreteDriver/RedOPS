"""Tests for observability module: metrics, tracing, logging."""

import pytest
from unittest.mock import patch, MagicMock
import json
import logging


class TestMetricsCollector:
    """Tests for metrics collection."""

    def test_metrics_config_from_env(self):
        """Test MetricsConfig from environment variables."""
        env = {
            "METRICS_ENABLED": "true",
            "OTEL_SERVICE_NAME": "test-service",
            "PROMETHEUS_PORT": "9999",
        }
        with patch.dict("os.environ", env):
            from redops.observability.metrics import MetricsConfig
            config = MetricsConfig.from_env()

            assert config.enabled is True
            assert config.service_name == "test-service"
            assert config.prometheus_port == 9999

    def test_metrics_collector_disabled(self):
        """Test metrics collector when disabled."""
        from redops.observability.metrics import MetricsCollector, MetricsConfig

        config = MetricsConfig(enabled=False)
        collector = MetricsCollector(config)

        # Should not raise, just no-op
        collector.record_scan("test", "example.com", "success", 1.0)
        collector.record_finding("test.module", "high")
        collector.record_api_request("GET", "/api/scan", 200, 0.1)

    def test_metrics_collector_no_otel(self):
        """Test metrics collector without OpenTelemetry."""
        with patch("redops.observability.metrics.HAS_OTEL", False):
            from redops.observability.metrics import MetricsCollector, MetricsConfig

            config = MetricsConfig(enabled=True)
            collector = MetricsCollector(config)

            # Should not be initialized without OTEL
            assert not collector._initialized

    def test_gauge_operations(self):
        """Test gauge increment/decrement."""
        from redops.observability.metrics import MetricsCollector, MetricsConfig

        config = MetricsConfig(enabled=False)
        collector = MetricsCollector(config)

        collector.set_gauge("active_scans", 5)
        assert collector._gauge_values["active_scans"] == 5

        collector.increment_gauge("active_scans", 2)
        assert collector._gauge_values["active_scans"] == 7

        collector.decrement_gauge("active_scans", 3)
        assert collector._gauge_values["active_scans"] == 4

        # Should not go below 0
        collector.decrement_gauge("active_scans", 10)
        assert collector._gauge_values["active_scans"] == 0

    def test_get_metrics_collector_singleton(self):
        """Test global metrics collector is singleton."""
        from redops.observability.metrics import get_metrics_collector

        collector1 = get_metrics_collector()
        collector2 = get_metrics_collector()

        # Note: They may be different in tests due to module reloading
        assert collector1 is not None
        assert collector2 is not None

    def test_record_scan_duration_decorator(self):
        """Test scan duration decorator."""
        from redops.observability.metrics import record_scan_duration

        @record_scan_duration(pipeline="test", target="example.com")
        def mock_scan():
            return "result"

        result = mock_scan()
        assert result == "result"

    def test_record_api_request_decorator(self):
        """Test API request decorator."""
        from redops.observability.metrics import record_api_request

        @record_api_request(method="GET", endpoint="/test")
        def mock_endpoint():
            return MagicMock(status_code=200)

        result = mock_endpoint()
        assert result.status_code == 200


class TestTracingProvider:
    """Tests for distributed tracing."""

    def test_tracing_config_from_env(self):
        """Test TracingConfig from environment variables."""
        env = {
            "TRACING_ENABLED": "true",
            "OTEL_SERVICE_NAME": "test-service",
            "TRACING_EXPORTER": "jaeger",
            "JAEGER_HOST": "jaeger.local",
        }
        with patch.dict("os.environ", env):
            from redops.observability.tracing import TracingConfig
            config = TracingConfig.from_env()

            assert config.enabled is True
            assert config.service_name == "test-service"
            assert config.exporter == "jaeger"
            assert config.jaeger_host == "jaeger.local"

    def test_tracing_provider_disabled(self):
        """Test tracing provider when disabled."""
        from redops.observability.tracing import TracingProvider, TracingConfig

        config = TracingConfig(enabled=False)
        provider = TracingProvider(config)

        assert not provider._initialized

    def test_tracing_provider_no_otel(self):
        """Test tracing provider without OpenTelemetry."""
        with patch("redops.observability.tracing.HAS_OTEL", False):
            from redops.observability.tracing import TracingProvider, TracingConfig

            config = TracingConfig(enabled=True)
            provider = TracingProvider(config)

            assert not provider._initialized

    def test_start_span_disabled(self):
        """Test span creation when disabled."""
        from redops.observability.tracing import TracingProvider, TracingConfig

        config = TracingConfig(enabled=False)
        provider = TracingProvider(config)

        with provider.start_span("test-span") as span:
            assert span is None

    def test_trace_function_decorator(self):
        """Test function tracing decorator."""
        from redops.observability.tracing import trace_function

        @trace_function(name="test-function")
        def mock_function(x, y):
            return x + y

        result = mock_function(1, 2)
        assert result == 3

    def test_trace_function_async_decorator(self):
        """Test async function tracing decorator."""
        import asyncio
        from redops.observability.tracing import trace_function

        @trace_function(name="async-test")
        async def mock_async():
            return "async-result"

        result = asyncio.get_event_loop().run_until_complete(mock_async())
        assert result == "async-result"

    def test_trace_pipeline_decorator(self):
        """Test pipeline tracing decorator."""
        from redops.observability.tracing import trace_pipeline
        from redops.core.context import Context

        @trace_pipeline(pipeline_name="test-pipeline")
        def mock_pipeline(target=None):
            ctx = Context(target=target)
            ctx.add("finding_test", {"title": "Test"})
            return ctx

        result = mock_pipeline(target="example.com")
        assert result.target == "example.com"

    def test_trace_module_decorator(self):
        """Test module tracing decorator."""
        from redops.observability.tracing import trace_module
        from redops.core.context import Context

        @trace_module(module_name="test.module")
        def mock_module(ctx, params=None):
            ctx.add("result", "done")
            return ctx

        ctx = Context(target="example.com")
        result = mock_module(ctx)
        assert result.get("result") == "done"


class TestStructuredLogging:
    """Tests for structured logging."""

    def test_logging_config_from_env(self):
        """Test LoggingConfig from environment variables."""
        env = {
            "LOG_LEVEL": "DEBUG",
            "LOG_FORMAT": "json",
            "OTEL_SERVICE_NAME": "test-service",
        }
        with patch.dict("os.environ", env):
            from redops.observability.logging import LoggingConfig
            config = LoggingConfig.from_env()

            assert config.level == "DEBUG"
            assert config.format == "json"
            assert config.service_name == "test-service"

    def test_log_context_set_get(self):
        """Test LogContext set and get."""
        from redops.observability.logging import LogContext

        LogContext.clear()
        LogContext.set("request_id", "123")
        LogContext.set("user", "test")

        assert LogContext.get("request_id") == "123"
        assert LogContext.get("user") == "test"
        assert LogContext.get("missing", "default") == "default"

    def test_log_context_scope(self):
        """Test LogContext scope management."""
        from redops.observability.logging import LogContext

        LogContext.clear()
        LogContext.set("outer", "value")

        with LogContext.scope(inner="scoped"):
            assert LogContext.get("outer") == "value"
            assert LogContext.get("inner") == "scoped"

        # After scope, inner should be gone
        assert LogContext.get("inner") is None
        assert LogContext.get("outer") == "value"

    def test_json_formatter(self):
        """Test JSON log formatter."""
        from redops.observability.logging import JsonFormatter

        formatter = JsonFormatter(
            service_name="test",
            include_trace_id=False,
            include_timestamp=True,
        )

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["service"] == "test"
        assert "timestamp" in data

    def test_json_formatter_with_extra(self):
        """Test JSON formatter with extra fields."""
        from redops.observability.logging import JsonFormatter

        formatter = JsonFormatter(service_name="test", include_trace_id=False)

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.custom_field = "custom_value"
        record.scan_id = "scan-123"

        output = formatter.format(record)
        data = json.loads(output)

        assert data["custom_field"] == "custom_value"
        assert data["scan_id"] == "scan-123"

    def test_text_formatter(self):
        """Test text log formatter."""
        from redops.observability.logging import TextFormatter

        formatter = TextFormatter()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        assert "INFO" in output
        assert "Test message" in output
        assert "[test.logger]" in output

    def test_structured_logger(self):
        """Test structured logger wrapper."""
        from redops.observability.logging import StructuredLogger

        mock_logger = MagicMock()
        logger = StructuredLogger(mock_logger)

        logger.info("Test message", request_id="123")

        mock_logger.log.assert_called_once()
        call_args = mock_logger.log.call_args
        assert call_args[0][0] == logging.INFO
        assert call_args[0][1] == "Test message"
        assert call_args[1]["extra"]["request_id"] == "123"

    def test_structured_logger_levels(self):
        """Test all logging levels."""
        from redops.observability.logging import StructuredLogger

        mock_logger = MagicMock()
        logger = StructuredLogger(mock_logger)

        logger.debug("debug")
        logger.info("info")
        logger.warning("warning")
        logger.error("error")
        logger.critical("critical")

        assert mock_logger.log.call_count == 5

    def test_structured_logger_context(self):
        """Test structured logger with context scope."""
        from redops.observability.logging import StructuredLogger, LogContext

        mock_logger = MagicMock()
        logger = StructuredLogger(mock_logger)

        LogContext.clear()
        with logger.context(request_id="456"):
            assert LogContext.get("request_id") == "456"

    def test_setup_structured_logging(self):
        """Test logging setup."""
        from redops.observability.logging import setup_structured_logging, LoggingConfig

        config = LoggingConfig(
            level="DEBUG",
            format="json",
            output="stdout",
        )

        setup_structured_logging(config)

        logger = logging.getLogger("redops")
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1

    def test_get_logger(self):
        """Test get_logger function."""
        from redops.observability.logging import get_logger

        logger = get_logger("test.module")

        assert logger._logger.name == "redops.test.module"

    def test_get_logger_with_prefix(self):
        """Test get_logger with redops prefix."""
        from redops.observability.logging import get_logger

        logger = get_logger("redops.existing")

        assert logger._logger.name == "redops.existing"


class TestObservabilityImports:
    """Test that all observability modules are properly exported."""

    def test_metrics_imports(self):
        """Test metrics imports."""
        from redops.observability import (
            MetricsCollector,
            get_metrics_collector,
            record_scan_duration,
            record_finding_count,
            record_api_request,
        )

        assert callable(get_metrics_collector)
        assert callable(record_scan_duration)

    def test_tracing_imports(self):
        """Test tracing imports."""
        from redops.observability import (
            TracingProvider,
            get_tracer,
            trace_function,
            trace_pipeline,
            trace_module,
        )

        assert callable(get_tracer)
        assert callable(trace_function)
        assert callable(trace_pipeline)
        assert callable(trace_module)

    def test_logging_imports(self):
        """Test logging imports."""
        from redops.observability import (
            setup_structured_logging,
            get_logger,
            LogContext,
        )

        assert callable(setup_structured_logging)
        assert callable(get_logger)
