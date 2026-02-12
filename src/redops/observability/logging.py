"""
Structured logging for RedOPS.

Provides JSON-formatted logging with trace correlation and context propagation.
"""

from typing import Any
from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import contextmanager
import logging
import json
import os
import sys
import threading

# Try to import OpenTelemetry for trace correlation
try:
    from opentelemetry import trace

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "INFO"
    format: str = "json"  # json or text
    service_name: str = "redops"
    include_trace_id: bool = True
    include_timestamp: bool = True
    output: str = "stdout"  # stdout, stderr, file
    file_path: str = ""

    @classmethod
    def from_env(cls) -> "LoggingConfig":
        """Create config from environment variables."""
        return cls(
            level=os.environ.get("LOG_LEVEL", "INFO"),
            format=os.environ.get("LOG_FORMAT", "json"),
            service_name=os.environ.get("OTEL_SERVICE_NAME", "redops"),
            include_trace_id=os.environ.get("LOG_TRACE_ID", "true").lower() == "true",
            include_timestamp=os.environ.get("LOG_TIMESTAMP", "true").lower() == "true",
            output=os.environ.get("LOG_OUTPUT", "stdout"),
            file_path=os.environ.get("LOG_FILE", ""),
        )


class LogContext:
    """
    Thread-local context for logging.

    Stores contextual information that will be included in all log messages
    within the current thread/async context.
    """

    _local = threading.local()

    @classmethod
    def get_context(cls) -> dict[str, Any]:
        """Get the current context."""
        if not hasattr(cls._local, "context"):
            cls._local.context = {}
        return cls._local.context

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        """Set a context value."""
        ctx = cls.get_context()
        ctx[key] = value

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """Get a context value."""
        ctx = cls.get_context()
        return ctx.get(key, default)

    @classmethod
    def clear(cls) -> None:
        """Clear all context."""
        cls._local.context = {}

    @classmethod
    @contextmanager
    def scope(cls, **kwargs):
        """
        Create a context scope.

        Args:
            **kwargs: Context values to set

        Yields:
            The context
        """
        old_context = cls.get_context().copy()
        try:
            for key, value in kwargs.items():
                cls.set(key, value)
            yield cls.get_context()
        finally:
            cls._local.context = old_context


class JsonFormatter(logging.Formatter):
    """JSON log formatter with OpenTelemetry trace correlation."""

    def __init__(
        self,
        service_name: str = "redops",
        include_trace_id: bool = True,
        include_timestamp: bool = True,
    ):
        super().__init__()
        self.service_name = service_name
        self.include_trace_id = include_trace_id
        self.include_timestamp = include_timestamp

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        log_data = {
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "service": self.service_name,
        }

        if self.include_timestamp:
            log_data["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Add trace context if available
        if self.include_trace_id and HAS_OTEL:
            span = trace.get_current_span()
            if span:
                span_context = span.get_span_context()
                if span_context.is_valid:
                    log_data["trace_id"] = format(span_context.trace_id, "032x")
                    log_data["span_id"] = format(span_context.span_id, "016x")

        # Add thread-local context
        log_context = LogContext.get_context()
        if log_context:
            log_data["context"] = log_context

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields from the record
        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
            ):
                try:
                    json.dumps(value)  # Check if serializable
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter with colors."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as colored text."""
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        message = record.getMessage()

        # Build the log line
        parts = [
            f"{timestamp}",
            f"{color}{record.levelname:8}{reset}",
            f"[{record.name}]",
            message,
        ]

        # Add context if present
        log_context = LogContext.get_context()
        if log_context:
            context_str = " ".join(f"{k}={v}" for k, v in log_context.items())
            parts.append(f"({context_str})")

        # Add trace ID if available
        if HAS_OTEL:
            span = trace.get_current_span()
            if span:
                span_context = span.get_span_context()
                if span_context.is_valid:
                    trace_id = format(span_context.trace_id, "032x")[:8]
                    parts.append(f"[trace:{trace_id}]")

        log_line = " ".join(parts)

        # Add exception if present
        if record.exc_info:
            log_line += f"\n{self.formatException(record.exc_info)}"

        return log_line


class StructuredLogger:
    """
    Structured logger wrapper.

    Provides convenient methods for logging with context and extra fields.
    """

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def _log(
        self,
        level: int,
        message: str,
        **kwargs,
    ) -> None:
        """Log a message with extra fields."""
        self._logger.log(level, message, extra=kwargs)

    def debug(self, message: str, **kwargs) -> None:
        """Log a debug message."""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        """Log an info message."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """Log a warning message."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        """Log an error message."""
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        """Log a critical message."""
        self._log(logging.CRITICAL, message, **kwargs)

    def exception(self, message: str, **kwargs) -> None:
        """Log an exception with traceback."""
        self._logger.exception(message, extra=kwargs)

    @contextmanager
    def context(self, **kwargs):
        """
        Create a logging context scope.

        Args:
            **kwargs: Context values

        Yields:
            Self for method chaining
        """
        with LogContext.scope(**kwargs):
            yield self


def setup_structured_logging(config: LoggingConfig | None = None) -> None:
    """
    Set up structured logging.

    Args:
        config: Logging configuration
    """
    config = config or LoggingConfig.from_env()

    # Get the root logger for redops
    logger = logging.getLogger("redops")
    logger.setLevel(getattr(logging, config.level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Create formatter
    if config.format.lower() == "json":
        formatter = JsonFormatter(
            service_name=config.service_name,
            include_trace_id=config.include_trace_id,
            include_timestamp=config.include_timestamp,
        )
    else:
        formatter = TextFormatter()

    # Create handler
    if config.output == "file" and config.file_path:
        handler = logging.FileHandler(config.file_path)
    elif config.output == "stderr":
        handler = logging.StreamHandler(sys.stderr)
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Don't propagate to root logger
    logger.propagate = False


def get_logger(name: str = "redops") -> StructuredLogger:
    """
    Get a structured logger.

    Args:
        name: Logger name (will be prefixed with "redops.")

    Returns:
        StructuredLogger instance
    """
    if not name.startswith("redops"):
        name = f"redops.{name}"
    return StructuredLogger(logging.getLogger(name))
