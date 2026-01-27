"""
Logging and Auditing Module for RedOPS.

Provides structured logging, audit trails, log rotation,
and context propagation for security operations.
"""

import json
import re
import sys
import threading
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union


class LogLevel(Enum):
    """Log severity levels."""

    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    AUDIT = 60  # Special level for audit events

    @classmethod
    def from_string(cls, level: str) -> "LogLevel":
        """Convert string to LogLevel."""
        mapping = {
            "trace": cls.TRACE,
            "debug": cls.DEBUG,
            "info": cls.INFO,
            "warning": cls.WARNING,
            "warn": cls.WARNING,
            "error": cls.ERROR,
            "critical": cls.CRITICAL,
            "audit": cls.AUDIT,
        }
        return mapping.get(level.lower(), cls.INFO)


class AuditEventType(Enum):
    """Types of audit events."""

    # Authentication events
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_FAILED = "auth.failed"
    AUTH_TOKEN_REFRESH = "auth.token_refresh"

    # Data access events
    DATA_READ = "data.read"
    DATA_WRITE = "data.write"
    DATA_DELETE = "data.delete"
    DATA_EXPORT = "data.export"

    # Configuration events
    CONFIG_CHANGE = "config.change"
    CONFIG_READ = "config.read"

    # Security events
    SECURITY_ALERT = "security.alert"
    SECURITY_SCAN = "security.scan"
    SECURITY_THREAT = "security.threat"

    # System events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_ERROR = "system.error"

    # Custom events
    CUSTOM = "custom"


@dataclass
class LogContext:
    """Context information for log entries."""

    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    component: Optional[str] = None
    operation: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary."""
        result = {}
        if self.correlation_id:
            result["correlation_id"] = self.correlation_id
        if self.request_id:
            result["request_id"] = self.request_id
        if self.user_id:
            result["user_id"] = self.user_id
        if self.session_id:
            result["session_id"] = self.session_id
        if self.component:
            result["component"] = self.component
        if self.operation:
            result["operation"] = self.operation
        result.update(self.extra)
        return result

    def merge(self, other: "LogContext") -> "LogContext":
        """Merge with another context, other takes precedence."""
        return LogContext(
            correlation_id=other.correlation_id or self.correlation_id,
            request_id=other.request_id or self.request_id,
            user_id=other.user_id or self.user_id,
            session_id=other.session_id or self.session_id,
            component=other.component or self.component,
            operation=other.operation or self.operation,
            extra={**self.extra, **other.extra},
        )


@dataclass
class AuditEvent:
    """Represents an audit event."""

    event_type: AuditEventType
    timestamp: datetime
    actor: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    outcome: str = "success"
    details: Dict[str, Any] = field(default_factory=dict)
    context: Optional[LogContext] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        result = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "outcome": self.outcome,
        }
        if self.actor:
            result["actor"] = self.actor
        if self.resource:
            result["resource"] = self.resource
        if self.action:
            result["action"] = self.action
        if self.details:
            result["details"] = self.details
        if self.context:
            result["context"] = self.context.to_dict()
        return result


@dataclass
class LogEntry:
    """Represents a structured log entry."""

    level: LogLevel
    message: str
    timestamp: datetime
    logger_name: str
    context: Optional[LogContext] = None
    exception: Optional[Exception] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary."""
        result = {
            "level": self.level.name,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "logger": self.logger_name,
        }
        if self.context:
            result["context"] = self.context.to_dict()
        if self.exception:
            result["exception"] = {
                "type": type(self.exception).__name__,
                "message": str(self.exception),
            }
        if self.extra:
            result["extra"] = self.extra
        return result


class SensitiveDataMasker:
    """Masks sensitive data in log messages."""

    # Default patterns to mask
    DEFAULT_PATTERNS = [
        (r'password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', "password=***"),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', "api_key=***"),
        (r'secret["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', "secret=***"),
        (r'token["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', "token=***"),
        (r"bearer\s+([A-Za-z0-9\-_=]+)", "Bearer ***"),
        (r"\b\d{16}\b", "****-****-****-****"),  # Credit card
        (r"\b\d{3}-\d{2}-\d{4}\b", "***-**-****"),  # SSN
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "***@***.***"),  # Email
    ]

    def __init__(
        self, patterns: Optional[List[tuple]] = None, mask_emails: bool = False
    ):
        """Initialize masker with patterns."""
        self._patterns = (
            list(self.DEFAULT_PATTERNS) if patterns is None else list(patterns)
        )
        if not mask_emails:
            # Remove email pattern if not masking emails
            self._patterns = [p for p in self._patterns if "@" not in p[1]]
        self._compiled = [
            (re.compile(p[0], re.IGNORECASE), p[1]) for p in self._patterns
        ]

    def add_pattern(self, pattern: str, replacement: str) -> None:
        """Add a custom pattern to mask."""
        self._patterns.append((pattern, replacement))
        self._compiled.append((re.compile(pattern, re.IGNORECASE), replacement))

    def mask(self, text: str) -> str:
        """Mask sensitive data in text."""
        result = text
        for regex, replacement in self._compiled:
            result = regex.sub(replacement, result)
        return result

    def mask_dict(
        self, data: Dict[str, Any], sensitive_keys: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        """Mask sensitive data in a dictionary."""
        if sensitive_keys is None:
            sensitive_keys = {
                "password",
                "secret",
                "token",
                "api_key",
                "apikey",
                "credential",
            }

        result = {}
        for key, value in data.items():
            if key.lower() in sensitive_keys:
                result[key] = "***"
            elif isinstance(value, str):
                result[key] = self.mask(value)
            elif isinstance(value, dict):
                result[key] = self.mask_dict(value, sensitive_keys)
            else:
                result[key] = value
        return result


class LogFormatter(ABC):
    """Base class for log formatters."""

    @abstractmethod
    def format(self, entry: LogEntry) -> str:
        """Format a log entry to string."""
        pass


class TextFormatter(LogFormatter):
    """Plain text log formatter."""

    def __init__(
        self,
        format_string: Optional[str] = None,
        include_context: bool = True,
        include_extra: bool = True,
    ):
        """Initialize text formatter."""
        self._format_string = (
            format_string or "{timestamp} [{level}] {logger}: {message}"
        )
        self._include_context = include_context
        self._include_extra = include_extra

    def format(self, entry: LogEntry) -> str:
        """Format log entry as text."""
        result = self._format_string.format(
            timestamp=entry.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            level=entry.level.name.ljust(8),
            logger=entry.logger_name,
            message=entry.message,
        )

        if self._include_context and entry.context:
            ctx = entry.context.to_dict()
            if ctx:
                ctx_str = " ".join(f"{k}={v}" for k, v in ctx.items())
                result += f" [{ctx_str}]"

        if self._include_extra and entry.extra:
            extra_str = " ".join(f"{k}={v}" for k, v in entry.extra.items())
            result += f" {{{extra_str}}}"

        if entry.exception:
            result += (
                f"\n  Exception: {type(entry.exception).__name__}: {entry.exception}"
            )

        return result


class JSONFormatter(LogFormatter):
    """JSON log formatter."""

    def __init__(self, pretty: bool = False, include_all: bool = True):
        """Initialize JSON formatter."""
        self._pretty = pretty
        self._include_all = include_all

    def format(self, entry: LogEntry) -> str:
        """Format log entry as JSON."""
        data = entry.to_dict()
        if self._pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)


class LogHandler(ABC):
    """Base class for log handlers."""

    def __init__(
        self,
        formatter: Optional[LogFormatter] = None,
        level: LogLevel = LogLevel.DEBUG,
        masker: Optional[SensitiveDataMasker] = None,
    ):
        """Initialize handler."""
        self._formatter = formatter or TextFormatter()
        self._level = level
        self._masker = masker

    @abstractmethod
    def emit(self, entry: LogEntry) -> None:
        """Emit a log entry."""
        pass

    def should_handle(self, entry: LogEntry) -> bool:
        """Check if this handler should process the entry."""
        return entry.level.value >= self._level.value

    def handle(self, entry: LogEntry) -> None:
        """Handle a log entry."""
        if self.should_handle(entry):
            # Mask sensitive data if masker is configured
            if self._masker:
                masked_message = self._masker.mask(entry.message)
                if entry.extra:
                    masked_extra = self._masker.mask_dict(entry.extra)
                else:
                    masked_extra = entry.extra
                entry = LogEntry(
                    level=entry.level,
                    message=masked_message,
                    timestamp=entry.timestamp,
                    logger_name=entry.logger_name,
                    context=entry.context,
                    exception=entry.exception,
                    extra=masked_extra,
                )
            self.emit(entry)

    def close(self) -> None:
        """Close the handler."""
        pass


class ConsoleHandler(LogHandler):
    """Handler that writes to console."""

    def __init__(self, stream: Optional[Any] = None, colorize: bool = True, **kwargs):
        """Initialize console handler."""
        super().__init__(**kwargs)
        self._stream = stream or sys.stderr
        self._colorize = (
            colorize and hasattr(self._stream, "isatty") and self._stream.isatty()
        )

        # ANSI color codes
        self._colors = {
            LogLevel.TRACE: "\033[90m",  # Gray
            LogLevel.DEBUG: "\033[36m",  # Cyan
            LogLevel.INFO: "\033[32m",  # Green
            LogLevel.WARNING: "\033[33m",  # Yellow
            LogLevel.ERROR: "\033[31m",  # Red
            LogLevel.CRITICAL: "\033[35m",  # Magenta
            LogLevel.AUDIT: "\033[34m",  # Blue
        }
        self._reset = "\033[0m"

    def emit(self, entry: LogEntry) -> None:
        """Emit log entry to console."""
        formatted = self._formatter.format(entry)

        if self._colorize:
            color = self._colors.get(entry.level, "")
            formatted = f"{color}{formatted}{self._reset}"

        print(formatted, file=self._stream)


class FileHandler(LogHandler):
    """Handler that writes to a file."""

    def __init__(
        self, path: Union[str, Path], mode: str = "a", encoding: str = "utf-8", **kwargs
    ):
        """Initialize file handler."""
        super().__init__(**kwargs)
        self._path = Path(path)
        self._mode = mode
        self._encoding = encoding
        self._file: Optional[Any] = None
        self._lock = threading.Lock()
        self._open_file()

    def _open_file(self) -> None:
        """Open the log file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, self._mode, encoding=self._encoding)

    def emit(self, entry: LogEntry) -> None:
        """Emit log entry to file."""
        formatted = self._formatter.format(entry)
        with self._lock:
            if self._file:
                self._file.write(formatted + "\n")
                self._file.flush()

    def close(self) -> None:
        """Close the file handler."""
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None


class RotatingFileHandler(LogHandler):
    """Handler that writes to rotating log files."""

    def __init__(
        self,
        path: Union[str, Path],
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
        encoding: str = "utf-8",
        **kwargs,
    ):
        """Initialize rotating file handler."""
        super().__init__(**kwargs)
        self._path = Path(path)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._encoding = encoding
        self._file: Optional[Any] = None
        self._lock = threading.Lock()
        self._current_size = 0
        self._open_file()

    def _open_file(self) -> None:
        """Open the log file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a", encoding=self._encoding)
        self._current_size = self._path.stat().st_size if self._path.exists() else 0

    def _rotate(self) -> None:
        """Rotate log files."""
        if self._file:
            self._file.close()

        # Rotate existing backups
        for i in range(self._backup_count - 1, 0, -1):
            src = self._path.with_suffix(f"{self._path.suffix}.{i}")
            dst = self._path.with_suffix(f"{self._path.suffix}.{i + 1}")
            if src.exists():
                src.rename(dst)

        # Move current to .1
        if self._path.exists():
            self._path.rename(self._path.with_suffix(f"{self._path.suffix}.1"))

        # Open new file
        self._open_file()

    def emit(self, entry: LogEntry) -> None:
        """Emit log entry with rotation."""
        formatted = self._formatter.format(entry) + "\n"
        encoded_size = len(formatted.encode(self._encoding))

        with self._lock:
            if self._current_size + encoded_size > self._max_bytes:
                self._rotate()

            if self._file:
                self._file.write(formatted)
                self._file.flush()
                self._current_size += encoded_size

    def close(self) -> None:
        """Close the rotating file handler."""
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None


class MemoryHandler(LogHandler):
    """Handler that stores logs in memory (useful for testing)."""

    def __init__(self, max_entries: int = 1000, **kwargs):
        """Initialize memory handler."""
        super().__init__(**kwargs)
        self._max_entries = max_entries
        self._entries: List[LogEntry] = []
        self._lock = threading.Lock()

    def emit(self, entry: LogEntry) -> None:
        """Store log entry in memory."""
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries = self._entries[-self._max_entries :]

    def get_entries(self, level: Optional[LogLevel] = None) -> List[LogEntry]:
        """Get stored log entries."""
        with self._lock:
            if level:
                return [e for e in self._entries if e.level == level]
            return list(self._entries)

    def clear(self) -> None:
        """Clear stored entries."""
        with self._lock:
            self._entries.clear()


class AuditLogger:
    """Dedicated logger for audit events."""

    def __init__(
        self,
        handlers: Optional[List[LogHandler]] = None,
        context: Optional[LogContext] = None,
    ):
        """Initialize audit logger."""
        self._handlers = handlers or []
        self._context = context
        self._lock = threading.Lock()

    def add_handler(self, handler: LogHandler) -> None:
        """Add a handler."""
        with self._lock:
            self._handlers.append(handler)

    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        # Merge contexts
        if self._context and event.context:
            event.context = self._context.merge(event.context)
        elif self._context:
            event.context = self._context

        # Create log entry from audit event
        entry = LogEntry(
            level=LogLevel.AUDIT,
            message=f"[AUDIT] {event.event_type.value}: {event.action or 'N/A'}",
            timestamp=event.timestamp,
            logger_name="audit",
            context=event.context,
            extra=event.to_dict(),
        )

        with self._lock:
            for handler in self._handlers:
                handler.handle(entry)

    def auth_login(self, actor: str, outcome: str = "success", **details) -> None:
        """Log authentication login."""
        self.log(
            AuditEvent(
                event_type=AuditEventType.AUTH_LOGIN,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                action="login",
                outcome=outcome,
                details=details,
            )
        )

    def auth_logout(self, actor: str, **details) -> None:
        """Log authentication logout."""
        self.log(
            AuditEvent(
                event_type=AuditEventType.AUTH_LOGOUT,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                action="logout",
                outcome="success",
                details=details,
            )
        )

    def auth_failed(self, actor: str, reason: str, **details) -> None:
        """Log failed authentication."""
        details["reason"] = reason
        self.log(
            AuditEvent(
                event_type=AuditEventType.AUTH_FAILED,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                action="login",
                outcome="failure",
                details=details,
            )
        )

    def data_access(
        self,
        actor: str,
        resource: str,
        action: str,
        outcome: str = "success",
        **details,
    ) -> None:
        """Log data access event."""
        event_type = {
            "read": AuditEventType.DATA_READ,
            "write": AuditEventType.DATA_WRITE,
            "delete": AuditEventType.DATA_DELETE,
            "export": AuditEventType.DATA_EXPORT,
        }.get(action.lower(), AuditEventType.DATA_READ)

        self.log(
            AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                resource=resource,
                action=action,
                outcome=outcome,
                details=details,
            )
        )

    def security_event(
        self,
        event_type: AuditEventType,
        action: str,
        resource: Optional[str] = None,
        actor: Optional[str] = None,
        outcome: str = "detected",
        **details,
    ) -> None:
        """Log security-related event."""
        self.log(
            AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                resource=resource,
                action=action,
                outcome=outcome,
                details=details,
            )
        )

    def config_change(
        self, actor: str, resource: str, old_value: Any, new_value: Any, **details
    ) -> None:
        """Log configuration change."""
        details["old_value"] = old_value
        details["new_value"] = new_value
        self.log(
            AuditEvent(
                event_type=AuditEventType.CONFIG_CHANGE,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                resource=resource,
                action="change",
                outcome="success",
                details=details,
            )
        )


# Thread-local storage for context
_context_var = threading.local()


def get_current_context() -> Optional[LogContext]:
    """Get the current thread-local context."""
    return getattr(_context_var, "context", None)


def set_current_context(context: Optional[LogContext]) -> None:
    """Set the current thread-local context."""
    _context_var.context = context


@contextmanager
def log_context(**kwargs):
    """Context manager for setting log context."""
    previous = get_current_context()
    new_context = LogContext(**kwargs)
    if previous:
        new_context = previous.merge(new_context)
    set_current_context(new_context)
    try:
        yield new_context
    finally:
        set_current_context(previous)


class Logger:
    """Main logger class with structured logging support."""

    def __init__(
        self,
        name: str,
        handlers: Optional[List[LogHandler]] = None,
        level: LogLevel = LogLevel.DEBUG,
        context: Optional[LogContext] = None,
    ):
        """Initialize logger."""
        self._name = name
        self._handlers = handlers or []
        self._level = level
        self._context = context
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        """Get logger name."""
        return self._name

    @property
    def level(self) -> LogLevel:
        """Get logger level."""
        return self._level

    @level.setter
    def level(self, value: LogLevel) -> None:
        """Set logger level."""
        self._level = value

    def add_handler(self, handler: LogHandler) -> None:
        """Add a handler."""
        with self._lock:
            self._handlers.append(handler)

    def remove_handler(self, handler: LogHandler) -> None:
        """Remove a handler."""
        with self._lock:
            if handler in self._handlers:
                self._handlers.remove(handler)

    def _log(
        self,
        level: LogLevel,
        message: str,
        exception: Optional[Exception] = None,
        **extra,
    ) -> None:
        """Internal log method."""
        if level.value < self._level.value:
            return

        # Get context from thread-local or instance
        context = get_current_context()
        if self._context:
            context = self._context.merge(context) if context else self._context

        entry = LogEntry(
            level=level,
            message=message,
            timestamp=datetime.now(timezone.utc),
            logger_name=self._name,
            context=context,
            exception=exception,
            extra=extra,
        )

        with self._lock:
            for handler in self._handlers:
                try:
                    handler.handle(entry)
                except Exception:
                    # Don't let handler errors break logging
                    pass

    def trace(self, message: str, **extra) -> None:
        """Log at TRACE level."""
        self._log(LogLevel.TRACE, message, **extra)

    def debug(self, message: str, **extra) -> None:
        """Log at DEBUG level."""
        self._log(LogLevel.DEBUG, message, **extra)

    def info(self, message: str, **extra) -> None:
        """Log at INFO level."""
        self._log(LogLevel.INFO, message, **extra)

    def warning(self, message: str, **extra) -> None:
        """Log at WARNING level."""
        self._log(LogLevel.WARNING, message, **extra)

    def error(
        self, message: str, exception: Optional[Exception] = None, **extra
    ) -> None:
        """Log at ERROR level."""
        self._log(LogLevel.ERROR, message, exception=exception, **extra)

    def critical(
        self, message: str, exception: Optional[Exception] = None, **extra
    ) -> None:
        """Log at CRITICAL level."""
        self._log(LogLevel.CRITICAL, message, exception=exception, **extra)

    def exception(self, message: str, exception: Exception, **extra) -> None:
        """Log exception at ERROR level."""
        self._log(LogLevel.ERROR, message, exception=exception, **extra)

    def child(self, name: str, **context_kwargs) -> "Logger":
        """Create a child logger with additional context."""
        child_name = f"{self._name}.{name}"
        child_context = LogContext(**context_kwargs)
        if self._context:
            child_context = self._context.merge(child_context)

        child_logger = Logger(
            name=child_name,
            handlers=self._handlers,  # Share handlers
            level=self._level,
            context=child_context,
        )
        return child_logger


class LoggerFactory:
    """Factory for creating and managing loggers."""

    _instance: Optional["LoggerFactory"] = None
    _lock = threading.Lock()

    def __init__(self):
        """Initialize logger factory."""
        self._loggers: Dict[str, Logger] = {}
        self._default_handlers: List[LogHandler] = []
        self._default_level = LogLevel.INFO
        self._logger_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "LoggerFactory":
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
            if cls._instance:
                # Close all handlers
                for logger in cls._instance._loggers.values():
                    for handler in logger._handlers:
                        handler.close()
            cls._instance = None

    def add_default_handler(self, handler: LogHandler) -> None:
        """Add a default handler for new loggers."""
        self._default_handlers.append(handler)

    def set_default_level(self, level: LogLevel) -> None:
        """Set default level for new loggers."""
        self._default_level = level

    def get_logger(self, name: str) -> Logger:
        """Get or create a logger by name."""
        with self._logger_lock:
            if name not in self._loggers:
                logger = Logger(
                    name=name,
                    handlers=list(self._default_handlers),
                    level=self._default_level,
                )
                self._loggers[name] = logger
            return self._loggers[name]

    def get_all_loggers(self) -> Dict[str, Logger]:
        """Get all registered loggers."""
        with self._logger_lock:
            return dict(self._loggers)


# Convenience functions
def get_logger(name: str) -> Logger:
    """Get a logger by name."""
    return LoggerFactory.get_instance().get_logger(name)


def configure_logging(
    level: LogLevel = LogLevel.INFO,
    handlers: Optional[List[LogHandler]] = None,
    format_type: str = "text",
    log_file: Optional[str] = None,
    mask_sensitive: bool = True,
) -> None:
    """Configure the logging system."""
    factory = LoggerFactory.get_instance()
    factory.set_default_level(level)

    masker = SensitiveDataMasker() if mask_sensitive else None

    if format_type == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    # Add console handler by default
    if not handlers:
        handlers = [ConsoleHandler(formatter=formatter, level=level, masker=masker)]

    # Add file handler if specified
    if log_file:
        file_handler = RotatingFileHandler(
            path=log_file,
            formatter=formatter,
            level=level,
            masker=masker,
        )
        handlers.append(file_handler)

    for handler in handlers:
        factory.add_default_handler(handler)


def logged(
    level: LogLevel = LogLevel.DEBUG,
    include_args: bool = False,
    include_result: bool = False,
):
    """Decorator to log function calls."""

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Get logger at call time to pick up handlers added after decoration
            logger = get_logger(func.__module__ or "unknown")
            func_name = func.__name__

            # Log entry
            if include_args:
                logger._log(level, f"Entering {func_name}", args=args, kwargs=kwargs)
            else:
                logger._log(level, f"Entering {func_name}")

            try:
                result = func(*args, **kwargs)

                # Log exit
                if include_result:
                    logger._log(level, f"Exiting {func_name}", result=result)
                else:
                    logger._log(level, f"Exiting {func_name}")

                return result
            except Exception as e:
                logger.error(f"Exception in {func_name}", exception=e)
                raise

        return wrapper

    return decorator


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return str(uuid.uuid4())


def generate_request_id() -> str:
    """Generate a new request ID."""
    return f"req_{uuid.uuid4().hex[:12]}"
