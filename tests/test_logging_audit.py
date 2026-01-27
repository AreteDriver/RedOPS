"""Tests for the Logging and Auditing module."""

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from redops.core.logging_audit import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    ConsoleHandler,
    FileHandler,
    JSONFormatter,
    LogContext,
    LogEntry,
    LoggerFactory,
    LogLevel,
    Logger,
    MemoryHandler,
    RotatingFileHandler,
    SensitiveDataMasker,
    TextFormatter,
    configure_logging,
    generate_correlation_id,
    generate_request_id,
    get_current_context,
    get_logger,
    log_context,
    logged,
    set_current_context,
)


class TestLogLevel:
    """Tests for LogLevel enum."""

    def test_all_levels_exist(self):
        """Test all log levels are defined."""
        assert LogLevel.TRACE.value == 5
        assert LogLevel.DEBUG.value == 10
        assert LogLevel.INFO.value == 20
        assert LogLevel.WARNING.value == 30
        assert LogLevel.ERROR.value == 40
        assert LogLevel.CRITICAL.value == 50
        assert LogLevel.AUDIT.value == 60

    def test_from_string(self):
        """Test conversion from string."""
        assert LogLevel.from_string("debug") == LogLevel.DEBUG
        assert LogLevel.from_string("DEBUG") == LogLevel.DEBUG
        assert LogLevel.from_string("info") == LogLevel.INFO
        assert LogLevel.from_string("warning") == LogLevel.WARNING
        assert LogLevel.from_string("warn") == LogLevel.WARNING
        assert LogLevel.from_string("error") == LogLevel.ERROR
        assert LogLevel.from_string("critical") == LogLevel.CRITICAL
        assert LogLevel.from_string("unknown") == LogLevel.INFO


class TestAuditEventType:
    """Tests for AuditEventType enum."""

    def test_auth_events(self):
        """Test authentication event types."""
        assert AuditEventType.AUTH_LOGIN.value == "auth.login"
        assert AuditEventType.AUTH_LOGOUT.value == "auth.logout"
        assert AuditEventType.AUTH_FAILED.value == "auth.failed"

    def test_data_events(self):
        """Test data event types."""
        assert AuditEventType.DATA_READ.value == "data.read"
        assert AuditEventType.DATA_WRITE.value == "data.write"
        assert AuditEventType.DATA_DELETE.value == "data.delete"

    def test_security_events(self):
        """Test security event types."""
        assert AuditEventType.SECURITY_ALERT.value == "security.alert"
        assert AuditEventType.SECURITY_THREAT.value == "security.threat"


class TestLogContext:
    """Tests for LogContext."""

    def test_default_values(self):
        """Test default context values."""
        ctx = LogContext()
        assert ctx.correlation_id is None
        assert ctx.user_id is None
        assert ctx.extra == {}

    def test_custom_values(self):
        """Test custom context values."""
        ctx = LogContext(
            correlation_id="abc123",
            user_id="user1",
            component="api",
        )
        assert ctx.correlation_id == "abc123"
        assert ctx.user_id == "user1"
        assert ctx.component == "api"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        ctx = LogContext(
            correlation_id="abc",
            user_id="user1",
            extra={"custom": "value"},
        )
        d = ctx.to_dict()
        assert d["correlation_id"] == "abc"
        assert d["user_id"] == "user1"
        assert d["custom"] == "value"

    def test_merge(self):
        """Test context merging."""
        ctx1 = LogContext(correlation_id="abc", user_id="user1")
        ctx2 = LogContext(user_id="user2", component="api")

        merged = ctx1.merge(ctx2)
        assert merged.correlation_id == "abc"  # From ctx1
        assert merged.user_id == "user2"  # Overridden by ctx2
        assert merged.component == "api"  # From ctx2


class TestAuditEvent:
    """Tests for AuditEvent."""

    def test_basic_event(self):
        """Test basic audit event creation."""
        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN,
            timestamp=datetime.now(timezone.utc),
            actor="user1",
            action="login",
        )
        assert event.event_type == AuditEventType.AUTH_LOGIN
        assert event.actor == "user1"
        assert event.outcome == "success"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        event = AuditEvent(
            event_type=AuditEventType.DATA_READ,
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            actor="user1",
            resource="/api/data",
            action="read",
            details={"count": 10},
        )
        d = event.to_dict()
        assert d["event_type"] == "data.read"
        assert d["actor"] == "user1"
        assert d["resource"] == "/api/data"
        assert d["details"]["count"] == 10


class TestLogEntry:
    """Tests for LogEntry."""

    def test_basic_entry(self):
        """Test basic log entry creation."""
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test message",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
        )
        assert entry.level == LogLevel.INFO
        assert entry.message == "Test message"

    def test_with_exception(self):
        """Test log entry with exception."""
        exc = ValueError("test error")
        entry = LogEntry(
            level=LogLevel.ERROR,
            message="Error occurred",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
            exception=exc,
        )
        d = entry.to_dict()
        assert d["exception"]["type"] == "ValueError"
        assert d["exception"]["message"] == "test error"


class TestSensitiveDataMasker:
    """Tests for SensitiveDataMasker."""

    def test_mask_password(self):
        """Test password masking."""
        masker = SensitiveDataMasker()
        result = masker.mask("password=secret123")
        assert "secret123" not in result
        assert "***" in result

    def test_mask_api_key(self):
        """Test API key masking."""
        masker = SensitiveDataMasker()
        result = masker.mask("api_key=test_fake_key")
        assert "test_fake_key" not in result

    def test_mask_bearer_token(self):
        """Test bearer token masking."""
        masker = SensitiveDataMasker()
        result = masker.mask("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_mask_credit_card(self):
        """Test credit card masking."""
        masker = SensitiveDataMasker()
        result = masker.mask("Card: 1234567890123456")
        assert "1234567890123456" not in result

    def test_mask_dict(self):
        """Test dictionary masking."""
        masker = SensitiveDataMasker()
        data = {
            "username": "john",
            "password": "secret",
            "nested": {"token": "abc123"},
        }
        result = masker.mask_dict(data)
        assert result["username"] == "john"
        assert result["password"] == "***"
        assert result["nested"]["token"] == "***"

    def test_add_custom_pattern(self):
        """Test adding custom pattern."""
        masker = SensitiveDataMasker()
        masker.add_pattern(r"custom_id=(\w+)", "custom_id=***")
        result = masker.mask("custom_id=abc123")
        assert "abc123" not in result


class TestTextFormatter:
    """Tests for TextFormatter."""

    def test_basic_format(self):
        """Test basic text formatting."""
        formatter = TextFormatter()
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test message",
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            logger_name="test",
        )
        result = formatter.format(entry)
        assert "INFO" in result
        assert "Test message" in result
        assert "test" in result

    def test_with_context(self):
        """Test formatting with context."""
        formatter = TextFormatter(include_context=True)
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
            context=LogContext(correlation_id="abc123"),
        )
        result = formatter.format(entry)
        assert "abc123" in result


class TestJSONFormatter:
    """Tests for JSONFormatter."""

    def test_basic_format(self):
        """Test basic JSON formatting."""
        formatter = JSONFormatter()
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test message",
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            logger_name="test",
        )
        result = formatter.format(entry)
        data = json.loads(result)
        assert data["level"] == "INFO"
        assert data["message"] == "Test message"

    def test_pretty_format(self):
        """Test pretty JSON formatting."""
        formatter = JSONFormatter(pretty=True)
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
        )
        result = formatter.format(entry)
        assert "\n" in result  # Pretty printing includes newlines


class TestMemoryHandler:
    """Tests for MemoryHandler."""

    def test_stores_entries(self):
        """Test that entries are stored."""
        handler = MemoryHandler()
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
        )
        handler.handle(entry)
        assert len(handler.get_entries()) == 1

    def test_max_entries(self):
        """Test max entries limit."""
        handler = MemoryHandler(max_entries=5)
        for i in range(10):
            entry = LogEntry(
                level=LogLevel.INFO,
                message=f"Test {i}",
                timestamp=datetime.now(timezone.utc),
                logger_name="test",
            )
            handler.handle(entry)
        assert len(handler.get_entries()) == 5

    def test_filter_by_level(self):
        """Test filtering entries by level."""
        handler = MemoryHandler()
        handler.handle(
            LogEntry(LogLevel.INFO, "info", datetime.now(timezone.utc), "test")
        )
        handler.handle(
            LogEntry(LogLevel.ERROR, "error", datetime.now(timezone.utc), "test")
        )

        info_entries = handler.get_entries(LogLevel.INFO)
        assert len(info_entries) == 1
        assert info_entries[0].message == "info"

    def test_clear(self):
        """Test clearing entries."""
        handler = MemoryHandler()
        handler.handle(
            LogEntry(LogLevel.INFO, "test", datetime.now(timezone.utc), "test")
        )
        handler.clear()
        assert len(handler.get_entries()) == 0


class TestConsoleHandler:
    """Tests for ConsoleHandler."""

    def test_emits_to_stream(self):
        """Test that handler emits to stream."""
        from io import StringIO

        stream = StringIO()
        handler = ConsoleHandler(stream=stream, colorize=False)
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Test message",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
        )
        handler.handle(entry)
        output = stream.getvalue()
        assert "Test message" in output

    def test_respects_level(self):
        """Test that handler respects level filter."""
        from io import StringIO

        stream = StringIO()
        handler = ConsoleHandler(stream=stream, level=LogLevel.ERROR)
        entry = LogEntry(
            level=LogLevel.INFO,
            message="Info message",
            timestamp=datetime.now(timezone.utc),
            logger_name="test",
        )
        handler.handle(entry)
        assert stream.getvalue() == ""


class TestFileHandler:
    """Tests for FileHandler."""

    def test_writes_to_file(self):
        """Test that handler writes to file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            path = f.name

        try:
            handler = FileHandler(path=path)
            entry = LogEntry(
                level=LogLevel.INFO,
                message="Test message",
                timestamp=datetime.now(timezone.utc),
                logger_name="test",
            )
            handler.handle(entry)
            handler.close()

            with open(path) as f:
                content = f.read()
            assert "Test message" in content
        finally:
            os.unlink(path)

    def test_creates_directory(self):
        """Test that handler creates parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "test.log"
            handler = FileHandler(path=path)
            handler.handle(
                LogEntry(LogLevel.INFO, "test", datetime.now(timezone.utc), "test")
            )
            handler.close()
            assert path.exists()


class TestRotatingFileHandler:
    """Tests for RotatingFileHandler."""

    def test_rotates_on_size(self):
        """Test that handler rotates files on size limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.log"
            handler = RotatingFileHandler(
                path=path,
                max_bytes=100,
                backup_count=3,
            )

            # Write enough to trigger rotation
            for i in range(20):
                entry = LogEntry(
                    level=LogLevel.INFO,
                    message=f"Message {i} with some extra content to fill the file",
                    timestamp=datetime.now(timezone.utc),
                    logger_name="test",
                )
                handler.handle(entry)

            handler.close()

            # Check that backup files exist
            assert path.exists()
            assert path.with_suffix(".log.1").exists()


class TestAuditLogger:
    """Tests for AuditLogger."""

    def test_logs_audit_event(self):
        """Test logging audit events."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        event = AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN,
            timestamp=datetime.now(timezone.utc),
            actor="user1",
            action="login",
        )
        audit.log(event)

        entries = handler.get_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.AUDIT

    def test_auth_login(self):
        """Test auth login convenience method."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        audit.auth_login("user1", ip="192.168.1.1")

        entries = handler.get_entries()
        assert len(entries) == 1
        assert "auth.login" in entries[0].message

    def test_auth_failed(self):
        """Test auth failed convenience method."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        audit.auth_failed("user1", "invalid password")

        entries = handler.get_entries()
        assert entries[0].extra["outcome"] == "failure"

    def test_data_access(self):
        """Test data access logging."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        audit.data_access("user1", "/api/users", "read")

        entries = handler.get_entries()
        assert "data.read" in entries[0].message

    def test_config_change(self):
        """Test config change logging."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        audit.config_change("admin", "log_level", "INFO", "DEBUG")

        entries = handler.get_entries()
        assert entries[0].extra["details"]["old_value"] == "INFO"
        assert entries[0].extra["details"]["new_value"] == "DEBUG"


class TestLogger:
    """Tests for Logger."""

    def test_basic_logging(self):
        """Test basic logging methods."""
        handler = MemoryHandler()
        logger = Logger("test", handlers=[handler])

        logger.info("Info message")
        logger.debug("Debug message")
        logger.warning("Warning message")
        logger.error("Error message")

        entries = handler.get_entries()
        assert len(entries) == 4

    def test_level_filtering(self):
        """Test that logger respects level."""
        handler = MemoryHandler(level=LogLevel.TRACE)
        logger = Logger("test", handlers=[handler], level=LogLevel.WARNING)

        logger.debug("Debug")
        logger.info("Info")
        logger.warning("Warning")

        entries = handler.get_entries()
        assert len(entries) == 1
        assert entries[0].level == LogLevel.WARNING

    def test_exception_logging(self):
        """Test exception logging."""
        handler = MemoryHandler()
        logger = Logger("test", handlers=[handler])

        try:
            raise ValueError("test error")
        except ValueError as e:
            logger.exception("Error occurred", e)

        entries = handler.get_entries()
        assert entries[0].exception is not None

    def test_extra_fields(self):
        """Test extra fields in log entries."""
        handler = MemoryHandler()
        logger = Logger("test", handlers=[handler])

        logger.info("Test", user_id="123", action="create")

        entries = handler.get_entries()
        assert entries[0].extra["user_id"] == "123"
        assert entries[0].extra["action"] == "create"

    def test_child_logger(self):
        """Test child logger creation."""
        handler = MemoryHandler()
        logger = Logger("parent", handlers=[handler])

        child = logger.child("child", component="api")
        child.info("Child message")

        entries = handler.get_entries()
        assert entries[0].logger_name == "parent.child"
        assert entries[0].context.component == "api"


class TestLogContextManagement:
    """Tests for log context management."""

    def test_context_manager(self):
        """Test log_context context manager."""
        set_current_context(None)  # Reset

        with log_context(correlation_id="abc123", user_id="user1"):
            ctx = get_current_context()
            assert ctx.correlation_id == "abc123"
            assert ctx.user_id == "user1"

        # Context should be restored
        assert get_current_context() is None

    def test_nested_context(self):
        """Test nested context managers."""
        set_current_context(None)

        with log_context(correlation_id="abc"):
            with log_context(user_id="user1"):
                ctx = get_current_context()
                assert ctx.correlation_id == "abc"
                assert ctx.user_id == "user1"

            # Inner context restored
            ctx = get_current_context()
            assert ctx.correlation_id == "abc"
            assert ctx.user_id is None

    def test_context_in_logger(self):
        """Test that logger uses current context."""
        handler = MemoryHandler()
        logger = Logger("test", handlers=[handler])
        set_current_context(None)

        with log_context(correlation_id="req123"):
            logger.info("Test message")

        entries = handler.get_entries()
        assert entries[0].context.correlation_id == "req123"


class TestLoggerFactory:
    """Tests for LoggerFactory."""

    def setup_method(self):
        """Reset factory before each test."""
        LoggerFactory.reset()

    def test_singleton(self):
        """Test singleton pattern."""
        factory1 = LoggerFactory.get_instance()
        factory2 = LoggerFactory.get_instance()
        assert factory1 is factory2

    def test_get_logger(self):
        """Test getting loggers by name."""
        factory = LoggerFactory.get_instance()
        logger1 = factory.get_logger("test")
        logger2 = factory.get_logger("test")
        assert logger1 is logger2

    def test_default_handlers(self):
        """Test default handlers are applied."""
        factory = LoggerFactory.get_instance()
        handler = MemoryHandler()
        factory.add_default_handler(handler)

        logger = factory.get_logger("test")
        logger.info("Test")

        assert len(handler.get_entries()) == 1


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def setup_method(self):
        """Reset factory before each test."""
        LoggerFactory.reset()

    def test_get_logger_function(self):
        """Test get_logger convenience function."""
        logger = get_logger("myapp")
        assert logger.name == "myapp"

    def test_configure_logging(self):
        """Test configure_logging function."""
        configure_logging(level=LogLevel.DEBUG)
        logger = get_logger("test")
        assert logger.level == LogLevel.DEBUG

    def test_generate_correlation_id(self):
        """Test correlation ID generation."""
        id1 = generate_correlation_id()
        id2 = generate_correlation_id()
        assert id1 != id2
        assert len(id1) == 36  # UUID format

    def test_generate_request_id(self):
        """Test request ID generation."""
        req_id = generate_request_id()
        assert req_id.startswith("req_")
        assert len(req_id) == 16  # "req_" + 12 chars


class TestLoggedDecorator:
    """Tests for @logged decorator."""

    def setup_method(self):
        """Reset factory before each test."""
        LoggerFactory.reset()

    def test_basic_decoration(self):
        """Test basic function decoration."""
        handler = MemoryHandler()
        factory = LoggerFactory.get_instance()
        factory.add_default_handler(handler)
        factory.set_default_level(LogLevel.DEBUG)  # Enable DEBUG level

        @logged()  # Uses DEBUG level by default
        def my_function():
            return 42

        result = my_function()
        assert result == 42

        entries = handler.get_entries()
        assert len(entries) == 2  # Enter + Exit

    def test_logs_exception(self):
        """Test that exceptions are logged."""
        handler = MemoryHandler()
        factory = LoggerFactory.get_instance()
        factory.add_default_handler(handler)
        factory.set_default_level(LogLevel.DEBUG)

        @logged()
        def failing_function():
            raise ValueError("test")

        with pytest.raises(ValueError):
            failing_function()

        entries = handler.get_entries()
        error_entries = [e for e in entries if e.level == LogLevel.ERROR]
        assert len(error_entries) == 1


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_logging(self):
        """Test concurrent logging from multiple threads."""
        handler = MemoryHandler(max_entries=1000)
        logger = Logger("test", handlers=[handler])

        def log_messages(thread_id):
            for i in range(100):
                logger.info(f"Thread {thread_id} message {i}")

        threads = [threading.Thread(target=log_messages, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        entries = handler.get_entries()
        assert len(entries) == 1000

    def test_concurrent_context(self):
        """Test thread-local context isolation."""
        contexts = {}

        def set_and_check_context(thread_id):
            with log_context(correlation_id=f"thread_{thread_id}"):
                time.sleep(0.01)  # Allow interleaving
                ctx = get_current_context()
                contexts[thread_id] = ctx.correlation_id

        threads = [
            threading.Thread(target=set_and_check_context, args=(i,)) for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each thread should have its own context
        for i in range(5):
            assert contexts[i] == f"thread_{i}"


class TestSensitiveDataMasking:
    """Tests for sensitive data masking in handlers."""

    def test_handler_masks_data(self):
        """Test that handler masks sensitive data."""
        masker = SensitiveDataMasker()
        handler = MemoryHandler(masker=masker)
        logger = Logger("test", handlers=[handler])

        logger.info("User login with password=secret123")

        entries = handler.get_entries()
        assert "secret123" not in entries[0].message
        assert "***" in entries[0].message

    def test_handler_masks_extra(self):
        """Test that handler masks extra fields."""
        masker = SensitiveDataMasker()
        handler = MemoryHandler(masker=masker)
        logger = Logger("test", handlers=[handler])

        logger.info("Login attempt", password="secret", token="abc123")

        entries = handler.get_entries()
        assert entries[0].extra["password"] == "***"
        assert entries[0].extra["token"] == "***"


class TestLogHandlerShouldHandle:
    """Tests for LogHandler.should_handle()."""

    def test_should_handle_higher_level(self):
        """Test handling higher level logs."""
        handler = MemoryHandler(level=LogLevel.INFO)
        entry = LogEntry(LogLevel.ERROR, "test", datetime.now(timezone.utc), "test")
        assert handler.should_handle(entry)

    def test_should_not_handle_lower_level(self):
        """Test not handling lower level logs."""
        handler = MemoryHandler(level=LogLevel.ERROR)
        entry = LogEntry(LogLevel.INFO, "test", datetime.now(timezone.utc), "test")
        assert not handler.should_handle(entry)


class TestSecurityEvents:
    """Tests for security event logging."""

    def test_security_alert(self):
        """Test security alert logging."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        audit.security_event(
            event_type=AuditEventType.SECURITY_ALERT,
            action="intrusion_detected",
            resource="firewall",
            severity="high",
        )

        entries = handler.get_entries()
        assert "security.alert" in entries[0].message

    def test_security_threat(self):
        """Test security threat logging."""
        handler = MemoryHandler()
        audit = AuditLogger(handlers=[handler])

        audit.security_event(
            event_type=AuditEventType.SECURITY_THREAT,
            action="malware_detected",
            resource="/tmp/malicious.exe",
            outcome="quarantined",
        )

        entries = handler.get_entries()
        assert entries[0].extra["outcome"] == "quarantined"
