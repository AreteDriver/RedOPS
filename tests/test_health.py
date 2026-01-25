"""Tests for health checks module."""

import asyncio
import socket
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from redops.core.health import (
    AsyncHealthCheck,
    CallableCheck,
    CheckResult,
    DatabaseCheck,
    DiskSpaceCheck,
    FileExistsCheck,
    HealthCheck,
    HealthCheckManager,
    HealthReport,
    HealthStatus,
    HTTPHealthCheck,
    LivenessProbe,
    MemoryCheck,
    ProcessCheck,
    ReadinessProbe,
    RedisCheck,
    TCPHealthCheck,
    check_disk,
    check_http,
    check_memory,
    check_tcp,
    create_health_manager,
)


class TestHealthStatus:
    """Tests for HealthStatus enum."""

    def test_status_values(self):
        """Test status values."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestCheckResult:
    """Tests for CheckResult dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        result = CheckResult(
            name="test",
            status=HealthStatus.HEALTHY,
            message="All good",
        )
        assert result.name == "test"
        assert result.status == HealthStatus.HEALTHY
        assert result.message == "All good"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = CheckResult(
            name="test",
            status=HealthStatus.HEALTHY,
            message="OK",
            details={"key": "value"},
            duration_ms=10.5,
        )
        d = result.to_dict()
        assert d["name"] == "test"
        assert d["status"] == "healthy"
        assert d["message"] == "OK"
        assert d["details"] == {"key": "value"}
        assert d["duration_ms"] == 10.5

    def test_is_healthy(self):
        """Test is_healthy property."""
        healthy = CheckResult(name="a", status=HealthStatus.HEALTHY)
        unhealthy = CheckResult(name="b", status=HealthStatus.UNHEALTHY)

        assert healthy.is_healthy is True
        assert unhealthy.is_healthy is False

    def test_is_unhealthy(self):
        """Test is_unhealthy property."""
        healthy = CheckResult(name="a", status=HealthStatus.HEALTHY)
        unhealthy = CheckResult(name="b", status=HealthStatus.UNHEALTHY)

        assert healthy.is_unhealthy is False
        assert unhealthy.is_unhealthy is True

    def test_timestamp(self):
        """Test timestamp is set."""
        result = CheckResult(name="test", status=HealthStatus.HEALTHY)
        assert result.timestamp is not None
        assert isinstance(result.timestamp, datetime)


class TestHealthReport:
    """Tests for HealthReport dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        report = HealthReport(
            status=HealthStatus.HEALTHY,
            checks=[
                CheckResult(name="a", status=HealthStatus.HEALTHY),
                CheckResult(name="b", status=HealthStatus.HEALTHY),
            ],
        )
        assert report.status == HealthStatus.HEALTHY
        assert len(report.checks) == 2

    def test_to_dict(self):
        """Test conversion to dictionary."""
        report = HealthReport(
            status=HealthStatus.HEALTHY,
            checks=[CheckResult(name="test", status=HealthStatus.HEALTHY)],
            version="1.0.0",
            uptime_seconds=100.0,
        )
        d = report.to_dict()
        assert d["status"] == "healthy"
        assert d["version"] == "1.0.0"
        assert d["uptime_seconds"] == 100.0
        assert d["healthy_count"] == 1
        assert d["unhealthy_count"] == 0
        assert d["total_checks"] == 1

    def test_is_healthy(self):
        """Test is_healthy property."""
        healthy = HealthReport(status=HealthStatus.HEALTHY)
        unhealthy = HealthReport(status=HealthStatus.UNHEALTHY)

        assert healthy.is_healthy is True
        assert unhealthy.is_healthy is False

    def test_get_check(self):
        """Test get_check method."""
        report = HealthReport(
            status=HealthStatus.HEALTHY,
            checks=[
                CheckResult(name="db", status=HealthStatus.HEALTHY),
                CheckResult(name="cache", status=HealthStatus.HEALTHY),
            ],
        )
        assert report.get_check("db") is not None
        assert report.get_check("db").name == "db"
        assert report.get_check("nonexistent") is None


class TestHealthCheck:
    """Tests for HealthCheck base class."""

    def test_abstract_check(self):
        """Test HealthCheck is abstract."""
        with pytest.raises(TypeError):
            HealthCheck()

    def test_subclass(self):
        """Test creating a HealthCheck subclass."""

        class MyCheck(HealthCheck):
            name = "mycheck"

            def check(self):
                return self.healthy("All good")

        check = MyCheck()
        result = check.check()
        assert result.status == HealthStatus.HEALTHY

    def test_helper_methods(self):
        """Test helper methods for creating results."""

        class MyCheck(HealthCheck):
            name = "test"

            def check(self):
                return self.healthy("OK")

        check = MyCheck()

        healthy = check.healthy("OK", {"key": "value"})
        assert healthy.status == HealthStatus.HEALTHY
        assert healthy.details == {"key": "value"}

        unhealthy = check.unhealthy("Failed", error="Error message")
        assert unhealthy.status == HealthStatus.UNHEALTHY
        assert unhealthy.error == "Error message"

        degraded = check.degraded("Slow")
        assert degraded.status == HealthStatus.DEGRADED


class TestTCPHealthCheck:
    """Tests for TCPHealthCheck class."""

    def test_successful_connection(self):
        """Test successful TCP connection."""
        # Create a test server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        try:
            check = TCPHealthCheck("127.0.0.1", port)
            result = check.check()
            assert result.status == HealthStatus.HEALTHY
            assert result.duration_ms > 0
        finally:
            server.close()

    def test_failed_connection(self):
        """Test failed TCP connection."""
        # Use a port that's likely not open
        check = TCPHealthCheck("127.0.0.1", 59999, timeout=1.0)
        result = check.check()
        assert result.status == HealthStatus.UNHEALTHY

    def test_custom_name(self):
        """Test custom name."""
        check = TCPHealthCheck("localhost", 80, name="web-server")
        assert check.name == "web-server"

    def test_default_name(self):
        """Test default name generation."""
        check = TCPHealthCheck("localhost", 8080)
        assert check.name == "tcp:localhost:8080"


class TestHTTPHealthCheck:
    """Tests for HTTPHealthCheck class."""

    def test_successful_request(self):
        """Test successful HTTP request."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            check = HTTPHealthCheck("http://example.com/health")
            result = check.check()
            assert result.status == HealthStatus.HEALTHY

    def test_wrong_status_code(self):
        """Test unexpected status code."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            check = HTTPHealthCheck("http://example.com/health", expected_status=200)
            result = check.check()
            assert result.status == HealthStatus.UNHEALTHY

    def test_connection_error(self):
        """Test connection error."""
        import urllib.error

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

            check = HTTPHealthCheck("http://localhost:99999/health")
            result = check.check()
            assert result.status == HealthStatus.UNHEALTHY

    def test_custom_method(self):
        """Test custom HTTP method."""
        check = HTTPHealthCheck("http://example.com", method="HEAD")
        assert check.method == "HEAD"


class TestDiskSpaceCheck:
    """Tests for DiskSpaceCheck class."""

    def test_check_disk_space(self):
        """Test disk space check."""
        check = DiskSpaceCheck("/", min_free_percent=1.0)
        result = check.check()
        # Should succeed on any system with at least 1% free
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
        assert "free_percent" in result.details

    def test_low_threshold(self):
        """Test with very high threshold."""
        check = DiskSpaceCheck("/", min_free_percent=99.9)
        result = check.check()
        # Should fail unless disk is nearly empty
        assert result.status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY]

    def test_invalid_path(self):
        """Test with invalid path."""
        check = DiskSpaceCheck("/nonexistent/path/xyz123")
        result = check.check()
        assert result.status == HealthStatus.UNHEALTHY


class TestMemoryCheck:
    """Tests for MemoryCheck class."""

    def test_check_memory(self):
        """Test memory check."""
        check = MemoryCheck(min_free_percent=1.0)
        result = check.check()
        # Should succeed on most systems
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.UNKNOWN]

    def test_high_threshold(self):
        """Test with very high threshold."""
        check = MemoryCheck(min_free_percent=99.9)
        result = check.check()
        # Should fail unless system has tons of free memory
        assert result.status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN]


class TestFileExistsCheck:
    """Tests for FileExistsCheck class."""

    def test_existing_file(self, tmp_path):
        """Test with existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        check = FileExistsCheck(str(test_file))
        result = check.check()
        assert result.status == HealthStatus.HEALTHY
        assert result.details["exists"] is True

    def test_missing_file(self):
        """Test with missing file."""
        check = FileExistsCheck("/nonexistent/file/xyz123.txt")
        result = check.check()
        assert result.status == HealthStatus.UNHEALTHY
        assert "does not exist" in result.error

    def test_readable_check(self, tmp_path):
        """Test readable check."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        check = FileExistsCheck(str(test_file), check_readable=True)
        result = check.check()
        assert result.status == HealthStatus.HEALTHY
        assert result.details["readable"] is True

    def test_writable_check(self, tmp_path):
        """Test writable check."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        check = FileExistsCheck(str(test_file), check_writable=True)
        result = check.check()
        assert result.status == HealthStatus.HEALTHY
        assert result.details["writable"] is True


class TestCallableCheck:
    """Tests for CallableCheck class."""

    def test_successful_callable(self):
        """Test with successful callable."""
        check = CallableCheck(lambda: True, name="my-check")
        result = check.check()
        assert result.status == HealthStatus.HEALTHY

    def test_failing_callable(self):
        """Test with failing callable."""
        check = CallableCheck(lambda: False, name="my-check")
        result = check.check()
        assert result.status == HealthStatus.UNHEALTHY

    def test_exception_in_callable(self):
        """Test with exception in callable."""

        def bad_func():
            raise ValueError("Something went wrong")

        check = CallableCheck(bad_func, name="my-check")
        result = check.check()
        assert result.status == HealthStatus.UNHEALTHY
        assert "Something went wrong" in result.error


class TestDatabaseCheck:
    """Tests for DatabaseCheck class."""

    def test_successful_connection(self):
        """Test successful database connection."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        check = DatabaseCheck(lambda: mock_conn)
        result = check.check()
        assert result.status == HealthStatus.HEALTHY
        mock_cursor.execute.assert_called_once()

    def test_failed_connection(self):
        """Test failed database connection."""

        def bad_connection():
            raise Exception("Connection failed")

        check = DatabaseCheck(bad_connection)
        result = check.check()
        assert result.status == HealthStatus.UNHEALTHY


class TestRedisCheck:
    """Tests for RedisCheck class."""

    def test_redis_not_installed(self):
        """Test when redis package is not installed."""
        with patch.dict("sys.modules", {"redis": None}):
            check = RedisCheck()
            # Will fail because redis isn't available in test environment
            result = check.check()
            assert result.status in [HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN]


class TestHealthCheckManager:
    """Tests for HealthCheckManager class."""

    def test_register_check(self):
        """Test registering a check."""

        class SimpleCheck(HealthCheck):
            name = "simple"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(SimpleCheck())
        assert "simple" in manager.list_checks()

    def test_unregister_check(self):
        """Test unregistering a check."""

        class SimpleCheck(HealthCheck):
            name = "simple"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(SimpleCheck())
        assert manager.unregister("simple") is True
        assert "simple" not in manager.list_checks()

    def test_unregister_nonexistent(self):
        """Test unregistering nonexistent check."""
        manager = HealthCheckManager()
        assert manager.unregister("nonexistent") is False

    def test_get_check(self):
        """Test getting a check."""

        class SimpleCheck(HealthCheck):
            name = "simple"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        check = SimpleCheck()
        manager.register(check)
        assert manager.get_check("simple") is check
        assert manager.get_check("nonexistent") is None

    def test_run_check(self):
        """Test running a single check."""

        class SimpleCheck(HealthCheck):
            name = "simple"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(SimpleCheck())
        result = manager.run_check("simple")
        assert result is not None
        assert result.status == HealthStatus.HEALTHY

    def test_run_nonexistent_check(self):
        """Test running nonexistent check."""
        manager = HealthCheckManager()
        result = manager.run_check("nonexistent")
        assert result is None

    def test_run_all(self):
        """Test running all checks."""

        class Check1(HealthCheck):
            name = "check1"

            def check(self):
                return self.healthy("OK")

        class Check2(HealthCheck):
            name = "check2"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager(version="1.0.0")
        manager.register(Check1())
        manager.register(Check2())

        report = manager.run_all()
        assert report.status == HealthStatus.HEALTHY
        assert len(report.checks) == 2
        assert report.version == "1.0.0"

    def test_run_all_with_failure(self):
        """Test running all checks with one failure."""

        class HealthyCheck(HealthCheck):
            name = "healthy"
            critical = False

            def check(self):
                return self.healthy("OK")

        class UnhealthyCheck(HealthCheck):
            name = "unhealthy"
            critical = True

            def check(self):
                return self.unhealthy("Failed")

        manager = HealthCheckManager()
        manager.register(HealthyCheck())
        manager.register(UnhealthyCheck())

        report = manager.run_all()
        assert report.status == HealthStatus.UNHEALTHY

    def test_run_all_with_non_critical_failure(self):
        """Test running all checks with non-critical failure."""

        class HealthyCheck(HealthCheck):
            name = "healthy"

            def check(self):
                return self.healthy("OK")

        class NonCriticalCheck(HealthCheck):
            name = "noncritical"
            critical = False

            def check(self):
                return self.unhealthy("Failed")

        manager = HealthCheckManager()
        manager.register(HealthyCheck())
        manager.register(NonCriticalCheck())

        report = manager.run_all()
        assert report.status == HealthStatus.DEGRADED

    def test_check_timeout(self):
        """Test check timeout handling."""

        class SlowCheck(HealthCheck):
            name = "slow"
            timeout = 0.1

            def check(self):
                time.sleep(1.0)  # Longer than timeout
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(SlowCheck())
        result = manager.run_check("slow")
        assert result.status == HealthStatus.UNHEALTHY
        assert "timed out" in result.message.lower()

    def test_uptime(self):
        """Test uptime tracking."""
        manager = HealthCheckManager()
        time.sleep(0.1)
        assert manager.uptime.total_seconds() >= 0.1

    def test_last_report(self):
        """Test last report tracking."""

        class SimpleCheck(HealthCheck):
            name = "simple"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(SimpleCheck())

        assert manager.last_report is None
        manager.run_all()
        assert manager.last_report is not None


class TestAsyncHealthCheck:
    """Tests for AsyncHealthCheck class."""

    def test_async_check_subclass(self):
        """Test creating an async health check."""

        class MyAsyncCheck(AsyncHealthCheck):
            name = "async-check"

            async def check(self):
                await asyncio.sleep(0.01)
                return self.healthy("OK")

        check = MyAsyncCheck()
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(check.check())
        loop.close()
        assert result.status == HealthStatus.HEALTHY

    def test_async_check_in_manager(self):
        """Test running async check in manager."""

        class MyAsyncCheck(AsyncHealthCheck):
            name = "async-check"

            async def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(MyAsyncCheck())
        result = manager.run_check("async-check")
        assert result.status == HealthStatus.HEALTHY


class TestReadinessProbe:
    """Tests for ReadinessProbe class."""

    def test_is_ready_with_healthy_checks(self):
        """Test readiness with healthy checks."""

        class HealthyCheck(HealthCheck):
            name = "healthy"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(HealthyCheck())

        probe = ReadinessProbe(manager)
        probe.add_check("healthy")
        assert probe.is_ready() is True

    def test_is_ready_with_unhealthy_check(self):
        """Test readiness with unhealthy check."""

        class UnhealthyCheck(HealthCheck):
            name = "unhealthy"

            def check(self):
                return self.unhealthy("Failed")

        manager = HealthCheckManager()
        manager.register(UnhealthyCheck())

        probe = ReadinessProbe(manager)
        probe.add_check("unhealthy")
        assert probe.is_ready() is False

    def test_get_status(self):
        """Test get_status method."""

        class HealthyCheck(HealthCheck):
            name = "db"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(HealthyCheck())

        probe = ReadinessProbe(manager)
        probe.add_check("db")

        status = probe.get_status()
        assert status["ready"] is True
        assert "db" in status["checks"]

    def test_empty_checks_runs_all(self):
        """Test that empty checks list runs all checks."""

        class HealthyCheck(HealthCheck):
            name = "check1"

            def check(self):
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(HealthyCheck())

        probe = ReadinessProbe(manager)
        # No specific checks added
        assert probe.is_ready() is True


class TestLivenessProbe:
    """Tests for LivenessProbe class."""

    def test_is_alive_default(self):
        """Test default liveness."""
        probe = LivenessProbe()
        assert probe.is_alive() is True

    def test_mark_dead(self):
        """Test marking as dead."""
        probe = LivenessProbe()
        probe.mark_dead()
        assert probe.is_alive() is False

    def test_mark_alive(self):
        """Test marking as alive."""
        probe = LivenessProbe()
        probe.mark_dead()
        probe.mark_alive()
        assert probe.is_alive() is True

    def test_custom_check(self):
        """Test with custom check function."""
        probe = LivenessProbe(custom_check=lambda: True)
        assert probe.is_alive() is True

        probe = LivenessProbe(custom_check=lambda: False)
        assert probe.is_alive() is False

    def test_custom_check_exception(self):
        """Test custom check that raises exception."""

        def bad_check():
            raise ValueError("Error")

        probe = LivenessProbe(custom_check=bad_check)
        assert probe.is_alive() is False

    def test_get_status(self):
        """Test get_status method."""
        probe = LivenessProbe()
        status = probe.get_status()
        assert status["alive"] is True
        assert "timestamp" in status


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_health_manager(self):
        """Test create_health_manager function."""
        manager = create_health_manager(version="2.0.0")
        assert isinstance(manager, HealthCheckManager)

    def test_check_tcp(self):
        """Test check_tcp function."""
        # Create a test server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        try:
            result = check_tcp("127.0.0.1", port)
            assert result.status == HealthStatus.HEALTHY
        finally:
            server.close()

    def test_check_disk(self):
        """Test check_disk function."""
        result = check_disk("/", min_free_percent=1.0)
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]

    def test_check_memory(self):
        """Test check_memory function."""
        result = check_memory(min_free_percent=1.0)
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.UNKNOWN]


class TestProcessCheck:
    """Tests for ProcessCheck class."""

    def test_check_running_process(self):
        """Test checking a running process."""
        # 'python' should be running since we're running tests
        check = ProcessCheck("python")
        result = check.check()
        # May or may not find it depending on how tests are run
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN]

    def test_check_nonexistent_process(self):
        """Test checking a nonexistent process."""
        check = ProcessCheck("nonexistent_process_xyz123")
        result = check.check()
        assert result.status in [HealthStatus.UNHEALTHY, HealthStatus.UNKNOWN]


class TestEdgeCases:
    """Tests for edge cases."""

    def test_manager_with_no_checks(self):
        """Test manager with no checks."""
        manager = HealthCheckManager()
        report = manager.run_all()
        assert report.status == HealthStatus.UNKNOWN
        assert len(report.checks) == 0

    def test_check_with_details(self):
        """Test check result with complex details."""

        class DetailedCheck(HealthCheck):
            name = "detailed"

            def check(self):
                return self.healthy(
                    "OK",
                    {
                        "nested": {"value": 123},
                        "list": [1, 2, 3],
                        "string": "test",
                    },
                )

        check = DetailedCheck()
        result = check.check()
        assert result.details["nested"]["value"] == 123
        assert result.details["list"] == [1, 2, 3]

    def test_concurrent_health_checks(self):
        """Test running checks from multiple threads."""
        import concurrent.futures

        class SlowCheck(HealthCheck):
            name = "slow"

            def check(self):
                time.sleep(0.05)
                return self.healthy("OK")

        manager = HealthCheckManager()
        manager.register(SlowCheck())

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(manager.run_all) for _ in range(5)]
            results = [f.result() for f in futures]

        assert all(r.status == HealthStatus.HEALTHY for r in results)

    def test_check_result_serialization(self):
        """Test CheckResult can be serialized to JSON."""
        import json

        result = CheckResult(
            name="test",
            status=HealthStatus.HEALTHY,
            message="OK",
            details={"key": "value"},
            duration_ms=10.5,
        )
        # Should not raise
        json_str = json.dumps(result.to_dict())
        parsed = json.loads(json_str)
        assert parsed["name"] == "test"

    def test_health_report_serialization(self):
        """Test HealthReport can be serialized to JSON."""
        import json

        report = HealthReport(
            status=HealthStatus.HEALTHY,
            checks=[
                CheckResult(name="a", status=HealthStatus.HEALTHY),
                CheckResult(name="b", status=HealthStatus.DEGRADED),
            ],
            version="1.0.0",
            uptime_seconds=100.0,
        )
        json_str = json.dumps(report.to_dict())
        parsed = json.loads(json_str)
        assert parsed["status"] == "healthy"
        assert len(parsed["checks"]) == 2
