"""
Health Checks Module for RedOPS.

Provides service health monitoring, dependency checks,
readiness probes, and liveness probes for the framework.
"""

import asyncio
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union
from urllib.parse import urlparse


class HealthStatus(Enum):
    """Health status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class CheckResult:
    """Result of a health check."""

    name: str
    status: HealthStatus
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
        }

    @property
    def is_healthy(self) -> bool:
        """Check if status is healthy."""
        return self.status == HealthStatus.HEALTHY

    @property
    def is_unhealthy(self) -> bool:
        """Check if status is unhealthy."""
        return self.status == HealthStatus.UNHEALTHY


@dataclass
class HealthReport:
    """Aggregated health report."""

    status: HealthStatus
    checks: List[CheckResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = ""
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "checks": [c.to_dict() for c in self.checks],
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "uptime_seconds": self.uptime_seconds,
            "healthy_count": sum(1 for c in self.checks if c.is_healthy),
            "unhealthy_count": sum(1 for c in self.checks if c.is_unhealthy),
            "total_checks": len(self.checks),
        }

    @property
    def is_healthy(self) -> bool:
        """Check if overall status is healthy."""
        return self.status == HealthStatus.HEALTHY

    def get_check(self, name: str) -> Optional[CheckResult]:
        """Get a specific check result by name."""
        for check in self.checks:
            if check.name == name:
                return check
        return None


class HealthCheck(ABC):
    """Base class for health checks."""

    name: str = "unnamed"
    description: str = ""
    critical: bool = True  # If True, failure makes overall status unhealthy
    timeout: float = 5.0  # Timeout in seconds

    @abstractmethod
    def check(self) -> CheckResult:
        """Execute the health check."""
        pass

    def _create_result(
        self,
        status: HealthStatus,
        message: str = "",
        details: Optional[Dict] = None,
        error: Optional[str] = None,
        duration_ms: float = 0.0,
    ) -> CheckResult:
        """Helper to create a CheckResult."""
        return CheckResult(
            name=self.name,
            status=status,
            message=message,
            details=details or {},
            error=error,
            duration_ms=duration_ms,
        )

    def healthy(self, message: str = "", details: Optional[Dict] = None) -> CheckResult:
        """Create a healthy result."""
        return self._create_result(HealthStatus.HEALTHY, message, details)

    def unhealthy(
        self, message: str, error: Optional[str] = None, details: Optional[Dict] = None
    ) -> CheckResult:
        """Create an unhealthy result."""
        return self._create_result(HealthStatus.UNHEALTHY, message, details, error)

    def degraded(self, message: str, details: Optional[Dict] = None) -> CheckResult:
        """Create a degraded result."""
        return self._create_result(HealthStatus.DEGRADED, message, details)


class AsyncHealthCheck(ABC):
    """Base class for async health checks."""

    name: str = "unnamed"
    description: str = ""
    critical: bool = True
    timeout: float = 5.0

    @abstractmethod
    async def check(self) -> CheckResult:
        """Execute the async health check."""
        pass

    def _create_result(
        self,
        status: HealthStatus,
        message: str = "",
        details: Optional[Dict] = None,
        error: Optional[str] = None,
        duration_ms: float = 0.0,
    ) -> CheckResult:
        """Helper to create a CheckResult."""
        return CheckResult(
            name=self.name,
            status=status,
            message=message,
            details=details or {},
            error=error,
            duration_ms=duration_ms,
        )

    def healthy(self, message: str = "", details: Optional[Dict] = None) -> CheckResult:
        """Create a healthy result."""
        return self._create_result(HealthStatus.HEALTHY, message, details)

    def unhealthy(
        self, message: str, error: Optional[str] = None, details: Optional[Dict] = None
    ) -> CheckResult:
        """Create an unhealthy result."""
        return self._create_result(HealthStatus.UNHEALTHY, message, details, error)

    def degraded(self, message: str, details: Optional[Dict] = None) -> CheckResult:
        """Create a degraded result."""
        return self._create_result(HealthStatus.DEGRADED, message, details)


# =============================================================================
# Built-in Health Checks
# =============================================================================


class TCPHealthCheck(HealthCheck):
    """Check if a TCP port is accessible."""

    def __init__(
        self,
        host: str,
        port: int,
        name: Optional[str] = None,
        timeout: float = 5.0,
        critical: bool = True,
    ):
        self.host = host
        self.port = port
        self.name = name or f"tcp:{host}:{port}"
        self.timeout = timeout
        self.critical = critical

    def check(self) -> CheckResult:
        """Check TCP connectivity."""
        start = time.perf_counter()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()

            duration = (time.perf_counter() - start) * 1000

            if result == 0:
                return self._create_result(
                    HealthStatus.HEALTHY,
                    f"Connected to {self.host}:{self.port}",
                    {"host": self.host, "port": self.port},
                    duration_ms=duration,
                )
            else:
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"Cannot connect to {self.host}:{self.port}",
                    {"host": self.host, "port": self.port, "error_code": result},
                    error=f"Connection failed with code {result}",
                    duration_ms=duration,
                )
        except socket.timeout:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Timeout connecting to {self.host}:{self.port}",
                {"host": self.host, "port": self.port},
                error="Connection timed out",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Error connecting to {self.host}:{self.port}",
                {"host": self.host, "port": self.port},
                error=str(e),
                duration_ms=duration,
            )


class HTTPHealthCheck(HealthCheck):
    """Check if an HTTP endpoint is accessible."""

    def __init__(
        self,
        url: str,
        name: Optional[str] = None,
        method: str = "GET",
        expected_status: int = 200,
        timeout: float = 5.0,
        critical: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.url = url
        parsed = urlparse(url)
        self.name = name or f"http:{parsed.netloc}{parsed.path}"
        self.method = method
        self.expected_status = expected_status
        self.timeout = timeout
        self.critical = critical
        self.headers = headers or {}

    def check(self) -> CheckResult:
        """Check HTTP endpoint."""
        start = time.perf_counter()
        try:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(
                self.url,
                method=self.method,
                headers=self.headers,
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status_code = response.status
                duration = (time.perf_counter() - start) * 1000

                if status_code == self.expected_status:
                    return self._create_result(
                        HealthStatus.HEALTHY,
                        f"HTTP {status_code} from {self.url}",
                        {"url": self.url, "status_code": status_code},
                        duration_ms=duration,
                    )
                else:
                    return self._create_result(
                        HealthStatus.UNHEALTHY,
                        f"Unexpected status {status_code} from {self.url}",
                        {
                            "url": self.url,
                            "status_code": status_code,
                            "expected": self.expected_status,
                        },
                        error=f"Expected {self.expected_status}, got {status_code}",
                        duration_ms=duration,
                    )
        except urllib.error.HTTPError as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"HTTP error from {self.url}",
                {"url": self.url, "status_code": e.code},
                error=str(e),
                duration_ms=duration,
            )
        except urllib.error.URLError as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Cannot reach {self.url}",
                {"url": self.url},
                error=str(e.reason),
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Error checking {self.url}",
                {"url": self.url},
                error=str(e),
                duration_ms=duration,
            )


class DiskSpaceCheck(HealthCheck):
    """Check available disk space."""

    def __init__(
        self,
        path: str = "/",
        min_free_bytes: Optional[int] = None,
        min_free_percent: float = 10.0,
        name: Optional[str] = None,
        critical: bool = True,
    ):
        self.path = path
        self.min_free_bytes = min_free_bytes
        self.min_free_percent = min_free_percent
        self.name = name or f"disk:{path}"
        self.critical = critical

    def check(self) -> CheckResult:
        """Check disk space."""
        import shutil

        start = time.perf_counter()
        try:
            usage = shutil.disk_usage(self.path)
            free_percent = (usage.free / usage.total) * 100
            duration = (time.perf_counter() - start) * 1000

            details = {
                "path": self.path,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "free_percent": round(free_percent, 2),
            }

            # Check thresholds
            if self.min_free_bytes and usage.free < self.min_free_bytes:
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"Low disk space: {usage.free} bytes free",
                    details,
                    error=f"Below minimum {self.min_free_bytes} bytes",
                    duration_ms=duration,
                )

            if free_percent < self.min_free_percent:
                return self._create_result(
                    HealthStatus.DEGRADED if free_percent > 5 else HealthStatus.UNHEALTHY,
                    f"Low disk space: {free_percent:.1f}% free",
                    details,
                    error=f"Below minimum {self.min_free_percent}%",
                    duration_ms=duration,
                )

            return self._create_result(
                HealthStatus.HEALTHY,
                f"Disk space OK: {free_percent:.1f}% free",
                details,
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Error checking disk at {self.path}",
                {"path": self.path},
                error=str(e),
                duration_ms=duration,
            )


class MemoryCheck(HealthCheck):
    """Check available memory."""

    def __init__(
        self,
        min_free_percent: float = 10.0,
        name: str = "memory",
        critical: bool = True,
    ):
        self.min_free_percent = min_free_percent
        self.name = name
        self.critical = critical

    def check(self) -> CheckResult:
        """Check memory usage."""
        start = time.perf_counter()
        try:
            # Read from /proc/meminfo on Linux
            import os

            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo") as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip().split()[0]
                            meminfo[key] = int(value) * 1024  # Convert KB to bytes

                total = meminfo.get("MemTotal", 0)
                available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            else:
                # Fallback for non-Linux
                import resource

                rusage = resource.getrusage(resource.RUSAGE_SELF)
                # This is a rough approximation
                total = 0
                available = 0

            duration = (time.perf_counter() - start) * 1000

            if total > 0:
                free_percent = (available / total) * 100
                details = {
                    "total_bytes": total,
                    "available_bytes": available,
                    "free_percent": round(free_percent, 2),
                }

                if free_percent < self.min_free_percent:
                    return self._create_result(
                        HealthStatus.DEGRADED if free_percent > 5 else HealthStatus.UNHEALTHY,
                        f"Low memory: {free_percent:.1f}% available",
                        details,
                        error=f"Below minimum {self.min_free_percent}%",
                        duration_ms=duration,
                    )

                return self._create_result(
                    HealthStatus.HEALTHY,
                    f"Memory OK: {free_percent:.1f}% available",
                    details,
                    duration_ms=duration,
                )
            else:
                return self._create_result(
                    HealthStatus.UNKNOWN,
                    "Could not determine memory usage",
                    {},
                    duration_ms=duration,
                )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNKNOWN,
                "Error checking memory",
                {},
                error=str(e),
                duration_ms=duration,
            )


class ProcessCheck(HealthCheck):
    """Check if a process is running."""

    def __init__(
        self,
        process_name: str,
        name: Optional[str] = None,
        critical: bool = True,
    ):
        self.process_name = process_name
        self.name = name or f"process:{process_name}"
        self.critical = critical

    def check(self) -> CheckResult:
        """Check if process is running."""
        import subprocess

        start = time.perf_counter()
        try:
            # Use pgrep to find process
            result = subprocess.run(
                ["pgrep", "-f", self.process_name],
                capture_output=True,
                timeout=5,
            )
            duration = (time.perf_counter() - start) * 1000

            if result.returncode == 0:
                pids = result.stdout.decode().strip().split("\n")
                return self._create_result(
                    HealthStatus.HEALTHY,
                    f"Process '{self.process_name}' is running",
                    {"process": self.process_name, "pids": pids},
                    duration_ms=duration,
                )
            else:
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"Process '{self.process_name}' is not running",
                    {"process": self.process_name},
                    error="Process not found",
                    duration_ms=duration,
                )
        except FileNotFoundError:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNKNOWN,
                "pgrep command not available",
                {},
                error="pgrep not found",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Error checking process '{self.process_name}'",
                {"process": self.process_name},
                error=str(e),
                duration_ms=duration,
            )


class FileExistsCheck(HealthCheck):
    """Check if a file exists and is accessible."""

    def __init__(
        self,
        path: str,
        name: Optional[str] = None,
        check_readable: bool = True,
        check_writable: bool = False,
        critical: bool = True,
    ):
        self.path = path
        self.name = name or f"file:{path}"
        self.check_readable = check_readable
        self.check_writable = check_writable
        self.critical = critical

    def check(self) -> CheckResult:
        """Check file existence and permissions."""
        import os

        start = time.perf_counter()
        try:
            details = {"path": self.path}

            if not os.path.exists(self.path):
                duration = (time.perf_counter() - start) * 1000
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"File not found: {self.path}",
                    details,
                    error="File does not exist",
                    duration_ms=duration,
                )

            details["exists"] = True
            details["is_file"] = os.path.isfile(self.path)
            details["is_dir"] = os.path.isdir(self.path)

            if self.check_readable and not os.access(self.path, os.R_OK):
                duration = (time.perf_counter() - start) * 1000
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"File not readable: {self.path}",
                    details,
                    error="No read permission",
                    duration_ms=duration,
                )
            details["readable"] = os.access(self.path, os.R_OK)

            if self.check_writable and not os.access(self.path, os.W_OK):
                duration = (time.perf_counter() - start) * 1000
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"File not writable: {self.path}",
                    details,
                    error="No write permission",
                    duration_ms=duration,
                )
            details["writable"] = os.access(self.path, os.W_OK)

            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.HEALTHY,
                f"File accessible: {self.path}",
                details,
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"Error checking file: {self.path}",
                {"path": self.path},
                error=str(e),
                duration_ms=duration,
            )


class CallableCheck(HealthCheck):
    """Health check that runs a custom callable."""

    def __init__(
        self,
        func: Callable[[], bool],
        name: str,
        description: str = "",
        critical: bool = True,
        timeout: float = 5.0,
    ):
        self.func = func
        self.name = name
        self.description = description
        self.critical = critical
        self.timeout = timeout

    def check(self) -> CheckResult:
        """Execute the callable."""
        start = time.perf_counter()
        try:
            result = self.func()
            duration = (time.perf_counter() - start) * 1000

            if result:
                return self._create_result(
                    HealthStatus.HEALTHY,
                    f"{self.name} check passed",
                    {},
                    duration_ms=duration,
                )
            else:
                return self._create_result(
                    HealthStatus.UNHEALTHY,
                    f"{self.name} check failed",
                    {},
                    error="Check returned False",
                    duration_ms=duration,
                )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                f"{self.name} check error",
                {},
                error=str(e),
                duration_ms=duration,
            )


class DatabaseCheck(HealthCheck):
    """Check database connectivity."""

    def __init__(
        self,
        connection_func: Callable[[], Any],
        query: str = "SELECT 1",
        name: str = "database",
        critical: bool = True,
        timeout: float = 5.0,
    ):
        self.connection_func = connection_func
        self.query = query
        self.name = name
        self.critical = critical
        self.timeout = timeout

    def check(self) -> CheckResult:
        """Check database connectivity."""
        start = time.perf_counter()
        try:
            conn = self.connection_func()
            cursor = conn.cursor()
            cursor.execute(self.query)
            cursor.fetchone()
            cursor.close()
            conn.close()

            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.HEALTHY,
                "Database connection OK",
                {"query": self.query},
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                "Database connection failed",
                {},
                error=str(e),
                duration_ms=duration,
            )


class RedisCheck(HealthCheck):
    """Check Redis connectivity."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        name: str = "redis",
        critical: bool = True,
        timeout: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.name = name
        self.critical = critical
        self.timeout = timeout

    def check(self) -> CheckResult:
        """Check Redis connectivity."""
        start = time.perf_counter()
        try:
            import redis

            client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                socket_timeout=self.timeout,
            )
            client.ping()
            info = client.info("server")
            client.close()

            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.HEALTHY,
                "Redis connection OK",
                {
                    "host": self.host,
                    "port": self.port,
                    "version": info.get("redis_version", "unknown"),
                },
                duration_ms=duration,
            )
        except ImportError:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNKNOWN,
                "Redis client not installed",
                {},
                error="redis package not installed",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return self._create_result(
                HealthStatus.UNHEALTHY,
                "Redis connection failed",
                {"host": self.host, "port": self.port},
                error=str(e),
                duration_ms=duration,
            )


# =============================================================================
# Health Check Manager
# =============================================================================


class HealthCheckManager:
    """Manages and executes health checks."""

    def __init__(self, version: str = ""):
        self._checks: Dict[str, Union[HealthCheck, AsyncHealthCheck]] = {}
        self._version = version
        self._start_time = datetime.now(timezone.utc)
        self._last_report: Optional[HealthReport] = None
        self._lock = threading.Lock()

    def register(
        self,
        check: Union[HealthCheck, AsyncHealthCheck],
        name: Optional[str] = None,
    ) -> "HealthCheckManager":
        """Register a health check."""
        check_name = name or check.name
        with self._lock:
            self._checks[check_name] = check
        return self

    def unregister(self, name: str) -> bool:
        """Unregister a health check."""
        with self._lock:
            if name in self._checks:
                del self._checks[name]
                return True
        return False

    def get_check(self, name: str) -> Optional[Union[HealthCheck, AsyncHealthCheck]]:
        """Get a registered health check."""
        return self._checks.get(name)

    def list_checks(self) -> List[str]:
        """List registered check names."""
        return list(self._checks.keys())

    def run_check(self, name: str) -> Optional[CheckResult]:
        """Run a specific health check."""
        check = self._checks.get(name)
        if not check:
            return None

        if isinstance(check, AsyncHealthCheck):
            # Run async check in event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(self._run_async_check(check))
        else:
            return self._run_check(check)

    def _run_check(self, check: HealthCheck) -> CheckResult:
        """Run a synchronous health check with timeout."""
        start = time.perf_counter()
        result = [None]
        exception = [None]

        def run():
            try:
                result[0] = check.check()
            except Exception as e:
                exception[0] = e

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=check.timeout)

        if thread.is_alive():
            # Timeout
            return CheckResult(
                name=check.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {check.timeout}s",
                error="Timeout",
                duration_ms=check.timeout * 1000,
            )

        if exception[0]:
            duration = (time.perf_counter() - start) * 1000
            return CheckResult(
                name=check.name,
                status=HealthStatus.UNHEALTHY,
                message="Health check failed with exception",
                error=str(exception[0]),
                duration_ms=duration,
            )

        return result[0]

    async def _run_async_check(self, check: AsyncHealthCheck) -> CheckResult:
        """Run an async health check with timeout."""
        try:
            result = await asyncio.wait_for(check.check(), timeout=check.timeout)
            return result
        except asyncio.TimeoutError:
            return CheckResult(
                name=check.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {check.timeout}s",
                error="Timeout",
                duration_ms=check.timeout * 1000,
            )
        except Exception as e:
            return CheckResult(
                name=check.name,
                status=HealthStatus.UNHEALTHY,
                message="Health check failed with exception",
                error=str(e),
                duration_ms=0,
            )

    def run_all(self) -> HealthReport:
        """Run all health checks and return aggregated report."""
        results = []

        for name, check in self._checks.items():
            result = self.run_check(name)
            if result:
                results.append(result)

        # Determine overall status
        overall_status = self._calculate_overall_status(results)

        report = HealthReport(
            status=overall_status,
            checks=results,
            version=self._version,
            uptime_seconds=(datetime.now(timezone.utc) - self._start_time).total_seconds(),
        )

        self._last_report = report
        return report

    async def run_all_async(self) -> HealthReport:
        """Run all health checks asynchronously."""
        tasks = []

        for name, check in self._checks.items():
            if isinstance(check, AsyncHealthCheck):
                tasks.append(self._run_async_check(check))
            else:
                # Wrap sync check in executor
                loop = asyncio.get_event_loop()
                tasks.append(loop.run_in_executor(None, lambda c=check: self._run_check(c)))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        check_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                name = list(self._checks.keys())[i]
                check_results.append(
                    CheckResult(
                        name=name,
                        status=HealthStatus.UNHEALTHY,
                        message="Check failed",
                        error=str(result),
                    )
                )
            else:
                check_results.append(result)

        overall_status = self._calculate_overall_status(check_results)

        report = HealthReport(
            status=overall_status,
            checks=check_results,
            version=self._version,
            uptime_seconds=(datetime.now(timezone.utc) - self._start_time).total_seconds(),
        )

        self._last_report = report
        return report

    def _calculate_overall_status(self, results: List[CheckResult]) -> HealthStatus:
        """Calculate overall health status from check results."""
        if not results:
            return HealthStatus.UNKNOWN

        has_critical_failure = False
        has_degraded = False

        for result in results:
            check = self._checks.get(result.name)
            is_critical = check.critical if check else True

            if result.status == HealthStatus.UNHEALTHY:
                if is_critical:
                    has_critical_failure = True
                else:
                    has_degraded = True
            elif result.status == HealthStatus.DEGRADED:
                has_degraded = True

        if has_critical_failure:
            return HealthStatus.UNHEALTHY
        elif has_degraded:
            return HealthStatus.DEGRADED
        else:
            return HealthStatus.HEALTHY

    @property
    def last_report(self) -> Optional[HealthReport]:
        """Get the last health report."""
        return self._last_report

    @property
    def uptime(self) -> timedelta:
        """Get uptime as timedelta."""
        return datetime.now(timezone.utc) - self._start_time


# =============================================================================
# Readiness and Liveness Probes
# =============================================================================


class ReadinessProbe:
    """Kubernetes-style readiness probe."""

    def __init__(self, manager: HealthCheckManager):
        self._manager = manager
        self._ready_checks: List[str] = []

    def add_check(self, name: str) -> "ReadinessProbe":
        """Add a check to the readiness probe."""
        self._ready_checks.append(name)
        return self

    def is_ready(self) -> bool:
        """Check if the service is ready."""
        if not self._ready_checks:
            # If no specific checks, run all
            report = self._manager.run_all()
            return report.is_healthy

        for name in self._ready_checks:
            result = self._manager.run_check(name)
            if not result or not result.is_healthy:
                return False
        return True

    def get_status(self) -> Dict[str, Any]:
        """Get readiness status details."""
        results = {}
        ready = True

        for name in self._ready_checks or self._manager.list_checks():
            result = self._manager.run_check(name)
            if result:
                results[name] = result.to_dict()
                if not result.is_healthy:
                    ready = False

        return {
            "ready": ready,
            "checks": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class LivenessProbe:
    """Kubernetes-style liveness probe."""

    def __init__(
        self,
        manager: Optional[HealthCheckManager] = None,
        custom_check: Optional[Callable[[], bool]] = None,
    ):
        self._manager = manager
        self._custom_check = custom_check
        self._alive = True

    def is_alive(self) -> bool:
        """Check if the service is alive."""
        if not self._alive:
            return False

        if self._custom_check:
            try:
                return self._custom_check()
            except Exception:
                return False

        if self._manager:
            # Basic liveness - just check that checks can run
            try:
                # Run a quick check
                checks = self._manager.list_checks()
                if checks:
                    result = self._manager.run_check(checks[0])
                    return result is not None
            except Exception:
                return False

        return True

    def mark_dead(self) -> None:
        """Mark the service as dead."""
        self._alive = False

    def mark_alive(self) -> None:
        """Mark the service as alive."""
        self._alive = True

    def get_status(self) -> Dict[str, Any]:
        """Get liveness status details."""
        alive = self.is_alive()
        return {
            "alive": alive,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# =============================================================================
# Convenience Functions
# =============================================================================


def create_health_manager(version: str = "") -> HealthCheckManager:
    """Create a new health check manager."""
    return HealthCheckManager(version=version)


def check_tcp(host: str, port: int, timeout: float = 5.0) -> CheckResult:
    """Quick TCP connectivity check."""
    check = TCPHealthCheck(host, port, timeout=timeout)
    return check.check()


def check_http(url: str, timeout: float = 5.0) -> CheckResult:
    """Quick HTTP endpoint check."""
    check = HTTPHealthCheck(url, timeout=timeout)
    return check.check()


def check_disk(path: str = "/", min_free_percent: float = 10.0) -> CheckResult:
    """Quick disk space check."""
    check = DiskSpaceCheck(path, min_free_percent=min_free_percent)
    return check.check()


def check_memory(min_free_percent: float = 10.0) -> CheckResult:
    """Quick memory check."""
    check = MemoryCheck(min_free_percent=min_free_percent)
    return check.check()
