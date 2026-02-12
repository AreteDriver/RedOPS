"""
Testing Utilities Module for RedOPS.
Provides test fixtures, mock factories, assertion helpers,
and testing infrastructure for the security framework.
"""
import contextlib
import copy
import json
import random
import string
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Generator,
    Generic,
    Type,
    TypeVar,
)
from unittest.mock import MagicMock, patch
T = TypeVar("T")
# =============================================================================
# Random Data Generators
# =============================================================================
class RandomGenerator:
    """Generate random test data."""
    def __init__(self, seed: int | None = None):
        """Initialize with optional seed for reproducibility."""
        self._rng = random.Random(seed)
    def string(self, length: int = 10, charset: str | None = None) -> str:
        """Generate random string."""
        charset = charset or string.ascii_letters + string.digits
        return "".join(self._rng.choices(charset, k=length))
    def hex_string(self, length: int = 32) -> str:
        """Generate random hex string."""
        return self.string(length, string.hexdigits.lower())
    def uuid(self) -> str:
        """Generate random UUID."""
        return str(uuid.UUID(int=self._rng.getrandbits(128), version=4))
    def email(self, domain: str | None = None) -> str:
        """Generate random email address."""
        domain = domain or f"{self.string(8)}.com"
        return f"{self.string(10).lower()}@{domain}"
    def ip_address(self, version: int = 4) -> str:
        """Generate random IP address."""
        if version == 4:
            return ".".join(str(self._rng.randint(1, 254)) for _ in range(4))
        else:
            return ":".join(f"{self._rng.randint(0, 65535):04x}" for _ in range(8))
    def domain(self, tld: str | None = None) -> str:
        """Generate random domain name."""
        tld = tld or self._rng.choice(["com", "org", "net", "io"])
        return f"{self.string(10).lower()}.{tld}"
    def url(self, scheme: str = "https") -> str:
        """Generate random URL."""
        return f"{scheme}://{self.domain()}/{self.string(8)}"
    def port(self, privileged: bool = False) -> int:
        """Generate random port number."""
        if privileged:
            return self._rng.randint(1, 1023)
        return self._rng.randint(1024, 65535)
    def mac_address(self) -> str:
        """Generate random MAC address."""
        return ":".join(f"{self._rng.randint(0, 255):02x}" for _ in range(6))
    def timestamp(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> datetime:
        """Generate random timestamp."""
        now = datetime.now(timezone.utc)
        start = start or (now - timedelta(days=365))
        end = end or now
        delta = (end - start).total_seconds()
        random_seconds = self._rng.uniform(0, delta)
        return start + timedelta(seconds=random_seconds)
    def choice(self, items: list[T]) -> T:
        """Choose random item from list."""
        return self._rng.choice(items)
    def sample(self, items: list[T], k: int) -> list[T]:
        """Sample k items from list."""
        return self._rng.sample(items, min(k, len(items)))
    def integer(self, min_val: int = 0, max_val: int = 100) -> int:
        """Generate random integer."""
        return self._rng.randint(min_val, max_val)
    def floating(self, min_val: float = 0.0, max_val: float = 1.0) -> float:
        """Generate random float."""
        return self._rng.uniform(min_val, max_val)
    def boolean(self, probability: float = 0.5) -> bool:
        """Generate random boolean with given probability of True."""
        return self._rng.random() < probability
    def hash_md5(self) -> str:
        """Generate fake MD5 hash."""
        return self.hex_string(32)
    def hash_sha1(self) -> str:
        """Generate fake SHA1 hash."""
        return self.hex_string(40)
    def hash_sha256(self) -> str:
        """Generate fake SHA256 hash."""
        return self.hex_string(64)
    def cve_id(self) -> str:
        """Generate fake CVE ID."""
        year = self._rng.randint(2015, 2025)
        num = self._rng.randint(1000, 99999)
        return f"CVE-{year}-{num}"
# Global random generator
_random = RandomGenerator()
def random_string(length: int = 10) -> str:
    """Generate random string."""
    return _random.string(length)
def random_email() -> str:
    """Generate random email."""
    return _random.email()
def random_ip() -> str:
    """Generate random IP address."""
    return _random.ip_address()
def random_domain() -> str:
    """Generate random domain."""
    return _random.domain()
def random_url() -> str:
    """Generate random URL."""
    return _random.url()
# =============================================================================
# Mock Factories
# =============================================================================
@dataclass
class MockConfig:
    """Configuration for mock behavior."""
    return_value: Any = None
    side_effect: Any = None
    call_count: int = 0
    raises: Type[Exception] | None = None
    delay: float = 0.0
class MockFactory:
    """Factory for creating configured mocks."""
    @staticmethod
    def create(
        spec: Type | None = None,
        return_value: Any = None,
        side_effect: Any = None,
        **kwargs,
    ) -> MagicMock:
        """Create a configured mock object."""
        mock = MagicMock(spec=spec, **kwargs)
        if return_value is not None:
            mock.return_value = return_value
        if side_effect is not None:
            mock.side_effect = side_effect
        return mock
    @staticmethod
    def async_mock(
        return_value: Any = None,
        side_effect: Any = None,
    ) -> MagicMock:
        """Create an async mock."""
        mock = MagicMock()
        if side_effect:
            async def async_side_effect(*args, **kwargs):
                if callable(side_effect):
                    return side_effect(*args, **kwargs)
                raise side_effect
            mock.return_value = async_side_effect()
        else:
            async def async_return(*args, **kwargs):
                return return_value
            mock.return_value = async_return()
        return mock
    @staticmethod
    def http_response(
        status_code: int = 200,
        json_data: dict | None = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> MagicMock:
        """Create a mock HTTP response."""
        response = MagicMock()
        response.status_code = status_code
        response.ok = 200 <= status_code < 300
        response.text = text or json.dumps(json_data or {})
        response.headers = headers or {}
        def json_method():
            if json_data is not None:
                return json_data
            return json.loads(text) if text else {}
        response.json = json_method
        response.raise_for_status = MagicMock()
        if not response.ok:
            response.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
        return response
    @staticmethod
    def database_connection(
        query_results: list[dict] | None = None,
    ) -> MagicMock:
        """Create a mock database connection."""
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.fetchall.return_value = query_results or []
        cursor.fetchone.return_value = query_results[0] if query_results else None
        cursor.rowcount = len(query_results or [])
        return conn
    @staticmethod
    def file_system(
        files: dict[str, str] | None = None,
    ) -> MagicMock:
        """Create a mock file system."""
        fs = MagicMock()
        files = files or {}
        def read_text(path):
            if path in files:
                return files[path]
            raise FileNotFoundError(path)
        def exists(path):
            return path in files
        def write_text(path, content):
            files[path] = content
        fs.read_text = read_text
        fs.exists = exists
        fs.write_text = write_text
        fs.files = files
        return fs
# =============================================================================
# Test Data Builders
# =============================================================================
class Builder(Generic[T]):
    """Base builder for test data objects."""
    def __init__(self, factory: Callable[..., T]):
        """Initialize with factory function."""
        self._factory = factory
        self._overrides: dict[str, Any] = {}
    def with_field(self, name: str, value: Any) -> "Builder[T]":
        """Override a field value."""
        self._overrides[name] = value
        return self
    def build(self) -> T:
        """Build the object."""
        return self._factory(**self._overrides)
    def build_many(self, count: int) -> list[T]:
        """Build multiple objects."""
        return [self.build() for _ in range(count)]
@dataclass
class SampleVulnerability:
    """Test vulnerability data."""
    id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: str = "medium"
    cvss_score: float = 5.0
    description: str = ""
    affected_component: str = ""
    remediation: str = ""
    discovered_at: datetime | None = None
    def __post_init__(self):
        if not self.id:
            self.id = _random.uuid()
        if not self.cve_id:
            self.cve_id = _random.cve_id()
        if not self.title:
            self.title = f"Vulnerability in {_random.string(8)}"
        if not self.description:
            self.description = f"Test vulnerability description {_random.string(20)}"
        if not self.affected_component:
            self.affected_component = _random.string(10)
        if not self.remediation:
            self.remediation = "Apply security patch"
        if not self.discovered_at:
            self.discovered_at = _random.timestamp()
@dataclass
class SampleThreatIndicator:
    """Test threat indicator (IOC) data."""
    id: str = ""
    type: str = "ip"
    value: str = ""
    confidence: float = 0.8
    source: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    def __post_init__(self):
        if not self.id:
            self.id = _random.uuid()
        if not self.value:
            if self.type == "ip":
                self.value = _random.ip_address()
            elif self.type == "domain":
                self.value = _random.domain()
            elif self.type == "url":
                self.value = _random.url()
            elif self.type == "hash":
                self.value = _random.hash_sha256()
            elif self.type == "email":
                self.value = _random.email()
            else:
                self.value = _random.string(20)
        if not self.source:
            self.source = f"test-source-{_random.string(5)}"
        if not self.tags:
            self.tags = _random.sample(
                ["malware", "phishing", "c2", "botnet", "spam"],
                _random.integer(1, 3),
            )
        if not self.first_seen:
            self.first_seen = _random.timestamp()
        if not self.last_seen:
            self.last_seen = datetime.now(timezone.utc)
@dataclass
class SampleAsset:
    """Test asset data."""
    id: str = ""
    name: str = ""
    type: str = "server"
    ip_address: str = ""
    hostname: str = ""
    os: str = ""
    criticality: str = "medium"
    owner: str = ""
    tags: list[str] = field(default_factory=list)
    def __post_init__(self):
        if not self.id:
            self.id = _random.uuid()
        if not self.name:
            self.name = f"asset-{_random.string(6)}"
        if not self.ip_address:
            self.ip_address = _random.ip_address()
        if not self.hostname:
            self.hostname = f"{self.name}.{_random.domain()}"
        if not self.os:
            self.os = _random.choice(
                ["Ubuntu 22.04", "Windows Server 2022", "CentOS 8", "Debian 11"]
            )
        if not self.owner:
            self.owner = _random.email()
@dataclass
class SampleScanResult:
    """Test scan result data."""
    id: str = ""
    target: str = ""
    scan_type: str = "vulnerability"
    status: str = "completed"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list[dict] = field(default_factory=list)
    def __post_init__(self):
        if not self.id:
            self.id = _random.uuid()
        if not self.target:
            self.target = _random.domain()
        if not self.started_at:
            self.started_at = _random.timestamp()
        if not self.completed_at:
            self.completed_at = datetime.now(timezone.utc)
        if not self.findings_count:
            self.findings_count = (
                self.critical_count
                + self.high_count
                + self.medium_count
                + self.low_count
            )
class VulnerabilityBuilder(Builder[SampleVulnerability]):
    """Builder for test vulnerabilities."""
    def __init__(self):
        super().__init__(SampleVulnerability)
    def critical(self) -> "VulnerabilityBuilder":
        """Set severity to critical."""
        self._overrides["severity"] = "critical"
        self._overrides["cvss_score"] = _random.floating(9.0, 10.0)
        return self
    def high(self) -> "VulnerabilityBuilder":
        """Set severity to high."""
        self._overrides["severity"] = "high"
        self._overrides["cvss_score"] = _random.floating(7.0, 8.9)
        return self
    def medium(self) -> "VulnerabilityBuilder":
        """Set severity to medium."""
        self._overrides["severity"] = "medium"
        self._overrides["cvss_score"] = _random.floating(4.0, 6.9)
        return self
    def low(self) -> "VulnerabilityBuilder":
        """Set severity to low."""
        self._overrides["severity"] = "low"
        self._overrides["cvss_score"] = _random.floating(0.1, 3.9)
        return self
    def with_cve(self, cve_id: str) -> "VulnerabilityBuilder":
        """Set specific CVE ID."""
        self._overrides["cve_id"] = cve_id
        return self
class ThreatIndicatorBuilder(Builder[SampleThreatIndicator]):
    """Builder for test threat indicators."""
    def __init__(self):
        super().__init__(SampleThreatIndicator)
    def ip(self, value: str | None = None) -> "ThreatIndicatorBuilder":
        """Create IP indicator."""
        self._overrides["type"] = "ip"
        if value:
            self._overrides["value"] = value
        return self
    def domain(self, value: str | None = None) -> "ThreatIndicatorBuilder":
        """Create domain indicator."""
        self._overrides["type"] = "domain"
        if value:
            self._overrides["value"] = value
        return self
    def url(self, value: str | None = None) -> "ThreatIndicatorBuilder":
        """Create URL indicator."""
        self._overrides["type"] = "url"
        if value:
            self._overrides["value"] = value
        return self
    def hash(self, value: str | None = None) -> "ThreatIndicatorBuilder":
        """Create hash indicator."""
        self._overrides["type"] = "hash"
        if value:
            self._overrides["value"] = value
        return self
    def high_confidence(self) -> "ThreatIndicatorBuilder":
        """Set high confidence."""
        self._overrides["confidence"] = _random.floating(0.9, 1.0)
        return self
    def low_confidence(self) -> "ThreatIndicatorBuilder":
        """Set low confidence."""
        self._overrides["confidence"] = _random.floating(0.1, 0.4)
        return self
# =============================================================================
# Assertion Helpers
# =============================================================================
class AssertionHelpers:
    """Custom assertion helpers for testing."""
    @staticmethod
    def assert_dict_contains(actual: dict, expected: dict, msg: str = "") -> None:
        """Assert that actual dict contains all expected key-value pairs."""
        for key, value in expected.items():
            if key not in actual:
                raise AssertionError(
                    f"{msg}Key '{key}' not found in dict. "
                    f"Available keys: {list(actual.keys())}"
                )
            if actual[key] != value:
                raise AssertionError(
                    f"{msg}Value mismatch for key '{key}': "
                    f"expected {value!r}, got {actual[key]!r}"
                )
    @staticmethod
    def assert_dict_structure(
        actual: dict,
        required_keys: list[str],
        msg: str = "",
    ) -> None:
        """Assert that dict has required keys."""
        missing = set(required_keys) - set(actual.keys())
        if missing:
            raise AssertionError(f"{msg}Missing required keys: {missing}")
    @staticmethod
    def assert_list_length(
        actual: list,
        expected_length: int,
        msg: str = "",
    ) -> None:
        """Assert list has expected length."""
        if len(actual) != expected_length:
            raise AssertionError(
                f"{msg}Expected length {expected_length}, got {len(actual)}"
            )
    @staticmethod
    def assert_in_range(
        value: int | float,
        min_val: int | float,
        max_val: int | float,
        msg: str = "",
    ) -> None:
        """Assert value is within range."""
        if not min_val <= value <= max_val:
            raise AssertionError(
                f"{msg}Value {value} not in range [{min_val}, {max_val}]"
            )
    @staticmethod
    def assert_matches_pattern(
        value: str,
        pattern: str,
        msg: str = "",
    ) -> None:
        """Assert string matches regex pattern."""
        import re
        if not re.match(pattern, value):
            raise AssertionError(
                f"{msg}Value '{value}' does not match pattern '{pattern}'"
            )
    @staticmethod
    def assert_valid_uuid(value: str, msg: str = "") -> None:
        """Assert value is a valid UUID."""
        try:
            uuid.UUID(value)
        except ValueError:
            raise AssertionError(f"{msg}Invalid UUID: {value}")
    @staticmethod
    def assert_valid_email(value: str, msg: str = "") -> None:
        """Assert value is a valid email format."""
        import re
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise AssertionError(f"{msg}Invalid email format: {value}")
    @staticmethod
    def assert_valid_ip(value: str, version: int = 4, msg: str = "") -> None:
        """Assert value is a valid IP address."""
        import ipaddress
        try:
            if version == 4:
                ipaddress.IPv4Address(value)
            else:
                ipaddress.IPv6Address(value)
        except ipaddress.AddressValueError:
            raise AssertionError(f"{msg}Invalid IPv{version} address: {value}")
    @staticmethod
    def assert_json_serializable(value: Any, msg: str = "") -> None:
        """Assert value can be serialized to JSON."""
        try:
            json.dumps(value)
        except (TypeError, ValueError) as e:
            raise AssertionError(f"{msg}Not JSON serializable: {e}")
    @staticmethod
    def assert_approximately_equal(
        actual: float,
        expected: float,
        tolerance: float = 0.001,
        msg: str = "",
    ) -> None:
        """Assert floats are approximately equal."""
        if abs(actual - expected) > tolerance:
            raise AssertionError(
                f"{msg}Values not approximately equal: "
                f"{actual} vs {expected} (tolerance: {tolerance})"
            )
    @staticmethod
    def assert_elapsed_time(
        elapsed: float,
        max_seconds: float,
        msg: str = "",
    ) -> None:
        """Assert operation completed within time limit."""
        if elapsed > max_seconds:
            raise AssertionError(
                f"{msg}Elapsed time {elapsed:.3f}s exceeds limit {max_seconds}s"
            )
    @staticmethod
    def assert_called_with_any(
        mock: MagicMock,
        *expected_args,
        **expected_kwargs,
    ) -> None:
        """Assert mock was called with expected args at some point."""
        for call in mock.call_args_list:
            args, kwargs = call
            if args == expected_args and all(
                kwargs.get(k) == v for k, v in expected_kwargs.items()
            ):
                return
        raise AssertionError(
            f"Mock never called with args={expected_args}, kwargs={expected_kwargs}. "
            f"Actual calls: {mock.call_args_list}"
        )
# Convenience access
assert_dict_contains = AssertionHelpers.assert_dict_contains
assert_dict_structure = AssertionHelpers.assert_dict_structure
assert_list_length = AssertionHelpers.assert_list_length
assert_in_range = AssertionHelpers.assert_in_range
assert_matches_pattern = AssertionHelpers.assert_matches_pattern
assert_valid_uuid = AssertionHelpers.assert_valid_uuid
assert_valid_email = AssertionHelpers.assert_valid_email
assert_valid_ip = AssertionHelpers.assert_valid_ip
assert_json_serializable = AssertionHelpers.assert_json_serializable
assert_approximately_equal = AssertionHelpers.assert_approximately_equal
assert_elapsed_time = AssertionHelpers.assert_elapsed_time
assert_called_with_any = AssertionHelpers.assert_called_with_any
# =============================================================================
# Context Managers
# =============================================================================
@contextlib.contextmanager
def temp_directory() -> Generator[Path, None, None]:
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)
@contextlib.contextmanager
def temp_file(
    content: str = "",
    suffix: str = ".txt",
) -> Generator[Path, None, None]:
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        delete=False,
    ) as f:
        f.write(content)
        f.flush()
        path = Path(f.name)
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)
@contextlib.contextmanager
def temp_json_file(data: Any) -> Generator[Path, None, None]:
    """Create a temporary JSON file for testing."""
    with temp_file(json.dumps(data), suffix=".json") as path:
        yield path
@contextlib.contextmanager
def environment_variables(**env_vars) -> Generator[None, None, None]:
    """Temporarily set environment variables."""
    import os
    original = {}
    for key, value in env_vars.items():
        original[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
@contextlib.contextmanager
def captured_time() -> Generator[dict[str, float], None, None]:
    """Capture elapsed time for a code block."""
    result = {"elapsed": 0.0, "start": 0.0, "end": 0.0}
    result["start"] = time.perf_counter()
    try:
        yield result
    finally:
        result["end"] = time.perf_counter()
        result["elapsed"] = result["end"] - result["start"]
@contextlib.contextmanager
def mock_datetime(
    fixed_time: datetime,
) -> Generator[None, None, None]:
    """Mock datetime.now() to return a fixed time."""
    class MockDateTime:
        @classmethod
        def now(cls, tz=None):
            if tz:
                return fixed_time.astimezone(tz)
            return fixed_time
        @classmethod
        def utcnow(cls):
            return fixed_time.replace(tzinfo=None)
        def __getattr__(self, name):
            return getattr(datetime, name)
    with patch("datetime.datetime", MockDateTime):
        yield
@contextlib.contextmanager
def suppress_output() -> Generator[None, None, None]:
    """Suppress stdout and stderr."""
    import io
    import sys
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
# =============================================================================
# Test Fixtures
# =============================================================================
class FixtureFactory:
    """Factory for creating test fixtures."""
    @staticmethod
    def vulnerability_set(
        count: int = 5,
        severity_distribution: dict[str, int] | None = None,
    ) -> list[SampleVulnerability]:
        """Create a set of vulnerabilities."""
        if severity_distribution:
            vulns = []
            for severity, num in severity_distribution.items():
                for _ in range(num):
                    vulns.append(
                        VulnerabilityBuilder().with_field("severity", severity).build()
                    )
            return vulns
        return VulnerabilityBuilder().build_many(count)
    @staticmethod
    def threat_indicators(
        count: int = 10,
        types: list[str] | None = None,
    ) -> list[SampleThreatIndicator]:
        """Create a set of threat indicators."""
        types = types or ["ip", "domain", "url", "hash"]
        indicators = []
        for _ in range(count):
            ioc_type = _random.choice(types)
            builder = ThreatIndicatorBuilder()
            if ioc_type == "ip":
                builder.ip()
            elif ioc_type == "domain":
                builder.domain()
            elif ioc_type == "url":
                builder.url()
            else:
                builder.hash()
            indicators.append(builder.build())
        return indicators
    @staticmethod
    def scan_results(
        count: int = 3,
        with_findings: bool = True,
    ) -> list[SampleScanResult]:
        """Create a set of scan results."""
        results = []
        for _ in range(count):
            result = SampleScanResult()
            if with_findings:
                result.critical_count = _random.integer(0, 2)
                result.high_count = _random.integer(0, 5)
                result.medium_count = _random.integer(0, 10)
                result.low_count = _random.integer(0, 20)
                result.findings_count = (
                    result.critical_count
                    + result.high_count
                    + result.medium_count
                    + result.low_count
                )
            results.append(result)
        return results
    @staticmethod
    def asset_inventory(count: int = 10) -> list[SampleAsset]:
        """Create an asset inventory."""
        return [SampleAsset() for _ in range(count)]
# =============================================================================
# Test Doubles
# =============================================================================
class FakeHTTPClient:
    """Fake HTTP client for testing."""
    def __init__(self):
        self._responses: dict[str, MagicMock] = {}
        self._requests: list[dict] = []
    def add_response(
        self,
        url: str,
        status_code: int = 200,
        json_data: dict | None = None,
        text: str = "",
        method: str = "GET",
    ) -> None:
        """Add a canned response for a URL."""
        key = f"{method}:{url}"
        self._responses[key] = MockFactory.http_response(
            status_code=status_code,
            json_data=json_data,
            text=text,
        )
    def get(self, url: str, **kwargs) -> MagicMock:
        """Simulate GET request."""
        return self._make_request("GET", url, **kwargs)
    def post(self, url: str, **kwargs) -> MagicMock:
        """Simulate POST request."""
        return self._make_request("POST", url, **kwargs)
    def put(self, url: str, **kwargs) -> MagicMock:
        """Simulate PUT request."""
        return self._make_request("PUT", url, **kwargs)
    def delete(self, url: str, **kwargs) -> MagicMock:
        """Simulate DELETE request."""
        return self._make_request("DELETE", url, **kwargs)
    def _make_request(self, method: str, url: str, **kwargs) -> MagicMock:
        """Make a simulated request."""
        self._requests.append(
            {
                "method": method,
                "url": url,
                "kwargs": kwargs,
            }
        )
        key = f"{method}:{url}"
        if key in self._responses:
            return self._responses[key]
        # Default 404 response
        return MockFactory.http_response(status_code=404)
    @property
    def requests(self) -> list[dict]:
        """Get recorded requests."""
        return self._requests
    def reset(self) -> None:
        """Reset recorded requests."""
        self._requests = []
class FakeDatabase:
    """Fake database for testing."""
    def __init__(self):
        self._tables: dict[str, list[dict]] = {}
        self._queries: list[str] = []
    def create_table(self, name: str) -> None:
        """Create a table."""
        self._tables[name] = []
    def insert(self, table: str, record: dict) -> None:
        """Insert a record."""
        if table not in self._tables:
            self._tables[table] = []
        self._tables[table].append(copy.deepcopy(record))
        self._queries.append(f"INSERT INTO {table}")
    def select(
        self,
        table: str,
        where: dict | None = None,
    ) -> list[dict]:
        """Select records."""
        self._queries.append(f"SELECT FROM {table}")
        if table not in self._tables:
            return []
        records = self._tables[table]
        if where:
            records = [
                r for r in records if all(r.get(k) == v for k, v in where.items())
            ]
        return copy.deepcopy(records)
    def update(
        self,
        table: str,
        values: dict,
        where: dict,
    ) -> int:
        """Update records."""
        self._queries.append(f"UPDATE {table}")
        if table not in self._tables:
            return 0
        count = 0
        for record in self._tables[table]:
            if all(record.get(k) == v for k, v in where.items()):
                record.update(values)
                count += 1
        return count
    def delete(self, table: str, where: dict) -> int:
        """Delete records."""
        self._queries.append(f"DELETE FROM {table}")
        if table not in self._tables:
            return 0
        original_count = len(self._tables[table])
        self._tables[table] = [
            r
            for r in self._tables[table]
            if not all(r.get(k) == v for k, v in where.items())
        ]
        return original_count - len(self._tables[table])
    @property
    def queries(self) -> list[str]:
        """Get recorded queries."""
        return self._queries
    def reset(self) -> None:
        """Reset database."""
        self._tables = {}
        self._queries = []
class FakeCache:
    """Fake cache for testing."""
    def __init__(self):
        self._data: dict[str, Any] = {}
        self._ttls: dict[str, float] = {}
        self._operations: list[str] = []
    def get(self, key: str) -> Any | None:
        """Get a value from cache."""
        self._operations.append(f"GET:{key}")
        if key in self._ttls:
            if time.time() > self._ttls[key]:
                del self._data[key]
                del self._ttls[key]
                return None
        return self._data.get(key)
    def set(
        self,
        key: str,
        value: Any,
        ttl: float | None = None,
    ) -> None:
        """Set a value in cache."""
        self._operations.append(f"SET:{key}")
        self._data[key] = value
        if ttl:
            self._ttls[key] = time.time() + ttl
    def delete(self, key: str) -> bool:
        """Delete a value from cache."""
        self._operations.append(f"DELETE:{key}")
        if key in self._data:
            del self._data[key]
            self._ttls.pop(key, None)
            return True
        return False
    def clear(self) -> None:
        """Clear the cache."""
        self._operations.append("CLEAR")
        self._data = {}
        self._ttls = {}
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    @property
    def operations(self) -> list[str]:
        """Get recorded operations."""
        return self._operations
    def reset(self) -> None:
        """Reset cache and operations."""
        self._data = {}
        self._ttls = {}
        self._operations = []
# =============================================================================
# Pytest Integration
# =============================================================================
def pytest_fixture(func: Callable) -> Callable:
    """Decorator to mark a function as a pytest fixture (for documentation)."""
    func._is_fixture = True
    return func
@pytest_fixture
def random_gen() -> RandomGenerator:
    """Fixture providing seeded random generator."""
    return RandomGenerator(seed=42)
@pytest_fixture
def fake_http() -> FakeHTTPClient:
    """Fixture providing fake HTTP client."""
    return FakeHTTPClient()
@pytest_fixture
def fake_db() -> FakeDatabase:
    """Fixture providing fake database."""
    return FakeDatabase()
@pytest_fixture
def fake_cache() -> FakeCache:
    """Fixture providing fake cache."""
    return FakeCache()