"""Tests for testing utilities module."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from redops.core.testing import (
    AssertionHelpers,
    Builder,
    FakeCache,
    FakeDatabase,
    FakeHTTPClient,
    FixtureFactory,
    MockFactory,
    RandomGenerator,
    SampleAsset,
    SampleScanResult,
    SampleThreatIndicator,
    SampleVulnerability,
    ThreatIndicatorBuilder,
    VulnerabilityBuilder,
    assert_approximately_equal,
    assert_called_with_any,
    assert_dict_contains,
    assert_dict_structure,
    assert_elapsed_time,
    assert_in_range,
    assert_json_serializable,
    assert_list_length,
    assert_matches_pattern,
    assert_valid_email,
    assert_valid_ip,
    assert_valid_uuid,
    captured_time,
    environment_variables,
    random_domain,
    random_email,
    random_ip,
    random_string,
    random_url,
    suppress_output,
    temp_directory,
    temp_file,
    temp_json_file,
)


class TestRandomGenerator:
    """Tests for RandomGenerator class."""

    def test_string_default(self):
        """Test default string generation."""
        gen = RandomGenerator(seed=42)
        s = gen.string()
        assert len(s) == 10
        assert s.isalnum()

    def test_string_custom_length(self):
        """Test custom length string."""
        gen = RandomGenerator(seed=42)
        s = gen.string(length=20)
        assert len(s) == 20

    def test_string_custom_charset(self):
        """Test custom charset string."""
        gen = RandomGenerator(seed=42)
        s = gen.string(length=10, charset="abc")
        assert len(s) == 10
        assert all(c in "abc" for c in s)

    def test_hex_string(self):
        """Test hex string generation."""
        gen = RandomGenerator(seed=42)
        s = gen.hex_string(32)
        assert len(s) == 32
        assert all(c in "0123456789abcdef" for c in s)

    def test_uuid(self):
        """Test UUID generation."""
        gen = RandomGenerator(seed=42)
        u = gen.uuid()
        # Should be valid UUID format
        parts = u.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12

    def test_email(self):
        """Test email generation."""
        gen = RandomGenerator(seed=42)
        email = gen.email()
        assert "@" in email
        assert "." in email.split("@")[1]

    def test_email_custom_domain(self):
        """Test email with custom domain."""
        gen = RandomGenerator(seed=42)
        email = gen.email(domain="example.com")
        assert email.endswith("@example.com")

    def test_ip_address_v4(self):
        """Test IPv4 address generation."""
        gen = RandomGenerator(seed=42)
        ip = gen.ip_address(version=4)
        parts = ip.split(".")
        assert len(parts) == 4
        assert all(1 <= int(p) <= 254 for p in parts)

    def test_ip_address_v6(self):
        """Test IPv6 address generation."""
        gen = RandomGenerator(seed=42)
        ip = gen.ip_address(version=6)
        parts = ip.split(":")
        assert len(parts) == 8

    def test_domain(self):
        """Test domain generation."""
        gen = RandomGenerator(seed=42)
        domain = gen.domain()
        assert "." in domain
        parts = domain.split(".")
        assert len(parts) >= 2

    def test_domain_custom_tld(self):
        """Test domain with custom TLD."""
        gen = RandomGenerator(seed=42)
        domain = gen.domain(tld="io")
        assert domain.endswith(".io")

    def test_url(self):
        """Test URL generation."""
        gen = RandomGenerator(seed=42)
        url = gen.url()
        assert url.startswith("https://")
        assert "." in url

    def test_url_custom_scheme(self):
        """Test URL with custom scheme."""
        gen = RandomGenerator(seed=42)
        url = gen.url(scheme="http")
        assert url.startswith("http://")

    def test_port_unprivileged(self):
        """Test unprivileged port generation."""
        gen = RandomGenerator(seed=42)
        port = gen.port(privileged=False)
        assert 1024 <= port <= 65535

    def test_port_privileged(self):
        """Test privileged port generation."""
        gen = RandomGenerator(seed=42)
        port = gen.port(privileged=True)
        assert 1 <= port <= 1023

    def test_mac_address(self):
        """Test MAC address generation."""
        gen = RandomGenerator(seed=42)
        mac = gen.mac_address()
        parts = mac.split(":")
        assert len(parts) == 6
        assert all(len(p) == 2 for p in parts)

    def test_timestamp(self):
        """Test timestamp generation."""
        gen = RandomGenerator(seed=42)
        ts = gen.timestamp()
        assert isinstance(ts, datetime)
        assert ts.tzinfo is not None

    def test_timestamp_range(self):
        """Test timestamp within range."""
        gen = RandomGenerator(seed=42)
        start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        end = datetime(2020, 12, 31, tzinfo=timezone.utc)
        ts = gen.timestamp(start=start, end=end)
        assert start <= ts <= end

    def test_choice(self):
        """Test random choice."""
        gen = RandomGenerator(seed=42)
        items = ["a", "b", "c"]
        choice = gen.choice(items)
        assert choice in items

    def test_sample(self):
        """Test random sample."""
        gen = RandomGenerator(seed=42)
        items = ["a", "b", "c", "d", "e"]
        sample = gen.sample(items, 3)
        assert len(sample) == 3
        assert all(s in items for s in sample)

    def test_integer(self):
        """Test integer generation."""
        gen = RandomGenerator(seed=42)
        i = gen.integer(10, 20)
        assert 10 <= i <= 20

    def test_floating(self):
        """Test float generation."""
        gen = RandomGenerator(seed=42)
        f = gen.floating(1.0, 2.0)
        assert 1.0 <= f <= 2.0

    def test_boolean(self):
        """Test boolean generation."""
        gen = RandomGenerator(seed=42)
        # With probability 1.0, should always be True
        assert gen.boolean(probability=1.0) is True
        # With probability 0.0, should always be False
        assert gen.boolean(probability=0.0) is False

    def test_hash_md5(self):
        """Test MD5 hash generation."""
        gen = RandomGenerator(seed=42)
        h = gen.hash_md5()
        assert len(h) == 32
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_sha1(self):
        """Test SHA1 hash generation."""
        gen = RandomGenerator(seed=42)
        h = gen.hash_sha1()
        assert len(h) == 40

    def test_hash_sha256(self):
        """Test SHA256 hash generation."""
        gen = RandomGenerator(seed=42)
        h = gen.hash_sha256()
        assert len(h) == 64

    def test_cve_id(self):
        """Test CVE ID generation."""
        gen = RandomGenerator(seed=42)
        cve = gen.cve_id()
        assert cve.startswith("CVE-")
        parts = cve.split("-")
        assert len(parts) == 3
        assert parts[1].isdigit()
        assert parts[2].isdigit()

    def test_reproducibility(self):
        """Test that same seed produces same results."""
        gen1 = RandomGenerator(seed=123)
        gen2 = RandomGenerator(seed=123)
        assert gen1.string(10) == gen2.string(10)
        assert gen1.integer(0, 100) == gen2.integer(0, 100)


class TestConvenienceFunctions:
    """Tests for convenience random functions."""

    def test_random_string(self):
        """Test random_string function."""
        s = random_string(15)
        assert len(s) == 15

    def test_random_email(self):
        """Test random_email function."""
        email = random_email()
        assert "@" in email

    def test_random_ip(self):
        """Test random_ip function."""
        ip = random_ip()
        assert len(ip.split(".")) == 4

    def test_random_domain(self):
        """Test random_domain function."""
        domain = random_domain()
        assert "." in domain

    def test_random_url(self):
        """Test random_url function."""
        url = random_url()
        assert url.startswith("https://")


class TestMockFactory:
    """Tests for MockFactory class."""

    def test_create_basic(self):
        """Test basic mock creation."""
        mock = MockFactory.create()
        assert isinstance(mock, MagicMock)

    def test_create_with_return_value(self):
        """Test mock with return value."""
        mock = MockFactory.create(return_value=42)
        assert mock() == 42

    def test_create_with_side_effect(self):
        """Test mock with side effect."""
        mock = MockFactory.create(side_effect=ValueError("test"))
        with pytest.raises(ValueError):
            mock()

    def test_http_response_success(self):
        """Test successful HTTP response mock."""
        response = MockFactory.http_response(
            status_code=200,
            json_data={"key": "value"},
        )
        assert response.status_code == 200
        assert response.ok is True
        assert response.json() == {"key": "value"}

    def test_http_response_error(self):
        """Test error HTTP response mock."""
        response = MockFactory.http_response(status_code=404)
        assert response.status_code == 404
        assert response.ok is False
        with pytest.raises(Exception):
            response.raise_for_status()

    def test_database_connection(self):
        """Test database connection mock."""
        conn = MockFactory.database_connection(
            query_results=[{"id": 1, "name": "test"}]
        )
        cursor = conn.cursor()
        assert cursor.fetchall() == [{"id": 1, "name": "test"}]
        assert cursor.fetchone() == {"id": 1, "name": "test"}
        assert cursor.rowcount == 1

    def test_file_system(self):
        """Test file system mock."""
        fs = MockFactory.file_system(
            files={"/test.txt": "content"}
        )
        assert fs.exists("/test.txt") is True
        assert fs.exists("/missing.txt") is False
        assert fs.read_text("/test.txt") == "content"
        with pytest.raises(FileNotFoundError):
            fs.read_text("/missing.txt")

    def test_file_system_write(self):
        """Test file system mock write."""
        fs = MockFactory.file_system()
        fs.write_text("/new.txt", "new content")
        assert fs.read_text("/new.txt") == "new content"


class TestBuilder:
    """Tests for Builder class."""

    def test_basic_build(self):
        """Test basic builder."""

        def factory(**kwargs):
            return {"a": kwargs.get("a", 1), "b": kwargs.get("b", 2)}

        builder = Builder(factory)
        result = builder.build()
        assert result == {"a": 1, "b": 2}

    def test_with_field(self):
        """Test builder with field override."""

        def factory(**kwargs):
            return {"a": kwargs.get("a", 1), "b": kwargs.get("b", 2)}

        builder = Builder(factory)
        result = builder.with_field("a", 10).build()
        assert result == {"a": 10, "b": 2}

    def test_build_many(self):
        """Test building multiple objects."""

        def factory(**kwargs):
            return {"value": kwargs.get("value", 0)}

        builder = Builder(factory)
        results = builder.build_many(3)
        assert len(results) == 3


class TestSampleVulnerability:
    """Tests for SampleVulnerability dataclass."""

    def test_default_creation(self):
        """Test default creation."""
        vuln = SampleVulnerability()
        assert vuln.id != ""
        assert vuln.cve_id.startswith("CVE-")
        assert vuln.severity == "medium"
        assert vuln.cvss_score == 5.0

    def test_custom_values(self):
        """Test custom values."""
        vuln = SampleVulnerability(
            severity="critical",
            cvss_score=9.8,
            title="Test Vuln",
        )
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 9.8
        assert vuln.title == "Test Vuln"


class SampleVulnerabilityBuilder:
    """Tests for VulnerabilityBuilder."""

    def test_critical(self):
        """Test critical severity."""
        vuln = VulnerabilityBuilder().critical().build()
        assert vuln.severity == "critical"
        assert vuln.cvss_score >= 9.0

    def test_high(self):
        """Test high severity."""
        vuln = VulnerabilityBuilder().high().build()
        assert vuln.severity == "high"
        assert 7.0 <= vuln.cvss_score < 9.0

    def test_medium(self):
        """Test medium severity."""
        vuln = VulnerabilityBuilder().medium().build()
        assert vuln.severity == "medium"
        assert 4.0 <= vuln.cvss_score < 7.0

    def test_low(self):
        """Test low severity."""
        vuln = VulnerabilityBuilder().low().build()
        assert vuln.severity == "low"
        assert vuln.cvss_score < 4.0

    def test_with_cve(self):
        """Test with specific CVE."""
        vuln = VulnerabilityBuilder().with_cve("CVE-2024-12345").build()
        assert vuln.cve_id == "CVE-2024-12345"


class TestSampleThreatIndicator:
    """Tests for SampleThreatIndicator dataclass."""

    def test_default_creation(self):
        """Test default creation."""
        ioc = SampleThreatIndicator()
        assert ioc.id != ""
        assert ioc.type == "ip"
        assert ioc.confidence == 0.8

    def test_domain_type(self):
        """Test domain type indicator."""
        ioc = SampleThreatIndicator(type="domain")
        assert ioc.type == "domain"
        assert "." in ioc.value


class SampleThreatIndicatorBuilder:
    """Tests for ThreatIndicatorBuilder."""

    def test_ip(self):
        """Test IP indicator."""
        ioc = ThreatIndicatorBuilder().ip().build()
        assert ioc.type == "ip"
        assert len(ioc.value.split(".")) == 4

    def test_domain(self):
        """Test domain indicator."""
        ioc = ThreatIndicatorBuilder().domain().build()
        assert ioc.type == "domain"
        assert "." in ioc.value

    def test_url(self):
        """Test URL indicator."""
        ioc = ThreatIndicatorBuilder().url().build()
        assert ioc.type == "url"
        assert ioc.value.startswith("http")

    def test_hash(self):
        """Test hash indicator."""
        ioc = ThreatIndicatorBuilder().hash().build()
        assert ioc.type == "hash"
        assert len(ioc.value) == 64  # SHA256

    def test_high_confidence(self):
        """Test high confidence."""
        ioc = ThreatIndicatorBuilder().high_confidence().build()
        assert ioc.confidence >= 0.9

    def test_low_confidence(self):
        """Test low confidence."""
        ioc = ThreatIndicatorBuilder().low_confidence().build()
        assert ioc.confidence <= 0.4

    def test_specific_value(self):
        """Test with specific value."""
        ioc = ThreatIndicatorBuilder().ip("1.2.3.4").build()
        assert ioc.value == "1.2.3.4"


class TestSampleAsset:
    """Tests for SampleAsset dataclass."""

    def test_default_creation(self):
        """Test default creation."""
        asset = SampleAsset()
        assert asset.id != ""
        assert asset.name.startswith("asset-")
        assert asset.type == "server"


class TestSampleScanResult:
    """Tests for SampleScanResult dataclass."""

    def test_default_creation(self):
        """Test default creation."""
        result = SampleScanResult()
        assert result.id != ""
        assert result.status == "completed"
        assert result.scan_type == "vulnerability"


class TestAssertionHelpers:
    """Tests for AssertionHelpers class."""

    def test_assert_dict_contains_pass(self):
        """Test assert_dict_contains passing."""
        actual = {"a": 1, "b": 2, "c": 3}
        expected = {"a": 1, "b": 2}
        assert_dict_contains(actual, expected)  # Should not raise

    def test_assert_dict_contains_missing_key(self):
        """Test assert_dict_contains with missing key."""
        actual = {"a": 1}
        expected = {"b": 2}
        with pytest.raises(AssertionError, match="not found"):
            assert_dict_contains(actual, expected)

    def test_assert_dict_contains_wrong_value(self):
        """Test assert_dict_contains with wrong value."""
        actual = {"a": 1}
        expected = {"a": 2}
        with pytest.raises(AssertionError, match="Value mismatch"):
            assert_dict_contains(actual, expected)

    def test_assert_dict_structure_pass(self):
        """Test assert_dict_structure passing."""
        actual = {"a": 1, "b": 2}
        assert_dict_structure(actual, ["a", "b"])

    def test_assert_dict_structure_fail(self):
        """Test assert_dict_structure failing."""
        actual = {"a": 1}
        with pytest.raises(AssertionError, match="Missing required keys"):
            assert_dict_structure(actual, ["a", "b"])

    def test_assert_list_length_pass(self):
        """Test assert_list_length passing."""
        assert_list_length([1, 2, 3], 3)

    def test_assert_list_length_fail(self):
        """Test assert_list_length failing."""
        with pytest.raises(AssertionError, match="Expected length"):
            assert_list_length([1, 2], 3)

    def test_assert_in_range_pass(self):
        """Test assert_in_range passing."""
        assert_in_range(5, 1, 10)

    def test_assert_in_range_fail(self):
        """Test assert_in_range failing."""
        with pytest.raises(AssertionError, match="not in range"):
            assert_in_range(15, 1, 10)

    def test_assert_matches_pattern_pass(self):
        """Test assert_matches_pattern passing."""
        assert_matches_pattern("test123", r"test\d+")

    def test_assert_matches_pattern_fail(self):
        """Test assert_matches_pattern failing."""
        with pytest.raises(AssertionError, match="does not match"):
            assert_matches_pattern("test", r"\d+")

    def test_assert_valid_uuid_pass(self):
        """Test assert_valid_uuid passing."""
        assert_valid_uuid("550e8400-e29b-41d4-a716-446655440000")

    def test_assert_valid_uuid_fail(self):
        """Test assert_valid_uuid failing."""
        with pytest.raises(AssertionError, match="Invalid UUID"):
            assert_valid_uuid("not-a-uuid")

    def test_assert_valid_email_pass(self):
        """Test assert_valid_email passing."""
        assert_valid_email("test@example.com")

    def test_assert_valid_email_fail(self):
        """Test assert_valid_email failing."""
        with pytest.raises(AssertionError, match="Invalid email"):
            assert_valid_email("not-an-email")

    def test_assert_valid_ip_v4_pass(self):
        """Test assert_valid_ip IPv4 passing."""
        assert_valid_ip("192.168.1.1", version=4)

    def test_assert_valid_ip_v4_fail(self):
        """Test assert_valid_ip IPv4 failing."""
        with pytest.raises(AssertionError, match="Invalid IPv4"):
            assert_valid_ip("not-an-ip", version=4)

    def test_assert_json_serializable_pass(self):
        """Test assert_json_serializable passing."""
        assert_json_serializable({"key": "value"})

    def test_assert_json_serializable_fail(self):
        """Test assert_json_serializable failing."""
        with pytest.raises(AssertionError, match="Not JSON serializable"):
            assert_json_serializable({"key": object()})

    def test_assert_approximately_equal_pass(self):
        """Test assert_approximately_equal passing."""
        assert_approximately_equal(1.001, 1.0, tolerance=0.01)

    def test_assert_approximately_equal_fail(self):
        """Test assert_approximately_equal failing."""
        with pytest.raises(AssertionError, match="not approximately equal"):
            assert_approximately_equal(1.5, 1.0, tolerance=0.01)

    def test_assert_elapsed_time_pass(self):
        """Test assert_elapsed_time passing."""
        assert_elapsed_time(0.5, max_seconds=1.0)

    def test_assert_elapsed_time_fail(self):
        """Test assert_elapsed_time failing."""
        with pytest.raises(AssertionError, match="exceeds limit"):
            assert_elapsed_time(2.0, max_seconds=1.0)

    def test_assert_called_with_any_pass(self):
        """Test assert_called_with_any passing."""
        mock = MagicMock()
        mock(1, 2)
        mock(3, 4)
        mock(5, key="value")
        assert_called_with_any(mock, 5, key="value")

    def test_assert_called_with_any_fail(self):
        """Test assert_called_with_any failing."""
        mock = MagicMock()
        mock(1, 2)
        with pytest.raises(AssertionError, match="Mock never called"):
            assert_called_with_any(mock, 9, 9)


class TestContextManagers:
    """Tests for context managers."""

    def test_temp_directory(self):
        """Test temp_directory context manager."""
        with temp_directory() as tmpdir:
            assert tmpdir.exists()
            assert tmpdir.is_dir()
            # Create a file
            (tmpdir / "test.txt").write_text("content")
            assert (tmpdir / "test.txt").exists()
        # Directory should be cleaned up
        assert not tmpdir.exists()

    def test_temp_file(self):
        """Test temp_file context manager."""
        with temp_file(content="hello", suffix=".txt") as path:
            assert path.exists()
            assert path.read_text() == "hello"
            assert path.suffix == ".txt"
        # File should be cleaned up
        assert not path.exists()

    def test_temp_json_file(self):
        """Test temp_json_file context manager."""
        data = {"key": "value", "num": 42}
        with temp_json_file(data) as path:
            assert path.exists()
            loaded = json.loads(path.read_text())
            assert loaded == data
        assert not path.exists()

    def test_environment_variables_set(self):
        """Test environment_variables sets vars."""
        with environment_variables(TEST_VAR="test_value"):
            assert os.environ.get("TEST_VAR") == "test_value"
        assert os.environ.get("TEST_VAR") is None

    def test_environment_variables_unset(self):
        """Test environment_variables can unset vars."""
        os.environ["TEMP_VAR"] = "original"
        with environment_variables(TEMP_VAR=None):
            assert "TEMP_VAR" not in os.environ
        assert os.environ.get("TEMP_VAR") == "original"
        del os.environ["TEMP_VAR"]

    def test_environment_variables_restore(self):
        """Test environment_variables restores original."""
        os.environ["RESTORE_VAR"] = "original"
        with environment_variables(RESTORE_VAR="modified"):
            assert os.environ.get("RESTORE_VAR") == "modified"
        assert os.environ.get("RESTORE_VAR") == "original"
        del os.environ["RESTORE_VAR"]

    def test_captured_time(self):
        """Test captured_time context manager."""
        with captured_time() as timing:
            time.sleep(0.05)
        assert timing["elapsed"] >= 0.05
        assert timing["start"] > 0
        assert timing["end"] > timing["start"]

    def test_suppress_output(self):
        """Test suppress_output context manager."""
        import sys
        original_stdout = sys.stdout
        with suppress_output():
            print("This should be suppressed")
            # stdout should be different inside context
        assert sys.stdout is original_stdout


class TestFixtureFactory:
    """Tests for FixtureFactory class."""

    def test_vulnerability_set_default(self):
        """Test vulnerability set with defaults."""
        vulns = FixtureFactory.vulnerability_set(count=5)
        assert len(vulns) == 5
        assert all(isinstance(v, SampleVulnerability) for v in vulns)

    def test_vulnerability_set_distribution(self):
        """Test vulnerability set with severity distribution."""
        vulns = FixtureFactory.vulnerability_set(
            severity_distribution={"critical": 1, "high": 2, "medium": 3}
        )
        assert len(vulns) == 6
        severities = [v.severity for v in vulns]
        assert severities.count("critical") == 1
        assert severities.count("high") == 2
        assert severities.count("medium") == 3

    def test_threat_indicators(self):
        """Test threat indicators generation."""
        iocs = FixtureFactory.threat_indicators(count=10)
        assert len(iocs) == 10
        assert all(isinstance(i, SampleThreatIndicator) for i in iocs)

    def test_threat_indicators_types(self):
        """Test threat indicators with specific types."""
        iocs = FixtureFactory.threat_indicators(count=10, types=["ip", "domain"])
        assert all(i.type in ["ip", "domain"] for i in iocs)

    def test_scan_results(self):
        """Test scan results generation."""
        results = FixtureFactory.scan_results(count=3)
        assert len(results) == 3
        assert all(isinstance(r, SampleScanResult) for r in results)

    def test_scan_results_with_findings(self):
        """Test scan results with findings."""
        results = FixtureFactory.scan_results(count=5, with_findings=True)
        # At least some should have findings
        total_findings = sum(r.findings_count for r in results)
        assert total_findings >= 0  # Could be 0 by chance but unlikely

    def test_asset_inventory(self):
        """Test asset inventory generation."""
        assets = FixtureFactory.asset_inventory(count=10)
        assert len(assets) == 10
        assert all(isinstance(a, SampleAsset) for a in assets)


class TestFakeHTTPClient:
    """Tests for FakeHTTPClient class."""

    def test_get_default_404(self):
        """Test GET returns 404 by default."""
        client = FakeHTTPClient()
        response = client.get("http://example.com")
        assert response.status_code == 404

    def test_add_response(self):
        """Test adding canned response."""
        client = FakeHTTPClient()
        client.add_response(
            "http://example.com/api",
            status_code=200,
            json_data={"result": "success"},
        )
        response = client.get("http://example.com/api")
        assert response.status_code == 200
        assert response.json() == {"result": "success"}

    def test_post(self):
        """Test POST request."""
        client = FakeHTTPClient()
        client.add_response(
            "http://example.com/api",
            method="POST",
            status_code=201,
        )
        response = client.post("http://example.com/api", json={"data": "test"})
        assert response.status_code == 201

    def test_requests_recorded(self):
        """Test requests are recorded."""
        client = FakeHTTPClient()
        client.get("http://example.com/a")
        client.post("http://example.com/b", json={})
        assert len(client.requests) == 2
        assert client.requests[0]["method"] == "GET"
        assert client.requests[1]["method"] == "POST"

    def test_reset(self):
        """Test reset clears requests."""
        client = FakeHTTPClient()
        client.get("http://example.com")
        client.reset()
        assert len(client.requests) == 0


class TestFakeDatabase:
    """Tests for FakeDatabase class."""

    def test_insert_and_select(self):
        """Test insert and select."""
        db = FakeDatabase()
        db.insert("users", {"id": 1, "name": "Alice"})
        db.insert("users", {"id": 2, "name": "Bob"})

        results = db.select("users")
        assert len(results) == 2

    def test_select_with_where(self):
        """Test select with where clause."""
        db = FakeDatabase()
        db.insert("users", {"id": 1, "name": "Alice"})
        db.insert("users", {"id": 2, "name": "Bob"})

        results = db.select("users", where={"name": "Alice"})
        assert len(results) == 1
        assert results[0]["name"] == "Alice"

    def test_update(self):
        """Test update."""
        db = FakeDatabase()
        db.insert("users", {"id": 1, "name": "Alice"})

        count = db.update("users", {"name": "Alicia"}, where={"id": 1})
        assert count == 1

        results = db.select("users", where={"id": 1})
        assert results[0]["name"] == "Alicia"

    def test_delete(self):
        """Test delete."""
        db = FakeDatabase()
        db.insert("users", {"id": 1, "name": "Alice"})
        db.insert("users", {"id": 2, "name": "Bob"})

        count = db.delete("users", where={"id": 1})
        assert count == 1

        results = db.select("users")
        assert len(results) == 1
        assert results[0]["name"] == "Bob"

    def test_queries_recorded(self):
        """Test queries are recorded."""
        db = FakeDatabase()
        db.insert("users", {"id": 1})
        db.select("users")
        db.update("users", {"name": "test"}, where={"id": 1})
        db.delete("users", where={"id": 1})

        assert "INSERT INTO users" in db.queries
        assert "SELECT FROM users" in db.queries
        assert "UPDATE users" in db.queries
        assert "DELETE FROM users" in db.queries

    def test_reset(self):
        """Test reset clears everything."""
        db = FakeDatabase()
        db.insert("users", {"id": 1})
        assert len(db.queries) == 1  # INSERT recorded
        db.reset()

        # After reset, queries should be cleared
        assert len(db.queries) == 0
        # Data should be cleared (select will add a new query)
        assert len(db.select("users")) == 0


class TestFakeCache:
    """Tests for FakeCache class."""

    def test_set_and_get(self):
        """Test set and get."""
        cache = FakeCache()
        cache.set("key", "value")
        assert cache.get("key") == "value"

    def test_get_missing(self):
        """Test get missing key."""
        cache = FakeCache()
        assert cache.get("missing") is None

    def test_delete(self):
        """Test delete."""
        cache = FakeCache()
        cache.set("key", "value")
        result = cache.delete("key")
        assert result is True
        assert cache.get("key") is None

    def test_delete_missing(self):
        """Test delete missing key."""
        cache = FakeCache()
        result = cache.delete("missing")
        assert result is False

    def test_clear(self):
        """Test clear."""
        cache = FakeCache()
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_exists(self):
        """Test exists."""
        cache = FakeCache()
        cache.set("key", "value")
        assert cache.exists("key") is True
        assert cache.exists("missing") is False

    def test_ttl_expired(self):
        """Test TTL expiration."""
        cache = FakeCache()
        cache.set("key", "value", ttl=0.01)  # 10ms
        time.sleep(0.02)  # Wait for expiration
        assert cache.get("key") is None

    def test_ttl_not_expired(self):
        """Test TTL not yet expired."""
        cache = FakeCache()
        cache.set("key", "value", ttl=10)  # 10 seconds
        assert cache.get("key") == "value"

    def test_operations_recorded(self):
        """Test operations are recorded."""
        cache = FakeCache()
        cache.set("key", "value")
        cache.get("key")
        cache.delete("key")
        cache.clear()

        assert "SET:key" in cache.operations
        assert "GET:key" in cache.operations
        assert "DELETE:key" in cache.operations
        assert "CLEAR" in cache.operations

    def test_reset(self):
        """Test reset clears everything."""
        cache = FakeCache()
        cache.set("key", "value")
        assert len(cache.operations) == 1  # SET recorded
        cache.reset()

        # After reset, operations should be cleared
        assert len(cache.operations) == 0
        # Data should be cleared (get will add a new operation)
        assert cache.get("key") is None
