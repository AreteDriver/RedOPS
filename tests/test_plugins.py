"""Tests for plugin system."""

import tempfile
from pathlib import Path
from typing import Set

import pytest

from redops.plugins.scanner import (
    Finding,
    ScannerCapability,
    ScannerPlugin,
    ScannerResult,
    Severity,
    CompositeScanner,
)
from redops.plugins.manifest import (
    PluginManifest,
    PluginDependency,
    ManifestError,
    load_manifest,
    save_manifest,
    validate_manifest,
)


class TestFinding:
    """Test Finding class."""

    def test_create_finding(self):
        """Create a finding."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            target="https://example.com",
            description="Test description",
        )

        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.target == "https://example.com"
        assert finding.id is not None

    def test_finding_to_dict(self):
        """Convert finding to dict."""
        finding = Finding(
            title="XSS Vulnerability",
            severity=Severity.CRITICAL,
            target="https://example.com/page",
            cwe_id="CWE-79",
        )

        data = finding.to_dict()

        assert data["title"] == "XSS Vulnerability"
        assert data["severity"] == "critical"
        assert data["cwe_id"] == "CWE-79"

    def test_finding_from_dict(self):
        """Create finding from dict."""
        data = {
            "id": "test-123",
            "title": "SQL Injection",
            "severity": "high",
            "target": "https://example.com/api",
            "cwe_id": "CWE-89",
        }

        finding = Finding.from_dict(data)

        assert finding.id == "test-123"
        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.HIGH


class TestScannerResult:
    """Test ScannerResult class."""

    def test_create_result(self):
        """Create scanner result."""
        result = ScannerResult(
            scanner_name="test-scanner",
            target="https://example.com",
        )

        assert result.scanner_name == "test-scanner"
        assert result.success is True
        assert len(result.findings) == 0

    def test_result_with_findings(self):
        """Result with multiple findings."""
        findings = [
            Finding(title="Finding 1", severity=Severity.LOW, target="test"),
            Finding(title="Finding 2", severity=Severity.HIGH, target="test"),
            Finding(title="Finding 3", severity=Severity.HIGH, target="test"),
        ]

        result = ScannerResult(
            scanner_name="test-scanner",
            target="https://example.com",
            findings=findings,
        )

        counts = result.finding_counts
        assert counts["low"] == 1
        assert counts["high"] == 2


class MockScanner(ScannerPlugin):
    """Mock scanner for testing."""

    @classmethod
    def get_name(cls) -> str:
        return "mock-scanner"

    @classmethod
    def get_version(cls) -> str:
        return "1.0.0"

    @classmethod
    def get_description(cls) -> str:
        return "Mock scanner for testing"

    @classmethod
    def get_capabilities(cls) -> Set[ScannerCapability]:
        return {ScannerCapability.WEB_SCAN}

    def scan(self, target: str, config=None) -> ScannerResult:
        """Return mock results."""
        finding = self._create_finding(
            title="Mock Finding",
            severity=Severity.MEDIUM,
            target=target,
            description="This is a mock finding",
        )
        return self._create_result(target, findings=[finding])


class TestScannerPlugin:
    """Test ScannerPlugin base class."""

    def test_mock_scanner(self):
        """Test mock scanner."""
        scanner = MockScanner()
        result = scanner.scan("https://example.com")

        assert result.scanner_name == "mock-scanner"
        assert result.target == "https://example.com"
        assert len(result.findings) == 1
        assert result.findings[0].title == "Mock Finding"

    def test_scanner_metadata(self):
        """Test scanner metadata."""
        assert MockScanner.get_name() == "mock-scanner"
        assert MockScanner.get_version() == "1.0.0"
        assert ScannerCapability.WEB_SCAN in MockScanner.get_capabilities()


class TestCompositeScanner:
    """Test CompositeScanner."""

    def test_composite_scan(self):
        """Run composite scan."""
        composite = CompositeScanner()
        composite.add_scanner(MockScanner())

        results = composite.scan("https://example.com")

        assert len(results) == 1
        assert results[0].scanner_name == "mock-scanner"

    def test_get_all_findings(self):
        """Get findings from all scanners."""
        composite = CompositeScanner()
        composite.add_scanner(MockScanner())

        results = composite.scan("https://example.com")
        findings = composite.get_all_findings(results)

        assert len(findings) == 1


class TestPluginManifest:
    """Test plugin manifest."""

    def test_create_manifest(self):
        """Create a manifest."""
        manifest = PluginManifest(
            name="test-plugin",
            version="1.0.0",
            entry_point="test_plugin:TestPlugin",
            description="Test plugin",
        )

        assert manifest.name == "test-plugin"
        assert manifest.version == "1.0.0"
        assert manifest.module_name == "test_plugin"
        assert manifest.class_name == "TestPlugin"

    def test_manifest_validation(self):
        """Validate manifest."""
        manifest = PluginManifest(
            name="valid-plugin",
            version="1.0.0",
            entry_point="plugin:Plugin",
        )

        errors = manifest.validate()
        assert len(errors) == 0

    def test_invalid_manifest(self):
        """Invalid manifest fails validation."""
        manifest = PluginManifest(
            name="",  # Invalid: empty
            version="invalid",  # Invalid: not semver
            entry_point="noclass",  # Invalid: no colon
        )

        errors = manifest.validate()
        assert len(errors) > 0

    def test_manifest_to_dict(self):
        """Serialize manifest."""
        manifest = PluginManifest(
            name="test-plugin",
            version="1.0.0",
            entry_point="test:Test",
            description="A test plugin",
            author="Test Author",
        )

        data = manifest.to_dict()

        assert data["name"] == "test-plugin"
        assert data["version"] == "1.0.0"
        assert data["author"] == "Test Author"

    def test_manifest_from_dict(self):
        """Deserialize manifest."""
        data = {
            "name": "my-plugin",
            "version": "2.0.0",
            "entry_point": "my_plugin:MyPlugin",
            "description": "My plugin",
        }

        manifest = PluginManifest.from_dict(data)

        assert manifest.name == "my-plugin"
        assert manifest.version == "2.0.0"


class TestPluginDependency:
    """Test plugin dependency."""

    def test_version_matching_wildcard(self):
        """Wildcard matches any version."""
        dep = PluginDependency(name="test", version="*")
        assert dep.matches_version("1.0.0")
        assert dep.matches_version("2.5.3")

    def test_version_matching_exact(self):
        """Exact version matching."""
        dep = PluginDependency(name="test", version="1.0.0")
        assert dep.matches_version("1.0.0")
        assert not dep.matches_version("1.0.1")

    def test_version_matching_gte(self):
        """Greater than or equal matching."""
        dep = PluginDependency(name="test", version=">=1.0.0")
        assert dep.matches_version("1.0.0")
        assert dep.matches_version("2.0.0")
        assert not dep.matches_version("0.9.0")

    def test_version_matching_caret(self):
        """Caret version matching (same major)."""
        dep = PluginDependency(name="test", version="^1.0.0")
        assert dep.matches_version("1.0.0")
        assert dep.matches_version("1.9.9")
        assert not dep.matches_version("2.0.0")


class TestManifestIO:
    """Test manifest file operations."""

    def test_save_and_load_manifest(self):
        """Save and load manifest."""
        manifest = PluginManifest(
            name="io-test",
            version="1.0.0",
            entry_point="io_test:IOTest",
            description="IO test plugin",
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "manifest.json"
            save_manifest(manifest, path)

            loaded = load_manifest(path)

            assert loaded.name == manifest.name
            assert loaded.version == manifest.version

    def test_load_missing_manifest(self):
        """Loading missing manifest raises error."""
        with pytest.raises(ManifestError):
            load_manifest("/nonexistent/manifest.json")

    def test_validate_manifest_dict(self):
        """Validate manifest dict."""
        valid = {
            "name": "test-plugin",
            "version": "1.0.0",
            "entry_point": "test:Test",
        }
        errors = validate_manifest(valid)
        assert len(errors) == 0

        invalid = {
            "name": "",
            "version": "bad",
        }
        errors = validate_manifest(invalid)
        assert len(errors) > 0
