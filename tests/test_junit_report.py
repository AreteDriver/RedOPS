"""Tests for the JUnit XML report module."""

import pytest
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET
from redops.core.context import Context
from redops.modules.reporting.junit_report import (
    export_junit,
    collect_findings,
    create_junit_document,
    group_by_module,
    create_testsuite,
    create_testcase,
    build_failure_text,
    build_system_out,
    normalize_severity,
    calculate_stats,
    get_junit_summary,
)


class TestExportJunit:
    """Tests for export_junit function."""

    def test_export_empty_context(self):
        """Test exporting empty context."""
        ctx = Context(target="example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_junit(ctx, {"output_dir": tmpdir})

            assert "junit_export_path" in result.data
            output_path = Path(result.data["junit_export_path"])
            assert output_path.exists()

    def test_export_with_findings(self):
        """Test exporting context with findings."""
        ctx = Context(target="example.com")
        ctx.add("finding_test_0", {
            "module": "test.module",
            "title": "Critical Finding",
            "description": "A critical security issue",
            "severity": "critical",
            "data": {},
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_junit(ctx, {"output_dir": tmpdir})

            assert result.data["junit_tests_count"] == 1
            assert result.data["junit_failures_count"] == 1

            # Verify XML is valid
            tree = ET.parse(result.data["junit_export_path"])
            root = tree.getroot()
            assert root.tag == "testsuites"

    def test_custom_suite_name(self):
        """Test custom test suite name."""
        ctx = Context(target="example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_junit(ctx, {
                "output_dir": tmpdir,
                "suite_name": "Custom Suite",
            })

            tree = ET.parse(result.data["junit_export_path"])
            root = tree.getroot()
            assert root.get("name") == "Custom Suite"


class TestCollectFindings:
    """Tests for collect_findings function."""

    def test_collect_finding_prefix(self):
        """Test collecting findings with finding_ prefix."""
        ctx = Context()
        ctx.add("finding_test_0", {"title": "Finding 1"})
        ctx.add("finding_test_1", {"title": "Finding 2"})

        findings = collect_findings(ctx)

        assert len(findings) == 2

    def test_collect_risks(self):
        """Test collecting from risks list."""
        ctx = Context()
        ctx.add("risks", [
            {"title": "Risk 1", "level": "high"},
        ])

        findings = collect_findings(ctx)

        assert len(findings) == 1


class TestCreateJunitDocument:
    """Tests for create_junit_document function."""

    def test_empty_findings(self):
        """Test document with no findings."""
        ctx = Context(target="example.com")

        xml_str = create_junit_document(ctx, [], "Test Suite")

        # Should have one passing test
        assert "No security issues found" in xml_str

    def test_with_findings(self):
        """Test document with findings."""
        ctx = Context(target="example.com")
        findings = [
            {"module": "test", "title": "Finding", "severity": "high"},
        ]

        xml_str = create_junit_document(ctx, findings, "Test Suite")

        # Should have a failure
        assert "failure" in xml_str.lower()


class TestGroupByModule:
    """Tests for group_by_module function."""

    def test_grouping(self):
        """Test findings are grouped by module."""
        findings = [
            {"module": "module_a", "title": "Finding 1"},
            {"module": "module_a", "title": "Finding 2"},
            {"module": "module_b", "title": "Finding 3"},
        ]

        groups = group_by_module(findings)

        assert len(groups) == 2
        assert len(groups["module_a"]) == 2
        assert len(groups["module_b"]) == 1


class TestCreateTestsuite:
    """Tests for create_testsuite function."""

    def test_testsuite_attributes(self):
        """Test testsuite has required attributes."""
        findings = [
            {"title": "Finding 1", "severity": "high"},
            {"title": "Finding 2", "severity": "low"},
        ]

        testsuite = create_testsuite(
            "test.module",
            findings,
            "example.com",
            fail_on_critical=True,
            fail_on_high=True,
            fail_on_medium=False,
        )

        assert testsuite.get("tests") == "2"
        assert testsuite.get("failures") == "1"  # Only high fails


class TestCreateTestcase:
    """Tests for create_testcase function."""

    def test_critical_failure(self):
        """Test critical finding creates failure."""
        finding = {"title": "Critical Issue", "severity": "critical"}

        testcase = create_testcase(
            finding, "module",
            fail_on_critical=True,
            fail_on_high=True,
            fail_on_medium=False,
        )

        assert testcase.find("failure") is not None

    def test_high_failure(self):
        """Test high finding creates failure when enabled."""
        finding = {"title": "High Issue", "severity": "high"}

        testcase = create_testcase(
            finding, "module",
            fail_on_critical=True,
            fail_on_high=True,
            fail_on_medium=False,
        )

        assert testcase.find("failure") is not None

    def test_medium_no_failure_by_default(self):
        """Test medium finding doesn't create failure by default."""
        finding = {"title": "Medium Issue", "severity": "medium"}

        testcase = create_testcase(
            finding, "module",
            fail_on_critical=True,
            fail_on_high=True,
            fail_on_medium=False,
        )

        assert testcase.find("failure") is None

    def test_low_skipped(self):
        """Test low finding creates skipped."""
        finding = {"title": "Low Issue", "severity": "low"}

        testcase = create_testcase(
            finding, "module",
            fail_on_critical=True,
            fail_on_high=True,
            fail_on_medium=False,
        )

        assert testcase.find("skipped") is not None


class TestBuildFailureText:
    """Tests for build_failure_text function."""

    def test_includes_title(self):
        """Test failure text includes title."""
        finding = {"title": "Test Finding", "severity": "high"}

        text = build_failure_text(finding)

        assert "Test Finding" in text

    def test_includes_data(self):
        """Test failure text includes data."""
        finding = {
            "title": "Finding",
            "severity": "high",
            "data": {"key": "value"},
        }

        text = build_failure_text(finding)

        assert "key: value" in text


class TestBuildSystemOut:
    """Tests for build_system_out function."""

    def test_includes_description(self):
        """Test system-out includes description."""
        finding = {"description": "This is a description"}

        text = build_system_out(finding)

        assert "This is a description" in text

    def test_handles_lists(self):
        """Test system-out handles list data."""
        finding = {
            "data": {"items": ["a", "b", "c"]},
        }

        text = build_system_out(finding)

        assert "items:" in text


class TestNormalizeSeverity:
    """Tests for normalize_severity function."""

    def test_string_severity(self):
        """Test string severity normalization."""
        assert normalize_severity("HIGH") == "high"
        assert normalize_severity("Critical") == "critical"

    def test_enum_severity(self):
        """Test enum-like severity normalization."""
        class MockSeverity:
            name = "MEDIUM"

        assert normalize_severity(MockSeverity()) == "medium"


class TestCalculateStats:
    """Tests for calculate_stats function."""

    def test_counts_failures(self):
        """Test counting failures."""
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ]

        stats = calculate_stats(
            findings,
            fail_on_critical=True,
            fail_on_high=True,
            fail_on_medium=False,
        )

        assert stats["tests"] == 4
        assert stats["failures"] == 2  # critical + high
        assert stats["skipped"] == 1  # low

    def test_empty_findings(self):
        """Test with empty findings."""
        stats = calculate_stats([], True, True, False)

        assert stats["tests"] == 1  # Minimum 1


class TestGetJunitSummary:
    """Tests for get_junit_summary function."""

    def test_with_data(self):
        """Test summary with data."""
        ctx = Context()
        ctx.add("junit_export_path", "/path/to/file.xml")
        ctx.add("junit_tests_count", 10)
        ctx.add("junit_failures_count", 2)
        ctx.add("junit_errors_count", 0)
        ctx.add("junit_skipped_count", 1)

        summary = get_junit_summary(ctx)

        assert summary["export_path"] == "/path/to/file.xml"
        assert summary["tests"] == 10
        assert summary["failures"] == 2

    def test_without_data(self):
        """Test summary without data."""
        ctx = Context()

        summary = get_junit_summary(ctx)

        assert summary["export_path"] == ""
        assert summary["tests"] == 0
