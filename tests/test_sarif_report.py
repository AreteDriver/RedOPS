"""Tests for the SARIF report module."""

import pytest
import json
import tempfile
from pathlib import Path
from redops.core.context import Context
from redops.modules.reporting.sarif_report import (
    export_sarif,
    create_sarif_document,
    collect_findings,
    build_rules,
    build_results,
    create_rule_id,
    sanitize_rule_name,
    severity_to_sarif_level,
    severity_to_score,
    create_fingerprint,
    get_sarif_summary,
)


class TestExportSarif:
    """Tests for export_sarif function."""

    def test_export_empty_context(self):
        """Test exporting empty context."""
        ctx = Context(target="example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_sarif(ctx, {"output_dir": tmpdir})

            assert "sarif_export_path" in result.data
            output_path = Path(result.data["sarif_export_path"])
            assert output_path.exists()

    def test_export_with_findings(self):
        """Test exporting context with findings."""
        ctx = Context(target="example.com")
        ctx.add("finding_test_0", {
            "module": "test.module",
            "title": "Test Finding",
            "description": "A test finding",
            "severity": "high",
            "data": {"url": "http://example.com"},
        })

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_sarif(ctx, {"output_dir": tmpdir})

            assert result.data["sarif_results_count"] == 1
            assert result.data["sarif_rules_count"] == 1

            # Verify file content
            with open(result.data["sarif_export_path"]) as f:
                sarif = json.load(f)

            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"]) == 1
            assert len(sarif["runs"][0]["results"]) == 1

    def test_custom_tool_info(self):
        """Test custom tool name and version."""
        ctx = Context(target="example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_sarif(ctx, {
                "output_dir": tmpdir,
                "tool_name": "CustomTool",
                "tool_version": "2.0.0",
            })

            with open(result.data["sarif_export_path"]) as f:
                sarif = json.load(f)

            driver = sarif["runs"][0]["tool"]["driver"]
            assert driver["name"] == "CustomTool"
            assert driver["version"] == "2.0.0"


class TestCreateSarifDocument:
    """Tests for create_sarif_document function."""

    def test_document_structure(self):
        """Test basic document structure."""
        ctx = Context(target="example.com")

        doc = create_sarif_document(ctx)

        assert "$schema" in doc
        assert doc["version"] == "2.1.0"
        assert "runs" in doc
        assert len(doc["runs"]) == 1

    def test_includes_artifacts(self):
        """Test that target is included as artifact."""
        ctx = Context(target="https://example.com")

        doc = create_sarif_document(ctx)

        assert "artifacts" in doc["runs"][0]
        assert doc["runs"][0]["artifacts"][0]["location"]["uri"] == "https://example.com"


class TestCollectFindings:
    """Tests for collect_findings function."""

    def test_collect_finding_prefix(self):
        """Test collecting findings with finding_ prefix."""
        ctx = Context()
        ctx.add("finding_test_0", {"title": "Finding 1"})
        ctx.add("finding_test_1", {"title": "Finding 2"})
        ctx.add("other_data", "not a finding")

        findings = collect_findings(ctx)

        assert len(findings) == 2

    def test_collect_risks(self):
        """Test collecting from risks list."""
        ctx = Context()
        ctx.add("risks", [
            {"title": "Risk 1", "level": "high"},
            {"title": "Risk 2", "level": "medium"},
        ])

        findings = collect_findings(ctx)

        assert len(findings) == 2


class TestBuildRules:
    """Tests for build_rules function."""

    def test_unique_rules(self):
        """Test that duplicate findings create one rule."""
        findings = [
            {"module": "test", "title": "Finding A", "severity": "high"},
            {"module": "test", "title": "Finding A", "severity": "high"},
        ]

        rules = build_rules(findings)

        assert len(rules) == 1

    def test_different_rules(self):
        """Test that different findings create different rules."""
        findings = [
            {"module": "test", "title": "Finding A", "severity": "high"},
            {"module": "test", "title": "Finding B", "severity": "medium"},
        ]

        rules = build_rules(findings)

        assert len(rules) == 2


class TestBuildResults:
    """Tests for build_results function."""

    def test_results_match_findings(self):
        """Test that results match findings count."""
        findings = [
            {"module": "test", "title": "Finding A", "severity": "high"},
            {"module": "test", "title": "Finding B", "severity": "medium"},
        ]
        rules = build_rules(findings)

        results = build_results(findings, rules)

        assert len(results) == 2

    def test_results_have_fingerprints(self):
        """Test that results have fingerprints."""
        findings = [{"module": "test", "title": "Finding", "severity": "high"}]
        rules = build_rules(findings)

        results = build_results(findings, rules)

        assert "fingerprints" in results[0]
        assert "primary" in results[0]["fingerprints"]


class TestCreateRuleId:
    """Tests for create_rule_id function."""

    def test_deterministic_id(self):
        """Test that same input creates same ID."""
        id1 = create_rule_id("module.test", "Title")
        id2 = create_rule_id("module.test", "Title")

        assert id1 == id2

    def test_different_inputs(self):
        """Test that different inputs create different IDs."""
        id1 = create_rule_id("module.test", "Title A")
        id2 = create_rule_id("module.test", "Title B")

        assert id1 != id2


class TestSanitizeRuleName:
    """Tests for sanitize_rule_name function."""

    def test_removes_special_chars(self):
        """Test that special characters are removed."""
        result = sanitize_rule_name("Test <script>alert(1)</script>")

        assert "<" not in result
        assert ">" not in result

    def test_limits_length(self):
        """Test that name is limited to 100 chars."""
        long_name = "A" * 200
        result = sanitize_rule_name(long_name)

        assert len(result) <= 100


class TestSeverityToSarifLevel:
    """Tests for severity_to_sarif_level function."""

    def test_critical_to_error(self):
        """Test critical maps to error."""
        assert severity_to_sarif_level("critical") == "error"

    def test_high_to_error(self):
        """Test high maps to error."""
        assert severity_to_sarif_level("high") == "error"

    def test_medium_to_warning(self):
        """Test medium maps to warning."""
        assert severity_to_sarif_level("medium") == "warning"

    def test_low_to_note(self):
        """Test low maps to note."""
        assert severity_to_sarif_level("low") == "note"

    def test_enum_value(self):
        """Test handling enum-like severity."""
        class MockSeverity:
            name = "HIGH"

        assert severity_to_sarif_level(MockSeverity()) == "error"


class TestSeverityToScore:
    """Tests for severity_to_score function."""

    def test_critical_score(self):
        """Test critical severity score."""
        assert severity_to_score("critical") == "9.0"

    def test_high_score(self):
        """Test high severity score."""
        assert severity_to_score("high") == "7.0"

    def test_medium_score(self):
        """Test medium severity score."""
        assert severity_to_score("medium") == "5.0"


class TestCreateFingerprint:
    """Tests for create_fingerprint function."""

    def test_deterministic(self):
        """Test fingerprint is deterministic."""
        finding = {"module": "test", "title": "Title", "description": "Desc"}

        fp1 = create_fingerprint(finding)
        fp2 = create_fingerprint(finding)

        assert fp1 == fp2

    def test_unique_for_different_findings(self):
        """Test different findings have different fingerprints."""
        finding1 = {"module": "test", "title": "Title 1", "description": "Desc"}
        finding2 = {"module": "test", "title": "Title 2", "description": "Desc"}

        fp1 = create_fingerprint(finding1)
        fp2 = create_fingerprint(finding2)

        assert fp1 != fp2


class TestGetSarifSummary:
    """Tests for get_sarif_summary function."""

    def test_with_data(self):
        """Test summary with data."""
        ctx = Context()
        ctx.add("sarif_export_path", "/path/to/file.sarif")
        ctx.add("sarif_results_count", 10)
        ctx.add("sarif_rules_count", 5)

        summary = get_sarif_summary(ctx)

        assert summary["export_path"] == "/path/to/file.sarif"
        assert summary["results_count"] == 10
        assert summary["rules_count"] == 5

    def test_without_data(self):
        """Test summary without data."""
        ctx = Context()

        summary = get_sarif_summary(ctx)

        assert summary["export_path"] == ""
        assert summary["results_count"] == 0
