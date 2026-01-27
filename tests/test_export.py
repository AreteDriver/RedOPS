"""Tests for the export utilities module."""

import json
import tempfile
from pathlib import Path
from redops.core.context import Context
from redops.modules.reporting.export import (
    export_json,
    export_csv,
    export_all,
    export_stix,
    export_from_template,
    export_executive_brief,
    export_technical_summary,
    create_stix_attack_pattern,
    create_stix_vulnerability,
    create_stix_indicator,
    STIX_ATTACK_PATTERN_TEMPLATE,
    STIX_INDICATOR_TEMPLATE,
    STIX_VULNERABILITY_TEMPLATE,
)


class TestTemplates:
    """Tests for STIX templates."""

    def test_attack_pattern_template(self):
        """Test attack pattern template structure."""
        assert STIX_ATTACK_PATTERN_TEMPLATE["type"] == "attack-pattern"
        assert STIX_ATTACK_PATTERN_TEMPLATE["spec_version"] == "2.1"

    def test_indicator_template(self):
        """Test indicator template structure."""
        assert STIX_INDICATOR_TEMPLATE["type"] == "indicator"
        assert STIX_INDICATOR_TEMPLATE["pattern_type"] == "stix"

    def test_vulnerability_template(self):
        """Test vulnerability template structure."""
        assert STIX_VULNERABILITY_TEMPLATE["type"] == "vulnerability"


class TestExportJson:
    """Tests for export_json function."""

    def test_basic_export(self):
        """Test basic JSON export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("test_data", {"key": "value"})

            result = export_json(ctx, params={"output_dir": tmpdir})

            assert "json_export_path" in result.data
            assert Path(result.data["json_export_path"]).exists()

    def test_export_content(self):
        """Test exported JSON content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("risks", [{"level": "high"}])

            result = export_json(ctx, params={"output_dir": tmpdir})

            with open(result.data["json_export_path"]) as f:
                data = json.load(f)

            assert "target" in data
            assert data["target"] == "test.com"

    def test_default_params(self):
        """Test export with default params."""
        ctx = Context(target="test.com")
        result = export_json(ctx, params=None)
        assert "json_export_path" in result.data
        # Cleanup
        Path(result.data["json_export_path"]).unlink(missing_ok=True)


class TestExportCsv:
    """Tests for export_csv function."""

    def test_export_dict_list(self):
        """Test exporting list of dicts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            ctx.add(
                "risks",
                [
                    {"level": "high", "title": "Risk 1"},
                    {"level": "medium", "title": "Risk 2"},
                ],
            )

            result = export_csv(ctx, params={"output_dir": tmpdir})

            assert "risks_csv_path" in result.data
            with open(result.data["risks_csv_path"]) as f:
                content = f.read()
            assert "level" in content
            assert "Risk 1" in content

    def test_export_simple_list(self):
        """Test exporting list of simple values (non-dict)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            ctx.add("items", ["item1", "item2", "item3"])

            result = export_csv(ctx, params={"output_dir": tmpdir, "data_key": "items"})

            assert "items_csv_path" in result.data
            with open(result.data["items_csv_path"]) as f:
                content = f.read()
            assert "items" in content
            assert "item1" in content

    def test_empty_data(self):
        """Test export with no data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()

            result = export_csv(ctx, params={"output_dir": tmpdir})

            # Should log warning, not create file
            warnings = result.get_logs(level="WARNING")
            assert any("No data found" in log["message"] for log in warnings)

    def test_custom_data_key(self):
        """Test export with custom data key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context()
            ctx.add("custom_data", [{"a": 1}, {"a": 2}])

            result = export_csv(
                ctx, params={"output_dir": tmpdir, "data_key": "custom_data"}
            )

            assert "custom_data_csv_path" in result.data


class TestExportAll:
    """Tests for export_all function."""

    def test_exports_json(self):
        """Test that JSON is always exported."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")

            result = export_all(ctx, params={"output_dir": tmpdir})

            assert "json_export_path" in result.data

    def test_exports_csv_when_risks(self):
        """Test CSV export when risks present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("risks", [{"level": "high", "title": "Test"}])

            result = export_all(ctx, params={"output_dir": tmpdir})

            assert "risks_csv_path" in result.data

    def test_exports_stix_when_mitre(self):
        """Test STIX export when MITRE data present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("mitre_techniques_used", ["T1059"])

            result = export_all(ctx, params={"output_dir": tmpdir})

            assert "stix_export_path" in result.data

    def test_exports_stix_when_mapping(self):
        """Test STIX export when mitre_mapping present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("mitre_mapping", {"T1059": {"name": "Test"}})

            result = export_all(ctx, params={"output_dir": tmpdir})

            assert "stix_export_path" in result.data


class TestExportStix:
    """Tests for export_stix function."""

    def test_basic_export(self):
        """Test basic STIX export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")

            result = export_stix(ctx, params={"output_dir": tmpdir})

            assert "stix_export_path" in result.data
            assert "stix_object_count" in result.data

    def test_with_mitre_mapping(self):
        """Test STIX with MITRE mapping."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add(
                "mitre_mapping",
                {
                    "T1059": {"name": "Command Interpreter", "tactic": "Execution"},
                },
            )

            result = export_stix(ctx, params={"output_dir": tmpdir})

            with open(result.data["stix_export_path"]) as f:
                bundle = json.load(f)

            # Should have identity + attack pattern
            assert len(bundle["objects"]) >= 2

    def test_with_risks(self):
        """Test STIX with risks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("risks", [{"title": "SQL Injection", "level": "critical"}])

            result = export_stix(ctx, params={"output_dir": tmpdir})

            with open(result.data["stix_export_path"]) as f:
                bundle = json.load(f)

            # Should have identity + vulnerability
            vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
            assert len(vulns) >= 1

    def test_with_findings(self):
        """Test STIX with findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add(
                "finding_1", {"title": "Exposed API", "description": "Test finding"}
            )

            result = export_stix(ctx, params={"output_dir": tmpdir})

            with open(result.data["stix_export_path"]) as f:
                bundle = json.load(f)

            # Should have identity + indicator
            indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
            assert len(indicators) >= 1


class TestCreateStixAttackPattern:
    """Tests for create_stix_attack_pattern function."""

    def test_with_dict_info(self):
        """Test with dict technique info."""
        result = create_stix_attack_pattern(
            "T1059",
            {
                "name": "Command Interpreter",
                "description": "Executes commands",
                "tactic": "Execution",
            },
            "2024-01-01T00:00:00.000Z",
        )

        assert result["type"] == "attack-pattern"
        assert result["name"] == "Command Interpreter"
        assert "Execution" in result["description"]
        assert len(result["kill_chain_phases"]) == 1

    def test_with_non_dict_info(self):
        """Test with non-dict technique info (just string)."""
        result = create_stix_attack_pattern(
            "T1059", "Just a string", "2024-01-01T00:00:00.000Z"
        )

        assert result["type"] == "attack-pattern"
        assert result["name"] == "T1059"  # Falls back to technique_id
        assert result["kill_chain_phases"] == []

    def test_external_references(self):
        """Test external references are correct."""
        result = create_stix_attack_pattern(
            "T1059.001", {"name": "PowerShell"}, "2024-01-01T00:00:00.000Z"
        )

        refs = result["external_references"]
        assert len(refs) == 1
        assert refs[0]["external_id"] == "T1059.001"
        assert "T1059/001" in refs[0]["url"]


class TestCreateStixVulnerability:
    """Tests for create_stix_vulnerability function."""

    def test_basic_vulnerability(self):
        """Test basic vulnerability creation."""
        result = create_stix_vulnerability(
            {
                "title": "SQL Injection",
                "description": "Input validation flaw",
                "level": "critical",
            },
            "2024-01-01T00:00:00.000Z",
        )

        assert result["type"] == "vulnerability"
        assert result["name"] == "SQL Injection"
        assert "CRITICAL" in result["description"]

    def test_with_cve(self):
        """Test vulnerability with CVE."""
        result = create_stix_vulnerability(
            {
                "title": "Log4Shell",
                "description": "RCE",
                "level": "critical",
                "cve": "CVE-2021-44228",
            },
            "2024-01-01T00:00:00.000Z",
        )

        assert len(result["external_references"]) == 1
        assert result["external_references"][0]["external_id"] == "CVE-2021-44228"


class TestCreateStixIndicator:
    """Tests for create_stix_indicator function."""

    def test_basic_indicator(self):
        """Test basic indicator creation."""
        result = create_stix_indicator(
            {"title": "Exposed API Key", "description": "Found in config file"},
            "2024-01-01T00:00:00.000Z",
        )

        assert result["type"] == "indicator"
        assert result["name"] == "Exposed API Key"
        assert "anomalous-activity" in result["indicator_types"]

    def test_empty_title_returns_none(self):
        """Test that empty title returns None."""
        result = create_stix_indicator(
            {"description": "No title"}, "2024-01-01T00:00:00.000Z"
        )

        assert result is None


class TestExportFromTemplate:
    """Tests for export_from_template function."""

    def test_basic_template(self):
        """Test basic template export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            template = "Target: {target}\nDate: {date}"

            result = export_from_template(ctx, template, params={"output_dir": tmpdir})

            assert "template_export_path" in result.data
            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "test.com" in content

    def test_with_risks(self):
        """Test template with risk variables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add(
                "risks",
                [
                    {"level": "critical"},
                    {"level": "high"},
                    {"level": "medium"},
                ],
            )
            template = "Critical: {critical_risks}, High: {high_risks}"

            result = export_from_template(ctx, template, params={"output_dir": tmpdir})

            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "Critical: 1" in content
            assert "High: 1" in content

    def test_with_simple_data_types(self):
        """Test template with simple data types (str, int, float, bool)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("custom_string", "hello")
            ctx.add("custom_int", 42)
            ctx.add("custom_float", 3.14)
            ctx.add("custom_bool", True)
            template = "String: {custom_string}, Int: {custom_int}, Float: {custom_float}, Bool: {custom_bool}"

            result = export_from_template(ctx, template, params={"output_dir": tmpdir})

            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "String: hello" in content
            assert "Int: 42" in content
            assert "Float: 3.14" in content
            assert "Bool: True" in content

    def test_with_list_data(self):
        """Test template with list context data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("items", ["a", "b", "c"])
            template = "Count: {items_count}, List: {items_list}"

            result = export_from_template(ctx, template, params={"output_dir": tmpdir})

            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "Count: 3" in content
            assert "a, b, c" in content

    def test_with_dict_data(self):
        """Test template with dict context data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("mapping", {"key1": "val1", "key2": "val2"})
            template = "Mapping count: {mapping_count}"

            result = export_from_template(ctx, template, params={"output_dir": tmpdir})

            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "Mapping count: 2" in content

    def test_missing_variable(self):
        """Test handling missing template variable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            template = "Target: {target}, Missing: {nonexistent}"

            result = export_from_template(ctx, template, params={"output_dir": tmpdir})

            # Should log warning
            warnings = result.get_logs(level="WARNING")
            assert any("not found" in log["message"] for log in warnings)

    def test_custom_output_name(self):
        """Test custom output filename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            template = "Test"

            result = export_from_template(
                ctx,
                template,
                params={"output_dir": tmpdir, "output_name": "custom.txt"},
            )

            assert "custom.txt" in result.data["template_export_path"]


class TestExportExecutiveBrief:
    """Tests for export_executive_brief function."""

    def test_basic_export(self):
        """Test basic executive brief export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("risks", [{"level": "critical"}])

            result = export_executive_brief(ctx, params={"output_dir": tmpdir})

            assert "template_export_path" in result.data
            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "SECURITY ASSESSMENT BRIEF" in content
            assert "test.com" in content


class TestExportTechnicalSummary:
    """Tests for export_technical_summary function."""

    def test_basic_export(self):
        """Test basic technical summary export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="test.com")
            ctx.add("mitre_techniques_used", ["T1059", "T1071"])

            result = export_technical_summary(ctx, params={"output_dir": tmpdir})

            assert "template_export_path" in result.data
            with open(result.data["template_export_path"]) as f:
                content = f.read()
            assert "Technical Security Assessment" in content
            assert "T1059" in content


class TestIntegration:
    """Integration tests for export module."""

    def test_full_export_workflow(self):
        """Test complete export workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="integration-test.com")
            ctx.add(
                "risks",
                [
                    {
                        "level": "critical",
                        "title": "Critical Issue",
                        "cve": "CVE-2024-0001",
                    },
                    {"level": "high", "title": "High Issue"},
                ],
            )
            ctx.add(
                "mitre_mapping",
                {
                    "T1059": {"name": "Command Interpreter", "tactic": "Execution"},
                },
            )
            ctx.add(
                "finding_test",
                {"title": "Test Finding", "description": "Found something"},
            )
            ctx.add("attack_paths", [{"name": "Path 1"}])

            result = export_all(ctx, params={"output_dir": tmpdir})

            # Verify all exports created
            assert "json_export_path" in result.data
            assert "risks_csv_path" in result.data
            assert "stix_export_path" in result.data

            # Verify STIX bundle content
            with open(result.data["stix_export_path"]) as f:
                bundle = json.load(f)

            assert bundle["type"] == "bundle"
            object_types = [o["type"] for o in bundle["objects"]]
            assert "identity" in object_types
            assert "attack-pattern" in object_types
            assert "vulnerability" in object_types
            assert "indicator" in object_types
