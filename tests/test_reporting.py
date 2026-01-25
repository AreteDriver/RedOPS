"""Tests for the Reporting modules."""

import json
from pathlib import Path
from redops.core.context import Context
from redops.modules.reporting.markdown_report import (
    generate_exec_summary,
    generate_technical_report,
    generate_full_report,
    build_executive_summary,
    build_mitre_matrix_markdown,
    build_risk_heatmap_markdown,
    build_attack_paths_markdown,
    build_scenarios_markdown,
    build_likelihood_impact_matrix,
    group_findings_by_category,
    calculate_overall_risk_level,
    RISK_INDICATORS,
    MITRE_TACTICS_ORDER,
)
from redops.modules.reporting.html_report import (
    generate_html,
    build_stats_overview,
    build_risk_section,
    build_mitre_matrix_html,
    build_attack_paths_html,
    build_scenarios_html,
    RISK_COLORS,
)
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
    EXECUTIVE_BRIEF_TEMPLATE,
    TECHNICAL_SUMMARY_TEMPLATE,
)


# ============================================================================
# Markdown Report Tests
# ============================================================================


class TestBuildExecutiveSummary:
    """Tests for build_executive_summary function."""

    def test_basic_summary(self):
        """Test basic summary generation."""
        ctx = Context(target="example.com")
        summary = build_executive_summary(ctx)

        assert isinstance(summary, str)
        assert "example.com" in summary
        assert "Assessment Overview" in summary

    def test_summary_with_risks(self):
        """Test summary with risk data."""
        ctx = Context(target="test.io")
        ctx.add(
            "risks",
            [
                {"title": "Critical Issue", "level": "critical"},
                {"title": "High Issue", "level": "high"},
                {"title": "Medium Issue", "level": "medium"},
            ],
        )

        summary = build_executive_summary(ctx)

        assert "Critical: 1" in summary
        assert "High: 1" in summary
        assert "Medium: 1" in summary

    def test_summary_with_attack_paths(self):
        """Test summary with attack paths."""
        ctx = Context(target="test.io")
        ctx.add(
            "attack_paths",
            [
                {"name": "Path 1", "likelihood": 4, "impact": 5},
                {"name": "Path 2", "likelihood": 3, "impact": 3},
            ],
        )

        summary = build_executive_summary(ctx)

        assert "2 potential attack path" in summary
        assert "Path 1" in summary

    def test_summary_with_mitre(self):
        """Test summary with MITRE techniques."""
        ctx = Context(target="test.io")
        ctx.add("mitre_techniques_used", ["T1595", "T1190", "T1078"])
        ctx.add(
            "mitre_summary",
            {
                "total_techniques": 3,
                "tactics_covered": 2,
                "coverage_percentage": 14.3,
            },
        )

        summary = build_executive_summary(ctx)

        assert "MITRE ATT&CK Coverage" in summary
        assert "3 technique" in summary

    def test_summary_with_scenarios(self):
        """Test summary with threat scenarios."""
        ctx = Context(target="test.io")
        ctx.add(
            "scenarios",
            [
                {"name": "Scenario 1", "risk_level": "HIGH"},
                {"name": "Scenario 2", "risk_level": "MEDIUM"},
            ],
        )

        summary = build_executive_summary(ctx)

        assert "Threat Scenarios" in summary
        assert "2 realistic attack scenario" in summary


class TestCalculateOverallRiskLevel:
    """Tests for calculate_overall_risk_level function."""

    def test_empty_risks(self):
        """Test with no risks."""
        assert calculate_overall_risk_level([]) == "low"

    def test_critical_risks(self):
        """Test with critical risks."""
        risks = [{"level": "critical"}]
        assert calculate_overall_risk_level(risks) == "critical"

    def test_multiple_high_risks(self):
        """Test with multiple high risks."""
        risks = [
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
        ]
        assert calculate_overall_risk_level(risks) == "high"

    def test_single_high_risk(self):
        """Test with single high risk."""
        risks = [{"level": "high"}]
        assert calculate_overall_risk_level(risks) == "medium"

    def test_many_medium_risks(self):
        """Test with many medium risks."""
        risks = [{"level": "medium"} for _ in range(5)]
        assert calculate_overall_risk_level(risks) == "medium"


class TestBuildMitreMatrixMarkdown:
    """Tests for build_mitre_matrix_markdown function."""

    def test_empty_matrix(self):
        """Test with no MITRE data."""
        ctx = Context(target="test.io")
        result = build_mitre_matrix_markdown(ctx)

        assert "No MITRE ATT&CK techniques" in result

    def test_matrix_with_techniques(self):
        """Test with MITRE techniques."""
        ctx = Context(target="test.io")
        ctx.add(
            "mitre_mapping",
            {
                "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
                "T1190": {
                    "name": "Exploit Public-Facing App",
                    "tactic": "Initial Access",
                },
            },
        )
        ctx.add("mitre_techniques_used", ["T1595", "T1190"])

        result = build_mitre_matrix_markdown(ctx)

        assert "ATT&CK Matrix Coverage" in result
        assert "Total Techniques" in result
        assert "Reconnaissance" in result

    def test_matrix_table_format(self):
        """Test that output is in table format."""
        ctx = Context(target="test.io")
        ctx.add(
            "mitre_mapping",
            {
                "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
            },
        )

        result = build_mitre_matrix_markdown(ctx)

        assert "| Tactic |" in result
        assert "|--------|" in result


class TestBuildRiskHeatmapMarkdown:
    """Tests for build_risk_heatmap_markdown function."""

    def test_empty_risks(self):
        """Test with no risks."""
        result = build_risk_heatmap_markdown([])
        assert "No risks identified" in result

    def test_risk_distribution(self):
        """Test risk distribution table."""
        risks = [
            {"level": "critical"},
            {"level": "high"},
            {"level": "high"},
            {"level": "medium"},
        ]
        result = build_risk_heatmap_markdown(risks)

        assert "Risk Distribution" in result
        assert "CRITICAL" in result
        assert "Total Risks" in result
        assert "4" in result

    def test_severity_indicators(self):
        """Test that severity indicators are used."""
        risks = [{"level": "critical"}]
        result = build_risk_heatmap_markdown(risks)

        assert RISK_INDICATORS["critical"] in result


class TestBuildLikelihoodImpactMatrix:
    """Tests for build_likelihood_impact_matrix function."""

    def test_no_metrics(self):
        """Test with risks lacking likelihood/impact."""
        risks = [{"title": "Test", "level": "high"}]
        result = build_likelihood_impact_matrix(risks)

        assert result == ""

    def test_with_metrics(self):
        """Test with likelihood and impact metrics."""
        risks = [
            {"likelihood": 4, "impact": 5},
            {"likelihood": 2, "impact": 3},
        ]
        result = build_likelihood_impact_matrix(risks)

        assert "Impact" in result
        assert "Likelihood" in result


class TestBuildAttackPathsMarkdown:
    """Tests for build_attack_paths_markdown function."""

    def test_empty_paths(self):
        """Test with no attack paths."""
        result = build_attack_paths_markdown([])
        assert "No attack paths identified" in result

    def test_path_visualization(self):
        """Test attack path visualization."""
        paths = [
            {
                "name": "Test Path",
                "likelihood": 4,
                "impact": 5,
                "steps": ["Entry", "Step 1", "Target"],
                "mitre_techniques": ["T1595", "T1190"],
            }
        ]
        result = build_attack_paths_markdown(paths)

        assert "Test Path" in result
        assert "CRITICAL" in result
        assert "[ENTRY]" in result
        assert "[TARGET]" in result
        assert "T1595" in result

    def test_path_sorting(self):
        """Test that paths are sorted by risk score."""
        paths = [
            {"name": "Low Risk", "likelihood": 1, "impact": 1},
            {"name": "High Risk", "likelihood": 5, "impact": 5},
        ]
        result = build_attack_paths_markdown(paths)

        # High risk should appear first
        high_pos = result.find("High Risk")
        low_pos = result.find("Low Risk")
        assert high_pos < low_pos

    def test_path_limit(self):
        """Test that only top 5 paths are shown."""
        paths = [{"name": f"Path {i}", "likelihood": 3, "impact": 3} for i in range(10)]
        result = build_attack_paths_markdown(paths)

        assert "and 5 more attack paths" in result


class TestBuildScenariosMarkdown:
    """Tests for build_scenarios_markdown function."""

    def test_empty_scenarios(self):
        """Test with no scenarios."""
        result = build_scenarios_markdown([])
        assert "No attack scenarios" in result

    def test_scenario_display(self):
        """Test scenario display."""
        scenarios = [
            {
                "name": "Test Scenario",
                "threat_actor": {"name": "APT Group", "motivation": "Espionage"},
                "objective": "Data theft",
                "risk_level": "HIGH",
                "executive_summary": "This is a test scenario summary.",
            }
        ]
        result = build_scenarios_markdown(scenarios)

        assert "Test Scenario" in result
        assert "APT Group" in result
        assert "Espionage" in result
        assert "Data theft" in result


class TestGroupFindingsByCategory:
    """Tests for group_findings_by_category function."""

    def test_groups_risks(self):
        """Test that risks are grouped correctly."""
        ctx = Context(target="test.io")
        ctx.add("risks", [{"title": "Test Risk"}])

        result = group_findings_by_category(ctx)

        assert "Security Risks" in result
        assert len(result["Security Risks"]) == 1

    def test_groups_findings(self):
        """Test that findings are grouped by category."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Test", "category": "Technical Findings"})
        ctx.add("finding_1", {"title": "Test 2", "category": "Configuration Issues"})

        result = group_findings_by_category(ctx)

        assert "Technical Findings" in result
        assert "Configuration Issues" in result


class TestGenerateExecSummary:
    """Tests for generate_exec_summary function."""

    def test_creates_file(self, tmp_path):
        """Test that executive summary generates a file."""
        ctx = Context(target="example.com")

        result = generate_exec_summary(ctx, params={"output_dir": str(tmp_path)})

        assert "executive_summary_path" in result.data
        output_path = Path(result.data["executive_summary_path"])
        assert output_path.exists()
        assert output_path.suffix == ".md"

    def test_file_content(self, tmp_path):
        """Test file content."""
        ctx = Context(target="example.com")
        ctx.add("risks", [{"title": "Test", "level": "high"}])

        result = generate_exec_summary(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["executive_summary_path"]).read_text()
        assert "example.com" in content


class TestGenerateTechnicalReport:
    """Tests for generate_technical_report function."""

    def test_creates_file(self, tmp_path):
        """Test that technical report generates a file."""
        ctx = Context(target="example.com")

        result = generate_technical_report(ctx, params={"output_dir": str(tmp_path)})

        assert "technical_report_path" in result.data
        output_path = Path(result.data["technical_report_path"])
        assert output_path.exists()

    def test_includes_mitre(self, tmp_path):
        """Test that MITRE section is included."""
        ctx = Context(target="example.com")
        ctx.add(
            "mitre_mapping",
            {"T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"}},
        )

        result = generate_technical_report(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["technical_report_path"]).read_text()
        assert "MITRE ATT&CK Coverage" in content


class TestGenerateFullReport:
    """Tests for generate_full_report function."""

    def test_creates_file(self, tmp_path):
        """Test that full report generates a file."""
        ctx = Context(target="example.com")

        result = generate_full_report(ctx, params={"output_dir": str(tmp_path)})

        assert "full_report_path" in result.data
        assert "full_report_content" in result.data

    def test_includes_toc(self, tmp_path):
        """Test that table of contents is included."""
        ctx = Context(target="example.com")

        result = generate_full_report(ctx, params={"output_dir": str(tmp_path)})

        content = result.data["full_report_content"]
        assert "Table of Contents" in content

    def test_section_options(self, tmp_path):
        """Test section inclusion options."""
        ctx = Context(target="example.com")
        ctx.add("mitre_mapping", {"T1595": {}})
        ctx.add("risks", [{"title": "Test", "level": "high"}])

        result = generate_full_report(
            ctx,
            params={
                "output_dir": str(tmp_path),
                "include_mitre": False,
            },
        )

        content = result.data["full_report_content"]
        assert "MITRE ATT&CK Coverage" not in content


# ============================================================================
# HTML Report Tests
# ============================================================================


class TestBuildStatsOverview:
    """Tests for build_stats_overview function."""

    def test_stats_cards(self):
        """Test that stats cards are generated."""
        ctx = Context(target="test.io")
        ctx.add("risks", [{"level": "high"}])
        ctx.add("attack_paths", [{}])
        ctx.add("mitre_techniques_used", ["T1595"])

        result = build_stats_overview(ctx)

        assert "stat-card" in result
        assert "Total Risks" in result
        assert "Attack Paths" in result
        assert "MITRE Techniques" in result


class TestBuildRiskSection:
    """Tests for build_risk_section function."""

    def test_empty_risks(self):
        """Test with no risks."""
        result = build_risk_section([])
        assert "No significant risks" in result

    def test_risk_chart(self):
        """Test risk distribution chart."""
        risks = [
            {"title": "Critical", "level": "critical"},
            {"title": "High", "level": "high"},
        ]
        result = build_risk_section(risks)

        assert "risk-chart" in result
        assert "risk-bar" in result
        assert "CRITICAL" in result

    def test_risk_table(self):
        """Test risk table generation."""
        risks = [
            {"title": "Test Risk", "level": "high", "score": 15, "description": "Test"}
        ]
        result = build_risk_section(risks)

        assert "<table>" in result
        assert "Test Risk" in result
        assert "badge-high" in result


class TestBuildMitreMatrixHtml:
    """Tests for build_mitre_matrix_html function."""

    def test_empty_matrix(self):
        """Test with no MITRE data."""
        ctx = Context(target="test.io")
        result = build_mitre_matrix_html(ctx)

        assert result == ""

    def test_matrix_grid(self):
        """Test MITRE matrix grid generation."""
        ctx = Context(target="test.io")
        ctx.add(
            "mitre_mapping",
            {
                "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
            },
        )

        result = build_mitre_matrix_html(ctx)

        assert "mitre-matrix" in result
        assert "mitre-tactic" in result
        assert "mitre-technique" in result
        assert "T1595" in result


class TestBuildAttackPathsHtml:
    """Tests for build_attack_paths_html function."""

    def test_empty_paths(self):
        """Test with no paths."""
        result = build_attack_paths_html([])
        assert result == ""

    def test_path_cards(self):
        """Test attack path cards."""
        paths = [
            {
                "name": "Test Path",
                "likelihood": 4,
                "impact": 5,
                "steps": ["Entry", "Target"],
            }
        ]
        result = build_attack_paths_html(paths)

        assert "attack-path" in result
        assert "Test Path" in result
        assert "path-steps" in result


class TestBuildScenariosHtml:
    """Tests for build_scenarios_html function."""

    def test_empty_scenarios(self):
        """Test with no scenarios."""
        result = build_scenarios_html([])
        assert result == ""

    def test_scenario_cards(self):
        """Test scenario card generation."""
        scenarios = [
            {
                "name": "Test Scenario",
                "threat_actor": {"name": "APT"},
                "objective": "Data theft",
                "risk_level": "HIGH",
            }
        ]
        result = build_scenarios_html(scenarios)

        assert "Test Scenario" in result
        assert "APT" in result
        assert "badge-high" in result


class TestGenerateHtml:
    """Tests for generate_html function."""

    def test_creates_file(self, tmp_path):
        """Test that HTML report generates a file."""
        ctx = Context(target="example.com")

        result = generate_html(ctx, params={"output_dir": str(tmp_path)})

        assert "html_report_path" in result.data
        output_path = Path(result.data["html_report_path"])
        assert output_path.exists()
        assert output_path.suffix == ".html"

    def test_valid_html(self, tmp_path):
        """Test that valid HTML is generated."""
        ctx = Context(target="example.com")

        result = generate_html(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["html_report_path"]).read_text()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_includes_styles(self, tmp_path):
        """Test that CSS styles are included."""
        ctx = Context(target="example.com")

        result = generate_html(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["html_report_path"]).read_text()
        assert "<style>" in content
        assert "--critical" in content

    def test_includes_javascript(self, tmp_path):
        """Test that JavaScript is included."""
        ctx = Context(target="example.com")

        result = generate_html(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["html_report_path"]).read_text()
        assert "<script>" in content


# ============================================================================
# Export Tests
# ============================================================================


class TestExportJson:
    """Tests for export_json function."""

    def test_creates_file(self, tmp_path):
        """Test that JSON export creates a file."""
        ctx = Context(target="example.com")
        ctx.add("test_data", {"key": "value"})

        result = export_json(ctx, params={"output_dir": str(tmp_path)})

        assert "json_export_path" in result.data
        output_path = Path(result.data["json_export_path"])
        assert output_path.exists()

    def test_valid_json(self, tmp_path):
        """Test that valid JSON is written."""
        ctx = Context(target="example.com")
        ctx.add("test_key", "test_value")

        result = export_json(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["json_export_path"]).read_text()
        data = json.loads(content)
        assert "test_key" in data.get("data", {})


class TestExportCsv:
    """Tests for export_csv function."""

    def test_creates_file(self, tmp_path):
        """Test that CSV export creates a file."""
        ctx = Context(target="example.com")
        ctx.add("risks", [{"title": "Test", "level": "high"}])

        result = export_csv(
            ctx, params={"output_dir": str(tmp_path), "data_key": "risks"}
        )

        assert "risks_csv_path" in result.data
        output_path = Path(result.data["risks_csv_path"])
        assert output_path.exists()

    def test_no_data_warning(self, tmp_path):
        """Test warning when no data to export."""
        ctx = Context(target="example.com")

        result = export_csv(
            ctx, params={"output_dir": str(tmp_path), "data_key": "missing"}
        )

        warning_logs = result.get_logs(level="WARNING")
        assert len(warning_logs) > 0


class TestExportStix:
    """Tests for export_stix function."""

    def test_creates_bundle(self, tmp_path):
        """Test that STIX bundle is created."""
        ctx = Context(target="example.com")
        ctx.add(
            "mitre_mapping",
            {
                "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
            },
        )

        result = export_stix(ctx, params={"output_dir": str(tmp_path)})

        assert "stix_export_path" in result.data
        assert "stix_object_count" in result.data

    def test_valid_stix_bundle(self, tmp_path):
        """Test that valid STIX bundle structure is created."""
        ctx = Context(target="example.com")
        ctx.add("mitre_mapping", {"T1595": {}})
        ctx.add("risks", [{"title": "Test Risk", "level": "high"}])

        result = export_stix(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["stix_export_path"]).read_text()
        bundle = json.loads(content)

        assert bundle["type"] == "bundle"
        assert "objects" in bundle
        assert len(bundle["objects"]) >= 1

    def test_includes_identity(self, tmp_path):
        """Test that tool identity is included."""
        ctx = Context(target="example.com")
        ctx.add("mitre_mapping", {"T1595": {}})

        result = export_stix(ctx, params={"output_dir": str(tmp_path)})

        content = Path(result.data["stix_export_path"]).read_text()
        bundle = json.loads(content)

        identities = [obj for obj in bundle["objects"] if obj["type"] == "identity"]
        assert len(identities) == 1
        assert "RedOps" in identities[0]["name"]


class TestCreateStixAttackPattern:
    """Tests for create_stix_attack_pattern function."""

    def test_basic_pattern(self):
        """Test basic attack pattern creation."""
        result = create_stix_attack_pattern(
            "T1595",
            {"name": "Active Scanning", "tactic": "Reconnaissance"},
            "2024-01-01T00:00:00.000Z",
        )

        assert result["type"] == "attack-pattern"
        assert result["spec_version"] == "2.1"
        assert result["name"] == "Active Scanning"
        assert "external_references" in result

    def test_mitre_reference(self):
        """Test MITRE external reference."""
        result = create_stix_attack_pattern(
            "T1595",
            {"name": "Test", "tactic": "Reconnaissance"},
            "2024-01-01T00:00:00.000Z",
        )

        refs = result["external_references"]
        assert len(refs) == 1
        assert refs[0]["source_name"] == "mitre-attack"
        assert refs[0]["external_id"] == "T1595"


class TestCreateStixVulnerability:
    """Tests for create_stix_vulnerability function."""

    def test_basic_vulnerability(self):
        """Test basic vulnerability creation."""
        result = create_stix_vulnerability(
            {"title": "Test Vuln", "description": "Test", "level": "high"},
            "2024-01-01T00:00:00.000Z",
        )

        assert result["type"] == "vulnerability"
        assert result["name"] == "Test Vuln"
        assert "HIGH" in result["description"]


class TestCreateStixIndicator:
    """Tests for create_stix_indicator function."""

    def test_basic_indicator(self):
        """Test basic indicator creation."""
        result = create_stix_indicator(
            {"title": "Test Finding", "description": "Test"}, "2024-01-01T00:00:00.000Z"
        )

        assert result["type"] == "indicator"
        assert result["name"] == "Test Finding"
        assert result["pattern_type"] == "stix"

    def test_empty_title_returns_none(self):
        """Test that empty title returns None."""
        result = create_stix_indicator(
            {"description": "No title"}, "2024-01-01T00:00:00.000Z"
        )

        assert result is None


class TestExportFromTemplate:
    """Tests for export_from_template function."""

    def test_basic_template(self, tmp_path):
        """Test basic template export."""
        ctx = Context(target="example.com")
        template = "Target: {target}\nDate: {date}"

        result = export_from_template(
            ctx, template, params={"output_dir": str(tmp_path)}
        )

        assert "template_export_path" in result.data
        content = Path(result.data["template_export_path"]).read_text()
        assert "Target: example.com" in content

    def test_risk_variables(self, tmp_path):
        """Test risk count variables in template."""
        ctx = Context(target="example.com")
        ctx.add(
            "risks",
            [
                {"level": "critical"},
                {"level": "high"},
            ],
        )
        template = "Critical: {critical_risks}, High: {high_risks}"

        result = export_from_template(
            ctx, template, params={"output_dir": str(tmp_path)}
        )

        content = Path(result.data["template_export_path"]).read_text()
        assert "Critical: 1" in content
        assert "High: 1" in content


class TestExportExecutiveBrief:
    """Tests for export_executive_brief function."""

    def test_creates_file(self, tmp_path):
        """Test that executive brief creates a file."""
        ctx = Context(target="example.com")

        result = export_executive_brief(ctx, params={"output_dir": str(tmp_path)})

        assert "template_export_path" in result.data
        content = Path(result.data["template_export_path"]).read_text()
        assert "SECURITY ASSESSMENT BRIEF" in content


class TestExportTechnicalSummary:
    """Tests for export_technical_summary function."""

    def test_creates_file(self, tmp_path):
        """Test that technical summary creates a file."""
        ctx = Context(target="example.com")

        result = export_technical_summary(ctx, params={"output_dir": str(tmp_path)})

        assert "template_export_path" in result.data
        content = Path(result.data["template_export_path"]).read_text()
        assert "Technical Security Assessment" in content


class TestExportAll:
    """Tests for export_all function."""

    def test_exports_multiple_formats(self, tmp_path):
        """Test that multiple formats are exported."""
        ctx = Context(target="example.com")
        ctx.add("risks", [{"title": "Test", "level": "high"}])
        ctx.add("mitre_mapping", {"T1595": {}})

        result = export_all(ctx, params={"output_dir": str(tmp_path)})

        assert "json_export_path" in result.data
        assert "risks_csv_path" in result.data
        assert "stix_export_path" in result.data


# ============================================================================
# Constants Tests
# ============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_risk_indicators(self):
        """Test risk indicators are defined."""
        assert "critical" in RISK_INDICATORS
        assert "high" in RISK_INDICATORS
        assert "medium" in RISK_INDICATORS
        assert "low" in RISK_INDICATORS
        assert "info" in RISK_INDICATORS

    def test_mitre_tactics_order(self):
        """Test MITRE tactics order."""
        assert "Reconnaissance" in MITRE_TACTICS_ORDER
        assert "Impact" in MITRE_TACTICS_ORDER
        assert MITRE_TACTICS_ORDER.index("Reconnaissance") < MITRE_TACTICS_ORDER.index(
            "Impact"
        )

    def test_risk_colors(self):
        """Test risk colors are defined."""
        assert "critical" in RISK_COLORS
        assert RISK_COLORS["critical"].startswith("#")

    def test_templates_defined(self):
        """Test that templates are defined."""
        assert "{target}" in EXECUTIVE_BRIEF_TEMPLATE
        assert "{target}" in TECHNICAL_SUMMARY_TEMPLATE


# ============================================================================
# Integration Tests
# ============================================================================


class TestReportingIntegration:
    """Integration tests for reporting modules."""

    def test_full_pipeline_export(self, tmp_path):
        """Test complete reporting pipeline."""
        ctx = Context(target="integration-test.io")

        # Add comprehensive data
        ctx.add(
            "risks",
            [
                {
                    "title": "SQL Injection",
                    "level": "critical",
                    "description": "Database vulnerable",
                },
                {"title": "XSS", "level": "high", "description": "Script injection"},
            ],
        )
        ctx.add(
            "attack_paths",
            [
                {
                    "name": "Web Application Attack",
                    "likelihood": 4,
                    "impact": 5,
                    "steps": ["Entry", "Exploit", "Exfiltrate"],
                    "mitre_techniques": ["T1190", "T1059"],
                }
            ],
        )
        ctx.add(
            "mitre_mapping",
            {
                "T1190": {
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                },
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                },
            },
        )
        ctx.add("mitre_techniques_used", ["T1190", "T1059"])
        ctx.add(
            "scenarios",
            [
                {
                    "name": "Data Breach Scenario",
                    "threat_actor": {"name": "Organized Crime"},
                    "objective": "Data theft",
                    "risk_level": "HIGH",
                }
            ],
        )

        # Generate all reports
        result = generate_full_report(ctx, params={"output_dir": str(tmp_path)})
        result = generate_html(result, params={"output_dir": str(tmp_path)})
        result = export_all(result, params={"output_dir": str(tmp_path)})

        # Verify all outputs exist
        assert "full_report_path" in result.data
        assert "html_report_path" in result.data
        assert "json_export_path" in result.data
        assert "stix_export_path" in result.data

        # Verify content quality
        md_content = Path(result.data["full_report_path"]).read_text()
        assert "CRITICAL" in md_content  # Risk level
        assert "MITRE ATT&CK" in md_content
        assert "Attack Paths" in md_content
        assert "Web Application Attack" in md_content  # Attack path name
        assert "T1190" in md_content  # MITRE technique

        html_content = Path(result.data["html_report_path"]).read_text()
        assert "<!DOCTYPE html>" in html_content
        assert "integration-test.io" in html_content

    def test_empty_context_handling(self, tmp_path):
        """Test that empty context is handled gracefully."""
        ctx = Context(target="empty-test.io")

        # Should not raise errors
        result = generate_full_report(ctx, params={"output_dir": str(tmp_path)})
        result = generate_html(result, params={"output_dir": str(tmp_path)})
        result = export_all(result, params={"output_dir": str(tmp_path)})

        assert "full_report_path" in result.data
        assert "html_report_path" in result.data
