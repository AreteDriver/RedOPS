"""Tests for the HTML report generation module."""

import tempfile
from pathlib import Path
from redops.core.context import Context
from redops.modules.reporting.html_report import (
    generate_html,
    build_html_content,
    build_stats_overview,
    build_risk_section,
    build_mitre_matrix_html,
    build_attack_paths_html,
    build_scenarios_html,
    build_detailed_findings_html,
    MITRE_TACTICS_ORDER,
    RISK_COLORS,
    HTML_TEMPLATE,
)


class TestConstants:
    """Tests for module constants."""

    def test_mitre_tactics_order(self):
        """Test MITRE tactics order contains expected values."""
        assert "Reconnaissance" in MITRE_TACTICS_ORDER
        assert "Initial Access" in MITRE_TACTICS_ORDER
        assert "Execution" in MITRE_TACTICS_ORDER
        assert "Impact" in MITRE_TACTICS_ORDER
        assert len(MITRE_TACTICS_ORDER) == 14

    def test_risk_colors(self):
        """Test risk colors are defined."""
        assert "critical" in RISK_COLORS
        assert "high" in RISK_COLORS
        assert "medium" in RISK_COLORS
        assert "low" in RISK_COLORS
        assert "info" in RISK_COLORS

    def test_html_template_has_placeholders(self):
        """Test HTML template contains required placeholders."""
        assert "{target}" in HTML_TEMPLATE
        assert "{timestamp}" in HTML_TEMPLATE
        assert "{pipeline}" in HTML_TEMPLATE
        assert "{content}" in HTML_TEMPLATE


class TestGenerateHtml:
    """Tests for generate_html function."""

    def test_basic_generation(self):
        """Test basic HTML generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="example.com")
            result = generate_html(ctx, params={"output_dir": tmpdir})

            assert "html_report_path" in result.data
            assert Path(result.data["html_report_path"]).exists()

    def test_creates_output_directory(self):
        """Test that output directory is created if missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "reports" / "html"
            ctx = Context(target="test.com")
            result = generate_html(ctx, params={"output_dir": str(output_dir)})

            assert output_dir.exists()
            assert "html_report_path" in result.data

    def test_report_contains_target(self):
        """Test that report contains target information."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="mytarget.com")
            result = generate_html(ctx, params={"output_dir": tmpdir})

            report_path = result.data["html_report_path"]
            with open(report_path) as f:
                content = f.read()

            assert "mytarget.com" in content

    def test_default_output_dir(self):
        """Test default output directory."""
        ctx = Context(target="test.com")
        # Just test it doesn't crash with no params
        result = generate_html(ctx, params=None)
        assert "html_report_path" in result.data
        # Cleanup
        Path(result.data["html_report_path"]).unlink(missing_ok=True)


class TestBuildHtmlContent:
    """Tests for build_html_content function."""

    def test_builds_all_sections(self):
        """Test that all sections are built."""
        ctx = Context(target="test.com")
        ctx.add("risks", [])
        ctx.add("attack_paths", [])
        ctx.add("scenarios", [])

        content = build_html_content(ctx)

        assert "Assessment Overview" in content
        assert "Risk Analysis" in content

    def test_with_data(self):
        """Test content building with actual data."""
        ctx = Context(target="test.com")
        ctx.add("risks", [{"level": "high", "title": "Test Risk", "score": 15}])
        ctx.add("attack_paths", [{"name": "Path 1", "likelihood": 3, "impact": 4}])

        content = build_html_content(ctx)

        assert "Test Risk" in content


class TestBuildStatsOverview:
    """Tests for build_stats_overview function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()
        content = build_stats_overview(ctx)

        assert "Assessment Overview" in content
        assert "Total Risks" in content
        assert "stat-value" in content

    def test_with_risks(self):
        """Test with risks data."""
        ctx = Context()
        ctx.add(
            "risks",
            [
                {"level": "critical"},
                {"level": "high"},
                {"level": "medium"},
            ],
        )

        content = build_stats_overview(ctx)

        assert "3" in content  # Total risks

    def test_with_attack_paths(self):
        """Test with attack paths data."""
        ctx = Context()
        ctx.add("attack_paths", [{"name": "Path 1"}, {"name": "Path 2"}])

        content = build_stats_overview(ctx)

        assert "2" in content  # Attack paths count

    def test_with_mitre_techniques(self):
        """Test with MITRE techniques."""
        ctx = Context()
        ctx.add("mitre_techniques_used", ["T1059", "T1071", "T1078"])

        content = build_stats_overview(ctx)

        assert "3" in content  # Techniques count


class TestBuildRiskSection:
    """Tests for build_risk_section function."""

    def test_empty_risks(self):
        """Test with no risks."""
        content = build_risk_section([])

        assert "No significant risks identified" in content

    def test_with_risks(self):
        """Test with multiple risks."""
        risks = [
            {
                "level": "critical",
                "title": "Critical Risk",
                "score": 25,
                "description": "Desc 1",
            },
            {
                "level": "high",
                "title": "High Risk",
                "score": 18,
                "description": "Desc 2",
            },
            {
                "level": "medium",
                "title": "Medium Risk",
                "score": 12,
                "description": "Desc 3",
            },
        ]

        content = build_risk_section(risks)

        assert "Critical Risk" in content
        assert "High Risk" in content
        assert "badge-critical" in content
        assert "badge-high" in content

    def test_severity_fallback(self):
        """Test severity field fallback."""
        risks = [
            {"severity": "low", "title": "Low Risk", "score": 5},
        ]

        content = build_risk_section(risks)

        assert "badge-low" in content

    def test_unknown_severity(self):
        """Test unknown severity defaults to info."""
        risks = [
            {"level": "unknown_level", "title": "Unknown", "score": 1},
        ]

        content = build_risk_section(risks)

        # Should count as info
        assert "INFO" in content or "info" in content.lower()

    def test_more_than_15_risks(self):
        """Test truncation message for many risks."""
        risks = [{"level": "low", "title": f"Risk {i}", "score": i} for i in range(20)]

        content = build_risk_section(risks)

        assert "... and 5 more risks" in content

    def test_html_escaping(self):
        """Test that HTML is escaped in risk fields."""
        risks = [
            {
                "level": "high",
                "title": "<script>alert(1)</script>",
                "score": 10,
                "description": "<img src=x>",
            },
        ]

        content = build_risk_section(risks)

        assert "<script>" not in content
        assert "&lt;script&gt;" in content


class TestBuildMitreMatrixHtml:
    """Tests for build_mitre_matrix_html function."""

    def test_empty_mapping(self):
        """Test with no MITRE data."""
        ctx = Context()
        content = build_mitre_matrix_html(ctx)

        assert content == ""

    def test_with_techniques_only(self):
        """Test with technique IDs only (no mapping)."""
        ctx = Context()
        ctx.add("mitre_techniques_used", ["T1059", "T1071"])

        content = build_mitre_matrix_html(ctx)

        assert "MITRE ATT&CK Coverage" in content
        # Note: Without a mapping, techniques are stored in "Identified Techniques"
        # which is not in MITRE_TACTICS_ORDER, so they appear in stats only
        assert "2 techniques" in content

    def test_with_mapping(self):
        """Test with full MITRE mapping."""
        ctx = Context()
        ctx.add(
            "mitre_mapping",
            {
                "T1059": {
                    "tactic": "Execution",
                    "name": "Command and Scripting Interpreter",
                },
                "T1071": {
                    "tactic": "Command and Control",
                    "name": "Application Layer Protocol",
                },
            },
        )

        content = build_mitre_matrix_html(ctx)

        assert "Execution" in content
        assert "Command and Control" in content
        assert "T1059" in content

    def test_with_unknown_tactic(self):
        """Test with unknown tactic in mapping."""
        ctx = Context()
        ctx.add(
            "mitre_mapping",
            {
                "T9999": {"name": "Unknown Technique"},  # No tactic
            },
        )

        content = build_mitre_matrix_html(ctx)

        assert "Other" in content
        assert "T9999" in content

    def test_more_than_8_techniques(self):
        """Test truncation for many techniques in one tactic."""
        ctx = Context()
        techniques = {
            f"T{1000 + i}": {"tactic": "Execution", "name": f"Tech {i}"}
            for i in range(12)
        }
        ctx.add("mitre_mapping", techniques)

        content = build_mitre_matrix_html(ctx)

        assert "+4 more" in content

    def test_non_dict_technique_info(self):
        """Test handling non-dict technique info."""
        ctx = Context()
        ctx.add(
            "mitre_mapping",
            {
                "T1059": "Just a string, not a dict",
            },
        )

        content = build_mitre_matrix_html(ctx)

        assert "T1059" in content


class TestBuildAttackPathsHtml:
    """Tests for build_attack_paths_html function."""

    def test_empty_paths(self):
        """Test with no attack paths."""
        content = build_attack_paths_html([])
        assert content == ""

    def test_basic_path(self):
        """Test with basic attack path."""
        paths = [
            {"name": "Path 1", "description": "Test path", "likelihood": 3, "impact": 4}
        ]

        content = build_attack_paths_html(paths)

        assert "Attack Paths" in content
        assert "Path 1" in content
        assert "Test path" in content

    def test_risk_levels(self):
        """Test different risk levels based on score."""
        # Critical: score >= 20
        paths_critical = [{"name": "Critical", "likelihood": 5, "impact": 5}]
        content = build_attack_paths_html(paths_critical)
        assert "CRITICAL" in content

        # High: score >= 12
        paths_high = [{"name": "High", "likelihood": 4, "impact": 4}]
        content = build_attack_paths_html(paths_high)
        assert "HIGH" in content

        # Medium: score >= 6
        paths_medium = [{"name": "Medium", "likelihood": 2, "impact": 3}]
        content = build_attack_paths_html(paths_medium)
        assert "MEDIUM" in content

        # Low: score < 6
        paths_low = [{"name": "Low", "likelihood": 1, "impact": 2}]
        content = build_attack_paths_html(paths_low)
        assert "LOW" in content

    def test_with_steps(self):
        """Test path with steps."""
        paths = [
            {
                "name": "Multi-step",
                "likelihood": 3,
                "impact": 3,
                "steps": [
                    {"name": "Entry Point"},
                    {"name": "Lateral Move"},
                    {"name": "Target System"},
                ],
            }
        ]

        content = build_attack_paths_html(paths)

        assert "Entry Point" in content
        assert "Lateral Move" in content
        assert "Target System" in content
        assert "[ENTRY]" in content
        assert "[TARGET]" in content

    def test_with_string_steps(self):
        """Test path with string steps (not dict)."""
        paths = [
            {
                "name": "String Steps",
                "likelihood": 3,
                "impact": 3,
                "steps": ["Step 1", "Step 2", "Step 3"],
            }
        ]

        content = build_attack_paths_html(paths)

        assert "Step 1" in content
        assert "Step 2" in content

    def test_with_mitre_techniques(self):
        """Test path with MITRE techniques."""
        paths = [
            {
                "name": "MITRE Path",
                "likelihood": 3,
                "impact": 3,
                "mitre_techniques": ["T1059", "T1071", "T1078"],
            }
        ]

        content = build_attack_paths_html(paths)

        assert "MITRE Techniques" in content
        assert "T1059" in content

    def test_many_mitre_techniques(self):
        """Test truncation of many MITRE techniques."""
        paths = [
            {
                "name": "Many Techniques",
                "likelihood": 3,
                "impact": 3,
                "mitre_techniques": [f"T{1000 + i}" for i in range(10)],
            }
        ]

        content = build_attack_paths_html(paths)

        assert "+5 more" in content

    def test_more_than_5_paths(self):
        """Test truncation message for many paths."""
        paths = [{"name": f"Path {i}", "likelihood": 3, "impact": 3} for i in range(8)]

        content = build_attack_paths_html(paths)

        assert "... and 3 more attack paths" in content


class TestBuildScenariosHtml:
    """Tests for build_scenarios_html function."""

    def test_empty_scenarios(self):
        """Test with no scenarios."""
        content = build_scenarios_html([])
        assert content == ""

    def test_basic_scenario(self):
        """Test basic scenario."""
        scenarios = [
            {"name": "Scenario 1", "objective": "Test objective", "risk_level": "HIGH"}
        ]

        content = build_scenarios_html(scenarios)

        assert "Threat Scenarios" in content
        assert "Scenario 1" in content
        assert "Test objective" in content

    def test_with_threat_actor_dict(self):
        """Test scenario with dict threat actor."""
        scenarios = [
            {
                "name": "APT Attack",
                "objective": "Data theft",
                "risk_level": "CRITICAL",
                "threat_actor": {"name": "APT29"},
            }
        ]

        content = build_scenarios_html(scenarios)

        assert "APT29" in content
        assert "Threat Actor" in content

    def test_with_threat_actor_string(self):
        """Test scenario with string threat actor."""
        scenarios = [
            {
                "name": "Attack",
                "objective": "Test",
                "risk_level": "MEDIUM",
                "threat_actor": "Unknown Actor",
            }
        ]

        content = build_scenarios_html(scenarios)

        assert "Unknown Actor" in content

    def test_with_executive_summary(self):
        """Test scenario with executive summary."""
        scenarios = [
            {
                "name": "Detailed Scenario",
                "objective": "Test",
                "risk_level": "HIGH",
                "executive_summary": "This is a detailed executive summary.",
            }
        ]

        content = build_scenarios_html(scenarios)

        assert "detailed executive summary" in content

    def test_long_executive_summary(self):
        """Test truncation of long executive summary."""
        scenarios = [
            {
                "name": "Long Summary",
                "objective": "Test",
                "risk_level": "MEDIUM",
                "executive_summary": "x" * 500,  # Longer than 400 chars
            }
        ]

        content = build_scenarios_html(scenarios)

        assert "..." in content

    def test_invalid_risk_level(self):
        """Test invalid risk level defaults to medium."""
        scenarios = [
            {"name": "Invalid Risk", "objective": "Test", "risk_level": "INVALID"}
        ]

        content = build_scenarios_html(scenarios)

        # Should use medium class
        assert "badge-medium" in content

    def test_more_than_3_scenarios(self):
        """Test truncation message for many scenarios."""
        scenarios = [
            {"name": f"Scenario {i}", "objective": "Test", "risk_level": "LOW"}
            for i in range(5)
        ]

        content = build_scenarios_html(scenarios)

        assert "... and 2 more scenarios" in content


class TestBuildDetailedFindingsHtml:
    """Tests for build_detailed_findings_html function."""

    def test_basic_output(self):
        """Test basic detailed findings output."""
        ctx = Context()
        ctx.add("test_key", "test_value")

        content = build_detailed_findings_html(ctx)

        assert "Technical Details" in content
        assert "test_key" in content

    def test_skips_private_keys(self):
        """Test that keys starting with _ are skipped."""
        ctx = Context()
        ctx.add("public_key", "visible")
        ctx.data["_private_key"] = "hidden"

        content = build_detailed_findings_html(ctx)

        assert "public_key" in content
        assert "_private_key" not in content

    def test_list_size(self):
        """Test list size display."""
        ctx = Context()
        ctx.add("items", [1, 2, 3, 4, 5])

        content = build_detailed_findings_html(ctx)

        assert "5" in content  # Size of list

    def test_dict_size(self):
        """Test dict size display."""
        ctx = Context()
        ctx.add("mapping", {"a": 1, "b": 2, "c": 3})

        content = build_detailed_findings_html(ctx)

        assert "3" in content  # Size of dict

    def test_string_length(self):
        """Test string length display."""
        ctx = Context()
        ctx.add("text", "hello world")

        content = build_detailed_findings_html(ctx)

        assert "11 chars" in content

    def test_other_types(self):
        """Test other types show dash for size."""
        ctx = Context()
        ctx.add("number", 42)

        content = build_detailed_findings_html(ctx)

        assert "int" in content


class TestIntegration:
    """Integration tests for HTML report generation."""

    def test_full_report_generation(self):
        """Test full report with all sections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target="integration-test.com")
            ctx.add("pipeline_name", "Full Assessment")
            ctx.add(
                "risks",
                [
                    {
                        "level": "critical",
                        "title": "SQL Injection",
                        "score": 25,
                        "description": "Database vulnerability",
                    },
                    {
                        "level": "high",
                        "title": "XSS",
                        "score": 18,
                        "description": "Cross-site scripting",
                    },
                ],
            )
            ctx.add(
                "attack_paths",
                [
                    {
                        "name": "Web App Attack",
                        "description": "Attack via web application",
                        "likelihood": 4,
                        "impact": 5,
                        "steps": [
                            {"name": "Recon"},
                            {"name": "Exploit"},
                            {"name": "Exfil"},
                        ],
                        "mitre_techniques": ["T1190", "T1059"],
                    }
                ],
            )
            ctx.add(
                "mitre_mapping",
                {
                    "T1190": {
                        "tactic": "Initial Access",
                        "name": "Exploit Public-Facing Application",
                    },
                    "T1059": {
                        "tactic": "Execution",
                        "name": "Command and Scripting Interpreter",
                    },
                },
            )
            ctx.add(
                "scenarios",
                [
                    {
                        "name": "External Attacker",
                        "objective": "Data exfiltration",
                        "risk_level": "CRITICAL",
                        "threat_actor": {"name": "APT Group"},
                        "executive_summary": "Sophisticated attack scenario",
                    }
                ],
            )

            result = generate_html(ctx, params={"output_dir": tmpdir})

            # Verify report was created
            assert "html_report_path" in result.data
            report_path = Path(result.data["html_report_path"])
            assert report_path.exists()

            # Read and verify content
            with open(report_path) as f:
                html = f.read()

            # Check all sections present
            assert "integration-test.com" in html
            assert "SQL Injection" in html
            assert "Web App Attack" in html
            assert "T1190" in html
            assert "External Attacker" in html
            assert "APT Group" in html
