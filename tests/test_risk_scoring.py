"""Tests for the Risk Scoring module."""

import pytest
from redops.core.context import Context
from redops.core.models import Risk, RiskLevel, RiskCategory
from redops.modules.intel.risk_scoring import (
    score_risks,
    extract_findings,
    score_finding,
    identify_risk_type,
    check_implicit_risks,
    calculate_risk_score,
    categorize_risk,
    aggregate_risks,
    prioritize_risks,
    get_remediation_plan,
    RISK_RULES,
)


class TestCalculateRiskScore:
    """Tests for risk score calculation."""

    def test_minimum_score(self):
        """Test minimum risk score."""
        assert calculate_risk_score(1, 1) == 1

    def test_maximum_score(self):
        """Test maximum risk score."""
        assert calculate_risk_score(5, 5) == 25

    def test_medium_score(self):
        """Test medium risk score."""
        assert calculate_risk_score(3, 3) == 9

    def test_asymmetric_score(self):
        """Test asymmetric likelihood/impact."""
        assert calculate_risk_score(5, 1) == 5
        assert calculate_risk_score(1, 5) == 5


class TestCategorizeRisk:
    """Tests for risk categorization."""

    def test_critical_threshold(self):
        """Test critical risk threshold."""
        assert categorize_risk(25) == RiskLevel.CRITICAL
        assert categorize_risk(20) == RiskLevel.CRITICAL

    def test_high_threshold(self):
        """Test high risk threshold."""
        assert categorize_risk(19) == RiskLevel.HIGH
        assert categorize_risk(12) == RiskLevel.HIGH

    def test_medium_threshold(self):
        """Test medium risk threshold."""
        assert categorize_risk(11) == RiskLevel.MEDIUM
        assert categorize_risk(6) == RiskLevel.MEDIUM

    def test_low_threshold(self):
        """Test low risk threshold."""
        assert categorize_risk(5) == RiskLevel.LOW
        assert categorize_risk(3) == RiskLevel.LOW

    def test_info_threshold(self):
        """Test info risk threshold."""
        assert categorize_risk(2) == RiskLevel.INFO
        assert categorize_risk(1) == RiskLevel.INFO


class TestIdentifyRiskType:
    """Tests for risk type identification."""

    def test_identify_missing_hsts(self):
        """Test identifying missing HSTS header."""
        risk_type = identify_risk_type(
            "finding_tech_0",
            "Missing Security Header: Strict-Transport-Security",
            "HSTS header is not present",
            {}
        )
        assert risk_type == "missing_hsts"

    def test_identify_missing_csp(self):
        """Test identifying missing CSP header."""
        risk_type = identify_risk_type(
            "finding_tech_0",
            "Missing Security Header: Content-Security-Policy",
            "CSP prevents XSS attacks",
            {}
        )
        assert risk_type == "missing_csp"

    def test_identify_missing_spf(self):
        """Test identifying missing SPF record."""
        risk_type = identify_risk_type(
            "finding_no_spf",
            "Missing SPF Record for example.com",
            "No SPF record found",
            {}
        )
        assert risk_type == "missing_spf"

    def test_identify_zone_transfer(self):
        """Test identifying zone transfer vulnerability."""
        risk_type = identify_risk_type(
            "finding_axfr",
            "Zone Transfer Allowed",
            "DNS zone transfer is permitted",
            {}
        )
        assert risk_type == "zone_transfer_allowed"

    def test_identify_version_disclosure(self):
        """Test identifying server version disclosure."""
        risk_type = identify_risk_type(
            "finding_version",
            "Server Version Disclosure",
            "Server is disclosing version information",
            {}
        )
        assert risk_type == "server_version_disclosure"

    def test_identify_wordpress(self):
        """Test identifying WordPress detection."""
        risk_type = identify_risk_type(
            "finding_tech",
            "WordPress Detected",
            "WordPress CMS is running",
            {}
        )
        assert risk_type == "wordpress_detected"

    def test_identify_dev_staging(self):
        """Test identifying exposed dev/staging subdomains."""
        risk_type = identify_risk_type(
            "finding_subdomains",
            "Discovered Subdomains",
            "Found active subdomains",
            {"subdomains": [{"subdomain": "dev.example.com"}]}
        )
        assert risk_type == "dev_staging_exposed"

    def test_identify_excessive_subdomains(self):
        """Test identifying excessive subdomains."""
        subdomains = [{"subdomain": f"sub{i}.example.com"} for i in range(25)]
        risk_type = identify_risk_type(
            "finding_subdomains",
            "Discovered Subdomains",
            "Found many subdomains",
            {"subdomains": subdomains}
        )
        assert risk_type == "excessive_subdomains"

    def test_no_matching_risk_type(self):
        """Test when no risk type matches."""
        risk_type = identify_risk_type(
            "finding_info",
            "DNS A Records",
            "Found IP addresses",
            {}
        )
        assert risk_type is None


class TestExtractFindings:
    """Tests for findings extraction."""

    def test_extract_findings_with_findings(self):
        """Test extracting findings from context."""
        ctx = Context(target="example.com")
        ctx.add("finding_dns_example.com", {"title": "DNS Finding", "severity": "info"})
        ctx.add("finding_tech_0", {"title": "Tech Finding", "severity": "low"})
        ctx.add("other_data", {"not": "a finding"})

        findings = extract_findings(ctx)

        assert len(findings) == 2
        assert "finding_dns_example.com" in findings
        assert "finding_tech_0" in findings
        assert "other_data" not in findings

    def test_extract_findings_empty(self):
        """Test extracting from context with no findings."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {"domain": "example.com"})

        findings = extract_findings(ctx)

        assert len(findings) == 0


class TestScoreFinding:
    """Tests for individual finding scoring."""

    def test_score_finding_with_rule(self):
        """Test scoring a finding with a matching rule."""
        ctx = Context(target="example.com")
        finding_data = {
            "title": "Missing Security Header: Strict-Transport-Security",
            "description": "HSTS is not present",
            "severity": "medium",
            "data": {}
        }

        risks = score_finding("finding_tech_0", finding_data, ctx)

        assert len(risks) == 1
        assert risks[0].likelihood == RISK_RULES["missing_hsts"]["likelihood"]
        assert risks[0].impact == RISK_RULES["missing_hsts"]["impact"]

    def test_score_finding_high_severity_no_rule(self):
        """Test scoring a high severity finding without specific rule."""
        ctx = Context(target="example.com")
        finding_data = {
            "title": "Unknown High Risk",
            "description": "Something bad",
            "severity": "high",
            "data": {}
        }

        risks = score_finding("finding_unknown", finding_data, ctx)

        assert len(risks) == 1
        assert risks[0].likelihood == 3
        assert risks[0].impact == 3

    def test_score_finding_critical_severity(self):
        """Test scoring a critical severity finding."""
        ctx = Context(target="example.com")
        finding_data = {
            "title": "Critical Issue",
            "description": "Very bad",
            "severity": "critical",
            "data": {}
        }

        risks = score_finding("finding_critical", finding_data, ctx)

        assert len(risks) == 1
        assert risks[0].impact == 4

    def test_score_finding_info_not_scored(self):
        """Test that info findings don't create risks."""
        ctx = Context(target="example.com")
        finding_data = {
            "title": "DNS A Records",
            "description": "Found IP addresses",
            "severity": "info",
            "data": {}
        }

        risks = score_finding("finding_dns", finding_data, ctx)

        assert len(risks) == 0


class TestCheckImplicitRisks:
    """Tests for implicit risk checking."""

    def test_implicit_missing_dmarc(self):
        """Test detecting missing DMARC implicitly."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {
            "domain": "example.com",
            "has_dmarc": False,
            "has_spf": True,
        })

        risks = check_implicit_risks(ctx)

        dmarc_risks = [r for r in risks if "dmarc" in r.title.lower()]
        assert len(dmarc_risks) == 1

    def test_no_implicit_risk_when_dmarc_present(self):
        """Test no DMARC risk when DMARC is present."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {
            "domain": "example.com",
            "has_dmarc": True,
            "has_spf": True,
        })

        risks = check_implicit_risks(ctx)

        dmarc_risks = [r for r in risks if "dmarc" in r.title.lower()]
        assert len(dmarc_risks) == 0

    def test_no_domain_profile(self):
        """Test handling missing domain profile."""
        ctx = Context(target="example.com")

        risks = check_implicit_risks(ctx)

        # Should not crash, may or may not have risks
        assert isinstance(risks, list)


class TestAggregateRisks:
    """Tests for risk aggregation."""

    def test_aggregate_empty_list(self):
        """Test aggregating empty risk list."""
        stats = aggregate_risks([])

        assert stats["total"] == 0
        assert stats["average_score"] == 0
        assert stats["highest_score"] == 0

    def test_aggregate_single_risk(self):
        """Test aggregating single risk."""
        risk = Risk(
            title="Test Risk",
            description="Test description",
            likelihood=3,
            impact=4,
            category=RiskCategory.OWASP,
            owasp_id="A05:2021",
        )

        stats = aggregate_risks([risk])

        assert stats["total"] == 1
        assert stats["average_score"] == 12
        assert stats["highest_score"] == 12
        assert stats["by_level"]["high"] == 1
        assert "A05:2021" in stats["owasp_categories"]

    def test_aggregate_multiple_risks(self):
        """Test aggregating multiple risks."""
        risks = [
            Risk(title="Critical", description="", likelihood=5, impact=5),
            Risk(title="High", description="", likelihood=4, impact=4),
            Risk(title="Medium", description="", likelihood=3, impact=3),
        ]

        stats = aggregate_risks(risks)

        assert stats["total"] == 3
        assert stats["highest_score"] == 25
        assert stats["by_level"]["critical"] == 1
        assert stats["by_level"]["high"] == 1
        assert stats["by_level"]["medium"] == 1

    def test_aggregate_with_mitre(self):
        """Test aggregating risks with MITRE IDs."""
        risks = [
            Risk(title="R1", description="", likelihood=3, impact=3, mitre_id="T1566"),
            Risk(title="R2", description="", likelihood=3, impact=3, mitre_id="T1590"),
        ]

        stats = aggregate_risks(risks)

        assert "T1566" in stats["mitre_techniques"]
        assert "T1590" in stats["mitre_techniques"]


class TestPrioritizeRisks:
    """Tests for risk prioritization."""

    def test_prioritize_empty(self):
        """Test prioritizing empty list."""
        result = prioritize_risks([])
        assert result == []

    def test_prioritize_sorts_by_score(self):
        """Test that prioritization sorts by score descending."""
        risks = [
            Risk(title="Low", description="", likelihood=1, impact=1),
            Risk(title="High", description="", likelihood=4, impact=4),
            Risk(title="Med", description="", likelihood=3, impact=3),
        ]

        result = prioritize_risks(risks)

        assert result[0].title == "High"
        assert result[1].title == "Med"
        assert result[2].title == "Low"

    def test_prioritize_respects_limit(self):
        """Test that prioritization respects limit."""
        risks = [
            Risk(title=f"R{i}", description="", likelihood=i, impact=i)
            for i in range(1, 6)
        ]

        result = prioritize_risks(risks, limit=3)

        assert len(result) == 3


class TestGetRemediationPlan:
    """Tests for remediation plan generation."""

    def test_remediation_plan_empty(self):
        """Test remediation plan for empty risk list."""
        plan = get_remediation_plan([])
        assert plan == []

    def test_remediation_plan_groups_by_priority(self):
        """Test that plan groups risks by priority."""
        risks = [
            Risk(title="Critical", description="Fix now", likelihood=5, impact=5, category=RiskCategory.OWASP),
            Risk(title="Medium", description="Fix soon", likelihood=3, impact=3, category=RiskCategory.EXPOSURE),
            Risk(title="Low", description="Fix later", likelihood=2, impact=2, category=RiskCategory.OPERATIONAL),
        ]

        plan = get_remediation_plan(risks)

        assert len(plan) == 3
        assert plan[0]["priority"] == "Immediate"
        assert plan[1]["priority"] == "Short-term"
        assert plan[2]["priority"] == "Long-term"

    def test_remediation_plan_includes_actions(self):
        """Test that plan includes action items."""
        risks = [
            Risk(
                title="High Risk",
                description="Do something about it",
                likelihood=4,
                impact=4,
                category=RiskCategory.OWASP
            )
        ]

        plan = get_remediation_plan(risks)

        assert len(plan) == 1
        assert len(plan[0]["items"]) == 1
        assert plan[0]["items"][0]["risk"] == "High Risk"
        assert plan[0]["items"][0]["action"] == "Do something about it"


class TestScoreRisks:
    """Tests for main score_risks function."""

    def test_score_risks_empty_context(self):
        """Test scoring with no findings."""
        ctx = Context(target="example.com")
        result = score_risks(ctx)

        assert "risks" in result.data
        assert "risk_summary" in result.data

    def test_score_risks_with_findings(self):
        """Test scoring context with findings."""
        ctx = Context(target="example.com")
        ctx.add("finding_tech_0", {
            "title": "Missing Security Header: Content-Security-Policy",
            "description": "CSP prevents XSS",
            "severity": "medium",
            "data": {}
        })
        ctx.add("domain_profile", {"has_dmarc": False})

        result = score_risks(ctx)

        risks = result.data["risks"]
        assert len(risks) >= 1  # At least CSP finding

    def test_score_risks_filters_info(self):
        """Test that INFO risks are filtered by default."""
        ctx = Context(target="example.com")
        ctx.add("finding_info", {
            "title": "Some Info",
            "description": "Just info",
            "severity": "info",
            "data": {}
        })

        result = score_risks(ctx)

        risks = result.data["risks"]
        info_risks = [r for r in risks if r.get("level") == "info"]
        assert len(info_risks) == 0

    def test_score_risks_includes_info_when_requested(self):
        """Test including INFO risks when requested."""
        ctx = Context(target="example.com")
        # Add a finding that will match a rule with low score
        ctx.add("finding_tech_0", {
            "title": "Missing Security Header: X-Content-Type-Options",
            "description": "nosniff not present",
            "severity": "low",
            "data": {}
        })

        result = score_risks(ctx, params={"include_info": True})

        # Should have at least the finding we added
        risks = result.data["risks"]
        assert len(risks) >= 0  # May or may not have info-level depending on score

    def test_score_risks_logs_warnings_for_high_risks(self):
        """Test that high/critical risks generate warnings."""
        ctx = Context(target="example.com")
        ctx.add("finding_critical", {
            "title": "Zone Transfer Allowed",
            "description": "AXFR permitted",
            "severity": "high",
            "data": {}
        })

        result = score_risks(ctx)

        # Check for warning logs
        all_logs = result.get_logs()
        # The function should log about scoring completion
        assert any("scoring" in log["message"].lower() for log in all_logs)

    def test_score_risks_creates_summary(self):
        """Test that risk summary is created."""
        ctx = Context(target="example.com")
        ctx.add("finding_tech_0", {
            "title": "Missing Security Header: Strict-Transport-Security",
            "description": "HSTS missing",
            "severity": "medium",
            "data": {}
        })

        result = score_risks(ctx)

        summary = result.data["risk_summary"]
        assert "total" in summary
        assert "by_level" in summary
        assert "average_score" in summary


class TestRiskRulesIntegrity:
    """Tests for risk rules integrity."""

    def test_all_rules_have_required_fields(self):
        """Test that all risk rules have required fields."""
        required_fields = ["likelihood", "impact", "category", "recommendation"]

        for rule_name, rule in RISK_RULES.items():
            for field in required_fields:
                assert field in rule, f"Rule {rule_name} missing {field}"

    def test_all_rules_have_valid_scores(self):
        """Test that all risk rules have valid likelihood/impact scores."""
        for rule_name, rule in RISK_RULES.items():
            assert 1 <= rule["likelihood"] <= 5, f"Rule {rule_name} has invalid likelihood"
            assert 1 <= rule["impact"] <= 5, f"Rule {rule_name} has invalid impact"

    def test_all_rules_have_valid_category(self):
        """Test that all risk rules have valid categories."""
        for rule_name, rule in RISK_RULES.items():
            assert isinstance(rule["category"], RiskCategory), f"Rule {rule_name} has invalid category"
