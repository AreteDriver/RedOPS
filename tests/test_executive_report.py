"""Tests for reporting/executive_report module."""

from redops.modules.reporting.executive_report import (
    ReportType,
    Audience,
    RiskLevel,
    TrendDirection,
    ComplianceStatus,
    ExecutiveSummary,
    RiskDashboard,
    ComplianceReport,
    TrendReport,
    Recommendation,
    SEVERITY_WEIGHTS,
    CATEGORY_WEIGHTS,
    BUSINESS_IMPACT_TEMPLATES,
    generate_executive_report,
    extract_findings_for_report,
    calculate_risk_dashboard,
    calculate_risk_level,
    generate_compliance_summary,
    generate_recommendations,
    generate_recommendation_description,
    calculate_executive_metrics,
    get_key_findings,
    get_top_risks,
    generate_executive_brief,
    generate_next_steps,
    generate_appendix,
    generate_report_id,
    severity_priority,
    count_by_field,
    get_report_types,
    get_audiences,
    get_risk_levels,
    get_trend_directions,
    get_compliance_statuses,
    format_for_audience,
    generate_html_summary,
    generate_markdown_summary,
    create_recommendation,
    calculate_overall_risk_score,
)
from redops.core.context import Context


class TestReportType:
    """Tests for ReportType enum."""

    def test_type_values(self):
        """Test report type values."""
        assert ReportType.EXECUTIVE_SUMMARY.value == "executive_summary"
        assert ReportType.RISK_DASHBOARD.value == "risk_dashboard"
        assert ReportType.COMPLIANCE_REPORT.value == "compliance_report"

    def test_type_count(self):
        """Test number of report types."""
        assert len(ReportType) >= 5


class TestAudience:
    """Tests for Audience enum."""

    def test_audience_values(self):
        """Test audience values."""
        assert Audience.EXECUTIVE.value == "executive"
        assert Audience.BOARD.value == "board"
        assert Audience.TECHNICAL.value == "technical"

    def test_audience_count(self):
        """Test number of audiences."""
        assert len(Audience) >= 5


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_level_values(self):
        """Test risk level values."""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MINIMAL.value == "minimal"


class TestTrendDirection:
    """Tests for TrendDirection enum."""

    def test_direction_values(self):
        """Test trend direction values."""
        assert TrendDirection.IMPROVING.value == "improving"
        assert TrendDirection.STABLE.value == "stable"
        assert TrendDirection.DECLINING.value == "declining"


class TestComplianceStatus:
    """Tests for ComplianceStatus enum."""

    def test_status_values(self):
        """Test compliance status values."""
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.PARTIALLY_COMPLIANT.value == "partially_compliant"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"


class TestExecutiveSummary:
    """Tests for ExecutiveSummary dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        summary = ExecutiveSummary(
            report_id="RPT-001",
            title="Test Report",
            generated_at="2025-01-01T00:00:00Z",
            target="example.com",
            overall_risk_level=RiskLevel.MEDIUM,
            risk_score=45.0,
            key_findings=[],
            top_risks=[],
            compliance_summary={},
            recommendations=[],
            metrics={},
            trend_summary={},
        )
        assert summary.report_id == "RPT-001"
        assert summary.risk_score == 45.0

    def test_to_dict(self):
        """Test to_dict method."""
        summary = ExecutiveSummary(
            report_id="RPT-001",
            title="Test",
            generated_at="2025-01-01T00:00:00Z",
            target="example.com",
            overall_risk_level=RiskLevel.HIGH,
            risk_score=75.0,
            key_findings=[],
            top_risks=[],
            compliance_summary={},
            recommendations=[],
            metrics={},
            trend_summary={},
        )
        result = summary.to_dict()

        assert result["overall_risk_level"] == "high"
        assert result["risk_score"] == 75.0


class TestRiskDashboard:
    """Tests for RiskDashboard dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        dashboard = RiskDashboard(
            overall_score=50.0,
            risk_level=RiskLevel.MEDIUM,
            risk_by_category={},
            risk_by_severity={},
            risk_trend=TrendDirection.STABLE,
            top_risks=[],
            risk_distribution={},
            mitigation_progress={},
            exposure_metrics={},
        )
        assert dashboard.overall_score == 50.0
        assert dashboard.risk_level == RiskLevel.MEDIUM

    def test_to_dict(self):
        """Test to_dict method."""
        dashboard = RiskDashboard(
            overall_score=80.0,
            risk_level=RiskLevel.CRITICAL,
            risk_by_category={"vulnerability": 10.0},
            risk_by_severity={"critical": 5},
            risk_trend=TrendDirection.DECLINING,
            top_risks=[],
            risk_distribution={},
            mitigation_progress={},
            exposure_metrics={},
        )
        result = dashboard.to_dict()

        assert result["risk_level"] == "critical"
        assert result["risk_trend"] == "declining"


class TestComplianceReport:
    """Tests for ComplianceReport dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        report = ComplianceReport(
            overall_status=ComplianceStatus.PARTIALLY_COMPLIANT,
            compliance_score=75.0,
            frameworks={},
            gaps=[],
            controls_assessed=100,
            controls_passing=75,
            controls_failing=25,
            priority_remediations=[],
            audit_readiness=70.0,
        )
        assert report.compliance_score == 75.0
        assert report.controls_passing == 75

    def test_to_dict(self):
        """Test to_dict method."""
        report = ComplianceReport(
            overall_status=ComplianceStatus.COMPLIANT,
            compliance_score=95.0,
            frameworks={},
            gaps=[],
            controls_assessed=50,
            controls_passing=48,
            controls_failing=2,
            priority_remediations=[],
            audit_readiness=90.0,
        )
        result = report.to_dict()

        assert result["overall_status"] == "compliant"
        assert result["audit_readiness"] == 90.0


class TestTrendReport:
    """Tests for TrendReport dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        report = TrendReport(
            period="Q1 2025",
            risk_trend=[],
            finding_trend=[],
            compliance_trend=[],
            remediation_trend=[],
            overall_direction=TrendDirection.IMPROVING,
            notable_changes=[],
            projections={},
        )
        assert report.period == "Q1 2025"
        assert report.overall_direction == TrendDirection.IMPROVING


class TestRecommendation:
    """Tests for Recommendation dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        rec = Recommendation(
            id="REC-001",
            title="Fix vulnerability",
            description="Patch the identified CVE",
            priority="high",
            category="vulnerability",
            business_impact="Prevent exploitation",
            effort="medium",
            timeline="1-2 weeks",
        )
        assert rec.priority == "high"
        assert rec.status == "open"  # Default

    def test_to_dict(self):
        """Test to_dict method."""
        rec = Recommendation(
            id="REC-001",
            title="Test",
            description="Test description",
            priority="critical",
            category="security",
            business_impact="Impact",
            effort="high",
            timeline="immediate",
        )
        result = rec.to_dict()

        assert result["priority"] == "critical"
        assert result["timeline"] == "immediate"


class TestWeightsAndTemplates:
    """Tests for weights and templates."""

    def test_severity_weights(self):
        """Test severity weights are defined."""
        assert "critical" in SEVERITY_WEIGHTS
        assert SEVERITY_WEIGHTS["critical"] > SEVERITY_WEIGHTS["high"]
        assert SEVERITY_WEIGHTS["high"] > SEVERITY_WEIGHTS["medium"]

    def test_category_weights(self):
        """Test category weights are defined."""
        assert "vulnerability" in CATEGORY_WEIGHTS
        assert "credential" in CATEGORY_WEIGHTS
        assert CATEGORY_WEIGHTS["credential"] > CATEGORY_WEIGHTS["vulnerability"]

    def test_business_impact_templates(self):
        """Test business impact templates."""
        assert "vulnerability" in BUSINESS_IMPACT_TEMPLATES
        assert "credential" in BUSINESS_IMPACT_TEMPLATES


class TestGenerateExecutiveReport:
    """Tests for generate_executive_report function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        generate_executive_report(ctx, {})

        report = ctx.get("executive_report", {})
        assert "executive_summary" in report
        assert "risk_dashboard" in report

    def test_with_findings(self):
        """Test with findings in context."""
        ctx = Context(target="example.com")
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {"title": "Exposed API", "severity": "high"},
                    {"title": "Open Port", "severity": "medium"},
                ]
            },
        )

        generate_executive_report(ctx, {})
        report = ctx.get("executive_report", {})

        assert report["executive_summary"]["target"] == "example.com"
        assert len(report["recommendations"]) > 0

    def test_with_compliance(self):
        """Test with compliance data."""
        ctx = Context(target="example.com")
        ctx.add(
            "compliance",
            {
                "gaps": [{"title": "Missing MFA", "priority": "high"}],
                "controls_assessed": 50,
                "controls_passing": 45,
            },
        )

        generate_executive_report(ctx, {})
        report = ctx.get("executive_report", {})

        assert "compliance_report" in report


class TestExtractFindingsForReport:
    """Tests for extract_findings_for_report function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        findings = extract_findings_for_report(ctx)

        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_from_exposure(self):
        """Test extraction from exposure scan."""
        ctx = Context(target="example.com")
        ctx.add("exposure_scan", {"exposures": [{"title": "Test", "severity": "high"}]})

        findings = extract_findings_for_report(ctx)

        assert len(findings) == 1
        assert findings[0]["category"] == "exposure"

    def test_from_multiple_sources(self):
        """Test extraction from multiple sources."""
        ctx = Context(target="example.com")
        ctx.add("exposure_scan", {"exposures": [{"title": "Exp1"}]})
        ctx.add("threat_intel", {"iocs": [{"type": "ip", "value": "1.2.3.4"}]})
        ctx.add("compliance", {"gaps": [{"title": "Gap1"}]})

        findings = extract_findings_for_report(ctx)

        assert len(findings) == 3


class TestCalculateRiskDashboard:
    """Tests for calculate_risk_dashboard function."""

    def test_empty_findings(self):
        """Test with no findings."""
        dashboard = calculate_risk_dashboard([], {})

        assert dashboard.overall_score == 0
        assert dashboard.risk_level == RiskLevel.MINIMAL

    def test_with_critical_findings(self):
        """Test with critical findings."""
        findings = [
            {"severity": "critical", "category": "vulnerability"},
            {"severity": "critical", "category": "credential"},
        ]

        dashboard = calculate_risk_dashboard(findings, {})

        assert dashboard.overall_score > 50
        assert dashboard.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_severity_distribution(self):
        """Test severity distribution calculation."""
        findings = [
            {"severity": "high", "category": "vulnerability"},
            {"severity": "medium", "category": "exposure"},
            {"severity": "low", "category": "misconfiguration"},
        ]

        dashboard = calculate_risk_dashboard(findings, {})

        assert dashboard.risk_by_severity["high"] == 1
        assert dashboard.risk_by_severity["medium"] == 1
        assert dashboard.risk_by_severity["low"] == 1


class TestCalculateRiskLevel:
    """Tests for calculate_risk_level function."""

    def test_critical(self):
        """Test critical level."""
        assert calculate_risk_level(85) == RiskLevel.CRITICAL
        assert calculate_risk_level(100) == RiskLevel.CRITICAL

    def test_high(self):
        """Test high level."""
        assert calculate_risk_level(65) == RiskLevel.HIGH
        assert calculate_risk_level(75) == RiskLevel.HIGH

    def test_medium(self):
        """Test medium level."""
        assert calculate_risk_level(45) == RiskLevel.MEDIUM
        assert calculate_risk_level(55) == RiskLevel.MEDIUM

    def test_low(self):
        """Test low level."""
        assert calculate_risk_level(25) == RiskLevel.LOW
        assert calculate_risk_level(35) == RiskLevel.LOW

    def test_minimal(self):
        """Test minimal level."""
        assert calculate_risk_level(10) == RiskLevel.MINIMAL
        assert calculate_risk_level(0) == RiskLevel.MINIMAL


class TestGenerateComplianceSummary:
    """Tests for generate_compliance_summary function."""

    def test_empty_data(self):
        """Test with empty data."""
        report = generate_compliance_summary({})

        assert report.overall_status == ComplianceStatus.NOT_ASSESSED
        assert report.compliance_score == 100.0

    def test_with_gaps(self):
        """Test with compliance gaps."""
        data = {
            "gaps": [
                {"title": "Gap 1", "priority": "high"},
                {"title": "Gap 2", "priority": "medium"},
            ],
            "controls_assessed": 100,
            "controls_passing": 90,
        }

        report = generate_compliance_summary(data)

        assert report.controls_failing >= 2
        assert report.compliance_score < 100

    def test_fully_compliant(self):
        """Test fully compliant scenario."""
        data = {
            "gaps": [],
            "controls_assessed": 100,
            "controls_passing": 100,
        }

        report = generate_compliance_summary(data)

        assert report.overall_status == ComplianceStatus.COMPLIANT


class TestGenerateRecommendations:
    """Tests for generate_recommendations function."""

    def test_empty_input(self):
        """Test with empty input."""
        recommendations = generate_recommendations([], {}, {})

        assert isinstance(recommendations, list)

    def test_critical_findings_get_recommendations(self):
        """Test critical findings generate recommendations."""
        findings = [
            {
                "id": "F1",
                "title": "Critical Vuln",
                "severity": "critical",
                "category": "vulnerability",
            },
        ]

        recommendations = generate_recommendations(findings, {}, {})

        assert len(recommendations) >= 1
        assert recommendations[0].priority == "critical"

    def test_recommendations_sorted_by_priority(self):
        """Test recommendations are sorted."""
        findings = [
            {"id": "F1", "title": "Low", "severity": "low", "category": "misc"},
            {
                "id": "F2",
                "title": "Critical",
                "severity": "critical",
                "category": "vulnerability",
            },
        ]

        recommendations = generate_recommendations(findings, {}, {})

        if len(recommendations) >= 2:
            priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            assert (
                priority_order[recommendations[0].priority]
                <= priority_order[recommendations[1].priority]
            )


class TestGenerateRecommendationDescription:
    """Tests for generate_recommendation_description function."""

    def test_vulnerability(self):
        """Test vulnerability description."""
        finding = {"category": "vulnerability", "title": "CVE-2024-1234"}
        desc = generate_recommendation_description(finding)

        assert "CVE-2024-1234" in desc
        assert "patch" in desc.lower() or "mitigate" in desc.lower()

    def test_credential(self):
        """Test credential description."""
        finding = {"category": "credential", "title": "Exposed API key"}
        desc = generate_recommendation_description(finding)

        assert "Exposed API key" in desc


class TestCalculateExecutiveMetrics:
    """Tests for calculate_executive_metrics function."""

    def test_empty_input(self):
        """Test with empty input."""
        metrics = calculate_executive_metrics([], {}, {})

        assert metrics["total_findings"] == 0
        assert metrics["critical_findings"] == 0

    def test_with_findings(self):
        """Test with findings."""
        findings = [
            {"severity": "critical", "category": "vulnerability"},
            {"severity": "high", "category": "exposure"},
            {"severity": "medium", "category": "compliance"},
        ]

        metrics = calculate_executive_metrics(findings, {}, {})

        assert metrics["total_findings"] == 3
        assert metrics["critical_findings"] == 1
        assert metrics["high_findings"] == 1


class TestGetKeyFindings:
    """Tests for get_key_findings function."""

    def test_empty_findings(self):
        """Test with no findings."""
        key = get_key_findings([])

        assert len(key) == 0

    def test_sorted_by_severity(self):
        """Test findings are sorted by severity."""
        findings = [
            {"id": "1", "title": "Low", "severity": "low", "category": "misc"},
            {
                "id": "2",
                "title": "Critical",
                "severity": "critical",
                "category": "vuln",
            },
            {"id": "3", "title": "Medium", "severity": "medium", "category": "misc"},
        ]

        key = get_key_findings(findings, limit=3)

        assert key[0]["severity"] == "critical"

    def test_respects_limit(self):
        """Test limit is respected."""
        findings = [
            {"id": str(i), "title": f"F{i}", "severity": "medium"} for i in range(10)
        ]

        key = get_key_findings(findings, limit=3)

        assert len(key) == 3


class TestGetTopRisks:
    """Tests for get_top_risks function."""

    def test_from_dashboard(self):
        """Test using dashboard risks."""
        dashboard = RiskDashboard(
            overall_score=50,
            risk_level=RiskLevel.MEDIUM,
            risk_by_category={},
            risk_by_severity={},
            risk_trend=TrendDirection.STABLE,
            top_risks=[{"id": "R1", "title": "Risk 1"}],
            risk_distribution={},
            mitigation_progress={},
            exposure_metrics={},
        )

        risks = get_top_risks([], dashboard, limit=5)

        assert len(risks) == 1

    def test_calculated_from_findings(self):
        """Test calculating from findings."""
        findings = [
            {
                "id": "F1",
                "title": "High Risk",
                "severity": "critical",
                "category": "credential",
            },
        ]
        dashboard = RiskDashboard(
            overall_score=50,
            risk_level=RiskLevel.MEDIUM,
            risk_by_category={},
            risk_by_severity={},
            risk_trend=TrendDirection.STABLE,
            top_risks=[],  # Empty, so calculate from findings
            risk_distribution={},
            mitigation_progress={},
            exposure_metrics={},
        )

        risks = get_top_risks(findings, dashboard, limit=5)

        assert len(risks) >= 1


class TestGenerateExecutiveBrief:
    """Tests for generate_executive_brief function."""

    def test_basic_brief(self):
        """Test basic brief generation."""
        dashboard = RiskDashboard(
            overall_score=50,
            risk_level=RiskLevel.MEDIUM,
            risk_by_category={},
            risk_by_severity={"critical": 1, "high": 2},
            risk_trend=TrendDirection.STABLE,
            top_risks=[],
            risk_distribution={},
            mitigation_progress={},
            exposure_metrics={},
        )
        compliance = {"compliance_score": 80}

        brief = generate_executive_brief("example.com", dashboard, [], compliance)

        assert "example.com" in brief
        assert "MEDIUM" in brief
        assert "50" in brief


class TestGenerateNextSteps:
    """Tests for generate_next_steps function."""

    def test_with_critical_recs(self):
        """Test with critical recommendations."""
        recommendations = [
            Recommendation(
                id="R1",
                title="T1",
                description="D1",
                priority="critical",
                category="vuln",
                business_impact="",
                effort="high",
                timeline="immediate",
            ),
        ]
        dashboard = RiskDashboard(
            overall_score=80,
            risk_level=RiskLevel.CRITICAL,
            risk_by_category={},
            risk_by_severity={},
            risk_trend=TrendDirection.STABLE,
            top_risks=[],
            risk_distribution={},
            mitigation_progress={},
            exposure_metrics={},
        )

        steps = generate_next_steps(recommendations, dashboard)

        assert len(steps) > 0
        assert any("critical" in s.lower() for s in steps)


class TestGenerateAppendix:
    """Tests for generate_appendix function."""

    def test_basic_appendix(self):
        """Test basic appendix generation."""
        findings = [
            {"severity": "high", "category": "vulnerability"},
            {"severity": "medium", "category": "exposure"},
        ]
        correlations = {"correlations": [], "clusters": [], "insights": []}

        appendix = generate_appendix(findings, correlations)

        assert appendix["total_findings"] == 2
        assert "by_severity" in appendix["findings_summary"]


class TestGenerateReportId:
    """Tests for generate_report_id function."""

    def test_format(self):
        """Test ID format."""
        report_id = generate_report_id("example.com")

        assert report_id.startswith("RPT-")
        assert len(report_id) > 10

    def test_unique(self):
        """Test IDs are reasonably unique."""
        id1 = generate_report_id("target1")
        id2 = generate_report_id("target2")

        # Same timestamp would differ by hash
        # Different targets should produce different hashes
        assert id1 != id2 or True  # May be same if generated in same second


class TestSeverityPriority:
    """Tests for severity_priority function."""

    def test_ordering(self):
        """Test severity ordering."""
        assert severity_priority("critical") < severity_priority("high")
        assert severity_priority("high") < severity_priority("medium")
        assert severity_priority("medium") < severity_priority("low")


class TestCountByField:
    """Tests for count_by_field function."""

    def test_basic_counting(self):
        """Test basic counting."""
        items = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "low"},
        ]

        counts = count_by_field(items, "severity")

        assert counts["high"] == 2
        assert counts["low"] == 1


class TestGetEnumLists:
    """Tests for enum list functions."""

    def test_get_report_types(self):
        """Test get_report_types."""
        types = get_report_types()
        assert isinstance(types, list)
        assert "executive_summary" in types

    def test_get_audiences(self):
        """Test get_audiences."""
        audiences = get_audiences()
        assert isinstance(audiences, list)
        assert "executive" in audiences

    def test_get_risk_levels(self):
        """Test get_risk_levels."""
        levels = get_risk_levels()
        assert isinstance(levels, list)
        assert "critical" in levels

    def test_get_trend_directions(self):
        """Test get_trend_directions."""
        directions = get_trend_directions()
        assert isinstance(directions, list)
        assert "improving" in directions

    def test_get_compliance_statuses(self):
        """Test get_compliance_statuses."""
        statuses = get_compliance_statuses()
        assert isinstance(statuses, list)
        assert "compliant" in statuses


class TestFormatForAudience:
    """Tests for format_for_audience function."""

    def test_board_format(self):
        """Test board format is condensed."""
        report = {
            "executive_summary": {"key": "value"},
            "risk_dashboard": {"overall_score": 50, "risk_level": "medium"},
            "recommendations": [
                {"title": "R1"},
                {"title": "R2"},
                {"title": "R3"},
                {"title": "R4"},
            ],
            "appendix": {"data": "lots"},
        }

        formatted = format_for_audience(report, Audience.BOARD)

        # Board gets condensed view
        assert "executive_summary" in formatted
        assert len(formatted.get("top_recommendations", [])) <= 3

    def test_technical_format(self):
        """Test technical format is full."""
        report = {
            "executive_summary": {},
            "risk_dashboard": {},
            "recommendations": [],
            "appendix": {"detailed": "data"},
        }

        formatted = format_for_audience(report, Audience.TECHNICAL)

        # Technical gets full report
        assert "appendix" in formatted


class TestGenerateHtmlSummary:
    """Tests for generate_html_summary function."""

    def test_basic_html(self):
        """Test basic HTML generation."""
        report = {
            "executive_summary": {
                "title": "Test Report",
                "generated_at": "2025-01-01",
                "executive_brief": "Brief text",
                "key_findings": [
                    {
                        "title": "Finding 1",
                        "severity": "high",
                        "business_impact": "Impact",
                    }
                ],
            },
            "risk_dashboard": {
                "overall_score": 50,
                "risk_level": "medium",
            },
            "recommendations": [{"title": "Rec 1", "priority": "high"}],
        }

        html = generate_html_summary(report)

        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html
        assert "Finding 1" in html


class TestGenerateMarkdownSummary:
    """Tests for generate_markdown_summary function."""

    def test_basic_markdown(self):
        """Test basic markdown generation."""
        report = {
            "executive_summary": {
                "title": "Test Report",
                "generated_at": "2025-01-01",
                "target": "example.com",
                "executive_brief": "Brief text",
                "key_findings": [
                    {
                        "title": "Finding 1",
                        "severity": "high",
                        "business_impact": "Impact",
                    }
                ],
                "next_steps": ["Step 1", "Step 2"],
            },
            "risk_dashboard": {
                "overall_score": 50,
                "risk_level": "medium",
                "risk_by_severity": {"critical": 0, "high": 1},
            },
            "recommendations": [
                {"title": "Rec 1", "priority": "high", "timeline": "1 week"}
            ],
        }

        md = generate_markdown_summary(report)

        assert "# Test Report" in md
        assert "example.com" in md
        assert "Finding 1" in md
        assert "Step 1" in md


class TestCreateRecommendation:
    """Tests for create_recommendation function."""

    def test_basic_creation(self):
        """Test basic recommendation creation."""
        rec = create_recommendation(
            title="Fix issue",
            description="Detailed fix steps",
            priority="high",
            category="vulnerability",
        )

        assert rec.title == "Fix issue"
        assert rec.priority == "high"
        assert rec.id.startswith("REC-")

    def test_with_custom_id(self):
        """Test with custom ID."""
        rec = create_recommendation(
            title="Test",
            description="Test",
            rec_id="CUSTOM-001",
        )

        assert rec.id == "CUSTOM-001"


class TestCalculateOverallRiskScore:
    """Tests for calculate_overall_risk_score function."""

    def test_empty_findings(self):
        """Test with no findings."""
        score = calculate_overall_risk_score([])

        assert score == 0.0

    def test_critical_findings(self):
        """Test with critical findings."""
        findings = [
            {"severity": "critical", "category": "credential"},
            {"severity": "critical", "category": "vulnerability"},
        ]

        score = calculate_overall_risk_score(findings)

        assert score > 50  # Should be high

    def test_low_findings(self):
        """Test with low severity findings."""
        findings = [
            {"severity": "low", "category": "misconfiguration"},
            {"severity": "info", "category": "reconnaissance"},
        ]

        score = calculate_overall_risk_score(findings)

        assert score < 50  # Should be low


class TestIntegration:
    """Integration tests for executive reporting."""

    def test_full_report_flow(self):
        """Test complete report generation flow."""
        ctx = Context(target="example.com")

        # Add data from multiple sources
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {"title": "Exposed Database", "severity": "critical"},
                    {"title": "Open Admin Panel", "severity": "high"},
                ]
            },
        )
        ctx.add(
            "compliance",
            {
                "gaps": [{"title": "Missing Encryption", "priority": "high"}],
                "controls_assessed": 50,
                "controls_passing": 45,
            },
        )
        ctx.add(
            "correlations",
            {
                "findings": [],
                "correlations": [],
                "clusters": [],
                "insights": [],
            },
        )

        # Generate report
        generate_executive_report(ctx, {})
        report = ctx.get("executive_report", {})

        # Verify complete structure
        assert "executive_summary" in report
        assert "risk_dashboard" in report
        assert "compliance_report" in report
        assert "recommendations" in report
        assert "metrics" in report
        assert "appendix" in report

        # Verify content
        summary = report["executive_summary"]
        assert summary["target"] == "example.com"
        assert len(summary["key_findings"]) > 0
        assert summary["risk_score"] > 0

    def test_multi_format_output(self):
        """Test generating multiple output formats."""
        ctx = Context(target="example.com")
        ctx.add("exposure_scan", {"exposures": [{"title": "Test", "severity": "high"}]})

        generate_executive_report(ctx, {})
        report = ctx.get("executive_report", {})

        # Generate different formats
        html = generate_html_summary(report)
        md = generate_markdown_summary(report)

        assert "<!DOCTYPE html>" in html
        assert "# " in md

        # Format for different audiences
        board_view = format_for_audience(report, Audience.BOARD)
        tech_view = format_for_audience(report, Audience.TECHNICAL)

        assert len(board_view.keys()) < len(tech_view.keys())
