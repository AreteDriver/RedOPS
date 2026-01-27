"""Tests for the dashboard widgets module."""

from collections import Counter
from redops.core.context import Context
from redops.web.dashboard_widgets import (
    get_risk_summary,
    calculate_risk_score,
    get_findings_timeline,
    get_module_stats,
    get_attack_surface_summary,
    calculate_exposure_score,
    get_compliance_status,
    get_threat_intel_summary,
    calculate_threat_level,
    generate_dashboard_data,
    get_recent_findings,
    normalize_severity,
    format_dashboard_html,
    get_score_class,
)


class TestGetRiskSummary:
    """Tests for get_risk_summary function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        summary = get_risk_summary(ctx)

        assert summary["total"] == 0
        assert summary["critical"] == 0
        assert summary["risk_score"] == 0

    def test_with_risks(self):
        """Test with risks present."""
        ctx = Context()
        ctx.add(
            "risks",
            [
                {"title": "Critical Issue", "level": "critical"},
                {"title": "High Issue", "level": "high"},
                {"title": "Medium Issue", "level": "medium"},
            ],
        )

        summary = get_risk_summary(ctx)

        assert summary["total"] == 3
        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1

    def test_percentages(self):
        """Test percentage calculations."""
        ctx = Context()
        ctx.add(
            "risks",
            [
                {"level": "high"},
                {"level": "high"},
                {"level": "medium"},
                {"level": "medium"},
            ],
        )

        summary = get_risk_summary(ctx)

        assert summary["percentages"]["high"] == 50.0
        assert summary["percentages"]["medium"] == 50.0


class TestCalculateRiskScore:
    """Tests for calculate_risk_score function."""

    def test_zero_score(self):
        """Test with no risks."""
        score = calculate_risk_score(Counter())

        assert score == 0

    def test_critical_weights_heavily(self):
        """Test that critical risks weight heavily."""
        score_critical = calculate_risk_score(Counter({"critical": 1}))
        score_low = calculate_risk_score(Counter({"low": 1}))

        assert score_critical > score_low

    def test_caps_at_100(self):
        """Test that score is capped at 100."""
        score = calculate_risk_score(Counter({"critical": 10, "high": 10}))

        assert score == 100


class TestGetFindingsTimeline:
    """Tests for get_findings_timeline function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        timeline = get_findings_timeline(ctx, days=7)

        assert len(timeline) == 8  # 7 days + today
        assert all(t["total"] == 0 for t in timeline)

    def test_timeline_structure(self):
        """Test timeline entry structure."""
        ctx = Context()

        timeline = get_findings_timeline(ctx, days=1)

        assert "date" in timeline[0]
        assert "total" in timeline[0]
        assert "critical" in timeline[0]


class TestGetModuleStats:
    """Tests for get_module_stats function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        stats = get_module_stats(ctx)

        assert len(stats) == 0

    def test_groups_by_module(self):
        """Test findings are grouped by module."""
        ctx = Context()
        ctx.add("finding_0", {"module": "module_a", "title": "F1", "severity": "high"})
        ctx.add("finding_1", {"module": "module_a", "title": "F2", "severity": "low"})
        ctx.add(
            "finding_2", {"module": "module_b", "title": "F3", "severity": "medium"}
        )

        stats = get_module_stats(ctx)

        assert len(stats) == 2
        module_a_stats = next(s for s in stats if s["module"] == "module_a")
        assert module_a_stats["total_findings"] == 2

    def test_sorted_by_count(self):
        """Test stats are sorted by finding count."""
        ctx = Context()
        ctx.add("finding_0", {"module": "few", "severity": "high"})
        ctx.add("finding_1", {"module": "many", "severity": "high"})
        ctx.add("finding_2", {"module": "many", "severity": "high"})
        ctx.add("finding_3", {"module": "many", "severity": "high"})

        stats = get_module_stats(ctx)

        assert stats[0]["module"] == "many"


class TestGetAttackSurfaceSummary:
    """Tests for get_attack_surface_summary function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        summary = get_attack_surface_summary(ctx)

        assert summary["subdomains_count"] == 0
        assert summary["exposure_score"] == 0

    def test_with_subdomains(self):
        """Test with subdomains present."""
        ctx = Context()
        ctx.add("subdomains", ["www.example.com", "api.example.com"])

        summary = get_attack_surface_summary(ctx)

        assert summary["subdomains_count"] == 2


class TestCalculateExposureScore:
    """Tests for calculate_exposure_score function."""

    def test_zero_exposure(self):
        """Test with no exposure."""
        score = calculate_exposure_score(0, 0, 0)

        assert score == 0

    def test_exposure_increases(self):
        """Test that more assets increases score."""
        low_score = calculate_exposure_score(5, 2, 1)
        high_score = calculate_exposure_score(50, 20, 10)

        assert high_score > low_score

    def test_caps_at_100(self):
        """Test that score is capped at 100."""
        score = calculate_exposure_score(1000, 1000, 1000)

        assert score == 100


class TestGetComplianceStatus:
    """Tests for get_compliance_status function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        status = get_compliance_status(ctx)

        assert status["total_controls"] == 0
        assert status["pass_rate"] == 100

    def test_with_risks(self):
        """Test compliance derived from risks."""
        ctx = Context()
        ctx.add(
            "risks",
            [
                {"level": "critical"},
                {"level": "high"},
                {"level": "medium"},
                {"level": "low"},
            ],
        )

        status = get_compliance_status(ctx)

        assert status["failed"] == 2  # critical + high
        assert status["warnings"] == 1  # medium


class TestGetThreatIntelSummary:
    """Tests for get_threat_intel_summary function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        summary = get_threat_intel_summary(ctx)

        assert summary["total_indicators"] == 0
        assert summary["threat_level"] == "low"

    def test_with_greynoise_noise(self):
        """Test with GreyNoise noise detection."""
        ctx = Context()
        ctx.add("greynoise_result", {"noise": True, "classification": "malicious"})

        summary = get_threat_intel_summary(ctx)

        assert summary["total_indicators"] == 1
        assert summary["threat_level"] == "high"

    def test_with_abuseipdb_high_score(self):
        """Test with high AbuseIPDB score."""
        ctx = Context()
        ctx.add("abuseipdb_result", {"abuseConfidenceScore": 80})

        summary = get_threat_intel_summary(ctx)

        assert summary["total_indicators"] == 1


class TestCalculateThreatLevel:
    """Tests for calculate_threat_level function."""

    def test_no_indicators(self):
        """Test with no indicators."""
        assert calculate_threat_level([]) == "low"

    def test_critical_indicator(self):
        """Test with critical indicator."""
        indicators = [{"severity": "critical"}]
        assert calculate_threat_level(indicators) == "critical"

    def test_mixed_severities(self):
        """Test with mixed severities."""
        indicators = [{"severity": "low"}, {"severity": "high"}]
        assert calculate_threat_level(indicators) == "high"


class TestGenerateDashboardData:
    """Tests for generate_dashboard_data function."""

    def test_structure(self):
        """Test dashboard data structure."""
        ctx = Context(target="example.com")

        data = generate_dashboard_data(ctx)

        assert data["target"] == "example.com"
        assert "timestamp" in data
        assert "risk_summary" in data
        assert "attack_surface" in data
        assert "module_stats" in data
        assert "compliance" in data
        assert "threat_intel" in data


class TestGetRecentFindings:
    """Tests for get_recent_findings function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context()

        findings = get_recent_findings(ctx)

        assert len(findings) == 0

    def test_respects_limit(self):
        """Test that limit is respected."""
        ctx = Context()
        for i in range(20):
            ctx.add(f"finding_{i}", {"title": f"Finding {i}", "severity": "low"})

        findings = get_recent_findings(ctx, limit=5)

        assert len(findings) == 5


class TestNormalizeSeverity:
    """Tests for normalize_severity function."""

    def test_string_severity(self):
        """Test string normalization."""
        assert normalize_severity("HIGH") == "high"

    def test_enum_severity(self):
        """Test enum-like normalization."""

        class MockSeverity:
            name = "CRITICAL"

        assert normalize_severity(MockSeverity()) == "critical"


class TestFormatDashboardHtml:
    """Tests for format_dashboard_html function."""

    def test_contains_metrics(self):
        """Test HTML contains key metrics."""
        data = {
            "risk_summary": {"risk_score": 50, "total": 10, "critical": 2, "high": 3},
            "attack_surface": {"subdomains_count": 15, "exposure_score": 40},
        }

        html = format_dashboard_html(data)

        assert "Risk Score" in html
        assert "50" in html
        assert "Total Findings" in html


class TestGetScoreClass:
    """Tests for get_score_class function."""

    def test_critical_class(self):
        """Test critical score class."""
        assert get_score_class(80) == "critical"

    def test_high_class(self):
        """Test high score class."""
        assert get_score_class(60) == "high"

    def test_medium_class(self):
        """Test medium score class."""
        assert get_score_class(30) == "medium"

    def test_low_class(self):
        """Test low score class."""
        assert get_score_class(10) == "low"
