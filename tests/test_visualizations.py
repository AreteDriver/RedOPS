"""Tests for dashboard visualizations."""

import pytest
from datetime import datetime, timezone, timedelta
import json


class TestChartData:
    """Tests for ChartData class."""

    def test_chart_data_creation(self):
        """Test ChartData creation."""
        from redops.web.visualizations import ChartData

        chart = ChartData(
            chart_type="bar",
            labels=["A", "B", "C"],
            datasets=[{"data": [1, 2, 3]}],
            title="Test Chart",
        )

        assert chart.chart_type == "bar"
        assert chart.labels == ["A", "B", "C"]
        assert len(chart.datasets) == 1

    def test_chart_data_to_dict(self):
        """Test ChartData to_dict conversion."""
        from redops.web.visualizations import ChartData

        chart = ChartData(
            chart_type="pie",
            labels=["X", "Y"],
            datasets=[{"data": [10, 20]}],
            title="Test",
            options={"responsive": True},
        )

        data = chart.to_dict()

        assert data["type"] == "pie"
        assert data["data"]["labels"] == ["X", "Y"]
        assert data["options"]["responsive"] is True

    def test_chart_data_to_json(self):
        """Test ChartData JSON serialization."""
        from redops.web.visualizations import ChartData

        chart = ChartData(
            chart_type="line",
            labels=["1", "2", "3"],
            datasets=[{"data": [1, 2, 3]}],
        )

        json_str = chart.to_json()
        parsed = json.loads(json_str)

        assert parsed["type"] == "line"


class TestSeverityDistributionChart:
    """Tests for severity distribution chart."""

    def test_empty_findings(self):
        """Test with no findings."""
        from redops.web.visualizations import SeverityDistributionChart

        chart = SeverityDistributionChart([])
        result = chart.generate()

        assert result.chart_type == "doughnut"
        assert result.labels == []
        assert result.datasets[0]["data"] == []

    def test_single_severity(self):
        """Test with findings of one severity."""
        from redops.web.visualizations import SeverityDistributionChart

        findings = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "high"},
        ]

        chart = SeverityDistributionChart(findings)
        result = chart.generate()

        assert result.labels == ["High"]
        assert result.datasets[0]["data"] == [3]

    def test_multiple_severities(self):
        """Test with mixed severities."""
        from redops.web.visualizations import SeverityDistributionChart

        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]

        chart = SeverityDistributionChart(findings)
        result = chart.generate()

        # Should be in order: critical, high, medium, low, info
        assert "Critical" in result.labels
        assert "High" in result.labels
        assert "Medium" in result.labels

    def test_unknown_severity(self):
        """Test with unknown severity."""
        from redops.web.visualizations import SeverityDistributionChart

        findings = [
            {"severity": "critical"},
            {},  # No severity
        ]

        chart = SeverityDistributionChart(findings)
        result = chart.generate()

        assert "Unknown" in result.labels

    def test_chart_type_override(self):
        """Test chart type can be changed."""
        from redops.web.visualizations import SeverityDistributionChart

        findings = [{"severity": "high"}]
        chart = SeverityDistributionChart(findings)

        result = chart.generate(chart_type="pie")
        assert result.chart_type == "pie"

        result = chart.generate(chart_type="bar")
        assert result.chart_type == "bar"


class TestModuleDistributionChart:
    """Tests for module distribution chart."""

    def test_empty_findings(self):
        """Test with no findings."""
        from redops.web.visualizations import ModuleDistributionChart

        chart = ModuleDistributionChart([])
        result = chart.generate()

        assert result.labels == []

    def test_module_counts(self):
        """Test module counting."""
        from redops.web.visualizations import ModuleDistributionChart

        findings = [
            {"module": "recon.dns"},
            {"module": "recon.dns"},
            {"module": "analysis.ssl"},
            {"module": "threat_intel.greynoise"},
        ]

        chart = ModuleDistributionChart(findings)
        result = chart.generate()

        # dns should have highest count
        assert result.labels[0] == "dns"
        assert result.datasets[0]["data"][0] == 2

    def test_max_modules_limit(self):
        """Test max_modules parameter."""
        from redops.web.visualizations import ModuleDistributionChart

        findings = [
            {"module": f"module{i}"} for i in range(20)
        ]

        chart = ModuleDistributionChart(findings)
        result = chart.generate(max_modules=5)

        assert len(result.labels) == 5


class TestTimelineChart:
    """Tests for timeline chart."""

    def test_empty_items(self):
        """Test with no items."""
        from redops.web.visualizations import TimelineChart

        chart = TimelineChart([])
        result = chart.generate()

        assert result.chart_type == "line"

    def test_daily_aggregation(self):
        """Test daily aggregation."""
        from redops.web.visualizations import TimelineChart

        now = datetime.now(timezone.utc)
        items = [
            {"timestamp": (now - timedelta(days=1)).isoformat()},
            {"timestamp": (now - timedelta(days=1)).isoformat()},
            {"timestamp": now.isoformat()},
        ]

        chart = TimelineChart(items)
        result = chart.generate(period="day", days=3)

        assert len(result.labels) >= 3

    def test_hourly_aggregation(self):
        """Test hourly aggregation."""
        from redops.web.visualizations import TimelineChart

        now = datetime.now(timezone.utc)
        items = [
            {"timestamp": (now - timedelta(hours=2)).isoformat()},
            {"timestamp": now.isoformat()},
        ]

        chart = TimelineChart(items)
        result = chart.generate(period="hour", days=1)

        assert result.chart_type == "line"

    def test_custom_timestamp_key(self):
        """Test custom timestamp key."""
        from redops.web.visualizations import TimelineChart

        now = datetime.now(timezone.utc)
        items = [
            {"created_at": now.isoformat()},
        ]

        chart = TimelineChart(items, timestamp_key="created_at")
        result = chart.generate(days=1)

        # Should process items correctly
        assert result.datasets[0]["data"][-1] >= 0


class TestRiskScoreGauge:
    """Tests for risk score gauge."""

    def test_empty_findings(self):
        """Test with no findings."""
        from redops.web.visualizations import RiskScoreGauge

        gauge = RiskScoreGauge([])
        score = gauge.calculate_score()

        assert score == 0

    def test_low_risk(self):
        """Test low risk score."""
        from redops.web.visualizations import RiskScoreGauge

        findings = [
            {"severity": "info"},
            {"severity": "low"},
        ]

        gauge = RiskScoreGauge(findings)
        score = gauge.calculate_score()

        assert score < 20

    def test_high_risk(self):
        """Test high risk score."""
        from redops.web.visualizations import RiskScoreGauge

        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
        ]

        gauge = RiskScoreGauge(findings)
        score = gauge.calculate_score()

        # 40 + 40 + 25 = 105, capped at 100
        assert score == 100

    def test_gauge_data_structure(self):
        """Test gauge data structure."""
        from redops.web.visualizations import RiskScoreGauge

        findings = [{"severity": "medium"}]
        gauge = RiskScoreGauge(findings)
        data = gauge.generate()

        assert data["type"] == "gauge"
        assert "value" in data
        assert "max" in data
        assert "color" in data
        assert "zones" in data
        assert len(data["zones"]) == 5


class TestThreatIntelSummary:
    """Tests for threat intel summary."""

    def test_empty_results(self):
        """Test with no intel results."""
        from redops.web.visualizations import ThreatIntelSummary

        summary = ThreatIntelSummary({})
        data = summary.generate()

        assert data["sources_queried"] == []
        assert data["total_hits"] == 0

    def test_greynoise_result(self):
        """Test GreyNoise result processing."""
        from redops.web.visualizations import ThreatIntelSummary

        results = {
            "greynoise_result": {"noise": True}
        }

        summary = ThreatIntelSummary(results)
        data = summary.generate()

        assert "GreyNoise" in data["sources_queried"]
        assert data["total_hits"] == 1

    def test_abuseipdb_result(self):
        """Test AbuseIPDB result processing."""
        from redops.web.visualizations import ThreatIntelSummary

        results = {
            "abuseipdb_result": {
                "data": {"abuseConfidenceScore": 75}
            }
        }

        summary = ThreatIntelSummary(results)
        data = summary.generate()

        assert "AbuseIPDB" in data["sources_queried"]
        assert data["reputation_scores"]["AbuseIPDB"] == 75
        assert len(data["malicious_indicators"]) > 0

    def test_multiple_sources(self):
        """Test multiple intel sources."""
        from redops.web.visualizations import ThreatIntelSummary

        results = {
            "greynoise_result": {"noise": True},
            "urlscan_result": {"analysis": {"is_malicious": True, "verdict": "malicious"}},
            "otx_indicator": {"analysis": {"is_malicious": True, "pulse_count": 5}},
        }

        summary = ThreatIntelSummary(results)
        data = summary.generate()

        assert len(data["sources_queried"]) == 3
        assert data["total_hits"] == 3


class TestScanSummaryDashboard:
    """Tests for scan summary dashboard."""

    def test_empty_context(self):
        """Test with empty context."""
        from redops.web.visualizations import ScanSummaryDashboard

        dashboard = ScanSummaryDashboard({})
        data = dashboard.generate()

        assert data["summary"]["total_findings"] == 0
        assert "charts" in data

    def test_with_findings(self):
        """Test with findings in context."""
        from redops.web.visualizations import ScanSummaryDashboard

        context = {
            "target": "example.com",
            "pipeline_name": "test-pipeline",
            "finding_sqli": {"title": "SQL Injection", "severity": "critical", "module": "analysis"},
            "finding_xss": {"title": "XSS", "severity": "high", "module": "analysis"},
            "finding_info": {"title": "Info", "severity": "low", "module": "recon"},
        }

        dashboard = ScanSummaryDashboard(context)
        data = dashboard.generate()

        assert data["summary"]["total_findings"] == 3
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 1
        assert data["summary"]["target"] == "example.com"
        assert "severity" in data["charts"]
        assert "modules" in data["charts"]

    def test_with_threat_intel(self):
        """Test with threat intel results."""
        from redops.web.visualizations import ScanSummaryDashboard

        context = {
            "finding_test": {"title": "Test", "severity": "medium", "module": "test"},
            "greynoise_result": {"noise": True},
            "otx_indicator": {"analysis": {"is_malicious": True, "pulse_count": 3}},
        }

        dashboard = ScanSummaryDashboard(context)
        data = dashboard.generate()

        assert "threat_intel" in data
        assert len(data["threat_intel"]["sources_queried"]) == 2


class TestGenerateDashboardHtml:
    """Tests for HTML generation."""

    def test_generate_html(self):
        """Test HTML generation."""
        from redops.web.visualizations import generate_dashboard_html

        dashboard_data = {
            "summary": {
                "total_findings": 5,
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
                "target": "test.com",
                "pipeline": "test",
            },
            "charts": {},
        }

        html = generate_dashboard_html(dashboard_data)

        assert "<!DOCTYPE html>" in html
        assert "test.com" in html
        assert "Total Findings" in html
        assert "chart.js" in html

    def test_html_with_charts(self):
        """Test HTML with chart data."""
        from redops.web.visualizations import generate_dashboard_html, ChartData

        dashboard_data = {
            "summary": {"total_findings": 1, "critical": 0, "high": 0, "medium": 1, "low": 0},
            "charts": {
                "severity": ChartData(
                    chart_type="doughnut",
                    labels=["Medium"],
                    datasets=[{"data": [1]}],
                ).to_dict(),
            },
        }

        html = generate_dashboard_html(dashboard_data)

        assert "severityChart" in html
        assert "doughnut" in html
