"""Tests for analysis module."""

from datetime import datetime, timedelta, timezone

import pytest

from redops.analysis import (
    ScanComparator,
    ComparisonResult,
    FindingDiff,
    TrendAnalyzer,
    TrendData,
    MetricType,
    RemediationTracker,
    RemediationStatus,
)
from redops.analysis.comparison import DiffType, FindingData


@pytest.fixture
def baseline_scan():
    """Create baseline scan data."""
    return {
        "scan_id": "scan-001",
        "target": "https://example.com",
        "pipeline": "web_security",
        "started_at": "2025-01-20T10:00:00Z",
        "completed_at": "2025-01-20T10:30:00Z",
        "status": "completed",
        "findings": [
            {
                "id": "f1",
                "title": "SQL Injection",
                "severity": "critical",
                "description": "SQL injection in search parameter",
                "module": "sql_scanner",
                "category": "injection",
            },
            {
                "id": "f2",
                "title": "XSS Vulnerability",
                "severity": "high",
                "description": "Reflected XSS",
                "module": "xss_scanner",
                "category": "xss",
            },
            {
                "id": "f3",
                "title": "Missing Headers",
                "severity": "medium",
                "description": "Security headers missing",
                "module": "header_scanner",
                "category": "configuration",
            },
        ],
    }


@pytest.fixture
def current_scan():
    """Create current scan data."""
    return {
        "scan_id": "scan-002",
        "target": "https://example.com",
        "pipeline": "web_security",
        "started_at": "2025-01-26T10:00:00Z",
        "completed_at": "2025-01-26T10:30:00Z",
        "status": "completed",
        "findings": [
            # f1 (SQL Injection) is resolved
            {
                "id": "f2",
                "title": "XSS Vulnerability",
                "severity": "high",
                "description": "Reflected XSS",
                "module": "xss_scanner",
                "category": "xss",
            },
            {
                "id": "f3",
                "title": "Missing Headers",
                "severity": "low",  # Severity changed
                "description": "Security headers missing",
                "module": "header_scanner",
                "category": "configuration",
            },
            {
                "id": "f4",
                "title": "CSRF Vulnerability",
                "severity": "high",
                "description": "Missing CSRF token",
                "module": "csrf_scanner",
                "category": "csrf",
            },
        ],
    }


class TestFindingData:
    """Test FindingData class."""

    def test_fingerprint_generation(self):
        """Fingerprint is generated from stable attributes."""
        finding1 = FindingData(
            id="f1",
            title="SQL Injection",
            severity="critical",
            description="Test",
            module="sql_scanner",
        )
        finding2 = FindingData(
            id="f2",  # Different ID
            title="SQL Injection",
            severity="critical",
            description="Different description",  # Different description
            module="sql_scanner",
        )
        # Same fingerprint despite different ID and description
        assert finding1.fingerprint == finding2.fingerprint

    def test_different_fingerprints(self):
        """Different findings have different fingerprints."""
        finding1 = FindingData(
            id="f1",
            title="SQL Injection",
            severity="critical",
            description="Test",
        )
        finding2 = FindingData(
            id="f2",
            title="XSS Vulnerability",
            severity="high",
            description="Test",
        )
        assert finding1.fingerprint != finding2.fingerprint


class TestScanComparator:
    """Test ScanComparator class."""

    def test_compare_basic(self, baseline_scan, current_scan):
        """Basic comparison works."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        assert isinstance(result, ComparisonResult)
        assert result.baseline_scan_id == "scan-001"
        assert result.current_scan_id == "scan-002"

    def test_new_findings_detected(self, baseline_scan, current_scan):
        """New findings are detected."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        # f4 (CSRF) is new
        new_titles = [d.finding.title for d in result.new_findings]
        assert "CSRF Vulnerability" in new_titles

    def test_resolved_findings_detected(self, baseline_scan, current_scan):
        """Resolved findings are detected."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        # f1 (SQL Injection) was resolved
        resolved_titles = [d.finding.title for d in result.resolved_findings]
        assert "SQL Injection" in resolved_titles

    def test_modified_findings_detected(self, baseline_scan, current_scan):
        """Modified findings are detected."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        # f3 (Missing Headers) severity changed
        modified_titles = [d.finding.title for d in result.modified_findings]
        assert "Missing Headers" in modified_titles

        # Check the change was recorded
        for diff in result.modified_findings:
            if diff.finding.title == "Missing Headers":
                assert "severity" in diff.changes

    def test_unchanged_findings_detected(self, baseline_scan, current_scan):
        """Unchanged findings are detected."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        # f2 (XSS) is unchanged
        unchanged_titles = [d.finding.title for d in result.unchanged_findings]
        assert "XSS Vulnerability" in unchanged_titles

    def test_remediation_rate(self, baseline_scan, current_scan):
        """Remediation rate is calculated."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        # 1 resolved out of 3 baseline = 33.33%
        assert result.remediation_rate == pytest.approx(33.33, rel=0.1)

    def test_to_dict(self, baseline_scan, current_scan):
        """Result can be serialized."""
        comparator = ScanComparator()
        result = comparator.compare(baseline_scan, current_scan)

        data = result.to_dict()
        assert "summary" in data
        assert "new" in data["summary"]
        assert "resolved" in data["summary"]


class TestFindingDiff:
    """Test FindingDiff class."""

    def test_is_improvement_resolved(self):
        """Resolved finding is an improvement."""
        finding = FindingData(id="f1", title="Test", severity="high", description="")
        diff = FindingDiff(diff_type=DiffType.RESOLVED, finding=finding)
        assert diff.is_improvement is True

    def test_is_improvement_severity_decreased(self):
        """Decreased severity is an improvement."""
        old = FindingData(id="f1", title="Test", severity="high", description="")
        new = FindingData(id="f1", title="Test", severity="low", description="")
        diff = FindingDiff(
            diff_type=DiffType.MODIFIED, finding=new, previous_finding=old
        )
        assert diff.is_improvement is True

    def test_is_regression_new(self):
        """New finding is a regression."""
        finding = FindingData(id="f1", title="Test", severity="high", description="")
        diff = FindingDiff(diff_type=DiffType.NEW, finding=finding)
        assert diff.is_regression is True


class TestRemediationTracker:
    """Test RemediationTracker class."""

    def test_track_finding(self):
        """Can track a finding."""
        tracker = RemediationTracker()
        record = tracker.track_finding(
            finding_id="f1",
            finding_title="SQL Injection",
            severity="critical",
        )

        assert record.finding_id == "f1"
        assert record.severity == "critical"
        assert record.status == RemediationStatus.OPEN

    def test_due_date_based_on_severity(self):
        """Due date is set based on severity SLA."""
        tracker = RemediationTracker()

        critical = tracker.track_finding("f1", "Critical", "critical")
        high = tracker.track_finding("f2", "High", "high")
        medium = tracker.track_finding("f3", "Medium", "medium")

        # Critical has shortest SLA
        assert critical.due_date < high.due_date < medium.due_date

    def test_update_status(self):
        """Status can be updated."""
        tracker = RemediationTracker()
        record = tracker.track_finding("f1", "Test", "high")

        record.update_status(RemediationStatus.IN_PROGRESS, "Started work")

        assert record.status == RemediationStatus.IN_PROGRESS
        assert len(record.notes) == 1

    def test_is_overdue(self):
        """Overdue detection works."""
        tracker = RemediationTracker()
        record = tracker.track_finding("f1", "Test", "critical")

        # Set due date in the past
        record.due_date = datetime.now() - timedelta(days=1)

        assert record.is_overdue is True

    def test_get_metrics(self):
        """Metrics are calculated."""
        tracker = RemediationTracker()

        # Add some findings
        tracker.track_finding("f1", "Critical", "critical")
        tracker.track_finding("f2", "High", "high")
        record3 = tracker.track_finding("f3", "Medium", "medium")
        record3.update_status(RemediationStatus.VERIFIED)

        metrics = tracker.get_metrics()

        assert metrics.total_findings == 3
        assert metrics.open_findings == 2
        assert metrics.verified == 1

    def test_track_from_scan(self, baseline_scan):
        """Can track all findings from a scan."""
        tracker = RemediationTracker()
        records = tracker.track_findings_from_scan(baseline_scan)

        assert len(records) == 3


class TestTrendAnalyzer:
    """Test TrendAnalyzer class."""

    @pytest.fixture
    def scan_history(self):
        """Create scan history for testing."""
        base_time = datetime(2025, 1, 1, tzinfo=timezone.utc)
        scans = []

        for i in range(10):
            scan_time = base_time + timedelta(days=i * 7)
            # Decreasing findings over time (improving)
            findings = [
                {
                    "id": f"f{j}",
                    "title": f"Finding {j}",
                    "severity": "high",
                    "description": "",
                }
                for j in range(10 - i)
            ]
            scans.append(
                {
                    "scan_id": f"scan-{i}",
                    "target": "https://example.com",
                    "started_at": scan_time.isoformat(),
                    "completed_at": (scan_time + timedelta(minutes=30)).isoformat(),
                    "status": "completed",
                    "findings": findings,
                }
            )

        return scans

    def test_analyze_basic(self, scan_history):
        """Basic analysis works."""
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(scan_history)

        assert report.scan_count == 10
        assert report.target == "https://example.com"

    def test_trend_direction(self, scan_history):
        """Trend direction is detected."""
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(scan_history)

        total = report.get_metric(MetricType.TOTAL_FINDINGS)
        # Findings are decreasing, so trend should be improving
        assert total.trend_direction.value == "improving"

    def test_metrics_calculated(self, scan_history):
        """Metrics are calculated."""
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(scan_history)

        total = report.get_metric(MetricType.TOTAL_FINDINGS)
        assert total.current_value is not None
        assert total.average is not None
        assert total.min_value is not None
        assert total.max_value is not None

    def test_risk_score_calculated(self, scan_history):
        """Risk score is calculated."""
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(scan_history)

        risk = report.get_metric(MetricType.RISK_SCORE)
        assert risk.current_value is not None

    def test_export_for_chart(self, scan_history):
        """Chart export works."""
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(scan_history)

        chart_data = analyzer.export_for_chart(report, MetricType.TOTAL_FINDINGS)

        assert "labels" in chart_data
        assert "values" in chart_data
        assert len(chart_data["labels"]) == len(chart_data["values"])

    def test_generate_summary(self, scan_history):
        """Summary generation works."""
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(scan_history)

        summary = analyzer.generate_summary(report)

        assert "Trend Analysis Summary" in summary
        assert "example.com" in summary


class TestTrendData:
    """Test TrendData class."""

    def test_add_point(self):
        """Points can be added."""
        trend = TrendData(metric=MetricType.TOTAL_FINDINGS)

        now = datetime.now()
        trend.add_point(now - timedelta(days=1), 10)
        trend.add_point(now, 15)

        assert len(trend.data_points) == 2
        assert trend.current_value == 15

    def test_statistics(self):
        """Statistics are calculated."""
        trend = TrendData(metric=MetricType.TOTAL_FINDINGS)

        now = datetime.now()
        for i in range(5):
            trend.add_point(now - timedelta(days=4 - i), float(10 + i))

        assert trend.min_value == 10
        assert trend.max_value == 14
        assert trend.average == 12

    def test_percent_change(self):
        """Percent change is calculated."""
        trend = TrendData(metric=MetricType.TOTAL_FINDINGS)

        now = datetime.now()
        trend.add_point(now - timedelta(days=1), 100)
        trend.add_point(now, 120)

        assert trend.percent_change == 20.0

    def test_to_dict(self):
        """Can be serialized."""
        trend = TrendData(metric=MetricType.TOTAL_FINDINGS)

        now = datetime.now()
        trend.add_point(now - timedelta(days=1), 10)
        trend.add_point(now, 15)

        data = trend.to_dict()

        assert data["metric"] == "total_findings"
        assert data["current_value"] == 15
        assert len(data["data_points"]) == 2
