"""Tests for report generation module."""

from datetime import datetime, timezone
import json

import pytest

from redops.reports import (
    ReportGenerator,
    ReportConfig,
    ExecutiveSummaryReport,
    DetailedFindingsReport,
    ComplianceReport,
)
from redops.reports.generator import (
    ReportFormat,
    ReportType,
    Finding,
    ScanResult,
)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            id="f1",
            title="SQL Injection Vulnerability",
            severity="critical",
            description="User input is not sanitized before database query.",
            module="sql_scanner",
            category="injection",
            evidence={
                "url": "http://example.com/search?q=test",
                "payload": "' OR 1=1--",
            },
            remediation="Use parameterized queries.",
            cvss_score=9.8,
            cve_ids=["CVE-2024-1234"],
            status="open",
        ),
        Finding(
            id="f2",
            title="Cross-Site Scripting (XSS)",
            severity="high",
            description="Reflected XSS in search parameter.",
            module="xss_scanner",
            category="xss",
            evidence={"parameter": "q", "payload": "<script>alert(1)</script>"},
            remediation="Encode output and validate input.",
            cvss_score=7.5,
            status="open",
        ),
        Finding(
            id="f3",
            title="Missing Security Headers",
            severity="medium",
            description="X-Frame-Options header is not set.",
            module="header_scanner",
            category="configuration",
            remediation="Add X-Frame-Options: DENY header.",
            status="open",
        ),
        Finding(
            id="f4",
            title="SSL Certificate Expiring Soon",
            severity="low",
            description="Certificate expires in 30 days.",
            module="ssl_scanner",
            category="crypto",
            status="open",
        ),
        Finding(
            id="f5",
            title="Server Version Disclosed",
            severity="info",
            description="Server header reveals version information.",
            module="header_scanner",
            category="information",
            status="open",
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_findings):
    """Create sample scan result for testing."""
    return ScanResult(
        scan_id="scan-123",
        target="https://example.com",
        pipeline="web_security",
        started_at=datetime(2025, 1, 26, 10, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 1, 26, 10, 15, 0, tzinfo=timezone.utc),
        status="completed",
        findings=sample_findings,
        metadata={"scanner_version": "1.0.0"},
    )


class TestScanResult:
    """Test ScanResult data class."""

    def test_duration(self, sample_scan_result):
        """Duration is calculated correctly."""
        assert sample_scan_result.duration == 900  # 15 minutes

    def test_duration_none_when_not_completed(self, sample_findings):
        """Duration is None when scan not completed."""
        result = ScanResult(
            scan_id="test",
            target="https://example.com",
            pipeline="test",
            started_at=datetime.now(timezone.utc),
            completed_at=None,
            status="running",
            findings=sample_findings,
        )
        assert result.duration is None

    def test_severity_counts(self, sample_scan_result):
        """Severity counts are calculated correctly."""
        counts = sample_scan_result.severity_counts
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 1

    def test_risk_score(self, sample_scan_result):
        """Risk score is calculated."""
        score = sample_scan_result.risk_score
        # 1*40 + 1*25 + 1*10 + 1*3 + 1*1 = 79
        assert score == 79


class TestReportConfig:
    """Test ReportConfig data class."""

    def test_default_config(self):
        """Default config has expected values."""
        config = ReportConfig()
        assert config.title == "Security Assessment Report"
        assert config.author == "RedOPS Security Scanner"
        assert config.include_toc is True
        assert config.include_summary is True
        assert config.classification == "CONFIDENTIAL"

    def test_custom_config(self):
        """Custom config values are used."""
        config = ReportConfig(
            title="Custom Report",
            author="Test Author",
            organization="Test Org",
            classification="TOP SECRET",
        )
        assert config.title == "Custom Report"
        assert config.author == "Test Author"
        assert config.organization == "Test Org"
        assert config.classification == "TOP SECRET"


class TestReportGenerator:
    """Test ReportGenerator class."""

    def test_generate_pdf_executive_summary(self, sample_scan_result):
        """Generate executive summary PDF."""
        generator = ReportGenerator()
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.PDF,
        )
        assert content is not None
        assert len(content) > 0
        # PDF starts with %PDF
        assert content[:4] == b"%PDF"

    def test_generate_pdf_detailed_findings(self, sample_scan_result):
        """Generate detailed findings PDF."""
        generator = ReportGenerator()
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.DETAILED_FINDINGS,
            report_format=ReportFormat.PDF,
        )
        assert content is not None
        assert content[:4] == b"%PDF"

    def test_generate_pdf_compliance(self, sample_scan_result):
        """Generate compliance PDF."""
        generator = ReportGenerator()
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.COMPLIANCE,
            report_format=ReportFormat.PDF,
        )
        assert content is not None
        assert content[:4] == b"%PDF"

    def test_generate_html(self, sample_scan_result):
        """Generate HTML report."""
        generator = ReportGenerator()
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.HTML,
        )
        html = content.decode("utf-8")
        assert "<!DOCTYPE html>" in html
        assert "example.com" in html
        assert "SQL Injection" in html

    def test_generate_markdown(self, sample_scan_result):
        """Generate Markdown report."""
        generator = ReportGenerator()
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.MARKDOWN,
        )
        md = content.decode("utf-8")
        assert "# Security Assessment Report" in md
        assert "example.com" in md
        assert "| # | Title | Severity | Status |" in md

    def test_generate_json(self, sample_scan_result):
        """Generate JSON report."""
        generator = ReportGenerator()
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.JSON,
        )
        data = json.loads(content.decode("utf-8"))
        assert data["scan_id"] == "scan-123"
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 5
        assert data["risk_score"] == 79

    def test_generate_with_custom_config(self, sample_scan_result):
        """Generate report with custom config."""
        config = ReportConfig(
            title="Custom Security Report",
            organization="ACME Corp",
            classification="INTERNAL",
        )
        generator = ReportGenerator(config)
        content = generator.generate(
            sample_scan_result,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            report_format=ReportFormat.JSON,
        )
        data = json.loads(content.decode("utf-8"))
        assert data["title"] == "Custom Security Report"

    def test_invalid_report_type(self, sample_scan_result):
        """Invalid report type raises error."""
        generator = ReportGenerator()
        with pytest.raises(ValueError, match="Unknown report type"):
            generator.generate(
                sample_scan_result,
                report_type="invalid",  # type: ignore
            )


class TestFinding:
    """Test Finding data class."""

    def test_finding_creation(self):
        """Finding can be created with all fields."""
        finding = Finding(
            id="test-1",
            title="Test Finding",
            severity="high",
            description="Test description",
            module="test_module",
            category="test_category",
            evidence={"key": "value"},
            remediation="Fix it",
            references=["https://example.com"],
            cvss_score=7.5,
            cve_ids=["CVE-2024-0001"],
            status="open",
        )
        assert finding.id == "test-1"
        assert finding.severity == "high"
        assert finding.cvss_score == 7.5

    def test_finding_defaults(self):
        """Finding has correct defaults."""
        finding = Finding(
            id="test-1",
            title="Test Finding",
            severity="medium",
            description="Test",
        )
        assert finding.module == ""
        assert finding.category == ""
        assert finding.evidence == {}
        assert finding.remediation == ""
        assert finding.references == []
        assert finding.cvss_score is None
        assert finding.cve_ids == []
        assert finding.status == "open"


class TestExecutiveSummaryReport:
    """Test ExecutiveSummaryReport class."""

    def test_report_generation(self, sample_scan_result):
        """Executive summary generates content."""
        config = ReportConfig()
        report = ExecutiveSummaryReport(config)
        elements = report.generate(sample_scan_result)
        assert len(elements) > 0

    def test_risk_levels(self, sample_findings):
        """Risk levels are calculated correctly."""
        config = ReportConfig()
        ExecutiveSummaryReport(config)

        # High risk (critical findings)
        high_risk = ScanResult(
            scan_id="test",
            target="test",
            pipeline="test",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            status="completed",
            findings=sample_findings,
        )
        assert high_risk.risk_score >= 60

        # Low risk (no critical/high)
        low_findings = [
            Finding(id="1", title="Low", severity="low", description="Test"),
            Finding(id="2", title="Info", severity="info", description="Test"),
        ]
        low_risk = ScanResult(
            scan_id="test",
            target="test",
            pipeline="test",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            status="completed",
            findings=low_findings,
        )
        assert low_risk.risk_score < 20


class TestDetailedFindingsReport:
    """Test DetailedFindingsReport class."""

    def test_report_generation(self, sample_scan_result):
        """Detailed findings generates content."""
        config = ReportConfig()
        report = DetailedFindingsReport(config)
        elements = report.generate(sample_scan_result)
        assert len(elements) > 0

    def test_findings_grouped_by_severity(self, sample_scan_result):
        """Findings are grouped by severity."""
        config = ReportConfig(include_toc=False, include_summary=False)
        report = DetailedFindingsReport(config)
        elements = report.generate(sample_scan_result)
        # Check that elements contain severity section headers
        assert len(elements) > 5


class TestComplianceReport:
    """Test ComplianceReport class."""

    def test_report_generation(self, sample_scan_result):
        """Compliance report generates content."""
        config = ReportConfig()
        report = ComplianceReport(config)
        elements = report.generate(sample_scan_result)
        assert len(elements) > 0

    def test_framework_mappings(self, sample_scan_result):
        """Findings are mapped to compliance frameworks."""
        config = ReportConfig()
        report = ComplianceReport(config)
        elements = report.generate(sample_scan_result)
        # Should have multiple framework sections
        assert len(elements) > 10
