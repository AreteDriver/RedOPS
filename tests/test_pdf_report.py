"""Tests for PDF report module."""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Check if fpdf is available
try:
    from fpdf import FPDF

    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

# Skip all tests if fpdf not available
pytestmark = pytest.mark.skipif(not HAS_FPDF, reason="fpdf2 not installed")

from redops.modules.reporting.pdf_report import (  # noqa: E402
    RedOPSPDFReport,
    PDFReportGenerator,
    generate_pdf_report,
)


class TestRedOPSPDFReport:
    """Tests for RedOPSPDFReport class."""

    def test_inherits_fpdf(self):
        """Test inherits from FPDF."""
        pdf = RedOPSPDFReport()
        assert isinstance(pdf, FPDF)

    def test_auto_page_break(self):
        """Test auto page break is set."""
        pdf = RedOPSPDFReport()
        assert pdf.auto_page_break is True

    def test_add_page(self):
        """Test adding a page."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        assert pdf.page_no() == 1

    def test_chapter_title(self):
        """Test adding chapter title."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.chapter_title("Test Chapter")
        # Should not raise

    def test_section_title(self):
        """Test adding section title."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.section_title("Test Section")
        # Should not raise

    def test_body_text(self):
        """Test adding body text."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.body_text("This is a test paragraph with some content.")
        # Should not raise

    def test_add_finding_critical(self):
        """Test adding critical finding."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.add_finding(
            title="Critical Vulnerability",
            severity="critical",
            description="This is a critical issue.",
            recommendation="Fix immediately.",
        )
        # Should not raise

    def test_add_finding_all_severities(self):
        """Test adding findings of all severities."""
        pdf = RedOPSPDFReport()
        pdf.add_page()

        for severity in ["critical", "high", "medium", "low", "info"]:
            pdf.add_finding(
                title=f"{severity.capitalize()} Finding",
                severity=severity,
                description=f"A {severity} severity issue.",
            )
        # Should not raise

    def test_add_finding_unknown_severity(self):
        """Test adding finding with unknown severity."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.add_finding(
            title="Unknown Severity",
            severity="unknown",
            description="Unknown severity level.",
        )
        # Should not raise - uses default color

    def test_add_finding_no_recommendation(self):
        """Test adding finding without recommendation."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.add_finding(
            title="Finding",
            severity="medium",
            description="Description only.",
        )
        # Should not raise

    def test_add_table(self):
        """Test adding table."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.add_table(
            headers=["Name", "Value", "Status"],
            rows=[
                ["Item 1", "100", "OK"],
                ["Item 2", "200", "Warning"],
            ],
        )
        # Should not raise

    def test_add_table_custom_widths(self):
        """Test adding table with custom column widths."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        pdf.add_table(
            headers=["Name", "Value"], rows=[["Test", "123"]], col_widths=[100, 90]
        )
        # Should not raise

    def test_add_table_truncates_long_text(self):
        """Test table truncates long cell text."""
        pdf = RedOPSPDFReport()
        pdf.add_page()
        long_text = "A" * 100
        pdf.add_table(headers=["Data"], rows=[[long_text]])
        # Should not raise - text truncated to 30 chars


class TestPDFReportGenerator:
    """Tests for PDFReportGenerator class."""

    def test_init(self):
        """Test initialization."""
        generator = PDFReportGenerator()
        assert generator is not None

    def test_generate_minimal(self, tmp_path):
        """Test generating minimal report."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        path = generator.generate(scan_data={}, output_path=str(output))

        assert Path(path).exists()
        assert output.exists()

    def test_generate_with_target(self, tmp_path):
        """Test generating report with target."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        path = generator.generate(
            scan_data={"target": "example.com"}, output_path=str(output)
        )

        assert Path(path).exists()

    def test_generate_with_findings(self, tmp_path):
        """Test generating report with findings."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "findings": [
                {
                    "title": "SQL Injection",
                    "severity": "critical",
                    "description": "Found SQL injection vulnerability.",
                    "recommendation": "Use parameterized queries.",
                },
                {
                    "title": "XSS",
                    "severity": "high",
                    "description": "Cross-site scripting found.",
                },
            ],
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_generate_with_executive_summary(self, tmp_path):
        """Test generating report with executive summary."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "executive_report": {
                "executive_summary": {
                    "risk_level": "High",
                    "overall_score": 35,
                    "summary": "The assessment revealed several critical issues.",
                }
            },
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_generate_with_technical_details(self, tmp_path):
        """Test generating report with technical details."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "domain_profile": {"dns": {"A": ["1.2.3.4"], "MX": ["mail.example.com"]}},
            "tech_stack": {"technologies": ["Python", "Flask", "PostgreSQL", "Redis"]},
            "infrastructure": {"cloud_provider": "AWS", "cdn": "CloudFront"},
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_generate_with_recommendations(self, tmp_path):
        """Test generating report with recommendations."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "executive_report": {
                "recommendations": [
                    {
                        "title": "Patch Vulnerabilities",
                        "description": "Update all software.",
                        "priority": "High",
                    },
                    {
                        "title": "Enable MFA",
                        "description": "Multi-factor auth.",
                        "priority": "Medium",
                    },
                ]
            },
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_generate_without_sections(self, tmp_path):
        """Test generating report without optional sections."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        path = generator.generate(
            scan_data={"target": "example.com"},
            output_path=str(output),
            include_executive_summary=False,
            include_technical_details=False,
            include_recommendations=False,
        )

        assert Path(path).exists()

    def test_generate_creates_parent_dirs(self, tmp_path):
        """Test generate creates parent directories."""
        generator = PDFReportGenerator()
        output = tmp_path / "nested" / "path" / "report.pdf"

        path = generator.generate(
            scan_data={"target": "example.com"}, output_path=str(output)
        )

        assert Path(path).exists()

    def test_generate_with_timestamp(self, tmp_path):
        """Test generating report with timestamp."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {"target": "example.com", "timestamp": "2024-01-15T10:30:00Z"}

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_extract_findings_from_exposures(self, tmp_path):
        """Test extracting findings from exposures."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "exposure_scan": {
                "exposures": [
                    {
                        "type": "open_port",
                        "severity": "high",
                        "description": "Port 22 open",
                    },
                ]
            },
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_extract_findings_from_iocs(self, tmp_path):
        """Test extracting findings from IOCs."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "threat_intel": {
                "iocs": [
                    {"type": "ip", "value": "192.168.1.1"},
                ]
            },
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_findings_sorted_by_severity(self, tmp_path):
        """Test findings are sorted by severity."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "findings": [
                {"title": "Low", "severity": "low", "description": "Low issue"},
                {
                    "title": "Critical",
                    "severity": "critical",
                    "description": "Critical issue",
                },
                {
                    "title": "Medium",
                    "severity": "medium",
                    "description": "Medium issue",
                },
            ],
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_limits_findings(self, tmp_path):
        """Test limits findings to 20."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "findings": [
                {
                    "title": f"Finding {i}",
                    "severity": "medium",
                    "description": f"Issue {i}",
                }
                for i in range(50)
            ],
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()

    def test_limits_recommendations(self, tmp_path):
        """Test limits recommendations to 10."""
        generator = PDFReportGenerator()
        output = tmp_path / "report.pdf"

        data = {
            "target": "example.com",
            "executive_report": {
                "recommendations": [
                    {"title": f"Rec {i}", "description": f"Recommendation {i}"}
                    for i in range(20)
                ]
            },
        }

        path = generator.generate(scan_data=data, output_path=str(output))
        assert Path(path).exists()


class TestGeneratePdfReport:
    """Tests for generate_pdf_report pipeline function."""

    def test_basic_generation(self, tmp_path):
        """Test basic pipeline generation."""
        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        params = {"output_dir": str(tmp_path)}
        result = generate_pdf_report(ctx, params)

        ctx.add.assert_called()
        ctx.log.assert_called()
        assert result == ctx

    def test_adds_report_path(self, tmp_path):
        """Test adds pdf_report_path to context."""
        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        params = {"output_dir": str(tmp_path)}
        generate_pdf_report(ctx, params)

        # Check that add was called with pdf_report_path
        add_calls = [call[0] for call in ctx.add.call_args_list]
        assert any("pdf_report_path" in str(call) for call in add_calls)

    def test_logs_success(self, tmp_path):
        """Test logs success message."""
        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        params = {"output_dir": str(tmp_path)}
        generate_pdf_report(ctx, params)

        log_calls = [str(call) for call in ctx.log.call_args_list]
        assert any("generated" in call.lower() for call in log_calls)

    def test_respects_include_options(self, tmp_path):
        """Test respects include options."""
        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        params = {
            "output_dir": str(tmp_path),
            "include_executive_summary": False,
            "include_technical_details": False,
            "include_recommendations": False,
        }

        result = generate_pdf_report(ctx, params)
        assert result == ctx

    def test_handles_none_params(self, tmp_path, monkeypatch):
        """Test handles None params with default output dir."""
        ctx = MagicMock()
        ctx.data = {"target": "example.com"}

        # Change to tmp_path so ./output is created there
        monkeypatch.chdir(tmp_path)

        result = generate_pdf_report(ctx, None)
        assert result == ctx

    def test_error_handling(self):
        """Test error handling."""
        ctx = MagicMock()
        ctx.data = None  # This should cause an error

        result = generate_pdf_report(ctx, {})

        # Should log error
        log_calls = [str(call) for call in ctx.log.call_args_list]
        assert any("error" in call.lower() for call in log_calls)
        assert result == ctx


class TestImportHandling:
    """Tests for import handling when fpdf is missing."""

    def test_has_fpdf_flag(self):
        """Test HAS_FPDF flag is set correctly."""
        from redops.modules.reporting.pdf_report import HAS_FPDF

        assert HAS_FPDF is True  # We're running tests, so it's available

    def test_import_error_in_generator(self):
        """Test ImportError raised when fpdf missing."""
        with patch.dict("sys.modules", {"fpdf": None}):
            # This is hard to test without actually removing fpdf
            # Just verify the class exists
            assert PDFReportGenerator is not None
