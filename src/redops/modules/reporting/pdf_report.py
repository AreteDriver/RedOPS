"""
PDF Report Generator for RedOPS.

Generates professional PDF security reports from scan results.
"""

import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False
    XPos = None
    YPos = None
    # Create a dummy FPDF class for when the library is not installed
    class FPDF:
        """Dummy FPDF class when fpdf2 is not installed."""
        pass


class RedOPSPDFReport(FPDF):
    """Custom PDF class for RedOPS reports."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        """Add header to each page."""
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(60, 60, 60)
        self.cell(0, 10, "RedOPS Security Assessment Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(200, 200, 200)
        self.line(10, 20, 200, 20)
        self.ln(5)
        self.set_x(self.l_margin)  # Reset to left margin

    def footer(self):
        """Add footer to each page."""
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def chapter_title(self, title: str):
        """Add a chapter title."""
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(40, 40, 40)
        self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def section_title(self, title: str):
        """Add a section title."""
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(60, 60, 60)
        self.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def body_text(self, text: str):
        """Add body text."""
        self.set_font("Helvetica", "", 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        recommendation: str = "",
    ):
        """Add a finding to the report."""
        # Severity colors
        colors = {
            "critical": (220, 53, 69),    # Red
            "high": (255, 128, 0),        # Orange
            "medium": (255, 193, 7),      # Yellow
            "low": (40, 167, 69),         # Green
            "info": (23, 162, 184),       # Blue
        }
        color = colors.get(severity.lower(), (100, 100, 100))

        # Reset position to left margin
        self.set_x(self.l_margin)

        # Title with severity prefix
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*color)
        severity_prefix = f"[{severity.upper()}] "
        self.set_text_color(40, 40, 40)
        # Truncate title if needed
        title_text = title[:70] if len(title) > 70 else title
        self.multi_cell(0, 6, f"{severity_prefix}{title_text}")

        # Description
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(60, 60, 60)
        desc_text = description[:500] if len(description) > 500 else description
        self.multi_cell(0, 4, desc_text)

        # Recommendation
        if recommendation:
            self.set_x(self.l_margin)
            self.set_font("Helvetica", "I", 9)
            rec_text = recommendation[:300] if len(recommendation) > 300 else recommendation
            self.multi_cell(0, 4, f"Recommendation: {rec_text}")

        self.ln(3)

    def add_table(self, headers: List[str], rows: List[List[str]], col_widths: Optional[List[int]] = None):
        """Add a table to the report."""
        if not col_widths:
            col_widths = [190 // len(headers)] * len(headers)

        # Header
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(240, 240, 240)
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, header, border=1, fill=True, align="C")
        self.ln()

        # Rows
        self.set_font("Helvetica", "", 9)
        for row in rows:
            for i, cell in enumerate(row):
                self.cell(col_widths[i], 6, str(cell)[:30], border=1)
            self.ln()

        self.ln(3)


class PDFReportGenerator:
    """Generator for PDF security reports."""

    def __init__(self):
        """Initialize the PDF report generator."""
        if not HAS_FPDF:
            raise ImportError(
                "fpdf2 library required for PDF reports. "
                "Install with: pip install fpdf2"
            )

    def generate(
        self,
        scan_data: Dict[str, Any],
        output_path: str,
        include_executive_summary: bool = True,
        include_technical_details: bool = True,
        include_recommendations: bool = True,
    ) -> str:
        """
        Generate a PDF report from scan data.

        Args:
            scan_data: Dictionary containing scan results
            output_path: Path to save the PDF
            include_executive_summary: Include executive summary section
            include_technical_details: Include technical details
            include_recommendations: Include recommendations section

        Returns:
            Path to the generated PDF file
        """
        pdf = RedOPSPDFReport()
        pdf.alias_nb_pages()
        pdf.add_page()

        # Title page
        self._add_title_page(pdf, scan_data)

        # Table of contents
        pdf.add_page()
        self._add_table_of_contents(pdf)

        # Executive Summary
        if include_executive_summary:
            pdf.add_page()
            self._add_executive_summary(pdf, scan_data)

        # Findings
        pdf.add_page()
        self._add_findings(pdf, scan_data)

        # Technical Details
        if include_technical_details:
            pdf.add_page()
            self._add_technical_details(pdf, scan_data)

        # Recommendations
        if include_recommendations:
            pdf.add_page()
            self._add_recommendations(pdf, scan_data)

        # Appendix
        pdf.add_page()
        self._add_appendix(pdf, scan_data)

        # Save
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(output_path))

        return str(output_path)

    def _add_title_page(self, pdf: RedOPSPDFReport, data: Dict[str, Any]):
        """Add title page."""
        pdf.set_font("Helvetica", "B", 24)
        pdf.set_text_color(40, 40, 40)
        pdf.ln(40)
        pdf.cell(0, 20, "Security Assessment Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", "", 14)
        pdf.ln(10)
        target = data.get("target", "Unknown Target")
        pdf.cell(0, 10, f"Target: {target}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(5)
        timestamp = data.get("timestamp", datetime.now(timezone.utc).isoformat())
        pdf.cell(0, 10, f"Date: {timestamp[:10]}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(20)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, "Generated by RedOPS Security Framework", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Classification
        pdf.ln(40)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(220, 53, 69)
        pdf.cell(0, 10, "CONFIDENTIAL", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _add_table_of_contents(self, pdf: RedOPSPDFReport):
        """Add table of contents."""
        pdf.chapter_title("Table of Contents")
        pdf.ln(5)

        sections = [
            ("1. Executive Summary", 3),
            ("2. Findings Overview", 4),
            ("3. Technical Details", 5),
            ("4. Recommendations", 6),
            ("5. Appendix", 7),
        ]

        pdf.set_font("Helvetica", "", 11)
        for section, page in sections:
            pdf.cell(150, 8, section)
            pdf.cell(0, 8, str(page), align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _add_executive_summary(self, pdf: RedOPSPDFReport, data: Dict[str, Any]):
        """Add executive summary section."""
        pdf.chapter_title("1. Executive Summary")

        # Risk overview
        exec_summary = data.get("executive_report", {}).get("executive_summary", {})
        risk_level = exec_summary.get("risk_level", "Unknown")
        overall_score = exec_summary.get("overall_score", "N/A")

        pdf.section_title("Risk Overview")
        pdf.body_text(f"Overall Risk Level: {risk_level}")
        pdf.body_text(f"Security Score: {overall_score}")

        # Summary text
        summary_text = exec_summary.get("summary", "")
        if summary_text:
            pdf.ln(3)
            pdf.body_text(summary_text)

        # Key findings summary
        findings = data.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")

        pdf.section_title("Findings Summary")
        pdf.add_table(
            ["Severity", "Count"],
            [
                ["Critical", str(critical)],
                ["High", str(high)],
                ["Medium", str(medium)],
                ["Low", str(low)],
            ],
            [95, 95],
        )

    def _add_findings(self, pdf: RedOPSPDFReport, data: Dict[str, Any]):
        """Add findings section."""
        pdf.chapter_title("2. Findings Overview")

        findings = data.get("findings", [])
        if not findings:
            # Try to extract from other sources
            findings = self._extract_findings(data)

        if not findings:
            pdf.body_text("No significant findings identified during this assessment.")
            return

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        for finding in findings[:20]:  # Limit to top 20
            pdf.add_finding(
                title=finding.get("title", "Untitled Finding"),
                severity=finding.get("severity", "info"),
                description=finding.get("description", "No description available."),
                recommendation=finding.get("recommendation", ""),
            )

    def _add_technical_details(self, pdf: RedOPSPDFReport, data: Dict[str, Any]):
        """Add technical details section."""
        pdf.chapter_title("3. Technical Details")

        # Domain profile
        domain = data.get("domain_profile", {})
        if domain:
            pdf.section_title("Domain Information")
            dns = domain.get("dns", {})
            if dns:
                pdf.body_text(f"DNS Records: {len(dns)} found")

        # Tech stack
        tech = data.get("tech_stack", {})
        if tech:
            pdf.section_title("Technology Stack")
            technologies = tech.get("technologies", [])
            if technologies:
                for t in technologies[:10]:
                    pdf.body_text(f"- {t}")

        # Infrastructure
        infra = data.get("infrastructure", {})
        if infra:
            pdf.section_title("Infrastructure")
            pdf.body_text(f"Cloud Provider: {infra.get('cloud_provider', 'Unknown')}")
            pdf.body_text(f"CDN: {infra.get('cdn', 'Not detected')}")

    def _add_recommendations(self, pdf: RedOPSPDFReport, data: Dict[str, Any]):
        """Add recommendations section."""
        pdf.chapter_title("4. Recommendations")

        recommendations = data.get("executive_report", {}).get("recommendations", [])

        if not recommendations:
            pdf.body_text("Based on the assessment, consider the following general recommendations:")
            pdf.body_text("- Review and update security policies regularly")
            pdf.body_text("- Implement continuous monitoring for exposed assets")
            pdf.body_text("- Conduct regular security assessments")
            return

        for i, rec in enumerate(recommendations[:10], 1):
            pdf.section_title(f"{i}. {rec.get('title', 'Recommendation')}")
            pdf.body_text(rec.get("description", ""))
            priority = rec.get("priority", "Medium")
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 5, f"Priority: {priority}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)

    def _add_appendix(self, pdf: RedOPSPDFReport, data: Dict[str, Any]):
        """Add appendix section."""
        pdf.chapter_title("5. Appendix")

        pdf.section_title("Assessment Methodology")
        pdf.body_text(
            "This assessment was conducted using RedOPS, an automated security "
            "intelligence and attack surface management platform. The assessment "
            "included reconnaissance, technology fingerprinting, exposure analysis, "
            "and threat correlation."
        )

        pdf.section_title("Scope")
        pdf.body_text(f"Target: {data.get('target', 'Not specified')}")
        pdf.body_text(f"Assessment Date: {data.get('timestamp', 'Not recorded')[:10] if data.get('timestamp') else 'Not recorded'}")

        pdf.section_title("Disclaimer")
        pdf.body_text(
            "This report is provided for informational purposes only. The findings "
            "represent a point-in-time assessment and security postures may change. "
            "This assessment was conducted within authorized scope boundaries."
        )

    def _extract_findings(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from various data sources."""
        findings = []

        # From exposure scan
        exposures = data.get("exposure_scan", {}).get("exposures", [])
        for exp in exposures:
            findings.append({
                "title": exp.get("type", "Exposure"),
                "severity": exp.get("severity", "medium"),
                "description": exp.get("description", str(exp)),
            })

        # From threat intel
        iocs = data.get("threat_intel", {}).get("iocs", [])
        for ioc in iocs:
            findings.append({
                "title": f"IOC: {ioc.get('type', 'Unknown')}",
                "severity": "high",
                "description": ioc.get("value", str(ioc)),
            })

        return findings


def generate_pdf_report(ctx, params: Optional[Dict[str, Any]] = None):
    """Pipeline module to generate PDF report."""
    params = params or {}

    try:
        generator = PDFReportGenerator()

        output_dir = params.get("output_dir", "./output")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.pdf"
        output_path = Path(output_dir) / filename

        path = generator.generate(
            scan_data=ctx.data,
            output_path=str(output_path),
            include_executive_summary=params.get("include_executive_summary", True),
            include_technical_details=params.get("include_technical_details", True),
            include_recommendations=params.get("include_recommendations", True),
        )

        ctx.add("pdf_report_path", path)
        ctx.log(f"PDF report generated: {path}", level="INFO")

    except ImportError as e:
        ctx.log(f"PDF generation skipped: {e}", level="WARNING")
    except Exception as e:
        ctx.log(f"PDF generation failed: {e}", level="ERROR")

    return ctx
