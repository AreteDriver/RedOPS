"""Detailed findings report template."""

from typing import Any, List

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    ListFlowable,
    ListItem,
    Preformatted,
)

from ..generator import BaseReport, ScanResult, Finding, ReportType, ReportGenerator


class DetailedFindingsReport(BaseReport):
    """Detailed technical findings report.

    Provides comprehensive technical details for each finding including
    evidence, remediation steps, and references.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._add_detail_styles()

    def _add_detail_styles(self) -> None:
        """Add styles specific to detailed reports."""
        self.styles.add(
            ParagraphStyle(
                "Evidence",
                parent=self.styles["Code"],
                fontSize=8,
                backColor=colors.HexColor("#f5f5f5"),
                leftIndent=20,
                rightIndent=20,
                spaceBefore=5,
                spaceAfter=5,
            )
        )

        self.styles.add(
            ParagraphStyle(
                "Remediation",
                parent=self.styles["Normal"],
                fontSize=10,
                leftIndent=20,
                textColor=colors.HexColor("#28a745"),
            )
        )

    def generate(self, data: ScanResult) -> List[Any]:
        """Generate detailed findings content."""
        elements = []

        # Header
        elements.extend(self._create_header(data))

        # Table of Contents
        if self.config.include_toc and data.findings:
            elements.append(
                Paragraph("Table of Contents", self.styles["SectionHeader"])
            )
            elements.append(self._create_toc(data))
            elements.append(PageBreak())

        # Summary
        if self.config.include_summary:
            elements.append(Paragraph("Summary", self.styles["SectionHeader"]))
            elements.append(self._create_summary(data))
            elements.append(Spacer(1, 20))

            # Severity chart
            elements.append(self._create_severity_chart(data))
            elements.append(Spacer(1, 20))

            # Findings overview table
            elements.append(
                Paragraph("Findings Overview", self.styles["SectionHeader"])
            )
            elements.append(
                self._create_findings_table(data.findings, include_details=True)
            )
            elements.append(PageBreak())

        # Detailed Findings
        elements.append(Paragraph("Detailed Findings", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 10))

        # Group findings by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {s: [] for s in severity_order}
        for finding in data.findings:
            severity = finding.severity.lower()
            if severity in grouped:
                grouped[severity].append(finding)

        for severity in severity_order:
            findings = grouped[severity]
            if findings:
                elements.append(
                    Paragraph(
                        f"{severity.upper()} Severity ({len(findings)})",
                        self.styles["Heading2"],
                    )
                )
                elements.append(Spacer(1, 10))

                for i, finding in enumerate(findings, 1):
                    elements.extend(self._create_finding_detail(finding, i))
                    elements.append(Spacer(1, 15))

        return elements

    def _create_toc(self, data: ScanResult) -> Table:
        """Create table of contents."""
        toc_entries = []

        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {s: [] for s in severity_order}
        for finding in data.findings:
            grouped[finding.severity.lower()].append(finding)

        page_num = 3  # Approximate starting page for findings

        for severity in severity_order:
            findings = grouped[severity]
            if findings:
                toc_entries.append(
                    [f"{severity.upper()} Severity Findings", str(page_num)]
                )
                for finding in findings:
                    toc_entries.append([f"    • {finding.title[:60]}...", ""])
                    page_num += 1

        if not toc_entries:
            toc_entries.append(["No findings to display", ""])

        table = Table(toc_entries, colWidths=[5 * inch, 0.5 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.grey),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return table

    def _create_summary(self, data: ScanResult) -> Paragraph:
        """Create summary paragraph."""
        counts = data.severity_counts
        total = sum(counts.values())
        duration = data.duration

        text = f"""
        This security assessment was performed on <b>{data.target}</b> using the
        <b>{data.pipeline}</b> pipeline. The scan identified <b>{total}</b> total findings
        across all severity levels.
        """

        if duration:
            text += f" The assessment completed in <b>{duration / 60:.1f} minutes</b>."

        text += f"""
        <br/><br/>
        <b>Assessment Details:</b><br/>
        • Scan ID: {data.scan_id}<br/>
        • Start Time: {data.started_at.strftime("%Y-%m-%d %H:%M:%S")}<br/>
        • Status: {data.status.title()}<br/>
        • Risk Score: {data.risk_score:.0f}/100
        """

        return Paragraph(text, self.styles["Normal"])

    def _create_finding_detail(self, finding: Finding, index: int) -> List[Any]:
        """Create detailed finding section."""
        elements = []

        # Finding header with severity badge
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }
        color = severity_colors.get(finding.severity.lower(), "#6c757d")

        header_text = f"""
        <font color="{color}"><b>[{finding.severity.upper()}]</b></font>
        {finding.title}
        """
        elements.append(Paragraph(header_text, self.styles["FindingTitle"]))

        # Metadata table
        meta_data = [
            ["Finding ID:", finding.id],
            ["Module:", finding.module or "N/A"],
            ["Category:", finding.category or "N/A"],
            ["Status:", finding.status.title()],
        ]
        if finding.cvss_score:
            meta_data.append(["CVSS Score:", f"{finding.cvss_score:.1f}"])
        if finding.cve_ids:
            meta_data.append(["CVE IDs:", ", ".join(finding.cve_ids)])

        meta_table = Table(meta_data, colWidths=[1.2 * inch, 4.5 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.grey),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Description
        elements.append(Paragraph("<b>Description:</b>", self.styles["Normal"]))
        elements.append(
            Paragraph(
                finding.description or "No description provided.",
                self.styles["Normal"],
            )
        )
        elements.append(Spacer(1, 10))

        # Evidence
        if finding.evidence:
            elements.append(Paragraph("<b>Evidence:</b>", self.styles["Normal"]))

            evidence_text = []
            for key, value in finding.evidence.items():
                if isinstance(value, str) and len(value) > 200:
                    value = value[:200] + "..."
                evidence_text.append(f"{key}: {value}")

            evidence_str = "\n".join(evidence_text)
            # Escape special characters for Preformatted
            evidence_str = (
                evidence_str.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            elements.append(
                Preformatted(evidence_str, self.styles["Code"], maxLineLength=80)
            )
            elements.append(Spacer(1, 10))

        # Remediation
        if self.config.include_remediation and finding.remediation:
            elements.append(Paragraph("<b>Remediation:</b>", self.styles["Normal"]))
            elements.append(Paragraph(finding.remediation, self.styles["Remediation"]))
            elements.append(Spacer(1, 10))

        # References
        if finding.references:
            elements.append(Paragraph("<b>References:</b>", self.styles["Normal"]))
            ref_items = [
                ListItem(
                    Paragraph(ref, self.styles["Normal"]),
                    bulletColor=colors.HexColor("#2c3e50"),
                )
                for ref in finding.references
            ]
            elements.append(ListFlowable(ref_items, bulletType="bullet"))

        # Separator
        elements.append(Spacer(1, 5))
        separator_table = Table([[""] * 1], colWidths=[6 * inch])
        separator_table.setStyle(
            TableStyle(
                [
                    ("LINEBELOW", (0, 0), (-1, -1), 1, colors.HexColor("#e9ecef")),
                ]
            )
        )
        elements.append(separator_table)

        return elements


# Register the report type
ReportGenerator.register_report_type(
    ReportType.DETAILED_FINDINGS, DetailedFindingsReport
)
