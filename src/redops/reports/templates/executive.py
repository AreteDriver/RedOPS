"""Executive summary report template."""

from typing import Any

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.graphics.shapes import Drawing, Rect, String

from ..generator import BaseReport, ScanResult, ReportType, ReportGenerator


class ExecutiveSummaryReport(BaseReport):
    """Executive summary report for management audiences.

    Provides high-level overview with risk scores, severity distribution,
    and key recommendations without technical details.
    """

    def generate(self, data: ScanResult) -> list[Any]:
        """Generate executive summary content."""
        elements = []

        # Header
        elements.extend(self._create_header(data))

        # Executive Summary Section
        elements.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
        elements.append(self._create_risk_overview(data))
        elements.append(Spacer(1, 20))

        # Risk Score Visualization
        elements.append(self._create_risk_gauge(data))
        elements.append(Spacer(1, 20))

        # Severity Distribution
        elements.append(
            Paragraph("Findings Distribution", self.styles["SectionHeader"])
        )
        elements.append(self._create_severity_chart(data))
        elements.append(Spacer(1, 20))

        # Key Statistics
        elements.append(Paragraph("Key Statistics", self.styles["SectionHeader"]))
        elements.append(self._create_statistics_table(data))
        elements.append(Spacer(1, 20))

        # Top Findings
        if data.findings:
            elements.append(
                Paragraph(
                    "Critical & High Severity Findings", self.styles["SectionHeader"]
                )
            )
            critical_high = [
                f for f in data.findings if f.severity.lower() in ("critical", "high")
            ]
            if critical_high:
                elements.append(self._create_findings_table(critical_high[:10]))
            else:
                elements.append(
                    Paragraph(
                        "No critical or high severity findings detected.",
                        self.styles["Normal"],
                    )
                )
            elements.append(Spacer(1, 20))

        # Recommendations
        elements.append(Paragraph("Key Recommendations", self.styles["SectionHeader"]))
        elements.append(self._create_recommendations(data))

        # Page break before appendix
        if self.config.include_appendix:
            elements.append(PageBreak())
            elements.append(
                Paragraph("Appendix: All Findings", self.styles["SectionHeader"])
            )
            elements.append(self._create_findings_table(data.findings))

        return elements

    def _create_risk_overview(self, data: ScanResult) -> Paragraph:
        """Create risk overview paragraph."""
        counts = data.severity_counts
        total = sum(counts.values())
        risk_score = data.risk_score

        if risk_score >= 80:
            risk_level = "CRITICAL"
            risk_color = "#dc3545"
        elif risk_score >= 60:
            risk_level = "HIGH"
            risk_color = "#fd7e14"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            risk_color = "#ffc107"
        elif risk_score >= 20:
            risk_level = "LOW"
            risk_color = "#17a2b8"
        else:
            risk_level = "MINIMAL"
            risk_color = "#28a745"

        text = f"""
        The security assessment of <b>{data.target}</b> identified <b>{total}</b> total findings.
        The overall risk level is rated as <font color="{risk_color}"><b>{risk_level}</b></font>
        with a risk score of <b>{risk_score:.0f}/100</b>.
        <br/><br/>
        <b>Finding Breakdown:</b><br/>
        • Critical: {counts["critical"]} findings<br/>
        • High: {counts["high"]} findings<br/>
        • Medium: {counts["medium"]} findings<br/>
        • Low: {counts["low"]} findings<br/>
        • Informational: {counts["info"]} findings
        """
        return Paragraph(text, self.styles["Normal"])

    def _create_risk_gauge(self, data: ScanResult) -> Drawing:
        """Create a risk score gauge visualization."""
        drawing = Drawing(400, 120)

        # Background rectangle
        drawing.add(
            Rect(50, 40, 300, 40, fillColor=colors.HexColor("#e9ecef"), strokeWidth=0)
        )

        # Risk score fill
        risk_score = data.risk_score
        fill_width = (risk_score / 100) * 300

        # Color based on score
        if risk_score >= 80:
            fill_color = colors.HexColor("#dc3545")
        elif risk_score >= 60:
            fill_color = colors.HexColor("#fd7e14")
        elif risk_score >= 40:
            fill_color = colors.HexColor("#ffc107")
        elif risk_score >= 20:
            fill_color = colors.HexColor("#17a2b8")
        else:
            fill_color = colors.HexColor("#28a745")

        drawing.add(Rect(50, 40, fill_width, 40, fillColor=fill_color, strokeWidth=0))

        # Score text
        drawing.add(
            String(
                200,
                100,
                f"Risk Score: {risk_score:.0f}/100",
                fontName="Helvetica-Bold",
                fontSize=14,
                textAnchor="middle",
            )
        )

        # Scale markers
        for i, label in enumerate(["0", "25", "50", "75", "100"]):
            x = 50 + (i * 75)
            drawing.add(
                String(
                    x, 25, label, fontName="Helvetica", fontSize=9, textAnchor="middle"
                )
            )

        return drawing

    def _create_statistics_table(self, data: ScanResult) -> Table:
        """Create key statistics table."""
        duration = data.duration
        duration_str = f"{duration / 60:.1f} minutes" if duration else "N/A"

        stats = [
            ["Metric", "Value"],
            ["Total Findings", str(len(data.findings))],
            ["Scan Duration", duration_str],
            ["Risk Score", f"{data.risk_score:.0f}/100"],
            ["Pipeline", data.pipeline],
            ["Status", data.status.title()],
        ]

        # Count findings by status
        status_counts = {}
        for finding in data.findings:
            status = finding.status
            status_counts[status] = status_counts.get(status, 0) + 1

        for status, count in status_counts.items():
            stats.append([f"Findings ({status.title()})", str(count)])

        table = Table(stats, colWidths=[2.5 * inch, 2 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8f9fa")],
                    ),
                ]
            )
        )
        return table

    def _create_recommendations(self, data: ScanResult) -> Table:
        """Create prioritized recommendations."""
        recommendations = []

        counts = data.severity_counts

        if counts["critical"] > 0:
            recommendations.append(
                [
                    "1",
                    "IMMEDIATE",
                    f"Address {counts['critical']} critical vulnerability(ies) immediately. "
                    "These pose an imminent threat to system security.",
                ]
            )

        if counts["high"] > 0:
            recommendations.append(
                [
                    str(len(recommendations) + 1),
                    "URGENT",
                    f"Remediate {counts['high']} high severity finding(s) within 7 days. "
                    "These represent significant security risks.",
                ]
            )

        if counts["medium"] > 0:
            recommendations.append(
                [
                    str(len(recommendations) + 1),
                    "MODERATE",
                    f"Plan remediation for {counts['medium']} medium severity finding(s) within 30 days.",
                ]
            )

        if counts["low"] > 0:
            recommendations.append(
                [
                    str(len(recommendations) + 1),
                    "LOW",
                    f"Review {counts['low']} low severity finding(s) for potential improvements.",
                ]
            )

        if not recommendations:
            recommendations.append(
                [
                    "1",
                    "MAINTAIN",
                    "Continue current security practices. No critical issues detected.",
                ]
            )

        # Add general recommendation
        recommendations.append(
            [
                str(len(recommendations) + 1),
                "ONGOING",
                "Schedule regular security assessments to maintain security posture.",
            ]
        )

        headers = [["#", "Priority", "Recommendation"]]
        table = Table(
            headers + recommendations,
            colWidths=[0.4 * inch, 1 * inch, 4.5 * inch],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8f9fa")],
                    ),
                ]
            )
        )
        return table


# Register the report type
ReportGenerator.register_report_type(
    ReportType.EXECUTIVE_SUMMARY, ExecutiveSummaryReport
)
