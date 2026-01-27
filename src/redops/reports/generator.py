"""
Report generator for RedOPS.

Generates PDF and other format reports from scan results.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any, Optional, Dict, List, Type
import logging

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats."""

    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"


class ReportType(Enum):
    """Types of reports."""

    EXECUTIVE_SUMMARY = "executive_summary"
    DETAILED_FINDINGS = "detailed_findings"
    COMPLIANCE = "compliance"
    TREND_ANALYSIS = "trend_analysis"
    COMPARISON = "comparison"


@dataclass
class ReportConfig:
    """Report configuration."""

    title: str = "Security Assessment Report"
    subtitle: str = ""
    author: str = "RedOPS Security Scanner"
    organization: str = ""
    logo_path: Optional[str] = None
    page_size: tuple = letter
    include_toc: bool = True
    include_summary: bool = True
    include_remediation: bool = True
    include_appendix: bool = False
    classification: str = "CONFIDENTIAL"
    custom_styles: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Scan finding for reports."""

    id: str
    title: str
    severity: str
    description: str
    module: str = ""
    category: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    status: str = "open"


@dataclass
class ScanResult:
    """Scan result data for reports."""

    scan_id: str
    target: str
    pipeline: str
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        weights = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}
        counts = self.severity_counts
        total = sum(counts.get(s, 0) * w for s, w in weights.items())
        # Normalize to 0-100 scale (cap at 100)
        return min(100, total)


class BaseReport(ABC):
    """Base class for all report types."""

    def __init__(self, config: ReportConfig):
        self.config = config
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self) -> None:
        """Set up custom paragraph styles."""
        # Title style
        self.styles.add(
            ParagraphStyle(
                "ReportTitle",
                parent=self.styles["Heading1"],
                fontSize=24,
                spaceAfter=30,
                alignment=1,  # Center
            )
        )

        # Subtitle style
        self.styles.add(
            ParagraphStyle(
                "ReportSubtitle",
                parent=self.styles["Normal"],
                fontSize=14,
                spaceAfter=20,
                alignment=1,
                textColor=colors.grey,
            )
        )

        # Section header style
        self.styles.add(
            ParagraphStyle(
                "SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=16,
                spaceBefore=20,
                spaceAfter=10,
                textColor=colors.HexColor("#2c3e50"),
            )
        )

        # Finding title style
        self.styles.add(
            ParagraphStyle(
                "FindingTitle",
                parent=self.styles["Heading3"],
                fontSize=12,
                spaceBefore=10,
                spaceAfter=5,
            )
        )

        # Severity styles
        for severity, color in [
            ("Critical", "#dc3545"),
            ("High", "#fd7e14"),
            ("Medium", "#ffc107"),
            ("Low", "#17a2b8"),
            ("Info", "#6c757d"),
        ]:
            self.styles.add(
                ParagraphStyle(
                    f"Severity{severity}",
                    parent=self.styles["Normal"],
                    fontSize=10,
                    textColor=colors.HexColor(color),
                    backColor=colors.HexColor(f"{color}20"),
                )
            )

    @abstractmethod
    def generate(self, data: ScanResult) -> List[Any]:
        """Generate report content.

        Args:
            data: Scan result data

        Returns:
            List of flowable elements
        """
        pass

    def _create_header(self, data: ScanResult) -> List[Any]:
        """Create report header."""
        elements = []

        # Logo if provided
        if self.config.logo_path and Path(self.config.logo_path).exists():
            logo = Image(self.config.logo_path, width=2 * inch, height=1 * inch)
            elements.append(logo)
            elements.append(Spacer(1, 20))

        # Title and subtitle
        elements.append(Paragraph(self.config.title, self.styles["ReportTitle"]))
        if self.config.subtitle:
            elements.append(
                Paragraph(self.config.subtitle, self.styles["ReportSubtitle"])
            )

        # Classification banner
        elements.append(
            Paragraph(
                f"<b>{self.config.classification}</b>",
                ParagraphStyle(
                    "Classification",
                    parent=self.styles["Normal"],
                    alignment=1,
                    textColor=colors.red,
                    fontSize=10,
                ),
            )
        )
        elements.append(Spacer(1, 20))

        # Report metadata table
        meta_data = [
            ["Target:", data.target],
            ["Scan ID:", data.scan_id],
            ["Pipeline:", data.pipeline],
            ["Date:", data.started_at.strftime("%Y-%m-%d %H:%M:%S")],
            ["Generated By:", self.config.author],
        ]
        if self.config.organization:
            meta_data.append(["Organization:", self.config.organization])

        meta_table = Table(meta_data, colWidths=[1.5 * inch, 4 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 30))

        return elements

    def _create_severity_chart(self, data: ScanResult) -> Drawing:
        """Create severity distribution pie chart."""
        drawing = Drawing(400, 200)

        counts = data.severity_counts
        labels = []
        data_values = []
        chart_colors = []

        color_map = {
            "critical": colors.HexColor("#dc3545"),
            "high": colors.HexColor("#fd7e14"),
            "medium": colors.HexColor("#ffc107"),
            "low": colors.HexColor("#17a2b8"),
            "info": colors.HexColor("#6c757d"),
        }

        for severity, count in counts.items():
            if count > 0:
                labels.append(f"{severity.title()} ({count})")
                data_values.append(count)
                chart_colors.append(color_map.get(severity, colors.grey))

        if data_values:
            pie = Pie()
            pie.x = 150
            pie.y = 50
            pie.width = 100
            pie.height = 100
            pie.data = data_values
            pie.labels = labels
            pie.slices.strokeWidth = 0.5

            for i, color in enumerate(chart_colors):
                pie.slices[i].fillColor = color

            drawing.add(pie)

        return drawing

    def _create_findings_table(
        self, findings: List[Finding], include_details: bool = False
    ) -> Table:
        """Create findings summary table."""
        headers = ["#", "Title", "Severity", "Category", "Status"]
        if include_details:
            headers.append("CVSS")

        rows = [headers]

        for i, finding in enumerate(findings, 1):
            row = [
                str(i),
                finding.title[:50] + "..."
                if len(finding.title) > 50
                else finding.title,
                finding.severity.upper(),
                finding.category or "N/A",
                finding.status.title(),
            ]
            if include_details:
                row.append(str(finding.cvss_score) if finding.cvss_score else "N/A")
            rows.append(row)

        col_widths = [0.4 * inch, 2.5 * inch, 0.8 * inch, 1 * inch, 0.8 * inch]
        if include_details:
            col_widths.append(0.5 * inch)

        table = Table(rows, colWidths=col_widths)

        # Style the table
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f8f9fa")],
            ),
        ]

        # Color severity cells
        severity_colors = {
            "CRITICAL": colors.HexColor("#dc354520"),
            "HIGH": colors.HexColor("#fd7e1420"),
            "MEDIUM": colors.HexColor("#ffc10720"),
            "LOW": colors.HexColor("#17a2b820"),
            "INFO": colors.HexColor("#6c757d20"),
        }

        for i, row in enumerate(rows[1:], 1):
            severity = row[2]
            if severity in severity_colors:
                style.append(("BACKGROUND", (2, i), (2, i), severity_colors[severity]))

        table.setStyle(TableStyle(style))
        return table


class ReportGenerator:
    """Main report generator class."""

    _report_types: Dict[ReportType, Type[BaseReport]] = {}

    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()

    @classmethod
    def register_report_type(
        cls, report_type: ReportType, report_class: Type[BaseReport]
    ) -> None:
        """Register a report type."""
        cls._report_types[report_type] = report_class

    def generate(
        self,
        data: ScanResult,
        report_type: ReportType = ReportType.EXECUTIVE_SUMMARY,
        output_path: Optional[str] = None,
        report_format: ReportFormat = ReportFormat.PDF,
    ) -> bytes:
        """Generate a report.

        Args:
            data: Scan result data
            report_type: Type of report to generate
            output_path: Optional path to save the report
            report_format: Output format

        Returns:
            Report content as bytes
        """
        if report_type not in self._report_types:
            raise ValueError(f"Unknown report type: {report_type}")

        report_class = self._report_types[report_type]
        report = report_class(self.config)

        if report_format == ReportFormat.PDF:
            content = self._generate_pdf(report, data)
        elif report_format == ReportFormat.HTML:
            content = self._generate_html(report, data)
        elif report_format == ReportFormat.MARKDOWN:
            content = self._generate_markdown(report, data)
        elif report_format == ReportFormat.JSON:
            content = self._generate_json(data)
        else:
            raise ValueError(f"Unsupported format: {report_format}")

        if output_path:
            Path(output_path).write_bytes(content)
            logger.info(f"Report saved to {output_path}")

        return content

    def _generate_pdf(self, report: BaseReport, data: ScanResult) -> bytes:
        """Generate PDF report."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=self.config.page_size,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        elements = report.generate(data)
        doc.build(elements)

        return buffer.getvalue()

    def _generate_html(self, report: BaseReport, data: ScanResult) -> bytes:
        """Generate HTML report."""
        # Basic HTML generation
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.config.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .info {{ color: #6c757d; }}
    </style>
</head>
<body>
    <h1>{self.config.title}</h1>
    <p><strong>Target:</strong> {data.target}</p>
    <p><strong>Scan ID:</strong> {data.scan_id}</p>
    <p><strong>Date:</strong> {data.started_at.strftime("%Y-%m-%d %H:%M:%S")}</p>

    <h2>Findings Summary</h2>
    <table>
        <tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th></tr>
"""
        for i, finding in enumerate(data.findings, 1):
            html += f"""        <tr>
            <td>{i}</td>
            <td>{finding.title}</td>
            <td class="{finding.severity.lower()}">{finding.severity.upper()}</td>
            <td>{finding.status.title()}</td>
        </tr>
"""
        html += """    </table>
</body>
</html>"""
        return html.encode("utf-8")

    def _generate_markdown(self, report: BaseReport, data: ScanResult) -> bytes:
        """Generate Markdown report."""
        md = f"""# {self.config.title}

**Target:** {data.target}
**Scan ID:** {data.scan_id}
**Date:** {data.started_at.strftime("%Y-%m-%d %H:%M:%S")}

## Findings Summary

| # | Title | Severity | Status |
|---|-------|----------|--------|
"""
        for i, finding in enumerate(data.findings, 1):
            md += f"| {i} | {finding.title} | {finding.severity.upper()} | {finding.status.title()} |\n"

        md += "\n## Detailed Findings\n\n"
        for i, finding in enumerate(data.findings, 1):
            md += f"""### {i}. {finding.title}

**Severity:** {finding.severity.upper()}
**Category:** {finding.category or "N/A"}
**Status:** {finding.status.title()}

{finding.description}

"""
            if finding.remediation:
                md += f"**Remediation:** {finding.remediation}\n\n"

        return md.encode("utf-8")

    def _generate_json(self, data: ScanResult) -> bytes:
        """Generate JSON report."""
        import json

        report_data = {
            "title": self.config.title,
            "scan_id": data.scan_id,
            "target": data.target,
            "pipeline": data.pipeline,
            "started_at": data.started_at.isoformat(),
            "completed_at": data.completed_at.isoformat()
            if data.completed_at
            else None,
            "status": data.status,
            "severity_counts": data.severity_counts,
            "risk_score": data.risk_score,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "category": f.category,
                    "module": f.module,
                    "remediation": f.remediation,
                    "cvss_score": f.cvss_score,
                    "cve_ids": f.cve_ids,
                    "status": f.status,
                }
                for f in data.findings
            ],
        }
        return json.dumps(report_data, indent=2).encode("utf-8")
