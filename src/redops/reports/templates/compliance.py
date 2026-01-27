"""Compliance report template."""

from typing import Any, List, Dict

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from ..generator import BaseReport, ScanResult, ReportType, ReportGenerator


# Compliance framework mappings
COMPLIANCE_FRAMEWORKS = {
    "OWASP": {
        "name": "OWASP Top 10",
        "version": "2021",
        "categories": {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable Components",
            "A07": "Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery",
        },
    },
    "CWE": {
        "name": "Common Weakness Enumeration",
        "version": "4.9",
        "categories": {
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-22": "Path Traversal",
            "CWE-78": "OS Command Injection",
            "CWE-352": "Cross-Site Request Forgery",
            "CWE-287": "Improper Authentication",
            "CWE-611": "XML External Entities",
            "CWE-918": "Server-Side Request Forgery",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-434": "Unrestricted File Upload",
        },
    },
    "PCI-DSS": {
        "name": "PCI DSS",
        "version": "4.0",
        "categories": {
            "Req-1": "Install and maintain network security controls",
            "Req-2": "Apply secure configurations",
            "Req-3": "Protect stored account data",
            "Req-4": "Protect cardholder data with strong cryptography",
            "Req-5": "Protect systems and networks from malicious software",
            "Req-6": "Develop and maintain secure systems and software",
            "Req-7": "Restrict access to system components",
            "Req-8": "Identify users and authenticate access",
            "Req-9": "Restrict physical access to cardholder data",
            "Req-10": "Log and monitor all access",
            "Req-11": "Test security of systems and networks regularly",
            "Req-12": "Support information security with organizational policies",
        },
    },
    "NIST": {
        "name": "NIST Cybersecurity Framework",
        "version": "2.0",
        "categories": {
            "ID": "Identify",
            "PR": "Protect",
            "DE": "Detect",
            "RS": "Respond",
            "RC": "Recover",
        },
    },
}


class ComplianceReport(BaseReport):
    """Compliance-focused report mapping findings to frameworks.

    Maps security findings to compliance requirements from various
    frameworks like OWASP, CWE, PCI-DSS, and NIST.
    """

    def generate(self, data: ScanResult) -> List[Any]:
        """Generate compliance report content."""
        elements = []

        # Header
        elements.extend(self._create_header(data))

        # Compliance Overview
        elements.append(Paragraph("Compliance Overview", self.styles["SectionHeader"]))
        elements.append(self._create_compliance_summary(data))
        elements.append(Spacer(1, 20))

        # OWASP Top 10 Mapping
        elements.append(
            Paragraph("OWASP Top 10 (2021) Mapping", self.styles["SectionHeader"])
        )
        elements.append(self._create_framework_mapping(data, "OWASP"))
        elements.append(Spacer(1, 20))

        # CWE Mapping
        elements.append(Paragraph("CWE Mapping", self.styles["SectionHeader"]))
        elements.append(self._create_framework_mapping(data, "CWE"))
        elements.append(Spacer(1, 20))

        # PCI-DSS Assessment
        elements.append(PageBreak())
        elements.append(
            Paragraph("PCI DSS 4.0 Assessment", self.styles["SectionHeader"])
        )
        elements.append(self._create_pci_assessment(data))
        elements.append(Spacer(1, 20))

        # NIST Framework Mapping
        elements.append(Paragraph("NIST CSF Mapping", self.styles["SectionHeader"]))
        elements.append(self._create_framework_mapping(data, "NIST"))
        elements.append(Spacer(1, 20))

        # Compliance Gaps
        elements.append(
            Paragraph("Compliance Gaps & Recommendations", self.styles["SectionHeader"])
        )
        elements.append(self._create_compliance_gaps(data))

        return elements

    def _create_compliance_summary(self, data: ScanResult) -> Table:
        """Create compliance summary table."""
        # Calculate compliance scores (simplified)
        counts = data.severity_counts
        total_findings = sum(counts.values())

        # Simplified scoring based on findings
        if counts["critical"] > 0 or counts["high"] > 5:
            owasp_status = "Non-Compliant"
            pci_status = "Fail"
        elif counts["high"] > 0 or counts["medium"] > 10:
            owasp_status = "Partially Compliant"
            pci_status = "At Risk"
        else:
            owasp_status = "Compliant"
            pci_status = "Pass"

        summary_data = [
            ["Framework", "Version", "Status", "Findings Mapped"],
            ["OWASP Top 10", "2021", owasp_status, str(total_findings)],
            ["CWE", "4.9", "See Details", str(total_findings)],
            ["PCI DSS", "4.0", pci_status, str(total_findings)],
            ["NIST CSF", "2.0", "See Details", str(total_findings)],
        ]

        table = Table(
            summary_data, colWidths=[1.5 * inch, 0.8 * inch, 1.5 * inch, 1.2 * inch]
        )

        # Status colors
        status_colors = {
            "Compliant": colors.HexColor("#28a745"),
            "Pass": colors.HexColor("#28a745"),
            "Partially Compliant": colors.HexColor("#ffc107"),
            "At Risk": colors.HexColor("#ffc107"),
            "Non-Compliant": colors.HexColor("#dc3545"),
            "Fail": colors.HexColor("#dc3545"),
        }

        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (2, 0), (3, -1), "CENTER"),
        ]

        # Color status cells
        for i, row in enumerate(summary_data[1:], 1):
            status = row[2]
            if status in status_colors:
                style.append(("TEXTCOLOR", (2, i), (2, i), status_colors[status]))
                style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))

        table.setStyle(TableStyle(style))
        return table

    def _create_framework_mapping(self, data: ScanResult, framework: str) -> Table:
        """Create framework-specific mapping table."""
        fw = COMPLIANCE_FRAMEWORKS.get(framework, {})
        categories = fw.get("categories", {})

        # Map findings to categories (simplified - would need real mapping logic)
        category_findings: Dict[str, List] = {cat_id: [] for cat_id in categories}

        # Simple heuristic mapping based on finding categories/titles
        for finding in data.findings:
            cat = (finding.category or "").lower()
            title = finding.title.lower()

            # Map to OWASP categories
            if framework == "OWASP":
                if "inject" in title or "sql" in cat:
                    category_findings.get("A03", []).append(finding)
                elif "auth" in title or "session" in cat:
                    category_findings.get("A07", []).append(finding)
                elif "xss" in title or "script" in cat:
                    category_findings.get("A03", []).append(finding)
                elif "config" in title or "default" in cat:
                    category_findings.get("A05", []).append(finding)
                elif "crypto" in title or "ssl" in cat or "tls" in cat:
                    category_findings.get("A02", []).append(finding)
                elif "access" in title or "permission" in cat:
                    category_findings.get("A01", []).append(finding)
                elif "ssrf" in title:
                    category_findings.get("A10", []).append(finding)
                elif "component" in cat or "version" in cat:
                    category_findings.get("A06", []).append(finding)
            elif framework == "CWE":
                if "xss" in title:
                    category_findings.get("CWE-79", []).append(finding)
                elif "sql" in title:
                    category_findings.get("CWE-89", []).append(finding)
                elif "path" in title or "traversal" in title:
                    category_findings.get("CWE-22", []).append(finding)
                elif "command" in title:
                    category_findings.get("CWE-78", []).append(finding)
            elif framework == "NIST":
                # Map to NIST functions
                if finding.severity.lower() in ("critical", "high"):
                    category_findings.get("PR", []).append(finding)
                else:
                    category_findings.get("DE", []).append(finding)

        # Build table
        table_data = [["Category", "Description", "Findings", "Status"]]

        for cat_id, cat_name in categories.items():
            findings_list = category_findings.get(cat_id, [])
            count = len(findings_list)

            if count == 0:
                status = "Pass"
            elif any(f.severity.lower() in ("critical", "high") for f in findings_list):
                status = "Fail"
            else:
                status = "Warning"

            table_data.append([cat_id, cat_name[:35], str(count), status])

        table = Table(
            table_data, colWidths=[0.8 * inch, 2.5 * inch, 0.8 * inch, 0.8 * inch]
        )

        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f8f9fa")],
            ),
        ]

        # Color status cells
        status_colors = {
            "Pass": colors.HexColor("#28a745"),
            "Warning": colors.HexColor("#ffc107"),
            "Fail": colors.HexColor("#dc3545"),
        }

        for i, row in enumerate(table_data[1:], 1):
            status = row[3]
            if status in status_colors:
                style.append(("TEXTCOLOR", (3, i), (3, i), status_colors[status]))
                style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))

        table.setStyle(TableStyle(style))
        return table

    def _create_pci_assessment(self, data: ScanResult) -> Table:
        """Create PCI-DSS specific assessment."""
        requirements = COMPLIANCE_FRAMEWORKS["PCI-DSS"]["categories"]

        # Map findings to PCI requirements (simplified)
        req_findings: Dict[str, List] = {req: [] for req in requirements}

        for finding in data.findings:
            cat = (finding.category or "").lower()
            title = finding.title.lower()

            # Simple mapping heuristics
            if "network" in cat or "firewall" in title:
                req_findings["Req-1"].append(finding)
            if "config" in cat or "default" in title:
                req_findings["Req-2"].append(finding)
            if "data" in cat or "storage" in title or "encrypt" in title:
                req_findings["Req-3"].append(finding)
                req_findings["Req-4"].append(finding)
            if "malware" in cat or "virus" in title:
                req_findings["Req-5"].append(finding)
            if "vuln" in cat or "patch" in title:
                req_findings["Req-6"].append(finding)
            if "access" in cat or "permission" in title:
                req_findings["Req-7"].append(finding)
            if "auth" in cat or "password" in title:
                req_findings["Req-8"].append(finding)
            if "log" in cat or "audit" in title:
                req_findings["Req-10"].append(finding)
            if "test" in cat or "scan" in title:
                req_findings["Req-11"].append(finding)

        table_data = [["Requirement", "Description", "Issues", "Status"]]

        for req_id, req_name in requirements.items():
            findings_list = req_findings.get(req_id, [])
            critical_high = sum(
                1 for f in findings_list if f.severity.lower() in ("critical", "high")
            )

            if critical_high > 0:
                status = "Fail"
            elif len(findings_list) > 0:
                status = "At Risk"
            else:
                status = "Pass"

            table_data.append([req_id, req_name[:40], str(len(findings_list)), status])

        table = Table(
            table_data, colWidths=[0.8 * inch, 3 * inch, 0.7 * inch, 0.8 * inch]
        )

        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f8f9fa")],
            ),
        ]

        status_colors = {
            "Pass": colors.HexColor("#28a745"),
            "At Risk": colors.HexColor("#ffc107"),
            "Fail": colors.HexColor("#dc3545"),
        }

        for i, row in enumerate(table_data[1:], 1):
            status = row[3]
            if status in status_colors:
                style.append(("TEXTCOLOR", (3, i), (3, i), status_colors[status]))
                style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))

        table.setStyle(TableStyle(style))
        return table

    def _create_compliance_gaps(self, data: ScanResult) -> Paragraph:
        """Create compliance gaps and recommendations section."""
        counts = data.severity_counts
        gaps = []

        if counts["critical"] > 0:
            gaps.append(
                f"• <b>Critical Gap:</b> {counts['critical']} critical findings require "
                "immediate remediation to achieve compliance with any framework."
            )

        if counts["high"] > 0:
            gaps.append(
                f"• <b>High Priority:</b> {counts['high']} high severity findings "
                "may impact PCI-DSS and OWASP compliance status."
            )

        if counts["medium"] > 5:
            gaps.append(
                f"• <b>Moderate Risk:</b> {counts['medium']} medium severity findings "
                "should be addressed within the next audit cycle."
            )

        if not gaps:
            gaps.append(
                "• <b>Good Standing:</b> No critical compliance gaps identified. "
                "Continue regular security assessments to maintain compliance."
            )

        # Add general recommendations
        gaps.extend(
            [
                "<br/><br/><b>General Recommendations:</b>",
                "• Implement a vulnerability management program with defined SLAs",
                "• Conduct regular penetration testing (at least annually for PCI-DSS)",
                "• Maintain security documentation and evidence for audits",
                "• Train development teams on secure coding practices (OWASP)",
                "• Implement continuous security monitoring and logging",
            ]
        )

        text = "<br/>".join(gaps)
        return Paragraph(text, self.styles["Normal"])


# Register the report type
ReportGenerator.register_report_type(ReportType.COMPLIANCE, ComplianceReport)
