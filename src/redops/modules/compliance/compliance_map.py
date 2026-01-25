"""
Compliance Mapping module.

Maps security findings to compliance frameworks including:
- PCI-DSS (Payment Card Industry Data Security Standard)
- HIPAA (Health Insurance Portability and Accountability Act)
- SOC 2 (Service Organization Control 2)
- NIST CSF (Cybersecurity Framework)
- ISO 27001 (Information Security Management)
- GDPR (General Data Protection Regulation)
- CIS Controls (Center for Internet Security)

Provides gap analysis, compliance scoring, and remediation prioritization.
"""

from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from redops.core.context import Context


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    CIS_CONTROLS = "cis_controls"


class ControlStatus(Enum):
    """Status of a compliance control."""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class ControlPriority(Enum):
    """Priority level for controls."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ComplianceControl:
    """A compliance control/requirement."""
    id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    priority: ControlPriority = ControlPriority.MEDIUM
    related_controls: List[str] = field(default_factory=list)  # Cross-framework mappings
    evidence_types: List[str] = field(default_factory=list)
    automation_possible: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "framework": self.framework.value,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "priority": self.priority.value,
            "related_controls": self.related_controls,
            "evidence_types": self.evidence_types,
            "automation_possible": self.automation_possible,
        }


@dataclass
class ControlAssessment:
    """Assessment result for a control."""
    control: ComplianceControl
    status: ControlStatus
    findings: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control.id,
            "framework": self.control.framework.value,
            "title": self.control.title,
            "status": self.status.value,
            "findings": self.findings,
            "evidence": self.evidence,
            "gaps": self.gaps,
            "remediation": self.remediation,
            "notes": self.notes,
        }


@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    framework: ComplianceFramework
    target: str
    assessments: List[ControlAssessment] = field(default_factory=list)
    overall_score: float = 0.0
    compliant_count: int = 0
    partial_count: int = 0
    non_compliant_count: int = 0
    not_assessed_count: int = 0
    critical_gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "target": self.target,
            "overall_score": self.overall_score,
            "compliant_count": self.compliant_count,
            "partial_count": self.partial_count,
            "non_compliant_count": self.non_compliant_count,
            "not_assessed_count": self.not_assessed_count,
            "critical_gaps": self.critical_gaps,
            "recommendations": self.recommendations,
            "assessments": [a.to_dict() for a in self.assessments],
        }


# ============================================================================
# PCI-DSS Controls (v4.0 simplified)
# ============================================================================

PCI_DSS_CONTROLS = {
    # Requirement 1: Network Security Controls
    "1.1": ComplianceControl(
        id="1.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Network Security Controls Defined",
        description="Processes and mechanisms for installing and maintaining network security controls are defined and understood",
        category="Network Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.AC-4", "ISO.A.13.1.1"],
        evidence_types=["firewall_config", "network_diagram"],
    ),
    "1.2": ComplianceControl(
        id="1.2",
        framework=ComplianceFramework.PCI_DSS,
        title="Network Security Controls Configured",
        description="Network security controls are configured and maintained",
        category="Network Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SC-7", "ISO.A.13.1.1"],
        evidence_types=["firewall_rules", "acl_config"],
    ),
    "1.3": ComplianceControl(
        id="1.3",
        framework=ComplianceFramework.PCI_DSS,
        title="Network Access Restricted",
        description="Network access to and from the cardholder data environment is restricted",
        category="Network Security",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.AC-3", "ISO.A.13.1.3"],
        evidence_types=["network_segmentation", "firewall_rules"],
    ),

    # Requirement 2: Secure Configurations
    "2.1": ComplianceControl(
        id="2.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Secure Configuration Processes",
        description="Processes and mechanisms for applying secure configurations are defined",
        category="Secure Configuration",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.CM-2", "ISO.A.12.5.1"],
        evidence_types=["hardening_standards", "config_baseline"],
    ),
    "2.2": ComplianceControl(
        id="2.2",
        framework=ComplianceFramework.PCI_DSS,
        title="System Components Securely Configured",
        description="System components are configured and managed securely",
        category="Secure Configuration",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.CM-6", "ISO.A.12.6.1"],
        evidence_types=["system_config", "hardening_scan"],
    ),

    # Requirement 3: Protect Stored Account Data
    "3.1": ComplianceControl(
        id="3.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Account Data Storage Minimized",
        description="Storage of account data is kept to a minimum",
        category="Data Protection",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.MP-6", "ISO.A.8.3.2", "GDPR.5"],
        evidence_types=["data_retention_policy", "data_inventory"],
    ),
    "3.2": ComplianceControl(
        id="3.2",
        framework=ComplianceFramework.PCI_DSS,
        title="Sensitive Authentication Data Not Stored",
        description="Sensitive authentication data is not stored after authorization",
        category="Data Protection",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.SC-28", "ISO.A.10.1.1"],
        evidence_types=["data_flow_diagram", "storage_audit"],
    ),

    # Requirement 4: Protect Cardholder Data in Transit
    "4.1": ComplianceControl(
        id="4.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Strong Cryptography for Transmission",
        description="Strong cryptography protects cardholder data during transmission",
        category="Encryption",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.SC-8", "ISO.A.10.1.1"],
        evidence_types=["tls_config", "encryption_policy"],
    ),

    # Requirement 5: Protect from Malware
    "5.1": ComplianceControl(
        id="5.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Anti-Malware Processes Defined",
        description="Processes and mechanisms for protecting against malware are defined",
        category="Malware Protection",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SI-3", "ISO.A.12.2.1"],
        evidence_types=["av_policy", "malware_scan_results"],
    ),
    "5.2": ComplianceControl(
        id="5.2",
        framework=ComplianceFramework.PCI_DSS,
        title="Malware is Prevented or Detected",
        description="Malware is prevented, or detected and addressed",
        category="Malware Protection",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SI-3", "ISO.A.12.2.1"],
        evidence_types=["av_logs", "endpoint_protection"],
    ),

    # Requirement 6: Secure Systems and Software
    "6.1": ComplianceControl(
        id="6.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Secure Development Processes",
        description="Processes and mechanisms for developing secure systems and software are defined",
        category="Secure Development",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SA-3", "ISO.A.14.2.1"],
        evidence_types=["sdlc_policy", "secure_coding_standards"],
    ),
    "6.2": ComplianceControl(
        id="6.2",
        framework=ComplianceFramework.PCI_DSS,
        title="Custom Software Developed Securely",
        description="Bespoke and custom software is developed securely",
        category="Secure Development",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SA-11", "ISO.A.14.2.5"],
        evidence_types=["code_review", "security_testing"],
    ),
    "6.3": ComplianceControl(
        id="6.3",
        framework=ComplianceFramework.PCI_DSS,
        title="Security Vulnerabilities Identified and Addressed",
        description="Security vulnerabilities are identified and addressed",
        category="Vulnerability Management",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.RA-5", "ISO.A.12.6.1"],
        evidence_types=["vuln_scan", "patch_management"],
    ),

    # Requirement 7: Restrict Access
    "7.1": ComplianceControl(
        id="7.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Access Control Processes Defined",
        description="Processes and mechanisms for restricting access are defined",
        category="Access Control",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.AC-1", "ISO.A.9.1.1"],
        evidence_types=["access_policy", "role_definitions"],
    ),
    "7.2": ComplianceControl(
        id="7.2",
        framework=ComplianceFramework.PCI_DSS,
        title="Access Appropriately Defined and Assigned",
        description="Access to system components and data is appropriately defined and assigned",
        category="Access Control",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.AC-2", "ISO.A.9.2.1"],
        evidence_types=["access_matrix", "user_provisioning"],
    ),

    # Requirement 8: Identify Users and Authenticate Access
    "8.1": ComplianceControl(
        id="8.1",
        framework=ComplianceFramework.PCI_DSS,
        title="User Identification Processes Defined",
        description="Processes for user identification and authentication are defined",
        category="Authentication",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.IA-1", "ISO.A.9.2.1"],
        evidence_types=["auth_policy", "identity_management"],
    ),
    "8.2": ComplianceControl(
        id="8.2",
        framework=ComplianceFramework.PCI_DSS,
        title="User Identification and Authentication for Users",
        description="User identification and related accounts are strictly managed",
        category="Authentication",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.IA-2", "ISO.A.9.2.3"],
        evidence_types=["user_accounts", "auth_logs"],
    ),
    "8.3": ComplianceControl(
        id="8.3",
        framework=ComplianceFramework.PCI_DSS,
        title="Strong Authentication Established",
        description="Strong authentication for users and administrators is established",
        category="Authentication",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.IA-5", "ISO.A.9.4.3"],
        evidence_types=["mfa_config", "password_policy"],
    ),

    # Requirement 10: Log and Monitor Access
    "10.1": ComplianceControl(
        id="10.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Logging Processes Defined",
        description="Processes for logging and monitoring are defined and implemented",
        category="Logging and Monitoring",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.AU-1", "ISO.A.12.4.1"],
        evidence_types=["logging_policy", "log_config"],
    ),
    "10.2": ComplianceControl(
        id="10.2",
        framework=ComplianceFramework.PCI_DSS,
        title="Audit Logs Implemented",
        description="Audit logs are implemented to support detection of anomalies",
        category="Logging and Monitoring",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.AU-2", "ISO.A.12.4.1"],
        evidence_types=["audit_logs", "log_review"],
    ),

    # Requirement 11: Test Security Regularly
    "11.1": ComplianceControl(
        id="11.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Security Testing Processes Defined",
        description="Processes for security testing are defined and implemented",
        category="Security Testing",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.CA-8", "ISO.A.18.2.3"],
        evidence_types=["testing_policy", "pentest_scope"],
    ),
    "11.3": ComplianceControl(
        id="11.3",
        framework=ComplianceFramework.PCI_DSS,
        title="Vulnerabilities Identified and Addressed",
        description="External and internal vulnerabilities are regularly identified and addressed",
        category="Vulnerability Management",
        priority=ControlPriority.CRITICAL,
        related_controls=["NIST.RA-5", "ISO.A.12.6.1"],
        evidence_types=["vuln_scan_results", "pentest_report"],
    ),

    # Requirement 12: Support Information Security with Policies
    "12.1": ComplianceControl(
        id="12.1",
        framework=ComplianceFramework.PCI_DSS,
        title="Information Security Policy",
        description="A comprehensive information security policy is established",
        category="Governance",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.PL-1", "ISO.A.5.1.1"],
        evidence_types=["security_policy", "policy_review"],
    ),
}

# ============================================================================
# HIPAA Controls (Simplified)
# ============================================================================

HIPAA_CONTROLS = {
    # Administrative Safeguards
    "164.308(a)(1)": ComplianceControl(
        id="164.308(a)(1)",
        framework=ComplianceFramework.HIPAA,
        title="Security Management Process",
        description="Implement policies and procedures to prevent, detect, contain, and correct security violations",
        category="Administrative Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.12.1", "ISO.A.5.1.1"],
        evidence_types=["security_policy", "risk_assessment"],
    ),
    "164.308(a)(3)": ComplianceControl(
        id="164.308(a)(3)",
        framework=ComplianceFramework.HIPAA,
        title="Workforce Security",
        description="Implement policies to ensure appropriate access to ePHI",
        category="Administrative Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.7.1", "ISO.A.9.1.1"],
        evidence_types=["access_policy", "workforce_clearance"],
    ),
    "164.308(a)(4)": ComplianceControl(
        id="164.308(a)(4)",
        framework=ComplianceFramework.HIPAA,
        title="Information Access Management",
        description="Implement policies for authorizing access to ePHI",
        category="Administrative Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.7.2", "ISO.A.9.2.1"],
        evidence_types=["access_authorization", "access_review"],
    ),
    "164.308(a)(5)": ComplianceControl(
        id="164.308(a)(5)",
        framework=ComplianceFramework.HIPAA,
        title="Security Awareness Training",
        description="Implement security awareness and training program",
        category="Administrative Safeguards",
        priority=ControlPriority.MEDIUM,
        related_controls=["NIST.AT-2", "ISO.A.7.2.2"],
        evidence_types=["training_records", "awareness_program"],
    ),
    "164.308(a)(6)": ComplianceControl(
        id="164.308(a)(6)",
        framework=ComplianceFramework.HIPAA,
        title="Security Incident Procedures",
        description="Implement policies for responding to security incidents",
        category="Administrative Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.IR-1", "ISO.A.16.1.1"],
        evidence_types=["incident_response_plan", "incident_logs"],
    ),
    "164.308(a)(7)": ComplianceControl(
        id="164.308(a)(7)",
        framework=ComplianceFramework.HIPAA,
        title="Contingency Plan",
        description="Establish policies for responding to emergencies",
        category="Administrative Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.CP-1", "ISO.A.17.1.1"],
        evidence_types=["contingency_plan", "backup_procedures"],
    ),

    # Physical Safeguards
    "164.310(a)(1)": ComplianceControl(
        id="164.310(a)(1)",
        framework=ComplianceFramework.HIPAA,
        title="Facility Access Controls",
        description="Limit physical access to facilities containing ePHI",
        category="Physical Safeguards",
        priority=ControlPriority.MEDIUM,
        related_controls=["NIST.PE-2", "ISO.A.11.1.2"],
        evidence_types=["facility_access_policy", "access_logs"],
    ),
    "164.310(b)": ComplianceControl(
        id="164.310(b)",
        framework=ComplianceFramework.HIPAA,
        title="Workstation Use",
        description="Implement policies for proper workstation use",
        category="Physical Safeguards",
        priority=ControlPriority.MEDIUM,
        related_controls=["NIST.AC-11", "ISO.A.11.2.8"],
        evidence_types=["workstation_policy", "workstation_audit"],
    ),
    "164.310(d)": ComplianceControl(
        id="164.310(d)",
        framework=ComplianceFramework.HIPAA,
        title="Device and Media Controls",
        description="Implement policies for device and media disposal and re-use",
        category="Physical Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.MP-6", "ISO.A.8.3.2"],
        evidence_types=["media_disposal_policy", "disposal_logs"],
    ),

    # Technical Safeguards
    "164.312(a)(1)": ComplianceControl(
        id="164.312(a)(1)",
        framework=ComplianceFramework.HIPAA,
        title="Access Control",
        description="Implement technical policies for electronic access to ePHI",
        category="Technical Safeguards",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.7.1", "ISO.A.9.1.1"],
        evidence_types=["access_controls", "authentication_config"],
    ),
    "164.312(b)": ComplianceControl(
        id="164.312(b)",
        framework=ComplianceFramework.HIPAA,
        title="Audit Controls",
        description="Implement mechanisms to record and examine access to ePHI",
        category="Technical Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.10.1", "ISO.A.12.4.1"],
        evidence_types=["audit_logs", "log_review"],
    ),
    "164.312(c)(1)": ComplianceControl(
        id="164.312(c)(1)",
        framework=ComplianceFramework.HIPAA,
        title="Integrity Controls",
        description="Implement mechanisms to protect ePHI from improper alteration",
        category="Technical Safeguards",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SI-7", "ISO.A.12.2.1"],
        evidence_types=["integrity_controls", "data_validation"],
    ),
    "164.312(d)": ComplianceControl(
        id="164.312(d)",
        framework=ComplianceFramework.HIPAA,
        title="Person or Entity Authentication",
        description="Implement procedures to verify identity seeking access to ePHI",
        category="Technical Safeguards",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.8.3", "ISO.A.9.2.1"],
        evidence_types=["authentication_policy", "mfa_config"],
    ),
    "164.312(e)(1)": ComplianceControl(
        id="164.312(e)(1)",
        framework=ComplianceFramework.HIPAA,
        title="Transmission Security",
        description="Implement measures to guard against unauthorized access during transmission",
        category="Technical Safeguards",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.4.1", "ISO.A.10.1.1"],
        evidence_types=["encryption_config", "tls_settings"],
    ),
}

# ============================================================================
# SOC 2 Trust Service Criteria (Simplified)
# ============================================================================

SOC2_CONTROLS = {
    # Security
    "CC1.1": ComplianceControl(
        id="CC1.1",
        framework=ComplianceFramework.SOC2,
        title="Control Environment - COSO Principle 1",
        description="The entity demonstrates commitment to integrity and ethical values",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["ISO.A.5.1.1"],
        evidence_types=["code_of_conduct", "ethics_policy"],
    ),
    "CC2.1": ComplianceControl(
        id="CC2.1",
        framework=ComplianceFramework.SOC2,
        title="Communication and Information",
        description="Entity obtains or generates relevant, quality information",
        category="Security",
        priority=ControlPriority.MEDIUM,
        related_controls=["NIST.PM-15"],
        evidence_types=["communication_policy", "info_management"],
    ),
    "CC3.1": ComplianceControl(
        id="CC3.1",
        framework=ComplianceFramework.SOC2,
        title="Risk Assessment - Objectives",
        description="Entity specifies objectives with sufficient clarity",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.RA-1", "ISO.A.6.1.2"],
        evidence_types=["risk_assessment", "objectives_doc"],
    ),
    "CC4.1": ComplianceControl(
        id="CC4.1",
        framework=ComplianceFramework.SOC2,
        title="Monitoring Activities",
        description="Entity selects and develops ongoing monitoring activities",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.CA-7", "ISO.A.12.4.1"],
        evidence_types=["monitoring_policy", "monitoring_logs"],
    ),
    "CC5.1": ComplianceControl(
        id="CC5.1",
        framework=ComplianceFramework.SOC2,
        title="Control Activities - Selection",
        description="Entity selects and develops control activities",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.PL-1"],
        evidence_types=["control_inventory", "control_design"],
    ),
    "CC6.1": ComplianceControl(
        id="CC6.1",
        framework=ComplianceFramework.SOC2,
        title="Logical and Physical Access",
        description="Entity implements logical access security controls",
        category="Security",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.7.1", "ISO.A.9.1.1"],
        evidence_types=["access_controls", "access_review"],
    ),
    "CC6.6": ComplianceControl(
        id="CC6.6",
        framework=ComplianceFramework.SOC2,
        title="Threat and Vulnerability Management",
        description="Entity implements measures to prevent and detect threats",
        category="Security",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.6.3", "ISO.A.12.6.1"],
        evidence_types=["vuln_scan", "threat_intel"],
    ),
    "CC6.7": ComplianceControl(
        id="CC6.7",
        framework=ComplianceFramework.SOC2,
        title="Transmission and Movement of Data",
        description="Entity restricts transmission and movement of data",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.4.1", "ISO.A.13.2.1"],
        evidence_types=["data_transfer_policy", "encryption_config"],
    ),
    "CC7.1": ComplianceControl(
        id="CC7.1",
        framework=ComplianceFramework.SOC2,
        title="System Operations - Detection",
        description="Entity detects configuration changes and anomalies",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SI-4", "ISO.A.12.4.1"],
        evidence_types=["detection_config", "alert_logs"],
    ),
    "CC7.2": ComplianceControl(
        id="CC7.2",
        framework=ComplianceFramework.SOC2,
        title="System Operations - Monitoring",
        description="Entity monitors system components for anomalies",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.SI-4", "ISO.A.12.4.1"],
        evidence_types=["monitoring_tools", "siem_config"],
    ),
    "CC8.1": ComplianceControl(
        id="CC8.1",
        framework=ComplianceFramework.SOC2,
        title="Change Management",
        description="Entity authorizes, designs, tests, and implements changes",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.CM-3", "ISO.A.12.1.2"],
        evidence_types=["change_management", "change_logs"],
    ),
    "CC9.1": ComplianceControl(
        id="CC9.1",
        framework=ComplianceFramework.SOC2,
        title="Risk Mitigation",
        description="Entity identifies, selects, and develops risk mitigation activities",
        category="Security",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.RA-3", "ISO.A.6.1.2"],
        evidence_types=["risk_treatment", "mitigation_plan"],
    ),

    # Availability
    "A1.1": ComplianceControl(
        id="A1.1",
        framework=ComplianceFramework.SOC2,
        title="Availability Commitments",
        description="Entity maintains capacity to meet availability commitments",
        category="Availability",
        priority=ControlPriority.MEDIUM,
        related_controls=["NIST.CP-2", "ISO.A.17.2.1"],
        evidence_types=["capacity_plan", "sla_docs"],
    ),
    "A1.2": ComplianceControl(
        id="A1.2",
        framework=ComplianceFramework.SOC2,
        title="Environmental Protections",
        description="Entity has environmental protections and recovery infrastructure",
        category="Availability",
        priority=ControlPriority.MEDIUM,
        related_controls=["NIST.PE-14", "ISO.A.11.1.4"],
        evidence_types=["environmental_controls", "dr_plan"],
    ),

    # Confidentiality
    "C1.1": ComplianceControl(
        id="C1.1",
        framework=ComplianceFramework.SOC2,
        title="Confidentiality Identification",
        description="Entity identifies and maintains confidential information",
        category="Confidentiality",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.RA-2", "ISO.A.8.2.1"],
        evidence_types=["data_classification", "confidential_inventory"],
    ),
    "C1.2": ComplianceControl(
        id="C1.2",
        framework=ComplianceFramework.SOC2,
        title="Confidentiality Disposal",
        description="Entity disposes of confidential information securely",
        category="Confidentiality",
        priority=ControlPriority.HIGH,
        related_controls=["NIST.MP-6", "ISO.A.8.3.2"],
        evidence_types=["disposal_policy", "disposal_logs"],
    ),
}

# ============================================================================
# NIST CSF Controls (Simplified)
# ============================================================================

NIST_CSF_CONTROLS = {
    # Identify
    "ID.AM-1": ComplianceControl(
        id="ID.AM-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Asset Inventory - Physical Devices",
        description="Physical devices and systems are inventoried",
        category="Identify",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.2.1", "ISO.A.8.1.1"],
        evidence_types=["asset_inventory", "cmdb"],
    ),
    "ID.AM-2": ComplianceControl(
        id="ID.AM-2",
        framework=ComplianceFramework.NIST_CSF,
        title="Asset Inventory - Software",
        description="Software platforms and applications are inventoried",
        category="Identify",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.2.1", "ISO.A.8.1.1"],
        evidence_types=["software_inventory", "license_management"],
    ),
    "ID.RA-1": ComplianceControl(
        id="ID.RA-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Risk Assessment - Vulnerabilities",
        description="Asset vulnerabilities are identified and documented",
        category="Identify",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.6.3", "ISO.A.12.6.1"],
        evidence_types=["vuln_assessment", "risk_register"],
    ),
    "ID.RA-3": ComplianceControl(
        id="ID.RA-3",
        framework=ComplianceFramework.NIST_CSF,
        title="Risk Assessment - Threats",
        description="Threats are identified and documented",
        category="Identify",
        priority=ControlPriority.HIGH,
        related_controls=["ISO.A.6.1.2"],
        evidence_types=["threat_assessment", "threat_intel"],
    ),

    # Protect
    "PR.AC-1": ComplianceControl(
        id="PR.AC-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Access Control - Identities",
        description="Identities and credentials are issued and managed",
        category="Protect",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.8.1", "ISO.A.9.2.1"],
        evidence_types=["identity_management", "credential_policy"],
    ),
    "PR.AC-4": ComplianceControl(
        id="PR.AC-4",
        framework=ComplianceFramework.NIST_CSF,
        title="Access Control - Permissions",
        description="Access permissions are managed incorporating least privilege",
        category="Protect",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.7.2", "ISO.A.9.1.2"],
        evidence_types=["access_review", "rbac_config"],
    ),
    "PR.DS-1": ComplianceControl(
        id="PR.DS-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Data Security - At Rest",
        description="Data-at-rest is protected",
        category="Protect",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.3.2", "ISO.A.10.1.1"],
        evidence_types=["encryption_policy", "storage_encryption"],
    ),
    "PR.DS-2": ComplianceControl(
        id="PR.DS-2",
        framework=ComplianceFramework.NIST_CSF,
        title="Data Security - In Transit",
        description="Data-in-transit is protected",
        category="Protect",
        priority=ControlPriority.CRITICAL,
        related_controls=["PCI.4.1", "ISO.A.13.2.1"],
        evidence_types=["tls_config", "transit_encryption"],
    ),
    "PR.IP-1": ComplianceControl(
        id="PR.IP-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Baseline Configuration",
        description="Configuration baselines are established and maintained",
        category="Protect",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.2.2", "ISO.A.12.5.1"],
        evidence_types=["config_baseline", "hardening_guide"],
    ),
    "PR.IP-12": ComplianceControl(
        id="PR.IP-12",
        framework=ComplianceFramework.NIST_CSF,
        title="Vulnerability Management",
        description="A vulnerability management plan is developed and implemented",
        category="Protect",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.6.3", "ISO.A.12.6.1"],
        evidence_types=["vuln_management_plan", "patch_policy"],
    ),

    # Detect
    "DE.AE-1": ComplianceControl(
        id="DE.AE-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Anomalies and Events - Baseline",
        description="A baseline of network operations and data flows is established",
        category="Detect",
        priority=ControlPriority.HIGH,
        related_controls=["SOC2.CC7.1", "ISO.A.12.4.1"],
        evidence_types=["network_baseline", "traffic_analysis"],
    ),
    "DE.CM-1": ComplianceControl(
        id="DE.CM-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Continuous Monitoring - Network",
        description="The network is monitored for potential cybersecurity events",
        category="Detect",
        priority=ControlPriority.HIGH,
        related_controls=["SOC2.CC7.2", "ISO.A.12.4.1"],
        evidence_types=["network_monitoring", "ids_config"],
    ),
    "DE.CM-4": ComplianceControl(
        id="DE.CM-4",
        framework=ComplianceFramework.NIST_CSF,
        title="Continuous Monitoring - Malware",
        description="Malicious code is detected",
        category="Detect",
        priority=ControlPriority.HIGH,
        related_controls=["PCI.5.2", "ISO.A.12.2.1"],
        evidence_types=["av_config", "malware_detection"],
    ),

    # Respond
    "RS.RP-1": ComplianceControl(
        id="RS.RP-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Response Planning",
        description="Response plan is executed during or after an incident",
        category="Respond",
        priority=ControlPriority.HIGH,
        related_controls=["HIPAA.164.308(a)(6)", "ISO.A.16.1.5"],
        evidence_types=["incident_response_plan", "ir_procedures"],
    ),
    "RS.CO-1": ComplianceControl(
        id="RS.CO-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Response Communications",
        description="Personnel know their roles during incident response",
        category="Respond",
        priority=ControlPriority.MEDIUM,
        related_controls=["ISO.A.16.1.1"],
        evidence_types=["ir_roles", "communication_plan"],
    ),

    # Recover
    "RC.RP-1": ComplianceControl(
        id="RC.RP-1",
        framework=ComplianceFramework.NIST_CSF,
        title="Recovery Planning",
        description="Recovery plan is executed during or after an incident",
        category="Recover",
        priority=ControlPriority.HIGH,
        related_controls=["HIPAA.164.308(a)(7)", "ISO.A.17.1.1"],
        evidence_types=["recovery_plan", "dr_procedures"],
    ),
}

# ============================================================================
# Mapping Keywords to Controls
# ============================================================================

FINDING_KEYWORD_MAP = {
    # Credential/Authentication related
    "password": ["PCI.8.3", "HIPAA.164.312(d)", "NIST.PR.AC-1"],
    "credential": ["PCI.8.3", "HIPAA.164.312(d)", "NIST.PR.AC-1"],
    "authentication": ["PCI.8.3", "HIPAA.164.312(d)", "NIST.PR.AC-1"],
    "mfa": ["PCI.8.3", "HIPAA.164.312(d)"],
    "2fa": ["PCI.8.3", "HIPAA.164.312(d)"],

    # Encryption related
    "encryption": ["PCI.4.1", "HIPAA.164.312(e)(1)", "NIST.PR.DS-1", "NIST.PR.DS-2"],
    "tls": ["PCI.4.1", "HIPAA.164.312(e)(1)", "NIST.PR.DS-2"],
    "ssl": ["PCI.4.1", "HIPAA.164.312(e)(1)", "NIST.PR.DS-2"],
    "cryptograph": ["PCI.4.1", "HIPAA.164.312(e)(1)"],

    # Access control related
    "access control": ["PCI.7.1", "HIPAA.164.312(a)(1)", "SOC2.CC6.1", "NIST.PR.AC-4"],
    "authorization": ["PCI.7.2", "HIPAA.164.308(a)(4)", "SOC2.CC6.1"],
    "privilege": ["PCI.7.2", "NIST.PR.AC-4"],
    "rbac": ["PCI.7.2", "NIST.PR.AC-4"],

    # Vulnerability related
    "vulnerability": ["PCI.6.3", "PCI.11.3", "SOC2.CC6.6", "NIST.ID.RA-1"],
    "patch": ["PCI.6.3", "NIST.PR.IP-12"],
    "cve": ["PCI.6.3", "SOC2.CC6.6", "NIST.ID.RA-1"],
    "exploit": ["PCI.6.3", "SOC2.CC6.6"],

    # Logging/Monitoring related
    "log": ["PCI.10.1", "PCI.10.2", "HIPAA.164.312(b)", "SOC2.CC7.2", "NIST.DE.CM-1"],
    "audit": ["PCI.10.2", "HIPAA.164.312(b)", "SOC2.CC4.1"],
    "monitor": ["PCI.10.1", "SOC2.CC7.2", "NIST.DE.CM-1"],
    "siem": ["PCI.10.2", "SOC2.CC7.2", "NIST.DE.CM-1"],

    # Malware related
    "malware": ["PCI.5.1", "PCI.5.2", "NIST.DE.CM-4"],
    "antivirus": ["PCI.5.2", "NIST.DE.CM-4"],
    "ransomware": ["PCI.5.2", "NIST.DE.CM-4"],

    # Network related
    "firewall": ["PCI.1.1", "PCI.1.2", "NIST.PR.AC-4"],
    "network": ["PCI.1.3", "NIST.DE.AE-1", "NIST.DE.CM-1"],
    "segmentation": ["PCI.1.3"],

    # Data protection related
    "data protection": ["PCI.3.1", "HIPAA.164.312(c)(1)", "SOC2.C1.1", "NIST.PR.DS-1"],
    "data retention": ["PCI.3.1", "SOC2.C1.2"],
    "data classification": ["SOC2.C1.1", "NIST.ID.AM-1"],

    # Incident response related
    "incident": ["HIPAA.164.308(a)(6)", "NIST.RS.RP-1"],
    "breach": ["HIPAA.164.308(a)(6)", "NIST.RS.RP-1"],
    "response": ["HIPAA.164.308(a)(6)", "NIST.RS.RP-1"],

    # Configuration related
    "configuration": ["PCI.2.1", "PCI.2.2", "NIST.PR.IP-1"],
    "hardening": ["PCI.2.2", "NIST.PR.IP-1"],
    "baseline": ["PCI.2.2", "NIST.PR.IP-1"],

    # Backup/Recovery related
    "backup": ["HIPAA.164.308(a)(7)", "SOC2.A1.2", "NIST.RC.RP-1"],
    "recovery": ["HIPAA.164.308(a)(7)", "NIST.RC.RP-1"],
    "disaster": ["HIPAA.164.308(a)(7)", "NIST.RC.RP-1"],

    # Secure development
    "secure development": ["PCI.6.1", "PCI.6.2"],
    "code review": ["PCI.6.2"],
    "sdlc": ["PCI.6.1"],
    "sql injection": ["PCI.6.2", "SOC2.CC6.6"],
    "xss": ["PCI.6.2", "SOC2.CC6.6"],
}


# ============================================================================
# All Controls Combined
# ============================================================================

ALL_CONTROLS: Dict[str, ComplianceControl] = {}
ALL_CONTROLS.update({f"PCI.{k}": v for k, v in PCI_DSS_CONTROLS.items()})
ALL_CONTROLS.update({f"HIPAA.{k}": v for k, v in HIPAA_CONTROLS.items()})
ALL_CONTROLS.update({f"SOC2.{k}": v for k, v in SOC2_CONTROLS.items()})
ALL_CONTROLS.update({f"NIST.{k}": v for k, v in NIST_CSF_CONTROLS.items()})


# ============================================================================
# Main Functions
# ============================================================================

def assess_compliance(
    ctx: Context,
    params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Assess compliance against specified frameworks.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - frameworks: List of frameworks to assess
            - include_not_applicable: Whether to include N/A controls
            - generate_recommendations: Whether to generate remediation recommendations

    Returns:
        Updated context with compliance assessments
    """
    params = params or {}
    target = params.get("target") or ctx.target

    if not target:
        ctx.log("No target specified for compliance assessment", level="WARNING")
        return ctx

    ctx.log(f"Assessing compliance for: {target}", level="INFO")

    # Determine frameworks to assess
    framework_names = params.get("frameworks", ["pci_dss", "hipaa", "soc2", "nist_csf"])
    frameworks = []
    for name in framework_names:
        try:
            frameworks.append(ComplianceFramework(name.lower().replace("-", "_")))
        except ValueError:
            ctx.log(f"Unknown framework: {name}", level="WARNING")

    if not frameworks:
        frameworks = [ComplianceFramework.PCI_DSS]

    # Initialize results
    compliance_data = {
        "target": target,
        "frameworks_assessed": [f.value for f in frameworks],
        "reports": [],
        "cross_framework_gaps": [],
        "priority_remediations": [],
        "overall_posture": {},
    }

    # Collect findings from context
    findings = collect_findings_from_context(ctx)

    # Assess each framework
    all_assessments = []
    for framework in frameworks:
        report = assess_framework(framework, findings, target)
        compliance_data["reports"].append(report.to_dict())
        all_assessments.extend(report.assessments)

    # Identify cross-framework gaps
    compliance_data["cross_framework_gaps"] = identify_cross_framework_gaps(all_assessments)

    # Generate priority remediations
    if params.get("generate_recommendations", True):
        compliance_data["priority_remediations"] = generate_priority_remediations(all_assessments)

    # Calculate overall posture
    compliance_data["overall_posture"] = calculate_overall_posture(compliance_data["reports"])

    # Add to context
    ctx.add("compliance_assessment", compliance_data)

    # Log summary
    for report in compliance_data["reports"]:
        ctx.log(
            f"{report['framework'].upper()}: {report['overall_score']:.1f}% compliant "
            f"({report['non_compliant_count']} gaps)",
            level="INFO"
        )

    return ctx


def collect_findings_from_context(ctx: Context) -> List[Dict[str, Any]]:
    """
    Collect security findings from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of findings
    """
    findings = []

    # Collect from various context keys
    finding_keys = [
        "findings", "risks", "vulnerabilities", "exposure_findings",
        "threat_intel", "attack_paths",
    ]

    for key in finding_keys:
        data = ctx.get(key, None)
        if data:
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict):
                # Handle nested findings
                if "findings" in data:
                    findings.extend(data["findings"])
                if "matches" in data:
                    findings.extend(data["matches"])

    # Also collect finding_N keys
    for key in ctx.data.keys():
        if key.startswith("finding_") or key.startswith("exposure_finding_"):
            finding = ctx.get(key)
            if finding:
                findings.append(finding)

    # Collect exposure scan data
    exposure_scan = ctx.get("exposure_scan", {})
    if exposure_scan.get("findings"):
        findings.extend(exposure_scan["findings"])

    return findings


def assess_framework(
    framework: ComplianceFramework,
    findings: List[Dict[str, Any]],
    target: str
) -> ComplianceReport:
    """
    Assess compliance against a specific framework.

    Args:
        framework: Framework to assess
        findings: Security findings
        target: Assessment target

    Returns:
        ComplianceReport
    """
    # Get controls for this framework
    controls = get_controls_for_framework(framework)

    # Map findings to controls
    finding_control_map = map_findings_to_controls(findings, framework)

    # Assess each control
    assessments = []
    for control_id, control in controls.items():
        assessment = assess_control(control, finding_control_map.get(control_id, []), findings)
        assessments.append(assessment)

    # Calculate statistics
    compliant = sum(1 for a in assessments if a.status == ControlStatus.COMPLIANT)
    partial = sum(1 for a in assessments if a.status == ControlStatus.PARTIAL)
    non_compliant = sum(1 for a in assessments if a.status == ControlStatus.NON_COMPLIANT)
    not_assessed = sum(1 for a in assessments if a.status == ControlStatus.NOT_ASSESSED)

    total_applicable = compliant + partial + non_compliant
    if total_applicable > 0:
        # Compliant = 100%, Partial = 50%, Non-compliant = 0%
        score = ((compliant * 100) + (partial * 50)) / total_applicable
    else:
        score = 0.0

    # Identify critical gaps
    critical_gaps = [
        a.control.title for a in assessments
        if a.status == ControlStatus.NON_COMPLIANT
        and a.control.priority == ControlPriority.CRITICAL
    ]

    # Generate recommendations
    recommendations = []
    for assessment in assessments:
        if assessment.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL]:
            recommendations.extend(assessment.remediation[:2])

    return ComplianceReport(
        framework=framework,
        target=target,
        assessments=assessments,
        overall_score=score,
        compliant_count=compliant,
        partial_count=partial,
        non_compliant_count=non_compliant,
        not_assessed_count=not_assessed,
        critical_gaps=critical_gaps[:5],
        recommendations=recommendations[:10],
    )


def get_controls_for_framework(framework: ComplianceFramework) -> Dict[str, ComplianceControl]:
    """
    Get controls for a specific framework.

    Args:
        framework: Framework

    Returns:
        Dictionary of controls
    """
    if framework == ComplianceFramework.PCI_DSS:
        return {f"PCI.{k}": v for k, v in PCI_DSS_CONTROLS.items()}
    elif framework == ComplianceFramework.HIPAA:
        return {f"HIPAA.{k}": v for k, v in HIPAA_CONTROLS.items()}
    elif framework == ComplianceFramework.SOC2:
        return {f"SOC2.{k}": v for k, v in SOC2_CONTROLS.items()}
    elif framework == ComplianceFramework.NIST_CSF:
        return {f"NIST.{k}": v for k, v in NIST_CSF_CONTROLS.items()}
    else:
        return {}


def map_findings_to_controls(
    findings: List[Dict[str, Any]],
    framework: ComplianceFramework
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Map findings to compliance controls.

    Args:
        findings: Security findings
        framework: Target framework

    Returns:
        Dictionary mapping control IDs to findings
    """
    control_findings: Dict[str, List[Dict[str, Any]]] = {}
    framework_prefix = {
        ComplianceFramework.PCI_DSS: "PCI.",
        ComplianceFramework.HIPAA: "HIPAA.",
        ComplianceFramework.SOC2: "SOC2.",
        ComplianceFramework.NIST_CSF: "NIST.",
    }.get(framework, "")

    for finding in findings:
        # Get finding text for keyword matching
        finding_text = " ".join([
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("category", "")),
        ]).lower()

        # Match keywords to controls
        matched_controls = set()
        for keyword, control_ids in FINDING_KEYWORD_MAP.items():
            if keyword.lower() in finding_text:
                for control_id in control_ids:
                    if control_id.startswith(framework_prefix):
                        matched_controls.add(control_id)

        # Add finding to matched controls
        for control_id in matched_controls:
            if control_id not in control_findings:
                control_findings[control_id] = []
            control_findings[control_id].append(finding)

    return control_findings


def assess_control(
    control: ComplianceControl,
    mapped_findings: List[Dict[str, Any]],
    all_findings: List[Dict[str, Any]]
) -> ControlAssessment:
    """
    Assess a single control.

    Args:
        control: Control to assess
        mapped_findings: Findings mapped to this control
        all_findings: All findings (for context)

    Returns:
        ControlAssessment
    """
    finding_titles = [f.get("title", "Unknown") for f in mapped_findings]
    gaps = []
    remediation = []
    evidence = []

    # Determine status based on findings
    if not mapped_findings:
        # No findings mapped - could be compliant or not assessed
        status = ControlStatus.NOT_ASSESSED
    else:
        # Check severity of findings
        severities = [f.get("severity", "info").lower() for f in mapped_findings]

        if "critical" in severities:
            status = ControlStatus.NON_COMPLIANT
            gaps.append(f"Critical issues found affecting {control.title}")
        elif "high" in severities:
            status = ControlStatus.PARTIAL
            gaps.append(f"High-severity issues need remediation for {control.title}")
        elif "medium" in severities:
            status = ControlStatus.PARTIAL
            gaps.append(f"Medium-severity issues identified")
        else:
            status = ControlStatus.PARTIAL
            gaps.append(f"Minor issues identified")

        # Generate remediation based on control category
        remediation = generate_control_remediation(control, mapped_findings)
        evidence = finding_titles[:5]

    return ControlAssessment(
        control=control,
        status=status,
        findings=finding_titles,
        evidence=evidence,
        gaps=gaps,
        remediation=remediation,
    )


def generate_control_remediation(
    control: ComplianceControl,
    findings: List[Dict[str, Any]]
) -> List[str]:
    """
    Generate remediation recommendations for a control.

    Args:
        control: Control
        findings: Related findings

    Returns:
        List of remediation recommendations
    """
    remediation = []

    category = control.category.lower()

    if "authentication" in category or "access" in category:
        remediation.append("Implement multi-factor authentication (MFA)")
        remediation.append("Review and enforce password policies")
        remediation.append("Conduct access rights review")

    elif "encryption" in category:
        remediation.append("Implement TLS 1.2+ for all transmissions")
        remediation.append("Enable encryption at rest for sensitive data")
        remediation.append("Review and rotate encryption keys")

    elif "vulnerability" in category or "patch" in category:
        remediation.append("Implement regular vulnerability scanning")
        remediation.append("Establish patch management process")
        remediation.append("Prioritize critical and high severity vulnerabilities")

    elif "logging" in category or "monitoring" in category:
        remediation.append("Enable comprehensive audit logging")
        remediation.append("Implement log aggregation and SIEM")
        remediation.append("Establish log retention policies")

    elif "network" in category:
        remediation.append("Review and update firewall rules")
        remediation.append("Implement network segmentation")
        remediation.append("Document network architecture")

    elif "malware" in category:
        remediation.append("Deploy endpoint protection on all systems")
        remediation.append("Enable real-time malware scanning")
        remediation.append("Implement email security controls")

    elif "incident" in category or "response" in category:
        remediation.append("Develop incident response plan")
        remediation.append("Conduct incident response training")
        remediation.append("Establish communication procedures")

    elif "backup" in category or "recovery" in category:
        remediation.append("Implement regular backup procedures")
        remediation.append("Test backup restoration regularly")
        remediation.append("Develop disaster recovery plan")

    else:
        remediation.append(f"Address findings related to {control.title}")
        remediation.append("Implement control measures as defined in policy")

    return remediation[:3]


def identify_cross_framework_gaps(assessments: List[ControlAssessment]) -> List[Dict[str, Any]]:
    """
    Identify gaps that affect multiple frameworks.

    Args:
        assessments: All control assessments

    Returns:
        List of cross-framework gaps
    """
    gaps = []

    # Group by related controls
    control_groups: Dict[str, List[ControlAssessment]] = {}

    for assessment in assessments:
        if assessment.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL]:
            for related in assessment.control.related_controls:
                if related not in control_groups:
                    control_groups[related] = []
                control_groups[related].append(assessment)

    # Identify gaps affecting multiple frameworks
    for related_id, related_assessments in control_groups.items():
        frameworks = set(a.control.framework.value for a in related_assessments)
        if len(frameworks) >= 2:
            gaps.append({
                "related_control": related_id,
                "affected_frameworks": list(frameworks),
                "affected_controls": [a.control.id for a in related_assessments],
                "description": f"Gap affecting {len(frameworks)} frameworks",
                "priority": "high" if len(frameworks) >= 3 else "medium",
            })

    return sorted(gaps, key=lambda x: len(x["affected_frameworks"]), reverse=True)[:10]


def generate_priority_remediations(assessments: List[ControlAssessment]) -> List[Dict[str, Any]]:
    """
    Generate prioritized remediation recommendations.

    Args:
        assessments: All control assessments

    Returns:
        List of prioritized remediations
    """
    remediations = []

    # Sort by priority and status
    priority_order = {
        ControlPriority.CRITICAL: 0,
        ControlPriority.HIGH: 1,
        ControlPriority.MEDIUM: 2,
        ControlPriority.LOW: 3,
    }

    non_compliant = [
        a for a in assessments
        if a.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL]
    ]

    sorted_assessments = sorted(
        non_compliant,
        key=lambda x: (priority_order.get(x.control.priority, 4), x.status.value)
    )

    for assessment in sorted_assessments[:15]:
        remediations.append({
            "control_id": assessment.control.id,
            "framework": assessment.control.framework.value,
            "title": assessment.control.title,
            "priority": assessment.control.priority.value,
            "status": assessment.status.value,
            "remediation_steps": assessment.remediation,
            "related_controls": assessment.control.related_controls,
        })

    return remediations


def calculate_overall_posture(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate overall compliance posture across frameworks.

    Args:
        reports: List of framework reports

    Returns:
        Overall posture summary
    """
    if not reports:
        return {"overall_score": 0, "status": "not_assessed"}

    total_score = sum(r["overall_score"] for r in reports)
    avg_score = total_score / len(reports)

    total_gaps = sum(r["non_compliant_count"] for r in reports)
    total_partial = sum(r["partial_count"] for r in reports)

    if avg_score >= 90:
        status = "strong"
    elif avg_score >= 70:
        status = "moderate"
    elif avg_score >= 50:
        status = "needs_improvement"
    else:
        status = "critical"

    return {
        "overall_score": avg_score,
        "status": status,
        "frameworks_assessed": len(reports),
        "total_gaps": total_gaps,
        "total_partial": total_partial,
        "framework_scores": {r["framework"]: r["overall_score"] for r in reports},
    }


# ============================================================================
# Helper Functions
# ============================================================================

def get_framework(name: str) -> Optional[ComplianceFramework]:
    """
    Get framework by name.

    Args:
        name: Framework name

    Returns:
        ComplianceFramework or None
    """
    name = name.lower().replace("-", "_").replace(" ", "_")
    try:
        return ComplianceFramework(name)
    except ValueError:
        return None


def get_all_frameworks() -> List[ComplianceFramework]:
    """
    Get all supported frameworks.

    Returns:
        List of frameworks
    """
    return list(ComplianceFramework)


def get_control(control_id: str) -> Optional[ComplianceControl]:
    """
    Get a specific control by ID.

    Args:
        control_id: Control ID (e.g., "PCI.8.3")

    Returns:
        ComplianceControl or None
    """
    return ALL_CONTROLS.get(control_id)


def get_related_controls(control_id: str) -> List[ComplianceControl]:
    """
    Get controls related to a given control.

    Args:
        control_id: Control ID

    Returns:
        List of related controls
    """
    control = get_control(control_id)
    if not control:
        return []

    related = []
    for related_id in control.related_controls:
        related_control = get_control(related_id)
        if related_control:
            related.append(related_control)

    return related


def get_controls_by_category(
    framework: ComplianceFramework,
    category: str
) -> List[ComplianceControl]:
    """
    Get controls by category within a framework.

    Args:
        framework: Framework
        category: Category name

    Returns:
        List of controls
    """
    controls = get_controls_for_framework(framework)
    return [c for c in controls.values() if c.category.lower() == category.lower()]


def get_controls_by_priority(
    framework: ComplianceFramework,
    priority: ControlPriority
) -> List[ComplianceControl]:
    """
    Get controls by priority within a framework.

    Args:
        framework: Framework
        priority: Priority level

    Returns:
        List of controls
    """
    controls = get_controls_for_framework(framework)
    return [c for c in controls.values() if c.priority == priority]


def map_control_across_frameworks(control_id: str) -> Dict[str, List[str]]:
    """
    Map a control to equivalent controls in other frameworks.

    Args:
        control_id: Control ID

    Returns:
        Dictionary mapping framework to control IDs
    """
    control = get_control(control_id)
    if not control:
        return {}

    mapping = {}
    for related_id in control.related_controls:
        parts = related_id.split(".")
        if len(parts) >= 2:
            framework = parts[0]
            if framework not in mapping:
                mapping[framework] = []
            mapping[framework].append(related_id)

    return mapping


def get_framework_categories(framework: ComplianceFramework) -> List[str]:
    """
    Get all categories within a framework.

    Args:
        framework: Framework

    Returns:
        List of category names
    """
    controls = get_controls_for_framework(framework)
    categories = set(c.category for c in controls.values())
    return sorted(categories)


def calculate_category_score(
    assessments: List[ControlAssessment],
    category: str
) -> float:
    """
    Calculate compliance score for a specific category.

    Args:
        assessments: Control assessments
        category: Category name

    Returns:
        Score (0-100)
    """
    category_assessments = [
        a for a in assessments
        if a.control.category.lower() == category.lower()
    ]

    if not category_assessments:
        return 0.0

    compliant = sum(1 for a in category_assessments if a.status == ControlStatus.COMPLIANT)
    partial = sum(1 for a in category_assessments if a.status == ControlStatus.PARTIAL)
    total = len(category_assessments)

    return ((compliant * 100) + (partial * 50)) / total


def export_gap_analysis(report: ComplianceReport) -> Dict[str, Any]:
    """
    Export gap analysis from a compliance report.

    Args:
        report: ComplianceReport

    Returns:
        Gap analysis dictionary
    """
    gaps = []

    for assessment in report.assessments:
        if assessment.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL]:
            gaps.append({
                "control_id": assessment.control.id,
                "title": assessment.control.title,
                "category": assessment.control.category,
                "priority": assessment.control.priority.value,
                "status": assessment.status.value,
                "gaps": assessment.gaps,
                "remediation": assessment.remediation,
                "evidence_needed": assessment.control.evidence_types,
            })

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda x: priority_order.get(x["priority"], 4))

    return {
        "framework": report.framework.value,
        "target": report.target,
        "total_gaps": len(gaps),
        "critical_gaps": sum(1 for g in gaps if g["priority"] == "critical"),
        "high_gaps": sum(1 for g in gaps if g["priority"] == "high"),
        "gaps": gaps,
    }
