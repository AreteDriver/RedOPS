"""
Executive Reporting module.

Generates stakeholder-ready summaries, dashboards, and reports for executives,
board members, and non-technical stakeholders. Focuses on business impact,
risk posture, compliance status, and actionable recommendations.

Report Types:
- Executive Summary: High-level overview for C-suite
- Risk Dashboard: Visual risk posture assessment
- Compliance Report: Regulatory compliance status
- Trend Report: Historical trend analysis
- Board Briefing: Condensed board-ready summary
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import hashlib
from redops.core.context import Context


class ReportType(Enum):
    """Types of executive reports."""

    EXECUTIVE_SUMMARY = "executive_summary"
    RISK_DASHBOARD = "risk_dashboard"
    COMPLIANCE_REPORT = "compliance_report"
    TREND_REPORT = "trend_report"
    BOARD_BRIEFING = "board_briefing"
    INCIDENT_SUMMARY = "incident_summary"
    REMEDIATION_TRACKER = "remediation_tracker"


class Audience(Enum):
    """Target audience for reports."""

    EXECUTIVE = "executive"
    BOARD = "board"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    SECURITY_TEAM = "security_team"
    MANAGEMENT = "management"


class RiskLevel(Enum):
    """Risk levels for executive reporting."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class TrendDirection(Enum):
    """Trend directions."""

    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"
    UNKNOWN = "unknown"


class ComplianceStatus(Enum):
    """Compliance status levels."""

    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


@dataclass
class ExecutiveSummary:
    """Executive summary structure."""

    report_id: str
    title: str
    generated_at: str
    target: str
    overall_risk_level: RiskLevel
    risk_score: float  # 0-100
    key_findings: List[Dict[str, Any]]
    top_risks: List[Dict[str, Any]]
    compliance_summary: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    trend_summary: Dict[str, Any]
    executive_brief: str = ""
    next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "title": self.title,
            "generated_at": self.generated_at,
            "target": self.target,
            "overall_risk_level": self.overall_risk_level.value,
            "risk_score": self.risk_score,
            "key_findings": self.key_findings,
            "top_risks": self.top_risks,
            "compliance_summary": self.compliance_summary,
            "recommendations": self.recommendations,
            "metrics": self.metrics,
            "trend_summary": self.trend_summary,
            "executive_brief": self.executive_brief,
            "next_steps": self.next_steps,
        }


@dataclass
class RiskDashboard:
    """Risk dashboard structure."""

    overall_score: float
    risk_level: RiskLevel
    risk_by_category: Dict[str, float]
    risk_by_severity: Dict[str, int]
    risk_trend: TrendDirection
    top_risks: List[Dict[str, Any]]
    risk_distribution: Dict[str, int]
    mitigation_progress: Dict[str, Any]
    exposure_metrics: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "risk_by_category": self.risk_by_category,
            "risk_by_severity": self.risk_by_severity,
            "risk_trend": self.risk_trend.value,
            "top_risks": self.top_risks,
            "risk_distribution": self.risk_distribution,
            "mitigation_progress": self.mitigation_progress,
            "exposure_metrics": self.exposure_metrics,
        }


@dataclass
class ComplianceReport:
    """Compliance report structure."""

    overall_status: ComplianceStatus
    compliance_score: float  # 0-100
    frameworks: Dict[str, Dict[str, Any]]
    gaps: List[Dict[str, Any]]
    controls_assessed: int
    controls_passing: int
    controls_failing: int
    priority_remediations: List[Dict[str, Any]]
    audit_readiness: float  # 0-100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "overall_status": self.overall_status.value,
            "compliance_score": self.compliance_score,
            "frameworks": self.frameworks,
            "gaps": self.gaps,
            "controls_assessed": self.controls_assessed,
            "controls_passing": self.controls_passing,
            "controls_failing": self.controls_failing,
            "priority_remediations": self.priority_remediations,
            "audit_readiness": self.audit_readiness,
        }


@dataclass
class TrendReport:
    """Trend report structure."""

    period: str
    risk_trend: List[Dict[str, Any]]
    finding_trend: List[Dict[str, Any]]
    compliance_trend: List[Dict[str, Any]]
    remediation_trend: List[Dict[str, Any]]
    overall_direction: TrendDirection
    notable_changes: List[str]
    projections: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "period": self.period,
            "risk_trend": self.risk_trend,
            "finding_trend": self.finding_trend,
            "compliance_trend": self.compliance_trend,
            "remediation_trend": self.remediation_trend,
            "overall_direction": self.overall_direction.value,
            "notable_changes": self.notable_changes,
            "projections": self.projections,
        }


@dataclass
class Recommendation:
    """Prioritized recommendation."""

    id: str
    title: str
    description: str
    priority: str  # critical, high, medium, low
    category: str
    business_impact: str
    effort: str  # low, medium, high
    timeline: str
    owner: str = ""
    status: str = "open"
    related_findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "category": self.category,
            "business_impact": self.business_impact,
            "effort": self.effort,
            "timeline": self.timeline,
            "owner": self.owner,
            "status": self.status,
            "related_findings": self.related_findings,
        }


# ============================================================================
# Risk Scoring Constants
# ============================================================================

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 0.5,
}

CATEGORY_WEIGHTS = {
    "vulnerability": 1.0,
    "exposure": 0.9,
    "credential": 1.2,
    "data_leak": 1.1,
    "misconfiguration": 0.8,
    "compliance": 0.7,
    "threat_indicator": 0.9,
    "reconnaissance": 0.5,
    "infrastructure": 0.6,
    "social": 0.5,
}

# Business impact templates
BUSINESS_IMPACT_TEMPLATES = {
    "credential": "Potential unauthorized access to systems and data",
    "data_leak": "Risk of data breach and regulatory penalties",
    "vulnerability": "Exploitable weakness that could lead to compromise",
    "exposure": "Publicly accessible information that aids attackers",
    "compliance": "Regulatory non-compliance risk and potential fines",
    "misconfiguration": "Security weakness from improper configuration",
}

# Effort estimation
EFFORT_ESTIMATES = {
    "critical": "immediate",
    "high": "1-2 weeks",
    "medium": "2-4 weeks",
    "low": "1-3 months",
}


# ============================================================================
# Main Functions
# ============================================================================


def generate_executive_report(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Generate executive report from context data.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - report_type: Type of report to generate
            - audience: Target audience
            - include_technical: Include technical details
            - period: Reporting period

    Returns:
        Updated context with executive report
    """
    params = params or {}
    target = params.get("target") or ctx.target or "Assessment Target"
    report_type = params.get("report_type", ReportType.EXECUTIVE_SUMMARY)
    audience = params.get("audience", Audience.EXECUTIVE)

    ctx.log(f"Generating executive report for: {target}", level="INFO")

    # Extract data from context
    correlations = ctx.get("correlations", {})
    compliance = ctx.get("compliance", {})
    risk_data = ctx.get("risk_assessment", {})
    ctx.get("infrastructure", {})
    ctx.get("exposure_scan", {})
    ctx.get("threat_intel", {})

    # Get findings from correlations or extract directly
    findings = correlations.get("findings", [])
    if not findings:
        findings = extract_findings_for_report(ctx)

    # Generate report components
    report_id = generate_report_id(target)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Calculate risk metrics
    risk_dashboard = calculate_risk_dashboard(findings, risk_data)

    # Generate compliance summary
    compliance_summary = generate_compliance_summary(compliance)

    # Generate recommendations
    recommendations = generate_recommendations(findings, correlations, compliance)

    # Calculate metrics
    metrics = calculate_executive_metrics(findings, correlations, compliance)

    # Generate trend summary
    trend_summary = generate_trend_summary(ctx, params.get("period", "current"))

    # Generate key findings (top 5)
    key_findings = get_key_findings(findings, limit=5)

    # Generate top risks (top 5)
    top_risks = get_top_risks(findings, risk_dashboard, limit=5)

    # Generate executive brief
    executive_brief = generate_executive_brief(
        target, risk_dashboard, key_findings, compliance_summary
    )

    # Generate next steps
    next_steps = generate_next_steps(recommendations, risk_dashboard)

    # Build executive summary
    summary = ExecutiveSummary(
        report_id=report_id,
        title=f"Security Assessment Report: {target}",
        generated_at=generated_at,
        target=target,
        overall_risk_level=risk_dashboard.risk_level,
        risk_score=risk_dashboard.overall_score,
        key_findings=key_findings,
        top_risks=top_risks,
        compliance_summary=compliance_summary.to_dict()
        if hasattr(compliance_summary, "to_dict")
        else compliance_summary,
        recommendations=[r.to_dict() for r in recommendations[:10]],
        metrics=metrics,
        trend_summary=trend_summary,
        executive_brief=executive_brief,
        next_steps=next_steps,
    )

    # Build full report
    report = {
        "report_type": report_type.value
        if isinstance(report_type, ReportType)
        else report_type,
        "audience": audience.value if isinstance(audience, Audience) else audience,
        "executive_summary": summary.to_dict(),
        "risk_dashboard": risk_dashboard.to_dict(),
        "compliance_report": compliance_summary.to_dict()
        if hasattr(compliance_summary, "to_dict")
        else compliance_summary,
        "recommendations": [r.to_dict() for r in recommendations],
        "metrics": metrics,
        "appendix": generate_appendix(findings, correlations),
    }

    ctx.add("executive_report", report)

    ctx.log(
        f"Executive report generated: {len(key_findings)} key findings, "
        f"risk score {risk_dashboard.overall_score:.1f}",
        level="INFO",
    )

    return ctx


def extract_findings_for_report(ctx: Context) -> List[Dict[str, Any]]:
    """Extract findings from context for reporting."""
    findings = []

    # From exposure scan
    exposure = ctx.get("exposure_scan", {})
    for exp in exposure.get("exposures", []):
        findings.append(
            {
                "id": exp.get("id", f"EXP-{len(findings) + 1}"),
                "category": "exposure",
                "title": exp.get("title", "Exposure"),
                "severity": exp.get("severity", "medium"),
                "description": exp.get("description", ""),
            }
        )

    # From threat intel
    threat_intel = ctx.get("threat_intel", {})
    for ioc in threat_intel.get("iocs", []):
        findings.append(
            {
                "id": ioc.get("id", f"IOC-{len(findings) + 1}"),
                "category": "threat_indicator",
                "title": f"Threat Indicator: {ioc.get('type', 'Unknown')}",
                "severity": ioc.get("severity", "high"),
                "description": ioc.get("description", ""),
            }
        )

    # From compliance
    compliance = ctx.get("compliance", {})
    for gap in compliance.get("gaps", []):
        findings.append(
            {
                "id": gap.get("id", f"CMP-{len(findings) + 1}"),
                "category": "compliance",
                "title": gap.get("title", "Compliance Gap"),
                "severity": gap.get("priority", "medium"),
                "description": gap.get("description", ""),
            }
        )

    # From risk assessment
    risk = ctx.get("risk_assessment", {})
    for vuln in risk.get("vulnerabilities", []):
        findings.append(
            {
                "id": vuln.get("id", f"VUL-{len(findings) + 1}"),
                "category": "vulnerability",
                "title": vuln.get("title", "Vulnerability"),
                "severity": vuln.get("severity", "medium"),
                "description": vuln.get("description", ""),
            }
        )

    return findings


def calculate_risk_dashboard(
    findings: List[Dict[str, Any]], risk_data: Dict[str, Any]
) -> RiskDashboard:
    """Calculate risk dashboard metrics."""
    # Count by severity
    severity_counts = defaultdict(int)
    category_scores = defaultdict(float)

    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        category = finding.get("category", "unknown").lower()

        severity_counts[severity] += 1

        # Calculate weighted score
        weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        cat_weight = CATEGORY_WEIGHTS.get(category, 1.0)
        category_scores[category] += weight * cat_weight

    # Calculate overall risk score (0-100)
    total_weighted = sum(category_scores.values())
    max_possible = (
        len(findings) * 12.0 if findings else 1.0
    )  # Max: critical * credential
    overall_score = min(100, (total_weighted / max_possible) * 100) if findings else 0

    # Determine risk level
    risk_level = calculate_risk_level(overall_score)

    # Get top risks
    top_risks = get_top_risks_from_findings(findings, limit=5)

    # Calculate risk distribution
    risk_distribution = {
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "info": severity_counts.get("info", 0),
    }

    # Mitigation progress (simulated based on context)
    total_findings = len(findings)
    mitigation_progress = {
        "total": total_findings,
        "remediated": 0,
        "in_progress": 0,
        "open": total_findings,
        "progress_percent": 0,
    }

    # Exposure metrics
    exposure_metrics = {
        "total_exposures": severity_counts.get("critical", 0)
        + severity_counts.get("high", 0),
        "public_facing": sum(
            1 for f in findings if "exposure" in f.get("category", "")
        ),
        "credential_risks": sum(
            1 for f in findings if "credential" in f.get("category", "")
        ),
    }

    return RiskDashboard(
        overall_score=round(overall_score, 1),
        risk_level=risk_level,
        risk_by_category=dict(category_scores),
        risk_by_severity=dict(severity_counts),
        risk_trend=TrendDirection.UNKNOWN,
        top_risks=top_risks,
        risk_distribution=risk_distribution,
        mitigation_progress=mitigation_progress,
        exposure_metrics=exposure_metrics,
    )


def calculate_risk_level(score: float) -> RiskLevel:
    """Calculate risk level from score."""
    if score >= 80:
        return RiskLevel.CRITICAL
    elif score >= 60:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    elif score >= 20:
        return RiskLevel.LOW
    else:
        return RiskLevel.MINIMAL


def generate_compliance_summary(compliance_data: Dict[str, Any]) -> ComplianceReport:
    """Generate compliance summary from compliance data."""
    gaps = compliance_data.get("gaps", [])
    frameworks = compliance_data.get("frameworks", {})
    compliance_data.get("assessments", [])

    # Calculate controls
    controls_assessed = compliance_data.get("controls_assessed", 0)
    controls_passing = compliance_data.get("controls_passing", 0)
    controls_failing = len(gaps)

    if controls_assessed == 0:
        controls_assessed = controls_passing + controls_failing

    # Calculate compliance score
    if controls_assessed > 0:
        compliance_score = (controls_passing / controls_assessed) * 100
    else:
        compliance_score = 100.0 if not gaps else 0.0

    # Determine overall status
    if controls_assessed == 0 and not gaps:
        overall_status = ComplianceStatus.NOT_ASSESSED
    elif compliance_score >= 90:
        overall_status = ComplianceStatus.COMPLIANT
    elif compliance_score >= 70:
        overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
    else:
        overall_status = ComplianceStatus.NON_COMPLIANT

    # Framework summary
    framework_summary = {}
    for fw_name, fw_data in frameworks.items():
        if isinstance(fw_data, dict):
            framework_summary[fw_name] = {
                "status": fw_data.get("status", "not_assessed"),
                "score": fw_data.get("score", 0),
                "gaps": fw_data.get("gap_count", 0),
            }

    # Priority remediations
    priority_remediations = []
    for gap in sorted(gaps, key=lambda g: severity_priority(g.get("priority", "low")))[
        :5
    ]:
        priority_remediations.append(
            {
                "control": gap.get("control_id", gap.get("title", "Unknown")),
                "gap": gap.get("title", gap.get("description", "")),
                "priority": gap.get("priority", "medium"),
                "framework": gap.get("framework", "Unknown"),
            }
        )

    # Calculate audit readiness
    audit_readiness = compliance_score * 0.9  # Slightly conservative

    return ComplianceReport(
        overall_status=overall_status,
        compliance_score=round(compliance_score, 1),
        frameworks=framework_summary,
        gaps=[
            {
                "id": g.get("id", ""),
                "title": g.get("title", ""),
                "priority": g.get("priority", "medium"),
            }
            for g in gaps[:10]
        ],
        controls_assessed=controls_assessed,
        controls_passing=controls_passing,
        controls_failing=controls_failing,
        priority_remediations=priority_remediations,
        audit_readiness=round(audit_readiness, 1),
    )


def generate_recommendations(
    findings: List[Dict[str, Any]],
    correlations: Dict[str, Any],
    compliance: Dict[str, Any],
) -> List[Recommendation]:
    """Generate prioritized recommendations."""
    recommendations = []
    rec_id = 0

    # Group findings by category and severity
    critical_findings = [
        f for f in findings if f.get("severity", "").lower() == "critical"
    ]
    high_findings = [f for f in findings if f.get("severity", "").lower() == "high"]

    # Generate recommendations for critical findings
    for finding in critical_findings[:5]:
        rec_id += 1
        category = finding.get("category", "security")
        recommendations.append(
            Recommendation(
                id=f"REC-{rec_id:03d}",
                title=f"Remediate: {finding.get('title', 'Critical Issue')[:50]}",
                description=generate_recommendation_description(finding),
                priority="critical",
                category=category,
                business_impact=BUSINESS_IMPACT_TEMPLATES.get(
                    category, "Security risk"
                ),
                effort="high"
                if category in ["vulnerability", "infrastructure"]
                else "medium",
                timeline="immediate",
                related_findings=[finding.get("id", "")],
            )
        )

    # Generate recommendations for high findings
    for finding in high_findings[:5]:
        rec_id += 1
        category = finding.get("category", "security")
        recommendations.append(
            Recommendation(
                id=f"REC-{rec_id:03d}",
                title=f"Address: {finding.get('title', 'High Priority Issue')[:50]}",
                description=generate_recommendation_description(finding),
                priority="high",
                category=category,
                business_impact=BUSINESS_IMPACT_TEMPLATES.get(
                    category, "Security risk"
                ),
                effort="medium",
                timeline="1-2 weeks",
                related_findings=[finding.get("id", "")],
            )
        )

    # Add compliance recommendations
    for gap in compliance.get("gaps", [])[:3]:
        rec_id += 1
        recommendations.append(
            Recommendation(
                id=f"REC-{rec_id:03d}",
                title=f"Compliance: {gap.get('title', 'Address Gap')[:50]}",
                description=gap.get("description", "Implement required control"),
                priority=gap.get("priority", "medium"),
                category="compliance",
                business_impact="Regulatory compliance and audit requirements",
                effort="medium",
                timeline="2-4 weeks",
                related_findings=[gap.get("id", "")],
            )
        )

    # Add cluster-based recommendations from correlations
    for cluster in correlations.get("clusters", [])[:3]:
        rec_id += 1
        recommendations.append(
            Recommendation(
                id=f"REC-{rec_id:03d}",
                title=f"Investigate: {cluster.get('name', 'Related Findings')}",
                description=f"Review cluster of {len(cluster.get('finding_ids', []))} related findings",
                priority=cluster.get("aggregate_severity", "medium"),
                category=cluster.get("primary_category", "security"),
                business_impact="Potential attack chain or systemic issue",
                effort="medium",
                timeline="1-2 weeks",
                related_findings=cluster.get("finding_ids", []),
            )
        )

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda r: priority_order.get(r.priority, 4))

    return recommendations


def generate_recommendation_description(finding: Dict[str, Any]) -> str:
    """Generate recommendation description from finding."""
    category = finding.get("category", "security")
    title = finding.get("title", "")

    templates = {
        "vulnerability": f"Patch or mitigate the identified vulnerability: {title}",
        "exposure": f"Restrict access to exposed resource: {title}",
        "credential": f"Rotate and secure compromised credentials: {title}",
        "data_leak": f"Contain and remediate data exposure: {title}",
        "compliance": f"Implement required compliance control: {title}",
        "misconfiguration": f"Correct security configuration: {title}",
    }

    return templates.get(category, f"Address security finding: {title}")


def calculate_executive_metrics(
    findings: List[Dict[str, Any]],
    correlations: Dict[str, Any],
    compliance: Dict[str, Any],
) -> Dict[str, Any]:
    """Calculate executive-level metrics."""
    # Count findings by severity
    severity_counts = defaultdict(int)
    category_counts = defaultdict(int)

    for finding in findings:
        severity_counts[finding.get("severity", "medium").lower()] += 1
        category_counts[finding.get("category", "other").lower()] += 1

    # Calculate key metrics
    total_findings = len(findings)
    critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

    # Correlation metrics
    correlation_list = correlations.get("correlations", [])
    clusters = correlations.get("clusters", [])
    insights = correlations.get("insights", [])

    # Compliance metrics
    gaps = compliance.get("gaps", [])
    controls_assessed = compliance.get("controls_assessed", 0)
    controls_passing = compliance.get("controls_passing", 0)

    return {
        "total_findings": total_findings,
        "critical_findings": severity_counts.get("critical", 0),
        "high_findings": severity_counts.get("high", 0),
        "medium_findings": severity_counts.get("medium", 0),
        "low_findings": severity_counts.get("low", 0),
        "findings_by_category": dict(category_counts),
        "critical_high_ratio": round(critical_high / total_findings * 100, 1)
        if total_findings
        else 0,
        "correlation_count": len(correlation_list),
        "cluster_count": len(clusters),
        "insight_count": len(insights),
        "compliance_gaps": len(gaps),
        "controls_assessed": controls_assessed,
        "controls_passing": controls_passing,
        "compliance_rate": round(controls_passing / controls_assessed * 100, 1)
        if controls_assessed
        else 0,
    }


def generate_trend_summary(ctx: Context, period: str) -> Dict[str, Any]:
    """Generate trend summary."""
    # In a real implementation, this would compare against historical data
    # For now, we provide structure for future trend analysis

    return {
        "period": period,
        "risk_direction": TrendDirection.UNKNOWN.value,
        "finding_direction": TrendDirection.UNKNOWN.value,
        "compliance_direction": TrendDirection.UNKNOWN.value,
        "notable_changes": [],
        "comparison": {
            "previous_risk_score": None,
            "current_risk_score": None,
            "delta": None,
        },
    }


def get_key_findings(
    findings: List[Dict[str, Any]], limit: int = 5
) -> List[Dict[str, Any]]:
    """Get key findings for executive summary."""
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "medium").lower(), 5),
    )

    key_findings = []
    for finding in sorted_findings[:limit]:
        key_findings.append(
            {
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "medium"),
                "category": finding.get("category", "security"),
                "business_impact": BUSINESS_IMPACT_TEMPLATES.get(
                    finding.get("category", ""), "Potential security risk"
                ),
            }
        )

    return key_findings


def get_top_risks(
    findings: List[Dict[str, Any]], dashboard: RiskDashboard, limit: int = 5
) -> List[Dict[str, Any]]:
    """Get top risks for executive summary."""
    # Use dashboard top_risks or calculate from findings
    if dashboard.top_risks:
        return dashboard.top_risks[:limit]

    return get_top_risks_from_findings(findings, limit)


def get_top_risks_from_findings(
    findings: List[Dict[str, Any]], limit: int = 5
) -> List[Dict[str, Any]]:
    """Calculate top risks from findings."""
    # Score and rank findings
    scored_findings = []
    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        category = finding.get("category", "other").lower()

        score = SEVERITY_WEIGHTS.get(severity, 1.0) * CATEGORY_WEIGHTS.get(
            category, 1.0
        )
        scored_findings.append((finding, score))

    # Sort by score descending
    scored_findings.sort(key=lambda x: -x[1])

    top_risks = []
    for finding, score in scored_findings[:limit]:
        top_risks.append(
            {
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "medium"),
                "category": finding.get("category", "security"),
                "risk_score": round(score, 1),
                "business_impact": BUSINESS_IMPACT_TEMPLATES.get(
                    finding.get("category", ""), "Security risk requiring attention"
                ),
            }
        )

    return top_risks


def generate_executive_brief(
    target: str,
    dashboard: RiskDashboard,
    key_findings: List[Dict[str, Any]],
    compliance_summary: Any,
) -> str:
    """Generate executive brief text."""
    risk_level = dashboard.risk_level.value.upper()
    risk_score = dashboard.overall_score
    finding_count = len(key_findings)

    critical_count = dashboard.risk_by_severity.get("critical", 0)
    high_count = dashboard.risk_by_severity.get("high", 0)

    # Get compliance score
    if hasattr(compliance_summary, "compliance_score"):
        compliance_score = compliance_summary.compliance_score
    elif isinstance(compliance_summary, dict):
        compliance_score = compliance_summary.get("compliance_score", 0)
    else:
        compliance_score = 0

    brief = f"""Security Assessment Summary for {target}

Overall Risk Level: {risk_level} (Score: {risk_score:.1f}/100)

The assessment identified {finding_count} key findings requiring attention. """

    if critical_count > 0:
        brief += (
            f"There are {critical_count} critical issues requiring immediate action. "
        )

    if high_count > 0:
        brief += f"Additionally, {high_count} high-priority items should be addressed within the next 1-2 weeks. "

    if compliance_score > 0:
        brief += f"\n\nCompliance posture is at {compliance_score:.0f}%. "

    brief += (
        "\n\nRecommended immediate actions are detailed in the recommendations section."
    )

    return brief


def generate_next_steps(
    recommendations: List[Recommendation], dashboard: RiskDashboard
) -> List[str]:
    """Generate next steps list."""
    next_steps = []

    # Add critical/immediate items
    critical_recs = [r for r in recommendations if r.priority == "critical"]
    if critical_recs:
        next_steps.append(f"Address {len(critical_recs)} critical findings immediately")

    # Add high priority items
    high_recs = [r for r in recommendations if r.priority == "high"]
    if high_recs:
        next_steps.append(
            f"Schedule remediation for {len(high_recs)} high-priority items"
        )

    # Risk-based next steps
    if dashboard.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
        next_steps.append("Schedule follow-up assessment after remediations")
        next_steps.append("Review and update incident response procedures")

    # Compliance next steps
    if dashboard.exposure_metrics.get("credential_risks", 0) > 0:
        next_steps.append("Conduct credential rotation for exposed secrets")

    # Default next steps
    if not next_steps:
        next_steps.append("Review findings with security team")
        next_steps.append("Prioritize remediations based on business impact")

    return next_steps[:5]


def generate_appendix(
    findings: List[Dict[str, Any]], correlations: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate report appendix with detailed data."""
    return {
        "total_findings": len(findings),
        "findings_summary": {
            "by_severity": count_by_field(findings, "severity"),
            "by_category": count_by_field(findings, "category"),
        },
        "correlation_summary": {
            "total_correlations": len(correlations.get("correlations", [])),
            "total_clusters": len(correlations.get("clusters", [])),
            "total_insights": len(correlations.get("insights", [])),
        },
        "methodology": "Automated security assessment using RedOPS framework",
        "limitations": [
            "Assessment based on publicly available information",
            "Point-in-time assessment; conditions may change",
            "Not a substitute for comprehensive penetration testing",
        ],
    }


# ============================================================================
# Helper Functions
# ============================================================================


def generate_report_id(target: str) -> str:
    """Generate unique report ID."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    hash_input = f"{target}:{timestamp}"
    hash_val = hashlib.md5(hash_input.encode()).hexdigest()[:8]
    return f"RPT-{timestamp}-{hash_val.upper()}"


def severity_priority(severity: str) -> int:
    """Get numeric priority for severity."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        severity.lower(), 5
    )


def count_by_field(items: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    """Count items by field value."""
    counts = defaultdict(int)
    for item in items:
        value = item.get(field, "unknown")
        counts[value.lower() if isinstance(value, str) else str(value)] += 1
    return dict(counts)


def get_report_types() -> List[str]:
    """Get all report types."""
    return [t.value for t in ReportType]


def get_audiences() -> List[str]:
    """Get all audience types."""
    return [a.value for a in Audience]


def get_risk_levels() -> List[str]:
    """Get all risk levels."""
    return [r.value for r in RiskLevel]


def get_trend_directions() -> List[str]:
    """Get all trend directions."""
    return [t.value for t in TrendDirection]


def get_compliance_statuses() -> List[str]:
    """Get all compliance statuses."""
    return [s.value for s in ComplianceStatus]


# ============================================================================
# Report Formatting Functions
# ============================================================================


def format_for_audience(report: Dict[str, Any], audience: Audience) -> Dict[str, Any]:
    """Format report for specific audience."""
    if audience == Audience.BOARD:
        # Board gets condensed view
        return {
            "executive_summary": report.get("executive_summary", {}),
            "risk_dashboard": {
                "overall_score": report.get("risk_dashboard", {}).get("overall_score"),
                "risk_level": report.get("risk_dashboard", {}).get("risk_level"),
            },
            "top_recommendations": report.get("recommendations", [])[:3],
        }

    elif audience == Audience.TECHNICAL:
        # Technical gets full details
        return report

    elif audience == Audience.COMPLIANCE:
        # Compliance focuses on compliance sections
        return {
            "compliance_report": report.get("compliance_report", {}),
            "recommendations": [
                r
                for r in report.get("recommendations", [])
                if r.get("category") == "compliance"
            ],
            "appendix": report.get("appendix", {}),
        }

    else:
        # Default executive view
        return {
            "executive_summary": report.get("executive_summary", {}),
            "risk_dashboard": report.get("risk_dashboard", {}),
            "recommendations": report.get("recommendations", [])[:10],
        }


def generate_html_summary(report: Dict[str, Any]) -> str:
    """Generate HTML summary of report."""
    summary = report.get("executive_summary", {})
    dashboard = report.get("risk_dashboard", {})

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{summary.get("title", "Security Report")}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; background: #f5f5f5; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{summary.get("title", "Security Assessment Report")}</h1>
        <p>Generated: {summary.get("generated_at", "")}</p>
    </div>

    <h2>Risk Overview</h2>
    <div class="metric">
        <strong>Risk Score:</strong> {dashboard.get("overall_score", 0)}/100
    </div>
    <div class="metric">
        <strong>Risk Level:</strong>
        <span class="{dashboard.get("risk_level", "medium")}">{dashboard.get("risk_level", "Unknown").upper()}</span>
    </div>

    <h2>Executive Brief</h2>
    <p>{summary.get("executive_brief", "").replace(chr(10), "<br>")}</p>

    <h2>Key Findings</h2>
    <ul>
"""

    for finding in summary.get("key_findings", []):
        html += f"<li><strong class='{finding.get('severity', '')}'>{finding.get('title', '')}</strong> - {finding.get('business_impact', '')}</li>\n"

    html += """
    </ul>

    <h2>Recommendations</h2>
    <ol>
"""

    for rec in report.get("recommendations", [])[:5]:
        html += f"<li><strong>{rec.get('title', '')}</strong> - Priority: {rec.get('priority', '').upper()}</li>\n"

    html += """
    </ol>
</body>
</html>"""

    return html


def generate_markdown_summary(report: Dict[str, Any]) -> str:
    """Generate Markdown summary of report."""
    summary = report.get("executive_summary", {})
    dashboard = report.get("risk_dashboard", {})

    md = f"""# {summary.get("title", "Security Assessment Report")}

**Generated:** {summary.get("generated_at", "")}
**Target:** {summary.get("target", "")}

## Risk Overview

| Metric | Value |
|--------|-------|
| Risk Score | {dashboard.get("overall_score", 0)}/100 |
| Risk Level | {dashboard.get("risk_level", "Unknown").upper()} |
| Critical Findings | {dashboard.get("risk_by_severity", {}).get("critical", 0)} |
| High Findings | {dashboard.get("risk_by_severity", {}).get("high", 0)} |

## Executive Brief

{summary.get("executive_brief", "")}

## Key Findings

"""

    for finding in summary.get("key_findings", []):
        md += f"- **{finding.get('title', '')}** ({finding.get('severity', '').upper()})\n"
        md += f"  - Impact: {finding.get('business_impact', '')}\n"

    md += "\n## Recommendations\n\n"

    for i, rec in enumerate(report.get("recommendations", [])[:5], 1):
        md += f"{i}. **{rec.get('title', '')}**\n"
        md += f"   - Priority: {rec.get('priority', '').upper()}\n"
        md += f"   - Timeline: {rec.get('timeline', '')}\n"

    md += "\n## Next Steps\n\n"

    for step in summary.get("next_steps", []):
        md += f"- {step}\n"

    return md


def create_recommendation(
    title: str,
    description: str,
    priority: str = "medium",
    category: str = "security",
    effort: str = "medium",
    rec_id: Optional[str] = None,
) -> Recommendation:
    """Create a recommendation object."""
    if rec_id is None:
        hash_val = hashlib.md5(f"{title}:{description}".encode()).hexdigest()[:6]
        rec_id = f"REC-{hash_val.upper()}"

    return Recommendation(
        id=rec_id,
        title=title,
        description=description,
        priority=priority,
        category=category,
        business_impact=BUSINESS_IMPACT_TEMPLATES.get(category, "Security improvement"),
        effort=effort,
        timeline=EFFORT_ESTIMATES.get(priority, "TBD"),
    )


def calculate_overall_risk_score(findings: List[Dict[str, Any]]) -> float:
    """Calculate overall risk score from findings."""
    if not findings:
        return 0.0

    total_score = 0.0
    for finding in findings:
        severity = finding.get("severity", "medium").lower()
        category = finding.get("category", "other").lower()

        weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        cat_weight = CATEGORY_WEIGHTS.get(category, 1.0)
        total_score += weight * cat_weight

    max_possible = len(findings) * 12.0  # Max: critical (10) * credential (1.2)
    return min(100, (total_score / max_possible) * 100)
