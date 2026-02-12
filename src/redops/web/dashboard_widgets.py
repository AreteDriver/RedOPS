"""
Dashboard widgets and visualization helpers.

Provides reusable components for dashboard visualizations,
metrics calculations, and summary statistics.
"""

from typing import Any
from datetime import datetime, timedelta, timezone
from collections import Counter
from redops.core.context import Context


def get_risk_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of risks by severity.

    Args:
        ctx: Pipeline context

    Returns:
        Risk summary with counts and percentages
    """
    risks = ctx.get("risks", [])

    severity_counts = Counter()
    for risk in risks:
        if isinstance(risk, dict):
            level = risk.get("level", "unknown").lower()
            severity_counts[level] += 1

    total = sum(severity_counts.values())

    return {
        "total": total,
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "info": severity_counts.get("info", 0),
        "percentages": {
            "critical": round(severity_counts.get("critical", 0) / total * 100, 1)
            if total
            else 0,
            "high": round(severity_counts.get("high", 0) / total * 100, 1)
            if total
            else 0,
            "medium": round(severity_counts.get("medium", 0) / total * 100, 1)
            if total
            else 0,
            "low": round(severity_counts.get("low", 0) / total * 100, 1)
            if total
            else 0,
        },
        "risk_score": calculate_risk_score(severity_counts),
    }


def calculate_risk_score(severity_counts: Counter) -> int:
    """
    Calculate an overall risk score (0-100).

    Args:
        severity_counts: Counter of severities

    Returns:
        Risk score from 0 (safe) to 100 (critical)
    """
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1,
    }

    weighted_sum = sum(
        count * weights.get(severity, 0) for severity, count in severity_counts.items()
    )

    # Cap at 100
    return min(100, weighted_sum)


def get_findings_timeline(ctx: Context, days: int = 30) -> list[dict[str, Any]]:
    """
    Get findings grouped by time for timeline visualization.

    Args:
        ctx: Pipeline context
        days: Number of days to include

    Returns:
        List of daily finding counts
    """
    findings = []

    # Collect findings with timestamps
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            timestamp = value.get("timestamp") or value.get("discovered_at")
            if timestamp:
                findings.append(
                    {
                        "timestamp": timestamp,
                        "severity": value.get("severity", "unknown"),
                    }
                )

    # Group by date
    now = datetime.now(timezone.utc)
    timeline = []

    for day_offset in range(days, -1, -1):
        date = now - timedelta(days=day_offset)
        date_str = date.strftime("%Y-%m-%d")

        day_findings = [
            f
            for f in findings
            if f["timestamp"].startswith(date_str)
            if isinstance(f["timestamp"], str)
        ]

        severity_counts = Counter(f["severity"] for f in day_findings)

        timeline.append(
            {
                "date": date_str,
                "total": len(day_findings),
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
            }
        )

    return timeline


def get_module_stats(ctx: Context) -> list[dict[str, Any]]:
    """
    Get statistics by module.

    Args:
        ctx: Pipeline context

    Returns:
        List of module statistics
    """
    module_findings: dict[str, list[dict]] = {}

    # Collect findings by module
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            module = value.get("module", "unknown")
            if module not in module_findings:
                module_findings[module] = []
            module_findings[module].append(value)

    stats = []
    for module, findings in module_findings.items():
        severity_counts = Counter()
        for f in findings:
            severity = f.get("severity", "unknown")
            if hasattr(severity, "name"):
                severity = severity.name.lower()
            severity_counts[str(severity).lower()] += 1

        stats.append(
            {
                "module": module,
                "total_findings": len(findings),
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
            }
        )

    return sorted(stats, key=lambda x: x["total_findings"], reverse=True)


def get_attack_surface_summary(ctx: Context) -> dict[str, Any]:
    """
    Get attack surface summary metrics.

    Args:
        ctx: Pipeline context

    Returns:
        Attack surface summary
    """
    subdomains = ctx.get("subdomains", []) or ctx.get("ct_subdomains", [])
    ports = ctx.get("open_ports", [])
    services = ctx.get("services", [])
    technologies = ctx.get("technologies", []) or ctx.get("tech_stack", [])

    return {
        "subdomains_count": len(subdomains),
        "open_ports_count": len(ports),
        "services_count": len(services),
        "technologies_count": len(technologies),
        "attack_paths_count": len(ctx.get("attack_paths", [])),
        "mitre_techniques_count": len(ctx.get("mitre_techniques_used", [])),
        "exposure_score": calculate_exposure_score(
            len(subdomains),
            len(ports),
            len(services),
        ),
    }


def calculate_exposure_score(
    subdomain_count: int,
    port_count: int,
    service_count: int,
) -> int:
    """
    Calculate an exposure score based on attack surface.

    Args:
        subdomain_count: Number of discovered subdomains
        port_count: Number of open ports
        service_count: Number of exposed services

    Returns:
        Exposure score from 0 (minimal) to 100 (high exposure)
    """
    # Weight factors
    subdomain_weight = min(subdomain_count * 0.5, 30)
    port_weight = min(port_count * 2, 40)
    service_weight = min(service_count * 3, 30)

    return min(100, int(subdomain_weight + port_weight + service_weight))


def get_compliance_status(ctx: Context) -> dict[str, Any]:
    """
    Get compliance/control status summary.

    Args:
        ctx: Pipeline context

    Returns:
        Compliance status summary
    """
    compliance_data = ctx.get("compliance_results", {})

    if not compliance_data:
        # Generate basic compliance data from findings
        risks = ctx.get("risks", [])

        passed = 0
        failed = 0
        warnings = 0

        for risk in risks:
            if isinstance(risk, dict):
                level = risk.get("level", "").lower()
                if level in ("critical", "high"):
                    failed += 1
                elif level == "medium":
                    warnings += 1
                else:
                    passed += 1

        total = passed + failed + warnings

        return {
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "pass_rate": round(passed / total * 100, 1) if total else 100,
            "by_framework": {},
        }

    return compliance_data


def get_threat_intel_summary(ctx: Context) -> dict[str, Any]:
    """
    Get threat intelligence summary.

    Args:
        ctx: Pipeline context

    Returns:
        Threat intel summary
    """
    greynoise = ctx.get("greynoise_result", {})
    abuseipdb = ctx.get("abuseipdb_result", {})
    urlhaus = ctx.get("urlhaus_result", {})

    indicators = []

    # Count threat indicators
    if greynoise.get("noise"):
        indicators.append(
            {
                "type": "scanner_ip",
                "source": "greynoise",
                "severity": "high"
                if greynoise.get("classification") == "malicious"
                else "medium",
            }
        )

    if abuseipdb.get("abuseConfidenceScore", 0) > 50:
        indicators.append(
            {
                "type": "abusive_ip",
                "source": "abuseipdb",
                "severity": "high"
                if abuseipdb.get("abuseConfidenceScore", 0) > 75
                else "medium",
            }
        )

    if urlhaus.get("query_status") == "ok":
        indicators.append(
            {
                "type": "malicious_url",
                "source": "urlhaus",
                "severity": "critical"
                if urlhaus.get("url_status") == "online"
                else "high",
            }
        )

    return {
        "total_indicators": len(indicators),
        "indicators": indicators,
        "sources_checked": sum(
            [
                1 if greynoise else 0,
                1 if abuseipdb else 0,
                1 if urlhaus else 0,
            ]
        ),
        "threat_level": calculate_threat_level(indicators),
    }


def calculate_threat_level(indicators: list[dict]) -> str:
    """Calculate overall threat level from indicators."""
    if not indicators:
        return "low"

    severities = [i.get("severity", "low") for i in indicators]

    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


def generate_dashboard_data(ctx: Context) -> dict[str, Any]:
    """
    Generate complete dashboard data from context.

    Args:
        ctx: Pipeline context

    Returns:
        Complete dashboard data structure
    """
    return {
        "target": ctx.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_summary": get_risk_summary(ctx),
        "attack_surface": get_attack_surface_summary(ctx),
        "module_stats": get_module_stats(ctx),
        "compliance": get_compliance_status(ctx),
        "threat_intel": get_threat_intel_summary(ctx),
        "recent_findings": get_recent_findings(ctx, limit=10),
    }


def get_recent_findings(ctx: Context, limit: int = 10) -> list[dict[str, Any]]:
    """
    Get most recent findings.

    Args:
        ctx: Pipeline context
        limit: Maximum number of findings to return

    Returns:
        List of recent findings
    """
    findings = []

    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            findings.append(
                {
                    "id": key,
                    "title": value.get("title", "Unknown"),
                    "module": value.get("module", "unknown"),
                    "severity": normalize_severity(value.get("severity", "unknown")),
                    "timestamp": value.get("timestamp", ""),
                }
            )

    # Sort by timestamp (most recent first)
    findings.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return findings[:limit]


def normalize_severity(severity: Any) -> str:
    """Normalize severity to string."""
    if isinstance(severity, str):
        return severity.lower()
    elif hasattr(severity, "name"):
        return severity.name.lower()
    return str(severity).lower()


def format_dashboard_html(data: dict[str, Any]) -> str:
    """
    Format dashboard data as HTML widget.

    Args:
        data: Dashboard data

    Returns:
        HTML string
    """
    risk = data.get("risk_summary", {})
    surface = data.get("attack_surface", {})

    return f"""
    <div class="dashboard-summary">
        <div class="metric-card">
            <h3>Risk Score</h3>
            <div class="score score-{get_score_class(risk.get("risk_score", 0))}">{risk.get("risk_score", 0)}</div>
        </div>
        <div class="metric-card">
            <h3>Total Findings</h3>
            <div class="count">{risk.get("total", 0)}</div>
            <div class="breakdown">
                <span class="critical">{risk.get("critical", 0)} Critical</span>
                <span class="high">{risk.get("high", 0)} High</span>
            </div>
        </div>
        <div class="metric-card">
            <h3>Attack Surface</h3>
            <div class="count">{surface.get("subdomains_count", 0)}</div>
            <div class="label">Subdomains</div>
        </div>
        <div class="metric-card">
            <h3>Exposure Score</h3>
            <div class="score score-{get_score_class(surface.get("exposure_score", 0))}">{surface.get("exposure_score", 0)}</div>
        </div>
    </div>
    """


def get_score_class(score: int) -> str:
    """Get CSS class for score value."""
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    return "low"
