"""
Markdown report generation module.

Generates executive summaries and technical reports in Markdown format.
Includes MITRE ATT&CK matrix visualization, risk heatmaps, and attack path diagrams.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime
from redops.core.context import Context


# Risk level colors for text indicators
RISK_INDICATORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "🔵",
}

# MITRE ATT&CK tactics in kill chain order
MITRE_TACTICS_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def generate_exec_summary(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Generate an executive summary report.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Generating executive summary", level="INFO")

    # Build the report
    report = build_executive_summary(ctx)

    # Save to file
    output_path = (
        output_dir / f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    with open(output_path, "w") as f:
        f.write(report)

    ctx.add("executive_summary_path", str(output_path))
    ctx.log(f"Executive summary saved to {output_path}", level="INFO")

    return ctx


def build_executive_summary(ctx: Context) -> str:
    """
    Build the executive summary content.

    Args:
        ctx: Pipeline context

    Returns:
        Markdown report string
    """
    target = ctx.target or "N/A"
    pipeline = ctx.get("pipeline_name", "Unknown")

    # Calculate overall risk level
    risks = ctx.get("risks", [])
    overall_risk = calculate_overall_risk_level(risks)
    risk_indicator = RISK_INDICATORS.get(overall_risk.lower(), "⚪")

    report = f"""### Assessment Overview

| Metric | Value |
|--------|-------|
| Target | {target} |
| Pipeline | {pipeline} |
| Overall Risk | {risk_indicator} {overall_risk.upper()} |
| Assessment Date | {datetime.now().strftime("%Y-%m-%d")} |

### Key Findings Summary

"""

    # Risk summary
    if risks:
        critical = sum(1 for r in risks if r.get("level", "").lower() == "critical")
        high = sum(1 for r in risks if r.get("level", "").lower() == "high")
        medium = sum(1 for r in risks if r.get("level", "").lower() == "medium")
        low = sum(1 for r in risks if r.get("level", "").lower() == "low")

        report += "**Risk Distribution:**\n"
        report += f"- {RISK_INDICATORS['critical']} Critical: {critical}\n"
        report += f"- {RISK_INDICATORS['high']} High: {high}\n"
        report += f"- {RISK_INDICATORS['medium']} Medium: {medium}\n"
        report += f"- {RISK_INDICATORS['low']} Low: {low}\n\n"
    else:
        report += "No significant risks identified during this assessment.\n\n"

    # Attack paths summary
    attack_paths = ctx.get("attack_paths", [])
    if attack_paths:
        report += "**Attack Surface:**\n"
        report += f"- {len(attack_paths)} potential attack path(s) identified\n"

        # Get highest risk path
        sorted_paths = sorted(
            attack_paths,
            key=lambda p: p.get("likelihood", 0) * p.get("impact", 0),
            reverse=True,
        )
        if sorted_paths:
            top_path = sorted_paths[0]
            top_score = top_path.get("likelihood", 0) * top_path.get("impact", 0)
            top_name = top_path.get("name", "Unnamed")
            report += f"- Highest risk path: **{top_name}** (score: {top_score})\n"
        report += "\n"

    # MITRE coverage summary
    mitre_techniques = ctx.get("mitre_techniques_used", [])
    mitre_summary = ctx.get("mitre_summary", {})
    if mitre_techniques or mitre_summary:
        total_techniques = mitre_summary.get("total_techniques", len(mitre_techniques))
        tactics_covered = mitre_summary.get("tactics_covered", 0)
        coverage_pct = mitre_summary.get("coverage_percentage", 0)

        report += "**MITRE ATT&CK Coverage:**\n"
        report += f"- {total_techniques} technique(s) mapped\n"
        report += f"- {tactics_covered} tactic(s) covered\n"
        if coverage_pct > 0:
            report += f"- Coverage: {coverage_pct:.1f}%\n"
        report += "\n"

    # Scenarios summary
    scenarios = ctx.get("scenarios", [])
    if scenarios:
        report += "**Threat Scenarios:**\n"
        report += f"- {len(scenarios)} realistic attack scenario(s) modeled\n"

        # Count by risk level
        scenario_levels = {}
        for s in scenarios:
            level = s.get("risk_level", "MEDIUM")
            scenario_levels[level] = scenario_levels.get(level, 0) + 1

        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if level in scenario_levels:
                indicator = RISK_INDICATORS.get(level.lower(), "⚪")
                report += f"  - {indicator} {level}: {scenario_levels[level]}\n"
        report += "\n"

    # Quick recommendations
    report += "### Priority Recommendations\n\n"

    if critical > 0 if risks else False:
        report += f"1. {RISK_INDICATORS['critical']} **IMMEDIATE:** Address {critical} critical risk(s)\n"
    if high > 0 if risks else False:
        report += f"2. {RISK_INDICATORS['high']} **HIGH PRIORITY:** Remediate {high} high-severity finding(s)\n"
    if attack_paths:
        report += f"3. {RISK_INDICATORS['medium']} Review and mitigate identified attack paths\n"

    report += "4. Implement continuous security monitoring\n"
    report += "5. Conduct follow-up assessments\n"

    return report


def calculate_overall_risk_level(risks: List[Dict[str, Any]]) -> str:
    """
    Calculate overall risk level from list of risks.

    Args:
        risks: List of risk dictionaries

    Returns:
        Risk level string
    """
    if not risks:
        return "low"

    critical = sum(1 for r in risks if r.get("level", "").lower() == "critical")
    high = sum(1 for r in risks if r.get("level", "").lower() == "high")
    medium = sum(1 for r in risks if r.get("level", "").lower() == "medium")

    if critical > 0:
        return "critical"
    elif high >= 3:
        return "high"
    elif high > 0 or medium >= 5:
        return "medium"
    else:
        return "low"


def generate_technical_report(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Generate a detailed technical report.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Generating technical report", level="INFO")

    # Build the report
    report = build_technical_report(ctx)

    # Save to file
    output_path = (
        output_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    with open(output_path, "w") as f:
        f.write(report)

    ctx.add("technical_report_path", str(output_path))
    ctx.log(f"Technical report saved to {output_path}", level="INFO")

    return ctx


def build_technical_report(ctx: Context) -> str:
    """
    Build the technical report content.

    Args:
        ctx: Pipeline context

    Returns:
        Markdown report string
    """
    target = ctx.target or "N/A"
    pipeline = ctx.get("pipeline_name", "Unknown")

    report = f"""# RedOps Technical Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
**Target:** {target}
**Pipeline:** {pipeline}

---

## Executive Summary

{build_executive_summary(ctx)}

"""

    # Add MITRE ATT&CK Matrix if techniques are available
    mitre_mapping = ctx.get("mitre_mapping", {})
    mitre_techniques = ctx.get("mitre_techniques_used", [])
    if mitre_mapping or mitre_techniques:
        report += "## MITRE ATT&CK Coverage\n\n"
        report += build_mitre_matrix_markdown(ctx)
        report += "\n"

    # Add Risk Heatmap
    risks = ctx.get("risks", [])
    if risks:
        report += "## Risk Heatmap\n\n"
        report += build_risk_heatmap_markdown(risks)
        report += "\n"

    # Add Attack Paths visualization
    attack_paths = ctx.get("attack_paths", [])
    if attack_paths:
        report += "## Attack Path Analysis\n\n"
        report += build_attack_paths_markdown(attack_paths)
        report += "\n"

    # Add Scenarios if available
    scenarios = ctx.get("scenarios", [])
    if scenarios:
        report += "## Attack Scenarios\n\n"
        report += build_scenarios_markdown(scenarios)
        report += "\n"

    # Detailed Findings
    report += "## Detailed Findings\n\n"

    # Group findings by category
    findings_by_category = group_findings_by_category(ctx)
    for category, findings in findings_by_category.items():
        report += f"### {category}\n\n"
        for finding in findings:
            title = finding.get("title", "Untitled")
            severity = finding.get("severity", finding.get("level", "info"))
            indicator = RISK_INDICATORS.get(severity.lower(), "⚪")
            report += f"- {indicator} **{title}**"
            if finding.get("description"):
                report += f": {finding['description'][:200]}"
            report += "\n"
        report += "\n"

    report += "## Logs\n\n"

    if ctx.get("include_logs", True):
        logs = ctx.get_logs()
        for log in logs[-20:]:  # Last 20 logs
            level = log.get("level", "INFO")
            message = log.get("message", "")
            report += f"- [{level}] {message}\n"

    return report


def build_mitre_matrix_markdown(ctx: Context) -> str:
    """
    Build a MITRE ATT&CK matrix visualization in markdown.

    Args:
        ctx: Pipeline context

    Returns:
        Markdown string with MITRE matrix
    """
    mitre_mapping = ctx.get("mitre_mapping", {})
    mitre_techniques = set(ctx.get("mitre_techniques_used", []))
    tactic_coverage = ctx.get("mitre_tactic_coverage", {})

    # Build matrix view from mapping
    matrix = ctx.get("mitre_matrix_view", {})
    if not matrix and mitre_mapping:
        # Build from mapping
        matrix = {}
        for technique_id, technique_info in mitre_mapping.items():
            if isinstance(technique_info, dict):
                tactic = technique_info.get("tactic", "Unknown")
            else:
                tactic = "Unknown"
            if tactic not in matrix:
                matrix[tactic] = []
            matrix[tactic].append(technique_id)

    if not matrix and not mitre_techniques:
        return "*No MITRE ATT&CK techniques identified.*\n"

    output = "### ATT&CK Matrix Coverage\n\n"

    # Summary statistics
    total_techniques = (
        len(mitre_techniques)
        if mitre_techniques
        else sum(len(v) for v in matrix.values())
    )
    tactics_covered = (
        len([t for t in matrix if matrix.get(t)]) if matrix else len(tactic_coverage)
    )

    output += f"- **Total Techniques:** {total_techniques}\n"
    output += f"- **Tactics Covered:** {tactics_covered}/{len(MITRE_TACTICS_ORDER)}\n\n"

    # Matrix table
    output += "| Tactic | Techniques | Count |\n"
    output += "|--------|------------|-------|\n"

    for tactic in MITRE_TACTICS_ORDER:
        techniques = matrix.get(tactic, [])
        count = tactic_coverage.get(tactic, len(techniques))

        if techniques:
            # Show first 3 techniques
            technique_str = ", ".join(sorted(techniques)[:3])
            if len(techniques) > 3:
                technique_str += f" (+{len(techniques) - 3} more)"
        else:
            technique_str = "-"

        indicator = "✅" if count > 0 else "⬜"
        output += f"| {indicator} {tactic} | {technique_str} | {count} |\n"

    return output


def build_risk_heatmap_markdown(risks: List[Dict[str, Any]]) -> str:
    """
    Build a risk heatmap visualization in markdown.

    Args:
        risks: List of risk dictionaries

    Returns:
        Markdown string with risk heatmap
    """
    if not risks:
        return "*No risks identified.*\n"

    # Count risks by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for risk in risks:
        level = risk.get("level", risk.get("severity", "info")).lower()
        if level in severity_counts:
            severity_counts[level] += 1
        else:
            severity_counts["info"] += 1

    output = "### Risk Distribution\n\n"
    output += "| Severity | Count | Indicator |\n"
    output += "|----------|-------|----------|\n"

    for severity in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts[severity]
        indicator = RISK_INDICATORS.get(severity, "⚪")
        bar = "█" * min(count, 20)  # Visual bar, max 20 chars
        output += f"| {indicator} {severity.upper()} | {count} | {bar} |\n"

    output += f"\n**Total Risks:** {len(risks)}\n\n"

    # Risk by likelihood/impact matrix if available
    likelihood_impact = build_likelihood_impact_matrix(risks)
    if likelihood_impact:
        output += "### Likelihood vs Impact Matrix\n\n"
        output += likelihood_impact

    return output


def build_likelihood_impact_matrix(risks: List[Dict[str, Any]]) -> str:
    """
    Build a likelihood vs impact matrix.

    Args:
        risks: List of risk dictionaries

    Returns:
        Markdown string with matrix
    """
    # Check if risks have likelihood and impact
    has_metrics = any("likelihood" in r and "impact" in r for r in risks)

    if not has_metrics:
        return ""

    # Build 5x5 matrix
    matrix = [[0 for _ in range(5)] for _ in range(5)]

    for risk in risks:
        likelihood = risk.get("likelihood", 3)
        impact = risk.get("impact", 3)
        # Clamp to 1-5 range
        likelihood = max(1, min(5, likelihood))
        impact = max(1, min(5, impact))
        matrix[5 - likelihood][impact - 1] += 1

    output = "```\n"
    output += "Impact →   1     2     3     4     5\n"
    output += "Likelihood\n"
    output += "    ↓\n"

    for i, row in enumerate(matrix):
        likelihood_level = 5 - i
        output += f"    {likelihood_level}    "
        for count in row:
            if count == 0:
                output += "  ·  "
            elif count < 10:
                output += f"  {count}  "
            else:
                output += f" {count}  "
        output += "\n"

    output += "```\n"

    return output


def build_attack_paths_markdown(attack_paths: List[Dict[str, Any]]) -> str:
    """
    Build attack path visualizations in markdown.

    Args:
        attack_paths: List of attack path dictionaries

    Returns:
        Markdown string with attack path diagrams
    """
    if not attack_paths:
        return "*No attack paths identified.*\n"

    output = f"### Identified Attack Paths ({len(attack_paths)} total)\n\n"

    # Show top 5 attack paths
    sorted_paths = sorted(
        attack_paths,
        key=lambda p: p.get("likelihood", 0) * p.get("impact", 0),
        reverse=True,
    )

    for i, path in enumerate(sorted_paths[:5], 1):
        name = path.get("name", f"Attack Path {i}")
        description = path.get("description", "")
        likelihood = path.get("likelihood", 0)
        impact = path.get("impact", 0)
        risk_score = likelihood * impact
        steps = path.get("steps", [])
        mitre_techniques = path.get("mitre_techniques", [])

        # Determine risk level
        if risk_score >= 20:
            risk_level = "CRITICAL"
            indicator = "🔴"
        elif risk_score >= 12:
            risk_level = "HIGH"
            indicator = "🟠"
        elif risk_score >= 6:
            risk_level = "MEDIUM"
            indicator = "🟡"
        else:
            risk_level = "LOW"
            indicator = "🟢"

        output += f"#### {i}. {indicator} {name}\n\n"

        if description:
            output += f"{description}\n\n"

        output += f"- **Risk Score:** {risk_score} ({risk_level})\n"
        output += f"- **Likelihood:** {likelihood}/5\n"
        output += f"- **Impact:** {impact}/5\n"

        if mitre_techniques:
            output += f"- **MITRE Techniques:** {', '.join(mitre_techniques[:5])}"
            if len(mitre_techniques) > 5:
                output += f" (+{len(mitre_techniques) - 5} more)"
            output += "\n"

        # Visualize path
        if steps:
            output += "\n**Attack Chain:**\n```\n"
            for j, step in enumerate(steps):
                if isinstance(step, dict):
                    step_name = step.get("name", step.get("node", f"Step {j + 1}"))
                else:
                    step_name = str(step)

                if j == 0:
                    output += f"[ENTRY] {step_name}\n"
                elif j == len(steps) - 1:
                    output += f"    └──▶ [TARGET] {step_name}\n"
                else:
                    output += f"    │\n    ├──▶ {step_name}\n"
            output += "```\n"

        output += "\n"

    if len(attack_paths) > 5:
        output += f"*... and {len(attack_paths) - 5} more attack paths.*\n\n"

    return output


def build_scenarios_markdown(scenarios: List[Dict[str, Any]]) -> str:
    """
    Build attack scenario summaries in markdown.

    Args:
        scenarios: List of scenario dictionaries

    Returns:
        Markdown string with scenarios
    """
    if not scenarios:
        return "*No attack scenarios generated.*\n"

    output = f"### Attack Scenarios ({len(scenarios)} total)\n\n"

    for i, scenario in enumerate(scenarios[:3], 1):
        name = scenario.get("name", f"Scenario {i}")
        threat_actor = scenario.get("threat_actor", {})
        objective = scenario.get("objective", "Unknown")
        risk_level = scenario.get("risk_level", "MEDIUM")
        executive_summary = scenario.get("executive_summary", "")

        # Risk indicator
        indicator = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(risk_level.upper(), "⚪")

        output += f"#### {i}. {indicator} {name}\n\n"

        if isinstance(threat_actor, dict):
            actor_name = threat_actor.get("name", "Unknown")
            actor_motivation = threat_actor.get("motivation", "")
            output += f"- **Threat Actor:** {actor_name}\n"
            if actor_motivation:
                output += f"- **Motivation:** {actor_motivation}\n"
        elif threat_actor:
            output += f"- **Threat Actor:** {threat_actor}\n"

        output += f"- **Objective:** {objective}\n"
        output += f"- **Risk Level:** {risk_level}\n"

        if executive_summary:
            output += f"\n{executive_summary[:500]}"
            if len(executive_summary) > 500:
                output += "..."
            output += "\n"

        output += "\n"

    if len(scenarios) > 3:
        output += f"*... and {len(scenarios) - 3} more scenarios.*\n\n"

    return output


def group_findings_by_category(ctx: Context) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group findings by category from context.

    Args:
        ctx: Pipeline context

    Returns:
        Dictionary mapping category names to finding lists
    """
    categories = {
        "Security Risks": [],
        "Technical Findings": [],
        "Configuration Issues": [],
        "Information Disclosure": [],
        "Other": [],
    }

    # Get risks
    risks = ctx.get("risks", [])
    for risk in risks:
        categories["Security Risks"].append(risk)

    # Get findings from various keys
    for key, value in ctx.data.items():
        if key.startswith("finding_"):
            if isinstance(value, dict):
                category = value.get("category", "Technical Findings")
                if category in categories:
                    categories[category].append(value)
                else:
                    categories["Technical Findings"].append(value)

    # Filter out empty categories
    return {k: v for k, v in categories.items() if v}


def generate_full_report(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Generate a comprehensive full report with all sections.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_dir', 'include_mitre',
                'include_risks', 'include_paths', 'include_scenarios'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Generating full comprehensive report", level="INFO")

    # Build sections based on params
    include_mitre = params.get("include_mitre", True)
    include_risks = params.get("include_risks", True)
    include_paths = params.get("include_paths", True)
    include_scenarios = params.get("include_scenarios", True)

    target = ctx.target or "N/A"
    pipeline = ctx.get("pipeline_name", "Unknown")

    report = f"""# RedOps Comprehensive Security Assessment

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
**Target:** {target}
**Pipeline:** {pipeline}

---

## Table of Contents

1. [Executive Summary](#executive-summary)
"""

    section_num = 2
    if include_mitre and (ctx.get("mitre_mapping") or ctx.get("mitre_techniques_used")):
        report += f"{section_num}. [MITRE ATT&CK Coverage](#mitre-attck-coverage)\n"
        section_num += 1
    if include_risks and ctx.get("risks"):
        report += f"{section_num}. [Risk Analysis](#risk-analysis)\n"
        section_num += 1
    if include_paths and ctx.get("attack_paths"):
        report += f"{section_num}. [Attack Paths](#attack-paths)\n"
        section_num += 1
    if include_scenarios and ctx.get("scenarios"):
        report += f"{section_num}. [Threat Scenarios](#threat-scenarios)\n"
        section_num += 1
    report += f"{section_num}. [Recommendations](#recommendations)\n"
    report += f"{section_num + 1}. [Technical Details](#technical-details)\n"

    report += "\n---\n\n"

    # Executive Summary
    report += "## Executive Summary\n\n"
    report += build_executive_summary(ctx)
    report += "\n---\n\n"

    # MITRE ATT&CK Section
    if include_mitre and (ctx.get("mitre_mapping") or ctx.get("mitre_techniques_used")):
        report += "## MITRE ATT&CK Coverage\n\n"
        report += build_mitre_matrix_markdown(ctx)
        report += "\n---\n\n"

    # Risk Analysis Section
    if include_risks and ctx.get("risks"):
        report += "## Risk Analysis\n\n"
        report += build_risk_heatmap_markdown(ctx.get("risks", []))
        report += "\n---\n\n"

    # Attack Paths Section
    if include_paths and ctx.get("attack_paths"):
        report += "## Attack Paths\n\n"
        report += build_attack_paths_markdown(ctx.get("attack_paths", []))
        report += "\n---\n\n"

    # Threat Scenarios Section
    if include_scenarios and ctx.get("scenarios"):
        report += "## Threat Scenarios\n\n"
        report += build_scenarios_markdown(ctx.get("scenarios", []))
        report += "\n---\n\n"

    # Recommendations
    report += "## Recommendations\n\n"
    report += build_recommendations_section(ctx)
    report += "\n---\n\n"

    # Technical Details
    report += "## Technical Details\n\n"
    report += build_technical_details_section(ctx)

    # Save to file
    output_path = (
        output_dir / f"full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    with open(output_path, "w") as f:
        f.write(report)

    ctx.add("full_report_path", str(output_path))
    ctx.add("full_report_content", report)
    ctx.log(f"Full report saved to {output_path}", level="INFO")

    return ctx


def build_recommendations_section(ctx: Context) -> str:
    """
    Build recommendations section based on findings.

    Args:
        ctx: Pipeline context

    Returns:
        Markdown string with recommendations
    """
    output = "### Priority Actions\n\n"

    recommendations = []

    # Check for critical risks
    risks = ctx.get("risks", [])
    critical_risks = [r for r in risks if r.get("level", "").lower() == "critical"]
    high_risks = [r for r in risks if r.get("level", "").lower() == "high"]

    if critical_risks:
        recommendations.append(
            {
                "priority": "CRITICAL",
                "action": f"Address {len(critical_risks)} critical risk(s) immediately",
                "description": "Critical risks pose immediate threat to security posture",
            }
        )

    if high_risks:
        recommendations.append(
            {
                "priority": "HIGH",
                "action": f"Remediate {len(high_risks)} high-severity finding(s)",
                "description": "High-severity issues should be addressed within 30 days",
            }
        )

    # Check for attack paths
    attack_paths = ctx.get("attack_paths", [])
    if attack_paths:
        recommendations.append(
            {
                "priority": "HIGH",
                "action": "Review and mitigate identified attack paths",
                "description": f"{len(attack_paths)} potential attack paths identified",
            }
        )

    # Check detection recommendations
    detection_recs = ctx.get("detection_recommendations", [])
    if detection_recs:
        recommendations.append(
            {
                "priority": "MEDIUM",
                "action": "Implement recommended detection capabilities",
                "description": "Enhance monitoring based on identified techniques",
            }
        )

    # Default recommendations
    if not recommendations:
        recommendations = [
            {
                "priority": "MEDIUM",
                "action": "Conduct regular security assessments",
                "description": "",
            },
            {
                "priority": "LOW",
                "action": "Maintain security awareness training",
                "description": "",
            },
        ]

    # Output recommendations
    for i, rec in enumerate(recommendations, 1):
        priority = rec["priority"]
        indicator = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            priority, "⚪"
        )
        output += f"{i}. {indicator} **[{priority}]** {rec['action']}\n"
        if rec.get("description"):
            output += f"   - {rec['description']}\n"

    return output


def build_technical_details_section(ctx: Context) -> str:
    """
    Build technical details section with raw data.

    Args:
        ctx: Pipeline context

    Returns:
        Markdown string with technical details
    """
    output = "### Data Summary\n\n"

    # List all data keys
    output += "| Data Key | Type | Size |\n"
    output += "|----------|------|------|\n"

    for key, value in ctx.data.items():
        if key.startswith("_"):
            continue
        value_type = type(value).__name__
        if isinstance(value, (list, dict)):
            size = len(value)
        elif isinstance(value, str):
            size = f"{len(value)} chars"
        else:
            size = "-"
        output += f"| {key} | {value_type} | {size} |\n"

    return output
