"""
Markdown report generation module.

Generates executive summaries and technical reports in Markdown format.
"""

from typing import Optional, Dict, Any
from pathlib import Path
from datetime import datetime
from redops.core.context import Context


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

    report = f"""# RedOps Executive Summary

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Target:** {target}  
**Pipeline:** {pipeline}

---

## Overview

This report summarizes the findings from the RedOps security assessment.

## Key Findings

"""

    # Add findings summary
    risks = ctx.get("risks", [])
    if risks:
        report += f"- **Total Risks Identified:** {len(risks)}\n"

        # Count by severity
        critical = sum(1 for r in risks if r.get("level") == "critical")
        high = sum(1 for r in risks if r.get("level") == "high")
        medium = sum(1 for r in risks if r.get("level") == "medium")

        if critical > 0:
            report += f"- **Critical Risks:** {critical}\n"
        if high > 0:
            report += f"- **High Risks:** {high}\n"
        if medium > 0:
            report += f"- **Medium Risks:** {medium}\n"
    else:
        report += "No significant risks identified.\n"

    report += "\n## Attack Paths\n\n"

    attack_paths = ctx.get("attack_paths", [])
    if attack_paths:
        report += f"{len(attack_paths)} potential attack paths were identified.\n\n"
        for i, path in enumerate(attack_paths[:3], 1):
            name = path.get("name", f"Path {i}")
            report += f"{i}. **{name}**\n"
            report += f"   - Risk Score: {path.get('likelihood', 0) * path.get('impact', 0)}\n"
    else:
        report += "No attack paths identified.\n"

    report += "\n## Recommendations\n\n"
    report += "1. Review and address all identified risks\n"
    report += "2. Implement security controls for high-priority attack paths\n"
    report += "3. Conduct regular security assessments\n"
    report += "4. Maintain comprehensive security monitoring\n"

    report += "\n---\n\n"
    report += "*This report was generated automatically by RedOps.*\n"

    return report


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

## Detailed Findings

"""

    # Add all context data
    for key, value in ctx.data.items():
        if key not in ["pipeline_name", "pipeline_version"]:
            report += f"### {key.replace('_', ' ').title()}\n\n"
            report += f"```\n{str(value)[:500]}\n```\n\n"

    report += "\n## Logs\n\n"

    if ctx.get("include_logs", True):
        logs = ctx.get_logs()
        for log in logs[-20:]:  # Last 20 logs
            level = log.get("level", "INFO")
            message = log.get("message", "")
            report += f"- [{level}] {message}\n"

    return report
