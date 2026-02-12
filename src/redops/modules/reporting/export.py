"""
Export utilities for RedOps.

Handles exporting data in various formats (JSON, CSV, STIX 2.1, etc.).
"""

from typing import Any
from pathlib import Path
import json
import csv
import uuid
from datetime import datetime, timezone
from redops.core.context import Context


# STIX 2.1 type mappings
STIX_ATTACK_PATTERN_TEMPLATE = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "",
    "created": "",
    "modified": "",
    "name": "",
    "description": "",
    "external_references": [],
}

STIX_INDICATOR_TEMPLATE = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "",
    "created": "",
    "modified": "",
    "name": "",
    "description": "",
    "pattern": "",
    "pattern_type": "stix",
    "valid_from": "",
}

STIX_VULNERABILITY_TEMPLATE = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "",
    "created": "",
    "modified": "",
    "name": "",
    "description": "",
    "external_references": [],
}


def export_json(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export context data as JSON.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Exporting data as JSON", level="INFO")

    # Export full context
    output_path = output_dir / f"data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(output_path, "w") as f:
        json.dump(ctx.to_dict(), f, indent=2, default=str)

    ctx.add("json_export_path", str(output_path))
    ctx.log(f"JSON export saved to {output_path}", level="INFO")

    return ctx


def export_csv(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export findings/risks as CSV.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path' and 'data_key'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    data_key = params.get("data_key", "risks")

    ctx.log(f"Exporting {data_key} as CSV", level="INFO")

    data = ctx.get(data_key, [])

    if not data:
        ctx.log(f"No data found for key: {data_key}", level="WARNING")
        return ctx

    output_path = (
        output_dir / f"{data_key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

    # Write CSV
    if isinstance(data, list) and len(data) > 0:
        if isinstance(data[0], dict):
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        else:
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([data_key])
                for item in data:
                    writer.writerow([item])

    ctx.add(f"{data_key}_csv_path", str(output_path))
    ctx.log(f"CSV export saved to {output_path}", level="INFO")

    return ctx


def export_all(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export all data in multiple formats.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}
    ctx.log("Exporting all data", level="INFO")

    # Export JSON
    ctx = export_json(ctx, params)

    # Export risks as CSV if present
    if ctx.get("risks"):
        ctx = export_csv(ctx, {**params, "data_key": "risks"})

    # Export STIX if MITRE techniques present
    if ctx.get("mitre_techniques_used") or ctx.get("mitre_mapping"):
        ctx = export_stix(ctx, params)

    ctx.log("All exports completed", level="INFO")

    return ctx


def export_stix(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export findings and techniques as STIX 2.1 bundle.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Exporting data as STIX 2.1", level="INFO")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    stix_objects = []

    # Add identity for the tool
    tool_identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": "RedOps Security Framework",
        "identity_class": "system",
    }
    stix_objects.append(tool_identity)

    # Convert MITRE techniques to attack patterns
    mitre_mapping = ctx.get("mitre_mapping", {})
    for technique_id, technique_info in mitre_mapping.items():
        attack_pattern = create_stix_attack_pattern(technique_id, technique_info, now)
        stix_objects.append(attack_pattern)

    # Convert risks to vulnerabilities
    risks = ctx.get("risks", [])
    for risk in risks:
        vulnerability = create_stix_vulnerability(risk, now)
        stix_objects.append(vulnerability)

    # Convert findings to indicators
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            indicator = create_stix_indicator(value, now)
            if indicator:
                stix_objects.append(indicator)

    # Create STIX bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects,
    }

    # Save to file
    output_path = (
        output_dir / f"stix_bundle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=2)

    ctx.add("stix_export_path", str(output_path))
    ctx.add("stix_object_count", len(stix_objects))
    ctx.log(
        f"STIX bundle saved to {output_path} ({len(stix_objects)} objects)",
        level="INFO",
    )

    return ctx


def create_stix_attack_pattern(
    technique_id: str, technique_info: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    """
    Create a STIX attack-pattern from MITRE technique.

    Args:
        technique_id: MITRE technique ID
        technique_info: Technique information
        timestamp: ISO timestamp

    Returns:
        STIX attack-pattern object
    """
    if isinstance(technique_info, dict):
        name = technique_info.get("name", technique_id)
        description = technique_info.get("description", "")
        tactic = technique_info.get("tactic", "")
    else:
        name = technique_id
        description = ""
        tactic = ""

    external_refs = [
        {
            "source_name": "mitre-attack",
            "external_id": technique_id,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
        }
    ]

    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": f"attack-pattern--{uuid.uuid4()}",
        "created": timestamp,
        "modified": timestamp,
        "name": name,
        "description": f"{description}\n\nTactic: {tactic}" if tactic else description,
        "external_references": external_refs,
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": tactic.lower().replace(" ", "-") if tactic else "unknown",
            }
        ]
        if tactic
        else [],
    }


def create_stix_vulnerability(risk: dict[str, Any], timestamp: str) -> dict[str, Any]:
    """
    Create a STIX vulnerability from risk.

    Args:
        risk: Risk dictionary
        timestamp: ISO timestamp

    Returns:
        STIX vulnerability object
    """
    title = risk.get("title", "Unknown Risk")
    description = risk.get("description", "")
    level = risk.get("level", "medium")

    external_refs = []
    if risk.get("cve"):
        external_refs.append(
            {
                "source_name": "cve",
                "external_id": risk["cve"],
            }
        )

    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": timestamp,
        "modified": timestamp,
        "name": title,
        "description": f"{description}\n\nSeverity: {level.upper()}",
        "external_references": external_refs,
    }


def create_stix_indicator(
    finding: dict[str, Any], timestamp: str
) -> dict[str, Any] | None:
    """
    Create a STIX indicator from finding.

    Args:
        finding: Finding dictionary
        timestamp: ISO timestamp

    Returns:
        STIX indicator object or None
    """
    title = finding.get("title", "")
    description = finding.get("description", "")

    if not title:
        return None

    # Create a simple pattern based on the finding
    pattern = f"[x-redops:finding = '{title}']"

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": timestamp,
        "modified": timestamp,
        "name": title,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "indicator_types": ["anomalous-activity"],
    }


def export_from_template(
    ctx: Context, template: str, params: dict[str, Any] | None = None
) -> Context:
    """
    Export using a custom template.

    Templates can use {variable} placeholders that will be filled
    from context data.

    Args:
        ctx: Pipeline context
        template: Template string with {placeholders}
        params: Optional parameters including 'output_path'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Exporting from template", level="INFO")

    # Build template variables
    variables = {
        "target": ctx.target or "N/A",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "date": datetime.now().strftime("%Y-%m-%d"),
    }

    # Add all context data
    for key, value in ctx.data.items():
        if isinstance(value, (str, int, float, bool)):
            variables[key] = value
        elif isinstance(value, list):
            variables[f"{key}_count"] = len(value)
            variables[f"{key}_list"] = ", ".join(str(v) for v in value[:10])
        elif isinstance(value, dict):
            variables[f"{key}_count"] = len(value)

    # Count risks by severity
    risks = ctx.get("risks", [])
    variables["total_risks"] = len(risks)
    variables["critical_risks"] = sum(
        1 for r in risks if r.get("level", "").lower() == "critical"
    )
    variables["high_risks"] = sum(
        1 for r in risks if r.get("level", "").lower() == "high"
    )
    variables["medium_risks"] = sum(
        1 for r in risks if r.get("level", "").lower() == "medium"
    )
    variables["low_risks"] = sum(
        1 for r in risks if r.get("level", "").lower() == "low"
    )

    # Attack paths
    attack_paths = ctx.get("attack_paths", [])
    variables["attack_paths_count"] = len(attack_paths)

    # MITRE techniques
    mitre_techniques = ctx.get("mitre_techniques_used", [])
    variables["mitre_techniques_count"] = len(mitre_techniques)
    variables["mitre_techniques_list"] = ", ".join(mitre_techniques[:10])

    # Fill template
    try:
        output = template.format(**variables)
    except KeyError as e:
        ctx.log(f"Template variable not found: {e}", level="WARNING")
        # Fill with placeholders for missing variables
        output = template
        for key in variables:
            output = output.replace(f"{{{key}}}", str(variables[key]))

    # Determine output filename
    output_name = params.get(
        "output_name", f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    output_path = output_dir / output_name

    with open(output_path, "w") as f:
        f.write(output)

    ctx.add("template_export_path", str(output_path))
    ctx.log(f"Template export saved to {output_path}", level="INFO")

    return ctx


# Built-in report templates
EXECUTIVE_BRIEF_TEMPLATE = """
SECURITY ASSESSMENT BRIEF
=========================
Target: {target}
Date: {date}

RISK SUMMARY
------------
Critical: {critical_risks}
High: {high_risks}
Medium: {medium_risks}
Low: {low_risks}
Total: {total_risks}

ATTACK SURFACE
--------------
Attack Paths Identified: {attack_paths_count}
MITRE Techniques Mapped: {mitre_techniques_count}

IMMEDIATE ACTIONS REQUIRED
--------------------------
1. Address all critical findings immediately
2. Review high-severity risks within 30 days
3. Implement monitoring for identified attack paths

Report generated by RedOps Security Framework
"""

TECHNICAL_SUMMARY_TEMPLATE = """
# Technical Security Assessment Summary

**Target:** {target}
**Assessment Date:** {timestamp}

## Findings Overview

| Severity | Count |
|----------|-------|
| Critical | {critical_risks} |
| High     | {high_risks} |
| Medium   | {medium_risks} |
| Low      | {low_risks} |

## Attack Surface Analysis

- **Attack Paths:** {attack_paths_count}
- **MITRE Techniques:** {mitre_techniques_count}

### Techniques Identified
{mitre_techniques_list}

---
*Generated by RedOps*
"""


def export_executive_brief(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Export a quick executive brief.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}
    params["output_name"] = (
        f"executive_brief_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    return export_from_template(ctx, EXECUTIVE_BRIEF_TEMPLATE, params)


def export_technical_summary(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Export a technical summary in markdown.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}
    params["output_name"] = (
        f"technical_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    return export_from_template(ctx, TECHNICAL_SUMMARY_TEMPLATE, params)
