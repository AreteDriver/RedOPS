"""
SARIF (Static Analysis Results Interchange Format) report generation.

Exports findings in SARIF format for integration with CI/CD pipelines
and security tools like GitHub Code Scanning, Azure DevOps, etc.
"""

from typing import Any
from pathlib import Path
from datetime import datetime, timezone
import json
import hashlib
from redops.core.context import Context


# SARIF spec version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def export_sarif(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export findings as a SARIF report.

    SARIF is the standard format for static analysis results,
    supported by GitHub, Azure DevOps, and many security tools.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - output_dir: Directory for output (default: ./output)
            - output_name: Output filename (auto-generated if not specified)
            - tool_name: Name of the tool (default: RedOps)
            - tool_version: Tool version (default: 1.0.0)
            - include_suppressed: Include suppressed findings (default: False)

    Returns:
        Updated context with sarif_export_path
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    tool_name = params.get("tool_name", "RedOps")
    tool_version = params.get("tool_version", "1.0.0")
    include_suppressed = params.get("include_suppressed", False)

    ctx.log("Generating SARIF report", level="INFO")

    # Build SARIF document
    sarif_doc = create_sarif_document(
        ctx,
        tool_name=tool_name,
        tool_version=tool_version,
        include_suppressed=include_suppressed,
    )

    # Determine output path
    output_name = params.get(
        "output_name",
        f"redops_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif",
    )
    output_path = output_dir / output_name

    # Write SARIF file
    with open(output_path, "w") as f:
        json.dump(sarif_doc, f, indent=2)

    # Get stats
    results_count = len(sarif_doc.get("runs", [{}])[0].get("results", []))
    rules_count = len(
        sarif_doc.get("runs", [{}])[0]
        .get("tool", {})
        .get("driver", {})
        .get("rules", [])
    )

    ctx.add("sarif_export_path", str(output_path))
    ctx.add("sarif_results_count", results_count)
    ctx.add("sarif_rules_count", rules_count)

    ctx.log(
        f"SARIF report saved to {output_path} ({results_count} results, {rules_count} rules)",
        level="INFO",
    )

    return ctx


def create_sarif_document(
    ctx: Context,
    tool_name: str = "RedOps",
    tool_version: str = "1.0.0",
    include_suppressed: bool = False,
) -> dict[str, Any]:
    """
    Create a complete SARIF document from context.

    Args:
        ctx: Pipeline context
        tool_name: Name of the analysis tool
        tool_version: Version of the tool
        include_suppressed: Include suppressed findings

    Returns:
        SARIF document dictionary
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Collect all findings from context
    findings = collect_findings(ctx)

    # Build rules from findings
    rules = build_rules(findings)

    # Build results from findings
    results = build_results(findings, rules)

    # Build the SARIF document
    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/redops/redops",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": now,
                    }
                ],
                "automationDetails": {
                    "id": f"{tool_name}/{ctx.target or 'unknown'}/{now}",
                    "description": {
                        "text": f"Security assessment of {ctx.target or 'target'}"
                    },
                },
            }
        ],
    }

    # Add target info as artifact
    if ctx.target:
        sarif_doc["runs"][0]["artifacts"] = [
            {
                "location": {
                    "uri": ctx.target,
                },
                "description": {"text": "Assessment target"},
            }
        ]

    return sarif_doc


def collect_findings(ctx: Context) -> list[dict[str, Any]]:
    """
    Collect all findings from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of finding dictionaries
    """
    findings = []

    # Get findings stored with finding_ prefix
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            findings.append(value)

    # Get risks if present
    risks = ctx.get("risks", [])
    for risk in risks:
        if isinstance(risk, dict):
            findings.append(
                {
                    "module": risk.get("module", "risk"),
                    "title": risk.get("title", "Unknown Risk"),
                    "description": risk.get("description", ""),
                    "severity": risk.get("level", "medium"),
                    "data": risk.get("data", {}),
                }
            )

    return findings


def build_rules(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Build SARIF rules from findings.

    Each unique finding type becomes a rule.

    Args:
        findings: List of findings

    Returns:
        Dictionary of rule_id -> rule
    """
    rules = {}

    for finding in findings:
        module = finding.get("module", "unknown")
        title = finding.get("title", "Unknown Finding")
        severity = finding.get("severity", "medium")

        # Create unique rule ID from module and title
        rule_id = create_rule_id(module, title)

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": sanitize_rule_name(title),
                "shortDescription": {
                    "text": title[:200] if len(title) > 200 else title
                },
                "fullDescription": {"text": finding.get("description", title)},
                "helpUri": f"https://docs.redops.io/rules/{rule_id}",
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(severity),
                },
                "properties": {
                    "tags": [module],
                    "security-severity": severity_to_score(severity),
                },
            }

    return rules


def build_results(
    findings: list[dict[str, Any]], rules: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Build SARIF results from findings.

    Args:
        findings: List of findings
        rules: Dictionary of rules

    Returns:
        List of SARIF result objects
    """
    results = []

    for finding in findings:
        module = finding.get("module", "unknown")
        title = finding.get("title", "Unknown Finding")
        description = finding.get("description", "")
        severity = finding.get("severity", "medium")
        data = finding.get("data", {})

        rule_id = create_rule_id(module, title)

        result = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(severity),
            "message": {
                "text": description or title,
            },
            "fingerprints": {
                "primary": create_fingerprint(finding),
            },
        }

        # Add location if available
        location = extract_location(data)
        if location:
            result["locations"] = [location]

        # Add related locations if multiple items
        related = extract_related_locations(data)
        if related:
            result["relatedLocations"] = related

        # Add properties for additional data
        if data:
            result["properties"] = {
                "data": data,
            }

        results.append(result)

    return results


def create_rule_id(module: str, title: str) -> str:
    """Create a unique rule ID from module and title."""
    # Create a deterministic short hash
    combined = f"{module}:{title}"
    hash_val = hashlib.md5(combined.encode()).hexdigest()[:8]
    module_prefix = module.replace(".", "-").replace("_", "-")[:20]
    return f"RO{hash_val.upper()}/{module_prefix}"


def sanitize_rule_name(title: str) -> str:
    """Sanitize title for use as rule name."""
    # Remove special characters and limit length
    name = "".join(c if c.isalnum() or c in " -_" else "" for c in title)
    return name[:100] if len(name) > 100 else name


def severity_to_sarif_level(severity: Any) -> str:
    """Convert severity to SARIF level."""
    if isinstance(severity, str):
        severity_str = severity.lower()
    elif hasattr(severity, "name"):
        severity_str = severity.name.lower()
    elif hasattr(severity, "value"):
        severity_str = str(severity.value).lower()
    else:
        severity_str = str(severity).lower()

    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
        "informational": "note",
    }

    return level_map.get(severity_str, "warning")


def severity_to_score(severity: Any) -> str:
    """Convert severity to CVSS-style score string."""
    if isinstance(severity, str):
        severity_str = severity.lower()
    elif hasattr(severity, "name"):
        severity_str = severity.name.lower()
    else:
        severity_str = str(severity).lower()

    score_map = {
        "critical": "9.0",
        "high": "7.0",
        "medium": "5.0",
        "low": "3.0",
        "info": "1.0",
        "informational": "1.0",
    }

    return score_map.get(severity_str, "5.0")


def create_fingerprint(finding: dict[str, Any]) -> str:
    """Create a unique fingerprint for deduplication."""
    key_data = f"{finding.get('module', '')}:{finding.get('title', '')}:{finding.get('description', '')}"
    return hashlib.sha256(key_data.encode()).hexdigest()


def extract_location(data: dict[str, Any]) -> dict[str, Any] | None:
    """Extract location information from finding data."""
    # Check for common location fields
    uri = (
        data.get("url")
        or data.get("uri")
        or data.get("host")
        or data.get("ip")
        or data.get("domain")
    )

    if uri:
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(uri),
                },
            },
        }

    return None


def extract_related_locations(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract related locations from finding data."""
    related = []

    # Check for lists of related items
    for key in ["subdomains", "urls", "hosts", "ips", "prefixes"]:
        items = data.get(key, [])
        for i, item in enumerate(items[:5]):  # Limit to 5 related locations
            if isinstance(item, str):
                related.append(
                    {
                        "id": i,
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": item,
                            },
                        },
                        "message": {
                            "text": f"Related {key[:-1] if key.endswith('s') else key}: {item}"
                        },
                    }
                )
            elif isinstance(item, dict):
                uri = (
                    item.get("prefix")
                    or item.get("url")
                    or item.get("host")
                    or str(item)
                )
                related.append(
                    {
                        "id": i,
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                            },
                        },
                    }
                )

    return related


def get_sarif_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of SARIF export results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    return {
        "export_path": ctx.get("sarif_export_path", ""),
        "results_count": ctx.get("sarif_results_count", 0),
        "rules_count": ctx.get("sarif_rules_count", 0),
    }
