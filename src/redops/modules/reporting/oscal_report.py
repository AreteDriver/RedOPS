"""
OSCAL (Open Security Controls Assessment Language) report generation.

Exports assessment results in OSCAL format, the NIST standard for
security controls, assessments, and compliance documentation.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime, timezone
import json
import uuid
from redops.core.context import Context


# OSCAL Schema version
OSCAL_VERSION = "1.0.4"


def export_oscal(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Export findings as an OSCAL Assessment Results document.

    OSCAL is the NIST standard for expressing security controls,
    assessments, and compliance information in a machine-readable format.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - output_dir: Directory for output (default: ./output)
            - output_name: Output filename (auto-generated if not specified)
            - organization_name: Name of the assessing organization
            - system_name: Name of the assessed system
            - assessment_title: Title of the assessment

    Returns:
        Updated context with oscal_export_path
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    organization_name = params.get("organization_name", "Security Assessment Team")
    system_name = params.get("system_name", ctx.target or "Target System")
    assessment_title = params.get("assessment_title", "Security Assessment Results")

    ctx.log("Generating OSCAL Assessment Results", level="INFO")

    # Build OSCAL document
    oscal_doc = create_oscal_assessment_results(
        ctx,
        organization_name=organization_name,
        system_name=system_name,
        assessment_title=assessment_title,
    )

    # Determine output path
    output_name = params.get(
        "output_name", f"oscal_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    output_path = output_dir / output_name

    # Write OSCAL file
    with open(output_path, "w") as f:
        json.dump(oscal_doc, f, indent=2)

    # Calculate stats
    results = oscal_doc.get("assessment-results", {}).get("results", [])
    findings_count = sum(len(r.get("findings", [])) for r in results)
    observations_count = sum(len(r.get("observations", [])) for r in results)

    ctx.add("oscal_export_path", str(output_path))
    ctx.add("oscal_findings_count", findings_count)
    ctx.add("oscal_observations_count", observations_count)

    ctx.log(
        f"OSCAL report saved to {output_path} "
        f"({findings_count} findings, {observations_count} observations)",
        level="INFO",
    )

    return ctx


def create_oscal_assessment_results(
    ctx: Context,
    organization_name: str = "Security Assessment Team",
    system_name: str = "Target System",
    assessment_title: str = "Security Assessment Results",
) -> Dict[str, Any]:
    """
    Create an OSCAL Assessment Results document.

    Args:
        ctx: Pipeline context
        organization_name: Assessing organization name
        system_name: Name of the system being assessed
        assessment_title: Title of the assessment

    Returns:
        OSCAL Assessment Results document
    """
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Generate UUIDs
    doc_uuid = str(uuid.uuid4())
    result_uuid = str(uuid.uuid4())

    # Collect findings
    findings = collect_findings(ctx)

    # Build OSCAL document
    oscal_doc = {
        "assessment-results": {
            "uuid": doc_uuid,
            "metadata": create_metadata(
                assessment_title,
                organization_name,
                now_str,
            ),
            "import-ap": {"href": "#assessment-plan"},
            "local-definitions": create_local_definitions(ctx, system_name),
            "results": [
                create_result(
                    result_uuid,
                    findings,
                    ctx,
                    now_str,
                )
            ],
        }
    }

    return oscal_doc


def create_metadata(
    title: str,
    organization: str,
    timestamp: str,
) -> Dict[str, Any]:
    """Create OSCAL metadata section."""
    return {
        "title": title,
        "last-modified": timestamp,
        "version": "1.0",
        "oscal-version": OSCAL_VERSION,
        "roles": [
            {
                "id": "assessor",
                "title": "Security Assessor",
            },
            {
                "id": "tool",
                "title": "Assessment Tool",
            },
        ],
        "parties": [
            {
                "uuid": str(uuid.uuid4()),
                "type": "organization",
                "name": organization,
            },
            {
                "uuid": str(uuid.uuid4()),
                "type": "tool",
                "name": "RedOps Security Framework",
            },
        ],
    }


def create_local_definitions(ctx: Context, system_name: str) -> Dict[str, Any]:
    """Create local definitions section."""
    definitions: Dict[str, Any] = {
        "components": [
            {
                "uuid": str(uuid.uuid4()),
                "type": "system",
                "title": system_name,
                "description": f"Target system for assessment: {ctx.target or 'N/A'}",
                "status": {"state": "operational"},
            }
        ],
        "inventory-items": [],
        "users": [],
    }

    # Add inventory items from discovered assets
    subdomains = ctx.get("subdomains", []) or ctx.get("ct_subdomains", [])
    for i, subdomain in enumerate(subdomains[:50]):  # Limit to 50
        definitions["inventory-items"].append(
            {
                "uuid": str(uuid.uuid4()),
                "description": f"Discovered subdomain: {subdomain}",
                "props": [
                    {"name": "asset-type", "value": "hostname"},
                    {"name": "fqdn", "value": subdomain},
                ],
            }
        )

    return definitions


def create_result(
    result_uuid: str,
    findings: List[Dict[str, Any]],
    ctx: Context,
    timestamp: str,
) -> Dict[str, Any]:
    """Create an assessment result."""
    result = {
        "uuid": result_uuid,
        "title": f"Assessment Results - {ctx.target or 'Target'}",
        "description": "Automated security assessment results",
        "start": timestamp,
        "end": timestamp,
        "local-definitions": {
            "assessment-assets": create_assessment_assets(),
        },
        "attestations": [
            {
                "responsible-parties": [{"role-id": "tool", "party-uuids": []}],
            }
        ],
        "observations": [],
        "findings": [],
    }

    # Convert findings to OSCAL observations and findings
    for finding in findings:
        observation = create_observation(finding, timestamp)
        oscal_finding = create_finding(finding, observation["uuid"], timestamp)

        result["observations"].append(observation)
        result["findings"].append(oscal_finding)

    return result


def create_assessment_assets() -> Dict[str, Any]:
    """Create assessment assets section."""
    return {
        "components": [
            {
                "uuid": str(uuid.uuid4()),
                "type": "software",
                "title": "RedOps Security Framework",
                "description": "Automated security assessment tool",
                "status": {"state": "operational"},
            }
        ],
        "assessment-platforms": [
            {
                "uuid": str(uuid.uuid4()),
                "title": "RedOps Platform",
                "uses-components": [],
            }
        ],
    }


def create_observation(
    finding: Dict[str, Any],
    timestamp: str,
) -> Dict[str, Any]:
    """
    Create an OSCAL observation from a finding.

    Observations are factual statements about what was observed.
    """
    observation_uuid = str(uuid.uuid4())
    title = finding.get("title", "Unknown Finding")
    description = finding.get("description", "")
    module = finding.get("module", "unknown")
    severity = normalize_severity(finding.get("severity", "medium"))
    data = finding.get("data", {})

    observation = {
        "uuid": observation_uuid,
        "title": title,
        "description": description,
        "methods": ["AUTOMATED"],
        "types": ["finding"],
        "collected": timestamp,
        "props": [
            {
                "name": "module",
                "value": module,
            },
            {
                "name": "severity",
                "value": severity,
            },
        ],
    }

    # Add subjects from data
    subjects = []
    if data.get("url"):
        subjects.append(
            {
                "subject-uuid": str(uuid.uuid4()),
                "type": "resource",
                "title": str(data["url"]),
            }
        )
    if data.get("ip"):
        subjects.append(
            {
                "subject-uuid": str(uuid.uuid4()),
                "type": "inventory-item",
                "title": str(data["ip"]),
            }
        )
    if data.get("domain") or data.get("host"):
        subjects.append(
            {
                "subject-uuid": str(uuid.uuid4()),
                "type": "inventory-item",
                "title": str(data.get("domain") or data.get("host")),
            }
        )

    if subjects:
        observation["subjects"] = subjects

    # Add relevant evidence as remarks
    if data:
        evidence_parts = []
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                evidence_parts.append(f"{key}: {value}")
            elif isinstance(value, list):
                evidence_parts.append(f"{key}: {len(value)} items")

        if evidence_parts:
            observation["remarks"] = "\n".join(evidence_parts)

    return observation


def create_finding(
    finding_data: Dict[str, Any],
    observation_uuid: str,
    timestamp: str,
) -> Dict[str, Any]:
    """
    Create an OSCAL finding from a finding.

    Findings are conclusions or determinations based on observations.
    """
    finding_uuid = str(uuid.uuid4())
    title = finding_data.get("title", "Unknown Finding")
    description = finding_data.get("description", "")
    severity = normalize_severity(finding_data.get("severity", "medium"))

    # Map severity to OSCAL state
    state = severity_to_state(severity)

    finding = {
        "uuid": finding_uuid,
        "title": title,
        "description": description,
        "target": {
            "type": "objective-id",
            "target-id": f"objective-{finding_uuid[:8]}",
            "status": {
                "state": state,
            },
        },
        "related-observations": [
            {
                "observation-uuid": observation_uuid,
            }
        ],
    }

    # Add implementation status based on severity
    if severity in ("critical", "high"):
        finding["implementation-statement-uuid"] = str(uuid.uuid4())

    return finding


def collect_findings(ctx: Context) -> List[Dict[str, Any]]:
    """Collect all findings from context."""
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


def normalize_severity(severity: Any) -> str:
    """Normalize severity to lowercase string."""
    if isinstance(severity, str):
        return severity.lower()
    elif hasattr(severity, "name"):
        return severity.name.lower()
    elif hasattr(severity, "value"):
        return str(severity.value).lower()
    return str(severity).lower()


def severity_to_state(severity: str) -> str:
    """Map severity to OSCAL objective status state."""
    state_map = {
        "critical": "not-satisfied",
        "high": "not-satisfied",
        "medium": "partially-satisfied",
        "low": "satisfied",
        "info": "satisfied",
        "informational": "satisfied",
    }
    return state_map.get(severity, "partially-satisfied")


def get_oscal_summary(ctx: Context) -> Dict[str, Any]:
    """
    Get a summary of OSCAL export results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    return {
        "export_path": ctx.get("oscal_export_path", ""),
        "findings_count": ctx.get("oscal_findings_count", 0),
        "observations_count": ctx.get("oscal_observations_count", 0),
    }


def export_oscal_catalog(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Export a basic OSCAL Catalog of security controls.

    This creates a catalog document that defines the controls
    being assessed.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Generating OSCAL Catalog", level="INFO")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    catalog = {
        "catalog": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": "RedOps Security Controls Catalog",
                "last-modified": now,
                "version": "1.0",
                "oscal-version": OSCAL_VERSION,
            },
            "groups": [
                {
                    "id": "recon",
                    "title": "Reconnaissance Controls",
                    "controls": [
                        {
                            "id": "recon-1",
                            "title": "Certificate Transparency Monitoring",
                            "props": [{"name": "label", "value": "RECON-1"}],
                        },
                        {
                            "id": "recon-2",
                            "title": "Subdomain Enumeration",
                            "props": [{"name": "label", "value": "RECON-2"}],
                        },
                        {
                            "id": "recon-3",
                            "title": "ASN Analysis",
                            "props": [{"name": "label", "value": "RECON-3"}],
                        },
                    ],
                },
                {
                    "id": "threat-intel",
                    "title": "Threat Intelligence Controls",
                    "controls": [
                        {
                            "id": "ti-1",
                            "title": "IP Reputation Checking",
                            "props": [{"name": "label", "value": "TI-1"}],
                        },
                        {
                            "id": "ti-2",
                            "title": "Malicious URL Detection",
                            "props": [{"name": "label", "value": "TI-2"}],
                        },
                    ],
                },
            ],
        }
    }

    output_name = params.get(
        "output_name", f"oscal_catalog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    output_path = output_dir / output_name

    with open(output_path, "w") as f:
        json.dump(catalog, f, indent=2)

    ctx.add("oscal_catalog_path", str(output_path))
    ctx.log(f"OSCAL catalog saved to {output_path}", level="INFO")

    return ctx
