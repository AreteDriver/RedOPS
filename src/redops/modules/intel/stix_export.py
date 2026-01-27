"""
STIX/TAXII Export Module for RedOPS.

Exports threat intelligence findings to STIX 2.1 format for sharing
via TAXII servers or integration with threat intel platforms.

STIX (Structured Threat Information Expression) is a standardized
language for representing cyber threat intelligence.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


# STIX 2.1 Object Types
STIX_VERSION = "2.1"


def generate_stix_id(object_type: str) -> str:
    """Generate a STIX identifier."""
    return f"{object_type}--{uuid.uuid4()}"


def stix_timestamp() -> str:
    """Generate a STIX-compliant timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class STIXObject:
    """Base STIX Domain Object."""

    type: str
    id: str = field(default_factory=lambda: "")
    spec_version: str = STIX_VERSION
    created: str = field(default_factory=stix_timestamp)
    modified: str = field(default_factory=stix_timestamp)

    def __post_init__(self):
        if not self.id:
            self.id = generate_stix_id(self.type)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, removing None values."""
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class Indicator(STIXObject):
    """STIX Indicator object."""

    type: str = "indicator"
    name: str = ""
    description: str = ""
    pattern: str = ""
    pattern_type: str = "stix"
    valid_from: str = field(default_factory=stix_timestamp)
    indicator_types: List[str] = field(default_factory=list)
    kill_chain_phases: List[Dict[str, str]] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    confidence: Optional[int] = None


@dataclass
class ThreatActor(STIXObject):
    """STIX Threat Actor object."""

    type: str = "threat-actor"
    name: str = ""
    description: str = ""
    threat_actor_types: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    goals: List[str] = field(default_factory=list)
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    primary_motivation: Optional[str] = None


@dataclass
class AttackPattern(STIXObject):
    """STIX Attack Pattern object (MITRE ATT&CK)."""

    type: str = "attack-pattern"
    name: str = ""
    description: str = ""
    external_references: List[Dict[str, str]] = field(default_factory=list)
    kill_chain_phases: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class Vulnerability(STIXObject):
    """STIX Vulnerability object."""

    type: str = "vulnerability"
    name: str = ""
    description: str = ""
    external_references: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class Infrastructure(STIXObject):
    """STIX Infrastructure object."""

    type: str = "infrastructure"
    name: str = ""
    description: str = ""
    infrastructure_types: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)


@dataclass
class Relationship(STIXObject):
    """STIX Relationship object."""

    type: str = "relationship"
    relationship_type: str = ""
    source_ref: str = ""
    target_ref: str = ""
    description: str = ""


@dataclass
class Bundle:
    """STIX Bundle container."""

    type: str = "bundle"
    id: str = field(default_factory=lambda: generate_stix_id("bundle"))
    objects: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, obj: STIXObject):
        """Add a STIX object to the bundle."""
        self.objects.append(obj.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        """Convert bundle to dictionary."""
        return {
            "type": self.type,
            "id": self.id,
            "objects": self.objects,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert bundle to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class STIXExporter:
    """Export RedOPS findings to STIX 2.1 format."""

    def __init__(self, identity_name: str = "RedOPS Security Scanner"):
        """Initialize the STIX exporter."""
        self.identity_name = identity_name
        self.identity_id = generate_stix_id("identity")

    def export(self, scan_data: Dict[str, Any]) -> Bundle:
        """
        Export scan data to STIX bundle.

        Args:
            scan_data: Dictionary containing scan results

        Returns:
            STIX Bundle containing all threat intelligence
        """
        bundle = Bundle()

        # Add identity for the scanner
        identity = self._create_identity()
        bundle.add(identity)

        # Export IOCs as indicators
        iocs = scan_data.get("threat_intel", {}).get("iocs", [])
        for ioc in iocs:
            indicator = self._ioc_to_indicator(ioc)
            if indicator:
                bundle.add(indicator)

        # Export vulnerabilities
        findings = scan_data.get("findings", [])
        for finding in findings:
            if "cve" in finding.get("title", "").lower() or finding.get("cve"):
                vuln = self._finding_to_vulnerability(finding)
                bundle.add(vuln)

        # Export attack patterns from MITRE mappings
        mitre_techniques = scan_data.get("threat_intel", {}).get("mitre_techniques", [])
        for technique in mitre_techniques:
            attack_pattern = self._technique_to_attack_pattern(technique)
            bundle.add(attack_pattern)

        # Export infrastructure from scan
        infra_data = scan_data.get("infrastructure", {})
        if infra_data:
            infra = self._create_infrastructure(
                scan_data.get("target", "Unknown"), infra_data
            )
            bundle.add(infra)

        # Export exposures as indicators
        exposures = scan_data.get("exposure_scan", {}).get("exposures", [])
        for exposure in exposures:
            indicator = self._exposure_to_indicator(exposure)
            if indicator:
                bundle.add(indicator)

        return bundle

    def _create_identity(self) -> STIXObject:
        """Create identity object for the scanner."""
        return STIXObject(
            type="identity",
            id=self.identity_id,
        )

    def _ioc_to_indicator(self, ioc: Dict[str, Any]) -> Optional[Indicator]:
        """Convert IOC to STIX Indicator."""
        ioc_type = ioc.get("type", "").lower()
        value = ioc.get("value", "")

        if not value:
            return None

        # Build STIX pattern based on IOC type
        if ioc_type == "ip" or ioc_type == "ipv4-addr":
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "ipv6-addr":
            pattern = f"[ipv6-addr:value = '{value}']"
        elif ioc_type == "domain" or ioc_type == "domain-name":
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
        elif ioc_type == "hash" or ioc_type == "file-hash":
            # Detect hash type
            if len(value) == 32:
                pattern = f"[file:hashes.MD5 = '{value}']"
            elif len(value) == 40:
                pattern = f"[file:hashes.'SHA-1' = '{value}']"
            elif len(value) == 64:
                pattern = f"[file:hashes.'SHA-256' = '{value}']"
            else:
                pattern = f"[file:hashes.'SHA-256' = '{value}']"
        elif ioc_type == "email":
            pattern = f"[email-addr:value = '{value}']"
        else:
            # Generic pattern
            pattern = f"[artifact:payload_bin = '{value}']"

        return Indicator(
            name=ioc.get("name", f"IOC: {value[:50]}"),
            description=ioc.get("description", f"Indicator of Compromise: {ioc_type}"),
            pattern=pattern,
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            confidence=ioc.get("confidence", 50),
            labels=ioc.get("tags", []),
        )

    def _finding_to_vulnerability(self, finding: Dict[str, Any]) -> Vulnerability:
        """Convert finding to STIX Vulnerability."""
        cve = finding.get("cve", "")
        external_refs = []

        if cve:
            external_refs.append(
                {
                    "source_name": "cve",
                    "external_id": cve,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                }
            )

        return Vulnerability(
            name=finding.get("title", "Unknown Vulnerability"),
            description=finding.get("description", ""),
            external_references=external_refs,
        )

    def _technique_to_attack_pattern(self, technique: Dict[str, Any]) -> AttackPattern:
        """Convert MITRE technique to STIX Attack Pattern."""
        technique_id = technique.get("technique_id", "")
        external_refs = []

        if technique_id:
            external_refs.append(
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            )

        kill_chain = []
        tactic = technique.get("tactic", "")
        if tactic:
            kill_chain.append(
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": tactic.lower().replace(" ", "-"),
                }
            )

        return AttackPattern(
            name=technique.get("name", technique_id),
            description=technique.get("description", ""),
            external_references=external_refs,
            kill_chain_phases=kill_chain,
        )

    def _create_infrastructure(
        self, target: str, infra_data: Dict[str, Any]
    ) -> Infrastructure:
        """Create infrastructure object from scan data."""
        infra_types = []

        if infra_data.get("cloud_provider"):
            infra_types.append("hosting")
        if infra_data.get("cdn"):
            infra_types.append("amplification")

        return Infrastructure(
            name=f"Infrastructure: {target}",
            description=f"Target infrastructure for {target}",
            infrastructure_types=infra_types or ["unknown"],
        )

    def _exposure_to_indicator(self, exposure: Dict[str, Any]) -> Optional[Indicator]:
        """Convert exposure finding to STIX Indicator."""
        exp_type = exposure.get("type", "").lower()
        value = exposure.get("value", exposure.get("description", ""))

        if not value:
            return None

        # Map exposure type to pattern
        if "port" in exp_type:
            pattern = f"[network-traffic:dst_port = {value}]"
        elif "domain" in exp_type:
            pattern = f"[domain-name:value = '{value}']"
        elif "email" in exp_type:
            pattern = f"[email-addr:value = '{value}']"
        else:
            # Generic indicator
            return None

        severity = exposure.get("severity", "medium")
        indicator_types = [
            "compromised" if severity in ("critical", "high") else "anomalous-activity"
        ]

        return Indicator(
            name=exposure.get("title", f"Exposure: {exp_type}"),
            description=exposure.get("description", str(value)),
            pattern=pattern,
            pattern_type="stix",
            indicator_types=indicator_types,
        )


def export_to_stix(ctx, params: Optional[Dict[str, Any]] = None):
    """Pipeline module to export findings to STIX format."""
    params = params or {}

    try:
        exporter = STIXExporter(
            identity_name=params.get("identity_name", "RedOPS Security Scanner")
        )

        bundle = exporter.export(ctx.data)

        # Save to file if output path specified
        output_path = params.get("output_path")
        if output_path:
            with open(output_path, "w") as f:
                f.write(bundle.to_json())
            ctx.add("stix_export_path", output_path)
            ctx.log(f"STIX bundle exported to: {output_path}", level="INFO")

        # Add bundle to context
        ctx.add("stix_bundle", bundle.to_dict())
        ctx.log(f"STIX bundle created with {len(bundle.objects)} objects", level="INFO")

    except Exception as e:
        ctx.log(f"STIX export failed: {e}", level="ERROR")

    return ctx
