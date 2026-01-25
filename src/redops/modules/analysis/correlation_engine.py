"""
Correlation Engine module.

Automatically correlates findings across different RedOPS modules to identify
relationships, patterns, and attack chains. Supports multiple correlation
strategies and confidence scoring.

Correlation Types:
- Temporal: Findings close in time may be related
- Entity: Findings sharing entities (IPs, domains, users)
- Attribute: Findings with similar attributes/characteristics
- Causal: Findings that may cause/enable other findings
- Pattern: Findings matching known attack patterns
"""

from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import re
import hashlib
from collections import defaultdict
from redops.core.context import Context


class CorrelationType(Enum):
    """Types of correlation between findings."""

    TEMPORAL = "temporal"
    ENTITY = "entity"
    ATTRIBUTE = "attribute"
    CAUSAL = "causal"
    PATTERN = "pattern"
    INFRASTRUCTURE = "infrastructure"
    BEHAVIORAL = "behavioral"


class CorrelationStrength(Enum):
    """Strength of correlation."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    POTENTIAL = "potential"


class FindingCategory(Enum):
    """Categories of findings."""

    VULNERABILITY = "vulnerability"
    EXPOSURE = "exposure"
    MISCONFIGURATION = "misconfiguration"
    THREAT_INDICATOR = "threat_indicator"
    RECONNAISSANCE = "reconnaissance"
    COMPLIANCE = "compliance"
    INFRASTRUCTURE = "infrastructure"
    CREDENTIAL = "credential"
    DATA_LEAK = "data_leak"
    SOCIAL = "social"


class FindingSeverity(Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a finding from any module."""

    id: str
    source_module: str
    category: FindingCategory
    title: str
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    timestamp: Optional[str] = None
    entities: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "source_module": self.source_module,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "entities": self.entities,
            "attributes": self.attributes,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class Correlation:
    """Represents a correlation between findings."""

    id: str
    finding_ids: List[str]
    correlation_type: CorrelationType
    strength: CorrelationStrength
    confidence: float  # 0.0 to 1.0
    reason: str
    shared_entities: List[str] = field(default_factory=list)
    shared_attributes: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_ids": self.finding_ids,
            "correlation_type": self.correlation_type.value,
            "strength": self.strength.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "shared_entities": self.shared_entities,
            "shared_attributes": self.shared_attributes,
            "timeline": self.timeline,
            "metadata": self.metadata,
        }


@dataclass
class CorrelationCluster:
    """A cluster of correlated findings."""

    id: str
    name: str
    finding_ids: List[str]
    correlations: List[str]  # Correlation IDs
    primary_category: FindingCategory
    aggregate_severity: FindingSeverity
    confidence: float
    summary: str = ""
    attack_pattern: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "finding_ids": self.finding_ids,
            "correlations": self.correlations,
            "primary_category": self.primary_category.value,
            "aggregate_severity": self.aggregate_severity.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "attack_pattern": self.attack_pattern,
            "recommendations": self.recommendations,
        }


@dataclass
class CorrelationInsight:
    """An insight derived from correlations."""

    id: str
    title: str
    description: str
    insight_type: str
    severity: FindingSeverity
    related_findings: List[str]
    related_correlations: List[str]
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.8

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "insight_type": self.insight_type,
            "severity": self.severity.value,
            "related_findings": self.related_findings,
            "related_correlations": self.related_correlations,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "confidence": self.confidence,
        }


# ============================================================================
# Attack Pattern Definitions
# ============================================================================

ATTACK_PATTERNS = {
    "credential_stuffing": {
        "name": "Credential Stuffing Attack",
        "categories": [FindingCategory.CREDENTIAL, FindingCategory.EXPOSURE],
        "indicators": ["leaked_credentials", "password_reuse", "dark_web"],
        "description": "Compromised credentials may enable account takeover",
    },
    "reconnaissance_chain": {
        "name": "Reconnaissance Activity",
        "categories": [FindingCategory.RECONNAISSANCE, FindingCategory.EXPOSURE],
        "indicators": ["subdomain", "port_scan", "technology_fingerprint"],
        "description": "Systematic reconnaissance preceding potential attack",
    },
    "infrastructure_exposure": {
        "name": "Infrastructure Exposure",
        "categories": [
            FindingCategory.INFRASTRUCTURE,
            FindingCategory.MISCONFIGURATION,
        ],
        "indicators": ["cloud", "s3", "azure", "exposed", "public"],
        "description": "Cloud infrastructure misconfigurations exposing assets",
    },
    "supply_chain_risk": {
        "name": "Supply Chain Risk",
        "categories": [FindingCategory.VULNERABILITY, FindingCategory.THREAT_INDICATOR],
        "indicators": ["dependency", "library", "cve", "vulnerable"],
        "description": "Third-party dependencies with known vulnerabilities",
    },
    "data_exfiltration_risk": {
        "name": "Data Exfiltration Risk",
        "categories": [FindingCategory.DATA_LEAK, FindingCategory.EXPOSURE],
        "indicators": ["sensitive", "pii", "api_key", "token", "secret"],
        "description": "Exposed sensitive data at risk of exfiltration",
    },
    "lateral_movement_path": {
        "name": "Lateral Movement Path",
        "categories": [FindingCategory.VULNERABILITY, FindingCategory.MISCONFIGURATION],
        "indicators": ["internal", "network", "trust", "permission"],
        "description": "Attack path enabling lateral movement",
    },
    "social_engineering_target": {
        "name": "Social Engineering Target",
        "categories": [FindingCategory.SOCIAL, FindingCategory.EXPOSURE],
        "indicators": ["email", "employee", "linkedin", "organization"],
        "description": "Exposed personnel information enabling social engineering",
    },
    "compliance_gap": {
        "name": "Compliance Gap",
        "categories": [FindingCategory.COMPLIANCE, FindingCategory.MISCONFIGURATION],
        "indicators": ["control", "policy", "requirement", "audit"],
        "description": "Compliance control gaps requiring remediation",
    },
}

# Entity extraction patterns
ENTITY_PATTERNS = {
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "url": r"https?://[^\s<>\"']+",
    "hash_md5": r"\b[a-fA-F0-9]{32}\b",
    "hash_sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"CVE-\d{4}-\d+",
    "aws_arn": r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d*:[a-z0-9-/]+",
}

# Causal relationships between categories
CAUSAL_RELATIONSHIPS = {
    FindingCategory.RECONNAISSANCE: [
        FindingCategory.VULNERABILITY,
        FindingCategory.EXPOSURE,
    ],
    FindingCategory.EXPOSURE: [
        FindingCategory.CREDENTIAL,
        FindingCategory.DATA_LEAK,
    ],
    FindingCategory.MISCONFIGURATION: [
        FindingCategory.EXPOSURE,
        FindingCategory.VULNERABILITY,
    ],
    FindingCategory.CREDENTIAL: [
        FindingCategory.DATA_LEAK,
    ],
    FindingCategory.VULNERABILITY: [
        FindingCategory.DATA_LEAK,
        FindingCategory.CREDENTIAL,
    ],
}


# ============================================================================
# Main Functions
# ============================================================================


def correlate_findings(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Correlate findings from context data.

    Args:
        ctx: Pipeline context containing findings from various modules
        params: Optional parameters:
            - temporal_window_hours: Time window for temporal correlation (default: 24)
            - min_confidence: Minimum confidence threshold (default: 0.3)
            - entity_types: Entity types to correlate on
            - enable_patterns: Whether to detect attack patterns
            - enable_clustering: Whether to cluster findings

    Returns:
        Updated context with correlation results
    """
    params = params or {}
    target = params.get("target") or ctx.target

    ctx.log(
        f"Starting finding correlation for: {target or 'all findings'}", level="INFO"
    )

    # Extract findings from context
    findings = extract_findings_from_context(ctx)

    if not findings:
        ctx.log("No findings to correlate", level="WARNING")
        ctx.add(
            "correlations",
            {"findings": [], "correlations": [], "clusters": [], "insights": []},
        )
        return ctx

    ctx.log(f"Extracted {len(findings)} findings for correlation", level="INFO")

    # Build finding index
    {f.id: f for f in findings}

    # Perform correlations
    correlations = []

    # Temporal correlation
    temporal_window = params.get("temporal_window_hours", 24)
    temporal_corrs = correlate_temporal(findings, temporal_window)
    correlations.extend(temporal_corrs)

    # Entity correlation
    entity_types = params.get("entity_types", list(ENTITY_PATTERNS.keys()))
    entity_corrs = correlate_entities(findings, entity_types)
    correlations.extend(entity_corrs)

    # Attribute correlation
    attr_corrs = correlate_attributes(findings)
    correlations.extend(attr_corrs)

    # Causal correlation
    causal_corrs = correlate_causal(findings)
    correlations.extend(causal_corrs)

    # Pattern detection
    if params.get("enable_patterns", True):
        pattern_corrs = detect_attack_patterns(findings)
        correlations.extend(pattern_corrs)

    # Filter by confidence
    min_confidence = params.get("min_confidence", 0.3)
    correlations = [c for c in correlations if c.confidence >= min_confidence]

    # Deduplicate correlations
    correlations = deduplicate_correlations(correlations)

    ctx.log(f"Found {len(correlations)} correlations", level="INFO")

    # Cluster findings
    clusters = []
    if params.get("enable_clustering", True):
        clusters = cluster_findings(findings, correlations)
        ctx.log(f"Created {len(clusters)} clusters", level="INFO")

    # Generate insights
    insights = generate_insights(findings, correlations, clusters)
    ctx.log(f"Generated {len(insights)} insights", level="INFO")

    # Build result
    result = {
        "target": target,
        "findings": [f.to_dict() for f in findings],
        "correlations": [c.to_dict() for c in correlations],
        "clusters": [c.to_dict() for c in clusters],
        "insights": [i.to_dict() for i in insights],
        "summary": generate_correlation_summary(
            findings, correlations, clusters, insights
        ),
        "graph": build_correlation_graph(findings, correlations),
    }

    ctx.add("correlations", result)

    return ctx


def extract_findings_from_context(ctx: Context) -> List[Finding]:
    """
    Extract findings from various context sources.

    Args:
        ctx: Pipeline context

    Returns:
        List of findings
    """
    findings = []
    finding_id = 0

    # Extract from exposure scan
    exposure = ctx.get("exposure_scan", {})
    for exp in exposure.get("exposures", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"EXP-{finding_id:04d}",
                source_module="exposure_scan",
                category=FindingCategory.EXPOSURE,
                title=exp.get("title", "Exposure Finding"),
                description=exp.get("description", ""),
                severity=parse_severity(exp.get("severity", "medium")),
                entities=extract_entities_from_text(str(exp)),
                attributes=exp,
                evidence=exp.get("evidence", []),
            )
        )

    # Extract from threat intel
    threat_intel = ctx.get("threat_intel", {})
    for ioc in threat_intel.get("iocs", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"IOC-{finding_id:04d}",
                source_module="threat_intel",
                category=FindingCategory.THREAT_INDICATOR,
                title=f"Threat Indicator: {ioc.get('type', 'Unknown')}",
                description=ioc.get("description", ""),
                severity=parse_severity(ioc.get("severity", "high")),
                entities=[ioc.get("value", "")],
                attributes=ioc,
            )
        )

    # Extract from compliance
    compliance = ctx.get("compliance", {})
    for gap in compliance.get("gaps", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"CMP-{finding_id:04d}",
                source_module="compliance",
                category=FindingCategory.COMPLIANCE,
                title=gap.get("title", "Compliance Gap"),
                description=gap.get("description", ""),
                severity=parse_severity(gap.get("priority", "medium")),
                attributes=gap,
            )
        )

    # Extract from infrastructure
    infrastructure = ctx.get("infrastructure", {})
    for issue in infrastructure.get("issues", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"INF-{finding_id:04d}",
                source_module="infrastructure",
                category=FindingCategory.INFRASTRUCTURE,
                title=issue.get("title", "Infrastructure Finding"),
                description=issue.get("description", ""),
                severity=parse_severity(issue.get("severity", "medium")),
                entities=extract_entities_from_text(str(issue)),
                attributes=issue,
            )
        )

    # Extract from domain profile
    domain_profile = ctx.get("domain_profile", {})
    for subdomain in domain_profile.get("subdomains", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"REC-{finding_id:04d}",
                source_module="recon",
                category=FindingCategory.RECONNAISSANCE,
                title=f"Subdomain: {subdomain}",
                description=f"Discovered subdomain: {subdomain}",
                severity=FindingSeverity.INFO,
                entities=[subdomain],
                attributes={"subdomain": subdomain},
            )
        )

    # Extract from tech stack
    tech_stack = ctx.get("tech_stack", {})
    for tech in tech_stack.get("technologies", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"TEC-{finding_id:04d}",
                source_module="tech_stack",
                category=FindingCategory.RECONNAISSANCE,
                title=f"Technology: {tech.get('name', 'Unknown')}",
                description=f"Detected technology: {tech.get('name', '')}",
                severity=FindingSeverity.INFO,
                entities=[tech.get("name", "")],
                attributes=tech,
            )
        )

    # Extract from social OSINT
    social = ctx.get("social_profiles", {})
    for profile in social.get("profiles", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"SOC-{finding_id:04d}",
                source_module="social_osint",
                category=FindingCategory.SOCIAL,
                title=f"Social Profile: {profile.get('platform', 'Unknown')}",
                description=profile.get("bio", ""),
                severity=FindingSeverity.LOW,
                entities=[profile.get("username", ""), profile.get("url", "")],
                attributes=profile,
            )
        )

    # Extract from risk scoring
    risk = ctx.get("risk_assessment", {})
    for vuln in risk.get("vulnerabilities", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"VUL-{finding_id:04d}",
                source_module="risk_scoring",
                category=FindingCategory.VULNERABILITY,
                title=vuln.get("title", "Vulnerability"),
                description=vuln.get("description", ""),
                severity=parse_severity(vuln.get("severity", "medium")),
                entities=extract_entities_from_text(str(vuln)),
                attributes=vuln,
            )
        )

    # Extract from code artifacts
    code = ctx.get("code_artifacts", {})
    for secret in code.get("secrets", []):
        finding_id += 1
        findings.append(
            Finding(
                id=f"SEC-{finding_id:04d}",
                source_module="code_artifacts",
                category=FindingCategory.CREDENTIAL,
                title=f"Exposed Secret: {secret.get('type', 'Unknown')}",
                description=secret.get("context", ""),
                severity=FindingSeverity.HIGH,
                entities=[secret.get("value", "")],
                attributes=secret,
            )
        )

    return findings


def correlate_temporal(
    findings: List[Finding], window_hours: int = 24
) -> List[Correlation]:
    """
    Correlate findings based on temporal proximity.

    Args:
        findings: List of findings
        window_hours: Time window in hours

    Returns:
        List of temporal correlations
    """
    correlations = []
    window = timedelta(hours=window_hours)

    # Group findings with timestamps
    timestamped = [(f, parse_timestamp(f.timestamp)) for f in findings if f.timestamp]
    timestamped = [(f, t) for f, t in timestamped if t is not None]

    if len(timestamped) < 2:
        return correlations

    # Sort by timestamp
    timestamped.sort(key=lambda x: x[1])

    # Find temporal clusters
    for i, (f1, t1) in enumerate(timestamped):
        related = []
        for f2, t2 in timestamped[i + 1 :]:
            if t2 - t1 <= window:
                related.append(f2)
            else:
                break

        if related:
            # Calculate confidence based on time proximity
            min_gap = min(
                (parse_timestamp(f.timestamp) - t1).total_seconds()
                for f in related
                if f.timestamp
            )
            confidence = max(0.3, 1.0 - (min_gap / (window_hours * 3600)))

            corr_id = generate_correlation_id([f1] + related, "temporal")
            correlations.append(
                Correlation(
                    id=corr_id,
                    finding_ids=[f1.id] + [f.id for f in related],
                    correlation_type=CorrelationType.TEMPORAL,
                    strength=calculate_strength(confidence),
                    confidence=confidence,
                    reason=f"Findings occurred within {window_hours} hours",
                    timeline=[
                        {"finding_id": f.id, "timestamp": f.timestamp}
                        for f in [f1] + related
                    ],
                )
            )

    return correlations


def correlate_entities(
    findings: List[Finding], entity_types: List[str]
) -> List[Correlation]:
    """
    Correlate findings based on shared entities.

    Args:
        findings: List of findings
        entity_types: Types of entities to correlate on

    Returns:
        List of entity correlations
    """
    correlations = []

    # Build entity index
    entity_to_findings: Dict[str, List[Finding]] = defaultdict(list)

    for finding in findings:
        for entity in finding.entities:
            entity_normalized = normalize_entity(entity)
            if entity_normalized:
                entity_to_findings[entity_normalized].append(finding)

        # Also extract entities from attributes
        for entity in extract_entities_from_text(str(finding.attributes)):
            entity_normalized = normalize_entity(entity)
            if entity_normalized:
                entity_to_findings[entity_normalized].append(finding)

    # Create correlations for shared entities
    for entity, related_findings in entity_to_findings.items():
        if len(related_findings) >= 2:
            # Deduplicate
            unique_findings = list({f.id: f for f in related_findings}.values())
            if len(unique_findings) >= 2:
                # Calculate confidence based on number of shared findings
                confidence = min(0.95, 0.5 + (len(unique_findings) - 2) * 0.1)

                corr_id = generate_correlation_id(
                    unique_findings, f"entity_{entity[:20]}"
                )
                correlations.append(
                    Correlation(
                        id=corr_id,
                        finding_ids=[f.id for f in unique_findings],
                        correlation_type=CorrelationType.ENTITY,
                        strength=calculate_strength(confidence),
                        confidence=confidence,
                        reason=f"Findings share entity: {entity[:50]}",
                        shared_entities=[entity],
                    )
                )

    return correlations


def correlate_attributes(findings: List[Finding]) -> List[Correlation]:
    """
    Correlate findings based on similar attributes.

    Args:
        findings: List of findings

    Returns:
        List of attribute correlations
    """
    correlations = []

    # Group by category
    by_category: Dict[FindingCategory, List[Finding]] = defaultdict(list)
    for finding in findings:
        by_category[finding.category].append(finding)

    # Correlate within categories based on shared attributes
    for category, cat_findings in by_category.items():
        if len(cat_findings) < 2:
            continue

        # Find findings with overlapping attribute keys
        for i, f1 in enumerate(cat_findings):
            for f2 in cat_findings[i + 1 :]:
                shared_keys = set(f1.attributes.keys()) & set(f2.attributes.keys())
                shared_values = {}

                for key in shared_keys:
                    if f1.attributes[key] == f2.attributes[key]:
                        shared_values[key] = f1.attributes[key]

                if shared_values:
                    confidence = min(0.8, 0.3 + len(shared_values) * 0.1)

                    corr_id = generate_correlation_id([f1, f2], "attribute")
                    correlations.append(
                        Correlation(
                            id=corr_id,
                            finding_ids=[f1.id, f2.id],
                            correlation_type=CorrelationType.ATTRIBUTE,
                            strength=calculate_strength(confidence),
                            confidence=confidence,
                            reason=f"Findings share {len(shared_values)} attribute(s)",
                            shared_attributes=shared_values,
                        )
                    )

    return correlations


def correlate_causal(findings: List[Finding]) -> List[Correlation]:
    """
    Correlate findings based on causal relationships.

    Args:
        findings: List of findings

    Returns:
        List of causal correlations
    """
    correlations = []

    # Group by category
    by_category: Dict[FindingCategory, List[Finding]] = defaultdict(list)
    for finding in findings:
        by_category[finding.category].append(finding)

    # Check for causal relationships
    for cause_category, effect_categories in CAUSAL_RELATIONSHIPS.items():
        cause_findings = by_category.get(cause_category, [])
        if not cause_findings:
            continue

        for effect_category in effect_categories:
            effect_findings = by_category.get(effect_category, [])
            if not effect_findings:
                continue

            # Look for entity overlap between cause and effect
            for cause in cause_findings:
                for effect in effect_findings:
                    # Check for shared entities
                    cause_entities = set(cause.entities)
                    effect_entities = set(effect.entities)
                    shared = cause_entities & effect_entities

                    if shared:
                        confidence = min(0.85, 0.5 + len(shared) * 0.15)

                        corr_id = generate_correlation_id([cause, effect], "causal")
                        correlations.append(
                            Correlation(
                                id=corr_id,
                                finding_ids=[cause.id, effect.id],
                                correlation_type=CorrelationType.CAUSAL,
                                strength=calculate_strength(confidence),
                                confidence=confidence,
                                reason=f"{cause_category.value} may enable {effect_category.value}",
                                shared_entities=list(shared),
                                metadata={
                                    "cause_category": cause_category.value,
                                    "effect_category": effect_category.value,
                                },
                            )
                        )

    return correlations


def detect_attack_patterns(findings: List[Finding]) -> List[Correlation]:
    """
    Detect known attack patterns in findings.

    Args:
        findings: List of findings

    Returns:
        List of pattern correlations
    """
    correlations = []

    for pattern_id, pattern in ATTACK_PATTERNS.items():
        matching_findings = []
        pattern_categories = set(pattern["categories"])
        pattern_indicators = pattern["indicators"]

        for finding in findings:
            # Check category match
            if finding.category in pattern_categories:
                matching_findings.append(finding)
                continue

            # Check indicator match
            finding_text = f"{finding.title} {finding.description} {str(finding.attributes)}".lower()
            if any(ind in finding_text for ind in pattern_indicators):
                matching_findings.append(finding)

        if len(matching_findings) >= 2:
            # Calculate confidence based on matches
            confidence = min(0.9, 0.4 + len(matching_findings) * 0.1)

            corr_id = generate_correlation_id(
                matching_findings, f"pattern_{pattern_id}"
            )
            correlations.append(
                Correlation(
                    id=corr_id,
                    finding_ids=[f.id for f in matching_findings],
                    correlation_type=CorrelationType.PATTERN,
                    strength=calculate_strength(confidence),
                    confidence=confidence,
                    reason=f"Matches attack pattern: {pattern['name']}",
                    metadata={
                        "pattern_id": pattern_id,
                        "pattern_name": pattern["name"],
                        "pattern_description": pattern["description"],
                    },
                )
            )

    return correlations


def cluster_findings(
    findings: List[Finding], correlations: List[Correlation]
) -> List[CorrelationCluster]:
    """
    Cluster related findings using correlation data.

    Args:
        findings: List of findings
        correlations: List of correlations

    Returns:
        List of clusters
    """
    clusters = []
    finding_index = {f.id: f for f in findings}

    # Build adjacency graph
    graph: Dict[str, Set[str]] = defaultdict(set)
    for corr in correlations:
        for i, fid1 in enumerate(corr.finding_ids):
            for fid2 in corr.finding_ids[i + 1 :]:
                graph[fid1].add(fid2)
                graph[fid2].add(fid1)

    # Find connected components using DFS
    visited: Set[str] = set()
    cluster_id = 0

    for finding in findings:
        if finding.id in visited:
            continue

        # DFS to find component
        component = []
        stack = [finding.id]

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            stack.extend(graph[current] - visited)

        if len(component) >= 2:
            cluster_id += 1
            component_findings = [
                finding_index[fid] for fid in component if fid in finding_index
            ]

            # Determine primary category
            category_counts: Dict[FindingCategory, int] = defaultdict(int)
            for f in component_findings:
                category_counts[f.category] += 1
            primary_category = max(category_counts, key=category_counts.get)

            # Determine aggregate severity
            severity_order = [
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
                FindingSeverity.MEDIUM,
                FindingSeverity.LOW,
                FindingSeverity.INFO,
            ]
            aggregate_severity = FindingSeverity.INFO
            for sev in severity_order:
                if any(f.severity == sev for f in component_findings):
                    aggregate_severity = sev
                    break

            # Get related correlations
            related_corrs = [
                c.id
                for c in correlations
                if any(fid in component for fid in c.finding_ids)
            ]

            # Calculate cluster confidence
            cluster_confidence = sum(
                c.confidence for c in correlations if c.id in related_corrs
            )
            cluster_confidence = min(
                0.95, cluster_confidence / max(1, len(related_corrs))
            )

            # Check for attack patterns
            attack_pattern = None
            for corr in correlations:
                if (
                    corr.id in related_corrs
                    and corr.correlation_type == CorrelationType.PATTERN
                ):
                    attack_pattern = corr.metadata.get("pattern_name")
                    break

            clusters.append(
                CorrelationCluster(
                    id=f"CLU-{cluster_id:04d}",
                    name=f"{primary_category.value.replace('_', ' ').title()} Cluster",
                    finding_ids=component,
                    correlations=related_corrs,
                    primary_category=primary_category,
                    aggregate_severity=aggregate_severity,
                    confidence=cluster_confidence,
                    summary=f"Cluster of {len(component)} related findings",
                    attack_pattern=attack_pattern,
                    recommendations=generate_cluster_recommendations(
                        component_findings, primary_category
                    ),
                )
            )

    return clusters


def generate_insights(
    findings: List[Finding],
    correlations: List[Correlation],
    clusters: List[CorrelationCluster],
) -> List[CorrelationInsight]:
    """
    Generate insights from correlation analysis.

    Args:
        findings: List of findings
        correlations: List of correlations
        clusters: List of clusters

    Returns:
        List of insights
    """
    insights = []
    insight_id = 0

    # Insight: Attack pattern detected
    pattern_corrs = [
        c for c in correlations if c.correlation_type == CorrelationType.PATTERN
    ]
    for corr in pattern_corrs:
        insight_id += 1
        pattern_name = corr.metadata.get("pattern_name", "Unknown Pattern")
        insights.append(
            CorrelationInsight(
                id=f"INS-{insight_id:04d}",
                title=f"Attack Pattern Detected: {pattern_name}",
                description=corr.metadata.get("pattern_description", ""),
                insight_type="attack_pattern",
                severity=FindingSeverity.HIGH,
                related_findings=corr.finding_ids,
                related_correlations=[corr.id],
                evidence=[corr.reason],
                recommendations=[
                    f"Investigate findings related to {pattern_name}",
                    "Review security controls for attack vector",
                    "Consider threat hunting for similar indicators",
                ],
                confidence=corr.confidence,
            )
        )

    # Insight: High severity clusters
    for cluster in clusters:
        if cluster.aggregate_severity in [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
        ]:
            insight_id += 1
            insights.append(
                CorrelationInsight(
                    id=f"INS-{insight_id:04d}",
                    title=f"High Severity Finding Cluster: {cluster.name}",
                    description=f"{len(cluster.finding_ids)} related high-severity findings detected",
                    insight_type="severity_cluster",
                    severity=cluster.aggregate_severity,
                    related_findings=cluster.finding_ids,
                    related_correlations=cluster.correlations,
                    recommendations=cluster.recommendations,
                    confidence=cluster.confidence,
                )
            )

    # Insight: Entity hotspots
    entity_counts: Dict[str, int] = defaultdict(int)
    for corr in correlations:
        if corr.correlation_type == CorrelationType.ENTITY:
            for entity in corr.shared_entities:
                entity_counts[entity] += len(corr.finding_ids)

    for entity, count in sorted(entity_counts.items(), key=lambda x: -x[1])[:5]:
        if count >= 3:
            insight_id += 1
            insights.append(
                CorrelationInsight(
                    id=f"INS-{insight_id:04d}",
                    title=f"Entity Hotspot: {entity[:50]}",
                    description=f"Entity appears in {count} findings across correlations",
                    insight_type="entity_hotspot",
                    severity=FindingSeverity.MEDIUM,
                    related_findings=[],
                    related_correlations=[
                        c.id for c in correlations if entity in c.shared_entities
                    ],
                    evidence=[f"Entity {entity} is highly connected"],
                    recommendations=[
                        f"Prioritize investigation of {entity}",
                        "Review all findings involving this entity",
                    ],
                    confidence=0.8,
                )
            )

    # Insight: Causal chains
    causal_corrs = [
        c for c in correlations if c.correlation_type == CorrelationType.CAUSAL
    ]
    if len(causal_corrs) >= 2:
        insight_id += 1
        insights.append(
            CorrelationInsight(
                id=f"INS-{insight_id:04d}",
                title="Potential Attack Chain Identified",
                description=f"{len(causal_corrs)} causal relationships suggest attack progression",
                insight_type="attack_chain",
                severity=FindingSeverity.HIGH,
                related_findings=list(
                    set(fid for c in causal_corrs for fid in c.finding_ids)
                ),
                related_correlations=[c.id for c in causal_corrs],
                evidence=[c.reason for c in causal_corrs],
                recommendations=[
                    "Analyze the attack chain progression",
                    "Implement controls to break the chain",
                    "Monitor for similar attack patterns",
                ],
                confidence=0.75,
            )
        )

    return insights


def build_correlation_graph(
    findings: List[Finding], correlations: List[Correlation]
) -> Dict[str, Any]:
    """
    Build a graph representation of correlations.

    Args:
        findings: List of findings
        correlations: List of correlations

    Returns:
        Graph data structure
    """
    nodes = [
        {
            "id": f.id,
            "label": f.title[:30],
            "category": f.category.value,
            "severity": f.severity.value,
            "module": f.source_module,
        }
        for f in findings
    ]

    edges = []
    for corr in correlations:
        for i, fid1 in enumerate(corr.finding_ids):
            for fid2 in corr.finding_ids[i + 1 :]:
                edges.append(
                    {
                        "source": fid1,
                        "target": fid2,
                        "type": corr.correlation_type.value,
                        "strength": corr.strength.value,
                        "confidence": corr.confidence,
                    }
                )

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def generate_correlation_summary(
    findings: List[Finding],
    correlations: List[Correlation],
    clusters: List[CorrelationCluster],
    insights: List[CorrelationInsight],
) -> Dict[str, Any]:
    """
    Generate summary of correlation analysis.

    Args:
        findings: List of findings
        correlations: List of correlations
        clusters: List of clusters
        insights: List of insights

    Returns:
        Summary dictionary
    """
    # Count by category
    category_counts = defaultdict(int)
    for f in findings:
        category_counts[f.category.value] += 1

    # Count by severity
    severity_counts = defaultdict(int)
    for f in findings:
        severity_counts[f.severity.value] += 1

    # Count by correlation type
    correlation_type_counts = defaultdict(int)
    for c in correlations:
        correlation_type_counts[c.correlation_type.value] += 1

    # Average confidence
    avg_confidence = (
        sum(c.confidence for c in correlations) / len(correlations)
        if correlations
        else 0
    )

    return {
        "total_findings": len(findings),
        "total_correlations": len(correlations),
        "total_clusters": len(clusters),
        "total_insights": len(insights),
        "findings_by_category": dict(category_counts),
        "findings_by_severity": dict(severity_counts),
        "correlations_by_type": dict(correlation_type_counts),
        "average_correlation_confidence": round(avg_confidence, 2),
        "high_severity_findings": severity_counts.get("critical", 0)
        + severity_counts.get("high", 0),
        "attack_patterns_detected": sum(
            1 for c in correlations if c.correlation_type == CorrelationType.PATTERN
        ),
    }


# ============================================================================
# Helper Functions
# ============================================================================


def generate_correlation_id(findings: List[Finding], prefix: str) -> str:
    """Generate a unique correlation ID."""
    finding_ids = sorted([f.id for f in findings])
    hash_input = f"{prefix}:{':'.join(finding_ids)}"
    hash_val = hashlib.md5(hash_input.encode()).hexdigest()[:8]
    return f"COR-{hash_val.upper()}"


def calculate_strength(confidence: float) -> CorrelationStrength:
    """Calculate correlation strength from confidence."""
    if confidence >= 0.8:
        return CorrelationStrength.STRONG
    elif confidence >= 0.6:
        return CorrelationStrength.MODERATE
    elif confidence >= 0.4:
        return CorrelationStrength.WEAK
    else:
        return CorrelationStrength.POTENTIAL


def parse_severity(severity_str: str) -> FindingSeverity:
    """Parse severity string to enum."""
    severity_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFO,
        "informational": FindingSeverity.INFO,
    }
    return severity_map.get(severity_str.lower(), FindingSeverity.MEDIUM)


def parse_timestamp(timestamp_str: Optional[str]) -> Optional[datetime]:
    """Parse timestamp string to datetime."""
    if not timestamp_str:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue

    return None


def normalize_entity(entity: str) -> Optional[str]:
    """Normalize an entity for comparison."""
    if not entity:
        return None

    entity = entity.strip().lower()

    # Skip very short entities
    if len(entity) < 3:
        return None

    # Skip common non-entity strings
    skip_strings = {"true", "false", "null", "none", "unknown", "n/a"}
    if entity in skip_strings:
        return None

    return entity


def extract_entities_from_text(text: str) -> List[str]:
    """Extract entities from text using patterns."""
    entities = []

    for entity_type, pattern in ENTITY_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities.extend(matches)

    return list(set(entities))


def deduplicate_correlations(correlations: List[Correlation]) -> List[Correlation]:
    """Remove duplicate correlations."""
    seen_ids = set()
    unique = []

    for corr in correlations:
        if corr.id not in seen_ids:
            seen_ids.add(corr.id)
            unique.append(corr)

    return unique


def generate_cluster_recommendations(
    findings: List[Finding], category: FindingCategory
) -> List[str]:
    """Generate recommendations for a cluster."""
    recommendations = []

    category_recommendations = {
        FindingCategory.VULNERABILITY: [
            "Prioritize patching critical vulnerabilities",
            "Implement vulnerability management process",
            "Review compensating controls",
        ],
        FindingCategory.EXPOSURE: [
            "Audit exposed services and data",
            "Implement access controls",
            "Review data classification",
        ],
        FindingCategory.CREDENTIAL: [
            "Rotate affected credentials immediately",
            "Enable MFA where applicable",
            "Review credential storage practices",
        ],
        FindingCategory.MISCONFIGURATION: [
            "Review configuration baselines",
            "Implement configuration management",
            "Enable configuration drift detection",
        ],
        FindingCategory.COMPLIANCE: [
            "Address compliance gaps by priority",
            "Document compensating controls",
            "Schedule remediation timeline",
        ],
        FindingCategory.INFRASTRUCTURE: [
            "Review infrastructure security",
            "Implement network segmentation",
            "Enable infrastructure monitoring",
        ],
    }

    recommendations.extend(
        category_recommendations.get(category, ["Review and remediate findings"])
    )

    # Add severity-specific recommendations
    has_critical = any(f.severity == FindingSeverity.CRITICAL for f in findings)
    if has_critical:
        recommendations.insert(0, "URGENT: Address critical findings immediately")

    return recommendations[:5]


# ============================================================================
# Additional Analysis Functions
# ============================================================================


def get_correlation_types() -> List[str]:
    """Get all correlation types."""
    return [t.value for t in CorrelationType]


def get_finding_categories() -> List[str]:
    """Get all finding categories."""
    return [c.value for c in FindingCategory]


def get_severity_levels() -> List[str]:
    """Get all severity levels."""
    return [s.value for s in FindingSeverity]


def get_attack_patterns() -> Dict[str, Dict[str, Any]]:
    """Get all defined attack patterns."""
    return {
        pid: {
            "name": p["name"],
            "description": p["description"],
            "categories": [c.value for c in p["categories"]],
            "indicators": p["indicators"],
        }
        for pid, p in ATTACK_PATTERNS.items()
    }


def find_related_findings(
    finding_id: str, correlations: List[Correlation]
) -> List[str]:
    """Find all findings related to a given finding."""
    related = set()

    for corr in correlations:
        if finding_id in corr.finding_ids:
            related.update(corr.finding_ids)

    related.discard(finding_id)
    return list(related)


def get_finding_correlations(
    finding_id: str, correlations: List[Correlation]
) -> List[Correlation]:
    """Get all correlations involving a finding."""
    return [c for c in correlations if finding_id in c.finding_ids]


def calculate_finding_centrality(
    finding_id: str, correlations: List[Correlation]
) -> float:
    """Calculate centrality score for a finding."""
    connections = 0
    total_confidence = 0.0

    for corr in correlations:
        if finding_id in corr.finding_ids:
            connections += len(corr.finding_ids) - 1
            total_confidence += corr.confidence

    if connections == 0:
        return 0.0

    return round(total_confidence / connections, 2)


def get_high_centrality_findings(
    findings: List[Finding], correlations: List[Correlation], top_n: int = 10
) -> List[Tuple[str, float]]:
    """Get findings with highest centrality scores."""
    centralities = [
        (f.id, calculate_finding_centrality(f.id, correlations)) for f in findings
    ]
    centralities.sort(key=lambda x: -x[1])
    return centralities[:top_n]


def create_finding(
    source_module: str,
    category: str,
    title: str,
    description: str = "",
    severity: str = "medium",
    entities: Optional[List[str]] = None,
    attributes: Optional[Dict[str, Any]] = None,
    finding_id: Optional[str] = None,
) -> Finding:
    """
    Create a Finding object.

    Args:
        source_module: Module that generated the finding
        category: Finding category
        title: Finding title
        description: Finding description
        severity: Severity level
        entities: Associated entities
        attributes: Additional attributes
        finding_id: Optional custom ID

    Returns:
        Finding object
    """
    if finding_id is None:
        hash_input = f"{source_module}:{title}:{description}"
        finding_id = f"FND-{hashlib.md5(hash_input.encode()).hexdigest()[:8].upper()}"

    return Finding(
        id=finding_id,
        source_module=source_module,
        category=FindingCategory(category) if isinstance(category, str) else category,
        title=title,
        description=description,
        severity=parse_severity(severity) if isinstance(severity, str) else severity,
        entities=entities or [],
        attributes=attributes or {},
    )


def merge_findings(
    findings: List[Finding], merge_strategy: str = "keep_highest_severity"
) -> List[Finding]:
    """
    Merge duplicate findings.

    Args:
        findings: List of findings
        merge_strategy: Strategy for merging ("keep_highest_severity", "keep_first", "combine")

    Returns:
        Deduplicated findings
    """
    # Group by title and category
    groups: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        key = f"{f.category.value}:{f.title.lower()}"
        groups[key].append(f)

    merged = []
    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4,
    }

    for key, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
        elif merge_strategy == "keep_highest_severity":
            group.sort(key=lambda f: severity_order[f.severity])
            merged.append(group[0])
        elif merge_strategy == "keep_first":
            merged.append(group[0])
        elif merge_strategy == "combine":
            # Combine entities and evidence
            combined = group[0]
            for f in group[1:]:
                combined.entities.extend(f.entities)
                combined.evidence.extend(f.evidence)
                combined.attributes.update(f.attributes)
            combined.entities = list(set(combined.entities))
            combined.evidence = list(set(combined.evidence))
            merged.append(combined)

    return merged
