"""
MITRE ATT&CK mapping module.

Maps findings, risks, and attack paths to MITRE ATT&CK framework techniques.
Provides tactical coverage analysis and detection recommendations.
"""

from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from redops.core.context import Context
from redops.core.models import RiskLevel


@dataclass
class MitreTechnique:
    """Represents a MITRE ATT&CK technique."""

    id: str
    name: str
    tactic: str
    description: str
    detection: str = ""
    mitigation: str = ""
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "detection": self.detection,
            "mitigation": self.mitigation,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
        }


# MITRE ATT&CK Tactics (Kill Chain Phases)
MITRE_TACTICS = [
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

# Expanded MITRE ATT&CK technique database
MITRE_TECHNIQUES: Dict[str, MitreTechnique] = {
    # Reconnaissance
    "T1595": MitreTechnique(
        id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        description="Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        detection="Monitor for suspicious network traffic patterns indicating scanning activity.",
        mitigation="Implement network segmentation and monitoring to detect scanning attempts.",
        platforms=["PRE"],
        data_sources=["Network Traffic"],
    ),
    "T1595.001": MitreTechnique(
        id="T1595.001",
        name="Active Scanning: Scanning IP Blocks",
        tactic="Reconnaissance",
        description="Adversaries may scan victim IP blocks to gather information.",
        detection="Monitor for connection attempts from single sources to multiple destinations.",
        mitigation="Rate limit incoming connections and implement IDS/IPS.",
        platforms=["PRE"],
        data_sources=["Network Traffic"],
    ),
    "T1595.002": MitreTechnique(
        id="T1595.002",
        name="Active Scanning: Vulnerability Scanning",
        tactic="Reconnaissance",
        description="Adversaries may scan for vulnerabilities to exploit.",
        detection="Monitor for known vulnerability scanning signatures.",
        mitigation="Keep systems patched and implement vulnerability scanning detection.",
        platforms=["PRE"],
        data_sources=["Network Traffic"],
    ),
    "T1590": MitreTechnique(
        id="T1590",
        name="Gather Victim Network Information",
        tactic="Reconnaissance",
        description="Adversaries may gather information about victim networks.",
        detection="Monitor for WHOIS queries and DNS reconnaissance.",
        mitigation="Minimize public exposure of internal network details.",
        platforms=["PRE"],
        data_sources=["Network Traffic", "DNS"],
    ),
    "T1590.002": MitreTechnique(
        id="T1590.002",
        name="Gather Victim Network Information: DNS",
        tactic="Reconnaissance",
        description="Adversaries may gather DNS information about the victim.",
        detection="Monitor for excessive DNS queries from single sources.",
        mitigation="Implement DNS query logging and anomaly detection.",
        platforms=["PRE"],
        data_sources=["DNS"],
    ),
    "T1592": MitreTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic="Reconnaissance",
        description="Adversaries may gather information about victim hosts.",
        detection="Monitor for fingerprinting attempts.",
        mitigation="Minimize information disclosure in service banners.",
        platforms=["PRE"],
        data_sources=["Network Traffic"],
    ),
    "T1592.002": MitreTechnique(
        id="T1592.002",
        name="Gather Victim Host Information: Software",
        tactic="Reconnaissance",
        description="Adversaries may gather software information from hosts.",
        detection="Monitor for software enumeration attempts.",
        mitigation="Remove version information from HTTP headers and responses.",
        platforms=["PRE"],
        data_sources=["Network Traffic"],
    ),
    "T1589": MitreTechnique(
        id="T1589",
        name="Gather Victim Identity Information",
        tactic="Reconnaissance",
        description="Adversaries may gather information about victim identities.",
        detection="Monitor for data harvesting from public sources.",
        mitigation="Limit publicly exposed employee information.",
        platforms=["PRE"],
        data_sources=["Web Logs"],
    ),
    "T1589.002": MitreTechnique(
        id="T1589.002",
        name="Gather Victim Identity Information: Email Addresses",
        tactic="Reconnaissance",
        description="Adversaries may gather email addresses for phishing.",
        detection="Monitor for email harvesting activity.",
        mitigation="Use contact forms instead of publishing email addresses.",
        platforms=["PRE"],
        data_sources=["Web Logs"],
    ),
    "T1591": MitreTechnique(
        id="T1591",
        name="Gather Victim Org Information",
        tactic="Reconnaissance",
        description="Adversaries may gather organizational information.",
        detection="Monitor for organizational data scraping.",
        mitigation="Limit public organizational structure disclosure.",
        platforms=["PRE"],
        data_sources=["Web Logs"],
    ),
    # Initial Access
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Adversaries may attempt to exploit weaknesses in Internet-facing applications.",
        detection="Monitor application logs for exploitation attempts.",
        mitigation="Keep applications patched and implement WAF.",
        platforms=["Linux", "Windows", "macOS", "Containers"],
        data_sources=["Application Log", "Network Traffic"],
    ),
    "T1133": MitreTechnique(
        id="T1133",
        name="External Remote Services",
        tactic="Initial Access",
        description="Adversaries may leverage external remote services for access.",
        detection="Monitor for unusual remote service access patterns.",
        mitigation="Implement MFA and VPN for remote access.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Authentication Logs", "Network Traffic"],
    ),
    "T1566": MitreTechnique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Adversaries may send phishing messages to gain access.",
        detection="Implement email filtering and user awareness training.",
        mitigation="Deploy email security solutions and sandbox attachments.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Email", "Network Traffic"],
    ),
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Initial Access",
        description="Adversaries may obtain credentials to maintain access.",
        detection="Monitor for unusual account activity.",
        mitigation="Implement strong authentication and credential policies.",
        platforms=["Linux", "Windows", "macOS", "Cloud"],
        data_sources=["Authentication Logs", "User Account"],
    ),
    "T1199": MitreTechnique(
        id="T1199",
        name="Trusted Relationship",
        tactic="Initial Access",
        description="Adversaries may breach organizations via trusted third parties.",
        detection="Monitor third-party access patterns.",
        mitigation="Implement least privilege for third-party access.",
        platforms=["Linux", "Windows", "macOS", "Cloud"],
        data_sources=["Authentication Logs", "Network Traffic"],
    ),
    # Privilege Escalation
    "T1068": MitreTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Adversaries may exploit software vulnerabilities to elevate privileges.",
        detection="Monitor for privilege escalation indicators.",
        mitigation="Keep systems patched and implement least privilege.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Process", "System Logs"],
    ),
    "T1548": MitreTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        description="Adversaries may abuse elevation mechanisms.",
        detection="Monitor for sudo/UAC bypass attempts.",
        mitigation="Configure elevation mechanisms securely.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Process", "Command Line"],
    ),
    # Credential Access
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force techniques to gain credentials.",
        detection="Monitor for multiple failed authentication attempts.",
        mitigation="Implement account lockout and MFA.",
        platforms=["Linux", "Windows", "macOS", "Cloud"],
        data_sources=["Authentication Logs"],
    ),
    "T1552": MitreTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic="Credential Access",
        description="Adversaries may search for unsecured credentials.",
        detection="Monitor for credential file access.",
        mitigation="Store credentials securely using secrets management.",
        platforms=["Linux", "Windows", "macOS", "Cloud"],
        data_sources=["File Access", "Command Line"],
    ),
    "T1552.001": MitreTechnique(
        id="T1552.001",
        name="Unsecured Credentials: Credentials In Files",
        tactic="Credential Access",
        description="Adversaries may search files for credentials.",
        detection="Monitor for file access to common credential locations.",
        mitigation="Use secrets management and avoid storing credentials in files.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["File Access"],
    ),
    # Discovery
    "T1087": MitreTechnique(
        id="T1087",
        name="Account Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to enumerate accounts.",
        detection="Monitor for account enumeration commands.",
        mitigation="Restrict access to account information.",
        platforms=["Linux", "Windows", "macOS", "Cloud"],
        data_sources=["Process", "Command Line"],
    ),
    "T1046": MitreTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries may scan for network services.",
        detection="Monitor for network scanning activity.",
        mitigation="Implement network segmentation.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic"],
    ),
    "T1018": MitreTechnique(
        id="T1018",
        name="Remote System Discovery",
        tactic="Discovery",
        description="Adversaries may discover remote systems.",
        detection="Monitor for network enumeration commands.",
        mitigation="Restrict network discovery protocols.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic", "Process"],
    ),
    # Command and Control
    "T1071": MitreTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Adversaries may communicate using application layer protocols.",
        detection="Monitor for unusual application protocol usage.",
        mitigation="Implement protocol inspection and filtering.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic"],
    ),
    "T1071.001": MitreTechnique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Command and Control",
        description="Adversaries may communicate over HTTP/HTTPS.",
        detection="Monitor for beaconing patterns in web traffic.",
        mitigation="Implement SSL inspection and domain filtering.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic"],
    ),
    "T1105": MitreTechnique(
        id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        description="Adversaries may transfer tools into the environment.",
        detection="Monitor for file downloads and transfers.",
        mitigation="Implement download restrictions and monitoring.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic", "File"],
    ),
    # Exfiltration
    "T1041": MitreTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Adversaries may exfiltrate data over C2 channel.",
        detection="Monitor for large data transfers.",
        mitigation="Implement DLP and egress filtering.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic"],
    ),
    "T1567": MitreTechnique(
        id="T1567",
        name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        description="Adversaries may exfiltrate data to cloud services.",
        detection="Monitor for uploads to cloud storage.",
        mitigation="Implement CASB and cloud access controls.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network Traffic"],
    ),
    # Impact
    "T1486": MitreTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Adversaries may encrypt data to impact availability (ransomware).",
        detection="Monitor for mass file encryption indicators.",
        mitigation="Implement backups and endpoint protection.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["File", "Process"],
    ),
    "T1498": MitreTechnique(
        id="T1498",
        name="Network Denial of Service",
        tactic="Impact",
        description="Adversaries may perform DoS attacks.",
        detection="Monitor for traffic spikes and anomalies.",
        mitigation="Implement DDoS protection and rate limiting.",
        platforms=["Linux", "Windows", "macOS", "Cloud"],
        data_sources=["Network Traffic"],
    ),
}

# Mapping keywords to MITRE techniques
KEYWORD_TECHNIQUE_MAP = {
    # Reconnaissance keywords
    "scan": ["T1595", "T1595.001", "T1595.002"],
    "enumerate": ["T1087", "T1046"],
    "fingerprint": ["T1592", "T1592.002"],
    "dns": ["T1590", "T1590.002"],
    "whois": ["T1590"],
    "subdomain": ["T1590.002", "T1595"],
    "email": ["T1589.002", "T1566"],
    # Initial Access keywords
    "vulnerability": ["T1190", "T1068"],
    "exploit": ["T1190", "T1068"],
    "injection": ["T1190"],
    "sql": ["T1190"],
    "xss": ["T1190"],
    "rce": ["T1190"],
    "remote": ["T1133", "T1190"],
    "phishing": ["T1566"],
    # Credential keywords
    "credential": ["T1552", "T1552.001", "T1078"],
    "password": ["T1110", "T1552"],
    "secret": ["T1552", "T1552.001"],
    "key": ["T1552", "T1552.001"],
    "token": ["T1552", "T1078"],
    "aws": ["T1552.001"],
    "api_key": ["T1552.001"],
    # Security misconfig
    "misconfiguration": ["T1190", "T1078"],
    "exposed": ["T1190", "T1552"],
    "default": ["T1078"],
    "unpatched": ["T1190", "T1068"],
    "outdated": ["T1190", "T1068"],
    # Headers/SSL
    "ssl": ["T1190", "T1071.001"],
    "tls": ["T1190", "T1071.001"],
    "certificate": ["T1190"],
    "header": ["T1190"],
    "cors": ["T1190"],
    "csp": ["T1190"],
}


def map_to_mitre(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Map findings, risks, and attack paths to MITRE ATT&CK techniques.

    Performs comprehensive mapping and generates coverage analysis.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - include_subtechniques: Include sub-techniques (default: True)
            - include_detection: Include detection recommendations (default: True)

    Returns:
        Updated context with MITRE mapping
    """
    params = params or {}
    include_subtechniques = params.get("include_subtechniques", True)
    include_detection = params.get("include_detection", True)

    ctx.log("Mapping to MITRE ATT&CK framework", level="INFO")

    # Collect all technique IDs
    techniques_used: Set[str] = set()

    # Map from attack paths
    attack_paths = ctx.get("attack_paths", [])
    for path in attack_paths:
        path_techniques = path.get("mitre_techniques", [])
        techniques_used.update(path_techniques)

    # Map from findings
    findings_mapping = map_findings_to_techniques(ctx)
    techniques_used.update(findings_mapping.keys())

    # Map from risks
    risks = ctx.get("risks", [])
    for risk in risks:
        if isinstance(risk, dict):
            risk_techniques = map_risk_to_techniques(risk)
            techniques_used.update(risk_techniques)

    # Filter sub-techniques if not wanted
    if not include_subtechniques:
        techniques_used = {t for t in techniques_used if "." not in t}

    # Build detailed mapping
    mitre_mapping = {}
    for technique_id in techniques_used:
        if technique_id in MITRE_TECHNIQUES:
            technique = MITRE_TECHNIQUES[technique_id]
            tech_dict = technique.to_dict()

            if not include_detection:
                tech_dict.pop("detection", None)
                tech_dict.pop("mitigation", None)

            mitre_mapping[technique_id] = tech_dict

    # Calculate tactic coverage
    tactic_coverage = calculate_tactic_coverage(techniques_used)

    # Generate detection recommendations
    detection_recommendations = []
    if include_detection:
        detection_recommendations = generate_detection_recommendations(techniques_used)

    # Add to context
    ctx.add("mitre_mapping", mitre_mapping)
    ctx.add("mitre_techniques_used", sorted(techniques_used))
    ctx.add("mitre_tactic_coverage", tactic_coverage)
    ctx.add("mitre_detection_recommendations", detection_recommendations)
    ctx.add("findings_technique_mapping", findings_mapping)
    ctx.add("mitre_summary", {
        "total_techniques": len(mitre_mapping),
        "tactics_covered": len([t for t, c in tactic_coverage.items() if c > 0]),
        "total_tactics": len(MITRE_TACTICS),
        "coverage_percentage": round(
            len([t for t, c in tactic_coverage.items() if c > 0]) / len(MITRE_TACTICS) * 100, 1
        ),
    })

    ctx.log(f"Mapped {len(mitre_mapping)} MITRE ATT&CK techniques", level="INFO")

    return ctx


def map_findings_to_techniques(ctx: Context) -> Dict[str, List[str]]:
    """
    Map findings to MITRE techniques based on keywords.

    Args:
        ctx: Pipeline context

    Returns:
        Dictionary of technique_id -> list of finding keys
    """
    mapping = defaultdict(list)

    for key in ctx.data.keys():
        if key.startswith("finding_"):
            finding = ctx.get(key)
            if not isinstance(finding, dict):
                continue

            # Get text to analyze
            title = finding.get("title", "").lower()
            description = finding.get("description", "").lower()
            text = f"{title} {description}"

            # Find matching techniques
            techniques = find_techniques_for_text(text)
            for technique_id in techniques:
                mapping[technique_id].append(key)

    return dict(mapping)


def find_techniques_for_text(text: str) -> Set[str]:
    """
    Find MITRE techniques that match text content.

    Args:
        text: Text to analyze

    Returns:
        Set of matching technique IDs
    """
    techniques = set()
    text_lower = text.lower()

    for keyword, technique_ids in KEYWORD_TECHNIQUE_MAP.items():
        if keyword in text_lower:
            techniques.update(technique_ids)

    return techniques


def map_risk_to_techniques(risk: Dict[str, Any]) -> Set[str]:
    """
    Map a risk to MITRE techniques.

    Args:
        risk: Risk dictionary

    Returns:
        Set of technique IDs
    """
    techniques = set()

    # Check if MITRE ID is directly specified
    mitre_id = risk.get("mitre_id")
    if mitre_id and mitre_id in MITRE_TECHNIQUES:
        techniques.add(mitre_id)

    # Map based on text
    title = risk.get("title", "").lower()
    description = risk.get("description", "").lower()
    text = f"{title} {description}"

    techniques.update(find_techniques_for_text(text))

    return techniques


def map_finding_to_technique(finding: Dict[str, Any]) -> Optional[str]:
    """
    Map a single finding to the most relevant MITRE technique.

    Args:
        finding: Finding data

    Returns:
        Most relevant technique ID or None
    """
    title = finding.get("title", "").lower()
    description = finding.get("description", "").lower()
    text = f"{title} {description}"

    techniques = find_techniques_for_text(text)

    if techniques:
        # Return the most specific technique (prefer sub-techniques)
        sub_techniques = [t for t in techniques if "." in t]
        if sub_techniques:
            return sorted(sub_techniques)[0]
        return sorted(techniques)[0]

    return None


def calculate_tactic_coverage(techniques: Set[str]) -> Dict[str, int]:
    """
    Calculate coverage of MITRE tactics.

    Args:
        techniques: Set of technique IDs

    Returns:
        Dictionary of tactic -> count
    """
    coverage = {tactic: 0 for tactic in MITRE_TACTICS}

    for technique_id in techniques:
        if technique_id in MITRE_TECHNIQUES:
            tactic = MITRE_TECHNIQUES[technique_id].tactic
            if tactic in coverage:
                coverage[tactic] += 1

    return coverage


def generate_detection_recommendations(techniques: Set[str]) -> List[Dict[str, Any]]:
    """
    Generate detection recommendations for used techniques.

    Args:
        techniques: Set of technique IDs

    Returns:
        List of detection recommendations
    """
    recommendations = []

    # Group by data source
    data_sources = defaultdict(list)
    for technique_id in techniques:
        if technique_id in MITRE_TECHNIQUES:
            technique = MITRE_TECHNIQUES[technique_id]
            for ds in technique.data_sources:
                data_sources[ds].append(technique_id)

    # Generate recommendations
    for data_source, technique_ids in sorted(data_sources.items(), key=lambda x: -len(x[1])):
        recommendations.append({
            "data_source": data_source,
            "techniques_detected": sorted(technique_ids),
            "priority": "high" if len(technique_ids) >= 3 else "medium" if len(technique_ids) >= 2 else "low",
            "recommendation": f"Implement logging and monitoring for {data_source} to detect {len(technique_ids)} techniques.",
        })

    return recommendations


def get_technique_info(technique_id: str) -> Optional[Dict[str, Any]]:
    """
    Get information about a MITRE ATT&CK technique.

    Args:
        technique_id: MITRE technique ID (e.g., "T1595")

    Returns:
        Technique information or None
    """
    if technique_id in MITRE_TECHNIQUES:
        return MITRE_TECHNIQUES[technique_id].to_dict()
    return None


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """
    Get all techniques for a specific tactic.

    Args:
        tactic: MITRE tactic name

    Returns:
        List of techniques
    """
    techniques = []

    for technique_id, technique in MITRE_TECHNIQUES.items():
        if technique.tactic == tactic:
            techniques.append({"id": technique_id, **technique.to_dict()})

    return techniques


def get_all_tactics() -> List[str]:
    """
    Get all MITRE ATT&CK tactics.

    Returns:
        List of tactic names
    """
    return MITRE_TACTICS.copy()


def get_mitigations_for_techniques(techniques: Set[str]) -> List[Dict[str, str]]:
    """
    Get mitigations for a set of techniques.

    Args:
        techniques: Set of technique IDs

    Returns:
        List of mitigation recommendations
    """
    mitigations = []

    for technique_id in sorted(techniques):
        if technique_id in MITRE_TECHNIQUES:
            technique = MITRE_TECHNIQUES[technique_id]
            if technique.mitigation:
                mitigations.append({
                    "technique_id": technique_id,
                    "technique_name": technique.name,
                    "mitigation": technique.mitigation,
                })

    return mitigations


def generate_attack_matrix_view(techniques: Set[str]) -> Dict[str, List[str]]:
    """
    Generate a view similar to the MITRE ATT&CK matrix.

    Args:
        techniques: Set of technique IDs in use

    Returns:
        Dictionary of tactic -> list of technique IDs
    """
    matrix = {tactic: [] for tactic in MITRE_TACTICS}

    for technique_id in techniques:
        if technique_id in MITRE_TECHNIQUES:
            tactic = MITRE_TECHNIQUES[technique_id].tactic
            if tactic in matrix:
                matrix[tactic].append(technique_id)

    # Sort techniques within each tactic
    for tactic in matrix:
        matrix[tactic] = sorted(matrix[tactic])

    return matrix
