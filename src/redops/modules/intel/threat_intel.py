"""
Threat Intelligence module.

Provides threat intelligence capabilities including:
- IOC (Indicators of Compromise) management
- Threat feed integration structures
- Reputation scoring
- Threat actor profiles
- Correlation with findings

IMPORTANT: This module uses simulated/example threat data.
Real implementations would integrate with actual threat feeds.
"""

from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta, timezone
import re
from redops.core.context import Context


class IOCType(Enum):
    """Types of Indicators of Compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    CVE = "cve"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    USER_AGENT = "user_agent"
    CERTIFICATE_HASH = "certificate_hash"
    BITCOIN_ADDRESS = "bitcoin_address"
    CIDR = "cidr"
    ASN = "asn"


class ThreatLevel(Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    """Categories of threats."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    C2 = "command_and_control"
    RANSOMWARE = "ransomware"
    APT = "advanced_persistent_threat"
    EXPLOIT_KIT = "exploit_kit"
    SPAM = "spam"
    CRYPTOMINING = "cryptomining"
    DATA_THEFT = "data_theft"
    DDOS = "ddos"
    SCANNER = "scanner"
    BRUTEFORCE = "bruteforce"
    SUSPICIOUS = "suspicious"


class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


@dataclass
class IOC:
    """Indicator of Compromise."""

    type: IOCType
    value: str
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    categories: List[ThreatCategory] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source: str = "unknown"
    tags: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type.value,
            "value": self.value,
            "threat_level": self.threat_level.value,
            "categories": [c.value for c in self.categories],
            "confidence": self.confidence.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "tags": self.tags,
            "related_iocs": self.related_iocs,
            "metadata": self.metadata,
        }


@dataclass
class ThreatActor:
    """Threat actor profile."""

    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    motivation: str = ""  # financial, espionage, hacktivism, etc.
    sophistication: str = ""  # low, medium, high, advanced
    origin: str = ""  # Country/region of origin
    active_since: Optional[str] = None
    last_activity: Optional[str] = None
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK TTPs
    tools: List[str] = field(default_factory=list)
    associated_iocs: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "motivation": self.motivation,
            "sophistication": self.sophistication,
            "origin": self.origin,
            "active_since": self.active_since,
            "last_activity": self.last_activity,
            "target_sectors": self.target_sectors,
            "target_regions": self.target_regions,
            "ttps": self.ttps,
            "tools": self.tools,
            "associated_iocs": self.associated_iocs,
            "references": self.references,
        }


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration."""

    name: str
    feed_type: str  # ip, domain, hash, mixed
    url: str = ""
    api_key_env: str = ""  # Environment variable name for API key
    update_frequency: str = "daily"  # hourly, daily, weekly
    enabled: bool = True
    last_update: Optional[str] = None
    ioc_count: int = 0
    confidence_default: ConfidenceLevel = ConfidenceLevel.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "feed_type": self.feed_type,
            "url": self.url,
            "update_frequency": self.update_frequency,
            "enabled": self.enabled,
            "last_update": self.last_update,
            "ioc_count": self.ioc_count,
            "confidence_default": self.confidence_default.value,
        }


@dataclass
class ThreatMatch:
    """Result of matching against threat intelligence."""

    ioc: IOC
    matched_value: str
    context: str  # Where the match was found
    match_type: str  # exact, partial, related
    score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ioc": self.ioc.to_dict(),
            "matched_value": self.matched_value,
            "context": self.context,
            "match_type": self.match_type,
            "score": self.score,
        }


# ============================================================================
# Known Threat Patterns (Simulated Data)
# ============================================================================

# Common malicious IP ranges (example/simulated - NOT real threat data)
KNOWN_MALICIOUS_PATTERNS = {
    "tor_exit_nodes": {
        "description": "Known Tor exit node patterns",
        "threat_level": ThreatLevel.LOW,
        "category": ThreatCategory.SUSPICIOUS,
    },
    "known_scanners": {
        "description": "Known vulnerability scanner sources",
        "threat_level": ThreatLevel.LOW,
        "category": ThreatCategory.SCANNER,
    },
    "bulletproof_hosting": {
        "description": "Bulletproof hosting providers",
        "threat_level": ThreatLevel.HIGH,
        "category": ThreatCategory.MALWARE,
    },
}

# Suspicious domain patterns
SUSPICIOUS_DOMAIN_PATTERNS = [
    (r"^[a-z0-9]{30,}\.(?:com|net|org|info)$", "DGA-like domain", ThreatLevel.HIGH),
    (
        r"^(?:login|secure|account|verify|update)-[a-z]+\.",
        "Phishing pattern",
        ThreatLevel.HIGH,
    ),
    (r"\.(?:tk|ml|ga|cf|gq)$", "Free TLD often abused", ThreatLevel.MEDIUM),
    (
        r"(?:paypal|apple|microsoft|google|amazon|facebook)-[a-z]+\.",
        "Brand impersonation",
        ThreatLevel.CRITICAL,
    ),
    (
        r"[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}\.",
        "IP-based domain",
        ThreatLevel.MEDIUM,
    ),
    (r"\.onion$", "Tor hidden service", ThreatLevel.MEDIUM),
    (
        r"(?:malware|trojan|virus|hack|crack|warez)\.",
        "Suspicious keywords",
        ThreatLevel.HIGH,
    ),
]

# Known malicious file hash patterns (example prefixes)
KNOWN_MALWARE_INDICATORS = {
    "ransomware_extensions": [
        ".locky",
        ".cryptolocker",
        ".cerber",
        ".wannacry",
        ".petya",
        ".ryuk",
        ".maze",
        ".revil",
        ".conti",
        ".lockbit",
    ],
    "suspicious_file_names": [
        "mimikatz",
        "lazagne",
        "procdump",
        "pwdump",
        "hashdump",
        "cobalt",
        "beacon",
        "meterpreter",
        "empire",
        "covenant",
    ],
    "c2_patterns": [
        r"/gate\.php$",
        r"/panel/",
        r"/admin\.php\?",
        r"/command\.php",
        r"/bot\.php",
        r"/loader\.php",
    ],
}

# Known threat actor database (simulated/educational)
THREAT_ACTORS_DB = {
    "APT28": ThreatActor(
        name="APT28",
        aliases=["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit"],
        description="State-sponsored threat actor known for cyber espionage",
        motivation="espionage",
        sophistication="advanced",
        origin="Eastern Europe",
        active_since="2004",
        target_sectors=["government", "military", "defense", "media"],
        target_regions=["North America", "Europe", "Asia"],
        ttps=["T1566", "T1059", "T1053", "T1071", "T1027"],
        tools=["X-Agent", "Zebrocy", "LoJax"],
    ),
    "APT29": ThreatActor(
        name="APT29",
        aliases=["Cozy Bear", "The Dukes", "CozyDuke"],
        description="Sophisticated threat actor focused on intelligence gathering",
        motivation="espionage",
        sophistication="advanced",
        origin="Eastern Europe",
        active_since="2008",
        target_sectors=["government", "think_tanks", "healthcare"],
        target_regions=["North America", "Europe"],
        ttps=["T1566.001", "T1204", "T1059.001", "T1071.001"],
        tools=["WellMess", "WellMail", "SoreFang"],
    ),
    "Lazarus": ThreatActor(
        name="Lazarus Group",
        aliases=["Hidden Cobra", "Zinc", "Labyrinth Chollima"],
        description="Threat actor known for financially motivated attacks",
        motivation="financial",
        sophistication="advanced",
        origin="East Asia",
        active_since="2009",
        target_sectors=["financial", "cryptocurrency", "entertainment"],
        target_regions=["Global"],
        ttps=["T1566", "T1059", "T1105", "T1486"],
        tools=["Manuscrypt", "AppleJeus", "FALLCHILL"],
    ),
    "FIN7": ThreatActor(
        name="FIN7",
        aliases=["Carbanak", "Navigator Group"],
        description="Financially motivated threat actor targeting retail and hospitality",
        motivation="financial",
        sophistication="high",
        origin="Eastern Europe",
        active_since="2013",
        target_sectors=["retail", "hospitality", "financial"],
        target_regions=["North America", "Europe"],
        ttps=["T1566.001", "T1059.001", "T1055", "T1071"],
        tools=["Carbanak", "GRIFFON", "HALFBAKED"],
    ),
}

# Threat feed configurations (simulated)
THREAT_FEEDS = {
    "abuse_ch_urlhaus": ThreatFeed(
        name="URLhaus",
        feed_type="url",
        url="https://urlhaus.abuse.ch/downloads/csv/",
        update_frequency="hourly",
        confidence_default=ConfidenceLevel.HIGH,
    ),
    "abuse_ch_malwarebazaar": ThreatFeed(
        name="MalwareBazaar",
        feed_type="hash",
        url="https://bazaar.abuse.ch/export/csv/recent/",
        update_frequency="hourly",
        confidence_default=ConfidenceLevel.HIGH,
    ),
    "blocklist_de": ThreatFeed(
        name="Blocklist.de",
        feed_type="ip",
        url="https://lists.blocklist.de/lists/all.txt",
        update_frequency="daily",
        confidence_default=ConfidenceLevel.MEDIUM,
    ),
    "phishtank": ThreatFeed(
        name="PhishTank",
        feed_type="url",
        url="https://data.phishtank.com/data/online-valid.csv",
        update_frequency="hourly",
        confidence_default=ConfidenceLevel.HIGH,
    ),
    "alienvault_otx": ThreatFeed(
        name="AlienVault OTX",
        feed_type="mixed",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        api_key_env="OTX_API_KEY",
        update_frequency="daily",
        confidence_default=ConfidenceLevel.MEDIUM,
    ),
}


# ============================================================================
# Main Functions
# ============================================================================


def analyze_threat_intel(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Analyze context data against threat intelligence.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - check_domains: Whether to check domains
            - check_ips: Whether to check IP addresses
            - check_urls: Whether to check URLs
            - check_hashes: Whether to check file hashes
            - min_threat_level: Minimum threat level to report

    Returns:
        Updated context with threat intelligence findings
    """
    params = params or {}
    target = params.get("target") or ctx.target

    if not target:
        ctx.log("No target specified for threat intel analysis", level="WARNING")
        return ctx

    ctx.log(f"Analyzing threat intelligence for: {target}", level="INFO")

    # Initialize results
    intel_data = {
        "target": target,
        "matches": [],
        "threat_actors": [],
        "domain_analysis": {},
        "ip_analysis": {},
        "url_analysis": {},
        "reputation_score": 0,
        "risk_indicators": [],
        "summary": {},
    }

    all_matches = []

    # Extract indicators from context
    indicators = extract_indicators_from_context(ctx)

    # Check domains
    if params.get("check_domains", True):
        domains = indicators.get("domains", [])
        domains.append(target)  # Include target
        domain_matches = check_domains_against_intel(list(set(domains)))
        all_matches.extend(domain_matches)
        intel_data["domain_analysis"] = analyze_domain_reputation(domains)

    # Check IPs
    if params.get("check_ips", True):
        ips = indicators.get("ips", [])
        ip_matches = check_ips_against_intel(ips)
        all_matches.extend(ip_matches)
        intel_data["ip_analysis"] = analyze_ip_reputation(ips)

    # Check URLs
    if params.get("check_urls", True):
        urls = indicators.get("urls", [])
        url_matches = check_urls_against_intel(urls)
        all_matches.extend(url_matches)
        intel_data["url_analysis"] = analyze_url_patterns(urls)

    # Check file hashes
    if params.get("check_hashes", True):
        hashes = indicators.get("hashes", [])
        hash_matches = check_hashes_against_intel(hashes)
        all_matches.extend(hash_matches)

    # Filter by minimum threat level
    min_level = params.get("min_threat_level", "low")
    level_order = ["critical", "high", "medium", "low", "unknown"]
    min_level_idx = level_order.index(min_level.lower())

    filtered_matches = []
    for match in all_matches:
        match_level_idx = level_order.index(match.ioc.threat_level.value)
        if match_level_idx <= min_level_idx:
            filtered_matches.append(match)

    intel_data["matches"] = [m.to_dict() for m in filtered_matches]

    # Check for threat actor associations
    threat_actors = identify_threat_actors(ctx, filtered_matches)
    intel_data["threat_actors"] = [ta.to_dict() for ta in threat_actors]

    # Calculate reputation score
    intel_data["reputation_score"] = calculate_reputation_score(filtered_matches)

    # Generate risk indicators
    intel_data["risk_indicators"] = generate_risk_indicators(
        filtered_matches, intel_data["domain_analysis"], intel_data["ip_analysis"]
    )

    # Generate summary
    intel_data["summary"] = generate_intel_summary(intel_data)

    # Add to context
    ctx.add("threat_intel", intel_data)

    # Log findings
    if filtered_matches:
        ctx.log(
            f"Found {len(filtered_matches)} threat intelligence matches",
            level="WARNING",
        )
        critical_count = sum(
            1 for m in filtered_matches if m.ioc.threat_level == ThreatLevel.CRITICAL
        )
        if critical_count > 0:
            ctx.log(
                f"CRITICAL: {critical_count} critical threat(s) detected", level="ERROR"
            )

    return ctx


def extract_indicators_from_context(ctx: Context) -> Dict[str, List[str]]:
    """
    Extract indicators (domains, IPs, URLs, hashes) from context.

    Args:
        ctx: Pipeline context

    Returns:
        Dictionary of indicator types to values
    """
    indicators = {
        "domains": [],
        "ips": [],
        "urls": [],
        "hashes": [],
        "emails": [],
    }

    # Patterns for extraction
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    url_pattern = r'https?://[^\s<>"\']+(?:\.[^\s<>"\']+)*'
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

    # Collect all text from context
    all_text = []
    for key, value in ctx.data.items():
        if isinstance(value, str):
            all_text.append(value)
        elif isinstance(value, dict):
            all_text.extend(_extract_strings(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    all_text.append(item)
                elif isinstance(item, dict):
                    all_text.extend(_extract_strings(item))

    combined = " ".join(all_text)

    # Extract each type
    indicators["ips"] = list(set(re.findall(ip_pattern, combined)))
    indicators["domains"] = list(set(re.findall(domain_pattern, combined)))
    indicators["urls"] = list(set(re.findall(url_pattern, combined)))
    indicators["emails"] = list(set(re.findall(email_pattern, combined, re.IGNORECASE)))

    # Extract hashes
    md5_hashes = set(re.findall(md5_pattern, combined))
    sha1_hashes = set(re.findall(sha1_pattern, combined))
    sha256_hashes = set(re.findall(sha256_pattern, combined))

    # Remove shorter hashes that might be substrings of longer ones
    sha1_hashes = sha1_hashes - md5_hashes
    sha256_hashes = sha256_hashes - sha1_hashes - md5_hashes

    indicators["hashes"] = list(md5_hashes | sha1_hashes | sha256_hashes)

    # Get from specific context fields
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("subdomains"):
        indicators["domains"].extend(domain_profile["subdomains"])

    # Deduplicate
    for key in indicators:
        indicators[key] = list(set(indicators[key]))

    return indicators


def _extract_strings(d: Dict[str, Any], max_depth: int = 3) -> List[str]:
    """Recursively extract strings from dictionary."""
    strings = []
    if max_depth <= 0:
        return strings

    for value in d.values():
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, dict):
            strings.extend(_extract_strings(value, max_depth - 1))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    strings.append(item)
                elif isinstance(item, dict):
                    strings.extend(_extract_strings(item, max_depth - 1))

    return strings


def check_domains_against_intel(domains: List[str]) -> List[ThreatMatch]:
    """
    Check domains against threat intelligence.

    Args:
        domains: List of domains to check

    Returns:
        List of threat matches
    """
    matches = []

    for domain in domains:
        domain_lower = domain.lower()

        # Check against suspicious patterns
        for pattern, description, threat_level in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain_lower):
                ioc = IOC(
                    type=IOCType.DOMAIN,
                    value=domain,
                    threat_level=threat_level,
                    categories=[ThreatCategory.PHISHING, ThreatCategory.SUSPICIOUS],
                    confidence=ConfidenceLevel.MEDIUM,
                    source="pattern_matching",
                    tags=["suspicious_pattern"],
                    metadata={"pattern": pattern, "description": description},
                )
                matches.append(
                    ThreatMatch(
                        ioc=ioc,
                        matched_value=domain,
                        context="domain_check",
                        match_type="pattern",
                        score=_threat_level_to_score(threat_level),
                    )
                )
                break  # One match per domain

    return matches


def check_ips_against_intel(ips: List[str]) -> List[ThreatMatch]:
    """
    Check IP addresses against threat intelligence.

    Args:
        ips: List of IP addresses to check

    Returns:
        List of threat matches
    """
    matches = []

    for ip in ips:
        # Check for private/reserved ranges (informational)
        if is_private_ip(ip):
            ioc = IOC(
                type=IOCType.IP_ADDRESS,
                value=ip,
                threat_level=ThreatLevel.LOW,
                categories=[ThreatCategory.SUSPICIOUS],
                confidence=ConfidenceLevel.CONFIRMED,
                source="range_check",
                tags=["private_ip", "internal"],
            )
            matches.append(
                ThreatMatch(
                    ioc=ioc,
                    matched_value=ip,
                    context="ip_check",
                    match_type="range",
                    score=0.1,
                )
            )

        # Check for bogon ranges
        if is_bogon_ip(ip):
            ioc = IOC(
                type=IOCType.IP_ADDRESS,
                value=ip,
                threat_level=ThreatLevel.MEDIUM,
                categories=[ThreatCategory.SUSPICIOUS],
                confidence=ConfidenceLevel.CONFIRMED,
                source="range_check",
                tags=["bogon", "invalid"],
            )
            matches.append(
                ThreatMatch(
                    ioc=ioc,
                    matched_value=ip,
                    context="ip_check",
                    match_type="range",
                    score=0.3,
                )
            )

    return matches


def check_urls_against_intel(urls: List[str]) -> List[ThreatMatch]:
    """
    Check URLs against threat intelligence.

    Args:
        urls: List of URLs to check

    Returns:
        List of threat matches
    """
    matches = []

    for url in urls:
        url_lower = url.lower()

        # Check for C2 patterns
        for pattern in KNOWN_MALWARE_INDICATORS["c2_patterns"]:
            if re.search(pattern, url_lower):
                ioc = IOC(
                    type=IOCType.URL,
                    value=url,
                    threat_level=ThreatLevel.HIGH,
                    categories=[ThreatCategory.C2, ThreatCategory.MALWARE],
                    confidence=ConfidenceLevel.MEDIUM,
                    source="pattern_matching",
                    tags=["c2_pattern", "malware"],
                    metadata={"pattern": pattern},
                )
                matches.append(
                    ThreatMatch(
                        ioc=ioc,
                        matched_value=url,
                        context="url_check",
                        match_type="pattern",
                        score=0.8,
                    )
                )
                break

        # Check for suspicious file downloads
        for extension in KNOWN_MALWARE_INDICATORS["ransomware_extensions"]:
            if url_lower.endswith(extension):
                ioc = IOC(
                    type=IOCType.URL,
                    value=url,
                    threat_level=ThreatLevel.CRITICAL,
                    categories=[ThreatCategory.RANSOMWARE],
                    confidence=ConfidenceLevel.HIGH,
                    source="pattern_matching",
                    tags=["ransomware", "malicious_extension"],
                )
                matches.append(
                    ThreatMatch(
                        ioc=ioc,
                        matched_value=url,
                        context="url_check",
                        match_type="extension",
                        score=1.0,
                    )
                )
                break

    return matches


def check_hashes_against_intel(hashes: List[str]) -> List[ThreatMatch]:
    """
    Check file hashes against threat intelligence.

    Args:
        hashes: List of file hashes to check

    Returns:
        List of threat matches
    """
    matches = []

    # In a real implementation, this would query threat intel databases
    # For now, we just validate hash format and return empty matches

    for hash_value in hashes:
        hash_type = identify_hash_type(hash_value)
        if hash_type:
            # Placeholder for actual threat intel lookup
            # Real implementation would query VirusTotal, MalwareBazaar, etc.
            pass

    return matches


def analyze_domain_reputation(domains: List[str]) -> Dict[str, Any]:
    """
    Analyze domain reputation.

    Args:
        domains: List of domains

    Returns:
        Domain reputation analysis
    """
    analysis = {
        "total_domains": len(domains),
        "suspicious_count": 0,
        "clean_count": 0,
        "unknown_count": 0,
        "by_tld": {},
        "age_analysis": {},
        "patterns_detected": [],
    }

    for domain in domains:
        domain_lower = domain.lower()

        # Extract TLD
        parts = domain_lower.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            analysis["by_tld"][tld] = analysis["by_tld"].get(tld, 0) + 1

        # Check patterns
        suspicious = False
        for pattern, description, _ in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain_lower):
                suspicious = True
                if description not in analysis["patterns_detected"]:
                    analysis["patterns_detected"].append(description)
                break

        if suspicious:
            analysis["suspicious_count"] += 1
        else:
            analysis["clean_count"] += 1

    return analysis


def analyze_ip_reputation(ips: List[str]) -> Dict[str, Any]:
    """
    Analyze IP reputation.

    Args:
        ips: List of IP addresses

    Returns:
        IP reputation analysis
    """
    analysis = {
        "total_ips": len(ips),
        "private_count": 0,
        "public_count": 0,
        "bogon_count": 0,
        "by_class": {"A": 0, "B": 0, "C": 0, "D": 0, "E": 0},
    }

    for ip in ips:
        if is_private_ip(ip):
            analysis["private_count"] += 1
        elif is_bogon_ip(ip):
            analysis["bogon_count"] += 1
        else:
            analysis["public_count"] += 1

        # Classify by class
        try:
            first_octet = int(ip.split(".")[0])
            if first_octet < 128:
                analysis["by_class"]["A"] += 1
            elif first_octet < 192:
                analysis["by_class"]["B"] += 1
            elif first_octet < 224:
                analysis["by_class"]["C"] += 1
            elif first_octet < 240:
                analysis["by_class"]["D"] += 1
            else:
                analysis["by_class"]["E"] += 1
        except (ValueError, IndexError):
            pass

    return analysis


def analyze_url_patterns(urls: List[str]) -> Dict[str, Any]:
    """
    Analyze URL patterns.

    Args:
        urls: List of URLs

    Returns:
        URL pattern analysis
    """
    analysis = {
        "total_urls": len(urls),
        "https_count": 0,
        "http_count": 0,
        "suspicious_patterns": [],
        "file_extensions": {},
        "parameters_detected": 0,
    }

    for url in urls:
        url_lower = url.lower()

        # Protocol analysis
        if url_lower.startswith("https://"):
            analysis["https_count"] += 1
        else:
            analysis["http_count"] += 1

        # Check for query parameters
        if "?" in url:
            analysis["parameters_detected"] += 1

        # Check for suspicious patterns
        for pattern in KNOWN_MALWARE_INDICATORS["c2_patterns"]:
            if re.search(pattern, url_lower):
                if pattern not in analysis["suspicious_patterns"]:
                    analysis["suspicious_patterns"].append(pattern)

        # Extract file extensions
        path = url.split("?")[0]
        if "." in path:
            ext = path.split(".")[-1].lower()[:10]
            if ext.isalpha():
                analysis["file_extensions"][ext] = (
                    analysis["file_extensions"].get(ext, 0) + 1
                )

    return analysis


def identify_threat_actors(
    ctx: Context, matches: List[ThreatMatch]
) -> List[ThreatActor]:
    """
    Identify potential threat actors based on context and matches.

    Args:
        ctx: Pipeline context
        matches: Threat matches found

    Returns:
        List of potentially associated threat actors
    """
    actors = []

    # Check for MITRE TTPs in context
    attack_paths = ctx.get("attack_paths", [])
    mitre_techniques = set()

    for path in attack_paths:
        if isinstance(path, dict):
            techniques = path.get("mitre_techniques", [])
            mitre_techniques.update(techniques)

    # Check context for MITRE mapping
    mitre_mapping = ctx.get("mitre_mapping", {})
    mitre_techniques.update(mitre_mapping.keys())

    # Match TTPs to threat actors
    for actor_id, actor in THREAT_ACTORS_DB.items():
        actor_ttps = set(actor.ttps)
        overlap = mitre_techniques & actor_ttps

        if len(overlap) >= 2:  # At least 2 TTP overlap
            actors.append(actor)

    # Check for tool signatures in context
    code_artifacts = ctx.get("code_artifacts", {})
    files = code_artifacts.get("files", [])

    for actor_id, actor in THREAT_ACTORS_DB.items():
        for tool in actor.tools:
            tool_lower = tool.lower()
            for file_path in files:
                if tool_lower in str(file_path).lower():
                    if actor not in actors:
                        actors.append(actor)
                    break

    return actors


def calculate_reputation_score(matches: List[ThreatMatch]) -> float:
    """
    Calculate overall reputation score based on matches.

    Score ranges from 0 (clean) to 100 (highly malicious).

    Args:
        matches: Threat matches

    Returns:
        Reputation score (0-100)
    """
    if not matches:
        return 0.0

    # Weight by threat level
    weights = {
        ThreatLevel.CRITICAL: 25,
        ThreatLevel.HIGH: 15,
        ThreatLevel.MEDIUM: 8,
        ThreatLevel.LOW: 3,
        ThreatLevel.UNKNOWN: 1,
    }

    total_score = 0
    for match in matches:
        weight = weights.get(match.ioc.threat_level, 1)
        confidence_multiplier = {
            ConfidenceLevel.CONFIRMED: 1.0,
            ConfidenceLevel.HIGH: 0.9,
            ConfidenceLevel.MEDIUM: 0.7,
            ConfidenceLevel.LOW: 0.4,
            ConfidenceLevel.UNVERIFIED: 0.2,
        }.get(match.ioc.confidence, 0.5)

        total_score += weight * confidence_multiplier

    # Cap at 100
    return min(100.0, total_score)


def generate_risk_indicators(
    matches: List[ThreatMatch],
    domain_analysis: Dict[str, Any],
    ip_analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Generate risk indicators from analysis.

    Args:
        matches: Threat matches
        domain_analysis: Domain reputation analysis
        ip_analysis: IP reputation analysis

    Returns:
        List of risk indicators
    """
    indicators = []

    # From matches
    if matches:
        critical_matches = [
            m for m in matches if m.ioc.threat_level == ThreatLevel.CRITICAL
        ]
        if critical_matches:
            indicators.append(
                {
                    "indicator": "critical_threats_detected",
                    "severity": "critical",
                    "count": len(critical_matches),
                    "description": f"{len(critical_matches)} critical threat(s) detected",
                }
            )

        high_matches = [m for m in matches if m.ioc.threat_level == ThreatLevel.HIGH]
        if high_matches:
            indicators.append(
                {
                    "indicator": "high_threats_detected",
                    "severity": "high",
                    "count": len(high_matches),
                    "description": f"{len(high_matches)} high-severity threat(s) detected",
                }
            )

    # From domain analysis
    if domain_analysis.get("suspicious_count", 0) > 0:
        indicators.append(
            {
                "indicator": "suspicious_domains",
                "severity": "medium",
                "count": domain_analysis["suspicious_count"],
                "description": f"{domain_analysis['suspicious_count']} suspicious domain(s) detected",
            }
        )

    if domain_analysis.get("patterns_detected"):
        indicators.append(
            {
                "indicator": "malicious_domain_patterns",
                "severity": "high",
                "patterns": domain_analysis["patterns_detected"],
                "description": f"Detected patterns: {', '.join(domain_analysis['patterns_detected'][:3])}",
            }
        )

    # From IP analysis
    if ip_analysis.get("bogon_count", 0) > 0:
        indicators.append(
            {
                "indicator": "bogon_ips",
                "severity": "medium",
                "count": ip_analysis["bogon_count"],
                "description": f"{ip_analysis['bogon_count']} bogon IP(s) detected",
            }
        )

    return indicators


def generate_intel_summary(intel_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate summary of threat intelligence analysis.

    Args:
        intel_data: Full threat intel data

    Returns:
        Summary dictionary
    """
    matches = intel_data.get("matches", [])

    summary = {
        "total_matches": len(matches),
        "critical_count": sum(
            1 for m in matches if m.get("ioc", {}).get("threat_level") == "critical"
        ),
        "high_count": sum(
            1 for m in matches if m.get("ioc", {}).get("threat_level") == "high"
        ),
        "medium_count": sum(
            1 for m in matches if m.get("ioc", {}).get("threat_level") == "medium"
        ),
        "low_count": sum(
            1 for m in matches if m.get("ioc", {}).get("threat_level") == "low"
        ),
        "threat_actors_identified": len(intel_data.get("threat_actors", [])),
        "reputation_score": intel_data.get("reputation_score", 0),
        "risk_level": "low",
        "risk_indicators_count": len(intel_data.get("risk_indicators", [])),
    }

    # Determine overall risk level
    if summary["critical_count"] > 0:
        summary["risk_level"] = "critical"
    elif summary["high_count"] > 0:
        summary["risk_level"] = "high"
    elif summary["medium_count"] > 0:
        summary["risk_level"] = "medium"
    elif summary["total_matches"] > 0:
        summary["risk_level"] = "low"
    else:
        summary["risk_level"] = "clean"

    return summary


# ============================================================================
# Helper Functions
# ============================================================================


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False

        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8 (loopback)
        if parts[0] == 127:
            return True

        return False
    except (ValueError, IndexError):
        return False


def is_bogon_ip(ip: str) -> bool:
    """Check if IP is a bogon (unallocated/reserved)."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False

        # 0.0.0.0/8
        if parts[0] == 0:
            return True
        # 100.64.0.0/10 (Carrier NAT)
        if parts[0] == 100 and 64 <= parts[1] <= 127:
            return True
        # 169.254.0.0/16 (Link-local)
        if parts[0] == 169 and parts[1] == 254:
            return True
        # 192.0.0.0/24 (IETF Protocol)
        if parts[0] == 192 and parts[1] == 0 and parts[2] == 0:
            return True
        # 192.0.2.0/24 (TEST-NET-1)
        if parts[0] == 192 and parts[1] == 0 and parts[2] == 2:
            return True
        # 198.51.100.0/24 (TEST-NET-2)
        if parts[0] == 198 and parts[1] == 51 and parts[2] == 100:
            return True
        # 203.0.113.0/24 (TEST-NET-3)
        if parts[0] == 203 and parts[1] == 0 and parts[2] == 113:
            return True
        # 224.0.0.0/4 (Multicast)
        if 224 <= parts[0] <= 239:
            return True
        # 240.0.0.0/4 (Reserved)
        if parts[0] >= 240:
            return True

        return False
    except (ValueError, IndexError):
        return False


def identify_hash_type(hash_value: str) -> Optional[IOCType]:
    """Identify the type of hash based on length and characters."""
    if not hash_value:
        return None

    hash_value = hash_value.lower()

    # Check if it's hexadecimal
    if not all(c in "0123456789abcdef" for c in hash_value):
        return None

    length = len(hash_value)

    if length == 32:
        return IOCType.FILE_HASH_MD5
    elif length == 40:
        return IOCType.FILE_HASH_SHA1
    elif length == 64:
        return IOCType.FILE_HASH_SHA256

    return None


def _threat_level_to_score(level: ThreatLevel) -> float:
    """Convert threat level to numeric score."""
    scores = {
        ThreatLevel.CRITICAL: 1.0,
        ThreatLevel.HIGH: 0.8,
        ThreatLevel.MEDIUM: 0.5,
        ThreatLevel.LOW: 0.2,
        ThreatLevel.UNKNOWN: 0.1,
    }
    return scores.get(level, 0.1)


def create_ioc(
    ioc_type: IOCType,
    value: str,
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN,
    categories: Optional[List[ThreatCategory]] = None,
    source: str = "manual",
    tags: Optional[List[str]] = None,
) -> IOC:
    """
    Create an IOC with common defaults.

    Args:
        ioc_type: Type of indicator
        value: Indicator value
        threat_level: Threat severity
        categories: Threat categories
        source: Source of the IOC
        tags: Tags for the IOC

    Returns:
        IOC object
    """
    return IOC(
        type=ioc_type,
        value=value,
        threat_level=threat_level,
        categories=categories or [],
        confidence=ConfidenceLevel.UNVERIFIED,
        first_seen=datetime.now(timezone.utc).isoformat(),
        source=source,
        tags=tags or [],
    )


def get_threat_actor(name: str) -> Optional[ThreatActor]:
    """
    Get threat actor by name or alias.

    Args:
        name: Actor name or alias

    Returns:
        ThreatActor or None
    """
    name_lower = name.lower()

    for actor_id, actor in THREAT_ACTORS_DB.items():
        if actor_id.lower() == name_lower:
            return actor
        if name_lower in [a.lower() for a in actor.aliases]:
            return actor

    return None


def get_all_threat_actors() -> List[ThreatActor]:
    """
    Get all known threat actors.

    Returns:
        List of threat actors
    """
    return list(THREAT_ACTORS_DB.values())


def get_threat_feeds() -> Dict[str, ThreatFeed]:
    """
    Get configured threat feeds.

    Returns:
        Dictionary of feed name to ThreatFeed
    """
    return THREAT_FEEDS.copy()


def get_ioc_types() -> List[str]:
    """
    Get all IOC types.

    Returns:
        List of IOC type values
    """
    return [t.value for t in IOCType]


def get_threat_categories() -> List[str]:
    """
    Get all threat categories.

    Returns:
        List of category values
    """
    return [c.value for c in ThreatCategory]


def validate_ioc(ioc_type: IOCType, value: str) -> Tuple[bool, str]:
    """
    Validate an IOC value.

    Args:
        ioc_type: Type of IOC
        value: Value to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not value:
        return False, "Value cannot be empty"

    validators = {
        IOCType.IP_ADDRESS: _validate_ip,
        IOCType.DOMAIN: _validate_domain,
        IOCType.URL: _validate_url,
        IOCType.EMAIL: _validate_email,
        IOCType.FILE_HASH_MD5: lambda v: _validate_hash(v, 32),
        IOCType.FILE_HASH_SHA1: lambda v: _validate_hash(v, 40),
        IOCType.FILE_HASH_SHA256: lambda v: _validate_hash(v, 64),
        IOCType.CVE: _validate_cve,
    }

    validator = validators.get(ioc_type)
    if validator:
        return validator(value)

    return True, ""  # No specific validation for this type


def _validate_ip(value: str) -> Tuple[bool, str]:
    """Validate IP address."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(pattern, value):
        return True, ""
    return False, "Invalid IP address format"


def _validate_domain(value: str) -> Tuple[bool, str]:
    """Validate domain name."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(pattern, value):
        return True, ""
    return False, "Invalid domain format"


def _validate_url(value: str) -> Tuple[bool, str]:
    """Validate URL."""
    pattern = r'^https?://[^\s<>"\']+$'
    if re.match(pattern, value):
        return True, ""
    return False, "Invalid URL format"


def _validate_email(value: str) -> Tuple[bool, str]:
    """Validate email address."""
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$"
    if re.match(pattern, value):
        return True, ""
    return False, "Invalid email format"


def _validate_hash(value: str, expected_length: int) -> Tuple[bool, str]:
    """Validate hash value."""
    if len(value) != expected_length:
        return False, f"Hash must be {expected_length} characters"
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        return False, "Hash must contain only hexadecimal characters"
    return True, ""


def _validate_cve(value: str) -> Tuple[bool, str]:
    """Validate CVE ID."""
    pattern = r"^CVE-\d{4}-\d{4,}$"
    if re.match(pattern, value, re.IGNORECASE):
        return True, ""
    return False, "Invalid CVE format (expected CVE-YYYY-NNNNN)"


def enrich_ioc(ioc: IOC) -> IOC:
    """
    Enrich an IOC with additional context.

    In a real implementation, this would query external services.

    Args:
        ioc: IOC to enrich

    Returns:
        Enriched IOC
    """
    # Add timestamp if not present
    if not ioc.last_seen:
        ioc.last_seen = datetime.now(timezone.utc).isoformat()

    # Add type-specific enrichment
    if ioc.type == IOCType.DOMAIN:
        # Extract TLD
        parts = ioc.value.split(".")
        if len(parts) >= 2:
            ioc.metadata["tld"] = parts[-1]
            ioc.metadata["sld"] = parts[-2]

    elif ioc.type == IOCType.IP_ADDRESS:
        # Add IP classification
        if is_private_ip(ioc.value):
            ioc.tags.append("private")
        if is_bogon_ip(ioc.value):
            ioc.tags.append("bogon")

    elif ioc.type in [
        IOCType.FILE_HASH_MD5,
        IOCType.FILE_HASH_SHA1,
        IOCType.FILE_HASH_SHA256,
    ]:
        ioc.metadata["hash_type"] = ioc.type.value

    return ioc
