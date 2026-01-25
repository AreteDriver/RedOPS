"""
Entity extraction module.

Extracts entities (emails, IPs, domains, hashes, etc.) from text and context data.
Uses regex patterns for reliable extraction without heavy NLP dependencies.
"""

import re
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel


@dataclass
class ExtractedEntities:
    """Container for extracted entities."""

    emails: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    ipv4_addresses: Set[str] = field(default_factory=set)
    ipv6_addresses: Set[str] = field(default_factory=set)
    phone_numbers: Set[str] = field(default_factory=set)
    md5_hashes: Set[str] = field(default_factory=set)
    sha1_hashes: Set[str] = field(default_factory=set)
    sha256_hashes: Set[str] = field(default_factory=set)
    social_handles: Set[str] = field(default_factory=set)
    credit_cards: Set[str] = field(default_factory=set)
    aws_keys: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary with sorted lists."""
        return {
            "emails": sorted(self.emails),
            "domains": sorted(self.domains),
            "urls": sorted(self.urls),
            "ipv4_addresses": sorted(self.ipv4_addresses),
            "ipv6_addresses": sorted(self.ipv6_addresses),
            "phone_numbers": sorted(self.phone_numbers),
            "md5_hashes": sorted(self.md5_hashes),
            "sha1_hashes": sorted(self.sha1_hashes),
            "sha256_hashes": sorted(self.sha256_hashes),
            "social_handles": sorted(self.social_handles),
            "credit_cards": sorted(self.credit_cards),
            "aws_keys": sorted(self.aws_keys),
        }

    def merge(self, other: "ExtractedEntities") -> None:
        """Merge another ExtractedEntities into this one."""
        self.emails.update(other.emails)
        self.domains.update(other.domains)
        self.urls.update(other.urls)
        self.ipv4_addresses.update(other.ipv4_addresses)
        self.ipv6_addresses.update(other.ipv6_addresses)
        self.phone_numbers.update(other.phone_numbers)
        self.md5_hashes.update(other.md5_hashes)
        self.sha1_hashes.update(other.sha1_hashes)
        self.sha256_hashes.update(other.sha256_hashes)
        self.social_handles.update(other.social_handles)
        self.credit_cards.update(other.credit_cards)
        self.aws_keys.update(other.aws_keys)

    def total_count(self) -> int:
        """Get total number of entities."""
        return sum(len(getattr(self, f)) for f in self.to_dict().keys())

    def is_empty(self) -> bool:
        """Check if no entities were extracted."""
        return self.total_count() == 0


# Compiled regex patterns for performance
PATTERNS = {
    # Email addresses
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE
    ),
    # URLs (http/https)
    "url": re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*", re.IGNORECASE),
    # Domain names (simplified, excludes common false positives)
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|co|dev|app|xyz|info|biz|us|uk|de|fr|jp|cn|ru|br|in|au|ca|nl|se|no|fi|dk|es|it|pl|cz|at|ch|be|ie|nz|za|mx|ar|cl|co\.uk|com\.au|co\.nz|co\.za)\b",
        re.IGNORECASE,
    ),
    # IPv4 addresses
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    # IPv6 addresses (simplified)
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    ),
    # Phone numbers (US format and international)
    "phone": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|"
        r"\b\+?[1-9]\d{1,14}\b"
    ),
    # MD5 hashes (32 hex chars)
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    # SHA1 hashes (40 hex chars)
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    # SHA256 hashes (64 hex chars)
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    # Social media handles (@username)
    "social": re.compile(r"@[A-Za-z0-9_]{1,30}\b"),
    # Credit card numbers (basic patterns, masked)
    "credit_card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
        r"5[1-5][0-9]{14}|"  # MasterCard
        r"3[47][0-9]{13}|"  # Amex
        r"6(?:011|5[0-9]{2})[0-9]{12})\b"  # Discover
    ),
    # AWS Access Key IDs
    "aws_key": re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
}


def extract_entities(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Extract entities from context data.

    Scans all text data in context for emails, IPs, domains, hashes, and more.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - include_findings: Also scan findings text (default: True)
            - extract_from_target: Extract from target domain (default: True)
            - sensitive_only: Only extract potentially sensitive entities (default: False)

    Returns:
        Updated context with extracted entities
    """
    params = params or {}
    include_findings = params.get("include_findings", True)
    extract_from_target = params.get("extract_from_target", True)
    sensitive_only = params.get("sensitive_only", False)

    ctx.log("Extracting entities from context data", level="INFO")

    entities = ExtractedEntities()
    findings: List[Finding] = []

    # Extract from target domain
    if extract_from_target and ctx.target:
        target_entities = extract_from_text(ctx.target)
        entities.merge(target_entities)

    # Extract from various context data sources
    text_sources = collect_text_sources(ctx, include_findings)

    for source_name, text in text_sources:
        if text:
            source_entities = extract_from_text(str(text))
            entities.merge(source_entities)
            ctx.log(
                f"Extracted from {source_name}: {source_entities.total_count()} entities",
                level="DEBUG",
            )

    # Create findings for sensitive entities
    if entities.credit_cards:
        findings.append(
            Finding(
                module="intel.entity_extract",
                title="Credit Card Numbers Detected",
                description=f"Found {len(entities.credit_cards)} potential credit card numbers in data.",
                severity=RiskLevel.CRITICAL,
                data={
                    "count": len(entities.credit_cards),
                    "recommendation": "Review and remove any exposed payment card data",
                },
            )
        )

    if entities.aws_keys:
        findings.append(
            Finding(
                module="intel.entity_extract",
                title="AWS Access Keys Detected",
                description=f"Found {len(entities.aws_keys)} AWS access key IDs in data.",
                severity=RiskLevel.CRITICAL,
                data={
                    "count": len(entities.aws_keys),
                    "keys": list(entities.aws_keys),
                    "recommendation": "Rotate these credentials immediately",
                },
            )
        )

    # Add entities to context
    entity_dict = entities.to_dict()

    if sensitive_only:
        # Only include potentially sensitive entities
        entity_dict = {
            k: v
            for k, v in entity_dict.items()
            if k in ["emails", "credit_cards", "aws_keys", "phone_numbers"]
        }

    ctx.add("entities", entity_dict)

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_entity_{i}", finding.model_dump())

    # Add summary
    ctx.add(
        "entity_summary",
        {
            "total_entities": entities.total_count(),
            "by_type": {k: len(v) for k, v in entity_dict.items()},
            "sensitive_findings": len(findings),
        },
    )

    ctx.log(
        f"Entity extraction completed: {entities.total_count()} entities found",
        level="INFO",
    )

    return ctx


def collect_text_sources(
    ctx: Context, include_findings: bool = True
) -> List[Tuple[str, str]]:
    """
    Collect text sources from context for entity extraction.

    Args:
        ctx: Pipeline context
        include_findings: Whether to include findings text

    Returns:
        List of (source_name, text) tuples
    """
    sources = []

    # Domain profile
    domain_profile = ctx.get("domain_profile")
    if domain_profile:
        sources.append(("domain_profile", str(domain_profile)))

    # DNS records
    dns_records = ctx.get("dns_records")
    if dns_records:
        sources.append(("dns_records", str(dns_records)))

    # Subdomains
    subdomains = ctx.get("subdomains")
    if subdomains:
        sources.append(("subdomains", str(subdomains)))

    # Tech stack
    tech_stack = ctx.get("tech_stack")
    if tech_stack:
        sources.append(("tech_stack", str(tech_stack)))

    # EXIF data
    exif_data = ctx.get("exif_data")
    if exif_data:
        sources.append(("exif_data", str(exif_data)))

    # Document metadata
    doc_metadata = ctx.get("document_metadata")
    if doc_metadata:
        sources.append(("document_metadata", str(doc_metadata)))

    # Repository analysis
    repo_analysis = ctx.get("repository_analysis")
    if repo_analysis:
        sources.append(("repository_analysis", str(repo_analysis)))

    # Findings (if enabled)
    if include_findings:
        for key in ctx.data.keys():
            if key.startswith("finding_"):
                finding_data = ctx.get(key)
                if finding_data:
                    sources.append((key, str(finding_data)))

    return sources


def extract_from_text(text: str) -> ExtractedEntities:
    """
    Extract entities from a text string.

    Args:
        text: Text to analyze

    Returns:
        ExtractedEntities object with found entities
    """
    entities = ExtractedEntities()

    if not text:
        return entities

    # Extract each entity type
    entities.emails.update(PATTERNS["email"].findall(text))
    entities.urls.update(PATTERNS["url"].findall(text))
    entities.ipv4_addresses.update(PATTERNS["ipv4"].findall(text))
    entities.ipv6_addresses.update(PATTERNS["ipv6"].findall(text))
    entities.phone_numbers.update(extract_phone_numbers(text))
    entities.md5_hashes.update(PATTERNS["md5"].findall(text))
    entities.sha1_hashes.update(PATTERNS["sha1"].findall(text))
    entities.sha256_hashes.update(PATTERNS["sha256"].findall(text))
    entities.social_handles.update(PATTERNS["social"].findall(text))
    entities.credit_cards.update(extract_credit_cards(text))
    entities.aws_keys.update(PATTERNS["aws_key"].findall(text))

    # Extract domains (excluding those already in URLs)
    domains = set(PATTERNS["domain"].findall(text.lower()))
    # Filter out domains that are part of extracted emails
    for email in entities.emails:
        domain = email.split("@")[-1].lower()
        domains.discard(domain)
    entities.domains.update(domains)

    # Clean up: remove obvious false positives
    entities = clean_entities(entities)

    return entities


def extract_phone_numbers(text: str) -> Set[str]:
    """
    Extract and normalize phone numbers.

    Args:
        text: Text to search

    Returns:
        Set of phone numbers
    """
    matches = PATTERNS["phone"].findall(text)

    # Filter out numbers that are too short or look like other data
    valid_phones = set()
    for match in matches:
        # Clean the match
        digits = re.sub(r"\D", "", match)
        # Valid phone numbers have 10-15 digits
        if 10 <= len(digits) <= 15:
            valid_phones.add(match)

    return valid_phones


def extract_credit_cards(text: str) -> Set[str]:
    """
    Extract credit card numbers (masked for security).

    Args:
        text: Text to search

    Returns:
        Set of masked credit card numbers
    """
    matches = PATTERNS["credit_card"].findall(text)

    # Mask the middle digits for security
    masked = set()
    for cc in matches:
        if luhn_check(cc):
            # Mask all but first 4 and last 4 digits
            masked_cc = cc[:4] + "*" * (len(cc) - 8) + cc[-4:]
            masked.add(masked_cc)

    return masked


def luhn_check(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.

    Args:
        card_number: Card number string

    Returns:
        True if valid Luhn checksum
    """
    digits = [int(d) for d in card_number if d.isdigit()]

    if len(digits) < 13:
        return False

    # Luhn algorithm
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def clean_entities(entities: ExtractedEntities) -> ExtractedEntities:
    """
    Clean up extracted entities by removing false positives.

    Args:
        entities: Raw extracted entities

    Returns:
        Cleaned entities
    """
    # Remove private/local IPs if extracting from public data
    private_ip_prefixes = (
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "127.",
        "0.",
    )

    entities.ipv4_addresses = {
        ip for ip in entities.ipv4_addresses if not ip.startswith(private_ip_prefixes)
    }

    # Remove common false positive domains
    false_positive_domains = {
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "test.com",
        "domain.com",
    }
    entities.domains -= false_positive_domains

    # Remove version-like MD5s (e.g., 00000000000000000000000000000000)
    entities.md5_hashes = {
        h for h in entities.md5_hashes if not all(c == h[0] for c in h)
    }

    return entities


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IOCs) from text.

    Focused on security-relevant entities.

    Args:
        text: Text to analyze

    Returns:
        Dictionary of IOC types to values
    """
    entities = extract_from_text(text)

    return {
        "ips": sorted(entities.ipv4_addresses | entities.ipv6_addresses),
        "domains": sorted(entities.domains),
        "urls": sorted(entities.urls),
        "emails": sorted(entities.emails),
        "hashes": sorted(
            entities.md5_hashes | entities.sha1_hashes | entities.sha256_hashes
        ),
    }


def defang_ioc(ioc: str) -> str:
    """
    Defang an IOC for safe sharing.

    Replaces . with [.] and http with hxxp.

    Args:
        ioc: IOC string

    Returns:
        Defanged IOC
    """
    defanged = ioc.replace(".", "[.]")
    defanged = defanged.replace("http", "hxxp")
    defanged = defanged.replace("://", "[://]")
    return defanged


def refang_ioc(ioc: str) -> str:
    """
    Refang a defanged IOC.

    Args:
        ioc: Defanged IOC string

    Returns:
        Original IOC
    """
    refanged = ioc.replace("[.]", ".")
    refanged = refanged.replace("hxxp", "http")
    refanged = refanged.replace("[://]", "://")
    return refanged


def get_entity_summary(entities: ExtractedEntities) -> Dict[str, Any]:
    """
    Generate a summary of extracted entities.

    Args:
        entities: Extracted entities

    Returns:
        Summary dictionary
    """
    entity_dict = entities.to_dict()

    return {
        "total": entities.total_count(),
        "by_type": {k: len(v) for k, v in entity_dict.items() if v},
        "has_sensitive": bool(entities.credit_cards or entities.aws_keys),
        "has_pii": bool(entities.emails or entities.phone_numbers),
        "has_iocs": bool(
            entities.ipv4_addresses
            or entities.domains
            or entities.md5_hashes
            or entities.sha1_hashes
            or entities.sha256_hashes
        ),
    }
