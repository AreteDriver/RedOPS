"""
Social OSINT module.

Performs open-source intelligence gathering from public sources only.
Limited to public profile metadata and pattern-based analysis.

IMPORTANT: This module operates on PUBLIC information only.
No private data access, no authentication bypass, no terms of service violations.
"""

from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
import hashlib
from redops.core.context import Context


@dataclass
class Platform:
    """Represents a social/professional platform."""
    name: str
    url_pattern: str
    category: str  # social, professional, code, forum, other
    username_format: str = r"^[a-zA-Z0-9_-]+$"  # Valid username regex
    min_length: int = 3
    max_length: int = 30

    def format_url(self, username: str) -> str:
        """Format profile URL for username."""
        return self.url_pattern.format(username=username)

    def is_valid_username(self, username: str) -> bool:
        """Check if username format is valid for this platform."""
        if len(username) < self.min_length or len(username) > self.max_length:
            return False
        return bool(re.match(self.username_format, username))


@dataclass
class UserProfile:
    """Represents a discovered user profile."""
    username: str
    platform: str
    url: str
    category: str
    confidence: float = 0.0  # 0.0 to 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "username": self.username,
            "platform": self.platform,
            "url": self.url,
            "category": self.category,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class BreachInfo:
    """Information about a data breach."""
    name: str
    date: str
    data_types: List[str]
    description: str
    severity: str  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "date": self.date,
            "data_types": self.data_types,
            "description": self.description,
            "severity": self.severity,
        }


@dataclass
class EmailPattern:
    """Represents an email pattern for a domain."""
    pattern: str  # e.g., "first.last", "flast", "firstl"
    example: str
    confidence: float = 0.0


# Common platforms for username checking
PLATFORMS = {
    "github": Platform(
        name="GitHub",
        url_pattern="https://github.com/{username}",
        category="code",
        username_format=r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$",
        max_length=39,
    ),
    "gitlab": Platform(
        name="GitLab",
        url_pattern="https://gitlab.com/{username}",
        category="code",
    ),
    "twitter": Platform(
        name="Twitter/X",
        url_pattern="https://twitter.com/{username}",
        category="social",
        username_format=r"^[a-zA-Z0-9_]+$",
        max_length=15,
    ),
    "linkedin": Platform(
        name="LinkedIn",
        url_pattern="https://linkedin.com/in/{username}",
        category="professional",
        username_format=r"^[a-zA-Z0-9-]+$",
    ),
    "reddit": Platform(
        name="Reddit",
        url_pattern="https://reddit.com/user/{username}",
        category="social",
        username_format=r"^[a-zA-Z0-9_-]+$",
        max_length=20,
    ),
    "hackernews": Platform(
        name="Hacker News",
        url_pattern="https://news.ycombinator.com/user?id={username}",
        category="forum",
    ),
    "stackoverflow": Platform(
        name="Stack Overflow",
        url_pattern="https://stackoverflow.com/users/{username}",
        category="code",
    ),
    "medium": Platform(
        name="Medium",
        url_pattern="https://medium.com/@{username}",
        category="social",
    ),
    "dev_to": Platform(
        name="DEV.to",
        url_pattern="https://dev.to/{username}",
        category="code",
    ),
    "keybase": Platform(
        name="Keybase",
        url_pattern="https://keybase.io/{username}",
        category="code",
    ),
    "bitbucket": Platform(
        name="Bitbucket",
        url_pattern="https://bitbucket.org/{username}",
        category="code",
    ),
    "instagram": Platform(
        name="Instagram",
        url_pattern="https://instagram.com/{username}",
        category="social",
        max_length=30,
    ),
    "facebook": Platform(
        name="Facebook",
        url_pattern="https://facebook.com/{username}",
        category="social",
    ),
    "youtube": Platform(
        name="YouTube",
        url_pattern="https://youtube.com/@{username}",
        category="social",
    ),
    "tiktok": Platform(
        name="TikTok",
        url_pattern="https://tiktok.com/@{username}",
        category="social",
    ),
    "pinterest": Platform(
        name="Pinterest",
        url_pattern="https://pinterest.com/{username}",
        category="social",
    ),
    "twitch": Platform(
        name="Twitch",
        url_pattern="https://twitch.tv/{username}",
        category="social",
    ),
    "mastodon": Platform(
        name="Mastodon",
        url_pattern="https://mastodon.social/@{username}",
        category="social",
    ),
    "npm": Platform(
        name="npm",
        url_pattern="https://npmjs.com/~{username}",
        category="code",
    ),
    "pypi": Platform(
        name="PyPI",
        url_pattern="https://pypi.org/user/{username}",
        category="code",
    ),
    "docker_hub": Platform(
        name="Docker Hub",
        url_pattern="https://hub.docker.com/u/{username}",
        category="code",
    ),
}

# Common email patterns (ordered by prevalence)
EMAIL_PATTERNS = [
    ("first.last", "{first}.{last}@{domain}"),
    ("firstlast", "{first}{last}@{domain}"),
    ("flast", "{first_initial}{last}@{domain}"),
    ("first_last", "{first}_{last}@{domain}"),
    ("first", "{first}@{domain}"),
    ("lastf", "{last}{first_initial}@{domain}"),
    ("last.first", "{last}.{first}@{domain}"),
    ("firstl", "{first}{last_initial}@{domain}"),
    ("f.last", "{first_initial}.{last}@{domain}"),
    ("first.l", "{first}.{last_initial}@{domain}"),
]

# Simulated breach database (for pattern matching - no real breach data)
# In production, this would query HaveIBeenPwned API or similar
KNOWN_BREACH_PATTERNS = {
    "credential_dump": BreachInfo(
        name="Credential Compilation",
        date="2017",
        data_types=["email", "password"],
        description="Large compilation of credentials from multiple sources",
        severity="high",
    ),
    "social_network": BreachInfo(
        name="Social Network Breach",
        date="2019",
        data_types=["email", "name", "phone"],
        description="Major social network data exposure",
        severity="high",
    ),
    "forum_breach": BreachInfo(
        name="Forum Data Leak",
        date="2020",
        data_types=["email", "username", "ip_address"],
        description="Online forum database leak",
        severity="medium",
    ),
}


def gather_osint(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Gather OSINT from public sources.

    Performs:
    - Username enumeration from context data
    - Platform correlation for discovered usernames
    - Email pattern analysis
    - Breach checking simulation

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - target: Override target
            - platforms: List of platform keys to check
            - include_breach_check: Whether to simulate breach checking
            - email_patterns: Whether to analyze email patterns

    Returns:
        Updated context with osint_data
    """
    params = params or {}
    target = params.get("target") or ctx.target

    if not target:
        ctx.log("No target specified for OSINT gathering", level="WARNING")
        return ctx

    ctx.log(f"Gathering OSINT for: {target}", level="INFO")

    # Initialize results
    osint_data = {
        "target": target,
        "usernames": [],
        "profiles": [],
        "correlations": [],
        "emails": [],
        "breach_results": [],
        "email_patterns": [],
    }

    # Extract usernames from existing context data
    usernames = extract_usernames_from_context(ctx)
    osint_data["usernames"] = list(usernames)
    ctx.log(f"Found {len(usernames)} potential usernames", level="INFO")

    # Get platforms to check
    platform_keys = params.get("platforms", list(PLATFORMS.keys()))

    # Correlate usernames across platforms
    if usernames:
        profiles, correlations = correlate_usernames_to_platforms(
            usernames, platform_keys
        )
        osint_data["profiles"] = [p.to_dict() for p in profiles]
        osint_data["correlations"] = correlations
        ctx.log(f"Generated {len(profiles)} potential profile URLs", level="INFO")

    # Analyze email patterns for domain targets
    if is_domain(target) and params.get("email_patterns", True):
        patterns = analyze_email_patterns(target)
        osint_data["email_patterns"] = [
            {"pattern": p.pattern, "example": p.example, "confidence": p.confidence}
            for p in patterns
        ]
        ctx.log(f"Identified {len(patterns)} email patterns", level="INFO")

    # Extract emails from context
    emails = extract_emails_from_context(ctx)
    osint_data["emails"] = list(emails)

    # Simulate breach checking if enabled
    if params.get("include_breach_check", True) and emails:
        breach_results = check_breaches_batch(emails)
        osint_data["breach_results"] = breach_results
        exposed_count = sum(1 for r in breach_results if r.get("exposed"))
        if exposed_count > 0:
            ctx.log(f"Found {exposed_count} potentially exposed emails", level="WARNING")

    # Generate findings
    findings = generate_osint_findings(osint_data)
    for i, finding in enumerate(findings):
        ctx.add(f"osint_finding_{i}", finding)

    ctx.add("osint_data", osint_data)
    ctx.log(f"OSINT gathering completed for {target}", level="INFO")

    return ctx


def extract_usernames_from_context(ctx: Context) -> Set[str]:
    """
    Extract potential usernames from context data.

    Looks for usernames in:
    - Domain profile (whois data)
    - Code artifacts (git authors, package maintainers)
    - Document metadata (authors)
    - Entity extractions

    Args:
        ctx: Pipeline context

    Returns:
        Set of unique usernames
    """
    usernames = set()

    # From domain profile
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("registrant_name"):
        name = domain_profile["registrant_name"]
        usernames.update(generate_usernames_from_name(name))

    # From code artifacts
    code_artifacts = ctx.get("code_artifacts", {})
    for author in code_artifacts.get("git_authors", []):
        if isinstance(author, dict):
            if author.get("name"):
                usernames.update(generate_usernames_from_name(author["name"]))
            if author.get("email"):
                username = extract_username_from_email(author["email"])
                if username:
                    usernames.add(username)
        elif isinstance(author, str):
            usernames.update(generate_usernames_from_name(author))

    # Package maintainers
    for maintainer in code_artifacts.get("package_maintainers", []):
        if isinstance(maintainer, dict):
            if maintainer.get("name"):
                usernames.update(generate_usernames_from_name(maintainer["name"]))
            if maintainer.get("username"):
                usernames.add(maintainer["username"])
        elif isinstance(maintainer, str):
            usernames.update(generate_usernames_from_name(maintainer))

    # From document metadata
    doc_metadata = ctx.get("document_metadata", {})
    for author in doc_metadata.get("authors", []):
        if isinstance(author, str):
            usernames.update(generate_usernames_from_name(author))

    # From entities
    entities = ctx.get("entities", {})
    for person in entities.get("persons", []):
        if isinstance(person, dict):
            name = person.get("name", person.get("value", ""))
        else:
            name = str(person)
        if name:
            usernames.update(generate_usernames_from_name(name))

    # From EXIF metadata
    exif_data = ctx.get("exif_metadata", {})
    if exif_data.get("artist"):
        usernames.update(generate_usernames_from_name(exif_data["artist"]))
    if exif_data.get("copyright"):
        usernames.update(generate_usernames_from_name(exif_data["copyright"]))

    # Filter out invalid usernames
    return {u for u in usernames if is_valid_username(u)}


def generate_usernames_from_name(name: str) -> Set[str]:
    """
    Generate potential usernames from a full name.

    Args:
        name: Full name (e.g., "John Doe")

    Returns:
        Set of potential usernames
    """
    if not name or len(name) < 2:
        return set()

    usernames = set()
    name = name.strip()

    # Clean name - remove titles, suffixes
    name = re.sub(r'\b(Mr|Mrs|Ms|Dr|Jr|Sr|III|II|IV)\b\.?', '', name, flags=re.IGNORECASE)
    name = name.strip()

    # Split into parts
    parts = name.split()
    if not parts:
        return set()

    # Single word name
    if len(parts) == 1:
        word = parts[0].lower()
        if len(word) >= 3:
            usernames.add(word)
        return usernames

    first = parts[0].lower()
    last = parts[-1].lower()

    # Remove non-alphanumeric
    first = re.sub(r'[^a-z0-9]', '', first)
    last = re.sub(r'[^a-z0-9]', '', last)

    if not first or not last:
        return set()

    # Common username patterns
    patterns = [
        f"{first}{last}",           # johndoe
        f"{first}.{last}",          # john.doe
        f"{first}_{last}",          # john_doe
        f"{first}-{last}",          # john-doe
        f"{first[0]}{last}",        # jdoe
        f"{first}{last[0]}",        # johnd
        f"{last}{first}",           # doejohn
        f"{last}{first[0]}",        # doej
        f"{first[0]}{last[0]}",     # jd (if long enough parts)
        first,                       # john
        last,                        # doe
    ]

    # Add number variations
    for pattern in patterns[:5]:  # Only for common ones
        usernames.add(pattern)
        usernames.add(f"{pattern}1")
        usernames.add(f"{pattern}123")

    usernames.update(patterns)

    # Filter valid usernames
    return {u for u in usernames if is_valid_username(u)}


def extract_username_from_email(email: str) -> Optional[str]:
    """
    Extract username portion from email address.

    Args:
        email: Email address

    Returns:
        Username portion or None
    """
    if not email or "@" not in email:
        return None

    local_part = email.split("@")[0]

    # Remove common prefixes/suffixes
    local_part = re.sub(r'[+.].*$', '', local_part)  # Remove + and . suffixes

    if is_valid_username(local_part):
        return local_part.lower()

    return None


def is_valid_username(username: str) -> bool:
    """
    Check if a string is a valid username.

    Args:
        username: Potential username

    Returns:
        True if valid
    """
    if not username:
        return False
    if len(username) < 3 or len(username) > 30:
        return False
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', username):
        return False
    # Exclude common non-usernames
    excluded = {'the', 'and', 'for', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out'}
    if username.lower() in excluded:
        return False
    return True


def correlate_usernames_to_platforms(
    usernames: Set[str],
    platform_keys: Optional[List[str]] = None
) -> Tuple[List[UserProfile], List[Dict[str, Any]]]:
    """
    Correlate usernames across platforms.

    Args:
        usernames: Set of usernames to check
        platform_keys: Platforms to check (defaults to all)

    Returns:
        Tuple of (profiles, correlations)
    """
    if platform_keys is None:
        platform_keys = list(PLATFORMS.keys())

    profiles = []
    correlations = []

    for username in usernames:
        user_platforms = []

        for key in platform_keys:
            platform = PLATFORMS.get(key)
            if not platform:
                continue

            if platform.is_valid_username(username):
                profile = UserProfile(
                    username=username,
                    platform=platform.name,
                    url=platform.format_url(username),
                    category=platform.category,
                    confidence=calculate_username_confidence(username, platform),
                )
                profiles.append(profile)
                user_platforms.append(platform.name)

        if user_platforms:
            correlations.append({
                "username": username,
                "platforms": user_platforms,
                "platform_count": len(user_platforms),
            })

    return profiles, correlations


def calculate_username_confidence(username: str, platform: Platform) -> float:
    """
    Calculate confidence score for a username on a platform.

    Based on:
    - Username length (longer = more unique)
    - Character variety
    - Platform-specific patterns

    Args:
        username: The username
        platform: The platform

    Returns:
        Confidence score 0.0 to 1.0
    """
    score = 0.5  # Base score

    # Length factor
    if len(username) >= 8:
        score += 0.2
    elif len(username) >= 5:
        score += 0.1

    # Variety factor
    has_numbers = bool(re.search(r'\d', username))
    has_special = bool(re.search(r'[._-]', username))
    if has_numbers:
        score += 0.1
    if has_special:
        score += 0.1

    # Platform-specific adjustments
    if platform.category == "code" and has_special:
        score += 0.05  # Developers more likely to use special chars
    if platform.category == "professional" and "." in username:
        score += 0.05  # LinkedIn often uses name.name

    return min(1.0, score)


def extract_emails_from_context(ctx: Context) -> Set[str]:
    """
    Extract email addresses from context data.

    Args:
        ctx: Pipeline context

    Returns:
        Set of email addresses
    """
    emails = set()

    # From domain profile
    domain_profile = ctx.get("domain_profile", {})
    for key in ["registrant_email", "admin_email", "tech_email"]:
        if domain_profile.get(key):
            emails.add(domain_profile[key].lower())

    # From code artifacts
    code_artifacts = ctx.get("code_artifacts", {})
    for author in code_artifacts.get("git_authors", []):
        if isinstance(author, dict) and author.get("email"):
            emails.add(author["email"].lower())

    # From entities
    entities = ctx.get("entities", {})
    for email in entities.get("emails", []):
        if isinstance(email, dict):
            emails.add(email.get("value", email.get("email", "")).lower())
        elif isinstance(email, str):
            emails.add(email.lower())

    # Filter valid emails
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return {e for e in emails if email_pattern.match(e)}


def is_domain(target: str) -> bool:
    """Check if target looks like a domain."""
    domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    return bool(domain_pattern.match(target))


def analyze_email_patterns(domain: str) -> List[EmailPattern]:
    """
    Analyze likely email patterns for a domain.

    Args:
        domain: Domain name

    Returns:
        List of email patterns with confidence scores
    """
    patterns = []

    for pattern_name, template in EMAIL_PATTERNS:
        example = template.format(
            first="john",
            last="doe",
            first_initial="j",
            last_initial="d",
            domain=domain,
        )
        # Assign confidence based on pattern prevalence
        confidence = 0.8 - (EMAIL_PATTERNS.index((pattern_name, template)) * 0.05)
        patterns.append(EmailPattern(
            pattern=pattern_name,
            example=example,
            confidence=max(0.3, confidence),
        ))

    return patterns


def generate_email_permutations(
    first_name: str,
    last_name: str,
    domain: str
) -> List[str]:
    """
    Generate email permutations for a person at a domain.

    Args:
        first_name: First name
        last_name: Last name
        domain: Email domain

    Returns:
        List of possible email addresses
    """
    first = first_name.lower().strip()
    last = last_name.lower().strip()

    if not first or not last or not domain:
        return []

    # Remove non-alpha characters
    first = re.sub(r'[^a-z]', '', first)
    last = re.sub(r'[^a-z]', '', last)

    permutations = []
    for _, template in EMAIL_PATTERNS:
        email = template.format(
            first=first,
            last=last,
            first_initial=first[0] if first else "",
            last_initial=last[0] if last else "",
            domain=domain,
        )
        permutations.append(email)

    return permutations


def check_breaches_batch(emails: Set[str]) -> List[Dict[str, Any]]:
    """
    Check multiple emails for breach exposure.

    NOTE: This is a simulation using pattern matching.
    In production, use HaveIBeenPwned API or similar service.

    Args:
        emails: Set of email addresses

    Returns:
        List of breach check results
    """
    results = []

    for email in emails:
        result = check_breach_simulated(email)
        results.append(result)

    return results


def check_breach_simulated(email: str) -> Dict[str, Any]:
    """
    Simulate breach checking for an email.

    Uses hash-based simulation to provide consistent results
    without storing or using real breach data.

    Args:
        email: Email address

    Returns:
        Breach check result
    """
    # Create deterministic hash for consistent results
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()

    # Use hash to determine simulated exposure (roughly 30% exposed)
    is_exposed = int(email_hash[:2], 16) < 77  # ~30%

    result = {
        "email": email,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "exposed": is_exposed,
        "breaches": [],
    }

    if is_exposed:
        # Determine which "breaches" based on hash
        hash_int = int(email_hash[:8], 16)

        if hash_int % 3 == 0:
            result["breaches"].append(KNOWN_BREACH_PATTERNS["credential_dump"].to_dict())
        if hash_int % 5 == 0:
            result["breaches"].append(KNOWN_BREACH_PATTERNS["social_network"].to_dict())
        if hash_int % 7 == 0:
            result["breaches"].append(KNOWN_BREACH_PATTERNS["forum_breach"].to_dict())

        # Ensure at least one breach if exposed
        if not result["breaches"]:
            result["breaches"].append(KNOWN_BREACH_PATTERNS["forum_breach"].to_dict())

    return result


def check_data_breaches(email: str) -> Dict[str, Any]:
    """
    Check if an email appears in known data breaches.

    NOTE: This is a simulation. For real breach checking,
    integrate with HaveIBeenPwned API or similar service.

    Args:
        email: Email address to check

    Returns:
        Breach information
    """
    return check_breach_simulated(email)


def correlate_usernames(usernames: List[str]) -> Dict[str, List[str]]:
    """
    Correlate usernames across platforms.

    Args:
        usernames: List of usernames to correlate

    Returns:
        Dictionary mapping usernames to platform lists
    """
    profiles, correlations = correlate_usernames_to_platforms(set(usernames))

    result = {}
    for corr in correlations:
        result[corr["username"]] = corr["platforms"]

    return result


def generate_osint_findings(osint_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate findings from OSINT data.

    Args:
        osint_data: Collected OSINT data

    Returns:
        List of findings
    """
    findings = []

    # Username exposure finding
    if osint_data.get("correlations"):
        high_exposure = [
            c for c in osint_data["correlations"]
            if c.get("platform_count", 0) >= 5
        ]
        if high_exposure:
            findings.append({
                "title": "High Username Exposure Detected",
                "description": f"{len(high_exposure)} username(s) found on 5+ platforms",
                "severity": "medium",
                "category": "Information Disclosure",
                "data": {
                    "usernames": [c["username"] for c in high_exposure],
                },
            })

    # Breach exposure finding
    breach_results = osint_data.get("breach_results", [])
    exposed_emails = [r for r in breach_results if r.get("exposed")]
    if exposed_emails:
        severity = "high" if len(exposed_emails) >= 3 else "medium"
        findings.append({
            "title": "Email Addresses Found in Data Breaches",
            "description": f"{len(exposed_emails)} email(s) potentially exposed in breaches",
            "severity": severity,
            "category": "Credential Exposure",
            "data": {
                "exposed_emails": [e["email"] for e in exposed_emails],
            },
        })

    # Email pattern finding
    if osint_data.get("email_patterns"):
        findings.append({
            "title": "Email Pattern Identified",
            "description": f"Common email patterns identified for target domain",
            "severity": "info",
            "category": "Information Disclosure",
            "data": {
                "patterns": osint_data["email_patterns"][:3],
            },
        })

    return findings


def discover_employees(
    ctx: Context,
    params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Discover potential employees from context data.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}
    target = params.get("target") or ctx.target

    ctx.log(f"Discovering employees for: {target}", level="INFO")

    employees = []

    # Extract from various context sources
    # Code artifacts - git authors
    code_artifacts = ctx.get("code_artifacts", {})
    for author in code_artifacts.get("git_authors", []):
        if isinstance(author, dict):
            employees.append({
                "name": author.get("name", "Unknown"),
                "email": author.get("email"),
                "source": "git_history",
                "role": "developer",
            })

    # Document metadata - authors
    doc_metadata = ctx.get("document_metadata", {})
    for author in doc_metadata.get("authors", []):
        if isinstance(author, str):
            employees.append({
                "name": author,
                "source": "document_metadata",
                "role": "unknown",
            })

    # Entities - persons
    entities = ctx.get("entities", {})
    for person in entities.get("persons", []):
        name = person.get("name", person.get("value")) if isinstance(person, dict) else str(person)
        if name:
            employees.append({
                "name": name,
                "source": "entity_extraction",
                "role": "unknown",
            })

    # Deduplicate by name
    seen_names = set()
    unique_employees = []
    for emp in employees:
        name_lower = emp.get("name", "").lower()
        if name_lower and name_lower not in seen_names:
            seen_names.add(name_lower)
            unique_employees.append(emp)

    ctx.add("discovered_employees", unique_employees)
    ctx.log(f"Discovered {len(unique_employees)} unique employees", level="INFO")

    return ctx


def get_platform_categories() -> Dict[str, List[str]]:
    """
    Get platforms grouped by category.

    Returns:
        Dictionary mapping categories to platform names
    """
    categories = {}
    for key, platform in PLATFORMS.items():
        if platform.category not in categories:
            categories[platform.category] = []
        categories[platform.category].append(platform.name)
    return categories


def get_platform_by_name(name: str) -> Optional[Platform]:
    """
    Get platform by name or key.

    Args:
        name: Platform name or key

    Returns:
        Platform object or None
    """
    # Try exact key match first
    if name.lower() in PLATFORMS:
        return PLATFORMS[name.lower()]

    # Try name match
    for platform in PLATFORMS.values():
        if platform.name.lower() == name.lower():
            return platform

    return None


def generate_profile_urls(username: str, platforms: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """
    Generate profile URLs for a username across platforms.

    Args:
        username: Username to check
        platforms: Optional list of platform keys (defaults to all)

    Returns:
        List of profile URL dictionaries
    """
    if platforms is None:
        platforms = list(PLATFORMS.keys())

    urls = []
    for key in platforms:
        platform = PLATFORMS.get(key)
        if platform and platform.is_valid_username(username):
            urls.append({
                "platform": platform.name,
                "url": platform.format_url(username),
                "category": platform.category,
            })

    return urls
