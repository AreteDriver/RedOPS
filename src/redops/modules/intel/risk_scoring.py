"""
Risk scoring module.

Analyzes findings from reconnaissance and assigns risk scores based on
likelihood and impact. Maps findings to industry frameworks (OWASP, MITRE).
"""

from typing import Optional, Dict, Any, List, Tuple
from redops.core.context import Context
from redops.core.models import Risk, RiskLevel, RiskCategory


# Risk scoring rules for different finding types
# Format: (likelihood, impact, category, mitre_id, owasp_id, recommendation)
RISK_RULES: Dict[str, Dict[str, Any]] = {
    # Security Header Findings
    "missing_hsts": {
        "likelihood": 3,
        "impact": 3,
        "category": RiskCategory.OWASP,
        "owasp_id": "A05:2021",  # Security Misconfiguration
        "mitre_id": None,
        "recommendation": "Enable HSTS with a minimum max-age of 31536000 seconds",
    },
    "missing_csp": {
        "likelihood": 4,
        "impact": 4,
        "category": RiskCategory.OWASP,
        "owasp_id": "A03:2021",  # Injection
        "mitre_id": None,
        "recommendation": "Implement Content-Security-Policy to prevent XSS attacks",
    },
    "missing_x_frame_options": {
        "likelihood": 3,
        "impact": 3,
        "category": RiskCategory.OWASP,
        "owasp_id": "A05:2021",
        "mitre_id": None,
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN header",
    },
    "missing_x_content_type_options": {
        "likelihood": 2,
        "impact": 2,
        "category": RiskCategory.OWASP,
        "owasp_id": "A05:2021",
        "mitre_id": None,
        "recommendation": "Add X-Content-Type-Options: nosniff header",
    },

    # DNS/Email Security Findings
    "missing_spf": {
        "likelihood": 4,
        "impact": 4,
        "category": RiskCategory.EXPOSURE,
        "owasp_id": None,
        "mitre_id": "T1566",  # Phishing
        "recommendation": "Add SPF record to prevent email spoofing",
    },
    "missing_dmarc": {
        "likelihood": 3,
        "impact": 4,
        "category": RiskCategory.EXPOSURE,
        "owasp_id": None,
        "mitre_id": "T1566",
        "recommendation": "Implement DMARC policy to protect against email spoofing",
    },
    "zone_transfer_allowed": {
        "likelihood": 2,
        "impact": 5,
        "category": RiskCategory.EXPOSURE,
        "owasp_id": "A01:2021",  # Broken Access Control
        "mitre_id": "T1590.002",  # DNS
        "recommendation": "Restrict DNS zone transfers to authorized servers only",
    },

    # Version Disclosure
    "server_version_disclosure": {
        "likelihood": 4,
        "impact": 2,
        "category": RiskCategory.EXPOSURE,
        "owasp_id": "A05:2021",
        "mitre_id": "T1592",  # Gather Victim Host Information
        "recommendation": "Remove version information from server headers",
    },

    # Technology Risks
    "outdated_framework": {
        "likelihood": 3,
        "impact": 4,
        "category": RiskCategory.OWASP,
        "owasp_id": "A06:2021",  # Vulnerable Components
        "mitre_id": None,
        "recommendation": "Update to the latest stable version of the framework",
    },
    "wordpress_detected": {
        "likelihood": 3,
        "impact": 3,
        "category": RiskCategory.OWASP,
        "owasp_id": "A06:2021",
        "mitre_id": "T1190",  # Exploit Public-Facing Application
        "recommendation": "Ensure WordPress core, themes, and plugins are up to date",
    },

    # SSL/TLS Risks
    "ssl_expiring_soon": {
        "likelihood": 4,
        "impact": 3,
        "category": RiskCategory.OPERATIONAL,
        "owasp_id": None,
        "mitre_id": None,
        "recommendation": "Renew SSL certificate before expiration",
    },
    "ssl_weak_cipher": {
        "likelihood": 3,
        "impact": 4,
        "category": RiskCategory.OWASP,
        "owasp_id": "A02:2021",  # Cryptographic Failures
        "mitre_id": None,
        "recommendation": "Disable weak cipher suites and enable TLS 1.2+",
    },

    # Subdomain Risks
    "excessive_subdomains": {
        "likelihood": 2,
        "impact": 2,
        "category": RiskCategory.EXPOSURE,
        "owasp_id": None,
        "mitre_id": "T1590.002",
        "recommendation": "Review and consolidate subdomains; remove unused ones",
    },
    "dev_staging_exposed": {
        "likelihood": 4,
        "impact": 4,
        "category": RiskCategory.EXPOSURE,
        "owasp_id": "A05:2021",
        "mitre_id": "T1590",
        "recommendation": "Restrict access to development/staging environments",
    },
}


def score_risks(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Calculate risk scores for findings in the context.

    Analyzes all findings (finding_* keys) and creates prioritized risks
    with likelihood/impact scores mapped to industry frameworks.

    Args:
        ctx: Pipeline context with findings
        params: Optional parameters
            - include_info: Include INFO-level risks (default: False)
            - min_score: Minimum risk score to include (default: 1)

    Returns:
        Updated context with risks list and risk_summary
    """
    params = params or {}
    include_info = params.get("include_info", False)
    min_score = params.get("min_score", 1)

    ctx.log("Analyzing findings for risk scoring", level="INFO")

    # Collect all findings from context
    findings = extract_findings(ctx)
    ctx.log(f"Found {len(findings)} findings to analyze", level="DEBUG")

    # Score each finding
    risks: List[Risk] = []

    for finding_key, finding_data in findings.items():
        finding_risks = score_finding(finding_key, finding_data, ctx)
        risks.extend(finding_risks)

    # Also check for implicit risks (things NOT found that should be)
    implicit_risks = check_implicit_risks(ctx)
    risks.extend(implicit_risks)

    # Filter by minimum score
    if min_score > 1:
        risks = [r for r in risks if r.score >= min_score]

    # Filter out INFO if not requested
    if not include_info:
        risks = [r for r in risks if r.level != RiskLevel.INFO]

    # Sort by score descending (highest risk first)
    risks.sort(key=lambda r: r.score, reverse=True)

    # Generate summary statistics
    risk_summary = aggregate_risks(risks)

    # Add to context
    ctx.add("risks", [r.model_dump() for r in risks])
    ctx.add("risk_summary", risk_summary)

    # Log summary
    ctx.log(f"Risk scoring completed: {len(risks)} risks identified", level="INFO")
    if risk_summary["by_level"]["critical"] > 0:
        ctx.log(f"CRITICAL risks found: {risk_summary['by_level']['critical']}", level="WARNING")
    if risk_summary["by_level"]["high"] > 0:
        ctx.log(f"HIGH risks found: {risk_summary['by_level']['high']}", level="WARNING")

    return ctx


def extract_findings(ctx: Context) -> Dict[str, Dict[str, Any]]:
    """
    Extract all findings from the context.

    Findings are stored with keys starting with 'finding_'.

    Args:
        ctx: Pipeline context

    Returns:
        Dictionary of finding_key -> finding_data
    """
    findings = {}
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            findings[key] = value
    return findings


def score_finding(finding_key: str, finding_data: Dict[str, Any], ctx: Context) -> List[Risk]:
    """
    Score a single finding and create Risk objects.

    Args:
        finding_key: The context key for this finding
        finding_data: The finding data dictionary
        ctx: Pipeline context for additional data

    Returns:
        List of Risk objects (usually one, but can be multiple)
    """
    risks = []

    title = finding_data.get("title", "")
    description = finding_data.get("description", "")
    severity = finding_data.get("severity", "info")
    data = finding_data.get("data", {})

    # Map finding to risk rule based on content
    risk_type = identify_risk_type(finding_key, title, description, data)

    if risk_type and risk_type in RISK_RULES:
        rule = RISK_RULES[risk_type]
        risk = Risk(
            title=title,
            description=f"{description}. {rule['recommendation']}",
            likelihood=rule["likelihood"],
            impact=rule["impact"],
            category=rule["category"],
            mitre_id=rule["mitre_id"],
            owasp_id=rule["owasp_id"],
        )
        risks.append(risk)
    elif severity in ["high", "critical"]:
        # Create a generic risk for high/critical findings without specific rules
        risk = Risk(
            title=title,
            description=description,
            likelihood=3,
            impact=4 if severity == "critical" else 3,
            category=RiskCategory.EXPOSURE,
        )
        risks.append(risk)
    elif severity == "medium":
        risk = Risk(
            title=title,
            description=description,
            likelihood=2,
            impact=3,
            category=RiskCategory.EXPOSURE,
        )
        risks.append(risk)

    return risks


def identify_risk_type(
    finding_key: str,
    title: str,
    description: str,
    data: Dict[str, Any]
) -> Optional[str]:
    """
    Identify the risk type from finding content.

    Args:
        finding_key: The context key
        title: Finding title
        description: Finding description
        data: Finding data

    Returns:
        Risk type string or None
    """
    title_lower = title.lower()
    desc_lower = description.lower()
    combined = f"{title_lower} {desc_lower}"

    # Security headers
    if "strict-transport-security" in combined or "hsts" in combined:
        return "missing_hsts"
    if "content-security-policy" in combined or "csp" in combined:
        return "missing_csp"
    if "x-frame-options" in combined:
        return "missing_x_frame_options"
    if "x-content-type-options" in combined:
        return "missing_x_content_type_options"

    # DNS/Email
    if "spf" in combined and ("missing" in combined or "no spf" in combined):
        return "missing_spf"
    if "dmarc" in combined and "missing" in combined:
        return "missing_dmarc"
    if "zone transfer" in combined:
        return "zone_transfer_allowed"

    # Version disclosure
    if "version" in combined and ("disclosure" in combined or "disclosed" in combined):
        return "server_version_disclosure"

    # CMS detection
    if "wordpress" in combined:
        return "wordpress_detected"

    # Subdomains
    if "subdomain" in combined:
        # Check for dev/staging
        subdomains = data.get("subdomains", [])
        for sub in subdomains:
            sub_name = sub.get("subdomain", "") if isinstance(sub, dict) else str(sub)
            if any(env in sub_name.lower() for env in ["dev", "staging", "test", "uat", "qa"]):
                return "dev_staging_exposed"
        if len(subdomains) > 20:
            return "excessive_subdomains"

    return None


def check_implicit_risks(ctx: Context) -> List[Risk]:
    """
    Check for implicit risks based on missing security controls.

    Args:
        ctx: Pipeline context

    Returns:
        List of Risk objects for implicit issues
    """
    risks = []

    # Check domain profile for missing email security
    domain_profile = ctx.get("domain_profile", {})

    if domain_profile:
        # Check for missing DMARC (SPF is already checked in domains.py)
        if not domain_profile.get("has_dmarc", True):
            # Only add if no explicit finding exists
            existing_findings = [k for k in ctx.data.keys() if "dmarc" in k.lower()]
            if not existing_findings:
                rule = RISK_RULES["missing_dmarc"]
                risk = Risk(
                    title="Missing DMARC Record",
                    description=f"No DMARC record found. {rule['recommendation']}",
                    likelihood=rule["likelihood"],
                    impact=rule["impact"],
                    category=rule["category"],
                    mitre_id=rule["mitre_id"],
                )
                risks.append(risk)

    # Check tech stack for SSL issues
    tech_stack = ctx.get("tech_stack", {})
    ssl_info = tech_stack.get("fingerprints", {}).get("ssl", {})

    if ssl_info:
        # Check certificate expiration (if we have the data)
        not_after = ssl_info.get("not_after")
        if not_after:
            # Parse and check expiration
            from datetime import datetime
            try:
                # Format: "Jan 15 12:00:00 2025 GMT"
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (expiry - datetime.now()).days

                if days_until_expiry < 30:
                    rule = RISK_RULES["ssl_expiring_soon"]
                    risk = Risk(
                        title="SSL Certificate Expiring Soon",
                        description=f"Certificate expires in {days_until_expiry} days. {rule['recommendation']}",
                        likelihood=rule["likelihood"],
                        impact=rule["impact"],
                        category=rule["category"],
                    )
                    risks.append(risk)
            except (ValueError, TypeError):
                pass  # Unable to parse date

    return risks


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Calculate risk score from likelihood and impact.

    Uses standard risk matrix: score = likelihood × impact

    Args:
        likelihood: Likelihood score (1-5)
            1 = Rare, 2 = Unlikely, 3 = Possible, 4 = Likely, 5 = Almost Certain
        impact: Impact score (1-5)
            1 = Negligible, 2 = Minor, 3 = Moderate, 4 = Major, 5 = Catastrophic

    Returns:
        Risk score (1-25)
    """
    return likelihood * impact


def categorize_risk(score: int) -> RiskLevel:
    """
    Categorize a risk based on its score.

    Score ranges:
    - 20-25: Critical (immediate action required)
    - 12-19: High (address soon)
    - 6-11: Medium (plan remediation)
    - 3-5: Low (accept or mitigate when convenient)
    - 1-2: Info (informational only)

    Args:
        score: Risk score (1-25)

    Returns:
        Risk level enum
    """
    if score >= 20:
        return RiskLevel.CRITICAL
    elif score >= 12:
        return RiskLevel.HIGH
    elif score >= 6:
        return RiskLevel.MEDIUM
    elif score >= 3:
        return RiskLevel.LOW
    return RiskLevel.INFO


def aggregate_risks(risks: List[Risk]) -> Dict[str, Any]:
    """
    Aggregate risk statistics for reporting.

    Args:
        risks: List of Risk objects

    Returns:
        Dictionary with:
        - total: Total number of risks
        - by_level: Count by risk level
        - by_category: Count by risk category
        - average_score: Average risk score
        - highest_score: Highest risk score
        - top_risks: Top 5 highest-scoring risks
        - mitre_techniques: List of MITRE ATT&CK techniques
        - owasp_categories: List of OWASP categories
    """
    stats = {
        "total": len(risks),
        "by_level": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "by_category": {},
        "average_score": 0.0,
        "highest_score": 0,
        "top_risks": [],
        "mitre_techniques": [],
        "owasp_categories": [],
    }

    if not risks:
        return stats

    total_score = 0
    mitre_ids = set()
    owasp_ids = set()

    for risk in risks:
        # Count by level
        level = risk.level.value
        stats["by_level"][level] = stats["by_level"].get(level, 0) + 1

        # Count by category
        if risk.category:
            cat = risk.category.value
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        # Track scores
        total_score += risk.score
        if risk.score > stats["highest_score"]:
            stats["highest_score"] = risk.score

        # Collect framework IDs
        if risk.mitre_id:
            mitre_ids.add(risk.mitre_id)
        if risk.owasp_id:
            owasp_ids.add(risk.owasp_id)

    stats["average_score"] = round(total_score / len(risks), 2)
    stats["top_risks"] = [
        {"title": r.title, "score": r.score, "level": r.level.value}
        for r in risks[:5]
    ]
    stats["mitre_techniques"] = sorted(list(mitre_ids))
    stats["owasp_categories"] = sorted(list(owasp_ids))

    return stats


def prioritize_risks(risks: List[Risk], limit: int = 10) -> List[Risk]:
    """
    Get the highest-priority risks for immediate attention.

    Args:
        risks: List of all risks
        limit: Maximum number to return

    Returns:
        Top N risks sorted by score
    """
    return sorted(risks, key=lambda r: r.score, reverse=True)[:limit]


def get_remediation_plan(risks: List[Risk]) -> List[Dict[str, Any]]:
    """
    Generate a remediation plan from risks.

    Groups risks by category and priority for actionable output.

    Args:
        risks: List of Risk objects

    Returns:
        List of remediation items with priority and actions
    """
    plan = []

    # Group by priority
    critical_high = [r for r in risks if r.level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
    medium = [r for r in risks if r.level == RiskLevel.MEDIUM]
    low = [r for r in risks if r.level == RiskLevel.LOW]

    if critical_high:
        plan.append({
            "priority": "Immediate",
            "timeframe": "Within 24-48 hours",
            "items": [
                {
                    "risk": r.title,
                    "score": r.score,
                    "action": r.description,
                    "category": r.category.value if r.category else "general",
                }
                for r in critical_high
            ],
        })

    if medium:
        plan.append({
            "priority": "Short-term",
            "timeframe": "Within 1-2 weeks",
            "items": [
                {
                    "risk": r.title,
                    "score": r.score,
                    "action": r.description,
                    "category": r.category.value if r.category else "general",
                }
                for r in medium
            ],
        })

    if low:
        plan.append({
            "priority": "Long-term",
            "timeframe": "Within 1-3 months",
            "items": [
                {
                    "risk": r.title,
                    "score": r.score,
                    "action": r.description,
                    "category": r.category.value if r.category else "general",
                }
                for r in low
            ],
        })

    return plan
