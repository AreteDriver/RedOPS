"""
Hunter.io Intelligence module.

Queries Hunter.io API for email discovery:
- Domain email patterns
- Email addresses associated with a domain
- Email verification
- Company information

IMPORTANT: Requires a Hunter.io API key.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import os

from redops.core.context import Context


@dataclass
class HunterDomainResult:
    """Hunter.io domain search result."""

    domain: str
    organization: Optional[str] = None
    disposable: bool = False
    webmail: bool = False
    accept_all: bool = False
    pattern: Optional[str] = None
    emails: List[Dict[str, Any]] = field(default_factory=list)
    linked_domains: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "organization": self.organization,
            "disposable": self.disposable,
            "webmail": self.webmail,
            "accept_all": self.accept_all,
            "pattern": self.pattern,
            "emails": self.emails,
            "linked_domains": self.linked_domains,
        }


@dataclass
class HunterEmail:
    """Hunter.io email result."""

    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    position: Optional[str] = None
    department: Optional[str] = None
    linkedin: Optional[str] = None
    twitter: Optional[str] = None
    confidence: int = 0
    sources: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "position": self.position,
            "department": self.department,
            "linkedin": self.linkedin,
            "twitter": self.twitter,
            "confidence": self.confidence,
            "sources": self.sources,
        }


def get_hunter_api_key() -> Optional[str]:
    """Get Hunter.io API key."""
    api_key = os.environ.get("HUNTER_API_KEY")
    if not api_key:
        try:
            from redops.cli.settings import get_api_key_direct
            api_key = get_api_key_direct("hunter")
        except Exception:
            pass
    return api_key


def _make_hunter_request(endpoint: str, api_key: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
    """Make a request to Hunter.io API."""
    try:
        import requests
    except ImportError:
        return None

    url = f"https://api.hunter.io/v2/{endpoint}"
    request_params = {"api_key": api_key}
    if params:
        request_params.update(params)

    try:
        response = requests.get(url, params=request_params, timeout=30)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "not_found"}
        elif response.status_code == 429:
            return {"error": "rate_limited"}
        elif response.status_code == 401:
            return {"error": "invalid_api_key"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def query_hunter_domain(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query Hunter.io for domain email information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)
            - limit: Maximum emails to return (default: 10)

    Returns:
        Updated context with Hunter.io domain data
    """
    params = params or {}
    target = params.get("domain") or ctx.target
    limit = params.get("limit", 10)

    if not target:
        ctx.log("No target specified for Hunter.io query", level="WARNING")
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying Hunter.io for domain: {domain}", level="INFO")

    hunter_data = {
        "domain": domain,
        "result": None,
        "error": None,
    }

    api_key = get_hunter_api_key()
    if not api_key:
        hunter_data["error"] = "Hunter.io API key not configured"
        ctx.log(hunter_data["error"], level="WARNING")
        ctx.add("hunter_domain", hunter_data)
        return ctx

    result = _make_hunter_request("domain-search", api_key, {
        "domain": domain,
        "limit": limit,
    })

    if result is None:
        hunter_data["error"] = "requests library not available"
    elif "error" in result:
        hunter_data["error"] = result["error"]
    elif "errors" in result:
        hunter_data["error"] = result["errors"][0].get("details", "Unknown error")
    else:
        data = result.get("data", {})
        domain_result = HunterDomainResult(
            domain=data.get("domain", domain),
            organization=data.get("organization"),
            disposable=data.get("disposable", False),
            webmail=data.get("webmail", False),
            accept_all=data.get("accept_all", False),
            pattern=data.get("pattern"),
            linked_domains=data.get("linked_domains", []),
        )

        # Parse emails
        for email_data in data.get("emails", []):
            email = HunterEmail(
                email=email_data.get("value", ""),
                first_name=email_data.get("first_name"),
                last_name=email_data.get("last_name"),
                position=email_data.get("position"),
                department=email_data.get("department"),
                linkedin=email_data.get("linkedin"),
                twitter=email_data.get("twitter"),
                confidence=email_data.get("confidence", 0),
                sources=email_data.get("sources", []),
            )
            domain_result.emails.append(email.to_dict())

        hunter_data["result"] = domain_result.to_dict()

        ctx.log(
            f"Hunter.io: found {len(domain_result.emails)} emails, pattern: {domain_result.pattern}",
            level="INFO",
        )

    ctx.add("hunter_domain", hunter_data)
    return ctx


def query_hunter_email_count(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query Hunter.io for email count on a domain.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)

    Returns:
        Updated context with email count
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log("No target specified for Hunter.io count query", level="WARNING")
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying Hunter.io email count for: {domain}", level="INFO")

    hunter_data = {
        "domain": domain,
        "count": 0,
        "error": None,
    }

    api_key = get_hunter_api_key()
    if not api_key:
        hunter_data["error"] = "Hunter.io API key not configured"
        ctx.log(hunter_data["error"], level="WARNING")
        ctx.add("hunter_count", hunter_data)
        return ctx

    result = _make_hunter_request("email-count", api_key, {"domain": domain})

    if result is None:
        hunter_data["error"] = "requests library not available"
    elif "error" in result:
        hunter_data["error"] = result["error"]
    else:
        data = result.get("data", {})
        hunter_data["count"] = data.get("total", 0)
        hunter_data["personal_emails"] = data.get("personal_emails", 0)
        hunter_data["generic_emails"] = data.get("generic_emails", 0)
        hunter_data["department"] = data.get("department", {})

        ctx.log(
            f"Hunter.io: {hunter_data['count']} total emails on domain",
            level="INFO",
        )

    ctx.add("hunter_count", hunter_data)
    return ctx


def verify_hunter_email(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Verify an email address using Hunter.io.

    Args:
        ctx: Pipeline context
        params: Required parameters:
            - email: Email address to verify

    Returns:
        Updated context with verification result
    """
    params = params or {}
    email = params.get("email")

    if not email:
        ctx.log("No email specified for Hunter.io verification", level="WARNING")
        return ctx

    ctx.log(f"Verifying email with Hunter.io: {email}", level="INFO")

    hunter_data = {
        "email": email,
        "result": None,
        "error": None,
    }

    api_key = get_hunter_api_key()
    if not api_key:
        hunter_data["error"] = "Hunter.io API key not configured"
        ctx.log(hunter_data["error"], level="WARNING")
        ctx.add("hunter_verify", hunter_data)
        return ctx

    result = _make_hunter_request("email-verifier", api_key, {"email": email})

    if result is None:
        hunter_data["error"] = "requests library not available"
    elif "error" in result:
        hunter_data["error"] = result["error"]
    else:
        data = result.get("data", {})
        hunter_data["result"] = {
            "status": data.get("status"),
            "result": data.get("result"),
            "score": data.get("score"),
            "email": data.get("email"),
            "regexp": data.get("regexp"),
            "gibberish": data.get("gibberish"),
            "disposable": data.get("disposable"),
            "webmail": data.get("webmail"),
            "mx_records": data.get("mx_records"),
            "smtp_server": data.get("smtp_server"),
            "smtp_check": data.get("smtp_check"),
            "accept_all": data.get("accept_all"),
            "block": data.get("block"),
        }

        ctx.log(
            f"Hunter.io verify: {data.get('result')} (score: {data.get('score')})",
            level="INFO",
        )

    ctx.add("hunter_verify", hunter_data)
    return ctx


def analyze_hunter_intel(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Run comprehensive Hunter.io analysis.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context with Hunter.io intel
    """
    params = params or {}
    target = ctx.target

    ctx.log(f"Running Hunter.io intelligence for: {target}", level="INFO")

    # Query domain
    ctx = query_hunter_domain(ctx, params)

    # Query email count
    ctx = query_hunter_email_count(ctx, params)

    # Compile summary
    hunter_intel = {
        "target": target,
        "domain": ctx.get("hunter_domain", {}),
        "count": ctx.get("hunter_count", {}),
        "summary": {},
    }

    # Generate summary
    domain_data = hunter_intel["domain"]
    count_data = hunter_intel["count"]

    if domain_data.get("result"):
        result = domain_data["result"]
        hunter_intel["summary"]["organization"] = result.get("organization")
        hunter_intel["summary"]["email_pattern"] = result.get("pattern")
        hunter_intel["summary"]["emails_found"] = len(result.get("emails", []))
        hunter_intel["summary"]["linked_domains"] = result.get("linked_domains", [])

        # Extract unique departments
        departments = set()
        for email in result.get("emails", []):
            if email.get("department"):
                departments.add(email["department"])
        hunter_intel["summary"]["departments"] = list(departments)

    if count_data.get("count"):
        hunter_intel["summary"]["total_emails"] = count_data["count"]
        hunter_intel["summary"]["personal_emails"] = count_data.get("personal_emails", 0)
        hunter_intel["summary"]["generic_emails"] = count_data.get("generic_emails", 0)

    ctx.add("hunter_intel", hunter_intel)

    email_count = hunter_intel["summary"].get("emails_found", 0)
    ctx.log(
        f"Hunter.io intel complete: {email_count} emails found",
        level="INFO",
    )

    return ctx


# Helper function

def _extract_domain(value: str) -> str:
    """Extract domain from URL or hostname."""
    if "://" in value:
        value = value.split("://", 1)[1]
    if "/" in value:
        value = value.split("/", 1)[0]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value
