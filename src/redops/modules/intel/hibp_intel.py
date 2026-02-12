"""
Have I Been Pwned Intelligence module.

Queries Have I Been Pwned API for breach data:
- Domain breach search
- Email breach lookup
- Paste data
- Breach details

IMPORTANT: Requires a Have I Been Pwned API key for most endpoints.
https://haveibeenpwned.com/API/Key
"""

from typing import Any
from dataclasses import dataclass, field
import os

from redops.core.context import Context


@dataclass
class HIBPBreach:
    """Have I Been Pwned breach record."""

    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str | None = None
    modified_date: str | None = None
    pwn_count: int = 0
    description: str | None = None
    logo_path: str | None = None
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_malware: bool = False
    is_subscription_free: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "added_date": self.added_date,
            "modified_date": self.modified_date,
            "pwn_count": self.pwn_count,
            "description": self.description,
            "logo_path": self.logo_path,
            "data_classes": self.data_classes,
            "is_verified": self.is_verified,
            "is_fabricated": self.is_fabricated,
            "is_sensitive": self.is_sensitive,
            "is_retired": self.is_retired,
            "is_spam_list": self.is_spam_list,
            "is_malware": self.is_malware,
            "is_subscription_free": self.is_subscription_free,
        }


@dataclass
class HIBPPaste:
    """Have I Been Pwned paste record."""

    source: str
    id: str
    title: str | None = None
    date: str | None = None
    email_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "id": self.id,
            "title": self.title,
            "date": self.date,
            "email_count": self.email_count,
        }


def get_hibp_api_key() -> str | None:
    """Get HIBP API key."""
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        try:
            from redops.cli.settings import get_api_key_direct

            api_key = get_api_key_direct("hibp")
        except Exception:
            pass
    return api_key


def _make_hibp_request(
    endpoint: str,
    api_key: str | None = None,
    user_agent: str = "RedOPS-Security-Scanner",
) -> dict[str, Any] | None:
    """Make a request to HIBP API."""
    try:
        import requests
    except ImportError:
        return None

    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json",
    }

    if api_key:
        headers["hibp-api-key"] = api_key

    url = f"https://haveibeenpwned.com/api/v3/{endpoint}"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"result": "not_found"}
        elif response.status_code == 401:
            return {"error": "api_key_required"}
        elif response.status_code == 403:
            return {"error": "forbidden"}
        elif response.status_code == 429:
            return {"error": "rate_limited"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def query_hibp_breaches(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Query HIBP for all breaches (no API key required).

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Filter by breached domain

    Returns:
        Updated context with breach list
    """
    params = params or {}
    domain_filter = params.get("domain")

    ctx.log("Querying HIBP for all breaches", level="INFO")

    hibp_data = {
        "breaches": [],
        "error": None,
    }

    endpoint = "breaches"
    if domain_filter:
        endpoint = f"breaches?domain={domain_filter}"

    result = _make_hibp_request(endpoint)

    if result is None:
        hibp_data["error"] = "requests library not available"
    elif "error" in result:
        hibp_data["error"] = result["error"]
    elif isinstance(result, list):
        for breach_data in result:
            breach = HIBPBreach(
                name=breach_data.get("Name", ""),
                title=breach_data.get("Title", ""),
                domain=breach_data.get("Domain", ""),
                breach_date=breach_data.get("BreachDate", ""),
                added_date=breach_data.get("AddedDate"),
                modified_date=breach_data.get("ModifiedDate"),
                pwn_count=breach_data.get("PwnCount", 0),
                description=breach_data.get("Description"),
                logo_path=breach_data.get("LogoPath"),
                data_classes=breach_data.get("DataClasses", []),
                is_verified=breach_data.get("IsVerified", False),
                is_fabricated=breach_data.get("IsFabricated", False),
                is_sensitive=breach_data.get("IsSensitive", False),
                is_retired=breach_data.get("IsRetired", False),
                is_spam_list=breach_data.get("IsSpamList", False),
                is_malware=breach_data.get("IsMalware", False),
                is_subscription_free=breach_data.get("IsSubscriptionFree", False),
            )
            hibp_data["breaches"].append(breach.to_dict())

        ctx.log(f"HIBP: found {len(hibp_data['breaches'])} breaches", level="INFO")

    ctx.add("hibp_breaches", hibp_data)
    return ctx


def query_hibp_domain(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query HIBP for breaches affecting a domain (requires API key).

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to search (default: target)

    Returns:
        Updated context with domain breach data
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log("No target specified for HIBP domain query", level="WARNING")
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying HIBP for domain breaches: {domain}", level="INFO")

    hibp_data = {
        "domain": domain,
        "breached_accounts": [],
        "error": None,
    }

    api_key = get_hibp_api_key()
    if not api_key:
        hibp_data["error"] = "HIBP API key not configured (required for domain search)"
        ctx.log(hibp_data["error"], level="WARNING")
        ctx.add("hibp_domain", hibp_data)
        return ctx

    result = _make_hibp_request(f"breacheddomain/{domain}", api_key)

    if result is None:
        hibp_data["error"] = "requests library not available"
    elif isinstance(result, list):
        hibp_data["breached_accounts"] = result
        total_accounts = len(result)
        ctx.log(f"HIBP: {total_accounts} breached accounts for {domain}", level="INFO")
    elif isinstance(result, dict) and "error" in result:
        hibp_data["error"] = result["error"]
    elif isinstance(result, dict) and result.get("result") == "not_found":
        hibp_data["breached_accounts"] = []
        ctx.log(f"HIBP: no breaches found for {domain}", level="INFO")

    ctx.add("hibp_domain", hibp_data)
    return ctx


def query_hibp_email(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query HIBP for breaches affecting an email (requires API key).

    Args:
        ctx: Pipeline context
        params: Required parameters:
            - email: Email address to check

    Returns:
        Updated context with email breach data
    """
    params = params or {}
    email = params.get("email")

    if not email:
        ctx.log("No email specified for HIBP email query", level="WARNING")
        return ctx

    ctx.log(f"Querying HIBP for email breaches: {email}", level="INFO")

    hibp_data = {
        "email": email,
        "breaches": [],
        "error": None,
    }

    api_key = get_hibp_api_key()
    if not api_key:
        hibp_data["error"] = "HIBP API key not configured"
        ctx.log(hibp_data["error"], level="WARNING")
        ctx.add("hibp_email", hibp_data)
        return ctx

    result = _make_hibp_request(f"breachedaccount/{email}", api_key)

    if result is None:
        hibp_data["error"] = "requests library not available"
    elif isinstance(result, list):
        for breach_data in result:
            breach = HIBPBreach(
                name=breach_data.get("Name", ""),
                title=breach_data.get("Title", ""),
                domain=breach_data.get("Domain", ""),
                breach_date=breach_data.get("BreachDate", ""),
                pwn_count=breach_data.get("PwnCount", 0),
                data_classes=breach_data.get("DataClasses", []),
                is_verified=breach_data.get("IsVerified", False),
            )
            hibp_data["breaches"].append(breach.to_dict())

        ctx.log(
            f"HIBP: {len(hibp_data['breaches'])} breaches for {email}", level="INFO"
        )
    elif isinstance(result, dict) and "error" in result:
        hibp_data["error"] = result["error"]
    elif isinstance(result, dict) and result.get("result") == "not_found":
        hibp_data["breaches"] = []
        ctx.log(f"HIBP: no breaches found for {email}", level="INFO")

    ctx.add("hibp_email", hibp_data)
    return ctx


def query_hibp_pastes(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query HIBP for pastes containing an email (requires API key).

    Args:
        ctx: Pipeline context
        params: Required parameters:
            - email: Email address to check

    Returns:
        Updated context with paste data
    """
    params = params or {}
    email = params.get("email")

    if not email:
        ctx.log("No email specified for HIBP paste query", level="WARNING")
        return ctx

    ctx.log(f"Querying HIBP for pastes: {email}", level="INFO")

    hibp_data = {
        "email": email,
        "pastes": [],
        "error": None,
    }

    api_key = get_hibp_api_key()
    if not api_key:
        hibp_data["error"] = "HIBP API key not configured"
        ctx.log(hibp_data["error"], level="WARNING")
        ctx.add("hibp_pastes", hibp_data)
        return ctx

    result = _make_hibp_request(f"pasteaccount/{email}", api_key)

    if result is None:
        hibp_data["error"] = "requests library not available"
    elif isinstance(result, list):
        for paste_data in result:
            paste = HIBPPaste(
                source=paste_data.get("Source", ""),
                id=paste_data.get("Id", ""),
                title=paste_data.get("Title"),
                date=paste_data.get("Date"),
                email_count=paste_data.get("EmailCount", 0),
            )
            hibp_data["pastes"].append(paste.to_dict())

        ctx.log(f"HIBP: {len(hibp_data['pastes'])} pastes for {email}", level="INFO")
    elif isinstance(result, dict) and "error" in result:
        hibp_data["error"] = result["error"]
    elif isinstance(result, dict) and result.get("result") == "not_found":
        hibp_data["pastes"] = []
        ctx.log(f"HIBP: no pastes found for {email}", level="INFO")

    ctx.add("hibp_pastes", hibp_data)
    return ctx


def analyze_hibp_intel(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Run comprehensive HIBP analysis.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context with HIBP intel
    """
    params = params or {}
    target = ctx.target

    ctx.log(f"Running HIBP intelligence for: {target}", level="INFO")

    # Query domain breaches
    if target:
        ctx = query_hibp_domain(ctx, params)

    # Compile summary
    hibp_intel = {
        "target": target,
        "domain": ctx.get("hibp_domain", {}),
        "summary": {},
    }

    # Generate summary
    domain_data = hibp_intel["domain"]

    if domain_data.get("breached_accounts"):
        accounts = domain_data["breached_accounts"]
        hibp_intel["summary"]["breached_accounts"] = len(accounts)

        # Count unique breaches
        all_breaches = set()
        for account in accounts:
            if isinstance(account, dict):
                for breach in account.get("Breaches", []):
                    all_breaches.add(breach)
            elif isinstance(account, str):
                all_breaches.add(account)

        hibp_intel["summary"]["unique_breaches"] = len(all_breaches)
        hibp_intel["summary"]["breach_names"] = list(all_breaches)[:10]
    else:
        hibp_intel["summary"]["breached_accounts"] = 0
        hibp_intel["summary"]["unique_breaches"] = 0

    hibp_intel["summary"]["has_breaches"] = (
        hibp_intel["summary"]["breached_accounts"] > 0
    )

    ctx.add("hibp_intel", hibp_intel)

    breach_count = hibp_intel["summary"].get("breached_accounts", 0)
    ctx.log(
        f"HIBP intel complete: {breach_count} breached accounts",
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
