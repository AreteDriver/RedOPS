"""
SecurityTrails Intelligence module.

Queries SecurityTrails API for DNS and domain intelligence:
- Current DNS records
- Historical DNS data
- Subdomain enumeration
- WHOIS history
- Associated domains

IMPORTANT: Requires a SecurityTrails API key.
"""

from typing import Any
from dataclasses import dataclass, field
import os

from redops.core.context import Context


@dataclass
class STDomainInfo:
    """SecurityTrails domain information."""

    domain: str
    alexa_rank: int | None = None
    apex_domain: str | None = None
    hostname: str | None = None
    current_dns: dict[str, Any] = field(default_factory=dict)
    subdomain_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "alexa_rank": self.alexa_rank,
            "apex_domain": self.apex_domain,
            "hostname": self.hostname,
            "current_dns": self.current_dns,
            "subdomain_count": self.subdomain_count,
        }


@dataclass
class STHistoricalDNS:
    """SecurityTrails historical DNS data."""

    domain: str
    record_type: str
    records: list[dict[str, Any]] = field(default_factory=list)
    pages: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "record_type": self.record_type,
            "records": self.records,
            "pages": self.pages,
        }


def get_st_api_key() -> str | None:
    """Get SecurityTrails API key."""
    api_key = os.environ.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        try:
            from redops.cli.settings import get_api_key_direct

            api_key = get_api_key_direct("securitytrails")
        except Exception:
            pass
    return api_key


def _make_st_request(endpoint: str, api_key: str) -> dict[str, Any] | None:
    """Make a request to SecurityTrails API."""
    try:
        import requests
    except ImportError:
        return None

    headers = {"APIKEY": api_key, "Accept": "application/json"}
    url = f"https://api.securitytrails.com/v1/{endpoint}"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "not_found"}
        elif response.status_code == 429:
            return {"error": "rate_limited"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def query_st_domain(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query SecurityTrails for domain information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)

    Returns:
        Updated context with SecurityTrails domain data
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log("No target specified for SecurityTrails query", level="WARNING")
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying SecurityTrails for domain: {domain}", level="INFO")

    st_data = {
        "domain": domain,
        "info": None,
        "error": None,
    }

    api_key = get_st_api_key()
    if not api_key:
        st_data["error"] = "SecurityTrails API key not configured"
        ctx.log(st_data["error"], level="WARNING")
        ctx.add("securitytrails_domain", st_data)
        return ctx

    result = _make_st_request(f"domain/{domain}", api_key)

    if result is None:
        st_data["error"] = "requests library not available"
    elif "error" in result:
        st_data["error"] = result["error"]
    else:
        info = STDomainInfo(
            domain=domain,
            alexa_rank=result.get("alexa_rank"),
            apex_domain=result.get("apex_domain"),
            hostname=result.get("hostname"),
            current_dns=result.get("current_dns", {}),
            subdomain_count=result.get("subdomain_count", 0),
        )
        st_data["info"] = info.to_dict()

        ctx.log(
            f"SecurityTrails: {info.subdomain_count} subdomains found",
            level="INFO",
        )

    ctx.add("securitytrails_domain", st_data)
    return ctx


def query_st_subdomains(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query SecurityTrails for subdomains.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)

    Returns:
        Updated context with subdomain list
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log(
            "No target specified for SecurityTrails subdomain query", level="WARNING"
        )
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying SecurityTrails subdomains for: {domain}", level="INFO")

    st_data = {
        "domain": domain,
        "subdomains": [],
        "error": None,
    }

    api_key = get_st_api_key()
    if not api_key:
        st_data["error"] = "SecurityTrails API key not configured"
        ctx.log(st_data["error"], level="WARNING")
        ctx.add("securitytrails_subdomains", st_data)
        return ctx

    result = _make_st_request(f"domain/{domain}/subdomains", api_key)

    if result is None:
        st_data["error"] = "requests library not available"
    elif "error" in result:
        st_data["error"] = result["error"]
    else:
        subdomains = result.get("subdomains", [])
        st_data["subdomains"] = subdomains
        st_data["count"] = len(subdomains)

        ctx.log(
            f"SecurityTrails: found {len(subdomains)} subdomains",
            level="INFO",
        )

    ctx.add("securitytrails_subdomains", st_data)
    return ctx


def query_st_history(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query SecurityTrails for historical DNS data.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)
            - record_type: DNS record type (default: "a")

    Returns:
        Updated context with historical DNS data
    """
    params = params or {}
    target = params.get("domain") or ctx.target
    record_type = params.get("record_type", "a")

    if not target:
        ctx.log("No target specified for SecurityTrails history query", level="WARNING")
        return ctx

    domain = _extract_domain(target)
    ctx.log(
        f"Querying SecurityTrails history for: {domain} ({record_type})", level="INFO"
    )

    st_data = {
        "domain": domain,
        "record_type": record_type,
        "history": None,
        "error": None,
    }

    api_key = get_st_api_key()
    if not api_key:
        st_data["error"] = "SecurityTrails API key not configured"
        ctx.log(st_data["error"], level="WARNING")
        ctx.add("securitytrails_history", st_data)
        return ctx

    result = _make_st_request(f"history/{domain}/dns/{record_type}", api_key)

    if result is None:
        st_data["error"] = "requests library not available"
    elif "error" in result:
        st_data["error"] = result["error"]
    else:
        history = STHistoricalDNS(
            domain=domain,
            record_type=record_type,
            records=result.get("records", []),
            pages=result.get("pages", 0),
        )
        st_data["history"] = history.to_dict()

        ctx.log(
            f"SecurityTrails: {len(history.records)} historical records",
            level="INFO",
        )

    ctx.add("securitytrails_history", st_data)
    return ctx


def query_st_associated(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query SecurityTrails for associated domains.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)

    Returns:
        Updated context with associated domains
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log(
            "No target specified for SecurityTrails associated query", level="WARNING"
        )
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying SecurityTrails associated domains for: {domain}", level="INFO")

    st_data = {
        "domain": domain,
        "associated": [],
        "error": None,
    }

    api_key = get_st_api_key()
    if not api_key:
        st_data["error"] = "SecurityTrails API key not configured"
        ctx.log(st_data["error"], level="WARNING")
        ctx.add("securitytrails_associated", st_data)
        return ctx

    result = _make_st_request(f"domain/{domain}/associated", api_key)

    if result is None:
        st_data["error"] = "requests library not available"
    elif "error" in result:
        st_data["error"] = result["error"]
    else:
        records = result.get("records", [])
        st_data["associated"] = records
        st_data["count"] = len(records)

        ctx.log(
            f"SecurityTrails: {len(records)} associated domains",
            level="INFO",
        )

    ctx.add("securitytrails_associated", st_data)
    return ctx


def analyze_securitytrails_intel(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Run comprehensive SecurityTrails analysis.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context with SecurityTrails intel
    """
    params = params or {}
    target = ctx.target

    ctx.log(f"Running SecurityTrails intelligence for: {target}", level="INFO")

    # Query domain info
    ctx = query_st_domain(ctx, params)

    # Query subdomains
    ctx = query_st_subdomains(ctx, params)

    # Query history for A records
    ctx = query_st_history(ctx, params)

    # Compile summary
    st_intel = {
        "target": target,
        "domain": ctx.get("securitytrails_domain", {}),
        "subdomains": ctx.get("securitytrails_subdomains", {}),
        "history": ctx.get("securitytrails_history", {}),
        "summary": {},
    }

    # Generate summary
    domain_data = st_intel["domain"]
    subdomain_data = st_intel["subdomains"]
    history_data = st_intel["history"]

    if domain_data.get("info"):
        info = domain_data["info"]
        st_intel["summary"]["alexa_rank"] = info.get("alexa_rank")
        st_intel["summary"]["subdomain_count"] = info.get("subdomain_count", 0)

        # Count DNS record types
        current_dns = info.get("current_dns", {})
        st_intel["summary"]["dns_record_types"] = list(current_dns.keys())

    if subdomain_data.get("subdomains"):
        st_intel["summary"]["subdomains_found"] = len(subdomain_data["subdomains"])
        st_intel["summary"]["subdomain_sample"] = subdomain_data["subdomains"][:10]

    if history_data.get("history"):
        history = history_data["history"]
        st_intel["summary"]["historical_records"] = len(history.get("records", []))

    ctx.add("securitytrails_intel", st_intel)

    subdomain_count = st_intel["summary"].get("subdomains_found", 0)
    ctx.log(
        f"SecurityTrails intel complete: {subdomain_count} subdomains",
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
