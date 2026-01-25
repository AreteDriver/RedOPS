"""
Shodan Intelligence module.

Queries Shodan API for host and IP intelligence:
- Host information (open ports, services, banners)
- DNS records
- Vulnerabilities (CVEs)
- Organization and ASN data
- Historical data

IMPORTANT: Requires a Shodan API key.
This module uses publicly available data from Shodan's database.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import os

from redops.core.context import Context


@dataclass
class ShodanHost:
    """Shodan host result."""

    ip: str
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    org: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    os: Optional[str] = None
    vulns: List[str] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    last_update: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "ports": self.ports,
            "org": self.org,
            "asn": self.asn,
            "isp": self.isp,
            "country": self.country,
            "city": self.city,
            "os": self.os,
            "vulns": self.vulns,
            "services": self.services,
            "last_update": self.last_update,
        }


@dataclass
class ShodanDNS:
    """Shodan DNS result."""

    domain: str
    subdomains: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    data: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "tags": self.tags,
            "data": self.data,
        }


def get_shodan_client():
    """
    Get Shodan API client.

    Returns:
        Shodan API client or None if not available
    """
    try:
        import shodan
    except ImportError:
        return None

    # Check for API key
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        # Try to get from settings
        try:
            from redops.cli.settings import get_api_key_direct
            api_key = get_api_key_direct("shodan")
        except Exception:
            pass

    if not api_key:
        return None

    return shodan.Shodan(api_key)


def query_shodan_host(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query Shodan for host information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - ip: IP address to query (default: resolved from target)
            - history: Include historical data (default: False)

    Returns:
        Updated context with Shodan host data
    """
    params = params or {}
    target = params.get("ip") or ctx.target

    if not target:
        ctx.log("No target specified for Shodan host query", level="WARNING")
        return ctx

    ctx.log(f"Querying Shodan for host: {target}", level="INFO")

    # Initialize result
    shodan_data = {
        "target": target,
        "hosts": [],
        "error": None,
    }

    client = get_shodan_client()
    if not client:
        shodan_data["error"] = "Shodan API not available (missing shodan package or API key)"
        ctx.log(shodan_data["error"], level="WARNING")
        ctx.add("shodan_host", shodan_data)
        return ctx

    try:
        # If target is a domain, resolve to IP first
        ip = target
        if not _is_ip(target):
            try:
                import socket
                ip = socket.gethostbyname(target)
                ctx.log(f"Resolved {target} to {ip}", level="DEBUG")
            except Exception as e:
                ctx.log(f"Could not resolve {target}: {e}", level="WARNING")
                shodan_data["error"] = f"Could not resolve domain: {e}"
                ctx.add("shodan_host", shodan_data)
                return ctx

        # Query Shodan
        history = params.get("history", False)
        result = client.host(ip, history=history)

        # Parse result
        host = ShodanHost(
            ip=result.get("ip_str", ip),
            hostnames=result.get("hostnames", []),
            ports=result.get("ports", []),
            org=result.get("org"),
            asn=result.get("asn"),
            isp=result.get("isp"),
            country=result.get("country_name"),
            city=result.get("city"),
            os=result.get("os"),
            vulns=list(result.get("vulns", {}).keys()) if result.get("vulns") else [],
            last_update=result.get("last_update"),
        )

        # Parse services/banners
        for item in result.get("data", []):
            service = {
                "port": item.get("port"),
                "protocol": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data", "")[:500],  # Truncate long banners
                "ssl": bool(item.get("ssl")),
                "timestamp": item.get("timestamp"),
            }
            host.services.append(service)

        shodan_data["hosts"].append(host.to_dict())

        ctx.log(
            f"Shodan found {len(host.ports)} ports, {len(host.vulns)} vulnerabilities",
            level="INFO",
        )

    except Exception as e:
        error_msg = str(e)
        if "No information available" in error_msg:
            shodan_data["error"] = f"No Shodan data for {ip}"
        else:
            shodan_data["error"] = f"Shodan API error: {error_msg}"
        ctx.log(shodan_data["error"], level="WARNING")

    ctx.add("shodan_host", shodan_data)
    return ctx


def query_shodan_dns(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query Shodan for DNS information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)

    Returns:
        Updated context with Shodan DNS data
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log("No target specified for Shodan DNS query", level="WARNING")
        return ctx

    # Extract domain from URL or hostname
    domain = _extract_domain(target)
    ctx.log(f"Querying Shodan DNS for: {domain}", level="INFO")

    # Initialize result
    dns_data = {
        "domain": domain,
        "subdomains": [],
        "records": [],
        "error": None,
    }

    client = get_shodan_client()
    if not client:
        dns_data["error"] = "Shodan API not available"
        ctx.log(dns_data["error"], level="WARNING")
        ctx.add("shodan_dns", dns_data)
        return ctx

    try:
        # Query DNS
        result = client.dns.domain_info(domain)

        dns_result = ShodanDNS(
            domain=domain,
            subdomains=result.get("subdomains", []),
            tags=result.get("tags", []),
            data=result.get("data", []),
        )

        dns_data["subdomains"] = dns_result.subdomains
        dns_data["tags"] = dns_result.tags
        dns_data["records"] = dns_result.data

        ctx.log(
            f"Shodan DNS found {len(dns_result.subdomains)} subdomains",
            level="INFO",
        )

    except Exception as e:
        dns_data["error"] = f"Shodan DNS error: {str(e)}"
        ctx.log(dns_data["error"], level="WARNING")

    ctx.add("shodan_dns", dns_data)
    return ctx


def search_shodan(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Search Shodan with a query.

    Args:
        ctx: Pipeline context
        params: Required parameters:
            - query: Shodan search query
            - limit: Maximum results (default: 10)

    Returns:
        Updated context with Shodan search results
    """
    params = params or {}
    query = params.get("query")
    limit = params.get("limit", 10)

    if not query:
        # Build query from target
        target = ctx.target
        if target:
            if _is_ip(target):
                query = f"ip:{target}"
            else:
                query = f"hostname:{target}"
        else:
            ctx.log("No query or target for Shodan search", level="WARNING")
            return ctx

    ctx.log(f"Searching Shodan: {query}", level="INFO")

    # Initialize result
    search_data = {
        "query": query,
        "total": 0,
        "results": [],
        "error": None,
    }

    client = get_shodan_client()
    if not client:
        search_data["error"] = "Shodan API not available"
        ctx.log(search_data["error"], level="WARNING")
        ctx.add("shodan_search", search_data)
        return ctx

    try:
        # Search Shodan
        results = client.search(query, limit=limit)

        search_data["total"] = results.get("total", 0)

        for match in results.get("matches", []):
            result = {
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "org": match.get("org"),
                "product": match.get("product"),
                "version": match.get("version"),
                "os": match.get("os"),
                "hostnames": match.get("hostnames", []),
                "location": {
                    "country": match.get("location", {}).get("country_name"),
                    "city": match.get("location", {}).get("city"),
                },
            }
            search_data["results"].append(result)

        ctx.log(
            f"Shodan search found {search_data['total']} total results",
            level="INFO",
        )

    except Exception as e:
        search_data["error"] = f"Shodan search error: {str(e)}"
        ctx.log(search_data["error"], level="WARNING")

    ctx.add("shodan_search", search_data)
    return ctx


def analyze_shodan_intel(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Run comprehensive Shodan analysis.

    Combines host, DNS, and search queries for full intel.

    Args:
        ctx: Pipeline context
        params: Optional parameters passed to sub-queries

    Returns:
        Updated context with comprehensive Shodan intel
    """
    params = params or {}
    target = ctx.target

    ctx.log(f"Running Shodan intelligence analysis for: {target}", level="INFO")

    # Run host query
    ctx = query_shodan_host(ctx, params)

    # Run DNS query if target is a domain
    if target and not _is_ip(target):
        ctx = query_shodan_dns(ctx, params)

    # Compile summary
    shodan_intel = {
        "target": target,
        "host": ctx.get("shodan_host", {}),
        "dns": ctx.get("shodan_dns", {}),
        "summary": {},
    }

    # Generate summary
    host_data = shodan_intel["host"]
    if host_data.get("hosts"):
        host = host_data["hosts"][0]
        shodan_intel["summary"] = {
            "open_ports": len(host.get("ports", [])),
            "services": len(host.get("services", [])),
            "vulnerabilities": len(host.get("vulns", [])),
            "organization": host.get("org"),
            "country": host.get("country"),
            "has_vulns": len(host.get("vulns", [])) > 0,
        }

    dns_data = shodan_intel["dns"]
    if dns_data.get("subdomains"):
        shodan_intel["summary"]["subdomains_found"] = len(dns_data["subdomains"])

    ctx.add("shodan_intel", shodan_intel)

    vuln_count = shodan_intel["summary"].get("vulnerabilities", 0)
    port_count = shodan_intel["summary"].get("open_ports", 0)
    ctx.log(
        f"Shodan intel complete: {port_count} ports, {vuln_count} vulnerabilities",
        level="INFO",
    )

    return ctx


# Helper functions

def _is_ip(value: str) -> bool:
    """Check if value is an IP address."""
    import re
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(ip_pattern, value))


def _extract_domain(value: str) -> str:
    """Extract domain from URL or hostname."""
    # Remove protocol
    if "://" in value:
        value = value.split("://", 1)[1]
    # Remove path
    if "/" in value:
        value = value.split("/", 1)[0]
    # Remove port
    if ":" in value:
        value = value.split(":", 1)[0]
    return value
