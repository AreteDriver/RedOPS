"""
ASN (Autonomous System Number) lookup module.

Performs ASN lookups to discover network ownership, IP ranges,
and organizational information for targets.
"""

from typing import Any
from datetime import datetime
import socket
import re
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests for API calls
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# BGPView API (free, no auth required)
BGPVIEW_API = "https://api.bgpview.io"

# IP to ASN mapping via DNS (Cymru)
CYMRU_DNS = "origin.asn.cymru.com"
CYMRU_ASN_DNS = "asn.cymru.com"


def lookup_asn(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Perform ASN lookup for a target.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - target: IP address, domain, or ASN to lookup
            - include_prefixes: Include announced prefixes (default: True)
            - include_peers: Include peer information (default: False)

    Returns:
        Updated context with ASN information
    """
    params = params or {}
    target = params.get("target") or ctx.target
    include_prefixes = params.get("include_prefixes", True)
    include_peers = params.get("include_peers", False)

    if not target:
        ctx.log("No target specified for ASN lookup", level="WARNING")
        return ctx

    ctx.log(f"Performing ASN lookup for: {target}", level="INFO")

    # Determine target type and get ASN info
    if is_ip_address(target):
        # IP address - look up ASN
        asn_info = lookup_asn_by_ip(target)
    elif is_asn(target):
        # ASN number - get details
        asn_info = lookup_asn_details(target)
    else:
        # Domain - resolve to IP first
        ip = resolve_domain_to_ip(target)
        if ip:
            ctx.log(f"Resolved {target} to {ip}", level="DEBUG")
            asn_info = lookup_asn_by_ip(ip)
            asn_info["resolved_from"] = target
            asn_info["resolved_ip"] = ip
        else:
            ctx.log(f"Could not resolve domain: {target}", level="WARNING")
            asn_info = {"error": "Could not resolve domain"}

    if asn_info.get("error"):
        ctx.log(f"ASN lookup failed: {asn_info['error']}", level="WARNING")
        ctx.add("asn_lookup", asn_info)
        return ctx

    asn = asn_info.get("asn")
    ctx.log(f"Found ASN: {asn} ({asn_info.get('name', 'Unknown')})", level="INFO")

    # Get additional details if we have an ASN
    if asn and include_prefixes:
        prefixes = get_asn_prefixes(asn)
        asn_info["prefixes"] = prefixes
        asn_info["prefix_count"] = len(prefixes)
        ctx.log(f"ASN announces {len(prefixes)} prefixes", level="DEBUG")

    if asn and include_peers:
        peers = get_asn_peers(asn)
        asn_info["peers"] = peers
        ctx.log(f"ASN has {len(peers.get('upstreams', []))} upstreams", level="DEBUG")

    # Add timestamp
    asn_info["lookup_timestamp"] = datetime.now().isoformat()

    # Analyze for security insights
    findings = analyze_asn_info(asn_info, target)

    # Store results
    ctx.add("asn_lookup", asn_info)
    ctx.add("asn", asn)
    ctx.add("asn_name", asn_info.get("name", ""))
    ctx.add("asn_prefixes", asn_info.get("prefixes", []))

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_asn_{i}", finding.model_dump())

    return ctx


def is_ip_address(value: str) -> bool:
    """Check if a string is an IP address."""
    # IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, value):
        parts = value.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True

    # IPv6 (simplified check)
    if ":" in value:
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except Exception:
            pass

    return False


def is_asn(value: str) -> bool:
    """Check if a string is an ASN."""
    # ASN format: AS12345 or just 12345
    value = value.upper()
    if value.startswith("AS"):
        value = value[2:]
    return value.isdigit() and 1 <= int(value) <= 4294967295


def resolve_domain_to_ip(domain: str) -> str | None:
    """Resolve a domain to its IP address."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def lookup_asn_by_ip(ip: str) -> dict[str, Any]:
    """
    Look up ASN information for an IP address.

    Args:
        ip: IP address to lookup

    Returns:
        ASN information dictionary
    """
    # Try BGPView API first
    if HAS_REQUESTS:
        result = lookup_asn_bgpview(ip)
        if not result.get("error"):
            return result

    # Fallback to DNS-based lookup (Cymru)
    return lookup_asn_cymru(ip)


def lookup_asn_bgpview(ip: str) -> dict[str, Any]:
    """Look up ASN via BGPView API."""
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    try:
        url = f"{BGPVIEW_API}/ip/{ip}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "ok" or not data.get("data"):
            return {"error": "No data found"}

        ip_data = data["data"]
        prefixes = ip_data.get("prefixes", [])

        if not prefixes:
            return {"error": "No ASN found for IP"}

        # Use the first prefix's ASN
        prefix = prefixes[0]
        asn_data = prefix.get("asn", {})

        return {
            "ip": ip,
            "asn": asn_data.get("asn"),
            "name": asn_data.get("name", ""),
            "description": asn_data.get("description", ""),
            "country": asn_data.get("country_code", ""),
            "prefix": prefix.get("prefix", ""),
            "rir": ip_data.get("rir_allocation", {}).get("rir_name", ""),
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Lookup failed: {str(e)}"}


def lookup_asn_cymru(ip: str) -> dict[str, Any]:
    """
    Look up ASN via Team Cymru DNS service.

    Args:
        ip: IP address to lookup

    Returns:
        ASN information dictionary
    """
    try:
        # Reverse the IP for DNS query
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{CYMRU_DNS}"

        # DNS TXT lookup
        import socket

        socket.gethostbyname_ex(query)

        # Parse the TXT record
        # Format: "ASN | Prefix | Country | RIR | Allocated"
        # This is a simplified approach - full implementation would use DNS TXT records

        return {
            "ip": ip,
            "asn": None,
            "name": "",
            "description": "",
            "source": "cymru_dns",
            "note": "Limited data via DNS fallback",
        }

    except Exception:
        return {"error": "DNS lookup failed"}


def lookup_asn_details(asn: str) -> dict[str, Any]:
    """
    Get details for a specific ASN.

    Args:
        asn: ASN number (with or without 'AS' prefix)

    Returns:
        ASN details dictionary
    """
    # Normalize ASN
    asn_num = asn.upper().replace("AS", "")

    if not HAS_REQUESTS:
        return {"asn": asn_num, "error": "requests library not available"}

    try:
        url = f"{BGPVIEW_API}/asn/{asn_num}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "ok" or not data.get("data"):
            return {"asn": asn_num, "error": "ASN not found"}

        asn_data = data["data"]

        return {
            "asn": asn_data.get("asn"),
            "name": asn_data.get("name", ""),
            "description": asn_data.get("description_short", ""),
            "country": asn_data.get("country_code", ""),
            "website": asn_data.get("website", ""),
            "email_contacts": asn_data.get("email_contacts", []),
            "abuse_contacts": asn_data.get("abuse_contacts", []),
            "rir": asn_data.get("rir_allocation", {}).get("rir_name", ""),
            "looking_glass": asn_data.get("looking_glass", ""),
            "traffic_estimation": asn_data.get("traffic_estimation", ""),
        }

    except requests.exceptions.RequestException:
        return {"asn": asn_num, "error": "API request failed"}
    except Exception:
        return {"asn": asn_num, "error": "Lookup failed"}


def get_asn_prefixes(asn: str) -> list[dict[str, Any]]:
    """
    Get IP prefixes announced by an ASN.

    Args:
        asn: ASN number

    Returns:
        List of prefix dictionaries
    """
    asn_num = str(asn).upper().replace("AS", "")

    if not HAS_REQUESTS:
        return []

    try:
        url = f"{BGPVIEW_API}/asn/{asn_num}/prefixes"
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "ok":
            return []

        prefixes = []
        prefix_data = data.get("data", {})

        # IPv4 prefixes
        for prefix in prefix_data.get("ipv4_prefixes", []):
            prefixes.append(
                {
                    "prefix": prefix.get("prefix", ""),
                    "ip_version": 4,
                    "name": prefix.get("name", ""),
                    "description": prefix.get("description", ""),
                    "country": prefix.get("country_code", ""),
                }
            )

        # IPv6 prefixes
        for prefix in prefix_data.get("ipv6_prefixes", []):
            prefixes.append(
                {
                    "prefix": prefix.get("prefix", ""),
                    "ip_version": 6,
                    "name": prefix.get("name", ""),
                    "description": prefix.get("description", ""),
                    "country": prefix.get("country_code", ""),
                }
            )

        return prefixes

    except Exception:
        return []


def get_asn_peers(asn: str) -> dict[str, list[dict[str, Any]]]:
    """
    Get peer information for an ASN.

    Args:
        asn: ASN number

    Returns:
        Dictionary with upstreams, downstreams, and peers
    """
    asn_num = str(asn).upper().replace("AS", "")

    if not HAS_REQUESTS:
        return {"upstreams": [], "downstreams": [], "peers": []}

    try:
        url = f"{BGPVIEW_API}/asn/{asn_num}/peers"
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "ok":
            return {"upstreams": [], "downstreams": [], "peers": []}

        peer_data = data.get("data", {})

        return {
            "upstreams": [
                {"asn": p.get("asn"), "name": p.get("name", "")}
                for p in peer_data.get("ipv4_upstreams", [])
            ],
            "downstreams": [
                {"asn": p.get("asn"), "name": p.get("name", "")}
                for p in peer_data.get("ipv4_downstreams", [])
            ],
            "peers": [
                {"asn": p.get("asn"), "name": p.get("name", "")}
                for p in peer_data.get("ipv4_peers", [])
            ],
        }

    except Exception:
        return {"upstreams": [], "downstreams": [], "peers": []}


def analyze_asn_info(asn_info: dict[str, Any], target: str) -> list[Finding]:
    """
    Analyze ASN information for security insights.

    Args:
        asn_info: ASN lookup results
        target: Original target

    Returns:
        List of security findings
    """
    findings = []

    asn = asn_info.get("asn")
    name = asn_info.get("name", "")
    prefixes = asn_info.get("prefixes", [])

    if not asn:
        return findings

    # Check for hosting providers (may indicate cloud infrastructure)
    cloud_keywords = [
        "amazon",
        "aws",
        "google",
        "microsoft",
        "azure",
        "cloudflare",
        "digitalocean",
        "linode",
        "vultr",
        "ovh",
        "hetzner",
    ]
    name_lower = name.lower()

    for keyword in cloud_keywords:
        if keyword in name_lower:
            findings.append(
                Finding(
                    module="recon.asn_lookup",
                    title=f"Cloud/Hosting Provider Detected: {name}",
                    description=f"Target {target} is hosted on {name} (AS{asn}). "
                    "This is a major cloud or hosting provider.",
                    severity=RiskLevel.INFO,
                    data={"asn": asn, "provider": name, "target": target},
                )
            )
            break

    # Large prefix count may indicate CDN or major provider
    if len(prefixes) > 100:
        findings.append(
            Finding(
                module="recon.asn_lookup",
                title=f"Large Network (AS{asn} - {len(prefixes)} prefixes)",
                description=f"AS{asn} ({name}) announces {len(prefixes)} IP prefixes. "
                "This indicates a large network infrastructure.",
                severity=RiskLevel.INFO,
                data={"asn": asn, "prefix_count": len(prefixes)},
            )
        )

    # Check for abuse contacts
    abuse_contacts = asn_info.get("abuse_contacts", [])
    if abuse_contacts:
        findings.append(
            Finding(
                module="recon.asn_lookup",
                title="Abuse Contact Information Available",
                description=f"Abuse contacts for AS{asn}: {', '.join(abuse_contacts[:3])}",
                severity=RiskLevel.INFO,
                data={"asn": asn, "abuse_contacts": abuse_contacts},
            )
        )

    return findings


def get_asn_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of ASN lookup results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    asn_info = ctx.get("asn_lookup", {})

    return {
        "asn": asn_info.get("asn"),
        "name": asn_info.get("name", ""),
        "country": asn_info.get("country", ""),
        "prefix_count": asn_info.get("prefix_count", 0),
        "timestamp": asn_info.get("lookup_timestamp", ""),
    }
