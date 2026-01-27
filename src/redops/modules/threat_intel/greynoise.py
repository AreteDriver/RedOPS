"""
GreyNoise threat intelligence integration.

Queries GreyNoise Community and Enterprise APIs to identify
internet scanners, known benign services, and malicious actors.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import os
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# GreyNoise API endpoints
GREYNOISE_COMMUNITY_API = "https://api.greynoise.io/v3/community"
GREYNOISE_ENTERPRISE_API = "https://api.greynoise.io/v2"


def query_greynoise(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Query GreyNoise for IP reputation information.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - ip: IP address to query (or use ctx.target)
            - api_key: GreyNoise API key (or GREYNOISE_API_KEY env var)
            - use_enterprise: Use Enterprise API if key available

    Returns:
        Updated context with GreyNoise results
    """
    params = params or {}
    ip = params.get("ip") or ctx.target
    api_key = params.get("api_key") or os.environ.get("GREYNOISE_API_KEY")
    use_enterprise = params.get("use_enterprise", bool(api_key))

    if not HAS_REQUESTS:
        ctx.log("requests library not available for GreyNoise queries", level="WARNING")
        return ctx

    if not ip:
        ctx.log("No IP address specified for GreyNoise query", level="WARNING")
        return ctx

    # Validate IP format
    if not _is_valid_ip(ip):
        ctx.log(f"Invalid IP address format: {ip}", level="WARNING")
        return ctx

    ctx.log(f"Querying GreyNoise for: {ip}", level="INFO")

    # Query appropriate API
    if use_enterprise and api_key:
        result = get_greynoise_context(ip, api_key)
    else:
        result = _query_community_api(ip, api_key)

    if result.get("error"):
        ctx.log(f"GreyNoise query failed: {result['error']}", level="WARNING")
        ctx.add("greynoise_result", result)
        return ctx

    # Also check RIOT database for known benign services
    riot_result = get_greynoise_riot(ip, api_key)
    if not riot_result.get("error"):
        result["riot"] = riot_result

    # Add timestamp
    result["query_timestamp"] = datetime.now().isoformat()

    # Analyze for security findings
    findings = analyze_greynoise_results(result, ip)

    # Store results
    ctx.add("greynoise_result", result)
    ctx.add("greynoise_noise", result.get("noise", False))
    ctx.add("greynoise_riot", result.get("riot", {}).get("riot", False))
    ctx.add("greynoise_classification", result.get("classification", "unknown"))

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_greynoise_{i}", finding.model_dump())

    return ctx


def _query_community_api(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Query GreyNoise Community API."""
    try:
        url = f"{GREYNOISE_COMMUNITY_API}/{ip}"
        headers = {}
        if api_key:
            headers["key"] = api_key

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "ip": ip,
                "noise": False,
                "riot": False,
                "message": "IP not observed by GreyNoise",
            }

        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"ip": ip, "error": f"Query failed: {str(e)}"}


def get_greynoise_context(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Get detailed context from GreyNoise Enterprise API.

    Args:
        ip: IP address to query
        api_key: GreyNoise Enterprise API key

    Returns:
        Detailed IP context
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    if not api_key:
        return {"error": "API key required for Enterprise API"}

    try:
        url = f"{GREYNOISE_ENTERPRISE_API}/noise/context/{ip}"
        headers = {"key": api_key}

        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                "ip": ip,
                "seen": False,
                "message": "IP not observed in GreyNoise dataset",
            }

        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"ip": ip, "error": f"Context lookup failed: {str(e)}"}


def get_greynoise_riot(ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Check if IP is in GreyNoise RIOT (Rule It OuT) database.

    RIOT identifies IPs belonging to known benign services like
    Google, Microsoft, CDNs, etc.

    Args:
        ip: IP address to check
        api_key: Optional API key (increases rate limits)

    Returns:
        RIOT lookup result
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    try:
        url = f"{GREYNOISE_ENTERPRISE_API}/riot/{ip}"
        headers = {}
        if api_key:
            headers["key"] = api_key

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "ip": ip,
                "riot": False,
                "message": "IP not found in RIOT database",
            }

        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": f"RIOT lookup failed: {str(e)}"}
    except Exception as e:
        return {"ip": ip, "error": f"RIOT query failed: {str(e)}"}


def analyze_greynoise_results(result: Dict[str, Any], ip: str) -> List[Finding]:
    """
    Analyze GreyNoise results for security findings.

    Args:
        result: GreyNoise API result
        ip: Original IP address

    Returns:
        List of security findings
    """
    findings = []

    if result.get("error"):
        return findings

    # Check if IP is a known scanner/noise
    noise = result.get("noise", False)
    classification = result.get("classification", "").lower()

    if noise:
        if classification == "malicious":
            findings.append(
                Finding(
                    module="threat_intel.greynoise",
                    title=f"Malicious Scanner Detected: {ip}",
                    description=(
                        f"IP {ip} is classified as MALICIOUS by GreyNoise. "
                        "This IP has been observed conducting internet-wide scanning "
                        "with malicious intent."
                    ),
                    severity=RiskLevel.HIGH,
                    data={
                        "ip": ip,
                        "classification": classification,
                        "noise": noise,
                        "actor": result.get("actor", ""),
                        "tags": result.get("tags", []),
                    },
                )
            )
        elif classification == "benign":
            findings.append(
                Finding(
                    module="threat_intel.greynoise",
                    title=f"Benign Scanner: {ip}",
                    description=(
                        f"IP {ip} is classified as a benign scanner by GreyNoise. "
                        "This is likely a security research or legitimate scanning service."
                    ),
                    severity=RiskLevel.INFO,
                    data={
                        "ip": ip,
                        "classification": classification,
                        "actor": result.get("actor", ""),
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    module="threat_intel.greynoise",
                    title=f"Internet Scanner Detected: {ip}",
                    description=(
                        f"IP {ip} has been observed conducting internet-wide scanning. "
                        "Classification: {classification or 'unknown'}."
                    ),
                    severity=RiskLevel.MEDIUM,
                    data={
                        "ip": ip,
                        "classification": classification,
                        "noise": noise,
                    },
                )
            )

    # Check RIOT (known benign services)
    riot_data = result.get("riot", {})
    if riot_data.get("riot"):
        findings.append(
            Finding(
                module="threat_intel.greynoise",
                title=f"Known Benign Service: {ip}",
                description=(
                    f"IP {ip} belongs to a known benign service: "
                    f"{riot_data.get('name', 'Unknown')}. "
                    f"Category: {riot_data.get('category', 'Unknown')}."
                ),
                severity=RiskLevel.INFO,
                data={
                    "ip": ip,
                    "service_name": riot_data.get("name", ""),
                    "category": riot_data.get("category", ""),
                    "trust_level": riot_data.get("trust_level", ""),
                },
            )
        )

    # Check for specific threat tags
    tags = result.get("tags", [])
    dangerous_tags = [
        "Mirai",
        "Emotet",
        "Cobalt Strike",
        "Metasploit",
        "Ransomware",
        "Botnet",
        "C2",
        "Tor Exit Node",
    ]

    matched_tags = [
        t for t in tags if any(d.lower() in t.lower() for d in dangerous_tags)
    ]
    if matched_tags:
        findings.append(
            Finding(
                module="threat_intel.greynoise",
                title=f"Dangerous Activity Tags: {ip}",
                description=(
                    f"IP {ip} has been tagged with potentially dangerous activity: "
                    f"{', '.join(matched_tags)}."
                ),
                severity=RiskLevel.HIGH,
                data={
                    "ip": ip,
                    "dangerous_tags": matched_tags,
                    "all_tags": tags,
                },
            )
        )

    return findings


def get_greynoise_summary(ctx: Context) -> Dict[str, Any]:
    """
    Get a summary of GreyNoise query results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    result = ctx.get("greynoise_result", {})

    return {
        "ip": result.get("ip", ""),
        "noise": result.get("noise", False),
        "riot": result.get("riot", {}).get("riot", False),
        "classification": result.get("classification", "unknown"),
        "actor": result.get("actor", ""),
        "tags": result.get("tags", []),
        "timestamp": result.get("query_timestamp", ""),
    }


def _is_valid_ip(ip: str) -> bool:
    """Validate IP address format."""
    import socket

    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False
