"""
AbuseIPDB threat intelligence integration.

Queries AbuseIPDB API to check IP reputation and abuse reports.
"""

from typing import Any
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


# AbuseIPDB API endpoint
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"


def check_ip_reputation(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Check IP reputation on AbuseIPDB.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - ip: IP address to check (or use ctx.target)
            - api_key: AbuseIPDB API key (or ABUSEIPDB_API_KEY env var)
            - max_age_days: Max age of reports to consider (default: 90)
            - verbose: Include detailed reports (default: False)

    Returns:
        Updated context with AbuseIPDB results
    """
    params = params or {}
    ip = params.get("ip") or ctx.target
    api_key = params.get("api_key") or os.environ.get("ABUSEIPDB_API_KEY")
    max_age_days = params.get("max_age_days", 90)
    verbose = params.get("verbose", False)

    if not HAS_REQUESTS:
        ctx.log("requests library not available for AbuseIPDB queries", level="WARNING")
        return ctx

    if not api_key:
        ctx.log("AbuseIPDB API key required (set ABUSEIPDB_API_KEY)", level="WARNING")
        return ctx

    if not ip:
        ctx.log("No IP address specified for AbuseIPDB query", level="WARNING")
        return ctx

    ctx.log(f"Checking AbuseIPDB reputation for: {ip}", level="INFO")

    result = _check_ip(ip, api_key, max_age_days, verbose)

    if result.get("error"):
        ctx.log(f"AbuseIPDB query failed: {result['error']}", level="WARNING")
        ctx.add("abuseipdb_result", result)
        return ctx

    # Add timestamp
    result["query_timestamp"] = datetime.now().isoformat()

    # Analyze for security findings
    findings = analyze_abuseipdb_results(result, ip)

    # Store results
    ctx.add("abuseipdb_result", result)
    ctx.add("abuseipdb_score", result.get("abuseConfidenceScore", 0))
    ctx.add("abuseipdb_total_reports", result.get("totalReports", 0))
    ctx.add("abuseipdb_is_whitelisted", result.get("isWhitelisted", False))

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_abuseipdb_{i}", finding.model_dump())

    return ctx


def _check_ip(
    ip: str, api_key: str, max_age_days: int = 90, verbose: bool = False
) -> dict[str, Any]:
    """Query AbuseIPDB check endpoint."""
    try:
        url = f"{ABUSEIPDB_API}/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": "true" if verbose else "false",
        }

        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()

        data = response.json()
        return data.get("data", {})

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return {"ip": ip, "error": "Invalid API key"}
        elif e.response.status_code == 429:
            return {"ip": ip, "error": "Rate limit exceeded"}
        return {"ip": ip, "error": f"API error: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"ip": ip, "error": f"Query failed: {str(e)}"}


def report_ip(
    ip: str,
    api_key: str,
    categories: list[int],
    comment: str = "",
) -> dict[str, Any]:
    """
    Report an IP address to AbuseIPDB.

    Args:
        ip: IP address to report
        api_key: AbuseIPDB API key
        categories: List of abuse category IDs
        comment: Optional comment describing the abuse

    Returns:
        Report submission result

    Category IDs:
        3 = Fraud Orders
        4 = DDoS Attack
        5 = FTP Brute-Force
        6 = Ping of Death
        7 = Phishing
        8 = Fraud VoIP
        9 = Open Proxy
        10 = Web Spam
        11 = Email Spam
        12 = Blog Spam
        13 = VPN IP
        14 = Port Scan
        15 = Hacking
        16 = SQL Injection
        17 = Spoofing
        18 = Brute-Force
        19 = Bad Web Bot
        20 = Exploited Host
        21 = Web App Attack
        22 = SSH
        23 = IoT Targeted
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    try:
        url = f"{ABUSEIPDB_API}/report"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        data = {
            "ip": ip,
            "categories": ",".join(str(c) for c in categories),
            "comment": comment,
        }

        response = requests.post(url, headers=headers, data=data, timeout=15)
        response.raise_for_status()

        return response.json().get("data", {})

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return {"error": "Invalid API key"}
        elif e.response.status_code == 429:
            return {"error": "Rate limit exceeded"}
        elif e.response.status_code == 422:
            return {"error": "Invalid data or duplicate report"}
        return {"error": f"API error: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Report failed: {str(e)}"}


def get_blacklist(
    api_key: str,
    confidence_minimum: int = 90,
    limit: int = 10000,
) -> list[dict[str, Any]]:
    """
    Get AbuseIPDB blacklist.

    Args:
        api_key: AbuseIPDB API key
        confidence_minimum: Minimum confidence score (default: 90)
        limit: Maximum entries to return (default: 10000)

    Returns:
        List of blacklisted IPs
    """
    if not HAS_REQUESTS:
        return []

    try:
        url = f"{ABUSEIPDB_API}/blacklist"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
        }

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()
        return data.get("data", [])

    except Exception:
        return []


def analyze_abuseipdb_results(result: dict[str, Any], ip: str) -> list[Finding]:
    """
    Analyze AbuseIPDB results for security findings.

    Args:
        result: AbuseIPDB API result
        ip: Original IP address

    Returns:
        List of security findings
    """
    findings = []

    if result.get("error"):
        return findings

    confidence_score = result.get("abuseConfidenceScore", 0)
    total_reports = result.get("totalReports", 0)
    is_whitelisted = result.get("isWhitelisted", False)
    is_tor = result.get("isTor", False)
    usage_type = result.get("usageType", "")
    isp = result.get("isp", "")
    domain = result.get("domain", "")
    country = result.get("countryCode", "")

    # Check for whitelisted IPs
    if is_whitelisted:
        findings.append(
            Finding(
                module="threat_intel.abuseipdb",
                title=f"Whitelisted IP: {ip}",
                description=(
                    f"IP {ip} is whitelisted on AbuseIPDB. "
                    "This indicates it's a known legitimate service."
                ),
                severity=RiskLevel.INFO,
                data={
                    "ip": ip,
                    "isp": isp,
                    "domain": domain,
                },
            )
        )
        return findings

    # High abuse confidence
    if confidence_score >= 75:
        findings.append(
            Finding(
                module="threat_intel.abuseipdb",
                title=f"High Abuse Confidence: {ip} ({confidence_score}%)",
                description=(
                    f"IP {ip} has a very high abuse confidence score of {confidence_score}%. "
                    f"Total reports: {total_reports}. ISP: {isp}. Country: {country}."
                ),
                severity=RiskLevel.HIGH,
                data={
                    "ip": ip,
                    "confidence_score": confidence_score,
                    "total_reports": total_reports,
                    "isp": isp,
                    "country": country,
                },
            )
        )
    elif confidence_score >= 50:
        findings.append(
            Finding(
                module="threat_intel.abuseipdb",
                title=f"Medium Abuse Confidence: {ip} ({confidence_score}%)",
                description=(
                    f"IP {ip} has a moderate abuse confidence score of {confidence_score}%. "
                    f"Total reports: {total_reports}."
                ),
                severity=RiskLevel.MEDIUM,
                data={
                    "ip": ip,
                    "confidence_score": confidence_score,
                    "total_reports": total_reports,
                },
            )
        )
    elif confidence_score > 0:
        findings.append(
            Finding(
                module="threat_intel.abuseipdb",
                title=f"Low Abuse Reports: {ip} ({confidence_score}%)",
                description=(
                    f"IP {ip} has a low abuse confidence score of {confidence_score}%. "
                    f"Total reports: {total_reports}."
                ),
                severity=RiskLevel.LOW,
                data={
                    "ip": ip,
                    "confidence_score": confidence_score,
                    "total_reports": total_reports,
                },
            )
        )

    # Tor exit node detection
    if is_tor:
        findings.append(
            Finding(
                module="threat_intel.abuseipdb",
                title=f"Tor Exit Node: {ip}",
                description=(
                    f"IP {ip} is identified as a Tor exit node. "
                    "Traffic from this IP may be anonymized."
                ),
                severity=RiskLevel.MEDIUM,
                data={
                    "ip": ip,
                    "is_tor": True,
                },
            )
        )

    # Analyze usage type
    suspicious_usage_types = ["Data Center/Web Hosting/Transit", "Fixed Line ISP"]
    if usage_type in suspicious_usage_types and total_reports > 10:
        findings.append(
            Finding(
                module="threat_intel.abuseipdb",
                title=f"Suspicious Infrastructure: {ip}",
                description=(
                    f"IP {ip} is from {usage_type} with {total_reports} abuse reports. "
                    "This may indicate a compromised or malicious server."
                ),
                severity=RiskLevel.MEDIUM,
                data={
                    "ip": ip,
                    "usage_type": usage_type,
                    "total_reports": total_reports,
                },
            )
        )

    return findings


def get_abuseipdb_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of AbuseIPDB query results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    result = ctx.get("abuseipdb_result", {})

    return {
        "ip": result.get("ipAddress", ""),
        "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
        "total_reports": result.get("totalReports", 0),
        "is_whitelisted": result.get("isWhitelisted", False),
        "is_tor": result.get("isTor", False),
        "isp": result.get("isp", ""),
        "domain": result.get("domain", ""),
        "country": result.get("countryCode", ""),
        "usage_type": result.get("usageType", ""),
        "timestamp": result.get("query_timestamp", ""),
    }
