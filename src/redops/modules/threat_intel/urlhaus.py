"""
URLhaus threat intelligence integration.

Queries URLhaus API to identify malicious URLs, hosts, and payloads.
URLhaus is a project of abuse.ch tracking malware distribution sites.
"""

from typing import Any
from datetime import datetime
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# URLhaus API endpoint (no auth required)
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"


def check_url(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Check if a URL is listed in URLhaus.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - url: URL to check (or use ctx.target)

    Returns:
        Updated context with URLhaus results
    """
    params = params or {}
    url = params.get("url") or ctx.target

    if not HAS_REQUESTS:
        ctx.log("requests library not available for URLhaus queries", level="WARNING")
        return ctx

    if not url:
        ctx.log("No URL specified for URLhaus query", level="WARNING")
        return ctx

    ctx.log(f"Checking URLhaus for URL: {url}", level="INFO")

    result = _query_url(url)

    if result.get("error"):
        ctx.log(f"URLhaus query failed: {result['error']}", level="WARNING")

    # Add timestamp
    result["query_timestamp"] = datetime.now().isoformat()

    # Analyze for security findings
    findings = analyze_urlhaus_results(result, url)

    # Store results
    ctx.add("urlhaus_result", result)
    ctx.add("urlhaus_status", result.get("query_status", ""))
    ctx.add("urlhaus_threat", result.get("threat", ""))

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_urlhaus_{i}", finding.model_dump())

    return ctx


def _query_url(url: str) -> dict[str, Any]:
    """Query URLhaus URL lookup endpoint."""
    try:
        api_url = f"{URLHAUS_API}/url/"
        data = {"url": url}

        response = requests.post(api_url, data=data, timeout=15)
        response.raise_for_status()

        result = response.json()
        result["queried_url"] = url
        return result

    except requests.exceptions.RequestException as e:
        return {"queried_url": url, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"queried_url": url, "error": f"Query failed: {str(e)}"}


def check_host(host: str) -> dict[str, Any]:
    """
    Check if a host/domain is listed in URLhaus.

    Args:
        host: Hostname or domain to check

    Returns:
        URLhaus host lookup result
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    try:
        url = f"{URLHAUS_API}/host/"
        data = {"host": host}

        response = requests.post(url, data=data, timeout=15)
        response.raise_for_status()

        result = response.json()
        result["queried_host"] = host
        return result

    except requests.exceptions.RequestException as e:
        return {"queried_host": host, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"queried_host": host, "error": f"Query failed: {str(e)}"}


def check_payload(
    payload_hash: str | None = None,
    md5: str | None = None,
    sha256: str | None = None,
) -> dict[str, Any]:
    """
    Check if a payload hash is listed in URLhaus.

    Args:
        payload_hash: Hash to check (MD5 or SHA256)
        md5: MD5 hash (alternative parameter)
        sha256: SHA256 hash (alternative parameter)

    Returns:
        URLhaus payload lookup result
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    # Determine which hash to use
    hash_value = payload_hash or md5 or sha256
    if not hash_value:
        return {"error": "No hash provided"}

    # Determine hash type
    hash_len = len(hash_value)
    if hash_len == 32:
        hash_type = "md5_hash"
    elif hash_len == 64:
        hash_type = "sha256_hash"
    else:
        return {"error": f"Invalid hash length: {hash_len}"}

    try:
        url = f"{URLHAUS_API}/payload/"
        data = {hash_type: hash_value}

        response = requests.post(url, data=data, timeout=15)
        response.raise_for_status()

        result = response.json()
        result["queried_hash"] = hash_value
        result["hash_type"] = hash_type
        return result

    except requests.exceptions.RequestException as e:
        return {"queried_hash": hash_value, "error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"queried_hash": hash_value, "error": f"Query failed: {str(e)}"}


def get_recent_urls(limit: int = 100) -> list[dict[str, Any]]:
    """
    Get recent malicious URLs from URLhaus.

    Args:
        limit: Maximum number of URLs to return (default: 100)

    Returns:
        List of recent malicious URLs
    """
    if not HAS_REQUESTS:
        return []

    try:
        url = f"{URLHAUS_API}/urls/recent/limit/{limit}/"

        response = requests.get(url, timeout=30)
        response.raise_for_status()

        data = response.json()
        return data.get("urls", [])

    except Exception:
        return []


def analyze_urlhaus_results(result: dict[str, Any], queried: str) -> list[Finding]:
    """
    Analyze URLhaus results for security findings.

    Args:
        result: URLhaus API result
        queried: Original URL or host queried

    Returns:
        List of security findings
    """
    findings = []

    if result.get("error"):
        return findings

    query_status = result.get("query_status", "")

    # Host lookup with multiple URLs (check first since it has "urls" field)
    if query_status == "ok" and "urls" in result:
        url_count = result.get("url_count", len(result.get("urls", [])))
        urls = result.get("urls", [])

        if url_count > 0:
            online_count = sum(1 for u in urls if u.get("url_status") == "online")

            findings.append(
                Finding(
                    module="threat_intel.urlhaus",
                    title=f"Malicious Host: {url_count} URLs tracked",
                    description=(
                        f"Host '{queried}' has {url_count} malicious URL(s) tracked in URLhaus. "
                        f"{online_count} are currently online."
                    ),
                    severity=RiskLevel.HIGH if online_count > 0 else RiskLevel.MEDIUM,
                    data={
                        "host": queried,
                        "total_urls": url_count,
                        "online_urls": online_count,
                    },
                )
            )

    # URL found in database (has threat/url_status fields)
    elif query_status == "ok" and "threat" in result:
        threat = result.get("threat", "malware")
        url_status = result.get("url_status", "unknown")
        date_added = result.get("date_added", "")
        tags = result.get("tags", [])

        # Determine severity based on status
        if url_status == "online":
            severity = RiskLevel.CRITICAL
            status_desc = "CURRENTLY ACTIVE"
        elif url_status == "offline":
            severity = RiskLevel.HIGH
            status_desc = "currently offline"
        else:
            severity = RiskLevel.HIGH
            status_desc = f"status: {url_status}"

        findings.append(
            Finding(
                module="threat_intel.urlhaus",
                title=f"Malicious URL Detected: {threat}",
                description=(
                    f"URL/Host '{queried}' is listed in URLhaus as malicious. "
                    f"Threat type: {threat}. Status: {status_desc}. "
                    f"First seen: {date_added}. Tags: {', '.join(tags) if tags else 'none'}."
                ),
                severity=severity,
                data={
                    "url": queried,
                    "threat": threat,
                    "status": url_status,
                    "date_added": date_added,
                    "tags": tags,
                    "urlhaus_reference": result.get("urlhaus_reference", ""),
                },
            )
        )

        # Check for specific threat types
        if threat == "malware_download":
            findings.append(
                Finding(
                    module="threat_intel.urlhaus",
                    title=f"Malware Distribution Site: {queried}",
                    description=(
                        f"URL/Host '{queried}' is known to distribute malware. "
                        "Direct downloads from this location may infect systems."
                    ),
                    severity=RiskLevel.CRITICAL,
                    data={
                        "url": queried,
                        "threat": threat,
                    },
                )
            )

        # Check payloads associated with URL
        payloads = result.get("payloads", [])
        if payloads:
            malware_names = list(
                set(
                    p.get("signature", "unknown")
                    for p in payloads
                    if p.get("signature")
                )
            )

            findings.append(
                Finding(
                    module="threat_intel.urlhaus",
                    title=f"Known Malware Payloads ({len(payloads)} samples)",
                    description=(
                        f"URL '{queried}' has been observed distributing "
                        f"{len(payloads)} malware payload(s). "
                        f"Malware families: {', '.join(malware_names[:5])}."
                    ),
                    severity=RiskLevel.CRITICAL,
                    data={
                        "url": queried,
                        "payload_count": len(payloads),
                        "malware_families": malware_names,
                        "sample_hashes": [
                            p.get("sha256_hash", "") for p in payloads[:5]
                        ],
                    },
                )
            )

    # Payload found
    if "signature" in result:
        signature = result.get("signature", "unknown")
        file_type = result.get("file_type", "")
        first_seen = result.get("firstseen", "")
        url_count = result.get("url_count", 0)

        findings.append(
            Finding(
                module="threat_intel.urlhaus",
                title=f"Known Malware: {signature}",
                description=(
                    f"Payload hash matches known malware: {signature}. "
                    f"File type: {file_type}. First seen: {first_seen}. "
                    f"Associated with {url_count} distribution URL(s)."
                ),
                severity=RiskLevel.CRITICAL,
                data={
                    "hash": result.get("queried_hash", ""),
                    "signature": signature,
                    "file_type": file_type,
                    "first_seen": first_seen,
                    "url_count": url_count,
                },
            )
        )

    return findings


def get_urlhaus_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of URLhaus query results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    result = ctx.get("urlhaus_result", {})

    return {
        "url": result.get("queried_url", result.get("queried_host", "")),
        "query_status": result.get("query_status", ""),
        "threat": result.get("threat", ""),
        "url_status": result.get("url_status", ""),
        "date_added": result.get("date_added", ""),
        "tags": result.get("tags", []),
        "payload_count": len(result.get("payloads", [])),
        "timestamp": result.get("query_timestamp", ""),
    }
