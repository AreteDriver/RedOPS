"""
ThreatFox threat intelligence integration.

Queries ThreatFox (abuse.ch) API for malware IOCs including
domains, IPs, URLs, and hashes associated with malware campaigns.
"""

from typing import Any
from datetime import datetime
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def query_ioc(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query ThreatFox for IOC information.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - ioc: IOC to query (IP, domain, URL, or hash)
            - ioc_type: Type hint ('ip', 'domain', 'url', 'hash')

    Returns:
        Updated context with ThreatFox results
    """
    params = params or {}
    ioc = params.get("ioc") or ctx.target

    if not HAS_REQUESTS:
        ctx.log("requests library not available for ThreatFox queries", level="WARNING")
        return ctx

    if not ioc:
        ctx.log("No IOC specified for ThreatFox query", level="WARNING")
        return ctx

    ctx.log(f"Querying ThreatFox for: {ioc}", level="INFO")

    result = _query_api({"query": "search_ioc", "search_term": ioc})

    if result.get("error"):
        ctx.log(f"ThreatFox query failed: {result['error']}", level="WARNING")
        ctx.add("threatfox_result", result)
        return ctx

    result["query_timestamp"] = datetime.now().isoformat()
    result["queried_ioc"] = ioc

    findings = analyze_threatfox_results(result, ioc)

    ctx.add("threatfox_result", result)
    ctx.add("threatfox_ioc_count", len(result.get("data", []) or []))

    for i, finding in enumerate(findings):
        ctx.add(f"finding_threatfox_{i}", finding.model_dump())

    return ctx


def search_malware(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Search ThreatFox for malware family information.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - malware: Malware family name (e.g., 'Emotet', 'Cobalt Strike')
            - limit: Max results (default 100)

    Returns:
        Updated context with malware IOCs
    """
    params = params or {}
    malware = params.get("malware")
    limit = params.get("limit", 100)

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not malware:
        ctx.log("No malware family specified", level="WARNING")
        return ctx

    ctx.log(f"Searching ThreatFox for malware: {malware}", level="INFO")

    result = _query_api({"query": "malwareinfo", "malware": malware, "limit": limit})

    if result.get("error"):
        ctx.log(f"ThreatFox search failed: {result['error']}", level="WARNING")

    result["query_timestamp"] = datetime.now().isoformat()
    result["searched_malware"] = malware

    ctx.add("threatfox_malware_result", result)
    ctx.add("threatfox_malware_iocs", len(result.get("data", []) or []))

    return ctx


def get_recent_iocs(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Get recent IOCs from ThreatFox.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - days: Number of days (1-7, default 1)

    Returns:
        Updated context with recent IOCs
    """
    params = params or {}
    days = min(max(params.get("days", 1), 1), 7)

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    ctx.log(f"Getting ThreatFox IOCs from last {days} day(s)", level="INFO")

    result = _query_api({"query": "get_iocs", "days": days})

    if result.get("error"):
        ctx.log(f"ThreatFox query failed: {result['error']}", level="WARNING")

    result["query_timestamp"] = datetime.now().isoformat()

    ctx.add("threatfox_recent_iocs", result)
    ctx.add("threatfox_recent_count", len(result.get("data", []) or []))

    return ctx


def get_ioc_by_id(ioc_id: str) -> dict[str, Any]:
    """
    Get specific IOC by ThreatFox ID.

    Args:
        ioc_id: ThreatFox IOC ID

    Returns:
        IOC details
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    return _query_api({"query": "ioc", "id": ioc_id})


def get_tag_iocs(tag: str, limit: int = 100) -> dict[str, Any]:
    """
    Get IOCs by tag.

    Args:
        tag: Tag name (e.g., 'c2', 'payload_delivery')
        limit: Max results

    Returns:
        Tagged IOCs
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    return _query_api({"query": "taginfo", "tag": tag, "limit": limit})


def _query_api(payload: dict[str, Any]) -> dict[str, Any]:
    """Make ThreatFox API request."""
    try:
        response = requests.post(
            THREATFOX_API,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("query_status") == "no_result":
            return {"data": [], "query_status": "no_result"}

        return data

    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
        return {"error": f"Query failed: {str(e)}"}


def analyze_threatfox_results(result: dict[str, Any], ioc: str) -> list[Finding]:
    """
    Analyze ThreatFox results for security findings.

    Args:
        result: ThreatFox API result
        ioc: Original IOC queried

    Returns:
        List of security findings
    """
    findings = []

    if result.get("error") or result.get("query_status") == "no_result":
        return findings

    data = result.get("data", []) or []

    if not data:
        return findings

    malware_families = set()
    threat_types = set()
    confidence_levels = []

    for entry in data:
        if entry.get("malware"):
            malware_families.add(entry["malware"])
        if entry.get("threat_type"):
            threat_types.add(entry["threat_type"])
        if entry.get("confidence_level"):
            confidence_levels.append(entry["confidence_level"])

    avg_confidence = (
        sum(confidence_levels) / len(confidence_levels) if confidence_levels else 0
    )

    if avg_confidence >= 75:
        severity = RiskLevel.CRITICAL
    elif avg_confidence >= 50:
        severity = RiskLevel.HIGH
    elif avg_confidence >= 25:
        severity = RiskLevel.MEDIUM
    else:
        severity = RiskLevel.LOW

    findings.append(
        Finding(
            module="threat_intel.threatfox",
            title=f"Malware IOC Detected: {ioc}",
            description=(
                f"IOC {ioc} found in ThreatFox database with {len(data)} entries. "
                f"Associated malware: {', '.join(malware_families) or 'Unknown'}. "
                f"Threat types: {', '.join(threat_types) or 'Unknown'}. "
                f"Average confidence: {avg_confidence:.0f}%."
            ),
            severity=severity,
            data={
                "ioc": ioc,
                "entry_count": len(data),
                "malware_families": list(malware_families),
                "threat_types": list(threat_types),
                "average_confidence": avg_confidence,
                "first_seen": data[0].get("first_seen") if data else None,
                "last_seen": data[-1].get("first_seen") if data else None,
            },
        )
    )

    c2_entries = [e for e in data if e.get("threat_type") == "botnet_cc"]
    if c2_entries:
        findings.append(
            Finding(
                module="threat_intel.threatfox",
                title=f"C2 Infrastructure Detected: {ioc}",
                description=(
                    f"IOC {ioc} is associated with Command & Control infrastructure. "
                    f"Found {len(c2_entries)} C2 entries in ThreatFox."
                ),
                severity=RiskLevel.CRITICAL,
                data={
                    "ioc": ioc,
                    "c2_count": len(c2_entries),
                    "malware": list(
                        {e.get("malware") for e in c2_entries if e.get("malware")}
                    ),
                },
            )
        )

    return findings


def get_threatfox_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of ThreatFox query results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    result = ctx.get("threatfox_result", {})
    data = result.get("data", []) or []

    malware_families = list({e.get("malware") for e in data if e.get("malware")})
    threat_types = list({e.get("threat_type") for e in data if e.get("threat_type")})

    return {
        "queried_ioc": result.get("queried_ioc", ""),
        "entry_count": len(data),
        "malware_families": malware_families,
        "threat_types": threat_types,
        "timestamp": result.get("query_timestamp", ""),
    }
