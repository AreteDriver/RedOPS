"""
Passive DNS threat intelligence integration.

Queries passive DNS databases to discover historical DNS records,
domain-IP relationships, and infrastructure changes over time.
"""

from typing import Any
from datetime import datetime, timezone
import os
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Passive DNS API endpoints
MNEMONIC_API = "https://api.mnemonic.no/pdns/v3"
CIRCL_API = "https://www.circl.lu/pdns/query"


def query_passivedns(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query passive DNS databases for historical DNS data.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - query: Domain or IP to query (or use ctx.target)
            - api_key: Mnemonic API key (or MNEMONIC_API_KEY env var)
            - limit: Max results to return (default 100)
            - source: Data source (mnemonic, circl, all)

    Returns:
        Updated context with passive DNS results
    """
    params = params or {}
    query = params.get("query") or ctx.target
    api_key = params.get("api_key") or os.environ.get("MNEMONIC_API_KEY")
    limit = params.get("limit", 100)
    source = params.get("source", "mnemonic")

    if not HAS_REQUESTS:
        ctx.log("requests library not available for passive DNS", level="WARNING")
        return ctx

    if not query:
        ctx.log("No query specified for passive DNS lookup", level="WARNING")
        return ctx

    ctx.log(f"Querying passive DNS for: {query}", level="INFO")

    results = {
        "query": query,
        "query_type": _detect_query_type(query),
        "records": [],
        "sources": [],
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }

    # Query selected sources
    if source in ("mnemonic", "all"):
        mnemonic_result = _query_mnemonic(query, api_key, limit)
        if mnemonic_result.get("records"):
            results["records"].extend(mnemonic_result["records"])
            results["sources"].append("mnemonic")
        if mnemonic_result.get("error"):
            results["mnemonic_error"] = mnemonic_result["error"]

    if source in ("circl", "all"):
        circl_result = _query_circl(query, limit)
        if circl_result.get("records"):
            results["records"].extend(circl_result["records"])
            results["sources"].append("circl")
        if circl_result.get("error"):
            results["circl_error"] = circl_result["error"]

    # Deduplicate records
    seen = set()
    unique_records = []
    for record in results["records"]:
        key = (record.get("rrname"), record.get("rrtype"), record.get("rdata"))
        if key not in seen:
            seen.add(key)
            unique_records.append(record)
    results["records"] = unique_records[:limit]

    # Analyze results
    analysis = analyze_passivedns_results(results)
    results["analysis"] = analysis

    ctx.log(f"Found {len(results['records'])} passive DNS records", level="INFO")

    # Create findings for suspicious patterns
    if analysis.get("suspicious_patterns"):
        for pattern in analysis["suspicious_patterns"]:
            finding = Finding(
                module="threat_intel.passivedns",
                title=f"Suspicious DNS Pattern: {pattern['type']}",
                description=pattern["description"],
                severity=RiskLevel.MEDIUM,
                data=pattern,
            )
            ctx.add(
                f"finding_pdns_{pattern['type']}_{query.replace('.', '_')}",
                finding.model_dump(),
            )

    ctx.add("passivedns_result", results)
    return ctx


def get_domain_history(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Get IP address history for a domain.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - domain: Domain to query (or use ctx.target)
            - api_key: API key

    Returns:
        Updated context with domain IP history
    """
    params = params or {}
    domain = params.get("domain") or ctx.target
    api_key = params.get("api_key") or os.environ.get("MNEMONIC_API_KEY")

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not domain:
        ctx.log("No domain specified", level="WARNING")
        return ctx

    ctx.log(f"Getting IP history for domain: {domain}", level="INFO")

    # Query for A records
    result = _query_mnemonic(domain, api_key, limit=500)

    history = {
        "domain": domain,
        "ip_addresses": [],
        "first_seen": None,
        "last_seen": None,
        "total_records": 0,
    }

    if result.get("records"):
        a_records = [r for r in result["records"] if r.get("rrtype") == "A"]
        history["total_records"] = len(a_records)

        # Extract unique IPs with timestamps
        ip_data = {}
        for record in a_records:
            ip = record.get("rdata")
            if ip:
                if ip not in ip_data:
                    ip_data[ip] = {
                        "ip": ip,
                        "first_seen": record.get("time_first"),
                        "last_seen": record.get("time_last"),
                        "count": 0,
                    }
                ip_data[ip]["count"] += 1
                # Update timestamps
                if record.get("time_first"):
                    if (
                        not ip_data[ip]["first_seen"]
                        or record["time_first"] < ip_data[ip]["first_seen"]
                    ):
                        ip_data[ip]["first_seen"] = record["time_first"]
                if record.get("time_last"):
                    if (
                        not ip_data[ip]["last_seen"]
                        or record["time_last"] > ip_data[ip]["last_seen"]
                    ):
                        ip_data[ip]["last_seen"] = record["time_last"]

        history["ip_addresses"] = sorted(
            ip_data.values(), key=lambda x: x.get("last_seen") or "", reverse=True
        )

        # Overall first/last seen
        all_times = [r.get("time_first") for r in a_records if r.get("time_first")]
        all_times.extend([r.get("time_last") for r in a_records if r.get("time_last")])
        if all_times:
            history["first_seen"] = min(all_times)
            history["last_seen"] = max(all_times)

    ctx.log(f"Found {len(history['ip_addresses'])} unique IPs", level="INFO")
    ctx.add("domain_ip_history", history)
    return ctx


def get_ip_history(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Get domain history for an IP address.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - ip: IP address to query (or use ctx.target)
            - api_key: API key

    Returns:
        Updated context with IP domain history
    """
    params = params or {}
    ip = params.get("ip") or ctx.target
    api_key = params.get("api_key") or os.environ.get("MNEMONIC_API_KEY")

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not ip:
        ctx.log("No IP specified", level="WARNING")
        return ctx

    ctx.log(f"Getting domain history for IP: {ip}", level="INFO")

    result = _query_mnemonic(ip, api_key, limit=500)

    history = {
        "ip": ip,
        "domains": [],
        "first_seen": None,
        "last_seen": None,
        "total_records": 0,
    }

    if result.get("records"):
        history["total_records"] = len(result["records"])

        # Extract unique domains with timestamps
        domain_data = {}
        for record in result["records"]:
            domain = record.get("rrname")
            if domain:
                domain = domain.rstrip(".")
                if domain not in domain_data:
                    domain_data[domain] = {
                        "domain": domain,
                        "rrtype": record.get("rrtype"),
                        "first_seen": record.get("time_first"),
                        "last_seen": record.get("time_last"),
                        "count": 0,
                    }
                domain_data[domain]["count"] += 1

        history["domains"] = sorted(
            domain_data.values(), key=lambda x: x.get("last_seen") or "", reverse=True
        )

        # Overall first/last seen
        all_times = [
            r.get("time_first") for r in result["records"] if r.get("time_first")
        ]
        all_times.extend(
            [r.get("time_last") for r in result["records"] if r.get("time_last")]
        )
        if all_times:
            history["first_seen"] = min(all_times)
            history["last_seen"] = max(all_times)

    ctx.log(f"Found {len(history['domains'])} domains for IP", level="INFO")
    ctx.add("ip_domain_history", history)
    return ctx


def _query_mnemonic(
    query: str, api_key: str | None, limit: int = 100
) -> dict[str, Any]:
    """Query Mnemonic passive DNS API."""
    headers = {}
    if api_key:
        headers["Argus-API-Key"] = api_key

    try:
        response = requests.get(
            f"{MNEMONIC_API}/{query}",
            headers=headers,
            params={"limit": limit},
            timeout=30,
        )

        if response.status_code == 401:
            return {"error": "Authentication required", "records": []}

        if response.status_code == 404:
            return {"records": []}

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}", "records": []}

        data = response.json()

        # Normalize records
        records = []
        for item in data.get("data", []):
            record = {
                "rrname": item.get("query"),
                "rrtype": item.get("rrtype"),
                "rdata": item.get("answer"),
                "time_first": item.get("firstSeenTimestamp"),
                "time_last": item.get("lastSeenTimestamp"),
                "source": "mnemonic",
            }
            records.append(record)

        return {"records": records}

    except requests.exceptions.RequestException as e:
        return {"error": str(e), "records": []}


def _query_circl(query: str, limit: int = 100) -> dict[str, Any]:
    """Query CIRCL passive DNS (public, no auth required)."""
    try:
        response = requests.get(
            f"{CIRCL_API}/{query}",
            timeout=30,
        )

        if response.status_code == 404:
            return {"records": []}

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}", "records": []}

        # CIRCL returns NDJSON (newline-delimited JSON)
        records = []
        for line in response.text.strip().split("\n"):
            if line:
                try:
                    import json

                    item = json.loads(line)
                    record = {
                        "rrname": item.get("rrname"),
                        "rrtype": item.get("rrtype"),
                        "rdata": item.get("rdata"),
                        "time_first": item.get("time_first"),
                        "time_last": item.get("time_last"),
                        "source": "circl",
                    }
                    records.append(record)
                except (ValueError, TypeError):
                    continue

        return {"records": records[:limit]}

    except requests.exceptions.RequestException as e:
        return {"error": str(e), "records": []}


def _detect_query_type(query: str) -> str:
    """Detect if query is an IP or domain."""
    import re

    # IPv4 pattern
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query):
        return "ip"
    # IPv6 pattern (simplified)
    if ":" in query:
        return "ip"
    return "domain"


def analyze_passivedns_results(results: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze passive DNS results for suspicious patterns.

    Args:
        results: Passive DNS query results

    Returns:
        Analysis summary
    """
    analysis = {
        "total_records": len(results.get("records", [])),
        "unique_ips": set(),
        "unique_domains": set(),
        "record_types": {},
        "suspicious_patterns": [],
        "infrastructure_changes": 0,
    }

    records = results.get("records", [])

    for record in records:
        # Count record types
        rrtype = record.get("rrtype", "UNKNOWN")
        analysis["record_types"][rrtype] = analysis["record_types"].get(rrtype, 0) + 1

        # Collect unique values
        if record.get("rdata"):
            rdata = record["rdata"]
            if _detect_query_type(rdata) == "ip":
                analysis["unique_ips"].add(rdata)
            else:
                analysis["unique_domains"].add(rdata)

        if record.get("rrname"):
            rrname = record["rrname"].rstrip(".")
            analysis["unique_domains"].add(rrname)

    # Convert sets to lists for JSON serialization
    analysis["unique_ips"] = list(analysis["unique_ips"])
    analysis["unique_domains"] = list(analysis["unique_domains"])

    # Detect suspicious patterns
    query_type = results.get("query_type")

    # High IP churn (domain pointing to many IPs)
    if query_type == "domain" and len(analysis["unique_ips"]) > 10:
        analysis["suspicious_patterns"].append(
            {
                "type": "high_ip_churn",
                "description": f"Domain has pointed to {len(analysis['unique_ips'])} different IPs",
                "count": len(analysis["unique_ips"]),
                "severity": "medium",
            }
        )

    # High domain count on IP (shared hosting or malicious)
    if query_type == "ip" and len(analysis["unique_domains"]) > 50:
        analysis["suspicious_patterns"].append(
            {
                "type": "high_domain_count",
                "description": f"IP hosts {len(analysis['unique_domains'])} domains",
                "count": len(analysis["unique_domains"]),
                "severity": "low",
            }
        )

    # Estimate infrastructure changes
    analysis["infrastructure_changes"] = max(len(analysis["unique_ips"]) - 1, 0)

    return analysis


def get_passivedns_summary(result: dict[str, Any]) -> str:
    """
    Generate a human-readable summary of passive DNS results.

    Args:
        result: Passive DNS result from context

    Returns:
        Summary string
    """
    if result.get("error"):
        return f"Passive DNS error: {result['error']}"

    analysis = result.get("analysis", {})

    parts = [
        f"Query: {result.get('query')}",
        f"Records: {analysis.get('total_records', 0)}",
        f"Unique IPs: {len(analysis.get('unique_ips', []))}",
        f"Unique Domains: {len(analysis.get('unique_domains', []))}",
    ]

    # Record type breakdown
    record_types = analysis.get("record_types", {})
    if record_types:
        type_str = ", ".join(f"{k}:{v}" for k, v in sorted(record_types.items()))
        parts.append(f"Types: {type_str}")

    # Suspicious patterns
    patterns = analysis.get("suspicious_patterns", [])
    if patterns:
        parts.append(f"Warnings: {len(patterns)}")

    return " | ".join(parts)
