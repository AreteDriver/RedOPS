"""
AlienVault OTX (Open Threat Exchange) integration.

Provides access to the OTX threat intelligence platform for
IOC lookups, pulse subscriptions, and threat indicator analysis.
"""

from typing import Optional, Dict, Any
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


# AlienVault OTX API endpoint
OTX_API = "https://otx.alienvault.com/api/v1"


def get_indicator(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Get threat intelligence for an indicator (IP, domain, URL, hash).

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - indicator: The indicator to look up (or use ctx.target)
            - indicator_type: Type (IPv4, IPv6, domain, hostname, url, file)
            - api_key: OTX API key (or OTX_API_KEY env var)
            - sections: Sections to retrieve (default: general,geo,malware,url_list)

    Returns:
        Updated context with OTX indicator data
    """
    params = params or {}
    indicator = params.get("indicator") or ctx.target
    api_key = params.get("api_key") or os.environ.get("OTX_API_KEY")
    indicator_type = params.get("indicator_type") or _detect_indicator_type(indicator)
    sections = params.get("sections", ["general", "geo", "malware", "url_list"])

    if not HAS_REQUESTS:
        ctx.log("requests library not available for OTX", level="WARNING")
        return ctx

    if not indicator:
        ctx.log("No indicator specified for OTX lookup", level="WARNING")
        return ctx

    if not api_key:
        ctx.log("OTX API key not configured", level="WARNING")
        ctx.add("otx_indicator", {"error": "API key required"})
        return ctx

    ctx.log(
        f"Querying OTX for indicator: {indicator} (type: {indicator_type})",
        level="INFO",
    )

    headers = {"X-OTX-API-KEY": api_key}

    result = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "sections": {},
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }

    # Query each section
    for section in sections:
        section_data = _query_indicator_section(
            indicator, indicator_type, section, headers
        )
        if section_data:
            result["sections"][section] = section_data

    # Analyze results for threats
    analysis = analyze_otx_indicator(result)
    result["analysis"] = analysis

    # Create findings for malicious indicators
    if analysis.get("is_malicious"):
        finding = Finding(
            module="threat_intel.alienvault",
            title=f"Malicious Indicator: {indicator}",
            description=f"OTX flagged this indicator as malicious. Pulses: {analysis.get('pulse_count', 0)}",
            severity=RiskLevel.HIGH
            if analysis.get("pulse_count", 0) > 5
            else RiskLevel.MEDIUM,
            data=analysis,
        )
        ctx.add(f"finding_otx_{indicator.replace('.', '_')[:50]}", finding.model_dump())

    ctx.log(
        f"OTX query complete: {analysis.get('pulse_count', 0)} pulses found",
        level="INFO",
    )
    ctx.add("otx_indicator", result)
    return ctx


def get_pulses(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Get user's subscribed pulses from OTX.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - api_key: OTX API key (or OTX_API_KEY env var)
            - limit: Max pulses to retrieve (default 10)
            - modified_since: ISO timestamp to filter pulses

    Returns:
        Updated context with subscribed pulses
    """
    params = params or {}
    api_key = params.get("api_key") or os.environ.get("OTX_API_KEY")
    limit = params.get("limit", 10)
    modified_since = params.get("modified_since")

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not api_key:
        ctx.log("OTX API key not configured", level="WARNING")
        ctx.add("otx_pulses", {"error": "API key required"})
        return ctx

    ctx.log("Fetching subscribed OTX pulses", level="INFO")

    headers = {"X-OTX-API-KEY": api_key}
    query_params = {"limit": limit}
    if modified_since:
        query_params["modified_since"] = modified_since

    try:
        response = requests.get(
            f"{OTX_API}/pulses/subscribed",
            headers=headers,
            params=query_params,
            timeout=30,
        )

        if response.status_code == 401:
            ctx.log("OTX authentication failed", level="WARNING")
            ctx.add("otx_pulses", {"error": "Authentication failed"})
            return ctx

        if response.status_code != 200:
            ctx.log(f"OTX pulse fetch failed: {response.status_code}", level="WARNING")
            ctx.add("otx_pulses", {"error": f"HTTP {response.status_code}"})
            return ctx

        data = response.json()
        pulses = data.get("results", [])

        result = {
            "count": len(pulses),
            "next": data.get("next"),
            "pulses": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description", "")[:200],
                    "author_name": p.get("author_name"),
                    "created": p.get("created"),
                    "modified": p.get("modified"),
                    "indicator_count": len(p.get("indicators", [])),
                    "tags": p.get("tags", []),
                    "targeted_countries": p.get("targeted_countries", []),
                    "malware_families": p.get("malware_families", []),
                }
                for p in pulses
            ],
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

        ctx.log(f"Retrieved {len(pulses)} subscribed pulses", level="INFO")
        ctx.add("otx_pulses", result)

    except requests.exceptions.RequestException as e:
        ctx.log(f"OTX pulse fetch failed: {e}", level="WARNING")
        ctx.add("otx_pulses", {"error": str(e)})

    return ctx


def search_pulses(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Search OTX pulses by query.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - query: Search query (or use ctx.target)
            - api_key: OTX API key (or OTX_API_KEY env var)
            - limit: Max results (default 10)

    Returns:
        Updated context with pulse search results
    """
    params = params or {}
    query = params.get("query") or ctx.target
    api_key = params.get("api_key") or os.environ.get("OTX_API_KEY")
    limit = params.get("limit", 10)

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not query:
        ctx.log("No query specified for OTX pulse search", level="WARNING")
        return ctx

    if not api_key:
        ctx.log("OTX API key not configured", level="WARNING")
        ctx.add("otx_pulse_search", {"error": "API key required"})
        return ctx

    ctx.log(f"Searching OTX pulses for: {query}", level="INFO")

    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(
            f"{OTX_API}/search/pulses",
            headers=headers,
            params={"q": query, "limit": limit},
            timeout=30,
        )

        if response.status_code != 200:
            ctx.log(f"OTX pulse search failed: {response.status_code}", level="WARNING")
            ctx.add("otx_pulse_search", {"error": f"HTTP {response.status_code}"})
            return ctx

        data = response.json()
        results = data.get("results", [])

        search_result = {
            "query": query,
            "count": len(results),
            "results": [
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "description": r.get("description", "")[:200],
                    "author_name": r.get("author_name"),
                    "created": r.get("created"),
                    "indicator_count": len(r.get("indicators", [])),
                    "tags": r.get("tags", []),
                }
                for r in results
            ],
            "searched_at": datetime.now(timezone.utc).isoformat(),
        }

        ctx.log(f"Found {len(results)} pulses matching query", level="INFO")
        ctx.add("otx_pulse_search", search_result)

    except requests.exceptions.RequestException as e:
        ctx.log(f"OTX pulse search failed: {e}", level="WARNING")
        ctx.add("otx_pulse_search", {"error": str(e)})

    return ctx


def get_pulse_details(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Get detailed information about a specific pulse.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - pulse_id: The pulse ID to retrieve
            - api_key: OTX API key (or OTX_API_KEY env var)

    Returns:
        Updated context with pulse details
    """
    params = params or {}
    pulse_id = params.get("pulse_id")
    api_key = params.get("api_key") or os.environ.get("OTX_API_KEY")

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not pulse_id:
        ctx.log("No pulse_id specified", level="WARNING")
        return ctx

    if not api_key:
        ctx.log("OTX API key not configured", level="WARNING")
        ctx.add("otx_pulse_details", {"error": "API key required"})
        return ctx

    ctx.log(f"Fetching OTX pulse details: {pulse_id}", level="INFO")

    headers = {"X-OTX-API-KEY": api_key}

    try:
        response = requests.get(
            f"{OTX_API}/pulses/{pulse_id}",
            headers=headers,
            timeout=30,
        )

        if response.status_code == 404:
            ctx.log("Pulse not found", level="WARNING")
            ctx.add(
                "otx_pulse_details", {"error": "Pulse not found", "pulse_id": pulse_id}
            )
            return ctx

        if response.status_code != 200:
            ctx.log(f"OTX pulse fetch failed: {response.status_code}", level="WARNING")
            ctx.add("otx_pulse_details", {"error": f"HTTP {response.status_code}"})
            return ctx

        pulse = response.json()

        # Extract indicators by type
        indicators_by_type = {}
        for ind in pulse.get("indicators", []):
            ind_type = ind.get("type", "unknown")
            if ind_type not in indicators_by_type:
                indicators_by_type[ind_type] = []
            indicators_by_type[ind_type].append(
                {
                    "indicator": ind.get("indicator"),
                    "created": ind.get("created"),
                    "title": ind.get("title"),
                }
            )

        result = {
            "id": pulse.get("id"),
            "name": pulse.get("name"),
            "description": pulse.get("description"),
            "author_name": pulse.get("author_name"),
            "created": pulse.get("created"),
            "modified": pulse.get("modified"),
            "tags": pulse.get("tags", []),
            "targeted_countries": pulse.get("targeted_countries", []),
            "malware_families": pulse.get("malware_families", []),
            "attack_ids": pulse.get("attack_ids", []),
            "references": pulse.get("references", []),
            "indicator_count": len(pulse.get("indicators", [])),
            "indicators_by_type": indicators_by_type,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }

        ctx.log(
            f"Retrieved pulse with {result['indicator_count']} indicators", level="INFO"
        )
        ctx.add("otx_pulse_details", result)

    except requests.exceptions.RequestException as e:
        ctx.log(f"OTX pulse fetch failed: {e}", level="WARNING")
        ctx.add("otx_pulse_details", {"error": str(e)})

    return ctx


def _detect_indicator_type(indicator: str) -> str:
    """Detect the type of indicator."""
    import re

    if not indicator:
        return "unknown"

    # IPv4
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        return "IPv4"

    # IPv6
    if ":" in indicator and not indicator.startswith("http"):
        return "IPv6"

    # URL
    if indicator.startswith(("http://", "https://")):
        return "url"

    # File hash (MD5, SHA1, SHA256)
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "file"  # MD5
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "file"  # SHA1
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "file"  # SHA256

    # Default to domain/hostname
    return "domain"


def _query_indicator_section(
    indicator: str, indicator_type: str, section: str, headers: Dict
) -> Optional[Dict]:
    """Query a specific section for an indicator."""
    try:
        # Map indicator types to API paths
        type_map = {
            "IPv4": "IPv4",
            "IPv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "url": "url",
            "file": "file",
        }
        api_type = type_map.get(indicator_type, "domain")

        response = requests.get(
            f"{OTX_API}/indicators/{api_type}/{indicator}/{section}",
            headers=headers,
            timeout=30,
        )

        if response.status_code == 200:
            return response.json()

        return None

    except requests.exceptions.RequestException:
        return None


def analyze_otx_indicator(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze OTX indicator results.

    Args:
        result: OTX indicator query result

    Returns:
        Analysis summary
    """
    analysis = {
        "is_malicious": False,
        "pulse_count": 0,
        "malware_samples": 0,
        "url_count": 0,
        "reputation": "unknown",
        "tags": [],
        "malware_families": [],
        "countries": [],
    }

    sections = result.get("sections", {})

    # Check general section
    general = sections.get("general", {})
    if general:
        pulse_info = general.get("pulse_info", {})
        analysis["pulse_count"] = pulse_info.get("count", 0)

        # If there are pulses, it's been flagged
        if analysis["pulse_count"] > 0:
            analysis["is_malicious"] = True

            # Extract tags from pulses
            for pulse in pulse_info.get("pulses", []):
                analysis["tags"].extend(pulse.get("tags", []))
                analysis["malware_families"].extend(pulse.get("malware_families", []))
                analysis["countries"].extend(pulse.get("targeted_countries", []))

        # Check reputation
        reputation = general.get("reputation")
        if reputation is not None:
            analysis["reputation"] = "malicious" if reputation < 0 else "clean"

    # Check malware section
    malware = sections.get("malware", {})
    if malware:
        analysis["malware_samples"] = malware.get("count", 0)
        if analysis["malware_samples"] > 0:
            analysis["is_malicious"] = True

    # Check URL list section
    url_list = sections.get("url_list", {})
    if url_list:
        analysis["url_count"] = url_list.get("actual_size", 0)

    # Check geo section
    geo = sections.get("geo", {})
    if geo:
        analysis["country_code"] = geo.get("country_code")
        analysis["asn"] = geo.get("asn")

    # Deduplicate
    analysis["tags"] = list(set(analysis["tags"]))
    analysis["malware_families"] = list(set(analysis["malware_families"]))
    analysis["countries"] = list(set(analysis["countries"]))

    return analysis


def get_otx_summary(result: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of OTX results.

    Args:
        result: OTX result from context

    Returns:
        Summary string
    """
    if result.get("error"):
        return f"OTX error: {result['error']}"

    analysis = result.get("analysis", {})

    parts = [f"Indicator: {result.get('indicator')}"]

    # Malicious status
    if analysis.get("is_malicious"):
        parts.append("Status: MALICIOUS")
        parts.append(f"Pulses: {analysis.get('pulse_count', 0)}")
    else:
        parts.append("Status: Clean")

    # Malware samples
    if analysis.get("malware_samples", 0) > 0:
        parts.append(f"Malware samples: {analysis['malware_samples']}")

    # Tags
    tags = analysis.get("tags", [])
    if tags:
        parts.append(f"Tags: {', '.join(tags[:5])}")

    # Malware families
    families = analysis.get("malware_families", [])
    if families:
        parts.append(f"Families: {', '.join(families[:3])}")

    # Geo
    if analysis.get("country_code"):
        parts.append(f"Country: {analysis['country_code']}")

    return " | ".join(parts)
