"""
URLScan.io threat intelligence integration.

Provides URL scanning and analysis capabilities via the URLScan.io API.
Can scan URLs for malicious content and retrieve scan results.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import os
import time
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# URLScan.io API endpoints
URLSCAN_API = "https://urlscan.io/api/v1"


def scan_url(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Submit a URL for scanning via URLScan.io.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - url: URL to scan (or use ctx.target)
            - api_key: URLScan.io API key (or URLSCAN_API_KEY env var)
            - visibility: Scan visibility (public, unlisted, private)
            - wait_for_result: Wait for scan to complete (default True)
            - timeout: Max seconds to wait for result (default 60)

    Returns:
        Updated context with URLScan.io results
    """
    params = params or {}
    url = params.get("url") or ctx.target
    api_key = params.get("api_key") or os.environ.get("URLSCAN_API_KEY")
    visibility = params.get("visibility", "unlisted")
    wait_for_result = params.get("wait_for_result", True)
    timeout = params.get("timeout", 60)

    if not HAS_REQUESTS:
        ctx.log("requests library not available for URLScan.io", level="WARNING")
        return ctx

    if not url:
        ctx.log("No URL specified for URLScan.io scan", level="WARNING")
        return ctx

    if not api_key:
        ctx.log("URLScan.io API key not configured", level="WARNING")
        ctx.add("urlscan_result", {"error": "API key required"})
        return ctx

    ctx.log(f"Submitting URL to URLScan.io: {url}", level="INFO")

    # Submit scan
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "url": url,
        "visibility": visibility,
    }

    try:
        response = requests.post(
            f"{URLSCAN_API}/scan/",
            headers=headers,
            json=payload,
            timeout=30,
        )

        if response.status_code == 429:
            ctx.log("URLScan.io rate limit exceeded", level="WARNING")
            ctx.add("urlscan_result", {"error": "Rate limit exceeded"})
            return ctx

        if response.status_code != 200:
            ctx.log(f"URLScan.io submission failed: {response.status_code}", level="WARNING")
            ctx.add("urlscan_result", {"error": f"HTTP {response.status_code}"})
            return ctx

        submission = response.json()
        scan_uuid = submission.get("uuid")
        result_url = submission.get("result")

        ctx.log(f"Scan submitted, UUID: {scan_uuid}", level="INFO")

        result = {
            "url": url,
            "uuid": scan_uuid,
            "result_url": result_url,
            "api_url": submission.get("api"),
            "visibility": visibility,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }

        if wait_for_result and scan_uuid:
            # Poll for results
            scan_result = _wait_for_scan_result(scan_uuid, api_key, timeout)
            if scan_result:
                result["scan_result"] = scan_result
                result["completed"] = True

                # Analyze for threats
                analysis = analyze_urlscan_results(scan_result)
                result["analysis"] = analysis

                # Create findings if malicious
                if analysis.get("is_malicious"):
                    finding = Finding(
                        module="threat_intel.urlscan",
                        title=f"Malicious URL Detected: {url}",
                        description=f"URLScan.io detected malicious content. Verdict: {analysis.get('verdict')}",
                        severity=RiskLevel.HIGH,
                        data=analysis,
                    )
                    ctx.add(f"finding_urlscan_{scan_uuid[:8]}", finding.model_dump())
            else:
                result["completed"] = False
                ctx.log("Scan did not complete within timeout", level="WARNING")

        ctx.add("urlscan_result", result)

    except requests.exceptions.Timeout:
        ctx.log("URLScan.io request timed out", level="WARNING")
        ctx.add("urlscan_result", {"error": "Request timeout"})
    except requests.exceptions.RequestException as e:
        ctx.log(f"URLScan.io request failed: {e}", level="WARNING")
        ctx.add("urlscan_result", {"error": str(e)})

    return ctx


def search_urlscan(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Search URLScan.io for existing scans.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - query: Search query (domain, IP, hash, etc.)
            - api_key: URLScan.io API key
            - size: Number of results (default 100)

    Returns:
        Updated context with search results
    """
    params = params or {}
    query = params.get("query") or params.get("domain") or ctx.target
    api_key = params.get("api_key") or os.environ.get("URLSCAN_API_KEY")
    size = params.get("size", 100)

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not query:
        ctx.log("No query specified for URLScan.io search", level="WARNING")
        return ctx

    ctx.log(f"Searching URLScan.io for: {query}", level="INFO")

    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    try:
        # Build search query
        search_query = query
        if ":" not in query:
            # Assume domain search if no field specified
            search_query = f"domain:{query}"

        response = requests.get(
            f"{URLSCAN_API}/search/",
            headers=headers,
            params={"q": search_query, "size": size},
            timeout=30,
        )

        if response.status_code != 200:
            ctx.log(f"URLScan.io search failed: {response.status_code}", level="WARNING")
            ctx.add("urlscan_search", {"error": f"HTTP {response.status_code}"})
            return ctx

        data = response.json()
        results = data.get("results", [])

        ctx.log(f"Found {len(results)} scan results", level="INFO")

        search_result = {
            "query": query,
            "total": data.get("total", len(results)),
            "results": results[:20],  # Limit stored results
            "has_more": data.get("has_more", False),
            "searched_at": datetime.now(timezone.utc).isoformat(),
        }

        # Analyze results for threats
        malicious_count = 0
        for result in results:
            verdicts = result.get("verdicts", {})
            if verdicts.get("overall", {}).get("malicious"):
                malicious_count += 1

        search_result["malicious_count"] = malicious_count

        if malicious_count > 0:
            finding = Finding(
                module="threat_intel.urlscan",
                title=f"Malicious Scans Found for {query}",
                description=f"Found {malicious_count} malicious scan(s) in URLScan.io history",
                severity=RiskLevel.MEDIUM,
                data={"query": query, "malicious_count": malicious_count},
            )
            ctx.add(f"finding_urlscan_search_{query.replace('.', '_')}", finding.model_dump())

        ctx.add("urlscan_search", search_result)

    except requests.exceptions.RequestException as e:
        ctx.log(f"URLScan.io search failed: {e}", level="WARNING")
        ctx.add("urlscan_search", {"error": str(e)})

    return ctx


def get_scan_result(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Retrieve results for a specific scan UUID.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - uuid: Scan UUID to retrieve
            - api_key: URLScan.io API key

    Returns:
        Updated context with scan results
    """
    params = params or {}
    uuid = params.get("uuid")
    api_key = params.get("api_key") or os.environ.get("URLSCAN_API_KEY")

    if not HAS_REQUESTS:
        ctx.log("requests library not available", level="WARNING")
        return ctx

    if not uuid:
        ctx.log("No UUID specified for URLScan.io result retrieval", level="WARNING")
        return ctx

    ctx.log(f"Retrieving URLScan.io result: {uuid}", level="INFO")

    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    try:
        response = requests.get(
            f"{URLSCAN_API}/result/{uuid}/",
            headers=headers,
            timeout=30,
        )

        if response.status_code == 404:
            ctx.log("Scan result not found or not yet available", level="WARNING")
            ctx.add("urlscan_result", {"error": "Not found", "uuid": uuid})
            return ctx

        if response.status_code != 200:
            ctx.log(f"Failed to retrieve scan: {response.status_code}", level="WARNING")
            ctx.add("urlscan_result", {"error": f"HTTP {response.status_code}"})
            return ctx

        result = response.json()
        analysis = analyze_urlscan_results(result)

        ctx.add("urlscan_result", {
            "uuid": uuid,
            "scan_result": result,
            "analysis": analysis,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
        })

    except requests.exceptions.RequestException as e:
        ctx.log(f"Failed to retrieve URLScan.io result: {e}", level="WARNING")
        ctx.add("urlscan_result", {"error": str(e)})

    return ctx


def _wait_for_scan_result(uuid: str, api_key: str, timeout: int = 60) -> Optional[Dict]:
    """Wait for scan to complete and return result."""
    headers = {"API-Key": api_key} if api_key else {}
    start_time = time.time()
    poll_interval = 5

    while time.time() - start_time < timeout:
        try:
            response = requests.get(
                f"{URLSCAN_API}/result/{uuid}/",
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                return response.json()

            # 404 means scan not yet complete
            if response.status_code != 404:
                return None

        except requests.exceptions.RequestException:
            pass

        time.sleep(poll_interval)

    return None


def analyze_urlscan_results(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze URLScan.io results for threat indicators.

    Args:
        result: URLScan.io scan result

    Returns:
        Analysis summary
    """
    analysis = {
        "is_malicious": False,
        "verdict": "clean",
        "score": 0,
        "threats": [],
        "categories": [],
        "technologies": [],
        "certificates": [],
        "requests_count": 0,
        "domains_contacted": [],
        "ips_contacted": [],
    }

    # Check verdicts
    verdicts = result.get("verdicts", {})
    overall = verdicts.get("overall", {})

    if overall.get("malicious"):
        analysis["is_malicious"] = True
        analysis["verdict"] = "malicious"
        analysis["score"] = overall.get("score", 100)

    # Collect threat tags
    for source, verdict in verdicts.items():
        if isinstance(verdict, dict):
            if verdict.get("malicious"):
                analysis["threats"].append({
                    "source": source,
                    "categories": verdict.get("categories", []),
                })
            analysis["categories"].extend(verdict.get("categories", []))

    # Deduplicate categories
    analysis["categories"] = list(set(analysis["categories"]))

    # Extract page info
    page = result.get("page", {})
    analysis["final_url"] = page.get("url")
    analysis["status_code"] = page.get("status")
    analysis["title"] = page.get("title")
    analysis["server"] = page.get("server")
    analysis["mime_type"] = page.get("mimeType")

    # Extract list data
    lists = result.get("lists", {})
    analysis["domains_contacted"] = lists.get("domains", [])[:20]
    analysis["ips_contacted"] = lists.get("ips", [])[:20]
    analysis["certificates"] = lists.get("certificates", [])[:10]

    # Count requests
    data = result.get("data", {})
    requests_data = data.get("requests", [])
    analysis["requests_count"] = len(requests_data)

    # Extract technologies
    meta = result.get("meta", {})
    processors = meta.get("processors", {})
    wappa = processors.get("wappa", {})
    analysis["technologies"] = [
        {"name": t.get("app"), "categories": t.get("categories", [])}
        for t in wappa.get("data", [])
    ][:20]

    return analysis


def get_urlscan_summary(result: Dict[str, Any]) -> str:
    """
    Generate a human-readable summary of URLScan.io results.

    Args:
        result: URLScan.io result from context

    Returns:
        Summary string
    """
    if result.get("error"):
        return f"URLScan.io error: {result['error']}"

    analysis = result.get("analysis", {})
    scan = result.get("scan_result", {})

    parts = []

    # Verdict
    verdict = analysis.get("verdict", "unknown")
    parts.append(f"Verdict: {verdict.upper()}")

    if analysis.get("is_malicious"):
        parts.append(f"Score: {analysis.get('score', 'N/A')}/100")
        if analysis.get("threats"):
            sources = [t["source"] for t in analysis["threats"]]
            parts.append(f"Flagged by: {', '.join(sources)}")

    # Page info
    if analysis.get("final_url"):
        parts.append(f"Final URL: {analysis['final_url']}")
    if analysis.get("title"):
        parts.append(f"Title: {analysis['title']}")

    # Stats
    parts.append(f"Requests: {analysis.get('requests_count', 0)}")
    parts.append(f"Domains contacted: {len(analysis.get('domains_contacted', []))}")
    parts.append(f"IPs contacted: {len(analysis.get('ips_contacted', []))}")

    # Technologies
    techs = analysis.get("technologies", [])
    if techs:
        tech_names = [t["name"] for t in techs[:5]]
        parts.append(f"Technologies: {', '.join(tech_names)}")

    return " | ".join(parts)
