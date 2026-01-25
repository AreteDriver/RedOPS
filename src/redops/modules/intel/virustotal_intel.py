"""
VirusTotal Intelligence module.

Queries VirusTotal API for threat intelligence:
- URL/domain reputation and analysis
- IP address reports
- File hash lookups
- Detection results from multiple AV engines

IMPORTANT: Requires a VirusTotal API key.
Free tier has rate limits (4 requests/minute).
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import os

from redops.core.context import Context


@dataclass
class VTDomainReport:
    """VirusTotal domain report."""

    domain: str
    reputation: int = 0
    categories: Dict[str, str] = field(default_factory=dict)
    last_analysis_stats: Dict[str, int] = field(default_factory=dict)
    last_analysis_date: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    whois: Optional[str] = None
    dns_records: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "reputation": self.reputation,
            "categories": self.categories,
            "last_analysis_stats": self.last_analysis_stats,
            "last_analysis_date": self.last_analysis_date,
            "registrar": self.registrar,
            "creation_date": self.creation_date,
            "whois": self.whois,
            "dns_records": self.dns_records,
        }


@dataclass
class VTIPReport:
    """VirusTotal IP report."""

    ip: str
    reputation: int = 0
    country: Optional[str] = None
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    last_analysis_stats: Dict[str, int] = field(default_factory=dict)
    last_analysis_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "reputation": self.reputation,
            "country": self.country,
            "asn": self.asn,
            "as_owner": self.as_owner,
            "last_analysis_stats": self.last_analysis_stats,
            "last_analysis_date": self.last_analysis_date,
        }


@dataclass
class VTURLReport:
    """VirusTotal URL report."""

    url: str
    reputation: int = 0
    last_analysis_stats: Dict[str, int] = field(default_factory=dict)
    last_analysis_date: Optional[str] = None
    categories: Dict[str, str] = field(default_factory=dict)
    threat_names: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "reputation": self.reputation,
            "last_analysis_stats": self.last_analysis_stats,
            "last_analysis_date": self.last_analysis_date,
            "categories": self.categories,
            "threat_names": self.threat_names,
        }


def get_vt_api_key() -> Optional[str]:
    """Get VirusTotal API key."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        try:
            from redops.cli.settings import get_api_key_direct
            api_key = get_api_key_direct("virustotal")
        except Exception:
            pass
    return api_key


def _make_vt_request(endpoint: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Make a request to VirusTotal API."""
    try:
        import requests
    except ImportError:
        return None

    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "not_found"}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def query_vt_domain(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query VirusTotal for domain information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to query (default: target)

    Returns:
        Updated context with VirusTotal domain data
    """
    params = params or {}
    target = params.get("domain") or ctx.target

    if not target:
        ctx.log("No target specified for VirusTotal domain query", level="WARNING")
        return ctx

    domain = _extract_domain(target)
    ctx.log(f"Querying VirusTotal for domain: {domain}", level="INFO")

    vt_data = {
        "domain": domain,
        "report": None,
        "error": None,
    }

    api_key = get_vt_api_key()
    if not api_key:
        vt_data["error"] = "VirusTotal API key not configured"
        ctx.log(vt_data["error"], level="WARNING")
        ctx.add("virustotal_domain", vt_data)
        return ctx

    result = _make_vt_request(f"domains/{domain}", api_key)

    if result is None:
        vt_data["error"] = "requests library not available"
    elif "error" in result:
        vt_data["error"] = result["error"]
    else:
        data = result.get("data", {}).get("attributes", {})
        report = VTDomainReport(
            domain=domain,
            reputation=data.get("reputation", 0),
            categories=data.get("categories", {}),
            last_analysis_stats=data.get("last_analysis_stats", {}),
            last_analysis_date=data.get("last_analysis_date"),
            registrar=data.get("registrar"),
            creation_date=data.get("creation_date"),
            whois=data.get("whois"),
        )

        # Parse DNS records
        if data.get("last_dns_records"):
            report.dns_records = data["last_dns_records"]

        vt_data["report"] = report.to_dict()

        stats = report.last_analysis_stats
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        ctx.log(
            f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections",
            level="INFO",
        )

    ctx.add("virustotal_domain", vt_data)
    return ctx


def query_vt_ip(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query VirusTotal for IP information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - ip: IP address to query

    Returns:
        Updated context with VirusTotal IP data
    """
    params = params or {}
    target = params.get("ip") or ctx.target

    if not target:
        ctx.log("No target specified for VirusTotal IP query", level="WARNING")
        return ctx

    # Resolve domain to IP if needed
    ip = target
    if not _is_ip(target):
        try:
            import socket
            ip = socket.gethostbyname(target)
        except Exception as e:
            ctx.log(f"Could not resolve {target}: {e}", level="WARNING")
            return ctx

    ctx.log(f"Querying VirusTotal for IP: {ip}", level="INFO")

    vt_data = {
        "ip": ip,
        "report": None,
        "error": None,
    }

    api_key = get_vt_api_key()
    if not api_key:
        vt_data["error"] = "VirusTotal API key not configured"
        ctx.log(vt_data["error"], level="WARNING")
        ctx.add("virustotal_ip", vt_data)
        return ctx

    result = _make_vt_request(f"ip_addresses/{ip}", api_key)

    if result is None:
        vt_data["error"] = "requests library not available"
    elif "error" in result:
        vt_data["error"] = result["error"]
    else:
        data = result.get("data", {}).get("attributes", {})
        report = VTIPReport(
            ip=ip,
            reputation=data.get("reputation", 0),
            country=data.get("country"),
            asn=data.get("asn"),
            as_owner=data.get("as_owner"),
            last_analysis_stats=data.get("last_analysis_stats", {}),
            last_analysis_date=data.get("last_analysis_date"),
        )

        vt_data["report"] = report.to_dict()

        stats = report.last_analysis_stats
        malicious = stats.get("malicious", 0)
        ctx.log(f"VirusTotal IP: {malicious} malicious detections", level="INFO")

    ctx.add("virustotal_ip", vt_data)
    return ctx


def query_vt_url(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Query VirusTotal for URL analysis.

    Args:
        ctx: Pipeline context
        params: Required parameters:
            - url: URL to analyze

    Returns:
        Updated context with VirusTotal URL data
    """
    params = params or {}
    url = params.get("url")

    if not url:
        # Build URL from target
        target = ctx.target
        if target:
            url = f"https://{target}" if not target.startswith("http") else target
        else:
            ctx.log("No URL specified for VirusTotal query", level="WARNING")
            return ctx

    ctx.log(f"Querying VirusTotal for URL: {url}", level="INFO")

    vt_data = {
        "url": url,
        "report": None,
        "error": None,
    }

    api_key = get_vt_api_key()
    if not api_key:
        vt_data["error"] = "VirusTotal API key not configured"
        ctx.log(vt_data["error"], level="WARNING")
        ctx.add("virustotal_url", vt_data)
        return ctx

    # URL ID is base64 of URL without padding
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    result = _make_vt_request(f"urls/{url_id}", api_key)

    if result is None:
        vt_data["error"] = "requests library not available"
    elif "error" in result:
        if result["error"] == "not_found":
            vt_data["error"] = "URL not previously scanned by VirusTotal"
        else:
            vt_data["error"] = result["error"]
    else:
        data = result.get("data", {}).get("attributes", {})
        report = VTURLReport(
            url=url,
            reputation=data.get("reputation", 0),
            last_analysis_stats=data.get("last_analysis_stats", {}),
            last_analysis_date=data.get("last_analysis_date"),
            categories=data.get("categories", {}),
            threat_names=data.get("threat_names", []),
        )

        vt_data["report"] = report.to_dict()

        stats = report.last_analysis_stats
        malicious = stats.get("malicious", 0)
        ctx.log(f"VirusTotal URL: {malicious} malicious detections", level="INFO")

    ctx.add("virustotal_url", vt_data)
    return ctx


def analyze_virustotal_intel(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Run comprehensive VirusTotal analysis.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context with VirusTotal intel
    """
    params = params or {}
    target = ctx.target

    ctx.log(f"Running VirusTotal intelligence for: {target}", level="INFO")

    # Query domain
    if target and not _is_ip(target):
        ctx = query_vt_domain(ctx, params)

    # Query IP
    ctx = query_vt_ip(ctx, params)

    # Compile summary
    vt_intel = {
        "target": target,
        "domain": ctx.get("virustotal_domain", {}),
        "ip": ctx.get("virustotal_ip", {}),
        "summary": {},
    }

    # Generate summary
    domain_data = vt_intel["domain"]
    ip_data = vt_intel["ip"]

    total_malicious = 0
    total_suspicious = 0

    if domain_data.get("report"):
        stats = domain_data["report"].get("last_analysis_stats", {})
        total_malicious += stats.get("malicious", 0)
        total_suspicious += stats.get("suspicious", 0)
        vt_intel["summary"]["domain_reputation"] = domain_data["report"].get("reputation", 0)

    if ip_data.get("report"):
        stats = ip_data["report"].get("last_analysis_stats", {})
        total_malicious += stats.get("malicious", 0)
        total_suspicious += stats.get("suspicious", 0)
        vt_intel["summary"]["ip_reputation"] = ip_data["report"].get("reputation", 0)
        vt_intel["summary"]["country"] = ip_data["report"].get("country")
        vt_intel["summary"]["asn"] = ip_data["report"].get("asn")

    vt_intel["summary"]["total_malicious"] = total_malicious
    vt_intel["summary"]["total_suspicious"] = total_suspicious
    vt_intel["summary"]["is_malicious"] = total_malicious > 0

    ctx.add("virustotal_intel", vt_intel)

    ctx.log(
        f"VirusTotal intel complete: {total_malicious} malicious, {total_suspicious} suspicious",
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
    if "://" in value:
        value = value.split("://", 1)[1]
    if "/" in value:
        value = value.split("/", 1)[0]
    if ":" in value:
        value = value.split(":", 1)[0]
    return value
