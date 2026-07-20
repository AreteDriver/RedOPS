"""
Censys Intelligence module.

Queries Censys API for host and certificate intelligence:
- Host/IP information (open ports, services, protocols)
- Certificate transparency data
- Organization and ASN data
- Historical data

IMPORTANT: Requires Censys API credentials (API ID and Secret).
This module uses publicly available data from Censys's database.
"""

from typing import Any
from dataclasses import dataclass, field
import os

from redops.core.context import Context


@dataclass
class CensysHost:
    """Censys host result."""

    ip: str
    services: list[dict[str, Any]] = field(default_factory=list)
    location: dict[str, Any] = field(default_factory=dict)
    autonomous_system: dict[str, Any] = field(default_factory=dict)
    operating_system: str | None = None
    dns: dict[str, Any] = field(default_factory=dict)
    last_updated: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "services": self.services,
            "location": self.location,
            "autonomous_system": self.autonomous_system,
            "operating_system": self.operating_system,
            "dns": self.dns,
            "last_updated": self.last_updated,
        }


@dataclass
class CensysCertificate:
    """Censys certificate result."""

    fingerprint: str
    names: list[str] = field(default_factory=list)
    issuer: str | None = None
    subject: str | None = None
    validity: dict[str, Any] = field(default_factory=dict)
    key_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "fingerprint": self.fingerprint,
            "names": self.names,
            "issuer": self.issuer,
            "subject": self.subject,
            "validity": self.validity,
            "key_info": self.key_info,
        }


def get_censys_client():
    """
    Get Censys API client.

    Returns:
        Tuple of (hosts_client, certs_client) or (None, None)
    """
    try:
        from censys.search import CensysHosts, CensysCerts
    except ImportError:
        return None, None

    # Check for API credentials
    api_id = os.environ.get("CENSYS_API_ID")
    api_secret = os.environ.get("CENSYS_API_SECRET")

    if not api_id or not api_secret:
        # Try to get from settings
        try:
            from redops.cli.settings import get_api_key_direct

            api_id = get_api_key_direct("censys_id")
            api_secret = get_api_key_direct("censys_secret")
        except (OSError, RuntimeError, TypeError, ValueError, ImportError):
            pass

    if not api_id or not api_secret:
        return None, None

    try:
        hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
        certs = CensysCerts(api_id=api_id, api_secret=api_secret)
        return hosts, certs
    except (OSError, RuntimeError, TypeError, ValueError, ImportError):
        return None, None


def query_censys_host(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Query Censys for host information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - ip: IP address to query (default: resolved from target)

    Returns:
        Updated context with Censys host data
    """
    params = params or {}
    target = params.get("ip") or ctx.target

    if not target:
        ctx.log("No target specified for Censys host query", level="WARNING")
        return ctx

    ctx.log(f"Querying Censys for host: {target}", level="INFO")

    # Initialize result
    censys_data = {
        "target": target,
        "hosts": [],
        "error": None,
    }

    hosts_client, _ = get_censys_client()
    if not hosts_client:
        censys_data["error"] = (
            "Censys API not available (missing censys package or API credentials)"
        )
        ctx.log(censys_data["error"], level="WARNING")
        ctx.add("censys_host", censys_data)
        return ctx

    try:
        # If target is a domain, resolve to IP first
        ip = target
        if not _is_ip(target):
            try:
                import socket

                ip = socket.gethostbyname(target)
                ctx.log(f"Resolved {target} to {ip}", level="DEBUG")
            except (OSError, ValueError, TypeError) as e:
                ctx.log(f"Could not resolve {target}: {e}", level="WARNING")
                censys_data["error"] = f"Could not resolve domain: {e}"
                ctx.add("censys_host", censys_data)
                return ctx

        # Query Censys
        result = hosts_client.view(ip)

        # Parse result
        host = CensysHost(
            ip=result.get("ip", ip),
            location=result.get("location", {}),
            autonomous_system=result.get("autonomous_system", {}),
            operating_system=result.get("operating_system", {}).get("product"),
            dns=result.get("dns", {}),
            last_updated=result.get("last_updated_at"),
        )

        # Parse services
        for service in result.get("services", []):
            svc = {
                "port": service.get("port"),
                "protocol": service.get("transport_protocol", "TCP"),
                "service_name": service.get("service_name"),
                "extended_service_name": service.get("extended_service_name"),
                "software": [],
                "certificate": None,
            }

            # Extract software info
            if service.get("software"):
                for sw in service["software"]:
                    svc["software"].append(
                        {
                            "product": sw.get("product"),
                            "version": sw.get("version"),
                            "vendor": sw.get("vendor"),
                        }
                    )

            # Extract TLS certificate info
            if service.get("tls") and service["tls"].get("certificates"):
                leaf = service["tls"]["certificates"].get("leaf_data", {})
                if leaf:
                    svc["certificate"] = {
                        "fingerprint": leaf.get("fingerprint"),
                        "issuer": leaf.get("issuer_dn"),
                        "subject": leaf.get("subject_dn"),
                        "names": leaf.get("names", []),
                    }

            host.services.append(svc)

        censys_data["hosts"].append(host.to_dict())

        ctx.log(
            f"Censys found {len(host.services)} services",
            level="INFO",
        )

    except (OSError, RuntimeError, TypeError, ValueError, KeyError, IndexError, AttributeError) as e:
        error_msg = str(e)
        if "404" in error_msg or "not found" in error_msg.lower():
            censys_data["error"] = f"No Censys data for {ip}"
        else:
            censys_data["error"] = f"Censys API error: {error_msg}"
        ctx.log(censys_data["error"], level="WARNING")

    ctx.add("censys_host", censys_data)
    return ctx


def query_censys_certificates(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Query Censys for certificate information.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - domain: Domain to search certificates for
            - fingerprint: Specific certificate fingerprint
            - limit: Maximum results (default: 25)

    Returns:
        Updated context with Censys certificate data
    """
    params = params or {}
    domain = params.get("domain") or ctx.target
    fingerprint = params.get("fingerprint")
    limit = params.get("limit", 25)

    if not domain and not fingerprint:
        ctx.log(
            "No domain or fingerprint for Censys certificate query", level="WARNING"
        )
        return ctx

    ctx.log(f"Querying Censys certificates for: {domain or fingerprint}", level="INFO")

    # Initialize result
    cert_data = {
        "query": domain or fingerprint,
        "certificates": [],
        "total": 0,
        "error": None,
    }

    _, certs_client = get_censys_client()
    if not certs_client:
        cert_data["error"] = "Censys API not available"
        ctx.log(cert_data["error"], level="WARNING")
        ctx.add("censys_certs", cert_data)
        return ctx

    try:
        if fingerprint:
            # Get specific certificate
            result = certs_client.view(fingerprint)
            cert = _parse_certificate(result)
            cert_data["certificates"].append(cert.to_dict())
            cert_data["total"] = 1
        else:
            # Search for certificates by domain
            domain_clean = _extract_domain(domain)
            query = f"names: {domain_clean}"

            count = 0
            for result in certs_client.search(query, per_page=min(limit, 100)):
                cert = _parse_certificate(result)
                cert_data["certificates"].append(cert.to_dict())
                count += 1
                if count >= limit:
                    break

            cert_data["total"] = count

        ctx.log(
            f"Censys found {cert_data['total']} certificates",
            level="INFO",
        )

    except (OSError, RuntimeError, TypeError, ValueError, KeyError, IndexError, AttributeError) as e:
        cert_data["error"] = f"Censys certificate error: {str(e)}"
        ctx.log(cert_data["error"], level="WARNING")

    ctx.add("censys_certs", cert_data)
    return ctx


def search_censys_hosts(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Search Censys hosts with a query.

    Args:
        ctx: Pipeline context
        params: Parameters:
            - query: Censys search query (default: built from target)
            - limit: Maximum results (default: 25)

    Returns:
        Updated context with Censys search results
    """
    params = params or {}
    query = params.get("query")
    limit = params.get("limit", 25)

    if not query:
        # Build query from target
        target = ctx.target
        if target:
            if _is_ip(target):
                query = f"ip: {target}"
            else:
                domain = _extract_domain(target)
                query = f"services.tls.certificates.leaf_data.names: {domain}"
        else:
            ctx.log("No query or target for Censys search", level="WARNING")
            return ctx

    ctx.log(f"Searching Censys hosts: {query}", level="INFO")

    # Initialize result
    search_data = {
        "query": query,
        "total": 0,
        "results": [],
        "error": None,
    }

    hosts_client, _ = get_censys_client()
    if not hosts_client:
        search_data["error"] = "Censys API not available"
        ctx.log(search_data["error"], level="WARNING")
        ctx.add("censys_search", search_data)
        return ctx

    try:
        count = 0
        for result in hosts_client.search(query, per_page=min(limit, 100)):
            host = {
                "ip": result.get("ip"),
                "services": [],
                "location": result.get("location", {}),
                "autonomous_system": result.get("autonomous_system", {}),
            }

            # Parse services
            for svc in result.get("services", []):
                host["services"].append(
                    {
                        "port": svc.get("port"),
                        "protocol": svc.get("transport_protocol"),
                        "service_name": svc.get("service_name"),
                    }
                )

            search_data["results"].append(host)
            count += 1
            if count >= limit:
                break

        search_data["total"] = count

        ctx.log(
            f"Censys search found {search_data['total']} hosts",
            level="INFO",
        )

    except (OSError, RuntimeError, TypeError, ValueError, KeyError, IndexError, AttributeError) as e:
        search_data["error"] = f"Censys search error: {str(e)}"
        ctx.log(search_data["error"], level="WARNING")

    ctx.add("censys_search", search_data)
    return ctx


def analyze_censys_intel(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Run comprehensive Censys analysis.

    Combines host and certificate queries for full intel.

    Args:
        ctx: Pipeline context
        params: Optional parameters passed to sub-queries

    Returns:
        Updated context with comprehensive Censys intel
    """
    params = params or {}
    target = ctx.target

    ctx.log(f"Running Censys intelligence analysis for: {target}", level="INFO")

    # Run host query
    ctx = query_censys_host(ctx, params)

    # Run certificate query if target is a domain
    if target and not _is_ip(target):
        ctx = query_censys_certificates(ctx, params)

    # Compile summary
    censys_intel = {
        "target": target,
        "host": ctx.get("censys_host", {}),
        "certificates": ctx.get("censys_certs", {}),
        "summary": {},
    }

    # Generate summary
    host_data = censys_intel["host"]
    if host_data.get("hosts"):
        host = host_data["hosts"][0]
        censys_intel["summary"] = {
            "services_count": len(host.get("services", [])),
            "location": host.get("location", {}).get("country"),
            "asn": host.get("autonomous_system", {}).get("asn"),
            "organization": host.get("autonomous_system", {}).get("name"),
            "operating_system": host.get("operating_system"),
        }

        # Extract unique ports
        ports = [s.get("port") for s in host.get("services", []) if s.get("port")]
        censys_intel["summary"]["open_ports"] = sorted(set(ports))

    cert_data = censys_intel["certificates"]
    if cert_data.get("certificates"):
        censys_intel["summary"]["certificates_found"] = len(cert_data["certificates"])

        # Collect all certificate names
        all_names = []
        for cert in cert_data["certificates"]:
            all_names.extend(cert.get("names", []))
        censys_intel["summary"]["certificate_names"] = list(set(all_names))[:20]

    ctx.add("censys_intel", censys_intel)

    svc_count = censys_intel["summary"].get("services_count", 0)
    cert_count = censys_intel["summary"].get("certificates_found", 0)
    ctx.log(
        f"Censys intel complete: {svc_count} services, {cert_count} certificates",
        level="INFO",
    )

    return ctx


# Helper functions


def _parse_certificate(data: dict[str, Any]) -> CensysCertificate:
    """Parse Censys certificate data."""
    return CensysCertificate(
        fingerprint=data.get("fingerprint_sha256", data.get("fingerprint", "")),
        names=data.get("names", []),
        issuer=data.get("issuer_dn") or data.get("issuer", {}).get("common_name"),
        subject=data.get("subject_dn") or data.get("subject", {}).get("common_name"),
        validity={
            "not_before": data.get("validity", {}).get("start"),
            "not_after": data.get("validity", {}).get("end"),
        },
        key_info={
            "algorithm": data.get("public_key", {}).get("algorithm"),
            "size": data.get("public_key", {}).get("key_size"),
        },
    )


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
