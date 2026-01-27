"""
Certificate Transparency log searching module.

Queries Certificate Transparency logs to discover subdomains and certificates
issued for a target domain. Uses crt.sh API for CT log data.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
import json
import re
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests for HTTP calls
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# crt.sh API endpoint
CRT_SH_API = "https://crt.sh/"


def search_ct_logs(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Search Certificate Transparency logs for a domain.

    Discovers subdomains and certificates by querying CT logs via crt.sh.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - domain: Domain to search (defaults to ctx.target)
            - include_expired: Include expired certificates (default: False)
            - deduplicate: Remove duplicate subdomains (default: True)

    Returns:
        Updated context with ct_results, ct_subdomains, ct_certificates
    """
    if not HAS_REQUESTS:
        ctx.log("requests library required for CT log search", level="WARNING")
        return ctx

    params = params or {}
    domain = params.get("domain") or ctx.target
    include_expired = params.get("include_expired", False)
    deduplicate = params.get("deduplicate", True)

    if not domain:
        ctx.log("No domain specified for CT log search", level="WARNING")
        return ctx

    ctx.log(f"Searching CT logs for: {domain}", level="INFO")

    # Query crt.sh
    certificates = query_crtsh(domain, include_expired=include_expired)

    if not certificates:
        ctx.log(f"No certificates found in CT logs for {domain}", level="INFO")
        ctx.add("ct_results", {"domain": domain, "certificates": [], "subdomains": []})
        return ctx

    ctx.log(f"Found {len(certificates)} certificates in CT logs", level="INFO")

    # Extract subdomains from certificates
    subdomains = extract_subdomains_from_certs(certificates, domain)

    if deduplicate:
        subdomains = list(set(subdomains))
        subdomains.sort()

    ctx.log(f"Extracted {len(subdomains)} unique subdomains", level="INFO")

    # Analyze certificates for security issues
    findings = analyze_certificates(certificates, domain)

    # Store results
    ctx.add(
        "ct_results",
        {
            "domain": domain,
            "certificates": certificates[:100],  # Limit stored certs
            "subdomains": subdomains,
            "total_certificates": len(certificates),
            "search_timestamp": datetime.now().isoformat(),
        },
    )
    ctx.add("ct_subdomains", subdomains)
    ctx.add("ct_certificates", certificates[:100])

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_ct_{i}", finding.model_dump())

    # Add to existing subdomains if present
    existing_subdomains = ctx.get("subdomains", [])
    all_subdomains = list(set(existing_subdomains + subdomains))
    ctx.add("subdomains", all_subdomains)

    return ctx


def query_crtsh(
    domain: str, include_expired: bool = False, timeout: int = 30
) -> List[Dict[str, Any]]:
    """
    Query crt.sh API for certificates.

    Args:
        domain: Domain to search
        include_expired: Include expired certificates
        timeout: Request timeout in seconds

    Returns:
        List of certificate records
    """
    if not HAS_REQUESTS:
        return []

    try:
        # Query crt.sh JSON API
        url = f"{CRT_SH_API}?q=%.{domain}&output=json"

        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        certificates = response.json()

        if not include_expired:
            now = datetime.now()
            certificates = [cert for cert in certificates if is_cert_valid(cert, now)]

        return certificates

    except requests.exceptions.Timeout:
        return []
    except requests.exceptions.RequestException:
        return []
    except json.JSONDecodeError:
        return []
    except Exception:
        return []


def is_cert_valid(cert: Dict[str, Any], now: datetime) -> bool:
    """
    Check if a certificate is currently valid.

    Args:
        cert: Certificate record from crt.sh
        now: Current datetime

    Returns:
        True if certificate is valid
    """
    try:
        not_after = cert.get("not_after", "")
        if not_after:
            # Parse crt.sh date format: "2024-12-31T23:59:59"
            expiry = datetime.fromisoformat(
                not_after.replace("Z", "+00:00").split("+")[0]
            )
            return expiry > now
        return True
    except Exception:
        return True


def extract_subdomains_from_certs(
    certificates: List[Dict[str, Any]], base_domain: str
) -> List[str]:
    """
    Extract subdomains from certificate name fields.

    Args:
        certificates: List of certificate records
        base_domain: Base domain to filter by

    Returns:
        List of discovered subdomains
    """
    subdomains = set()
    base_domain_lower = base_domain.lower()

    for cert in certificates:
        # Get common name
        common_name = cert.get("common_name", "")
        if common_name:
            names = parse_cert_name(common_name, base_domain_lower)
            subdomains.update(names)

        # Get Subject Alternative Names (SANs)
        name_value = cert.get("name_value", "")
        if name_value:
            # SANs may be newline-separated
            for name in name_value.split("\n"):
                names = parse_cert_name(name.strip(), base_domain_lower)
                subdomains.update(names)

    return list(subdomains)


def parse_cert_name(name: str, base_domain: str) -> List[str]:
    """
    Parse a certificate name and extract matching subdomains.

    Args:
        name: Certificate name (CN or SAN)
        base_domain: Base domain to match

    Returns:
        List of matching subdomains
    """
    results = []
    name_lower = name.lower().strip()

    # Remove wildcard prefix if present
    if name_lower.startswith("*."):
        name_lower = name_lower[2:]

    # Check if it's a subdomain of the base domain
    if name_lower.endswith(base_domain) or name_lower == base_domain:
        # Validate it looks like a domain
        if re.match(
            r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$",
            name_lower,
        ):
            results.append(name_lower)

    return results


def analyze_certificates(
    certificates: List[Dict[str, Any]], domain: str
) -> List[Finding]:
    """
    Analyze certificates for security issues.

    Args:
        certificates: List of certificate records
        domain: Target domain

    Returns:
        List of security findings
    """
    findings = []
    now = datetime.now()

    # Track issuers
    issuers = {}
    expired_count = 0
    expiring_soon_count = 0
    wildcard_count = 0

    for cert in certificates:
        issuer = cert.get("issuer_name", "Unknown")
        issuers[issuer] = issuers.get(issuer, 0) + 1

        # Check for expired certificates
        not_after = cert.get("not_after", "")
        if not_after:
            try:
                expiry = datetime.fromisoformat(
                    not_after.replace("Z", "+00:00").split("+")[0]
                )
                if expiry < now:
                    expired_count += 1
                elif (expiry - now).days < 30:
                    expiring_soon_count += 1
            except Exception:
                pass

        # Check for wildcards
        common_name = cert.get("common_name", "")
        if common_name.startswith("*."):
            wildcard_count += 1

    # Create findings
    if expired_count > 0:
        findings.append(
            Finding(
                module="recon.cert_transparency",
                title=f"Expired Certificates Found ({expired_count})",
                description=f"Found {expired_count} expired certificates in CT logs for {domain}. "
                "Expired certificates may indicate abandoned subdomains or poor certificate management.",
                severity=RiskLevel.LOW,
                data={"expired_count": expired_count, "domain": domain},
            )
        )

    if expiring_soon_count > 0:
        findings.append(
            Finding(
                module="recon.cert_transparency",
                title=f"Certificates Expiring Soon ({expiring_soon_count})",
                description=f"Found {expiring_soon_count} certificates expiring within 30 days for {domain}.",
                severity=RiskLevel.INFO,
                data={"expiring_soon_count": expiring_soon_count, "domain": domain},
            )
        )

    if wildcard_count > 5:
        findings.append(
            Finding(
                module="recon.cert_transparency",
                title=f"Multiple Wildcard Certificates ({wildcard_count})",
                description=f"Found {wildcard_count} wildcard certificates for {domain}. "
                "While not inherently insecure, wildcard certificates can increase "
                "the impact of private key compromise.",
                severity=RiskLevel.INFO,
                data={"wildcard_count": wildcard_count, "domain": domain},
            )
        )

    # Check for unusual issuers
    if len(issuers) > 5:
        findings.append(
            Finding(
                module="recon.cert_transparency",
                title=f"Multiple Certificate Issuers ({len(issuers)})",
                description=f"Certificates for {domain} were issued by {len(issuers)} different CAs. "
                "This may indicate inconsistent certificate management practices.",
                severity=RiskLevel.INFO,
                data={
                    "issuer_count": len(issuers),
                    "issuers": dict(list(issuers.items())[:10]),
                },
            )
        )

    return findings


def get_ct_summary(ctx: Context) -> Dict[str, Any]:
    """
    Get a summary of CT log search results.

    Args:
        ctx: Pipeline context with CT results

    Returns:
        Summary dictionary
    """
    ct_results = ctx.get("ct_results", {})

    return {
        "domain": ct_results.get("domain", ""),
        "total_certificates": ct_results.get("total_certificates", 0),
        "unique_subdomains": len(ct_results.get("subdomains", [])),
        "search_timestamp": ct_results.get("search_timestamp", ""),
    }
