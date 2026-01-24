"""
Domain reconnaissance module.

Performs OSINT on domains including DNS enumeration, zone analysis, and subdomain discovery.
Uses dnspython for comprehensive DNS lookups when available.
"""

from typing import Optional, Dict, Any, List
import socket
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import dnspython for full DNS support
try:
    import dns.resolver
    import dns.exception

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def get_dns_records(domain: str, record_type: str = "A") -> List[str]:
    """
    Get DNS records for a domain.

    Uses dnspython for comprehensive lookups. Falls back to socket for A records
    if dnspython is not installed.

    Args:
        domain: The domain to query
        record_type: Type of DNS record (A, AAAA, MX, TXT, NS, SOA, CNAME)

    Returns:
        List of DNS records as strings
    """
    if DNS_AVAILABLE:
        return _get_dns_records_dnspython(domain, record_type)
    else:
        # Fallback to socket for A records only
        if record_type == "A":
            return _get_dns_records_socket(domain)
        return []


def _get_dns_records_socket(domain: str) -> List[str]:
    """Fallback DNS lookup using socket (A records only)."""
    try:
        result = socket.gethostbyname_ex(domain)
        return result[2]
    except Exception:
        return []


def _get_dns_records_dnspython(domain: str, record_type: str) -> List[str]:
    """DNS lookup using dnspython library."""
    records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        answers = resolver.resolve(domain, record_type)

        for rdata in answers:
            if record_type == "MX":
                # MX records have priority and exchange
                records.append(f"{rdata.preference} {rdata.exchange.to_text()}")
            elif record_type == "SOA":
                # SOA has multiple fields
                records.append(
                    f"{rdata.mname.to_text()} {rdata.rname.to_text()} "
                    f"{rdata.serial} {rdata.refresh} {rdata.retry} "
                    f"{rdata.expire} {rdata.minimum}"
                )
            elif record_type == "TXT":
                # TXT records may have multiple strings
                txt_data = b"".join(rdata.strings).decode("utf-8", errors="replace")
                records.append(txt_data)
            else:
                # A, AAAA, NS, CNAME - simple string conversion
                records.append(rdata.to_text())

    except dns.resolver.NXDOMAIN:
        # Domain does not exist
        pass
    except dns.resolver.NoAnswer:
        # No records of this type
        pass
    except dns.resolver.NoNameservers:
        # No nameservers available
        pass
    except dns.exception.Timeout:
        # Query timed out
        pass
    except Exception:
        # Other errors
        pass

    return records


def get_all_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Get all common DNS record types for a domain.

    Args:
        domain: The domain to query

    Returns:
        Dictionary mapping record type to list of records
    """
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
    results = {}

    for rtype in record_types:
        records = get_dns_records(domain, rtype)
        if records:
            results[rtype] = records

    return results


def analyze_txt_records(txt_records: List[str]) -> Dict[str, Any]:
    """
    Analyze TXT records for security-relevant information.

    Identifies SPF, DKIM, DMARC, and other security records.

    Args:
        txt_records: List of TXT record values

    Returns:
        Analysis results with identified record types
    """
    analysis = {
        "spf": None,
        "dkim_selectors": [],
        "dmarc": None,
        "verification_records": [],
        "other": [],
    }

    for txt in txt_records:
        txt_lower = txt.lower()

        if txt_lower.startswith("v=spf1"):
            analysis["spf"] = txt
        elif txt_lower.startswith("v=dmarc1"):
            analysis["dmarc"] = txt
        elif "google-site-verification" in txt_lower:
            analysis["verification_records"].append(("google", txt))
        elif "ms=" in txt_lower or "msoid=" in txt_lower:
            analysis["verification_records"].append(("microsoft", txt))
        elif "facebook-domain-verification" in txt_lower:
            analysis["verification_records"].append(("facebook", txt))
        elif "docusign" in txt_lower:
            analysis["verification_records"].append(("docusign", txt))
        elif "_dmarc" in txt_lower or "dkim" in txt_lower:
            analysis["dkim_selectors"].append(txt)
        else:
            analysis["other"].append(txt)

    return analysis


def profile_domain(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Profile a domain with comprehensive reconnaissance.

    Performs:
    - Full DNS enumeration (A, AAAA, MX, TXT, NS, SOA, CNAME)
    - TXT record analysis (SPF, DKIM, DMARC detection)
    - Mail server identification
    - Nameserver analysis

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - domain: Override target domain

    Returns:
        Updated context with domain_profile data
    """
    params = params or {}
    domain = params.get("domain") or ctx.target

    if not domain:
        ctx.log("No domain specified for profiling", level="WARNING")
        return ctx

    ctx.log(f"Profiling domain: {domain}", level="INFO")

    profile = {
        "domain": domain,
        "dns_records": {},
        "mail_servers": [],
        "nameservers": [],
        "txt_analysis": {},
        "has_ipv6": False,
        "has_spf": False,
        "has_dmarc": False,
    }

    # Get all DNS records
    try:
        all_records = get_all_dns_records(domain)
        profile["dns_records"] = all_records

        # Process A records
        if "A" in all_records:
            a_records = all_records["A"]
            ctx.log(f"Found {len(a_records)} A records: {a_records}", level="INFO")

            finding = Finding(
                module="recon.domains",
                title=f"DNS A Records for {domain}",
                description=f"Found {len(a_records)} IPv4 addresses",
                severity=RiskLevel.INFO,
                data={"records": a_records},
            )
            ctx.add(f"finding_dns_a_{domain}", finding.model_dump())

        # Process AAAA records (IPv6)
        if "AAAA" in all_records:
            profile["has_ipv6"] = True
            ctx.log(f"IPv6 enabled: {all_records['AAAA']}", level="INFO")

        # Process MX records
        if "MX" in all_records:
            profile["mail_servers"] = all_records["MX"]
            ctx.log(f"Found {len(all_records['MX'])} mail servers", level="INFO")

            finding = Finding(
                module="recon.domains",
                title=f"Mail Servers for {domain}",
                description=f"Found {len(all_records['MX'])} MX records",
                severity=RiskLevel.INFO,
                data={"mail_servers": all_records["MX"]},
            )
            ctx.add(f"finding_dns_mx_{domain}", finding.model_dump())

        # Process NS records
        if "NS" in all_records:
            profile["nameservers"] = all_records["NS"]
            ctx.log(f"Nameservers: {all_records['NS']}", level="INFO")

        # Process TXT records
        if "TXT" in all_records:
            txt_analysis = analyze_txt_records(all_records["TXT"])
            profile["txt_analysis"] = txt_analysis
            profile["has_spf"] = txt_analysis["spf"] is not None
            profile["has_dmarc"] = txt_analysis["dmarc"] is not None

            if txt_analysis["spf"]:
                ctx.log(f"SPF record found: {txt_analysis['spf'][:80]}...", level="INFO")
            else:
                ctx.log("No SPF record found - email spoofing risk", level="WARNING")
                finding = Finding(
                    module="recon.domains",
                    title=f"Missing SPF Record for {domain}",
                    description="No SPF record found. Domain may be vulnerable to email spoofing.",
                    severity=RiskLevel.MEDIUM,
                    data={"recommendation": "Add SPF record to prevent email spoofing"},
                )
                ctx.add(f"finding_no_spf_{domain}", finding.model_dump())

            if txt_analysis["dmarc"]:
                ctx.log(f"DMARC record found", level="INFO")

            if txt_analysis["verification_records"]:
                services = [v[0] for v in txt_analysis["verification_records"]]
                ctx.log(f"Domain verified with services: {services}", level="INFO")

    except Exception as e:
        ctx.log(f"Error during DNS enumeration: {e}", level="ERROR")

    ctx.add("domain_profile", profile)
    ctx.log(f"Domain profiling completed for {domain}", level="INFO")

    return ctx


def enumerate_dns(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Enumerate all DNS records for a domain.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - domain: Override target domain
            - record_types: List of record types to query (default: all)

    Returns:
        Updated context with dns_enumeration data
    """
    params = params or {}
    domain = params.get("domain") or ctx.target
    record_types = params.get("record_types", ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"])

    if not domain:
        ctx.log("No domain specified for DNS enumeration", level="WARNING")
        return ctx

    ctx.log(f"Enumerating DNS for: {domain}", level="INFO")

    dns_data = {"domain": domain}

    for rtype in record_types:
        records = get_dns_records(domain, rtype)
        dns_data[rtype] = records
        if records:
            ctx.log(f"Found {len(records)} {rtype} records", level="DEBUG")

    # Add summary
    total_records = sum(len(v) for k, v in dns_data.items() if isinstance(v, list))
    dns_data["total_records"] = total_records

    ctx.add("dns_enumeration", dns_data)
    ctx.log(f"DNS enumeration completed for {domain}: {total_records} total records", level="INFO")

    return ctx


def discover_subdomains(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Discover subdomains using passive techniques.

    Currently implements:
    - Common subdomain brute-force (www, mail, ftp, etc.)

    Future implementations could add:
    - Certificate transparency logs
    - Search engine queries
    - Third-party APIs (SecurityTrails, etc.)

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - domain: Override target domain
            - wordlist: Custom subdomain wordlist

    Returns:
        Updated context with discovered subdomains
    """
    params = params or {}
    domain = params.get("domain") or ctx.target

    if not domain:
        ctx.log("No domain specified for subdomain discovery", level="WARNING")
        return ctx

    ctx.log(f"Discovering subdomains for: {domain}", level="INFO")

    # Common subdomain prefixes to check
    common_prefixes = params.get("wordlist", [
        "www", "mail", "ftp", "smtp", "pop", "imap",
        "webmail", "remote", "vpn", "admin", "portal",
        "api", "dev", "staging", "test", "beta",
        "app", "mobile", "m", "cdn", "static",
        "blog", "shop", "store", "support", "help",
        "docs", "wiki", "git", "gitlab", "github",
        "jenkins", "ci", "build", "deploy",
        "ns1", "ns2", "dns", "dns1", "dns2",
    ])

    discovered = []

    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        records = get_dns_records(subdomain, "A")
        if records:
            discovered.append({
                "subdomain": subdomain,
                "ip_addresses": records,
            })
            ctx.log(f"Found subdomain: {subdomain} -> {records}", level="INFO")

    ctx.add("subdomains", discovered)

    if discovered:
        finding = Finding(
            module="recon.domains",
            title=f"Discovered Subdomains for {domain}",
            description=f"Found {len(discovered)} active subdomains",
            severity=RiskLevel.INFO,
            data={"subdomains": discovered},
        )
        ctx.add(f"finding_subdomains_{domain}", finding.model_dump())

    ctx.log(f"Subdomain discovery completed: {len(discovered)} found", level="INFO")

    return ctx


def check_zone_transfer(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Check if DNS zone transfer (AXFR) is allowed.

    Zone transfer misconfiguration is a security issue that can expose
    all DNS records to unauthorized parties.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context with zone transfer check results
    """
    params = params or {}
    domain = params.get("domain") or ctx.target

    if not domain:
        ctx.log("No domain specified for zone transfer check", level="WARNING")
        return ctx

    if not DNS_AVAILABLE:
        ctx.log("dnspython required for zone transfer check", level="WARNING")
        ctx.add("zone_transfer", {"status": "skipped", "reason": "dnspython not available"})
        return ctx

    ctx.log(f"Checking zone transfer for: {domain}", level="INFO")

    # Get nameservers first
    nameservers = get_dns_records(domain, "NS")

    zone_transfer_results = {
        "domain": domain,
        "nameservers_checked": [],
        "vulnerable": False,
        "records_exposed": 0,
    }

    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        try:
            import dns.zone
            import dns.query

            # Attempt zone transfer
            zone = dns.zone.from_xfr(dns.query.xfr(ns_clean, domain, timeout=10))

            # If we get here, zone transfer succeeded (vulnerability!)
            records_count = len(list(zone.iterate_rdatasets()))
            zone_transfer_results["vulnerable"] = True
            zone_transfer_results["records_exposed"] = records_count
            zone_transfer_results["nameservers_checked"].append({
                "nameserver": ns_clean,
                "vulnerable": True,
                "records_count": records_count,
            })

            ctx.log(f"ZONE TRANSFER ALLOWED on {ns_clean}! Exposed {records_count} records", level="WARNING")

            finding = Finding(
                module="recon.domains",
                title=f"Zone Transfer Allowed on {ns_clean}",
                description=f"DNS zone transfer (AXFR) is allowed, exposing {records_count} DNS records",
                severity=RiskLevel.HIGH,
                data={"nameserver": ns_clean, "records_exposed": records_count},
            )
            ctx.add(f"finding_axfr_{ns_clean}", finding.model_dump())

        except Exception:
            # Zone transfer denied (expected/secure behavior)
            zone_transfer_results["nameservers_checked"].append({
                "nameserver": ns_clean,
                "vulnerable": False,
            })
            ctx.log(f"Zone transfer denied on {ns_clean} (secure)", level="DEBUG")

    ctx.add("zone_transfer", zone_transfer_results)

    if not zone_transfer_results["vulnerable"]:
        ctx.log("Zone transfer check completed: No vulnerabilities found", level="INFO")
    else:
        ctx.log("Zone transfer check completed: VULNERABILITY FOUND", level="WARNING")

    return ctx
