"""
Subdomain enumeration module.

Discovers subdomains using multiple techniques including DNS brute-forcing,
certificate transparency, and common subdomain wordlists.
"""

from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from datetime import datetime
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import dnspython for DNS lookups
try:
    import dns.resolver
    import dns.exception

    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# Common subdomain prefixes for brute-forcing
COMMON_SUBDOMAINS = [
    # Infrastructure
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "dns",
    "dns1",
    "dns2",
    "mx",
    "mx1",
    "mx2",
    # Web/Apps
    "app",
    "apps",
    "web",
    "www1",
    "www2",
    "portal",
    "api",
    "api1",
    "api2",
    "gateway",
    "gw",
    "proxy",
    "cdn",
    "static",
    "assets",
    "images",
    "img",
    "media",
    "files",
    "download",
    "downloads",
    "upload",
    "uploads",
    # Development
    "dev",
    "devel",
    "develop",
    "development",
    "stage",
    "staging",
    "stg",
    "test",
    "testing",
    "qa",
    "uat",
    "demo",
    "sandbox",
    "beta",
    "alpha",
    "preview",
    "preprod",
    "pre-prod",
    "prod",
    "production",
    # Admin/Management
    "admin",
    "administrator",
    "adm",
    "manage",
    "manager",
    "management",
    "cms",
    "cpanel",
    "panel",
    "dashboard",
    "console",
    "control",
    # Database/Backend
    "db",
    "db1",
    "db2",
    "database",
    "mysql",
    "postgres",
    "postgresql",
    "mongo",
    "mongodb",
    "redis",
    "cache",
    "memcached",
    "elastic",
    "elasticsearch",
    "sql",
    "mssql",
    "oracle",
    # Cloud/Infrastructure
    "cloud",
    "aws",
    "azure",
    "gcp",
    "s3",
    "storage",
    "backup",
    "backups",
    "vpn",
    "remote",
    "gateway",
    "lb",
    "loadbalancer",
    "haproxy",
    "nginx",
    # Services
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "svn",
    "repo",
    "repository",
    "jenkins",
    "ci",
    "cd",
    "build",
    "deploy",
    "docker",
    "k8s",
    "kubernetes",
    "grafana",
    "prometheus",
    "kibana",
    "elk",
    "log",
    "logs",
    "logging",
    "monitor",
    "monitoring",
    "metrics",
    "status",
    "health",
    # Communication
    "chat",
    "slack",
    "teams",
    "irc",
    "jabber",
    "xmpp",
    "voip",
    "sip",
    "conference",
    "meet",
    "meeting",
    "video",
    "webinar",
    # Security
    "auth",
    "authentication",
    "login",
    "signin",
    "sso",
    "oauth",
    "saml",
    "ldap",
    "ad",
    "identity",
    "id",
    "secure",
    "ssl",
    "cert",
    "certs",
    # Support/Help
    "support",
    "help",
    "helpdesk",
    "ticket",
    "tickets",
    "service",
    "services",
    "kb",
    "knowledge",
    "wiki",
    "docs",
    "documentation",
    "faq",
    # Internal
    "internal",
    "intranet",
    "extranet",
    "corp",
    "corporate",
    "office",
    "hq",
    "headquarters",
    "local",
    "private",
    "int",
    # Regional
    "us",
    "eu",
    "uk",
    "au",
    "ca",
    "de",
    "fr",
    "jp",
    "cn",
    "in",
    "east",
    "west",
    "north",
    "south",
    "central",
    # Misc
    "old",
    "new",
    "legacy",
    "archive",
    "temp",
    "tmp",
    "test1",
    "test2",
    "client",
    "clients",
    "customer",
    "customers",
    "partner",
    "partners",
    "vendor",
    "vendors",
    "shop",
    "store",
    "blog",
    "news",
    "press",
    "career",
    "careers",
    "jobs",
    "hr",
    "investor",
    "investors",
    "ir",
]


def enumerate_subdomains(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Enumerate subdomains using multiple techniques.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - domain: Domain to enumerate (defaults to ctx.target)
            - wordlist: Custom wordlist (defaults to COMMON_SUBDOMAINS)
            - threads: Number of concurrent threads (default: 10)
            - timeout: DNS timeout in seconds (default: 3)
            - use_ct: Also search CT logs (default: True)
            - resolve_only: Only return subdomains that resolve (default: True)

    Returns:
        Updated context with discovered subdomains
    """
    params = params or {}
    domain = params.get("domain") or ctx.target
    wordlist = params.get("wordlist", COMMON_SUBDOMAINS)
    threads = params.get("threads", 10)
    timeout = params.get("timeout", 3)
    use_ct = params.get("use_ct", True)
    resolve_only = params.get("resolve_only", True)

    if not domain:
        ctx.log("No domain specified for subdomain enumeration", level="WARNING")
        return ctx

    ctx.log(f"Enumerating subdomains for: {domain}", level="INFO")

    discovered: set[str] = set()

    # Method 1: DNS brute-force with wordlist
    ctx.log(f"Brute-forcing with {len(wordlist)} prefixes...", level="INFO")
    bruteforce_results = bruteforce_subdomains(
        domain, wordlist, threads=threads, timeout=timeout
    )
    discovered.update(bruteforce_results)
    ctx.log(f"Brute-force found {len(bruteforce_results)} subdomains", level="DEBUG")

    # Method 2: Certificate Transparency (if enabled and module available)
    if use_ct:
        try:
            from redops.modules.recon.cert_transparency import search_ct_logs

            ctx.log("Searching Certificate Transparency logs...", level="INFO")
            ctx = search_ct_logs(ctx, {"domain": domain})
            ct_subdomains = ctx.get("ct_subdomains", [])
            discovered.update(ct_subdomains)
            ctx.log(f"CT logs found {len(ct_subdomains)} subdomains", level="DEBUG")
        except ImportError:
            ctx.log("CT module not available", level="DEBUG")

    # Method 3: Check common DNS records that might reveal subdomains
    ctx.log("Checking DNS records for subdomain hints...", level="INFO")
    dns_hints = get_subdomains_from_dns(domain, timeout=timeout)
    discovered.update(dns_hints)

    # Filter to only resolved subdomains if requested
    if resolve_only:
        ctx.log("Verifying subdomain resolution...", level="INFO")
        discovered = verify_subdomains(discovered, threads=threads, timeout=timeout)

    # Sort results
    subdomains = sorted(list(discovered))

    ctx.log(f"Total unique subdomains discovered: {len(subdomains)}", level="INFO")

    # Analyze for security issues
    findings = analyze_subdomains(subdomains, domain)

    # Store results
    ctx.add("subdomains", subdomains)
    ctx.add(
        "subdomain_enum_results",
        {
            "domain": domain,
            "total_discovered": len(subdomains),
            "methods_used": ["bruteforce", "ct_logs" if use_ct else None, "dns_hints"],
            "timestamp": datetime.now().isoformat(),
        },
    )

    # Merge with existing subdomains
    existing = ctx.get("all_subdomains", [])
    all_subs = sorted(list(set(existing + subdomains)))
    ctx.add("all_subdomains", all_subs)

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_subdomain_{i}", finding.model_dump())

    return ctx


def bruteforce_subdomains(
    domain: str, wordlist: list[str], threads: int = 10, timeout: int = 3
) -> set[str]:
    """
    Brute-force subdomains using a wordlist.

    Args:
        domain: Base domain
        wordlist: List of subdomain prefixes to try
        threads: Number of concurrent threads
        timeout: DNS timeout

    Returns:
        Set of discovered subdomains
    """
    discovered = set()

    def check_subdomain(prefix: str) -> str | None:
        subdomain = f"{prefix}.{domain}"
        if resolve_domain(subdomain, timeout=timeout):
            return subdomain
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain, prefix): prefix for prefix in wordlist
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                discovered.add(result)

    return discovered


def resolve_domain(domain: str, timeout: int = 3) -> bool:
    """
    Check if a domain resolves to an IP address.

    Args:
        domain: Domain to check
        timeout: Timeout in seconds

    Returns:
        True if domain resolves
    """
    if HAS_DNS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            resolver.resolve(domain, "A")
            return True
        except (OSError, ValueError, TypeError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return False
    else:
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(domain)
            return True
        except (OSError, ValueError, TypeError):
            return False


def verify_subdomains(
    subdomains: set[str], threads: int = 10, timeout: int = 3
) -> set[str]:
    """
    Verify which subdomains actually resolve.

    Args:
        subdomains: Set of subdomains to verify
        threads: Number of concurrent threads
        timeout: DNS timeout

    Returns:
        Set of verified subdomains
    """
    verified = set()

    def verify(subdomain: str) -> str | None:
        if resolve_domain(subdomain, timeout=timeout):
            return subdomain
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(verify, sub): sub for sub in subdomains}

        for future in as_completed(futures):
            result = future.result()
            if result:
                verified.add(result)

    return verified


def get_subdomains_from_dns(domain: str, timeout: int = 3) -> set[str]:
    """
    Extract potential subdomains from DNS records.

    Args:
        domain: Base domain
        timeout: DNS timeout

    Returns:
        Set of discovered subdomains
    """
    subdomains = set()

    if not HAS_DNS:
        return subdomains

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Check MX records
        try:
            mx_records = resolver.resolve(domain, "MX")
            for rdata in mx_records:
                mx_host = str(rdata.exchange).rstrip(".")
                if mx_host.endswith(domain):
                    subdomains.add(mx_host)
        except (OSError, ValueError, TypeError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass

        # Check NS records
        try:
            ns_records = resolver.resolve(domain, "NS")
            for rdata in ns_records:
                ns_host = str(rdata).rstrip(".")
                if ns_host.endswith(domain):
                    subdomains.add(ns_host)
        except (OSError, ValueError, TypeError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass

        # Check TXT records for SPF includes
        try:
            txt_records = resolver.resolve(domain, "TXT")
            for rdata in txt_records:
                txt = str(rdata)
                # Look for SPF includes
                if "include:" in txt:
                    for part in txt.split():
                        if part.startswith("include:"):
                            include_domain = part[8:]
                            if include_domain.endswith(domain):
                                subdomains.add(include_domain)
        except (OSError, ValueError, TypeError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass

    except (OSError, ValueError, TypeError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    return subdomains


def analyze_subdomains(subdomains: list[str], domain: str) -> list[Finding]:
    """
    Analyze discovered subdomains for security issues.

    Args:
        subdomains: List of discovered subdomains
        domain: Base domain

    Returns:
        List of security findings
    """
    findings = []

    # Categorize subdomains
    dev_subs = []
    admin_subs = []
    internal_subs = []
    db_subs = []

    dev_keywords = [
        "dev",
        "test",
        "staging",
        "stage",
        "qa",
        "uat",
        "demo",
        "sandbox",
        "beta",
        "alpha",
    ]
    admin_keywords = [
        "admin",
        "manage",
        "panel",
        "cpanel",
        "console",
        "dashboard",
        "cms",
    ]
    internal_keywords = ["internal", "intranet", "corp", "private", "vpn", "office"]
    db_keywords = ["db", "database", "mysql", "postgres", "mongo", "redis", "sql"]

    for sub in subdomains:
        prefix = sub.replace(f".{domain}", "").lower()

        for kw in dev_keywords:
            if kw in prefix:
                dev_subs.append(sub)
                break

        for kw in admin_keywords:
            if kw in prefix:
                admin_subs.append(sub)
                break

        for kw in internal_keywords:
            if kw in prefix:
                internal_subs.append(sub)
                break

        for kw in db_keywords:
            if kw in prefix:
                db_subs.append(sub)
                break

    # Create findings
    if dev_subs:
        findings.append(
            Finding(
                module="recon.subdomain_enum",
                title=f"Development/Staging Subdomains Exposed ({len(dev_subs)})",
                description=f"Found {len(dev_subs)} development or staging subdomains: "
                f"{', '.join(dev_subs[:5])}{'...' if len(dev_subs) > 5 else ''}. "
                "These may contain unfinished features or debugging capabilities.",
                severity=RiskLevel.MEDIUM,
                data={"subdomains": dev_subs, "count": len(dev_subs)},
            )
        )

    if admin_subs:
        findings.append(
            Finding(
                module="recon.subdomain_enum",
                title=f"Administrative Subdomains Discovered ({len(admin_subs)})",
                description=f"Found {len(admin_subs)} administrative subdomains: "
                f"{', '.join(admin_subs[:5])}{'...' if len(admin_subs) > 5 else ''}. "
                "Ensure these are properly secured and not publicly accessible.",
                severity=RiskLevel.MEDIUM,
                data={"subdomains": admin_subs, "count": len(admin_subs)},
            )
        )

    if internal_subs:
        findings.append(
            Finding(
                module="recon.subdomain_enum",
                title=f"Internal Subdomains Exposed ({len(internal_subs)})",
                description=f"Found {len(internal_subs)} internal/corporate subdomains: "
                f"{', '.join(internal_subs[:5])}{'...' if len(internal_subs) > 5 else ''}. "
                "These should typically not be publicly resolvable.",
                severity=RiskLevel.HIGH,
                data={"subdomains": internal_subs, "count": len(internal_subs)},
            )
        )

    if db_subs:
        findings.append(
            Finding(
                module="recon.subdomain_enum",
                title=f"Database Subdomains Discovered ({len(db_subs)})",
                description=f"Found {len(db_subs)} database-related subdomains: "
                f"{', '.join(db_subs[:5])}{'...' if len(db_subs) > 5 else ''}. "
                "Database servers should not be directly exposed to the internet.",
                severity=RiskLevel.HIGH,
                data={"subdomains": db_subs, "count": len(db_subs)},
            )
        )

    # Large attack surface
    if len(subdomains) > 50:
        findings.append(
            Finding(
                module="recon.subdomain_enum",
                title=f"Large Attack Surface ({len(subdomains)} subdomains)",
                description=f"Discovered {len(subdomains)} subdomains for {domain}. "
                "A large number of subdomains increases the attack surface and "
                "may make it harder to maintain consistent security.",
                severity=RiskLevel.INFO,
                data={"subdomain_count": len(subdomains)},
            )
        )

    return findings


def get_subdomain_summary(ctx: Context) -> dict[str, Any]:
    """
    Get a summary of subdomain enumeration results.

    Args:
        ctx: Pipeline context

    Returns:
        Summary dictionary
    """
    results = ctx.get("subdomain_enum_results", {})
    subdomains = ctx.get("subdomains", [])

    return {
        "domain": results.get("domain", ""),
        "total_discovered": len(subdomains),
        "methods_used": results.get("methods_used", []),
        "timestamp": results.get("timestamp", ""),
    }
