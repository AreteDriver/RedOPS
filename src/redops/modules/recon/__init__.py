"""Recon modules for RedOPS."""

from redops.modules.recon.domains import (
    get_dns_records,
    get_all_dns_records,
    profile_domain,
    enumerate_dns,
    discover_subdomains,
)
from redops.modules.recon.infrastructure import (
    analyze_infrastructure,
    detect_cloud_providers,
    detect_cdn_providers,
    fingerprint_services,
)
from redops.modules.recon.tech_stack import (
    fingerprint,
    detect_technologies,
    analyze_headers,
)
from redops.modules.recon.social_osint import (
    gather_osint,
    discover_employees,
)
from redops.modules.recon.cert_transparency import (
    search_ct_logs,
    query_crtsh,
    get_ct_summary,
)
from redops.modules.recon.subdomain_enum import (
    enumerate_subdomains,
    bruteforce_subdomains,
    get_subdomain_summary,
    COMMON_SUBDOMAINS,
)
from redops.modules.recon.asn_lookup import (
    lookup_asn,
    get_asn_prefixes,
    get_asn_peers,
    get_asn_summary,
)

__all__ = [
    # domains
    "get_dns_records",
    "get_all_dns_records",
    "profile_domain",
    "enumerate_dns",
    "discover_subdomains",
    # infrastructure
    "analyze_infrastructure",
    "detect_cloud_providers",
    "detect_cdn_providers",
    "fingerprint_services",
    # tech_stack
    "fingerprint",
    "detect_technologies",
    "analyze_headers",
    # social_osint
    "gather_osint",
    "discover_employees",
    # cert_transparency
    "search_ct_logs",
    "query_crtsh",
    "get_ct_summary",
    # subdomain_enum
    "enumerate_subdomains",
    "bruteforce_subdomains",
    "get_subdomain_summary",
    "COMMON_SUBDOMAINS",
    # asn_lookup
    "lookup_asn",
    "get_asn_prefixes",
    "get_asn_peers",
    "get_asn_summary",
]
