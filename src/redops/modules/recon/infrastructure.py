"""
Infrastructure Analysis module.

Analyzes infrastructure patterns from publicly available information:
- Cloud provider detection (AWS, Azure, GCP, etc.)
- CDN provider detection (Cloudflare, Akamai, Fastly, etc.)
- Hosting provider identification
- Service fingerprinting from headers and responses
- Network topology inference
- DNS infrastructure analysis
- Certificate-based infrastructure detection

IMPORTANT: This module analyzes PUBLIC information only.
No active scanning or intrusive probing.
"""

from typing import Any
from dataclasses import dataclass, field
from enum import Enum
import re
from redops.core.context import Context


class CloudProvider(Enum):
    """Major cloud providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    LINODE = "linode"
    VULTR = "vultr"
    OVH = "ovh"
    HETZNER = "hetzner"
    ORACLE = "oracle"
    IBM = "ibm"
    ALIBABA = "alibaba"
    UNKNOWN = "unknown"


class CDNProvider(Enum):
    """CDN providers."""

    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    CLOUDFRONT = "cloudfront"
    AZURE_CDN = "azure_cdn"
    GOOGLE_CDN = "google_cdn"
    STACKPATH = "stackpath"
    BUNNY = "bunny"
    KEYCDN = "keycdn"
    SUCURI = "sucuri"
    INCAPSULA = "incapsula"
    UNKNOWN = "unknown"


class ServiceType(Enum):
    """Types of services detected."""

    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    DATABASE = "database"
    CACHE = "cache"
    LOAD_BALANCER = "load_balancer"
    WAF = "waf"
    API_GATEWAY = "api_gateway"
    STORAGE = "storage"
    CDN = "cdn"
    DNS = "dns"
    MAIL = "mail"
    CONTAINER = "container"
    SERVERLESS = "serverless"


class InfrastructureConfidence(Enum):
    """Confidence level for infrastructure detection."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFERRED = "inferred"


@dataclass
class CloudDetection:
    """Cloud provider detection result."""

    provider: CloudProvider
    confidence: InfrastructureConfidence
    indicators: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider": self.provider.value,
            "confidence": self.confidence.value,
            "indicators": self.indicators,
            "services": self.services,
            "regions": self.regions,
            "metadata": self.metadata,
        }


@dataclass
class CDNDetection:
    """CDN provider detection result."""

    provider: CDNProvider
    confidence: InfrastructureConfidence
    indicators: list[str] = field(default_factory=list)
    edge_locations: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider": self.provider.value,
            "confidence": self.confidence.value,
            "indicators": self.indicators,
            "edge_locations": self.edge_locations,
            "features": self.features,
        }


@dataclass
class ServiceFingerprint:
    """Service fingerprint result."""

    service_type: ServiceType
    name: str
    version: str | None = None
    confidence: InfrastructureConfidence = InfrastructureConfidence.MEDIUM
    indicators: list[str] = field(default_factory=list)
    configuration: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "service_type": self.service_type.value,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence.value,
            "indicators": self.indicators,
            "configuration": self.configuration,
        }


@dataclass
class NetworkComponent:
    """Network topology component."""

    component_type: str
    name: str
    address: str | None = None
    role: str = ""
    connections: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "component_type": self.component_type,
            "name": self.name,
            "address": self.address,
            "role": self.role,
            "connections": self.connections,
            "attributes": self.attributes,
        }


# ============================================================================
# Cloud Provider Indicators
# ============================================================================

AWS_INDICATORS = {
    "ip_ranges": [
        ".amazonaws.com",
        ".aws.amazon.com",
        ".awsstatic.com",
        ".elasticbeanstalk.com",
    ],
    "domain_patterns": [
        r"\.amazonaws\.com$",
        r"\.aws\.amazon\.com$",
        r"\.awsstatic\.com$",
        r"\.elasticbeanstalk\.com$",
    ],
    "headers": [
        ("x-amz-", "AWS header prefix"),
        ("x-amzn-", "AWS header prefix"),
        ("server", "AmazonS3"),
        ("server", "awselb"),
        ("x-amz-cf-", "CloudFront"),
        ("x-amz-request-id", "S3 request"),
    ],
    "dns_patterns": [
        r"s3[-.].*\.amazonaws\.com",
        r"ec2[-.].*\.amazonaws\.com",
        r"elb\..*\.amazonaws\.com",
        r"rds\..*\.amazonaws\.com",
        r"\.cloudfront\.net$",
        r"\.execute-api\..*\.amazonaws\.com",
    ],
    "services": [
        "EC2",
        "S3",
        "Lambda",
        "ELB",
        "CloudFront",
        "RDS",
        "DynamoDB",
        "API Gateway",
        "ECS",
        "EKS",
        "Fargate",
        "Route 53",
    ],
}

AZURE_INDICATORS = {
    "ip_ranges": [
        ".azure.com",
        ".azurewebsites.net",
        ".cloudapp.azure.com",
        ".azureedge.net",
        ".blob.core.windows.net",
    ],
    "domain_patterns": [
        r"\.azure\.com$",
        r"\.azurewebsites\.net$",
        r"\.cloudapp\.azure\.com$",
        r"\.azureedge\.net$",
        r"\.blob\.core\.windows\.net$",
    ],
    "headers": [
        ("x-ms-", "Azure header prefix"),
        ("x-azure-", "Azure header prefix"),
        ("server", "Microsoft-IIS"),
        ("server", "Microsoft-Azure"),
        ("x-aspnet-version", "ASP.NET"),
    ],
    "dns_patterns": [
        r"\.azurewebsites\.net$",
        r"\.blob\.core\.windows\.net$",
        r"\.azure-api\.net$",
        r"\.azurefd\.net$",
        r"\.trafficmanager\.net$",
    ],
    "services": [
        "App Service",
        "Azure Functions",
        "Blob Storage",
        "Azure CDN",
        "Azure SQL",
        "Cosmos DB",
        "AKS",
        "Virtual Machines",
    ],
}

GCP_INDICATORS = {
    "ip_ranges": [
        ".googleapis.com",
        ".appspot.com",
        ".run.app",
        ".cloudfunctions.net",
        ".storage.googleapis.com",
    ],
    "domain_patterns": [
        r"\.googleapis\.com$",
        r"\.appspot\.com$",
        r"\.run\.app$",
        r"\.cloudfunctions\.net$",
        r"\.storage\.googleapis\.com$",
    ],
    "headers": [
        ("x-goog-", "GCP header prefix"),
        ("x-cloud-trace-context", "Cloud Trace"),
        ("server", "Google Frontend"),
        ("server", "gws"),
        ("via", "google"),
    ],
    "dns_patterns": [
        r"\.appspot\.com$",
        r"\.run\.app$",
        r"\.cloudfunctions\.net$",
        r"storage\.googleapis\.com",
        r"\.firebaseapp\.com$",
    ],
    "services": [
        "Compute Engine",
        "Cloud Functions",
        "Cloud Run",
        "App Engine",
        "Cloud Storage",
        "BigQuery",
        "GKE",
        "Cloud SQL",
        "Firebase",
    ],
}

DIGITALOCEAN_INDICATORS = {
    "ip_ranges": [
        r"\.digitaloceanspaces\.com$",
        r"\.ondigitalocean\.app$",
    ],
    "headers": [
        ("server", "digitalocean"),
        ("x-do-", "DigitalOcean prefix"),
    ],
    "dns_patterns": [
        r"\.digitaloceanspaces\.com$",
        r"\.ondigitalocean\.app$",
    ],
    "services": ["Droplets", "Spaces", "App Platform", "Kubernetes"],
}

# ============================================================================
# CDN Provider Indicators
# ============================================================================

CLOUDFLARE_INDICATORS = {
    "headers": [
        ("cf-ray", "Cloudflare Ray ID"),
        ("cf-cache-status", "Cloudflare cache"),
        ("server", "cloudflare"),
        ("cf-request-id", "Cloudflare request"),
        ("cf-edge-ip", "Cloudflare edge"),
    ],
    "dns_patterns": [
        r"\.cdn\.cloudflare\.net$",
        r"\.cloudflare\.com$",
        r"\.cloudflaressl\.com$",
    ],
    "features": ["WAF", "DDoS Protection", "CDN", "DNS", "Workers"],
}

AKAMAI_INDICATORS = {
    "headers": [
        ("x-akamai-", "Akamai prefix"),
        ("akamai-", "Akamai prefix"),
        ("server", "AkamaiGHost"),
        ("x-true-cache-key", "Akamai cache"),
    ],
    "dns_patterns": [
        r"\.akamai\.net$",
        r"\.akamaized\.net$",
        r"\.akamaiedge\.net$",
        r"\.akamaitechnologies\.com$",
    ],
    "features": ["CDN", "WAF", "DDoS Protection", "Edge Computing"],
}

FASTLY_INDICATORS = {
    "headers": [
        ("x-fastly-request-id", "Fastly request"),
        ("fastly-", "Fastly prefix"),
        ("x-served-by", "cache-"),  # Fastly cache servers
        ("x-timer", "Fastly timer"),
    ],
    "dns_patterns": [
        r"\.fastly\.net$",
        r"\.fastlylb\.net$",
        r"\.global\.ssl\.fastly\.net$",
    ],
    "features": ["CDN", "Edge Computing", "Image Optimization"],
}

CLOUDFRONT_INDICATORS = {
    "headers": [
        ("x-amz-cf-id", "CloudFront ID"),
        ("x-amz-cf-pop", "CloudFront POP"),
        ("via", "CloudFront"),
        ("x-cache", "Hit from cloudfront"),
    ],
    "dns_patterns": [
        r"\.cloudfront\.net$",
        r"d[a-z0-9]+\.cloudfront\.net$",
    ],
    "features": ["CDN", "Lambda@Edge", "WAF Integration"],
}

# ============================================================================
# Service Fingerprints
# ============================================================================

WEB_SERVER_SIGNATURES = {
    "nginx": {
        "patterns": [r"nginx/?(\d+\.[\d.]+)?", r"openresty/?(\d+\.[\d.]+)?"],
        "headers": ["server"],
    },
    "apache": {
        "patterns": [r"Apache/?(\d+\.[\d.]+)?", r"Apache-Coyote"],
        "headers": ["server"],
    },
    "iis": {
        "patterns": [r"Microsoft-IIS/?(\d+\.[\d.]+)?"],
        "headers": ["server", "x-powered-by"],
    },
    "caddy": {
        "patterns": [r"Caddy"],
        "headers": ["server"],
    },
    "lighttpd": {
        "patterns": [r"lighttpd/?(\d+\.[\d.]+)?"],
        "headers": ["server"],
    },
    "litespeed": {
        "patterns": [r"LiteSpeed"],
        "headers": ["server"],
    },
}

APPLICATION_SIGNATURES = {
    "express": {
        "patterns": [r"Express"],
        "headers": ["x-powered-by"],
    },
    "django": {
        "patterns": [r"WSGIServer", r"gunicorn"],
        "headers": ["server"],
        "indicators": ["csrftoken", "django"],
    },
    "rails": {
        "patterns": [r"Phusion Passenger", r"Puma"],
        "headers": ["server", "x-powered-by"],
        "indicators": ["_rails", "csrf-token"],
    },
    "php": {
        "patterns": [r"PHP/?(\d+\.[\d.]+)?"],
        "headers": ["x-powered-by"],
    },
    "aspnet": {
        "patterns": [r"ASP\.NET"],
        "headers": ["x-powered-by", "x-aspnet-version"],
    },
    "tomcat": {
        "patterns": [r"Apache-Coyote", r"Apache Tomcat/?(\d+\.[\d.]+)?"],
        "headers": ["server"],
    },
    "jetty": {
        "patterns": [r"Jetty/?(\d+\.[\d.]+)?"],
        "headers": ["server"],
    },
    "spring": {
        "indicators": ["JSESSIONID", "spring"],
    },
    "flask": {
        "patterns": [r"Werkzeug/?(\d+\.[\d.]+)?"],
        "headers": ["server"],
    },
    "nextjs": {
        "headers": ["x-nextjs-"],
        "indicators": ["_next/"],
    },
    "nuxt": {
        "indicators": ["_nuxt/", "__nuxt"],
    },
}

LOAD_BALANCER_SIGNATURES = {
    "aws_elb": {
        "patterns": [r"awselb/?(\d+\.[\d.]+)?", r"ELB"],
        "headers": ["server"],
    },
    "haproxy": {
        "patterns": [r"HAProxy"],
        "headers": ["server"],
    },
    "envoy": {
        "patterns": [r"envoy"],
        "headers": ["server", "x-envoy-"],
    },
    "traefik": {
        "headers": ["x-traefik-"],
    },
}

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status"],
    },
    "aws_waf": {
        "headers": ["x-amzn-waf-"],
    },
    "akamai_kona": {
        "headers": ["akamai-"],
        "patterns": [r"AkamaiGHost"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "patterns": [r"Incapsula"],
    },
    "f5": {
        "patterns": [r"BIG-IP", r"F5"],
        "headers": ["server"],
    },
    "modsecurity": {
        "indicators": ["mod_security", "OWASP"],
    },
}

# ============================================================================
# DNS Infrastructure Patterns
# ============================================================================

DNS_PROVIDERS = {
    "cloudflare": {
        "nameserver_patterns": [r"\.cloudflare\.com$", r"cloudflare\.com$"],
    },
    "route53": {
        "nameserver_patterns": [r"\.awsdns-\d+\.(com|net|org|co\.uk)$"],
    },
    "azure_dns": {
        "nameserver_patterns": [r"\.azure-dns\.(com|net|org|info)$"],
    },
    "google_cloud_dns": {
        "nameserver_patterns": [r"\.googledomains\.com$", r"\.google\.com$"],
    },
    "godaddy": {
        "nameserver_patterns": [r"\.domaincontrol\.com$"],
    },
    "namecheap": {
        "nameserver_patterns": [r"\.registrar-servers\.com$"],
    },
    "dnsimple": {
        "nameserver_patterns": [r"\.dnsimple\.com$"],
    },
}

# ============================================================================
# Main Functions
# ============================================================================


def analyze_infrastructure(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Analyze infrastructure from context data.

    Args:
        ctx: Pipeline context
        params: Optional parameters:
            - detect_cloud: Whether to detect cloud providers
            - detect_cdn: Whether to detect CDN providers
            - fingerprint_services: Whether to fingerprint services
            - analyze_topology: Whether to infer network topology

    Returns:
        Updated context with infrastructure analysis
    """
    params = params or {}
    target = params.get("target") or ctx.target

    if not target:
        ctx.log("No target specified for infrastructure analysis", level="WARNING")
        return ctx

    ctx.log(f"Analyzing infrastructure for: {target}", level="INFO")

    # Initialize results
    infra_data = {
        "target": target,
        "cloud_providers": [],
        "cdn_providers": [],
        "services": [],
        "dns_infrastructure": {},
        "network_topology": [],
        "hosting_info": {},
        "security_features": [],
        "summary": {},
    }

    # Collect data from context
    headers = collect_headers_from_context(ctx)
    dns_records = collect_dns_from_context(ctx)
    urls = collect_urls_from_context(ctx)
    certificates = collect_certificates_from_context(ctx)

    # Detect cloud providers
    if params.get("detect_cloud", True):
        cloud_detections = detect_cloud_providers(headers, dns_records, urls, target)
        infra_data["cloud_providers"] = [c.to_dict() for c in cloud_detections]

    # Detect CDN providers
    if params.get("detect_cdn", True):
        cdn_detections = detect_cdn_providers(headers, dns_records)
        infra_data["cdn_providers"] = [c.to_dict() for c in cdn_detections]

    # Fingerprint services
    if params.get("fingerprint_services", True):
        services = fingerprint_services(headers, urls, ctx)
        infra_data["services"] = [s.to_dict() for s in services]

    # Analyze DNS infrastructure
    dns_info = analyze_dns_infrastructure(dns_records, target)
    infra_data["dns_infrastructure"] = dns_info

    # Analyze certificates
    if certificates:
        cert_info = analyze_certificates(certificates)
        infra_data["hosting_info"]["certificate_analysis"] = cert_info

    # Detect security features
    security = detect_security_features(headers, infra_data)
    infra_data["security_features"] = security

    # Infer network topology
    if params.get("analyze_topology", True):
        topology = infer_network_topology(infra_data, ctx)
        infra_data["network_topology"] = [t.to_dict() for t in topology]

    # Generate summary
    infra_data["summary"] = generate_infrastructure_summary(infra_data)

    # Add to context
    ctx.add("infrastructure", infra_data)

    # Log findings
    cloud_count = len(infra_data["cloud_providers"])
    cdn_count = len(infra_data["cdn_providers"])
    service_count = len(infra_data["services"])

    ctx.log(
        f"Infrastructure analysis complete: {cloud_count} cloud, {cdn_count} CDN, {service_count} services",
        level="INFO",
    )

    return ctx


def collect_headers_from_context(ctx: Context) -> dict[str, str]:
    """
    Collect HTTP headers from context.

    Args:
        ctx: Pipeline context

    Returns:
        Dictionary of headers
    """
    headers = {}

    # From tech_stack
    tech_stack = ctx.get("tech_stack", {})
    if tech_stack.get("headers"):
        headers.update(tech_stack["headers"])

    # From domain_profile
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("headers"):
        headers.update(domain_profile["headers"])

    # From response_headers
    response_headers = ctx.get("response_headers", {})
    if response_headers:
        headers.update(response_headers)

    return headers


def collect_dns_from_context(ctx: Context) -> dict[str, list[str]]:
    """
    Collect DNS records from context.

    Args:
        ctx: Pipeline context

    Returns:
        Dictionary of DNS record types to values
    """
    dns_records = {}

    # From domain_profile
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("dns_records"):
        dns_records.update(domain_profile["dns_records"])

    # From dns_info
    dns_info = ctx.get("dns_info", {})
    if dns_info:
        dns_records.update(dns_info)

    return dns_records


def collect_urls_from_context(ctx: Context) -> list[str]:
    """
    Collect URLs from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of URLs
    """
    urls = []

    # From tech_stack
    tech_stack = ctx.get("tech_stack", {})
    if tech_stack.get("urls"):
        urls.extend(tech_stack["urls"])

    # From domain_profile
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("urls"):
        urls.extend(domain_profile["urls"])

    # From subdomains
    subdomains = domain_profile.get("subdomains", [])
    urls.extend([f"https://{s}" for s in subdomains])

    # Target itself
    target = ctx.target
    if target:
        urls.append(f"https://{target}")

    return list(set(urls))


def collect_certificates_from_context(ctx: Context) -> list[dict[str, Any]]:
    """
    Collect SSL certificates from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of certificate data
    """
    certificates = []

    # From domain_profile
    domain_profile = ctx.get("domain_profile", {})
    if domain_profile.get("certificate"):
        certificates.append(domain_profile["certificate"])

    # From ssl_info
    ssl_info = ctx.get("ssl_info", {})
    if ssl_info:
        certificates.append(ssl_info)

    return certificates


def detect_cloud_providers(
    headers: dict[str, str],
    dns_records: dict[str, list[str]],
    urls: list[str],
    target: str,
) -> list[CloudDetection]:
    """
    Detect cloud providers from available data.

    Args:
        headers: HTTP headers
        dns_records: DNS records
        urls: URLs
        target: Target domain

    Returns:
        List of cloud detections
    """
    detections = []

    # Check each cloud provider
    providers = [
        (CloudProvider.AWS, AWS_INDICATORS),
        (CloudProvider.AZURE, AZURE_INDICATORS),
        (CloudProvider.GCP, GCP_INDICATORS),
        (CloudProvider.DIGITALOCEAN, DIGITALOCEAN_INDICATORS),
    ]

    for provider, indicators in providers:
        detection = check_cloud_provider(
            provider, indicators, headers, dns_records, urls, target
        )
        if detection:
            detections.append(detection)

    return detections


def check_cloud_provider(
    provider: CloudProvider,
    indicators: dict[str, Any],
    headers: dict[str, str],
    dns_records: dict[str, list[str]],
    urls: list[str],
    target: str,
) -> CloudDetection | None:
    """
    Check for a specific cloud provider.

    Args:
        provider: Cloud provider to check
        indicators: Indicators for this provider
        headers: HTTP headers
        dns_records: DNS records
        urls: URLs
        target: Target domain

    Returns:
        CloudDetection or None
    """
    found_indicators = []
    confidence = InfrastructureConfidence.LOW

    # Normalize headers to lowercase keys
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check headers
    for header_name, indicator in indicators.get("headers", []):
        # For headers like ("x-amz-", "AWS header prefix") - check prefix match
        if header_name.endswith("-"):
            for h_name in headers_lower.keys():
                if h_name.startswith(header_name.lower()):
                    found_indicators.append(f"Header prefix: {h_name}")
                    confidence = InfrastructureConfidence.HIGH
        elif header_name.lower() == "server":
            # For "server" header, we need to check the VALUE matches the indicator
            header_value = headers_lower.get("server", "")
            if header_value and indicator.lower() in header_value.lower():
                found_indicators.append(f"Header: server={indicator}")
                confidence = InfrastructureConfidence.HIGH
        else:
            # For exact header names like ("x-amz-request-id", "S3 request")
            if header_name.lower() in headers_lower:
                found_indicators.append(f"Header: {header_name}")
                confidence = InfrastructureConfidence.HIGH

    # Check DNS patterns
    all_dns = []
    for record_type, records in dns_records.items():
        if isinstance(records, list):
            all_dns.extend(records)

    # Check domain_patterns (regex patterns)
    for pattern in indicators.get("domain_patterns", []):
        for dns_value in all_dns:
            if re.search(pattern, str(dns_value), re.IGNORECASE):
                found_indicators.append(f"DNS: {dns_value}")
                if confidence != InfrastructureConfidence.HIGH:
                    confidence = InfrastructureConfidence.MEDIUM

    # Check dns_patterns (regex patterns)
    for pattern in indicators.get("dns_patterns", []):
        for dns_value in all_dns:
            if re.search(pattern, str(dns_value), re.IGNORECASE):
                if f"DNS: {dns_value}" not in found_indicators:
                    found_indicators.append(f"DNS: {dns_value}")
                    if confidence != InfrastructureConfidence.HIGH:
                        confidence = InfrastructureConfidence.MEDIUM

    # Also check ip_ranges for simple substring matches
    for suffix in indicators.get("ip_ranges", []):
        for dns_value in all_dns:
            if suffix.lower() in str(dns_value).lower():
                if f"DNS: {dns_value}" not in found_indicators:
                    found_indicators.append(f"DNS: {dns_value}")
                    if confidence != InfrastructureConfidence.HIGH:
                        confidence = InfrastructureConfidence.MEDIUM

    # Check URL patterns using ip_ranges (simple substring match)
    for suffix in indicators.get("ip_ranges", []):
        for url in urls + [target]:
            if suffix.lower() in str(url).lower():
                found_indicators.append(f"URL/Domain: {url}")
                confidence = InfrastructureConfidence.HIGH

    if found_indicators:
        return CloudDetection(
            provider=provider,
            confidence=confidence,
            indicators=found_indicators[:10],
            services=indicators.get("services", []),
        )

    return None


def detect_cdn_providers(
    headers: dict[str, str], dns_records: dict[str, list[str]]
) -> list[CDNDetection]:
    """
    Detect CDN providers from available data.

    Args:
        headers: HTTP headers
        dns_records: DNS records

    Returns:
        List of CDN detections
    """
    detections = []

    cdn_configs = [
        (CDNProvider.CLOUDFLARE, CLOUDFLARE_INDICATORS),
        (CDNProvider.AKAMAI, AKAMAI_INDICATORS),
        (CDNProvider.FASTLY, FASTLY_INDICATORS),
        (CDNProvider.CLOUDFRONT, CLOUDFRONT_INDICATORS),
    ]

    for provider, indicators in cdn_configs:
        detection = check_cdn_provider(provider, indicators, headers, dns_records)
        if detection:
            detections.append(detection)

    return detections


def check_cdn_provider(
    provider: CDNProvider,
    indicators: dict[str, Any],
    headers: dict[str, str],
    dns_records: dict[str, list[str]],
) -> CDNDetection | None:
    """
    Check for a specific CDN provider.

    Args:
        provider: CDN provider to check
        indicators: Indicators for this provider
        headers: HTTP headers
        dns_records: DNS records

    Returns:
        CDNDetection or None
    """
    found_indicators = []
    confidence = InfrastructureConfidence.LOW

    # Normalize headers to lowercase keys
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check headers
    for header_check in indicators.get("headers", []):
        if isinstance(header_check, tuple):
            header_name, description = header_check
            # Check if header exists (the description is just metadata)
            if header_name.lower() in headers_lower:
                found_indicators.append(f"Header: {header_name}")
                confidence = InfrastructureConfidence.HIGH
        else:
            # Just check if header exists by prefix
            for h_name in headers_lower.keys():
                if h_name.startswith(header_check.lower()):
                    found_indicators.append(f"Header: {h_name}")
                    confidence = InfrastructureConfidence.HIGH

    # Check DNS patterns
    all_dns = []
    for records in dns_records.values():
        if isinstance(records, list):
            all_dns.extend(records)

    for pattern in indicators.get("dns_patterns", []):
        for dns_value in all_dns:
            if re.search(pattern, str(dns_value), re.IGNORECASE):
                found_indicators.append(f"DNS: {dns_value}")
                if confidence != InfrastructureConfidence.HIGH:
                    confidence = InfrastructureConfidence.MEDIUM

    if found_indicators:
        return CDNDetection(
            provider=provider,
            confidence=confidence,
            indicators=found_indicators[:10],
            features=indicators.get("features", []),
        )

    return None


def fingerprint_services(
    headers: dict[str, str], urls: list[str], ctx: Context
) -> list[ServiceFingerprint]:
    """
    Fingerprint services from headers and other data.

    Args:
        headers: HTTP headers
        urls: URLs
        ctx: Context for additional data

    Returns:
        List of service fingerprints
    """
    services = []

    # Check web servers
    for server_name, signature in WEB_SERVER_SIGNATURES.items():
        fingerprint = check_service_signature(
            server_name, signature, headers, ServiceType.WEB_SERVER
        )
        if fingerprint:
            services.append(fingerprint)

    # Check application servers
    for app_name, signature in APPLICATION_SIGNATURES.items():
        fingerprint = check_service_signature(
            app_name, signature, headers, ServiceType.APPLICATION_SERVER
        )
        if fingerprint:
            services.append(fingerprint)

    # Check load balancers
    for lb_name, signature in LOAD_BALANCER_SIGNATURES.items():
        fingerprint = check_service_signature(
            lb_name, signature, headers, ServiceType.LOAD_BALANCER
        )
        if fingerprint:
            services.append(fingerprint)

    # Check WAFs
    for waf_name, signature in WAF_SIGNATURES.items():
        fingerprint = check_service_signature(
            waf_name, signature, headers, ServiceType.WAF
        )
        if fingerprint:
            services.append(fingerprint)

    return services


def check_service_signature(
    name: str,
    signature: dict[str, Any],
    headers: dict[str, str],
    service_type: ServiceType,
) -> ServiceFingerprint | None:
    """
    Check for a specific service signature.

    Args:
        name: Service name
        signature: Signature patterns
        headers: HTTP headers
        service_type: Type of service

    Returns:
        ServiceFingerprint or None
    """
    found_indicators = []
    version = None

    # Check header patterns
    for header_name in signature.get("headers", []):
        header_value = headers.get(header_name.lower(), "")
        if header_value:
            for pattern in signature.get("patterns", []):
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    found_indicators.append(f"{header_name}: {header_value}")
                    # Try to extract version
                    if match.groups():
                        version = match.group(1)
                    break

    # Check for header prefix matches
    for header_name in signature.get("headers", []):
        if header_name.endswith("-"):
            # This is a prefix check
            for h_name in headers.keys():
                if h_name.lower().startswith(header_name.lower()):
                    found_indicators.append(f"Header prefix: {h_name}")

    if found_indicators:
        return ServiceFingerprint(
            service_type=service_type,
            name=name,
            version=version,
            confidence=InfrastructureConfidence.HIGH
            if version
            else InfrastructureConfidence.MEDIUM,
            indicators=found_indicators[:5],
        )

    return None


def analyze_dns_infrastructure(
    dns_records: dict[str, list[str]], target: str
) -> dict[str, Any]:
    """
    Analyze DNS infrastructure.

    Args:
        dns_records: DNS records
        target: Target domain

    Returns:
        DNS infrastructure analysis
    """
    analysis = {
        "dns_provider": None,
        "nameservers": [],
        "mx_servers": [],
        "has_spf": False,
        "has_dkim": False,
        "has_dmarc": False,
        "record_counts": {},
    }

    # Get nameservers
    nameservers = dns_records.get("NS", [])
    analysis["nameservers"] = nameservers

    # Detect DNS provider
    for provider_name, config in DNS_PROVIDERS.items():
        for ns in nameservers:
            for pattern in config.get("nameserver_patterns", []):
                if re.search(pattern, str(ns), re.IGNORECASE):
                    analysis["dns_provider"] = provider_name
                    break

    # Get MX servers
    analysis["mx_servers"] = dns_records.get("MX", [])

    # Check for email security records
    txt_records = dns_records.get("TXT", [])
    for txt in txt_records:
        txt_str = str(txt).lower()
        if "v=spf1" in txt_str:
            analysis["has_spf"] = True
        if "v=dkim1" in txt_str:
            analysis["has_dkim"] = True
        if "v=dmarc1" in txt_str:
            analysis["has_dmarc"] = True

    # Count records
    for record_type, records in dns_records.items():
        if isinstance(records, list):
            analysis["record_counts"][record_type] = len(records)

    return analysis


def analyze_certificates(certificates: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze SSL certificates for infrastructure info.

    Args:
        certificates: Certificate data

    Returns:
        Certificate analysis
    """
    analysis = {
        "issuers": [],
        "san_domains": [],
        "organization": None,
        "validity": {},
    }

    for cert in certificates:
        # Issuer
        issuer = cert.get("issuer", "")
        if issuer and issuer not in analysis["issuers"]:
            analysis["issuers"].append(issuer)

        # SAN domains
        san = cert.get("san", [])
        if isinstance(san, list):
            analysis["san_domains"].extend(san)

        # Organization
        if cert.get("organization"):
            analysis["organization"] = cert["organization"]

        # Validity
        if cert.get("not_before") or cert.get("not_after"):
            analysis["validity"] = {
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
            }

    # Deduplicate
    analysis["san_domains"] = list(set(analysis["san_domains"]))

    return analysis


def detect_security_features(
    headers: dict[str, str], infra_data: dict[str, Any]
) -> list[dict[str, Any]]:
    """
    Detect security features in use.

    Args:
        headers: HTTP headers
        infra_data: Infrastructure data collected

    Returns:
        List of security features
    """
    features = []

    # Check security headers
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    for header, name in security_headers.items():
        if header in [h.lower() for h in headers.keys()]:
            features.append(
                {
                    "feature": name,
                    "type": "security_header",
                    "status": "enabled",
                }
            )

    # Check for WAF from services
    for service in infra_data.get("services", []):
        if service.get("service_type") == "waf":
            features.append(
                {
                    "feature": f"WAF ({service.get('name', 'Unknown')})",
                    "type": "waf",
                    "status": "detected",
                }
            )

    # Check for CDN WAF features
    for cdn in infra_data.get("cdn_providers", []):
        if "WAF" in cdn.get("features", []):
            features.append(
                {
                    "feature": f"CDN WAF ({cdn.get('provider', 'Unknown')})",
                    "type": "cdn_waf",
                    "status": "detected",
                }
            )

    # Check DNS security
    dns_info = infra_data.get("dns_infrastructure", {})
    if dns_info.get("has_spf"):
        features.append(
            {"feature": "SPF", "type": "email_security", "status": "enabled"}
        )
    if dns_info.get("has_dkim"):
        features.append(
            {"feature": "DKIM", "type": "email_security", "status": "enabled"}
        )
    if dns_info.get("has_dmarc"):
        features.append(
            {"feature": "DMARC", "type": "email_security", "status": "enabled"}
        )

    return features


def infer_network_topology(
    infra_data: dict[str, Any], ctx: Context
) -> list[NetworkComponent]:
    """
    Infer network topology from infrastructure data.

    Args:
        infra_data: Infrastructure data
        ctx: Context

    Returns:
        List of network components
    """
    components = []
    target = ctx.target

    # Add target as primary component
    if target:
        components.append(
            NetworkComponent(
                component_type="domain",
                name=target,
                role="primary",
            )
        )

    # Add cloud providers
    for cloud in infra_data.get("cloud_providers", []):
        components.append(
            NetworkComponent(
                component_type="cloud",
                name=cloud.get("provider", "unknown"),
                role="hosting",
                attributes={"services": cloud.get("services", [])},
            )
        )

    # Add CDN
    for cdn in infra_data.get("cdn_providers", []):
        components.append(
            NetworkComponent(
                component_type="cdn",
                name=cdn.get("provider", "unknown"),
                role="edge",
                attributes={"features": cdn.get("features", [])},
            )
        )

    # Add DNS
    dns_info = infra_data.get("dns_infrastructure", {})
    if dns_info.get("dns_provider"):
        components.append(
            NetworkComponent(
                component_type="dns",
                name=dns_info["dns_provider"],
                role="dns",
                attributes={"nameservers": dns_info.get("nameservers", [])},
            )
        )

    # Add services
    for service in infra_data.get("services", []):
        components.append(
            NetworkComponent(
                component_type="service",
                name=service.get("name", "unknown"),
                role=service.get("service_type", "unknown"),
                attributes={"version": service.get("version")},
            )
        )

    return components


def generate_infrastructure_summary(infra_data: dict[str, Any]) -> dict[str, Any]:
    """
    Generate summary of infrastructure analysis.

    Args:
        infra_data: Infrastructure data

    Returns:
        Summary dictionary
    """
    summary = {
        "cloud_providers_detected": len(infra_data.get("cloud_providers", [])),
        "cdn_providers_detected": len(infra_data.get("cdn_providers", [])),
        "services_detected": len(infra_data.get("services", [])),
        "security_features_count": len(infra_data.get("security_features", [])),
        "primary_cloud": None,
        "primary_cdn": None,
        "infrastructure_type": "unknown",
    }

    # Determine primary cloud
    clouds = infra_data.get("cloud_providers", [])
    if clouds:
        # Sort by confidence
        sorted_clouds = sorted(
            clouds,
            key=lambda x: {"high": 0, "medium": 1, "low": 2, "inferred": 3}.get(
                x.get("confidence", "low"), 3
            ),
        )
        summary["primary_cloud"] = sorted_clouds[0].get("provider")

    # Determine primary CDN
    cdns = infra_data.get("cdn_providers", [])
    if cdns:
        sorted_cdns = sorted(
            cdns,
            key=lambda x: {"high": 0, "medium": 1, "low": 2, "inferred": 3}.get(
                x.get("confidence", "low"), 3
            ),
        )
        summary["primary_cdn"] = sorted_cdns[0].get("provider")

    # Determine infrastructure type
    if summary["primary_cloud"]:
        if summary["primary_cdn"]:
            summary["infrastructure_type"] = "cloud_with_cdn"
        else:
            summary["infrastructure_type"] = "cloud_native"
    elif summary["primary_cdn"]:
        summary["infrastructure_type"] = "cdn_fronted"
    else:
        summary["infrastructure_type"] = "traditional"

    return summary


# ============================================================================
# Helper Functions
# ============================================================================


def get_cloud_provider(name: str) -> CloudProvider | None:
    """
    Get cloud provider by name.

    Args:
        name: Provider name

    Returns:
        CloudProvider or None (returns None for "unknown" as well)
    """
    name_normalized = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    # Return None for "unknown" - this is a sentinel value, not a real provider
    if name_normalized == "unknown":
        return None
    try:
        return CloudProvider(name_normalized)
    except ValueError:
        return None


def get_cdn_provider(name: str) -> CDNProvider | None:
    """
    Get CDN provider by name.

    Args:
        name: Provider name

    Returns:
        CDNProvider or None (returns None for "unknown" as well)
    """
    name_normalized = name.lower().replace(" ", "").replace("-", "").replace("_", "")
    # Return None for "unknown" - this is a sentinel value, not a real provider
    if name_normalized == "unknown":
        return None
    # Handle special cases with underscores in enum values
    special_cases = {
        "azurecdn": "azure_cdn",
        "googlecdn": "google_cdn",
    }
    if name_normalized in special_cases:
        name_normalized = special_cases[name_normalized]
    try:
        return CDNProvider(name_normalized)
    except ValueError:
        return None


def get_all_cloud_providers() -> list[CloudProvider]:
    """
    Get all cloud providers.

    Returns:
        List of cloud providers
    """
    return list(CloudProvider)


def get_all_cdn_providers() -> list[CDNProvider]:
    """
    Get all CDN providers.

    Returns:
        List of CDN providers
    """
    return list(CDNProvider)


def get_service_types() -> list[str]:
    """
    Get all service types.

    Returns:
        List of service type values
    """
    return [t.value for t in ServiceType]


def identify_cloud_from_ip(ip: str) -> CloudProvider | None:
    """
    Identify cloud provider from IP address patterns.

    Note: This is a simplified check based on common patterns.
    Real implementation would use IP range databases.

    Args:
        ip: IP address

    Returns:
        CloudProvider or None
    """
    # This would require IP range databases for accurate detection
    # For now, return None as we can't reliably detect from IP alone
    return None


def identify_cloud_from_domain(domain: str) -> CloudProvider | None:
    """
    Identify cloud provider from domain name.

    Args:
        domain: Domain name

    Returns:
        CloudProvider or None
    """
    domain_lower = domain.lower()

    # AWS patterns
    if any(
        p in domain_lower
        for p in [".amazonaws.com", ".awsstatic.com", ".cloudfront.net"]
    ):
        return CloudProvider.AWS

    # Azure patterns
    if any(
        p in domain_lower for p in [".azure.com", ".azurewebsites.net", ".windows.net"]
    ):
        return CloudProvider.AZURE

    # GCP patterns
    if any(p in domain_lower for p in [".googleapis.com", ".appspot.com", ".run.app"]):
        return CloudProvider.GCP

    # DigitalOcean patterns
    if any(
        p in domain_lower for p in [".digitaloceanspaces.com", ".ondigitalocean.app"]
    ):
        return CloudProvider.DIGITALOCEAN

    return None


def identify_cdn_from_headers(headers: dict[str, str]) -> CDNProvider | None:
    """
    Identify CDN provider from headers.

    Args:
        headers: HTTP headers

    Returns:
        CDNProvider or None
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Cloudflare
    if "cf-ray" in headers_lower:
        return CDNProvider.CLOUDFLARE

    # CloudFront
    if "x-amz-cf-id" in headers_lower:
        return CDNProvider.CLOUDFRONT

    # Fastly
    if "x-fastly-request-id" in headers_lower:
        return CDNProvider.FASTLY

    # Akamai
    if any(h.startswith("x-akamai") for h in headers_lower):
        return CDNProvider.AKAMAI

    return None


def get_aws_services() -> list[str]:
    """
    Get list of AWS services.

    Returns:
        List of AWS service names
    """
    return AWS_INDICATORS.get("services", [])


def get_azure_services() -> list[str]:
    """
    Get list of Azure services.

    Returns:
        List of Azure service names
    """
    return AZURE_INDICATORS.get("services", [])


def get_gcp_services() -> list[str]:
    """
    Get list of GCP services.

    Returns:
        List of GCP service names
    """
    return GCP_INDICATORS.get("services", [])


def is_cloud_hosted(infra_data: dict[str, Any]) -> bool:
    """
    Check if infrastructure is cloud-hosted.

    Args:
        infra_data: Infrastructure analysis data

    Returns:
        True if cloud-hosted
    """
    return len(infra_data.get("cloud_providers", [])) > 0


def is_cdn_fronted(infra_data: dict[str, Any]) -> bool:
    """
    Check if infrastructure is CDN-fronted.

    Args:
        infra_data: Infrastructure analysis data

    Returns:
        True if CDN-fronted
    """
    return len(infra_data.get("cdn_providers", [])) > 0


def get_security_posture(infra_data: dict[str, Any]) -> str:
    """
    Assess infrastructure security posture.

    Args:
        infra_data: Infrastructure analysis data

    Returns:
        Security posture assessment
    """
    features = infra_data.get("security_features", [])
    feature_count = len(features)

    # Check for critical features
    has_waf = any(f.get("type") in ["waf", "cdn_waf"] for f in features)
    has_hsts = any(f.get("feature") == "HSTS" for f in features)
    has_csp = any(f.get("feature") == "CSP" for f in features)

    if has_waf and has_hsts and has_csp and feature_count >= 5:
        return "strong"
    elif has_waf or (has_hsts and feature_count >= 3):
        return "moderate"
    elif feature_count >= 2:
        return "basic"
    else:
        return "minimal"
