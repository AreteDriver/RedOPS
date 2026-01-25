"""Tests for recon/infrastructure module."""

from redops.modules.recon.infrastructure import (
    CloudProvider,
    CDNProvider,
    ServiceType,
    InfrastructureConfidence,
    CloudDetection,
    CDNDetection,
    ServiceFingerprint,
    NetworkComponent,
    AWS_INDICATORS,
    AZURE_INDICATORS,
    GCP_INDICATORS,
    CLOUDFLARE_INDICATORS,
    WEB_SERVER_SIGNATURES,
    APPLICATION_SIGNATURES,
    DNS_PROVIDERS,
    analyze_infrastructure,
    collect_headers_from_context,
    collect_dns_from_context,
    collect_urls_from_context,
    detect_cloud_providers,
    check_cloud_provider,
    detect_cdn_providers,
    fingerprint_services,
    analyze_dns_infrastructure,
    analyze_certificates,
    detect_security_features,
    infer_network_topology,
    generate_infrastructure_summary,
    get_cloud_provider,
    get_cdn_provider,
    get_all_cloud_providers,
    get_all_cdn_providers,
    get_service_types,
    identify_cloud_from_domain,
    identify_cdn_from_headers,
    get_aws_services,
    get_azure_services,
    get_gcp_services,
    is_cloud_hosted,
    is_cdn_fronted,
    get_security_posture,
)
from redops.core.context import Context


class TestCloudProvider:
    """Tests for CloudProvider enum."""

    def test_provider_values(self):
        """Test all provider values exist."""
        assert CloudProvider.AWS.value == "aws"
        assert CloudProvider.AZURE.value == "azure"
        assert CloudProvider.GCP.value == "gcp"
        assert CloudProvider.DIGITALOCEAN.value == "digitalocean"

    def test_provider_count(self):
        """Test number of providers."""
        assert len(CloudProvider) >= 10


class TestCDNProvider:
    """Tests for CDNProvider enum."""

    def test_provider_values(self):
        """Test all provider values exist."""
        assert CDNProvider.CLOUDFLARE.value == "cloudflare"
        assert CDNProvider.AKAMAI.value == "akamai"
        assert CDNProvider.FASTLY.value == "fastly"
        assert CDNProvider.CLOUDFRONT.value == "cloudfront"

    def test_provider_count(self):
        """Test number of providers."""
        assert len(CDNProvider) >= 10


class TestServiceType:
    """Tests for ServiceType enum."""

    def test_service_types(self):
        """Test service type values."""
        assert ServiceType.WEB_SERVER.value == "web_server"
        assert ServiceType.APPLICATION_SERVER.value == "application_server"
        assert ServiceType.LOAD_BALANCER.value == "load_balancer"
        assert ServiceType.WAF.value == "waf"
        assert ServiceType.CDN.value == "cdn"


class TestInfrastructureConfidence:
    """Tests for InfrastructureConfidence enum."""

    def test_confidence_levels(self):
        """Test confidence level values."""
        assert InfrastructureConfidence.HIGH.value == "high"
        assert InfrastructureConfidence.MEDIUM.value == "medium"
        assert InfrastructureConfidence.LOW.value == "low"
        assert InfrastructureConfidence.INFERRED.value == "inferred"


class TestCloudDetection:
    """Tests for CloudDetection dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        detection = CloudDetection(
            provider=CloudProvider.AWS,
            confidence=InfrastructureConfidence.HIGH,
        )
        assert detection.provider == CloudProvider.AWS
        assert detection.indicators == []

    def test_full_creation(self):
        """Test creation with all fields."""
        detection = CloudDetection(
            provider=CloudProvider.AWS,
            confidence=InfrastructureConfidence.HIGH,
            indicators=["Header: x-amz-request-id"],
            services=["EC2", "S3"],
            regions=["us-east-1"],
            metadata={"account": "test"},
        )
        assert len(detection.services) == 2
        assert "us-east-1" in detection.regions

    def test_to_dict(self):
        """Test to_dict method."""
        detection = CloudDetection(
            provider=CloudProvider.AZURE,
            confidence=InfrastructureConfidence.MEDIUM,
        )
        result = detection.to_dict()

        assert result["provider"] == "azure"
        assert result["confidence"] == "medium"


class TestCDNDetection:
    """Tests for CDNDetection dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        detection = CDNDetection(
            provider=CDNProvider.CLOUDFLARE,
            confidence=InfrastructureConfidence.HIGH,
        )
        assert detection.provider == CDNProvider.CLOUDFLARE

    def test_to_dict(self):
        """Test to_dict method."""
        detection = CDNDetection(
            provider=CDNProvider.AKAMAI,
            confidence=InfrastructureConfidence.MEDIUM,
            features=["CDN", "WAF"],
        )
        result = detection.to_dict()

        assert result["provider"] == "akamai"
        assert "WAF" in result["features"]


class TestServiceFingerprint:
    """Tests for ServiceFingerprint dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        fp = ServiceFingerprint(
            service_type=ServiceType.WEB_SERVER,
            name="nginx",
        )
        assert fp.name == "nginx"
        assert fp.version is None

    def test_with_version(self):
        """Test with version."""
        fp = ServiceFingerprint(
            service_type=ServiceType.WEB_SERVER,
            name="nginx",
            version="1.18.0",
        )
        assert fp.version == "1.18.0"

    def test_to_dict(self):
        """Test to_dict method."""
        fp = ServiceFingerprint(
            service_type=ServiceType.APPLICATION_SERVER,
            name="express",
            version="4.17.1",
        )
        result = fp.to_dict()

        assert result["service_type"] == "application_server"
        assert result["name"] == "express"
        assert result["version"] == "4.17.1"


class TestNetworkComponent:
    """Tests for NetworkComponent dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        component = NetworkComponent(
            component_type="domain",
            name="example.com",
        )
        assert component.name == "example.com"

    def test_to_dict(self):
        """Test to_dict method."""
        component = NetworkComponent(
            component_type="cloud",
            name="aws",
            role="hosting",
            attributes={"services": ["EC2"]},
        )
        result = component.to_dict()

        assert result["component_type"] == "cloud"
        assert result["role"] == "hosting"


class TestAWSIndicators:
    """Tests for AWS indicators."""

    def test_ip_ranges_patterns(self):
        """Test IP range patterns exist."""
        assert len(AWS_INDICATORS["ip_ranges"]) >= 3
        assert any(".amazonaws.com" in p for p in AWS_INDICATORS["ip_ranges"])

    def test_headers_defined(self):
        """Test headers are defined."""
        assert len(AWS_INDICATORS["headers"]) >= 3
        assert any("x-amz" in h[0] for h in AWS_INDICATORS["headers"])

    def test_services_listed(self):
        """Test services are listed."""
        assert "EC2" in AWS_INDICATORS["services"]
        assert "S3" in AWS_INDICATORS["services"]
        assert "Lambda" in AWS_INDICATORS["services"]


class TestAzureIndicators:
    """Tests for Azure indicators."""

    def test_ip_ranges_patterns(self):
        """Test IP range patterns exist."""
        assert len(AZURE_INDICATORS["ip_ranges"]) >= 3
        assert any(".azure.com" in p for p in AZURE_INDICATORS["ip_ranges"])

    def test_services_listed(self):
        """Test services are listed."""
        assert "App Service" in AZURE_INDICATORS["services"]
        assert "Blob Storage" in AZURE_INDICATORS["services"]


class TestGCPIndicators:
    """Tests for GCP indicators."""

    def test_ip_ranges_patterns(self):
        """Test IP range patterns exist."""
        assert len(GCP_INDICATORS["ip_ranges"]) >= 3
        assert any(".googleapis.com" in p for p in GCP_INDICATORS["ip_ranges"])

    def test_services_listed(self):
        """Test services are listed."""
        assert "Compute Engine" in GCP_INDICATORS["services"]
        assert "Cloud Functions" in GCP_INDICATORS["services"]


class TestCloudflareIndicators:
    """Tests for Cloudflare indicators."""

    def test_headers_defined(self):
        """Test headers are defined."""
        assert len(CLOUDFLARE_INDICATORS["headers"]) >= 3
        assert any("cf-ray" in h[0] for h in CLOUDFLARE_INDICATORS["headers"])

    def test_features_listed(self):
        """Test features are listed."""
        assert "WAF" in CLOUDFLARE_INDICATORS["features"]
        assert "CDN" in CLOUDFLARE_INDICATORS["features"]


class TestWebServerSignatures:
    """Tests for web server signatures."""

    def test_nginx_signature(self):
        """Test nginx signature exists."""
        assert "nginx" in WEB_SERVER_SIGNATURES
        assert "patterns" in WEB_SERVER_SIGNATURES["nginx"]

    def test_apache_signature(self):
        """Test apache signature exists."""
        assert "apache" in WEB_SERVER_SIGNATURES
        assert "patterns" in WEB_SERVER_SIGNATURES["apache"]


class TestApplicationSignatures:
    """Tests for application signatures."""

    def test_express_signature(self):
        """Test express signature exists."""
        assert "express" in APPLICATION_SIGNATURES

    def test_django_signature(self):
        """Test django signature exists."""
        assert "django" in APPLICATION_SIGNATURES

    def test_rails_signature(self):
        """Test rails signature exists."""
        assert "rails" in APPLICATION_SIGNATURES


class TestDNSProviders:
    """Tests for DNS providers."""

    def test_cloudflare_dns(self):
        """Test Cloudflare DNS patterns."""
        assert "cloudflare" in DNS_PROVIDERS
        assert "nameserver_patterns" in DNS_PROVIDERS["cloudflare"]

    def test_route53_dns(self):
        """Test Route53 DNS patterns."""
        assert "route53" in DNS_PROVIDERS


class TestAnalyzeInfrastructure:
    """Tests for analyze_infrastructure function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        result = analyze_infrastructure(ctx)

        assert "infrastructure" in result.data
        infra = result.get("infrastructure")
        assert infra["target"] == "example.com"
        assert "cloud_providers" in infra
        assert "summary" in infra

    def test_no_target_warning(self):
        """Test warning when no target."""
        ctx = Context(target="")
        result = analyze_infrastructure(ctx)

        warnings = result.get_logs(level="WARNING")
        assert len(warnings) >= 1

    def test_with_aws_headers(self):
        """Test with AWS headers."""
        ctx = Context(target="example.com")
        ctx.add(
            "tech_stack",
            {
                "headers": {
                    "x-amz-request-id": "ABC123",
                    "server": "AmazonS3",
                }
            },
        )

        result = analyze_infrastructure(ctx)
        infra = result.get("infrastructure")

        # Should detect AWS
        assert len(infra["cloud_providers"]) >= 1
        assert any(c["provider"] == "aws" for c in infra["cloud_providers"])

    def test_with_cloudflare_headers(self):
        """Test with Cloudflare headers."""
        ctx = Context(target="example.com")
        ctx.add(
            "tech_stack",
            {
                "headers": {
                    "cf-ray": "ABC123-IAD",
                    "cf-cache-status": "HIT",
                }
            },
        )

        result = analyze_infrastructure(ctx)
        infra = result.get("infrastructure")

        # Should detect Cloudflare
        assert len(infra["cdn_providers"]) >= 1
        assert any(c["provider"] == "cloudflare" for c in infra["cdn_providers"])

    def test_with_nginx_server(self):
        """Test with nginx server header."""
        ctx = Context(target="example.com")
        ctx.add(
            "tech_stack",
            {
                "headers": {
                    "server": "nginx/1.18.0",
                }
            },
        )

        result = analyze_infrastructure(ctx)
        infra = result.get("infrastructure")

        # Should detect nginx
        assert len(infra["services"]) >= 1
        assert any(s["name"] == "nginx" for s in infra["services"])


class TestCollectHeadersFromContext:
    """Tests for collect_headers_from_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        headers = collect_headers_from_context(ctx)
        assert headers == {}

    def test_from_tech_stack(self):
        """Test collecting from tech_stack."""
        ctx = Context(target="example.com")
        ctx.add("tech_stack", {"headers": {"server": "nginx"}})

        headers = collect_headers_from_context(ctx)
        assert headers["server"] == "nginx"

    def test_from_domain_profile(self):
        """Test collecting from domain_profile."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {"headers": {"x-custom": "value"}})

        headers = collect_headers_from_context(ctx)
        assert headers["x-custom"] == "value"


class TestCollectDNSFromContext:
    """Tests for collect_dns_from_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        dns = collect_dns_from_context(ctx)
        assert dns == {}

    def test_from_domain_profile(self):
        """Test collecting from domain_profile."""
        ctx = Context(target="example.com")
        ctx.add(
            "domain_profile",
            {
                "dns_records": {
                    "A": ["1.2.3.4"],
                    "NS": ["ns1.example.com"],
                }
            },
        )

        dns = collect_dns_from_context(ctx)
        assert "A" in dns
        assert "NS" in dns


class TestCollectURLsFromContext:
    """Tests for collect_urls_from_context function."""

    def test_includes_target(self):
        """Test target is included."""
        ctx = Context(target="example.com")
        urls = collect_urls_from_context(ctx)

        assert any("example.com" in url for url in urls)

    def test_from_subdomains(self):
        """Test collecting from subdomains."""
        ctx = Context(target="example.com")
        ctx.add(
            "domain_profile", {"subdomains": ["www.example.com", "api.example.com"]}
        )

        urls = collect_urls_from_context(ctx)
        assert any("www.example.com" in url for url in urls)


class TestDetectCloudProviders:
    """Tests for detect_cloud_providers function."""

    def test_detect_aws(self):
        """Test AWS detection."""
        headers = {"x-amz-request-id": "ABC123"}
        dns = {}
        urls = ["https://mybucket.s3.amazonaws.com"]

        detections = detect_cloud_providers(headers, dns, urls, "example.com")

        assert len(detections) >= 1
        assert any(d.provider == CloudProvider.AWS for d in detections)

    def test_detect_azure(self):
        """Test Azure detection."""
        headers = {}
        dns = {"CNAME": ["myapp.azurewebsites.net"]}
        urls = []

        detections = detect_cloud_providers(headers, dns, urls, "example.com")

        assert len(detections) >= 1
        assert any(d.provider == CloudProvider.AZURE for d in detections)

    def test_detect_gcp(self):
        """Test GCP detection."""
        headers = {"x-goog-meta-custom": "value"}
        dns = {"CNAME": ["myapp.appspot.com"]}
        urls = []

        detections = detect_cloud_providers(headers, dns, urls, "example.com")

        assert len(detections) >= 1
        assert any(d.provider == CloudProvider.GCP for d in detections)

    def test_no_detection(self):
        """Test no detection with clean data."""
        headers = {"server": "nginx"}
        dns = {"A": ["1.2.3.4"]}
        urls = []

        detections = detect_cloud_providers(headers, dns, urls, "example.com")

        # Should be empty or minimal
        assert len(detections) == 0


class TestCheckCloudProvider:
    """Tests for check_cloud_provider function."""

    def test_aws_header_detection(self):
        """Test AWS header detection."""
        headers = {"x-amz-request-id": "ABC123"}
        detection = check_cloud_provider(
            CloudProvider.AWS, AWS_INDICATORS, headers, {}, [], "example.com"
        )

        assert detection is not None
        assert detection.provider == CloudProvider.AWS
        assert detection.confidence == InfrastructureConfidence.HIGH

    def test_aws_dns_detection(self):
        """Test AWS DNS detection."""
        dns = {"CNAME": ["bucket.s3.amazonaws.com"]}
        detection = check_cloud_provider(
            CloudProvider.AWS, AWS_INDICATORS, {}, dns, [], "example.com"
        )

        assert detection is not None
        assert detection.provider == CloudProvider.AWS


class TestDetectCDNProviders:
    """Tests for detect_cdn_providers function."""

    def test_detect_cloudflare(self):
        """Test Cloudflare detection."""
        headers = {"cf-ray": "ABC123-IAD"}
        dns = {}

        detections = detect_cdn_providers(headers, dns)

        assert len(detections) >= 1
        assert any(d.provider == CDNProvider.CLOUDFLARE for d in detections)

    def test_detect_cloudfront(self):
        """Test CloudFront detection."""
        headers = {"x-amz-cf-id": "ABC123"}
        dns = {}

        detections = detect_cdn_providers(headers, dns)

        assert len(detections) >= 1
        assert any(d.provider == CDNProvider.CLOUDFRONT for d in detections)

    def test_detect_fastly(self):
        """Test Fastly detection."""
        headers = {"x-fastly-request-id": "ABC123"}
        dns = {}

        detections = detect_cdn_providers(headers, dns)

        assert len(detections) >= 1
        assert any(d.provider == CDNProvider.FASTLY for d in detections)


class TestFingerprintServices:
    """Tests for fingerprint_services function."""

    def test_nginx_detection(self):
        """Test nginx detection."""
        headers = {"server": "nginx/1.18.0"}
        ctx = Context(target="example.com")

        services = fingerprint_services(headers, [], ctx)

        assert any(s.name == "nginx" for s in services)
        nginx = next(s for s in services if s.name == "nginx")
        assert nginx.version == "1.18.0"

    def test_apache_detection(self):
        """Test apache detection."""
        headers = {"server": "Apache/2.4.41"}
        ctx = Context(target="example.com")

        services = fingerprint_services(headers, [], ctx)

        assert any(s.name == "apache" for s in services)

    def test_express_detection(self):
        """Test express detection."""
        headers = {"x-powered-by": "Express"}
        ctx = Context(target="example.com")

        services = fingerprint_services(headers, [], ctx)

        assert any(s.name == "express" for s in services)

    def test_php_detection(self):
        """Test PHP detection."""
        headers = {"x-powered-by": "PHP/7.4.3"}
        ctx = Context(target="example.com")

        services = fingerprint_services(headers, [], ctx)

        assert any(s.name == "php" for s in services)


class TestAnalyzeDNSInfrastructure:
    """Tests for analyze_dns_infrastructure function."""

    def test_empty_records(self):
        """Test with empty records."""
        analysis = analyze_dns_infrastructure({}, "example.com")

        assert analysis["dns_provider"] is None
        assert analysis["nameservers"] == []

    def test_cloudflare_dns(self):
        """Test Cloudflare DNS detection."""
        dns = {"NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"]}
        analysis = analyze_dns_infrastructure(dns, "example.com")

        assert analysis["dns_provider"] == "cloudflare"

    def test_route53_dns(self):
        """Test Route53 DNS detection."""
        dns = {"NS": ["ns-123.awsdns-45.com"]}
        analysis = analyze_dns_infrastructure(dns, "example.com")

        assert analysis["dns_provider"] == "route53"

    def test_email_security(self):
        """Test email security detection."""
        dns = {
            "TXT": [
                "v=spf1 include:_spf.google.com ~all",
                "v=DMARC1; p=reject",
            ]
        }
        analysis = analyze_dns_infrastructure(dns, "example.com")

        assert analysis["has_spf"] is True
        assert analysis["has_dmarc"] is True


class TestAnalyzeCertificates:
    """Tests for analyze_certificates function."""

    def test_empty_certificates(self):
        """Test with empty certificates."""
        analysis = analyze_certificates([])

        assert analysis["issuers"] == []
        assert analysis["san_domains"] == []

    def test_with_certificate(self):
        """Test with certificate data."""
        certs = [
            {
                "issuer": "Let's Encrypt",
                "san": ["example.com", "www.example.com"],
                "organization": "Example Inc",
            }
        ]
        analysis = analyze_certificates(certs)

        assert "Let's Encrypt" in analysis["issuers"]
        assert "example.com" in analysis["san_domains"]


class TestDetectSecurityFeatures:
    """Tests for detect_security_features function."""

    def test_security_headers(self):
        """Test security header detection."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        }
        infra = {"services": [], "cdn_providers": [], "dns_infrastructure": {}}

        features = detect_security_features(headers, infra)

        assert any(f["feature"] == "HSTS" for f in features)
        assert any(f["feature"] == "CSP" for f in features)
        assert any(f["feature"] == "X-Frame-Options" for f in features)

    def test_email_security(self):
        """Test email security detection."""
        headers = {}
        infra = {
            "services": [],
            "cdn_providers": [],
            "dns_infrastructure": {
                "has_spf": True,
                "has_dkim": True,
                "has_dmarc": True,
            },
        }

        features = detect_security_features(headers, infra)

        assert any(f["feature"] == "SPF" for f in features)
        assert any(f["feature"] == "DKIM" for f in features)
        assert any(f["feature"] == "DMARC" for f in features)


class TestInferNetworkTopology:
    """Tests for infer_network_topology function."""

    def test_basic_topology(self):
        """Test basic topology inference."""
        ctx = Context(target="example.com")
        infra = {
            "cloud_providers": [{"provider": "aws", "services": ["EC2"]}],
            "cdn_providers": [{"provider": "cloudflare", "features": ["WAF"]}],
            "services": [{"name": "nginx", "service_type": "web_server"}],
            "dns_infrastructure": {"dns_provider": "route53"},
        }

        topology = infer_network_topology(infra, ctx)

        assert len(topology) >= 3  # domain, cloud, cdn at minimum
        assert any(c.component_type == "domain" for c in topology)
        assert any(c.component_type == "cloud" for c in topology)


class TestGenerateInfrastructureSummary:
    """Tests for generate_infrastructure_summary function."""

    def test_empty_data(self):
        """Test with empty data."""
        summary = generate_infrastructure_summary({})

        assert summary["cloud_providers_detected"] == 0
        assert summary["infrastructure_type"] == "traditional"

    def test_cloud_native(self):
        """Test cloud native detection."""
        infra = {
            "cloud_providers": [{"provider": "aws", "confidence": "high"}],
            "cdn_providers": [],
            "services": [],
            "security_features": [],
        }
        summary = generate_infrastructure_summary(infra)

        assert summary["primary_cloud"] == "aws"
        assert summary["infrastructure_type"] == "cloud_native"

    def test_cloud_with_cdn(self):
        """Test cloud with CDN detection."""
        infra = {
            "cloud_providers": [{"provider": "aws", "confidence": "high"}],
            "cdn_providers": [{"provider": "cloudflare", "confidence": "high"}],
            "services": [],
            "security_features": [],
        }
        summary = generate_infrastructure_summary(infra)

        assert summary["infrastructure_type"] == "cloud_with_cdn"


class TestGetCloudProvider:
    """Tests for get_cloud_provider function."""

    def test_valid_provider(self):
        """Test getting valid provider."""
        assert get_cloud_provider("aws") == CloudProvider.AWS
        assert get_cloud_provider("azure") == CloudProvider.AZURE

    def test_normalized_name(self):
        """Test normalized name lookup."""
        assert get_cloud_provider("AWS") == CloudProvider.AWS
        assert get_cloud_provider("digital-ocean") == CloudProvider.DIGITALOCEAN

    def test_invalid_provider(self):
        """Test invalid provider."""
        assert get_cloud_provider("unknown") is None


class TestGetCDNProvider:
    """Tests for get_cdn_provider function."""

    def test_valid_provider(self):
        """Test getting valid provider."""
        assert get_cdn_provider("cloudflare") == CDNProvider.CLOUDFLARE
        assert get_cdn_provider("akamai") == CDNProvider.AKAMAI

    def test_invalid_provider(self):
        """Test invalid provider."""
        assert get_cdn_provider("unknown") is None


class TestGetAllCloudProviders:
    """Tests for get_all_cloud_providers function."""

    def test_returns_list(self):
        """Test returns list."""
        providers = get_all_cloud_providers()
        assert isinstance(providers, list)
        assert CloudProvider.AWS in providers
        assert len(providers) >= 10


class TestGetAllCDNProviders:
    """Tests for get_all_cdn_providers function."""

    def test_returns_list(self):
        """Test returns list."""
        providers = get_all_cdn_providers()
        assert isinstance(providers, list)
        assert CDNProvider.CLOUDFLARE in providers


class TestGetServiceTypes:
    """Tests for get_service_types function."""

    def test_returns_list(self):
        """Test returns list of service types."""
        types = get_service_types()
        assert isinstance(types, list)
        assert "web_server" in types
        assert "waf" in types


class TestIdentifyCloudFromDomain:
    """Tests for identify_cloud_from_domain function."""

    def test_aws_domain(self):
        """Test AWS domain detection."""
        assert (
            identify_cloud_from_domain("bucket.s3.amazonaws.com") == CloudProvider.AWS
        )
        assert identify_cloud_from_domain("app.cloudfront.net") == CloudProvider.AWS

    def test_azure_domain(self):
        """Test Azure domain detection."""
        assert (
            identify_cloud_from_domain("myapp.azurewebsites.net") == CloudProvider.AZURE
        )
        assert (
            identify_cloud_from_domain("storage.blob.core.windows.net")
            == CloudProvider.AZURE
        )

    def test_gcp_domain(self):
        """Test GCP domain detection."""
        assert identify_cloud_from_domain("myapp.appspot.com") == CloudProvider.GCP
        assert identify_cloud_from_domain("api.googleapis.com") == CloudProvider.GCP

    def test_unknown_domain(self):
        """Test unknown domain."""
        assert identify_cloud_from_domain("example.com") is None


class TestIdentifyCDNFromHeaders:
    """Tests for identify_cdn_from_headers function."""

    def test_cloudflare(self):
        """Test Cloudflare detection."""
        headers = {"cf-ray": "ABC123"}
        assert identify_cdn_from_headers(headers) == CDNProvider.CLOUDFLARE

    def test_cloudfront(self):
        """Test CloudFront detection."""
        headers = {"x-amz-cf-id": "ABC123"}
        assert identify_cdn_from_headers(headers) == CDNProvider.CLOUDFRONT

    def test_fastly(self):
        """Test Fastly detection."""
        headers = {"x-fastly-request-id": "ABC123"}
        assert identify_cdn_from_headers(headers) == CDNProvider.FASTLY

    def test_unknown(self):
        """Test unknown headers."""
        headers = {"server": "nginx"}
        assert identify_cdn_from_headers(headers) is None


class TestGetCloudServices:
    """Tests for cloud service listing functions."""

    def test_aws_services(self):
        """Test AWS services list."""
        services = get_aws_services()
        assert "EC2" in services
        assert "S3" in services
        assert "Lambda" in services

    def test_azure_services(self):
        """Test Azure services list."""
        services = get_azure_services()
        assert "App Service" in services
        assert "Blob Storage" in services

    def test_gcp_services(self):
        """Test GCP services list."""
        services = get_gcp_services()
        assert "Compute Engine" in services
        assert "Cloud Functions" in services


class TestIsCloudHosted:
    """Tests for is_cloud_hosted function."""

    def test_with_cloud(self):
        """Test with cloud providers."""
        infra = {"cloud_providers": [{"provider": "aws"}]}
        assert is_cloud_hosted(infra) is True

    def test_without_cloud(self):
        """Test without cloud providers."""
        infra = {"cloud_providers": []}
        assert is_cloud_hosted(infra) is False


class TestIsCDNFronted:
    """Tests for is_cdn_fronted function."""

    def test_with_cdn(self):
        """Test with CDN providers."""
        infra = {"cdn_providers": [{"provider": "cloudflare"}]}
        assert is_cdn_fronted(infra) is True

    def test_without_cdn(self):
        """Test without CDN providers."""
        infra = {"cdn_providers": []}
        assert is_cdn_fronted(infra) is False


class TestGetSecurityPosture:
    """Tests for get_security_posture function."""

    def test_strong_posture(self):
        """Test strong security posture."""
        infra = {
            "security_features": [
                {"feature": "WAF", "type": "waf"},
                {"feature": "HSTS", "type": "security_header"},
                {"feature": "CSP", "type": "security_header"},
                {"feature": "X-Frame-Options", "type": "security_header"},
                {"feature": "SPF", "type": "email_security"},
                {"feature": "DMARC", "type": "email_security"},
            ]
        }
        assert get_security_posture(infra) == "strong"

    def test_minimal_posture(self):
        """Test minimal security posture."""
        infra = {"security_features": []}
        assert get_security_posture(infra) == "minimal"


class TestIntegration:
    """Integration tests for infrastructure analysis."""

    def test_full_analysis(self):
        """Test full infrastructure analysis."""
        ctx = Context(target="example.com")
        ctx.add(
            "tech_stack",
            {
                "headers": {
                    "server": "nginx/1.18.0",
                    "x-amz-request-id": "ABC123",
                    "cf-ray": "DEF456-IAD",
                    "strict-transport-security": "max-age=31536000",
                }
            },
        )
        ctx.add(
            "domain_profile",
            {
                "dns_records": {
                    "NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
                    "TXT": ["v=spf1 include:_spf.google.com ~all"],
                },
                "subdomains": ["www.example.com", "api.example.com"],
            },
        )

        result = analyze_infrastructure(ctx)
        infra = result.get("infrastructure")

        # Should detect multiple components
        assert len(infra["cloud_providers"]) >= 1
        assert len(infra["cdn_providers"]) >= 1
        assert len(infra["services"]) >= 1
        assert len(infra["security_features"]) >= 1

        # Summary should be generated
        assert infra["summary"]["infrastructure_type"] in [
            "cloud_with_cdn",
            "cloud_native",
            "cdn_fronted",
        ]
