"""Tests for the Technology Stack Fingerprinting module."""

import sys
from unittest.mock import patch, MagicMock
import pytest
from redops.core.context import Context
from redops.modules.recon.tech_stack import (
    fingerprint,
    normalize_url,
    analyze_headers,
    check_security_headers,
    detect_technologies,
    favicon_hash,
    check_version_disclosure,
    get_ssl_info,
    detect_frameworks,
    REQUESTS_AVAILABLE,
    SECURITY_HEADERS,
    TECH_PATTERNS,
    SERVER_PATTERNS,
    FAVICON_HASHES,
)


class TestNormalizeUrl:
    """Tests for URL normalization."""

    def test_normalize_domain(self):
        """Test normalizing a plain domain."""
        assert normalize_url("example.com") == "https://example.com"

    def test_normalize_https_url(self):
        """Test that HTTPS URLs are unchanged."""
        assert normalize_url("https://example.com") == "https://example.com"

    def test_normalize_http_url(self):
        """Test that HTTP URLs are unchanged."""
        assert normalize_url("http://example.com") == "http://example.com"

    def test_normalize_with_path(self):
        """Test normalizing domain with path."""
        assert normalize_url("example.com/path") == "https://example.com/path"

    def test_normalize_with_port(self):
        """Test normalizing domain with port."""
        assert normalize_url("example.com:8080") == "https://example.com:8080"

    def test_normalize_ip_address(self):
        """Test normalizing IP address."""
        assert normalize_url("192.168.1.1") == "https://192.168.1.1"


class TestAnalyzeHeaders:
    """Tests for header analysis."""

    def test_analyze_nginx_server(self):
        """Test detecting nginx server."""
        headers = {"Server": "nginx/1.18.0"}
        analysis = analyze_headers(headers)
        assert "nginx" in analysis["server"]

    def test_analyze_apache_server(self):
        """Test detecting Apache server."""
        headers = {"Server": "Apache/2.4.41"}
        analysis = analyze_headers(headers)
        assert "Apache" in analysis["server"]

    def test_analyze_cloudflare_server(self):
        """Test detecting Cloudflare."""
        headers = {"Server": "cloudflare"}
        analysis = analyze_headers(headers)
        assert "Cloudflare" in analysis["server"]

    def test_analyze_iis_server(self):
        """Test detecting IIS server."""
        headers = {"Server": "Microsoft-IIS/10.0"}
        analysis = analyze_headers(headers)
        assert "IIS" in analysis["server"]

    def test_analyze_litespeed_server(self):
        """Test detecting LiteSpeed server."""
        headers = {"Server": "LiteSpeed"}
        analysis = analyze_headers(headers)
        assert "LiteSpeed" in analysis["server"]

    def test_analyze_gunicorn_server(self):
        """Test detecting Gunicorn server."""
        headers = {"Server": "gunicorn/20.1.0"}
        analysis = analyze_headers(headers)
        assert "Gunicorn" in analysis["server"]

    def test_analyze_openresty_server(self):
        """Test detecting OpenResty server."""
        headers = {"Server": "openresty/1.19.3"}
        analysis = analyze_headers(headers)
        assert "OpenResty" in analysis["server"]

    def test_analyze_werkzeug_server(self):
        """Test detecting Werkzeug (Flask) server."""
        headers = {"Server": "Werkzeug/2.0.1"}
        analysis = analyze_headers(headers)
        assert "Werkzeug" in analysis["server"]

    def test_analyze_kestrel_server(self):
        """Test detecting Kestrel server."""
        headers = {"Server": "Kestrel"}
        analysis = analyze_headers(headers)
        assert "Kestrel" in analysis["server"]

    def test_analyze_caddy_server(self):
        """Test detecting Caddy server."""
        headers = {"Server": "Caddy"}
        analysis = analyze_headers(headers)
        assert "Caddy" in analysis["server"]

    def test_analyze_gws_server(self):
        """Test detecting Google Web Server."""
        headers = {"Server": "gws"}
        analysis = analyze_headers(headers)
        assert "Google Web Server" in analysis["server"]

    def test_analyze_uvicorn_server(self):
        """Test detecting Uvicorn server."""
        headers = {"Server": "uvicorn"}
        analysis = analyze_headers(headers)
        assert "Uvicorn" in analysis["server"]

    def test_analyze_powered_by(self):
        """Test detecting X-Powered-By header."""
        headers = {"X-Powered-By": "PHP/8.0"}
        analysis = analyze_headers(headers)
        assert analysis["powered_by"] == "PHP/8.0"

    def test_analyze_security_headers_present(self):
        """Test collecting present security headers."""
        headers = {
            "Server": "nginx",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        analysis = analyze_headers(headers)
        assert "Strict-Transport-Security" in analysis["security_headers"]
        assert "X-Content-Type-Options" in analysis["security_headers"]

    def test_analyze_unknown_server(self):
        """Test handling unknown server."""
        headers = {"Server": "CustomServer/1.0"}
        analysis = analyze_headers(headers)
        assert analysis["server"] == "CustomServer/1.0"

    def test_analyze_empty_headers(self):
        """Test handling empty headers."""
        analysis = analyze_headers({})
        assert analysis["server"] == "Unknown"
        assert analysis["powered_by"] == "Unknown"

    def test_analyze_server_without_version(self):
        """Test server without version number."""
        headers = {"Server": "nginx"}
        analysis = analyze_headers(headers)
        assert analysis["server"] == "nginx"


class TestCheckSecurityHeaders:
    """Tests for security header checking."""

    def test_all_headers_missing(self):
        """Test when all security headers are missing."""
        missing = check_security_headers({})
        assert "Strict-Transport-Security" in missing
        assert "Content-Security-Policy" in missing
        assert "X-Frame-Options" in missing

    def test_some_headers_present(self):
        """Test when some security headers are present."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        }
        missing = check_security_headers(headers)
        assert "Strict-Transport-Security" not in missing
        assert "X-Frame-Options" not in missing
        assert "Content-Security-Policy" in missing

    def test_all_headers_present(self):
        """Test when all security headers are present."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }
        missing = check_security_headers(headers)
        assert len(missing) == 0

    def test_case_insensitive(self):
        """Test that header check is case-insensitive."""
        headers = {"strict-transport-security": "max-age=31536000"}
        missing = check_security_headers(headers)
        assert "Strict-Transport-Security" not in missing


class TestDetectTechnologies:
    """Tests for technology detection from HTML."""

    def test_detect_react(self):
        """Test detecting React."""
        html = '<div id="root" data-reactroot></div>'
        techs = detect_technologies(html, {})
        assert "React" in techs

    def test_detect_react_devtools(self):
        """Test detecting React via devtools marker."""
        html = '<script>window.__REACT_DEVTOOLS_GLOBAL_HOOK__</script>'
        techs = detect_technologies(html, {})
        assert "React" in techs

    def test_detect_vue(self):
        """Test detecting Vue.js."""
        html = '<div data-v-123abc class="app"></div>'
        techs = detect_technologies(html, {})
        assert "Vue.js" in techs

    def test_detect_angular(self):
        """Test detecting Angular."""
        html = '<app-root ng-version="12.0.0"></app-root>'
        techs = detect_technologies(html, {})
        assert "Angular" in techs

    def test_detect_angular_ng_app(self):
        """Test detecting Angular via ng-app."""
        html = '<html ng-app="myApp"></html>'
        techs = detect_technologies(html, {})
        assert "Angular" in techs

    def test_detect_jquery(self):
        """Test detecting jQuery."""
        html = '<script src="jquery.min.js"></script>'
        techs = detect_technologies(html, {})
        assert "jQuery" in techs

    def test_detect_wordpress(self):
        """Test detecting WordPress."""
        html = '<link rel="stylesheet" href="/wp-content/themes/theme/style.css">'
        techs = detect_technologies(html, {})
        assert "WordPress" in techs

    def test_detect_wordpress_generator(self):
        """Test detecting WordPress via generator meta."""
        html = '<meta name="generator" content="WordPress 5.9">'
        techs = detect_technologies(html, {})
        assert "WordPress" in techs

    def test_detect_drupal(self):
        """Test detecting Drupal."""
        html = '<script>Drupal.settings.basePath</script>'
        techs = detect_technologies(html, {})
        assert "Drupal" in techs

    def test_detect_joomla(self):
        """Test detecting Joomla."""
        html = '<meta name="generator" content="Joomla! - Open Source">'
        techs = detect_technologies(html, {})
        assert "Joomla" in techs

    def test_detect_shopify(self):
        """Test detecting Shopify."""
        html = '<script src="//cdn.shopify.com/s/files/1/theme.js"></script>'
        techs = detect_technologies(html, {})
        assert "Shopify" in techs

    def test_detect_bootstrap(self):
        """Test detecting Bootstrap."""
        html = '<link href="bootstrap.min.css" rel="stylesheet">'
        techs = detect_technologies(html, {})
        assert "Bootstrap" in techs

    def test_detect_tailwind(self):
        """Test detecting Tailwind CSS."""
        html = '<div class="flex p-4 m-2 text-lg"></div>'
        techs = detect_technologies(html, {})
        assert "Tailwind CSS" in techs

    def test_detect_django(self):
        """Test detecting Django."""
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
        techs = detect_technologies(html, {})
        assert "Django" in techs

    def test_detect_rails(self):
        """Test detecting Ruby on Rails."""
        html = '<meta name="csrf-token" content="abc123"><script src="rails-ujs"></script>'
        techs = detect_technologies(html, {})
        assert "Ruby on Rails" in techs

    def test_detect_laravel(self):
        """Test detecting Laravel."""
        html = '<meta name="csrf-token" content="abc"><input name="XSRF-TOKEN">'
        # Check cookies header
        headers = {"Set-Cookie": "laravel_session=abc123"}
        techs = detect_technologies(html, headers)
        assert "Laravel" in techs

    def test_detect_aspnet(self):
        """Test detecting ASP.NET."""
        html = '<input type="hidden" name="__VIEWSTATE" value="abc">'
        techs = detect_technologies(html, {})
        assert "ASP.NET" in techs

    def test_detect_google_analytics(self):
        """Test detecting Google Analytics."""
        html = '<script src="https://www.google-analytics.com/analytics.js"></script>'
        techs = detect_technologies(html, {})
        assert "Google Analytics" in techs

    def test_detect_google_tag_manager(self):
        """Test detecting Google Tag Manager."""
        html = '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC123"></script>'
        techs = detect_technologies(html, {})
        assert "Google Tag Manager" in techs

    def test_detect_facebook_pixel(self):
        """Test detecting Facebook Pixel."""
        html = '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>'
        techs = detect_technologies(html, {})
        assert "Facebook Pixel" in techs

    def test_detect_cloudflare_from_headers(self):
        """Test detecting Cloudflare from headers."""
        headers = {"cf-ray": "12345-IAD"}
        techs = detect_technologies("", headers)
        assert "Cloudflare" in techs

    def test_detect_fastly_from_headers(self):
        """Test detecting Fastly from headers."""
        headers = {"X-Served-By": "cache-iad-kiad7000042-IAD"}
        techs = detect_technologies("", headers)
        assert "Fastly" in techs

    def test_detect_akamai_from_headers(self):
        """Test detecting Akamai from headers."""
        headers = {"X-Akamai-Transformed": "9 - 0"}
        techs = detect_technologies("", headers)
        assert "Akamai" in techs

    def test_detect_express_from_headers(self):
        """Test detecting Express.js from headers."""
        headers = {"X-Powered-By": "Express"}
        techs = detect_technologies("", headers)
        assert "Express.js" in techs

    def test_detect_multiple_technologies(self):
        """Test detecting multiple technologies."""
        html = """
        <script src="react.js"></script>
        <script src="jquery.min.js"></script>
        <link href="bootstrap.css">
        """
        techs = detect_technologies(html, {})
        assert "React" in techs
        assert "jQuery" in techs
        assert "Bootstrap" in techs

    def test_no_technologies(self):
        """Test when no technologies are detected."""
        html = "<html><body>Hello World</body></html>"
        techs = detect_technologies(html, {})
        assert len(techs) == 0


class TestDetectFrameworks:
    """Tests for the detect_frameworks wrapper function."""

    def test_detect_frameworks_is_alias(self):
        """Test that detect_frameworks is an alias for detect_technologies."""
        html = '<script src="react.js"></script>'
        result1 = detect_technologies(html, {})
        result2 = detect_frameworks(html, {})
        assert result1 == result2

    def test_detect_frameworks_with_headers(self):
        """Test detect_frameworks with headers."""
        headers = {"X-Powered-By": "Express"}
        techs = detect_frameworks("", headers)
        assert "Express.js" in techs


class TestFaviconHash:
    """Tests for favicon hashing."""

    def test_favicon_hash_calculation(self):
        """Test that favicon hash is calculated correctly."""
        test_bytes = b"test favicon content"
        hash_result = favicon_hash(test_bytes)
        assert len(hash_result) == 32  # MD5 hex length
        assert hash_result.isalnum()

    def test_favicon_hash_consistency(self):
        """Test that same content produces same hash."""
        content = b"same content"
        assert favicon_hash(content) == favicon_hash(content)

    def test_favicon_hash_different_content(self):
        """Test that different content produces different hash."""
        assert favicon_hash(b"content1") != favicon_hash(b"content2")

    def test_favicon_hash_empty(self):
        """Test hashing empty bytes."""
        hash_result = favicon_hash(b"")
        assert len(hash_result) == 32


class TestVersionDisclosure:
    """Tests for version disclosure detection."""

    def test_server_version_disclosure(self):
        """Test detecting server version disclosure."""
        disclosed = check_version_disclosure({}, "nginx/1.18.0")
        assert any("nginx/1.18.0" in d for d in disclosed)

    def test_no_version_disclosure(self):
        """Test when no version is disclosed."""
        disclosed = check_version_disclosure({}, "nginx")
        assert len(disclosed) == 0

    def test_no_server_no_disclosure(self):
        """Test when no server is provided."""
        disclosed = check_version_disclosure({}, None)
        assert len(disclosed) == 0

    def test_powered_by_disclosure(self):
        """Test detecting X-Powered-By disclosure."""
        headers = {"X-Powered-By": "PHP/8.0"}
        disclosed = check_version_disclosure(headers, None)
        assert any("PHP/8.0" in d for d in disclosed)

    def test_aspnet_version_disclosure(self):
        """Test detecting ASP.NET version disclosure."""
        headers = {"X-AspNet-Version": "4.0.30319"}
        disclosed = check_version_disclosure(headers, None)
        assert any("4.0.30319" in d for d in disclosed)

    def test_aspnetmvc_version_disclosure(self):
        """Test detecting ASP.NET MVC version disclosure."""
        headers = {"X-AspNetMvc-Version": "5.2"}
        disclosed = check_version_disclosure(headers, None)
        assert any("5.2" in d for d in disclosed)

    def test_multiple_disclosures(self):
        """Test multiple version disclosures."""
        headers = {
            "X-Powered-By": "PHP/8.0",
            "X-AspNet-Version": "4.0",
        }
        disclosed = check_version_disclosure(headers, "nginx/1.18.0")
        assert len(disclosed) == 3


class TestFingerprint:
    """Tests for main fingerprint function."""

    def test_fingerprint_no_target(self):
        """Test fingerprinting without target."""
        ctx = Context()
        result = fingerprint(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("no target" in log["message"].lower() for log in warnings)

    def test_fingerprint_requests_not_available(self):
        """Test fingerprinting when requests not available."""
        import redops.modules.recon.tech_stack as ts_module
        original_available = ts_module.REQUESTS_AVAILABLE

        ts_module.REQUESTS_AVAILABLE = False
        try:
            ctx = Context(target="example.com")
            result = fingerprint(ctx)

            assert "tech_stack" in result.data
            warnings = result.get_logs(level="WARNING")
            assert any("requests" in log["message"].lower() for log in warnings)
        finally:
            ts_module.REQUESTS_AVAILABLE = original_available


class TestFingerprintWithMockedRequests:
    """Tests for fingerprint function with mocked requests."""

    @pytest.fixture(autouse=True)
    def setup_requests_mock(self):
        """Setup mock requests module."""
        self.mock_requests = MagicMock()

        # Patch the module to have requests available
        with patch.dict(sys.modules, {'requests': self.mock_requests}):
            import redops.modules.recon.tech_stack as ts_module
            self.original_available = ts_module.REQUESTS_AVAILABLE
            ts_module.REQUESTS_AVAILABLE = True
            ts_module.requests = self.mock_requests

            # Create mock exceptions
            self.mock_requests.exceptions = MagicMock()
            self.mock_requests.exceptions.RequestException = Exception
            self.mock_requests.exceptions.SSLError = type('SSLError', (Exception,), {})
            self.mock_requests.exceptions.Timeout = type('Timeout', (Exception,), {})

            self.ts_module = ts_module
            yield

            # Restore
            ts_module.REQUESTS_AVAILABLE = self.original_available

    def test_fingerprint_with_mock_response(self):
        """Test fingerprinting with mocked HTTP response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/8.0",
            "Content-Type": "text/html",
        }
        mock_response.text = '<script src="jquery.min.js"></script>'
        mock_response.content = b"<html></html>"

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    assert "tech_stack" in result.data
                    tech_stack = result.data["tech_stack"]
                    assert "nginx" in tech_stack["web_server"]
                    assert "jQuery" in tech_stack["libraries"]

    def test_fingerprint_missing_security_headers(self):
        """Test that missing security headers create findings."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}  # No security headers
        mock_response.text = "<html></html>"
        mock_response.content = b"<html></html>"

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    # Should have findings for missing security headers
                    finding_keys = [
                        k for k in result.data.keys() if k.startswith("finding_tech_")
                    ]
                    assert len(finding_keys) > 0

    def test_fingerprint_connection_error(self):
        """Test handling connection errors."""
        with patch.object(self.ts_module, 'make_request', return_value=None):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="nonexistent.invalid")
                    result = self.ts_module.fingerprint(ctx)

                    # Should still return a tech_stack, just empty
                    assert "tech_stack" in result.data

    def test_fingerprint_with_custom_params(self):
        """Test fingerprinting with custom parameters."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.content = b""

        with patch.object(self.ts_module, 'make_request', return_value=mock_response) as mock_req:
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="default.com")
                    result = self.ts_module.fingerprint(
                        ctx,
                        params={
                            "target": "custom.com",
                            "timeout": 5,
                            "verify_ssl": False,
                        },
                    )

                    # Should have used custom target
                    info_logs = result.get_logs(level="INFO")
                    assert any("custom.com" in log["message"] for log in info_logs)

    def test_fingerprint_logs_start_and_completion(self):
        """Test that fingerprinting logs start and completion messages."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.content = b""

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    info_logs = result.get_logs(level="INFO")
                    assert any("fingerprinting" in log["message"].lower() for log in info_logs)
                    assert any("completed" in log["message"].lower() for log in info_logs)

    def test_fingerprint_with_favicon_detection(self):
        """Test fingerprinting with successful favicon detection."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "Apache"}
        mock_response.text = ""
        mock_response.content = b""

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=("abc123", "Apache Default")):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    tech_stack = result.data["tech_stack"]
                    assert tech_stack["fingerprints"]["favicon_hash"] == "abc123"
                    assert "Apache Default" in tech_stack["libraries"]

    def test_fingerprint_with_ssl_info(self):
        """Test fingerprinting with SSL certificate info."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.content = b""

        ssl_info = {
            "issuer": "Let's Encrypt",
            "subject": "example.com",
            "not_after": "2025-01-01",
        }

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=ssl_info):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    tech_stack = result.data["tech_stack"]
                    assert tech_stack["fingerprints"]["ssl"]["issuer"] == "Let's Encrypt"

    def test_fingerprint_with_frameworks_detected(self):
        """Test fingerprinting with frameworks in HTML."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = '<script src="react.js"></script><div data-reactroot></div>'
        mock_response.content = b"<html></html>"

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    tech_stack = result.data["tech_stack"]
                    assert "React" in tech_stack["frameworks"]

    def test_fingerprint_with_version_disclosure(self):
        """Test fingerprinting detects version disclosure."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/8.0",
        }
        mock_response.text = ""
        mock_response.content = b""

        with patch.object(self.ts_module, 'make_request', return_value=mock_response):
            with patch.object(self.ts_module, 'fetch_favicon_hash', return_value=None):
                with patch.object(self.ts_module, 'get_ssl_info', return_value=None):
                    ctx = Context(target="example.com")
                    result = self.ts_module.fingerprint(ctx)

                    # Should have a version disclosure finding
                    finding_keys = [k for k in result.data.keys() if "finding" in k]
                    has_version_finding = any(
                        "version" in result.data[k].get("title", "").lower()
                        for k in finding_keys
                    )
                    assert has_version_finding


class TestMakeRequest:
    """Tests for make_request function."""

    @pytest.fixture(autouse=True)
    def setup_requests_mock(self):
        """Setup mock requests module."""
        self.mock_requests = MagicMock()

        with patch.dict(sys.modules, {'requests': self.mock_requests}):
            import redops.modules.recon.tech_stack as ts_module
            self.original_available = ts_module.REQUESTS_AVAILABLE
            ts_module.REQUESTS_AVAILABLE = True
            ts_module.requests = self.mock_requests
            self.ts_module = ts_module
            yield
            ts_module.REQUESTS_AVAILABLE = self.original_available

    def test_make_request_success(self):
        """Test successful HTTP request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        self.mock_requests.get.return_value = mock_response

        result = self.ts_module.make_request("https://example.com")
        assert result is not None
        self.mock_requests.get.assert_called_once()

    def test_make_request_with_params(self):
        """Test request with custom parameters."""
        mock_response = MagicMock()
        self.mock_requests.get.return_value = mock_response

        self.ts_module.make_request(
            "https://example.com",
            timeout=5,
            follow_redirects=False,
            verify_ssl=False
        )

        self.mock_requests.get.assert_called_once()
        call_kwargs = self.mock_requests.get.call_args[1]
        assert call_kwargs["timeout"] == 5
        assert call_kwargs["allow_redirects"] is False
        assert call_kwargs["verify"] is False

    def test_make_request_https_fails_tries_http(self):
        """Test that HTTPS failure falls back to HTTP."""
        # First call (HTTPS) fails, second call (HTTP) succeeds
        mock_response = MagicMock()
        self.mock_requests.get.side_effect = [Exception("SSL Error"), mock_response]

        result = self.ts_module.make_request("https://example.com")

        assert result == mock_response
        assert self.mock_requests.get.call_count == 2

    def test_make_request_both_fail(self):
        """Test when both HTTPS and HTTP fail."""
        self.mock_requests.get.side_effect = Exception("Connection failed")

        result = self.ts_module.make_request("https://example.com")
        assert result is None

    def test_make_request_http_url_no_fallback(self):
        """Test HTTP URL doesn't trigger HTTPS fallback."""
        self.mock_requests.get.side_effect = Exception("Connection failed")

        result = self.ts_module.make_request("http://example.com")
        assert result is None
        # Should only try once since it's already HTTP
        assert self.mock_requests.get.call_count == 1

    def test_make_request_not_available(self):
        """Test make_request when requests not available."""
        self.ts_module.REQUESTS_AVAILABLE = False
        result = self.ts_module.make_request("https://example.com")
        assert result is None


class TestFetchFaviconHash:
    """Tests for fetch_favicon_hash function."""

    @pytest.fixture(autouse=True)
    def setup_requests_mock(self):
        """Setup mock requests module."""
        self.mock_requests = MagicMock()

        with patch.dict(sys.modules, {'requests': self.mock_requests}):
            import redops.modules.recon.tech_stack as ts_module
            self.original_available = ts_module.REQUESTS_AVAILABLE
            ts_module.REQUESTS_AVAILABLE = True
            ts_module.requests = self.mock_requests
            self.ts_module = ts_module
            yield
            ts_module.REQUESTS_AVAILABLE = self.original_available

    def test_fetch_favicon_success(self):
        """Test successful favicon fetch."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"favicon content"
        self.mock_requests.get.return_value = mock_response

        result = self.ts_module.fetch_favicon_hash("https://example.com")

        assert result is not None
        hash_value, tech = result
        assert len(hash_value) == 32  # MD5 hex
        assert tech is None  # Unknown favicon

    def test_fetch_favicon_known_hash(self):
        """Test favicon matches known hash."""
        # Use content that produces a known hash
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"test"
        self.mock_requests.get.return_value = mock_response

        # Patch FAVICON_HASHES to include our test hash
        test_hash = self.ts_module.favicon_hash(b"test")
        with patch.dict(self.ts_module.FAVICON_HASHES, {test_hash: "Test Technology"}):
            result = self.ts_module.fetch_favicon_hash("https://example.com")

            assert result is not None
            hash_value, tech = result
            assert tech == "Test Technology"

    def test_fetch_favicon_404(self):
        """Test favicon not found."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.content = b""
        self.mock_requests.get.return_value = mock_response

        result = self.ts_module.fetch_favicon_hash("https://example.com")
        assert result is None

    def test_fetch_favicon_empty_content(self):
        """Test favicon with empty content."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b""
        self.mock_requests.get.return_value = mock_response

        result = self.ts_module.fetch_favicon_hash("https://example.com")
        assert result is None

    def test_fetch_favicon_exception(self):
        """Test favicon fetch with exception."""
        self.mock_requests.get.side_effect = Exception("Connection error")

        result = self.ts_module.fetch_favicon_hash("https://example.com")
        assert result is None

    def test_fetch_favicon_not_available(self):
        """Test fetch_favicon_hash when requests not available."""
        self.ts_module.REQUESTS_AVAILABLE = False
        result = self.ts_module.fetch_favicon_hash("https://example.com")
        assert result is None

    def test_fetch_favicon_tries_multiple_urls(self):
        """Test that favicon fetch tries both .ico and .png."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        self.mock_requests.get.return_value = mock_response

        self.ts_module.fetch_favicon_hash("https://example.com")

        # Should try both favicon.ico and favicon.png
        assert self.mock_requests.get.call_count == 2


class TestGetSslInfo:
    """Tests for SSL certificate info retrieval."""

    def test_ssl_info_invalid_host(self):
        """Test SSL info for invalid host returns None."""
        result = get_ssl_info("nonexistent.invalid")
        assert result is None

    def test_ssl_info_http_url(self):
        """Test extracting hostname from HTTP URL."""
        with patch("socket.create_connection") as mock_socket:
            mock_socket.side_effect = Exception("Connection failed")
            result = get_ssl_info("http://example.com")
            assert result is None

    def test_ssl_info_https_url(self):
        """Test extracting hostname from HTTPS URL."""
        with patch("socket.create_connection") as mock_socket:
            mock_socket.side_effect = Exception("Connection failed")
            result = get_ssl_info("https://example.com")
            assert result is None

    def test_ssl_info_with_port(self):
        """Test extracting hostname when port is present."""
        with patch("socket.create_connection") as mock_socket:
            mock_socket.side_effect = Exception("Connection failed")
            result = get_ssl_info("example.com:8443")
            assert result is None

    def test_ssl_info_success(self):
        """Test successful SSL info retrieval."""
        mock_cert = {
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Apr  1 00:00:00 2024 GMT",
            "serialNumber": "ABC123",
            "version": 3,
        }

        with patch("socket.create_connection") as mock_socket:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = mock_cert

            mock_context = MagicMock()
            mock_context.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            mock_context.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_socket.return_value = mock_sock

            with patch("ssl.create_default_context", return_value=mock_context):
                result = get_ssl_info("example.com")

                assert result is not None
                assert result["issuer"] == "Let's Encrypt"
                assert result["subject"] == "example.com"


class TestConstants:
    """Tests for module constants."""

    def test_security_headers_defined(self):
        """Test that security headers are defined."""
        assert "Strict-Transport-Security" in SECURITY_HEADERS
        assert "Content-Security-Policy" in SECURITY_HEADERS
        assert "X-Frame-Options" in SECURITY_HEADERS

    def test_tech_patterns_defined(self):
        """Test that technology patterns are defined."""
        assert "React" in TECH_PATTERNS
        assert "Vue.js" in TECH_PATTERNS
        assert "Angular" in TECH_PATTERNS
        assert "WordPress" in TECH_PATTERNS

    def test_server_patterns_defined(self):
        """Test that server patterns are defined."""
        assert len(SERVER_PATTERNS) > 0

    def test_favicon_hashes_defined(self):
        """Test that favicon hashes are defined."""
        assert len(FAVICON_HASHES) > 0
