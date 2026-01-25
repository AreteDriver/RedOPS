"""Tests for the Technology Stack Fingerprinting module."""

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
    REQUESTS_AVAILABLE,
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

    def test_detect_bootstrap(self):
        """Test detecting Bootstrap."""
        html = '<link href="bootstrap.min.css" rel="stylesheet">'
        techs = detect_technologies(html, {})
        assert "Bootstrap" in techs

    def test_detect_google_analytics(self):
        """Test detecting Google Analytics."""
        html = '<script src="https://www.google-analytics.com/analytics.js"></script>'
        techs = detect_technologies(html, {})
        assert "Google Analytics" in techs

    def test_detect_cloudflare_from_headers(self):
        """Test detecting Cloudflare from headers."""
        headers = {"cf-ray": "12345-IAD"}
        techs = detect_technologies("", headers)
        assert "Cloudflare" in techs

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


class TestFingerprint:
    """Tests for main fingerprint function."""

    def test_fingerprint_no_target(self):
        """Test fingerprinting without target."""
        ctx = Context()
        result = fingerprint(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("no target" in log["message"].lower() for log in warnings)

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not available")
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

        with patch("redops.modules.recon.tech_stack.make_request") as mock_request:
            mock_request.return_value = mock_response

            with patch(
                "redops.modules.recon.tech_stack.fetch_favicon_hash"
            ) as mock_favicon:
                mock_favicon.return_value = None

                with patch("redops.modules.recon.tech_stack.get_ssl_info") as mock_ssl:
                    mock_ssl.return_value = None

                    ctx = Context(target="example.com")
                    result = fingerprint(ctx)

                    assert "tech_stack" in result.data
                    tech_stack = result.data["tech_stack"]
                    assert "nginx" in tech_stack["web_server"]
                    assert "jQuery" in tech_stack["libraries"]

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not available")
    def test_fingerprint_missing_security_headers(self):
        """Test that missing security headers create findings."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}  # No security headers
        mock_response.text = "<html></html>"
        mock_response.content = b"<html></html>"

        with patch("redops.modules.recon.tech_stack.make_request") as mock_request:
            mock_request.return_value = mock_response

            with patch(
                "redops.modules.recon.tech_stack.fetch_favicon_hash"
            ) as mock_favicon:
                mock_favicon.return_value = None

                with patch("redops.modules.recon.tech_stack.get_ssl_info") as mock_ssl:
                    mock_ssl.return_value = None

                    ctx = Context(target="example.com")
                    result = fingerprint(ctx)

                    # Should have findings for missing security headers
                    finding_keys = [
                        k for k in result.data.keys() if k.startswith("finding_tech_")
                    ]
                    assert len(finding_keys) > 0

    def test_fingerprint_connection_error(self):
        """Test handling connection errors."""
        with patch("redops.modules.recon.tech_stack.make_request") as mock_request:
            mock_request.return_value = None

            with patch(
                "redops.modules.recon.tech_stack.fetch_favicon_hash"
            ) as mock_favicon:
                mock_favicon.return_value = None

                with patch("redops.modules.recon.tech_stack.get_ssl_info") as mock_ssl:
                    mock_ssl.return_value = None

                    ctx = Context(target="nonexistent.invalid")
                    result = fingerprint(ctx)

                    # Should still return a tech_stack, just empty
                    assert "tech_stack" in result.data

    def test_fingerprint_with_custom_params(self):
        """Test fingerprinting with custom parameters."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = ""
        mock_response.content = b""

        with patch("redops.modules.recon.tech_stack.make_request") as mock_request:
            mock_request.return_value = mock_response

            with patch(
                "redops.modules.recon.tech_stack.fetch_favicon_hash"
            ) as mock_favicon:
                mock_favicon.return_value = None

                with patch("redops.modules.recon.tech_stack.get_ssl_info") as mock_ssl:
                    mock_ssl.return_value = None

                    ctx = Context(target="default.com")
                    result = fingerprint(
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


class TestGetSslInfo:
    """Tests for SSL certificate info retrieval."""

    def test_ssl_info_invalid_host(self):
        """Test SSL info for invalid host returns None."""
        result = get_ssl_info("nonexistent.invalid")
        assert result is None

    def test_ssl_info_http_url(self):
        """Test extracting hostname from HTTP URL."""
        # This will fail to connect but tests URL parsing
        with patch("socket.create_connection") as mock_socket:
            mock_socket.side_effect = Exception("Connection failed")
            result = get_ssl_info("http://example.com")
            assert result is None

    def test_ssl_info_with_port(self):
        """Test extracting hostname when port is present."""
        with patch("socket.create_connection") as mock_socket:
            mock_socket.side_effect = Exception("Connection failed")
            result = get_ssl_info("example.com:8443")
            assert result is None


class TestLogging:
    """Tests for logging behavior."""

    def test_fingerprint_logs_start(self):
        """Test that fingerprinting logs start message."""
        with patch("redops.modules.recon.tech_stack.make_request") as mock_request:
            mock_request.return_value = None

            with patch(
                "redops.modules.recon.tech_stack.fetch_favicon_hash"
            ) as mock_favicon:
                mock_favicon.return_value = None

                with patch("redops.modules.recon.tech_stack.get_ssl_info") as mock_ssl:
                    mock_ssl.return_value = None

                    ctx = Context(target="example.com")
                    result = fingerprint(ctx)

                    info_logs = result.get_logs(level="INFO")
                    assert any(
                        "fingerprinting" in log["message"].lower() for log in info_logs
                    )

    def test_fingerprint_logs_completion(self):
        """Test that fingerprinting logs completion message."""
        with patch("redops.modules.recon.tech_stack.make_request") as mock_request:
            mock_request.return_value = None

            with patch(
                "redops.modules.recon.tech_stack.fetch_favicon_hash"
            ) as mock_favicon:
                mock_favicon.return_value = None

                with patch("redops.modules.recon.tech_stack.get_ssl_info") as mock_ssl:
                    mock_ssl.return_value = None

                    ctx = Context(target="example.com")
                    result = fingerprint(ctx)

                    info_logs = result.get_logs(level="INFO")
                    assert any(
                        "completed" in log["message"].lower() for log in info_logs
                    )
