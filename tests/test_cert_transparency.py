"""Tests for the Certificate Transparency module."""

from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from redops.core.context import Context
from redops.modules.recon.cert_transparency import (
    search_ct_logs,
    query_crtsh,
    is_cert_valid,
    extract_subdomains_from_certs,
    parse_cert_name,
    analyze_certificates,
    get_ct_summary,
)


class TestSearchCtLogs:
    """Tests for search_ct_logs function."""

    def test_no_requests_library(self):
        """Test handling when requests library not available."""
        with patch("redops.modules.recon.cert_transparency.HAS_REQUESTS", False):
            ctx = Context(target="example.com")
            result = search_ct_logs(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("requests library" in log["message"] for log in warnings)

    def test_no_domain(self):
        """Test handling when no domain specified."""
        ctx = Context()
        result = search_ct_logs(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No domain" in log["message"] for log in warnings)

    @patch("redops.modules.recon.cert_transparency.query_crtsh")
    def test_no_certificates_found(self, mock_query):
        """Test handling when no certificates found."""
        mock_query.return_value = []

        ctx = Context(target="nonexistent-domain-12345.com")
        result = search_ct_logs(ctx)

        assert "ct_results" in result.data
        assert result.data["ct_results"]["certificates"] == []

    @patch("redops.modules.recon.cert_transparency.query_crtsh")
    def test_successful_search(self, mock_query):
        """Test successful CT log search."""
        mock_query.return_value = [
            {
                "common_name": "www.example.com",
                "name_value": "www.example.com\napi.example.com",
                "issuer_name": "Let's Encrypt",
                "not_after": (datetime.now() + timedelta(days=90)).isoformat(),
            }
        ]

        ctx = Context(target="example.com")
        result = search_ct_logs(ctx)

        assert "ct_results" in result.data
        assert "ct_subdomains" in result.data
        assert len(result.data["ct_subdomains"]) >= 1

    @patch("redops.modules.recon.cert_transparency.query_crtsh")
    def test_deduplication(self, mock_query):
        """Test subdomain deduplication."""
        mock_query.return_value = [
            {"common_name": "www.example.com", "name_value": "www.example.com"},
            {"common_name": "www.example.com", "name_value": "www.example.com"},
        ]

        ctx = Context(target="example.com")
        result = search_ct_logs(ctx, {"deduplicate": True})

        # Should only have one entry for www.example.com
        subdomains = result.data["ct_subdomains"]
        assert subdomains.count("www.example.com") == 1


class TestQueryCrtsh:
    """Tests for query_crtsh function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.recon.cert_transparency.HAS_REQUESTS", False):
            result = query_crtsh("example.com")
            assert result == []

    @patch("redops.modules.recon.cert_transparency.requests")
    def test_timeout(self, mock_requests):
        """Test timeout handling."""
        import requests

        mock_requests.get.side_effect = requests.exceptions.Timeout()
        mock_requests.exceptions = requests.exceptions

        result = query_crtsh("example.com")
        assert result == []

    @patch("redops.modules.recon.cert_transparency.requests")
    def test_request_error(self, mock_requests):
        """Test request error handling."""
        import requests

        mock_requests.get.side_effect = requests.exceptions.RequestException()
        mock_requests.exceptions = requests.exceptions

        result = query_crtsh("example.com")
        assert result == []

    @patch("redops.modules.recon.cert_transparency.requests")
    def test_json_error(self, mock_requests):
        """Test JSON decode error handling."""
        import requests as real_requests

        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_requests.get.return_value = mock_response
        mock_requests.exceptions = real_requests.exceptions

        result = query_crtsh("example.com")
        assert result == []

    @patch("redops.modules.recon.cert_transparency.requests")
    def test_filter_expired(self, mock_requests):
        """Test filtering expired certificates."""
        past = (datetime.now() - timedelta(days=30)).isoformat()
        future = (datetime.now() + timedelta(days=30)).isoformat()

        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"common_name": "expired.example.com", "not_after": past},
            {"common_name": "valid.example.com", "not_after": future},
        ]
        mock_requests.get.return_value = mock_response

        result = query_crtsh("example.com", include_expired=False)
        assert len(result) == 1


class TestIsCertValid:
    """Tests for is_cert_valid function."""

    def test_valid_certificate(self):
        """Test valid certificate."""
        future = (datetime.now() + timedelta(days=30)).isoformat()
        cert = {"not_after": future}
        assert is_cert_valid(cert, datetime.now()) is True

    def test_expired_certificate(self):
        """Test expired certificate."""
        past = (datetime.now() - timedelta(days=30)).isoformat()
        cert = {"not_after": past}
        assert is_cert_valid(cert, datetime.now()) is False

    def test_no_expiry(self):
        """Test certificate with no expiry."""
        cert = {}
        assert is_cert_valid(cert, datetime.now()) is True

    def test_invalid_date(self):
        """Test certificate with invalid date."""
        cert = {"not_after": "invalid-date"}
        assert is_cert_valid(cert, datetime.now()) is True


class TestExtractSubdomainsFromCerts:
    """Tests for extract_subdomains_from_certs function."""

    def test_extract_from_common_name(self):
        """Test extraction from common name."""
        certs = [{"common_name": "www.example.com"}]
        result = extract_subdomains_from_certs(certs, "example.com")
        assert "www.example.com" in result

    def test_extract_from_san(self):
        """Test extraction from SANs."""
        certs = [{"name_value": "api.example.com\nwww.example.com"}]
        result = extract_subdomains_from_certs(certs, "example.com")
        assert "api.example.com" in result
        assert "www.example.com" in result

    def test_filter_other_domains(self):
        """Test filtering out other domains."""
        certs = [{"common_name": "www.other.com"}]
        result = extract_subdomains_from_certs(certs, "example.com")
        assert "www.other.com" not in result

    def test_handle_wildcards(self):
        """Test handling wildcard certificates."""
        certs = [{"common_name": "*.example.com"}]
        result = extract_subdomains_from_certs(certs, "example.com")
        assert "example.com" in result


class TestParseCertName:
    """Tests for parse_cert_name function."""

    def test_simple_subdomain(self):
        """Test parsing simple subdomain."""
        result = parse_cert_name("www.example.com", "example.com")
        assert "www.example.com" in result

    def test_wildcard(self):
        """Test parsing wildcard name."""
        result = parse_cert_name("*.example.com", "example.com")
        assert "example.com" in result

    def test_different_domain(self):
        """Test parsing name from different domain."""
        result = parse_cert_name("www.other.com", "example.com")
        assert len(result) == 0

    def test_invalid_format(self):
        """Test parsing invalid name format."""
        result = parse_cert_name("not a valid domain!", "example.com")
        assert len(result) == 0


class TestAnalyzeCertificates:
    """Tests for analyze_certificates function."""

    def test_expired_certificates(self):
        """Test finding expired certificates."""
        past = (datetime.now() - timedelta(days=30)).isoformat()
        certs = [{"not_after": past, "issuer_name": "Test CA"}]

        findings = analyze_certificates(certs, "example.com")
        assert any("Expired" in f.title for f in findings)

    def test_expiring_soon(self):
        """Test finding certificates expiring soon."""
        soon = (datetime.now() + timedelta(days=15)).isoformat()
        certs = [{"not_after": soon, "issuer_name": "Test CA"}]

        findings = analyze_certificates(certs, "example.com")
        assert any("Expiring Soon" in f.title for f in findings)

    def test_wildcard_certificates(self):
        """Test finding many wildcard certificates."""
        certs = [
            {"common_name": f"*.example{i}.com", "issuer_name": "CA"} for i in range(10)
        ]

        findings = analyze_certificates(certs, "example.com")
        assert any("Wildcard" in f.title for f in findings)

    def test_multiple_issuers(self):
        """Test finding multiple certificate issuers."""
        certs = [{"issuer_name": f"CA {i}"} for i in range(10)]

        findings = analyze_certificates(certs, "example.com")
        assert any("Issuers" in f.title for f in findings)


class TestGetCtSummary:
    """Tests for get_ct_summary function."""

    def test_with_results(self):
        """Test summary with results."""
        ctx = Context()
        ctx.add(
            "ct_results",
            {
                "domain": "example.com",
                "total_certificates": 50,
                "subdomains": ["www.example.com", "api.example.com"],
                "search_timestamp": "2024-01-01T00:00:00",
            },
        )

        summary = get_ct_summary(ctx)

        assert summary["domain"] == "example.com"
        assert summary["total_certificates"] == 50
        assert summary["unique_subdomains"] == 2

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_ct_summary(ctx)

        assert summary["domain"] == ""
        assert summary["total_certificates"] == 0
