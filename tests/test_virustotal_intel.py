"""Tests for VirusTotal intelligence module."""

import socket
import sys
from importlib import reload
from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.intel.virustotal_intel import (
    query_vt_domain,
    query_vt_ip,
    query_vt_url,
    analyze_virustotal_intel,
    _is_ip,
    _extract_domain,
    VTDomainReport,
    VTIPReport,
    VTURLReport,
)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_is_ip_valid(self):
        """Test valid IP detection."""
        assert _is_ip("192.168.1.1") is True
        assert _is_ip("10.0.0.1") is True
        assert _is_ip("8.8.8.8") is True

    def test_is_ip_invalid(self):
        """Test invalid IP detection."""
        assert _is_ip("example.com") is False
        assert _is_ip("192.168.1") is False
        assert _is_ip("not.an.ip.address.really") is False

    def test_extract_domain(self):
        """Test domain extraction."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.example.com:8080/") == "sub.example.com"
        assert _extract_domain("example.com") == "example.com"


class TestVTDataclasses:
    """Tests for VirusTotal dataclasses."""

    def test_vt_domain_report_to_dict(self):
        """Test VTDomainReport serialization."""
        report = VTDomainReport(
            domain="example.com",
            reputation=0,
            categories={"Forcepoint ThreatSeeker": "information technology"},
            last_analysis_stats={"malicious": 0, "suspicious": 1, "harmless": 70},
        )
        result = report.to_dict()

        assert result["domain"] == "example.com"
        assert result["reputation"] == 0
        assert "Forcepoint ThreatSeeker" in result["categories"]
        assert result["last_analysis_stats"]["harmless"] == 70

    def test_vt_ip_report_to_dict(self):
        """Test VTIPReport serialization."""
        report = VTIPReport(
            ip="8.8.8.8",
            reputation=0,
            country="US",
            asn=15169,
            as_owner="GOOGLE",
            last_analysis_stats={"malicious": 0, "suspicious": 0, "harmless": 90},
        )
        result = report.to_dict()

        assert result["ip"] == "8.8.8.8"
        assert result["country"] == "US"
        assert result["asn"] == 15169
        assert result["as_owner"] == "GOOGLE"

    def test_vt_url_report_to_dict(self):
        """Test VTURLReport serialization."""
        report = VTURLReport(
            url="https://example.com/test",
            reputation=0,
            last_analysis_stats={"malicious": 2, "suspicious": 1},
            threat_names=["phishing", "malware"],
        )
        result = report.to_dict()

        assert result["url"] == "https://example.com/test"
        assert result["last_analysis_stats"]["malicious"] == 2
        assert "phishing" in result["threat_names"]


class TestQueryVTDomain:
    """Tests for query_vt_domain."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_vt_domain(ctx)

        assert "virustotal_domain" not in result.data

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key", return_value=None
        ):
            result = query_vt_domain(ctx)

        data = result.get("virustotal_domain")
        assert data is not None
        assert "not configured" in data["error"]

    def test_successful_domain_query(self):
        """Test successful domain query."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "categories": {"vendor": "tech"},
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 85,
                    },
                    "registrar": "Example Registrar",
                    "creation_date": "1995-08-14",
                }
            }
        }

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=mock_response,
            ):
                result = query_vt_domain(ctx)

        data = result.get("virustotal_domain")
        assert data is not None
        assert data["error"] is None
        assert data["report"]["domain"] == "example.com"
        assert data["report"]["last_analysis_stats"]["harmless"] == 85

    def test_not_found(self):
        """Test domain not found."""
        ctx = Context(target="nonexistent.invalid")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value={"error": "not_found"},
            ):
                result = query_vt_domain(ctx)

        data = result.get("virustotal_domain")
        assert data["error"] == "not_found"


class TestQueryVTIP:
    """Tests for query_vt_ip."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_vt_ip(ctx)

        assert "virustotal_ip" not in result.data

    def test_successful_ip_query(self):
        """Test successful IP query."""
        ctx = Context(target="8.8.8.8")

        mock_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "country": "US",
                    "asn": 15169,
                    "as_owner": "GOOGLE",
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 90,
                    },
                }
            }
        }

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=mock_response,
            ):
                result = query_vt_ip(ctx)

        data = result.get("virustotal_ip")
        assert data is not None
        assert data["error"] is None
        assert data["report"]["ip"] == "8.8.8.8"
        assert data["report"]["country"] == "US"

    def test_domain_resolution(self):
        """Test domain to IP resolution."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "country": "US",
                    "last_analysis_stats": {"malicious": 0},
                }
            }
        }

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=mock_response,
            ):
                with patch("socket.gethostbyname", return_value="93.184.216.34"):
                    result = query_vt_ip(ctx)

        data = result.get("virustotal_ip")
        assert data["report"]["ip"] == "93.184.216.34"


class TestQueryVTURL:
    """Tests for query_vt_url."""

    def test_no_url(self):
        """Test with no URL and no target."""
        ctx = Context(target=None)
        result = query_vt_url(ctx)

        assert "virustotal_url" not in result.data

    def test_build_url_from_target(self):
        """Test URL building from target."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                }
            }
        }

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=mock_response,
            ):
                result = query_vt_url(ctx)

        data = result.get("virustotal_url")
        assert data is not None
        assert data["url"] == "https://example.com"

    def test_url_not_scanned(self):
        """Test URL not previously scanned."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value={"error": "not_found"},
            ):
                result = query_vt_url(ctx)

        data = result.get("virustotal_url")
        assert "not previously scanned" in data["error"]


class TestAnalyzeVirusTotalIntel:
    """Tests for analyze_virustotal_intel."""

    def test_comprehensive_analysis(self):
        """Test comprehensive VirusTotal analysis."""
        ctx = Context(target="example.com")

        domain_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 2,
                        "harmless": 80,
                    },
                }
            }
        }

        ip_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "country": "US",
                    "asn": 12345,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 1,
                        "harmless": 90,
                    },
                }
            }
        }

        def mock_request(endpoint, api_key):
            if "domains" in endpoint:
                return domain_response
            elif "ip_addresses" in endpoint:
                return ip_response
            return {"error": "unknown"}

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                side_effect=mock_request,
            ):
                with patch("socket.gethostbyname", return_value="93.184.216.34"):
                    result = analyze_virustotal_intel(ctx)

        intel = result.get("virustotal_intel")
        assert intel is not None
        assert intel["summary"]["total_malicious"] == 1  # from domain only (IP has 0)
        assert intel["summary"]["total_suspicious"] == 3  # 2 from domain + 1 from IP
        assert intel["summary"]["is_malicious"] is True

    def test_no_api_key(self):
        """Test analysis without API key."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key", return_value=None
        ):
            result = analyze_virustotal_intel(ctx)

        intel = result.get("virustotal_intel")
        assert intel is not None
        assert intel["domain"]["error"] is not None


class TestGetVTApiKey:
    """Tests for get_vt_api_key function."""

    def test_api_key_from_env(self):
        """Test API key loaded from environment."""
        from redops.modules.intel.virustotal_intel import get_vt_api_key

        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "env-api-key"}):
            result = get_vt_api_key()
            assert result == "env-api-key"

    def test_api_key_from_settings_fallback(self):
        """Test API key loaded from settings when env not set."""
        from redops.modules.intel.virustotal_intel import get_vt_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "redops.cli.settings.get_api_key_direct", return_value="settings-key"
            ):
                result = get_vt_api_key()
                assert result == "settings-key"

    def test_settings_fallback_exception(self):
        """Test that settings exception returns None."""
        from redops.modules.intel.virustotal_intel import get_vt_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "redops.cli.settings.get_api_key_direct",
                side_effect=RuntimeError("Settings error"),
            ):
                result = get_vt_api_key()
                assert result is None

    def test_no_api_key_anywhere(self):
        """Test returns None when no API key configured."""
        from redops.modules.intel.virustotal_intel import get_vt_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch("redops.cli.settings.get_api_key_direct", return_value=None):
                result = get_vt_api_key()
                assert result is None


class TestMakeVTRequest:
    """Tests for _make_vt_request function."""

    def test_import_error_returns_none(self):
        """Test that import error returns None."""

        def mock_import(name, *args, **kwargs):
            if name == "requests":
                raise ImportError("No module named 'requests'")
            return original_import(name, *args, **kwargs)

        import builtins

        original_import = builtins.__import__

        import redops.modules.intel.virustotal_intel as vt_mod

        try:
            builtins.__import__ = mock_import
            reload(vt_mod)
            result = vt_mod._make_vt_request("domains/test.com", "test-key")
            assert result is None
        finally:
            builtins.__import__ = original_import
            reload(vt_mod)

    def test_successful_request(self):
        """Test successful 200 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"attributes": {"reputation": 0}}}
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.virustotal_intel as vt_mod

            reload(vt_mod)

            result = vt_mod._make_vt_request("domains/test.com", "test-key")
            assert result == {"data": {"attributes": {"reputation": 0}}}

    def test_404_response(self):
        """Test 404 not found response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.virustotal_intel as vt_mod

            reload(vt_mod)

            result = vt_mod._make_vt_request("domains/nonexistent.com", "test-key")
            assert result == {"error": "not_found"}

    def test_other_status_code_response(self):
        """Test other HTTP status code response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.virustotal_intel as vt_mod

            reload(vt_mod)

            result = vt_mod._make_vt_request("domains/test.com", "test-key")
            assert result == {"error": "HTTP 429"}

    def test_request_exception(self):
        """Test request exception handling."""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = ConnectionError("Connection error")

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.virustotal_intel as vt_mod

            reload(vt_mod)

            result = vt_mod._make_vt_request("domains/test.com", "test-key")
            assert result == {"error": "Connection error"}


class TestQueryVTDomainEdgeCases:
    """Edge case tests for query_vt_domain."""

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=None,
            ):
                result = query_vt_domain(ctx)

        data = result.get("virustotal_domain")
        assert "requests library not available" in data["error"]

    def test_domain_with_dns_records(self):
        """Test domain query with DNS records."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 85,
                    },
                    "last_dns_records": [
                        {"type": "A", "value": "93.184.216.34"},
                        {"type": "AAAA", "value": "2606:2800:220:1:248:1893:25c8:1946"},
                    ],
                }
            }
        }

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=mock_response,
            ):
                result = query_vt_domain(ctx)

        data = result.get("virustotal_domain")
        assert data["error"] is None
        assert len(data["report"]["dns_records"]) == 2


class TestQueryVTIPEdgeCases:
    """Edge case tests for query_vt_ip."""

    def test_domain_resolution_failure(self):
        """Test handling of domain resolution failure."""
        ctx = Context(target="nonexistent.invalid.domain")

        with patch(
            "socket.gethostbyname", side_effect=socket.gaierror("DNS resolution failed")
        ):
            result = query_vt_ip(ctx)

        # Should return early, no data added
        assert "virustotal_ip" not in result.data

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="8.8.8.8")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key", return_value=None
        ):
            result = query_vt_ip(ctx)

        data = result.get("virustotal_ip")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="8.8.8.8")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=None,
            ):
                result = query_vt_ip(ctx)

        data = result.get("virustotal_ip")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="8.8.8.8")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value={"error": "not_found"},
            ):
                result = query_vt_ip(ctx)

        data = result.get("virustotal_ip")
        assert data["error"] == "not_found"


class TestQueryVTURLEdgeCases:
    """Edge case tests for query_vt_url."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key", return_value=None
        ):
            result = query_vt_url(ctx)

        data = result.get("virustotal_url")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=None,
            ):
                result = query_vt_url(ctx)

        data = result.get("virustotal_url")
        assert "requests library not available" in data["error"]

    def test_other_error_in_response(self):
        """Test when other error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value={"error": "HTTP 429"},
            ):
                result = query_vt_url(ctx)

        data = result.get("virustotal_url")
        assert data["error"] == "HTTP 429"

    def test_url_with_http_prefix(self):
        """Test URL already has http prefix."""
        ctx = Context(target="http://example.com/page")

        mock_response = {
            "data": {
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {"malicious": 0},
                }
            }
        }

        with patch(
            "redops.modules.intel.virustotal_intel.get_vt_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.virustotal_intel._make_vt_request",
                return_value=mock_response,
            ):
                result = query_vt_url(ctx)

        data = result.get("virustotal_url")
        # URL should use the existing http:// prefix, not add https://
        assert data["url"] == "http://example.com/page"
