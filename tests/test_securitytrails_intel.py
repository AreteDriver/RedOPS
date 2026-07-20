"""Tests for SecurityTrails intelligence module."""

import sys
from importlib import reload
from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.intel.securitytrails_intel import (
    query_st_domain,
    query_st_subdomains,
    query_st_history,
    query_st_associated,
    analyze_securitytrails_intel,
    _extract_domain,
    STDomainInfo,
    STHistoricalDNS,
)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_extract_domain(self):
        """Test domain extraction."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.example.com:8080/") == "sub.example.com"
        assert _extract_domain("example.com") == "example.com"


class TestSTDataclasses:
    """Tests for SecurityTrails dataclasses."""

    def test_st_domain_info_to_dict(self):
        """Test STDomainInfo serialization."""
        info = STDomainInfo(
            domain="example.com",
            alexa_rank=1000,
            apex_domain="example.com",
            hostname="www.example.com",
            current_dns={"a": ["93.184.216.34"]},
            subdomain_count=42,
        )
        result = info.to_dict()

        assert result["domain"] == "example.com"
        assert result["alexa_rank"] == 1000
        assert result["subdomain_count"] == 42
        assert result["current_dns"]["a"] == ["93.184.216.34"]

    def test_st_historical_dns_to_dict(self):
        """Test STHistoricalDNS serialization."""
        history = STHistoricalDNS(
            domain="example.com",
            record_type="a",
            records=[{"ip": "1.2.3.4", "first_seen": "2020-01-01"}],
            pages=5,
        )
        result = history.to_dict()

        assert result["domain"] == "example.com"
        assert result["record_type"] == "a"
        assert len(result["records"]) == 1
        assert result["pages"] == 5


class TestQuerySTDomain:
    """Tests for query_st_domain."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_st_domain(ctx)

        assert "securitytrails_domain" not in result.data

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value=None,
        ):
            result = query_st_domain(ctx)

        data = result.get("securitytrails_domain")
        assert data is not None
        assert "not configured" in data["error"]

    def test_successful_domain_query(self):
        """Test successful domain query."""
        ctx = Context(target="example.com")

        mock_response = {
            "alexa_rank": 1000,
            "apex_domain": "example.com",
            "hostname": "example.com",
            "current_dns": {
                "a": {"values": [{"ip": "93.184.216.34"}]},
                "mx": {"values": [{"priority": 10, "hostname": "mail.example.com"}]},
            },
            "subdomain_count": 42,
        }

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=mock_response,
            ):
                result = query_st_domain(ctx)

        data = result.get("securitytrails_domain")
        assert data is not None
        assert data["error"] is None
        assert data["info"]["domain"] == "example.com"
        assert data["info"]["subdomain_count"] == 42

    def test_not_found(self):
        """Test domain not found."""
        ctx = Context(target="nonexistent.invalid")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value={"error": "not_found"},
            ):
                result = query_st_domain(ctx)

        data = result.get("securitytrails_domain")
        assert data["error"] == "not_found"


class TestQuerySTSubdomains:
    """Tests for query_st_subdomains."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_st_subdomains(ctx)

        assert "securitytrails_subdomains" not in result.data

    def test_successful_subdomain_query(self):
        """Test successful subdomain query."""
        ctx = Context(target="example.com")

        mock_response = {
            "subdomains": ["www", "api", "mail", "blog", "dev"],
        }

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=mock_response,
            ):
                result = query_st_subdomains(ctx)

        data = result.get("securitytrails_subdomains")
        assert data is not None
        assert data["domain"] == "example.com"
        assert len(data["subdomains"]) == 5
        assert "www" in data["subdomains"]
        assert "api" in data["subdomains"]


class TestQuerySTHistory:
    """Tests for query_st_history."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_st_history(ctx)

        assert "securitytrails_history" not in result.data

    def test_successful_history_query(self):
        """Test successful history query."""
        ctx = Context(target="example.com")

        mock_response = {
            "records": [
                {
                    "ip": "1.2.3.4",
                    "first_seen": "2018-01-01",
                    "last_seen": "2020-01-01",
                },
                {
                    "ip": "5.6.7.8",
                    "first_seen": "2020-01-02",
                    "last_seen": "2023-01-01",
                },
            ],
            "pages": 1,
        }

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=mock_response,
            ):
                result = query_st_history(ctx)

        data = result.get("securitytrails_history")
        assert data is not None
        assert data["record_type"] == "a"
        assert len(data["history"]["records"]) == 2


class TestQuerySTAssociated:
    """Tests for query_st_associated."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_st_associated(ctx)

        assert "securitytrails_associated" not in result.data

    def test_successful_associated_query(self):
        """Test successful associated domains query."""
        ctx = Context(target="example.com")

        mock_response = {
            "records": [
                {"hostname": "related1.com"},
                {"hostname": "related2.net"},
            ],
        }

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=mock_response,
            ):
                result = query_st_associated(ctx)

        data = result.get("securitytrails_associated")
        assert data is not None
        assert data["domain"] == "example.com"
        assert data["count"] == 2


class TestAnalyzeSecurityTrailsIntel:
    """Tests for analyze_securitytrails_intel."""

    def test_comprehensive_analysis(self):
        """Test comprehensive SecurityTrails analysis."""
        ctx = Context(target="example.com")

        def mock_request(endpoint, api_key):
            if "subdomains" in endpoint:
                return {"subdomains": ["www", "api", "mail"]}
            elif "history" in endpoint:
                return {
                    "records": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}],
                    "pages": 1,
                }
            else:
                return {
                    "alexa_rank": 5000,
                    "subdomain_count": 50,
                    "current_dns": {"a": [], "mx": []},
                }

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                side_effect=mock_request,
            ):
                result = analyze_securitytrails_intel(ctx)

        intel = result.get("securitytrails_intel")
        assert intel is not None
        assert intel["summary"]["subdomains_found"] == 3
        assert intel["summary"]["historical_records"] == 2

    def test_no_api_key(self):
        """Test analysis without API key."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value=None,
        ):
            result = analyze_securitytrails_intel(ctx)

        intel = result.get("securitytrails_intel")
        assert intel is not None
        assert intel["domain"]["error"] is not None


class TestGetSTApiKey:
    """Tests for get_st_api_key function."""

    def test_api_key_from_env(self):
        """Test API key loaded from environment."""
        from redops.modules.intel.securitytrails_intel import get_st_api_key

        with patch.dict("os.environ", {"SECURITYTRAILS_API_KEY": "env-api-key"}):
            result = get_st_api_key()
            assert result == "env-api-key"

    def test_api_key_from_settings_fallback(self):
        """Test API key loaded from settings when env not set."""
        from redops.modules.intel.securitytrails_intel import get_st_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "redops.cli.settings.get_api_key_direct", return_value="settings-key"
            ):
                result = get_st_api_key()
                assert result == "settings-key"

    def test_settings_fallback_exception(self):
        """Test that settings exception returns None."""
        from redops.modules.intel.securitytrails_intel import get_st_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "redops.cli.settings.get_api_key_direct",
                side_effect=RuntimeError("Settings error"),
            ):
                result = get_st_api_key()
                assert result is None

    def test_no_api_key_anywhere(self):
        """Test returns None when no API key configured."""
        from redops.modules.intel.securitytrails_intel import get_st_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch("redops.cli.settings.get_api_key_direct", return_value=None):
                result = get_st_api_key()
                assert result is None


class TestMakeSTRequest:
    """Tests for _make_st_request function."""

    def test_import_error_returns_none(self):
        """Test that import error returns None."""

        def mock_import(name, *args, **kwargs):
            if name == "requests":
                raise ImportError("No module named 'requests'")
            return original_import(name, *args, **kwargs)

        import builtins

        original_import = builtins.__import__

        import redops.modules.intel.securitytrails_intel as st_mod

        try:
            builtins.__import__ = mock_import
            reload(st_mod)
            result = st_mod._make_st_request("domain/test.com", "test-key")
            assert result is None
        finally:
            builtins.__import__ = original_import
            reload(st_mod)

    def test_successful_request(self):
        """Test successful 200 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"domain": "test.com", "subdomain_count": 10}
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.securitytrails_intel as st_mod

            reload(st_mod)

            result = st_mod._make_st_request("domain/test.com", "test-key")
            assert result == {"domain": "test.com", "subdomain_count": 10}

    def test_404_response(self):
        """Test 404 not found response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.securitytrails_intel as st_mod

            reload(st_mod)

            result = st_mod._make_st_request("domain/nonexistent.com", "test-key")
            assert result == {"error": "not_found"}

    def test_429_rate_limit_response(self):
        """Test 429 rate limit response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.securitytrails_intel as st_mod

            reload(st_mod)

            result = st_mod._make_st_request("domain/test.com", "test-key")
            assert result == {"error": "rate_limited"}

    def test_other_status_code_response(self):
        """Test other HTTP status code response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.securitytrails_intel as st_mod

            reload(st_mod)

            result = st_mod._make_st_request("domain/test.com", "test-key")
            assert result == {"error": "HTTP 500"}

    def test_request_exception(self):
        """Test request exception handling."""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = ConnectionError("Connection error")

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import redops.modules.intel.securitytrails_intel as st_mod

            reload(st_mod)

            result = st_mod._make_st_request("domain/test.com", "test-key")
            assert result == {"error": "Connection error"}


class TestQuerySTDomainEdgeCases:
    """Edge case tests for query_st_domain."""

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=None,
            ):
                result = query_st_domain(ctx)

        data = result.get("securitytrails_domain")
        assert "requests library not available" in data["error"]


class TestQuerySTSubdomainsEdgeCases:
    """Edge case tests for query_st_subdomains."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value=None,
        ):
            result = query_st_subdomains(ctx)

        data = result.get("securitytrails_subdomains")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=None,
            ):
                result = query_st_subdomains(ctx)

        data = result.get("securitytrails_subdomains")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value={"error": "rate_limited"},
            ):
                result = query_st_subdomains(ctx)

        data = result.get("securitytrails_subdomains")
        assert data["error"] == "rate_limited"


class TestQuerySTHistoryEdgeCases:
    """Edge case tests for query_st_history."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value=None,
        ):
            result = query_st_history(ctx)

        data = result.get("securitytrails_history")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=None,
            ):
                result = query_st_history(ctx)

        data = result.get("securitytrails_history")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value={"error": "not_found"},
            ):
                result = query_st_history(ctx)

        data = result.get("securitytrails_history")
        assert data["error"] == "not_found"


class TestQuerySTAssociatedEdgeCases:
    """Edge case tests for query_st_associated."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value=None,
        ):
            result = query_st_associated(ctx)

        data = result.get("securitytrails_associated")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value=None,
            ):
                result = query_st_associated(ctx)

        data = result.get("securitytrails_associated")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.securitytrails_intel.get_st_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.securitytrails_intel._make_st_request",
                return_value={"error": "HTTP 500"},
            ):
                result = query_st_associated(ctx)

        data = result.get("securitytrails_associated")
        assert data["error"] == "HTTP 500"
