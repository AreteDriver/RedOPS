"""Tests for Have I Been Pwned intelligence module."""

from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.intel.hibp_intel import (
    query_hibp_breaches,
    query_hibp_domain,
    query_hibp_email,
    query_hibp_pastes,
    analyze_hibp_intel,
    _extract_domain,
    HIBPBreach,
    HIBPPaste,
)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_extract_domain(self):
        """Test domain extraction."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.example.com:8080/") == "sub.example.com"
        assert _extract_domain("example.com") == "example.com"


class TestHIBPDataclasses:
    """Tests for HIBP dataclasses."""

    def test_hibp_breach_to_dict(self):
        """Test HIBPBreach serialization."""
        breach = HIBPBreach(
            name="ExampleBreach",
            title="Example Breach",
            domain="example.com",
            breach_date="2023-01-15",
            pwn_count=1000000,
            description="A data breach at Example Inc.",
            data_classes=["Email addresses", "Passwords", "Names"],
            is_verified=True,
            is_sensitive=False,
        )
        data = breach.to_dict()

        assert data["name"] == "ExampleBreach"
        assert data["title"] == "Example Breach"
        assert data["pwn_count"] == 1000000
        assert "Email addresses" in data["data_classes"]
        assert data["is_verified"] is True

    def test_hibp_paste_to_dict(self):
        """Test HIBPPaste serialization."""
        paste = HIBPPaste(
            source="Pastebin",
            id="abc123",
            title="Leaked Credentials",
            date="2023-06-01",
            email_count=500,
        )
        data = paste.to_dict()

        assert data["source"] == "Pastebin"
        assert data["id"] == "abc123"
        assert data["email_count"] == 500


class TestQueryHIBPBreaches:
    """Tests for query_hibp_breaches (all breaches - no API key needed)."""

    def test_successful_breaches_query(self):
        """Test successful all-breaches query."""
        ctx = Context(target="example.com")

        mock_response = [
            {
                "Name": "Breach1",
                "Title": "First Breach",
                "Domain": "site1.com",
                "BreachDate": "2020-01-01",
                "PwnCount": 500000,
                "DataClasses": ["Emails", "Passwords"],
                "IsVerified": True,
            },
            {
                "Name": "Breach2",
                "Title": "Second Breach",
                "Domain": "site2.com",
                "BreachDate": "2021-06-15",
                "PwnCount": 1000000,
                "DataClasses": ["Emails"],
                "IsVerified": True,
            },
        ]

        with patch(
            "redops.modules.intel.hibp_intel._make_hibp_request",
            return_value=mock_response,
        ):
            result = query_hibp_breaches(ctx)

        data = result.get("hibp_breaches")
        assert data is not None
        assert data["error"] is None
        assert len(data["breaches"]) == 2
        assert data["breaches"][0]["name"] == "Breach1"

    def test_filter_by_domain(self):
        """Test filtering breaches by domain."""
        ctx = Context(target="example.com")

        with patch("redops.modules.intel.hibp_intel._make_hibp_request") as mock_req:
            mock_req.return_value = []
            query_hibp_breaches(ctx, {"domain": "example.com"})

            # Verify the domain filter was applied to the request
            call_args = mock_req.call_args
            assert "domain=example.com" in call_args[0][0]


class TestQueryHIBPDomain:
    """Tests for query_hibp_domain."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_hibp_domain(ctx)

        assert "hibp_domain" not in result.data

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value=None
        ):
            result = query_hibp_domain(ctx)

        data = result.get("hibp_domain")
        assert data is not None
        assert "API key" in data["error"]

    def test_successful_domain_query(self):
        """Test successful domain breach query."""
        ctx = Context(target="example.com")

        mock_response = [
            {"Email": "user1@example.com", "Breaches": ["Breach1", "Breach2"]},
            {"Email": "user2@example.com", "Breaches": ["Breach1"]},
            {"Email": "user3@example.com", "Breaches": ["Breach3"]},
        ]

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value=mock_response,
            ):
                result = query_hibp_domain(ctx)

        data = result.get("hibp_domain")
        assert data is not None
        assert data["error"] is None
        assert len(data["breached_accounts"]) == 3

    def test_no_breaches_found(self):
        """Test domain with no breaches."""
        ctx = Context(target="secure-domain.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"result": "not_found"},
            ):
                result = query_hibp_domain(ctx)

        data = result.get("hibp_domain")
        assert data["breached_accounts"] == []


class TestQueryHIBPEmail:
    """Tests for query_hibp_email."""

    def test_no_email(self):
        """Test with no email."""
        ctx = Context(target="example.com")
        result = query_hibp_email(ctx)

        assert "hibp_email" not in result.data

    def test_successful_email_query(self):
        """Test successful email breach query."""
        ctx = Context(target="example.com")

        mock_response = [
            {
                "Name": "LinkedIn",
                "Title": "LinkedIn",
                "Domain": "linkedin.com",
                "BreachDate": "2012-05-05",
                "PwnCount": 164611595,
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
            },
            {
                "Name": "Adobe",
                "Title": "Adobe",
                "Domain": "adobe.com",
                "BreachDate": "2013-10-04",
                "PwnCount": 152445165,
                "DataClasses": ["Email addresses", "Password hints", "Passwords"],
                "IsVerified": True,
            },
        ]

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value=mock_response,
            ):
                result = query_hibp_email(ctx, {"email": "test@example.com"})

        data = result.get("hibp_email")
        assert data is not None
        assert data["email"] == "test@example.com"
        assert len(data["breaches"]) == 2
        assert data["breaches"][0]["name"] == "LinkedIn"


class TestQueryHIBPPastes:
    """Tests for query_hibp_pastes."""

    def test_no_email(self):
        """Test with no email."""
        ctx = Context(target="example.com")
        result = query_hibp_pastes(ctx)

        assert "hibp_pastes" not in result.data

    def test_successful_pastes_query(self):
        """Test successful pastes query."""
        ctx = Context(target="example.com")

        mock_response = [
            {
                "Source": "Pastebin",
                "Id": "abc123",
                "Title": "Credential dump",
                "Date": "2023-01-15T10:30:00Z",
                "EmailCount": 250,
            },
            {
                "Source": "Pastie",
                "Id": "xyz789",
                "Title": None,
                "Date": "2022-06-01T14:00:00Z",
                "EmailCount": 100,
            },
        ]

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value=mock_response,
            ):
                result = query_hibp_pastes(ctx, {"email": "test@example.com"})

        data = result.get("hibp_pastes")
        assert data is not None
        assert data["email"] == "test@example.com"
        assert len(data["pastes"]) == 2
        assert data["pastes"][0]["source"] == "Pastebin"


class TestAnalyzeHIBPIntel:
    """Tests for analyze_hibp_intel."""

    def test_comprehensive_analysis(self):
        """Test comprehensive HIBP analysis."""
        ctx = Context(target="example.com")

        mock_domain_response = [
            {"Email": "user1@example.com", "Breaches": ["Breach1", "Breach2"]},
            {"Email": "user2@example.com", "Breaches": ["Breach1"]},
        ]

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value=mock_domain_response,
            ):
                result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel is not None
        assert intel["summary"]["breached_accounts"] == 2
        assert intel["summary"]["has_breaches"] is True
        assert intel["summary"]["unique_breaches"] == 2

    def test_no_breaches(self):
        """Test analysis with no breaches."""
        ctx = Context(target="secure.example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"result": "not_found"},
            ):
                result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel is not None
        assert intel["summary"]["breached_accounts"] == 0
        assert intel["summary"]["has_breaches"] is False

    def test_no_api_key(self):
        """Test analysis without API key."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value=None
        ):
            result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel is not None
        assert intel["domain"]["error"] is not None

    def test_rate_limited(self):
        """Test handling rate limit error."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"error": "rate_limited"},
            ):
                result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel["domain"]["error"] == "rate_limited"


class TestGetHIBPApiKey:
    """Tests for get_hibp_api_key function."""

    def test_from_environment(self):
        """Test getting API key from environment variable."""
        from redops.modules.intel.hibp_intel import get_hibp_api_key

        with patch.dict("os.environ", {"HIBP_API_KEY": "env-test-key"}):
            key = get_hibp_api_key()

        assert key == "env-test-key"

    def test_from_settings(self):
        """Test getting API key from settings when env not set."""
        from redops.modules.intel.hibp_intel import get_hibp_api_key

        with patch.dict("os.environ", {}, clear=False):
            # Make sure HIBP_API_KEY is not in env
            import os

            os.environ.pop("HIBP_API_KEY", None)

            with patch(
                "redops.cli.settings.get_api_key_direct", return_value="settings-key"
            ):
                key = get_hibp_api_key()

        assert key == "settings-key"

    def test_settings_import_error(self):
        """Test when settings import fails."""
        from redops.modules.intel.hibp_intel import get_hibp_api_key

        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("HIBP_API_KEY", None)

            with patch(
                "redops.cli.settings.get_api_key_direct", side_effect=ImportError
            ):
                key = get_hibp_api_key()

        assert key is None

    def test_settings_exception(self):
        """Test when settings raises exception."""
        from redops.modules.intel.hibp_intel import get_hibp_api_key

        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("HIBP_API_KEY", None)

            with patch(
                "redops.cli.settings.get_api_key_direct", side_effect=RuntimeError("Error")
            ):
                key = get_hibp_api_key()

        assert key is None


class TestMakeHIBPRequest:
    """Tests for _make_hibp_request function."""

    def test_requests_not_available(self):
        """Test when requests library not available."""
        from redops.modules.intel.hibp_intel import _make_hibp_request

        with patch.dict("sys.modules", {"requests": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = _make_hibp_request("breaches")

        assert result is None

    def test_successful_request(self):
        """Test successful API request."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"Name": "Test"}]
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == [{"Name": "Test"}]

    def test_not_found_response(self):
        """Test 404 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == {"result": "not_found"}

    def test_unauthorized_response(self):
        """Test 401 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == {"error": "api_key_required"}

    def test_forbidden_response(self):
        """Test 403 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == {"error": "forbidden"}

    def test_rate_limited_response(self):
        """Test 429 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == {"error": "rate_limited"}

    def test_other_error_response(self):
        """Test other HTTP error response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == {"error": "HTTP 500"}

    def test_request_exception(self):
        """Test request exception handling."""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = ConnectionError("Connection error")

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            result = hibp_mod._make_hibp_request("breaches")

        assert result == {"error": "Connection error"}

    def test_with_api_key(self):
        """Test request with API key header."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_requests.get.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hibp_intel as hibp_mod

            reload(hibp_mod)
            hibp_mod._make_hibp_request("breaches", api_key="test-key")

        # Verify API key header was set
        call_kwargs = mock_requests.get.call_args[1]
        assert "hibp-api-key" in call_kwargs["headers"]
        assert call_kwargs["headers"]["hibp-api-key"] == "test-key"


class TestQueryHIBPBreachesAdvanced:
    """Additional tests for query_hibp_breaches."""

    def test_requests_not_available(self):
        """Test when _make_hibp_request returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel._make_hibp_request", return_value=None
        ):
            result = query_hibp_breaches(ctx)

        data = result.get("hibp_breaches")
        assert data["error"] == "requests library not available"

    def test_error_response(self):
        """Test when API returns error."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel._make_hibp_request",
            return_value={"error": "rate_limited"},
        ):
            result = query_hibp_breaches(ctx)

        data = result.get("hibp_breaches")
        assert data["error"] == "rate_limited"


class TestQueryHIBPDomainAdvanced:
    """Additional tests for query_hibp_domain."""

    def test_requests_not_available(self):
        """Test when _make_hibp_request returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request", return_value=None
            ):
                result = query_hibp_domain(ctx)

        data = result.get("hibp_domain")
        assert data["error"] == "requests library not available"

    def test_error_response(self):
        """Test when API returns error."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"error": "forbidden"},
            ):
                result = query_hibp_domain(ctx)

        data = result.get("hibp_domain")
        assert data["error"] == "forbidden"

    def test_with_url_target(self):
        """Test with URL as target."""
        ctx = Context(target="https://example.com/path")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request", return_value=[]
            ):
                result = query_hibp_domain(ctx)

        data = result.get("hibp_domain")
        assert data["domain"] == "example.com"


class TestQueryHIBPEmailAdvanced:
    """Additional tests for query_hibp_email."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value=None
        ):
            result = query_hibp_email(ctx, {"email": "test@example.com"})

        data = result.get("hibp_email")
        assert data is not None
        assert "API key" in data["error"]

    def test_requests_not_available(self):
        """Test when _make_hibp_request returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request", return_value=None
            ):
                result = query_hibp_email(ctx, {"email": "test@example.com"})

        data = result.get("hibp_email")
        assert data["error"] == "requests library not available"

    def test_error_response(self):
        """Test when API returns error."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"error": "rate_limited"},
            ):
                result = query_hibp_email(ctx, {"email": "test@example.com"})

        data = result.get("hibp_email")
        assert data["error"] == "rate_limited"

    def test_not_found_response(self):
        """Test when email not found in breaches."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"result": "not_found"},
            ):
                result = query_hibp_email(ctx, {"email": "secure@example.com"})

        data = result.get("hibp_email")
        assert data["breaches"] == []


class TestQueryHIBPPastesAdvanced:
    """Additional tests for query_hibp_pastes."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value=None
        ):
            result = query_hibp_pastes(ctx, {"email": "test@example.com"})

        data = result.get("hibp_pastes")
        assert data is not None
        assert "API key" in data["error"]

    def test_requests_not_available(self):
        """Test when _make_hibp_request returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request", return_value=None
            ):
                result = query_hibp_pastes(ctx, {"email": "test@example.com"})

        data = result.get("hibp_pastes")
        assert data["error"] == "requests library not available"

    def test_error_response(self):
        """Test when API returns error."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"error": "forbidden"},
            ):
                result = query_hibp_pastes(ctx, {"email": "test@example.com"})

        data = result.get("hibp_pastes")
        assert data["error"] == "forbidden"

    def test_not_found_response(self):
        """Test when email not found in pastes."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value={"result": "not_found"},
            ):
                result = query_hibp_pastes(ctx, {"email": "secure@example.com"})

        data = result.get("hibp_pastes")
        assert data["pastes"] == []


class TestAnalyzeHIBPIntelAdvanced:
    """Additional tests for analyze_hibp_intel."""

    def test_no_target(self):
        """Test analysis with no target."""
        ctx = Context(target=None)

        result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel is not None
        assert intel["target"] is None

    def test_string_accounts_in_response(self):
        """Test when breached accounts are strings (not dicts)."""
        ctx = Context(target="example.com")

        # Some responses have accounts as strings
        mock_domain_response = [
            "Breach1",
            "Breach2",
            "Breach3",
        ]

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value=mock_domain_response,
            ):
                result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel is not None
        assert intel["summary"]["breached_accounts"] == 3
        assert intel["summary"]["unique_breaches"] == 3

    def test_mixed_accounts_format(self):
        """Test with mixed account formats."""
        ctx = Context(target="example.com")

        mock_domain_response = [
            {"Email": "user1@example.com", "Breaches": ["Breach1"]},
            "Breach2",  # String format
        ]

        with patch(
            "redops.modules.intel.hibp_intel.get_hibp_api_key", return_value="test-key"
        ):
            with patch(
                "redops.modules.intel.hibp_intel._make_hibp_request",
                return_value=mock_domain_response,
            ):
                result = analyze_hibp_intel(ctx)

        intel = result.get("hibp_intel")
        assert intel["summary"]["breached_accounts"] == 2
