"""Tests for Hunter.io intelligence module."""

from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.intel.hunter_intel import (
    query_hunter_domain,
    query_hunter_email_count,
    verify_hunter_email,
    analyze_hunter_intel,
    _extract_domain,
    HunterDomainResult,
    HunterEmail,
)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_extract_domain(self):
        """Test domain extraction."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.example.com:8080/") == "sub.example.com"
        assert _extract_domain("example.com") == "example.com"


class TestHunterDataclasses:
    """Tests for Hunter.io dataclasses."""

    def test_hunter_domain_result_to_dict(self):
        """Test HunterDomainResult serialization."""
        result = HunterDomainResult(
            domain="example.com",
            organization="Example Inc",
            disposable=False,
            webmail=False,
            accept_all=True,
            pattern="{first}.{last}",
            linked_domains=["example.org", "example.net"],
        )
        data = result.to_dict()

        assert data["domain"] == "example.com"
        assert data["organization"] == "Example Inc"
        assert data["pattern"] == "{first}.{last}"
        assert len(data["linked_domains"]) == 2

    def test_hunter_email_to_dict(self):
        """Test HunterEmail serialization."""
        email = HunterEmail(
            email="john.doe@example.com",
            first_name="John",
            last_name="Doe",
            position="Software Engineer",
            department="Engineering",
            confidence=95,
        )
        data = email.to_dict()

        assert data["email"] == "john.doe@example.com"
        assert data["first_name"] == "John"
        assert data["position"] == "Software Engineer"
        assert data["confidence"] == 95


class TestQueryHunterDomain:
    """Tests for query_hunter_domain."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_hunter_domain(ctx)

        assert "hunter_domain" not in result.data

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key", return_value=None
        ):
            result = query_hunter_domain(ctx)

        data = result.get("hunter_domain")
        assert data is not None
        assert "not configured" in data["error"]

    def test_successful_domain_query(self):
        """Test successful domain query."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "domain": "example.com",
                "organization": "Example Inc",
                "disposable": False,
                "webmail": False,
                "accept_all": True,
                "pattern": "{first}.{last}",
                "linked_domains": ["example.org"],
                "emails": [
                    {
                        "value": "john.doe@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "position": "CEO",
                        "department": "Executive",
                        "confidence": 95,
                        "sources": [],
                    },
                    {
                        "value": "jane.smith@example.com",
                        "first_name": "Jane",
                        "last_name": "Smith",
                        "position": "CTO",
                        "department": "Technology",
                        "confidence": 90,
                        "sources": [],
                    },
                ],
            }
        }

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=mock_response,
            ):
                result = query_hunter_domain(ctx)

        data = result.get("hunter_domain")
        assert data is not None
        assert data["error"] is None
        assert data["result"]["domain"] == "example.com"
        assert data["result"]["pattern"] == "{first}.{last}"
        assert len(data["result"]["emails"]) == 2

    def test_api_error(self):
        """Test API error handling."""
        ctx = Context(target="example.com")

        mock_response = {"errors": [{"details": "Invalid API key"}]}

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="bad-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=mock_response,
            ):
                result = query_hunter_domain(ctx)

        data = result.get("hunter_domain")
        assert "Invalid API key" in data["error"]


class TestQueryHunterEmailCount:
    """Tests for query_hunter_email_count."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_hunter_email_count(ctx)

        assert "hunter_count" not in result.data

    def test_successful_count_query(self):
        """Test successful email count query."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "total": 150,
                "personal_emails": 100,
                "generic_emails": 50,
                "department": {
                    "engineering": 40,
                    "sales": 30,
                    "marketing": 25,
                },
            }
        }

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=mock_response,
            ):
                result = query_hunter_email_count(ctx)

        data = result.get("hunter_count")
        assert data is not None
        assert data["count"] == 150
        assert data["personal_emails"] == 100
        assert data["generic_emails"] == 50


class TestVerifyHunterEmail:
    """Tests for verify_hunter_email."""

    def test_no_email(self):
        """Test with no email."""
        ctx = Context(target="example.com")
        result = verify_hunter_email(ctx)

        assert "hunter_verify" not in result.data

    def test_successful_verification(self):
        """Test successful email verification."""
        ctx = Context(target="example.com")

        mock_response = {
            "data": {
                "status": "valid",
                "result": "deliverable",
                "score": 95,
                "email": "john@example.com",
                "regexp": True,
                "gibberish": False,
                "disposable": False,
                "webmail": False,
                "mx_records": True,
                "smtp_server": True,
                "smtp_check": True,
                "accept_all": False,
                "block": False,
            }
        }

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=mock_response,
            ):
                result = verify_hunter_email(ctx, {"email": "john@example.com"})

        data = result.get("hunter_verify")
        assert data is not None
        assert data["result"]["status"] == "valid"
        assert data["result"]["score"] == 95
        assert data["result"]["result"] == "deliverable"


class TestAnalyzeHunterIntel:
    """Tests for analyze_hunter_intel."""

    def test_comprehensive_analysis(self):
        """Test comprehensive Hunter.io analysis."""
        ctx = Context(target="example.com")

        def mock_request(endpoint, api_key, params=None):
            if "email-count" in endpoint:
                return {
                    "data": {
                        "total": 100,
                        "personal_emails": 70,
                        "generic_emails": 30,
                    }
                }
            else:
                return {
                    "data": {
                        "domain": "example.com",
                        "organization": "Example Inc",
                        "pattern": "{first}.{last}",
                        "linked_domains": ["example.org"],
                        "emails": [
                            {"value": "a@example.com", "department": "Engineering"},
                            {"value": "b@example.com", "department": "Sales"},
                            {"value": "c@example.com", "department": "Engineering"},
                        ],
                    }
                }

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                side_effect=mock_request,
            ):
                result = analyze_hunter_intel(ctx)

        intel = result.get("hunter_intel")
        assert intel is not None
        assert intel["summary"]["organization"] == "Example Inc"
        assert intel["summary"]["email_pattern"] == "{first}.{last}"
        assert intel["summary"]["emails_found"] == 3
        assert intel["summary"]["total_emails"] == 100
        assert "Engineering" in intel["summary"]["departments"]

    def test_no_api_key(self):
        """Test analysis without API key."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key", return_value=None
        ):
            result = analyze_hunter_intel(ctx)

        intel = result.get("hunter_intel")
        assert intel is not None
        assert intel["domain"]["error"] is not None


class TestGetHunterApiKey:
    """Tests for get_hunter_api_key function."""

    def test_api_key_from_env(self):
        """Test API key loaded from environment."""
        from redops.modules.intel.hunter_intel import get_hunter_api_key

        with patch.dict("os.environ", {"HUNTER_API_KEY": "env-api-key"}):
            result = get_hunter_api_key()
            assert result == "env-api-key"

    def test_api_key_from_settings_fallback(self):
        """Test API key loaded from settings when env not set."""
        from redops.modules.intel.hunter_intel import get_hunter_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "redops.cli.settings.get_api_key_direct", return_value="settings-key"
            ):
                result = get_hunter_api_key()
                assert result == "settings-key"

    def test_settings_fallback_exception(self):
        """Test that settings exception returns None."""
        from redops.modules.intel.hunter_intel import get_hunter_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "redops.cli.settings.get_api_key_direct",
                side_effect=RuntimeError("Settings error"),
            ):
                result = get_hunter_api_key()
                assert result is None

    def test_no_api_key_anywhere(self):
        """Test returns None when no API key configured."""
        from redops.modules.intel.hunter_intel import get_hunter_api_key

        with patch.dict("os.environ", {}, clear=True):
            with patch("redops.cli.settings.get_api_key_direct", return_value=None):
                result = get_hunter_api_key()
                assert result is None


class TestMakeHunterRequest:
    """Tests for _make_hunter_request function."""

    def test_import_error_returns_none(self):
        """Test that import error returns None."""

        # Test the case where requests is not installed by mocking the import to fail
        def mock_import(name, *args, **kwargs):
            if name == "requests":
                raise ImportError("No module named 'requests'")
            return original_import(name, *args, **kwargs)

        import builtins

        original_import = builtins.__import__

        from importlib import reload
        import redops.modules.intel.hunter_intel as hunter_mod

        try:
            builtins.__import__ = mock_import
            reload(hunter_mod)
            result = hunter_mod._make_hunter_request("domain-search", "test-key")
            assert result is None
        finally:
            builtins.__import__ = original_import
            reload(hunter_mod)

    def test_successful_request(self):
        """Test successful 200 response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"domain": "test.com"}}
        mock_requests.get.return_value = mock_response

        import sys

        with patch.dict(sys.modules, {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hunter_intel as hunter_mod

            reload(hunter_mod)

            result = hunter_mod._make_hunter_request(
                "domain-search", "test-key", {"domain": "test.com"}
            )
            assert result == {"data": {"domain": "test.com"}}

    def test_404_response(self):
        """Test 404 not found response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        import sys

        with patch.dict(sys.modules, {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hunter_intel as hunter_mod

            reload(hunter_mod)

            result = hunter_mod._make_hunter_request("domain-search", "test-key")
            assert result == {"error": "not_found"}

    def test_429_rate_limit_response(self):
        """Test 429 rate limit response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response

        import sys

        with patch.dict(sys.modules, {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hunter_intel as hunter_mod

            reload(hunter_mod)

            result = hunter_mod._make_hunter_request("domain-search", "test-key")
            assert result == {"error": "rate_limited"}

    def test_401_unauthorized_response(self):
        """Test 401 unauthorized response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.get.return_value = mock_response

        import sys

        with patch.dict(sys.modules, {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hunter_intel as hunter_mod

            reload(hunter_mod)

            result = hunter_mod._make_hunter_request("domain-search", "test-key")
            assert result == {"error": "invalid_api_key"}

    def test_other_status_code_response(self):
        """Test other HTTP status code response."""
        mock_requests = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response

        import sys

        with patch.dict(sys.modules, {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hunter_intel as hunter_mod

            reload(hunter_mod)

            result = hunter_mod._make_hunter_request("domain-search", "test-key")
            assert result == {"error": "HTTP 500"}

    def test_request_exception(self):
        """Test request exception handling."""
        mock_requests = MagicMock()
        mock_requests.get.side_effect = ConnectionError("Connection error")

        import sys

        with patch.dict(sys.modules, {"requests": mock_requests}):
            from importlib import reload
            import redops.modules.intel.hunter_intel as hunter_mod

            reload(hunter_mod)

            result = hunter_mod._make_hunter_request("domain-search", "test-key")
            assert result == {"error": "Connection error"}


class TestQueryHunterDomainEdgeCases:
    """Edge case tests for query_hunter_domain."""

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=None,
            ):
                result = query_hunter_domain(ctx)

        data = result.get("hunter_domain")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value={"error": "rate_limited"},
            ):
                result = query_hunter_domain(ctx)

        data = result.get("hunter_domain")
        assert data["error"] == "rate_limited"

    def test_errors_array_in_response(self):
        """Test when errors array in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value={"errors": [{"details": "Domain not found"}]},
            ):
                result = query_hunter_domain(ctx)

        data = result.get("hunter_domain")
        assert "Domain not found" in data["error"]


class TestQueryHunterEmailCountEdgeCases:
    """Edge case tests for query_hunter_email_count."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key", return_value=None
        ):
            result = query_hunter_email_count(ctx)

        data = result.get("hunter_count")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=None,
            ):
                result = query_hunter_email_count(ctx)

        data = result.get("hunter_count")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value={"error": "invalid_api_key"},
            ):
                result = query_hunter_email_count(ctx)

        data = result.get("hunter_count")
        assert data["error"] == "invalid_api_key"


class TestVerifyHunterEmailEdgeCases:
    """Edge case tests for verify_hunter_email."""

    def test_no_api_key(self):
        """Test when API key not configured."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key", return_value=None
        ):
            result = verify_hunter_email(ctx, {"email": "test@example.com"})

        data = result.get("hunter_verify")
        assert data is not None
        assert "not configured" in data["error"]

    def test_requests_not_available(self):
        """Test when requests library returns None."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value=None,
            ):
                result = verify_hunter_email(ctx, {"email": "test@example.com"})

        data = result.get("hunter_verify")
        assert "requests library not available" in data["error"]

    def test_error_in_response(self):
        """Test when error key in response."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.hunter_intel.get_hunter_api_key",
            return_value="test-key",
        ):
            with patch(
                "redops.modules.intel.hunter_intel._make_hunter_request",
                return_value={"error": "not_found"},
            ):
                result = verify_hunter_email(ctx, {"email": "test@example.com"})

        data = result.get("hunter_verify")
        assert data["error"] == "not_found"
