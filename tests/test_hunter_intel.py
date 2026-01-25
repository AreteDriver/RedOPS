"""Tests for Hunter.io intelligence module."""

import pytest
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

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value=None):
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

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value="test-key"):
            with patch("redops.modules.intel.hunter_intel._make_hunter_request", return_value=mock_response):
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

        mock_response = {
            "errors": [{"details": "Invalid API key"}]
        }

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value="bad-key"):
            with patch("redops.modules.intel.hunter_intel._make_hunter_request", return_value=mock_response):
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

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value="test-key"):
            with patch("redops.modules.intel.hunter_intel._make_hunter_request", return_value=mock_response):
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

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value="test-key"):
            with patch("redops.modules.intel.hunter_intel._make_hunter_request", return_value=mock_response):
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

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value="test-key"):
            with patch("redops.modules.intel.hunter_intel._make_hunter_request", side_effect=mock_request):
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

        with patch("redops.modules.intel.hunter_intel.get_hunter_api_key", return_value=None):
            result = analyze_hunter_intel(ctx)

        intel = result.get("hunter_intel")
        assert intel is not None
        assert intel["domain"]["error"] is not None
