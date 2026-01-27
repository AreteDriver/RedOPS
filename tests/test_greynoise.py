"""Tests for the GreyNoise threat intelligence module."""

from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.modules.threat_intel.greynoise import (
    query_greynoise,
    get_greynoise_context,
    get_greynoise_riot,
    analyze_greynoise_results,
    get_greynoise_summary,
    _is_valid_ip,
)


class TestIsValidIp:
    """Tests for IP validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert _is_valid_ip("8.8.8.8") is True
        assert _is_valid_ip("192.168.1.1") is True
        assert _is_valid_ip("10.0.0.1") is True

    def test_invalid_ipv4(self):
        """Test invalid IPv4 addresses."""
        assert _is_valid_ip("256.1.1.1") is False
        assert _is_valid_ip("not.an.ip") is False
        assert _is_valid_ip("example.com") is False

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert _is_valid_ip("::1") is True
        assert _is_valid_ip("2001:db8::1") is True


class TestQueryGreynoise:
    """Tests for query_greynoise function."""

    def test_no_target(self):
        """Test handling when no target specified."""
        ctx = Context()
        result = query_greynoise(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No IP address" in log["message"] for log in warnings)

    def test_invalid_ip(self):
        """Test handling invalid IP format."""
        ctx = Context(target="not-an-ip")
        result = query_greynoise(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("Invalid IP" in log["message"] for log in warnings)

    def test_no_requests_library(self):
        """Test handling when requests library not available."""
        with patch("redops.modules.threat_intel.greynoise.HAS_REQUESTS", False):
            ctx = Context(target="8.8.8.8")
            result = query_greynoise(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("requests library" in log["message"] for log in warnings)

    @patch("redops.modules.threat_intel.greynoise._query_community_api")
    @patch("redops.modules.threat_intel.greynoise.get_greynoise_riot")
    def test_successful_query(self, mock_riot, mock_query):
        """Test successful GreyNoise query."""
        mock_query.return_value = {
            "ip": "8.8.8.8",
            "noise": False,
            "riot": True,
            "classification": "benign",
        }
        mock_riot.return_value = {
            "ip": "8.8.8.8",
            "riot": True,
            "name": "Google",
            "category": "public_dns",
        }

        ctx = Context(target="8.8.8.8")
        result = query_greynoise(ctx)

        assert "greynoise_result" in result.data
        assert result.data["greynoise_noise"] is False

    @patch("redops.modules.threat_intel.greynoise._query_community_api")
    @patch("redops.modules.threat_intel.greynoise.get_greynoise_riot")
    def test_malicious_ip(self, mock_riot, mock_query):
        """Test detection of malicious IP."""
        mock_query.return_value = {
            "ip": "1.2.3.4",
            "noise": True,
            "classification": "malicious",
            "actor": "unknown",
            "tags": ["Mirai"],
        }
        mock_riot.return_value = {"ip": "1.2.3.4", "riot": False}

        ctx = Context(target="1.2.3.4")
        result = query_greynoise(ctx)

        assert result.data["greynoise_noise"] is True
        assert result.data["greynoise_classification"] == "malicious"


class TestGetGreynoiseContext:
    """Tests for get_greynoise_context function."""

    def test_no_api_key(self):
        """Test when API key not provided."""
        result = get_greynoise_context("8.8.8.8", "")
        assert "error" in result

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.greynoise.HAS_REQUESTS", False):
            result = get_greynoise_context("8.8.8.8", "test-key")
            assert "error" in result

    @patch("redops.modules.threat_intel.greynoise.requests")
    def test_successful_context(self, mock_requests):
        """Test successful context lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "seen": True,
            "classification": "benign",
            "actor": "GOOGLE",
        }
        mock_requests.get.return_value = mock_response

        result = get_greynoise_context("8.8.8.8", "test-key")

        assert result["ip"] == "8.8.8.8"
        assert result["classification"] == "benign"

    @patch("redops.modules.threat_intel.greynoise.requests")
    def test_not_found(self, mock_requests):
        """Test IP not found in dataset."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        result = get_greynoise_context("192.168.1.1", "test-key")

        assert result["seen"] is False


class TestGetGreynoiseRiot:
    """Tests for get_greynoise_riot function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.greynoise.HAS_REQUESTS", False):
            result = get_greynoise_riot("8.8.8.8")
            assert "error" in result

    @patch("redops.modules.threat_intel.greynoise.requests")
    def test_riot_match(self, mock_requests):
        """Test IP found in RIOT database."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "riot": True,
            "name": "Google Public DNS",
            "category": "public_dns",
        }
        mock_requests.get.return_value = mock_response

        result = get_greynoise_riot("8.8.8.8")

        assert result["riot"] is True
        assert "Google" in result["name"]

    @patch("redops.modules.threat_intel.greynoise.requests")
    def test_riot_no_match(self, mock_requests):
        """Test IP not found in RIOT database."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        result = get_greynoise_riot("1.2.3.4")

        assert result["riot"] is False


class TestAnalyzeGreynoiseResults:
    """Tests for analyze_greynoise_results function."""

    def test_error_result(self):
        """Test no findings for error results."""
        result = {"error": "API failed"}
        findings = analyze_greynoise_results(result, "8.8.8.8")
        assert len(findings) == 0

    def test_malicious_scanner(self):
        """Test finding for malicious scanner."""
        result = {
            "ip": "1.2.3.4",
            "noise": True,
            "classification": "malicious",
            "actor": "Unknown",
            "tags": [],
        }

        findings = analyze_greynoise_results(result, "1.2.3.4")

        assert any("Malicious Scanner" in f.title for f in findings)
        assert any(f.severity.name == "HIGH" for f in findings)

    def test_benign_scanner(self):
        """Test finding for benign scanner."""
        result = {
            "ip": "8.8.8.8",
            "noise": True,
            "classification": "benign",
            "actor": "Shodan",
        }

        findings = analyze_greynoise_results(result, "8.8.8.8")

        assert any("Benign Scanner" in f.title for f in findings)

    def test_riot_service(self):
        """Test finding for RIOT service."""
        result = {
            "ip": "8.8.8.8",
            "noise": False,
            "riot": {
                "riot": True,
                "name": "Google Public DNS",
                "category": "public_dns",
            },
        }

        findings = analyze_greynoise_results(result, "8.8.8.8")

        assert any("Known Benign Service" in f.title for f in findings)

    def test_dangerous_tags(self):
        """Test finding for dangerous activity tags."""
        result = {
            "ip": "1.2.3.4",
            "noise": True,
            "classification": "unknown",
            "tags": ["Mirai", "SSH Bruteforcer"],
        }

        findings = analyze_greynoise_results(result, "1.2.3.4")

        assert any("Dangerous Activity" in f.title for f in findings)


class TestGetGreynoiseSummary:
    """Tests for get_greynoise_summary function."""

    def test_with_results(self):
        """Test summary with results."""
        ctx = Context()
        ctx.add(
            "greynoise_result",
            {
                "ip": "8.8.8.8",
                "noise": False,
                "classification": "benign",
                "actor": "GOOGLE",
                "tags": ["DNS"],
                "query_timestamp": "2024-01-01T00:00:00",
            },
        )

        summary = get_greynoise_summary(ctx)

        assert summary["ip"] == "8.8.8.8"
        assert summary["noise"] is False
        assert summary["classification"] == "benign"

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_greynoise_summary(ctx)

        assert summary["ip"] == ""
        assert summary["noise"] is False
        assert summary["classification"] == "unknown"
