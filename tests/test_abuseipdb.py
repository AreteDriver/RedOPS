"""Tests for the AbuseIPDB threat intelligence module."""

from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.modules.threat_intel.abuseipdb import (
    check_ip_reputation,
    report_ip,
    get_blacklist,
    analyze_abuseipdb_results,
    get_abuseipdb_summary,
)


class TestCheckIpReputation:
    """Tests for check_ip_reputation function."""

    def test_no_api_key(self):
        """Test handling when no API key provided."""
        ctx = Context(target="8.8.8.8")
        result = check_ip_reputation(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("API key" in log["message"] for log in warnings)

    def test_no_target(self):
        """Test handling when no target specified."""
        ctx = Context()
        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}):
            result = check_ip_reputation(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("No IP address" in log["message"] for log in warnings)

    def test_no_requests_library(self):
        """Test handling when requests library not available."""
        with patch("redops.modules.threat_intel.abuseipdb.HAS_REQUESTS", False):
            ctx = Context(target="8.8.8.8")
            result = check_ip_reputation(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("requests library" in log["message"] for log in warnings)

    @patch("redops.modules.threat_intel.abuseipdb._check_ip")
    def test_successful_check(self, mock_check):
        """Test successful IP reputation check."""
        mock_check.return_value = {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isWhitelisted": True,
            "isp": "Google LLC",
        }

        ctx = Context(target="8.8.8.8")
        result = check_ip_reputation(ctx, {"api_key": "test-key"})

        assert "abuseipdb_result" in result.data
        assert result.data["abuseipdb_is_whitelisted"] is True

    @patch("redops.modules.threat_intel.abuseipdb._check_ip")
    def test_high_abuse_score(self, mock_check):
        """Test IP with high abuse score."""
        mock_check.return_value = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 95,
            "totalReports": 500,
            "isWhitelisted": False,
            "isp": "Malicious ISP",
            "countryCode": "XX",
        }

        ctx = Context(target="1.2.3.4")
        result = check_ip_reputation(ctx, {"api_key": "test-key"})

        assert result.data["abuseipdb_score"] == 95
        assert result.data["abuseipdb_total_reports"] == 500

    @patch("redops.modules.threat_intel.abuseipdb._check_ip")
    def test_api_error(self, mock_check):
        """Test handling API errors."""
        mock_check.return_value = {"ip": "8.8.8.8", "error": "Rate limit exceeded"}

        ctx = Context(target="8.8.8.8")
        result = check_ip_reputation(ctx, {"api_key": "test-key"})

        warnings = result.get_logs(level="WARNING")
        assert any("failed" in log["message"] for log in warnings)


class TestReportIp:
    """Tests for report_ip function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.abuseipdb.HAS_REQUESTS", False):
            result = report_ip("1.2.3.4", "test-key", [14, 15])
            assert "error" in result

    @patch("redops.modules.threat_intel.abuseipdb.requests")
    def test_successful_report(self, mock_requests):
        """Test successful IP report."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 50,
            }
        }
        mock_requests.post.return_value = mock_response

        result = report_ip("1.2.3.4", "test-key", [14, 15], "Port scanning detected")

        assert result["ipAddress"] == "1.2.3.4"

    @patch("redops.modules.threat_intel.abuseipdb.requests")
    def test_invalid_api_key(self, mock_requests):
        """Test handling invalid API key."""
        import requests as real_requests

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = real_requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_requests.post.return_value = mock_response
        mock_requests.exceptions = real_requests.exceptions

        result = report_ip("1.2.3.4", "bad-key", [14])

        assert "error" in result
        assert "Invalid API key" in result["error"]


class TestGetBlacklist:
    """Tests for get_blacklist function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.abuseipdb.HAS_REQUESTS", False):
            result = get_blacklist("test-key")
            assert result == []

    @patch("redops.modules.threat_intel.abuseipdb.requests")
    def test_successful_blacklist(self, mock_requests):
        """Test successful blacklist retrieval."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100},
                {"ipAddress": "5.6.7.8", "abuseConfidenceScore": 95},
            ]
        }
        mock_requests.get.return_value = mock_response

        result = get_blacklist("test-key", confidence_minimum=90, limit=100)

        assert len(result) == 2

    @patch("redops.modules.threat_intel.abuseipdb.requests")
    def test_blacklist_error(self, mock_requests):
        """Test error handling in blacklist."""
        mock_requests.get.side_effect = ConnectionError("API error")

        result = get_blacklist("test-key")

        assert result == []


class TestAnalyzeAbuseipdbResults:
    """Tests for analyze_abuseipdb_results function."""

    def test_error_result(self):
        """Test no findings for error results."""
        result = {"error": "API failed"}
        findings = analyze_abuseipdb_results(result, "8.8.8.8")
        assert len(findings) == 0

    def test_whitelisted_ip(self):
        """Test finding for whitelisted IP."""
        result = {
            "ipAddress": "8.8.8.8",
            "isWhitelisted": True,
            "isp": "Google LLC",
            "domain": "google.com",
        }

        findings = analyze_abuseipdb_results(result, "8.8.8.8")

        assert any("Whitelisted" in f.title for f in findings)
        # Should return early after whitelisted finding
        assert len(findings) == 1

    def test_high_abuse_confidence(self):
        """Test finding for high abuse confidence."""
        result = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 80,
            "totalReports": 100,
            "isWhitelisted": False,
            "isp": "Malicious ISP",
            "countryCode": "XX",
        }

        findings = analyze_abuseipdb_results(result, "1.2.3.4")

        assert any("High Abuse Confidence" in f.title for f in findings)
        assert any(f.severity.name == "HIGH" for f in findings)

    def test_medium_abuse_confidence(self):
        """Test finding for medium abuse confidence."""
        result = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 60,
            "totalReports": 20,
            "isWhitelisted": False,
        }

        findings = analyze_abuseipdb_results(result, "1.2.3.4")

        assert any("Medium Abuse Confidence" in f.title for f in findings)

    def test_low_abuse_reports(self):
        """Test finding for low abuse reports."""
        result = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 10,
            "totalReports": 2,
            "isWhitelisted": False,
        }

        findings = analyze_abuseipdb_results(result, "1.2.3.4")

        assert any("Low Abuse Reports" in f.title for f in findings)

    def test_tor_exit_node(self):
        """Test finding for Tor exit node."""
        result = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isWhitelisted": False,
            "isTor": True,
        }

        findings = analyze_abuseipdb_results(result, "1.2.3.4")

        assert any("Tor Exit Node" in f.title for f in findings)

    def test_suspicious_infrastructure(self):
        """Test finding for suspicious infrastructure."""
        result = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 30,
            "totalReports": 50,
            "isWhitelisted": False,
            "usageType": "Data Center/Web Hosting/Transit",
        }

        findings = analyze_abuseipdb_results(result, "1.2.3.4")

        assert any("Suspicious Infrastructure" in f.title for f in findings)


class TestGetAbuseipdbSummary:
    """Tests for get_abuseipdb_summary function."""

    def test_with_results(self):
        """Test summary with results."""
        ctx = Context()
        ctx.add(
            "abuseipdb_result",
            {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isWhitelisted": True,
                "isTor": False,
                "isp": "Google LLC",
                "domain": "google.com",
                "countryCode": "US",
                "usageType": "Data Center",
                "query_timestamp": "2024-01-01T00:00:00",
            },
        )

        summary = get_abuseipdb_summary(ctx)

        assert summary["ip"] == "8.8.8.8"
        assert summary["abuse_confidence_score"] == 0
        assert summary["is_whitelisted"] is True

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_abuseipdb_summary(ctx)

        assert summary["ip"] == ""
        assert summary["abuse_confidence_score"] == 0
        assert summary["is_whitelisted"] is False
