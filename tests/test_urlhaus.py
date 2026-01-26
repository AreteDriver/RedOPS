"""Tests for the URLhaus threat intelligence module."""

import pytest
from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.modules.threat_intel.urlhaus import (
    check_url,
    check_host,
    check_payload,
    get_recent_urls,
    analyze_urlhaus_results,
    get_urlhaus_summary,
    HAS_REQUESTS,
)


class TestCheckUrl:
    """Tests for check_url function."""

    def test_no_target(self):
        """Test handling when no target specified."""
        ctx = Context()
        result = check_url(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No URL" in log["message"] for log in warnings)

    def test_no_requests_library(self):
        """Test handling when requests library not available."""
        with patch("redops.modules.threat_intel.urlhaus.HAS_REQUESTS", False):
            ctx = Context(target="http://malware.example.com/bad.exe")
            result = check_url(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("requests library" in log["message"] for log in warnings)

    @patch("redops.modules.threat_intel.urlhaus._query_url")
    def test_url_not_found(self, mock_query):
        """Test URL not found in database."""
        mock_query.return_value = {
            "query_status": "no_results",
            "queried_url": "http://safe.example.com",
        }

        ctx = Context(target="http://safe.example.com")
        result = check_url(ctx)

        assert result.data["urlhaus_status"] == "no_results"

    @patch("redops.modules.threat_intel.urlhaus._query_url")
    def test_malicious_url_found(self, mock_query):
        """Test malicious URL found."""
        mock_query.return_value = {
            "query_status": "ok",
            "queried_url": "http://malware.example.com/bad.exe",
            "threat": "malware_download",
            "url_status": "online",
            "date_added": "2024-01-01",
            "tags": ["elf", "Mirai"],
        }

        ctx = Context(target="http://malware.example.com/bad.exe")
        result = check_url(ctx)

        assert result.data["urlhaus_status"] == "ok"
        assert result.data["urlhaus_threat"] == "malware_download"


class TestCheckHost:
    """Tests for check_host function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.urlhaus.HAS_REQUESTS", False):
            result = check_host("malware.example.com")
            assert "error" in result

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_host_found(self, mock_requests):
        """Test host found in database."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "url_count": 5,
            "urls": [
                {"url": "http://malware.example.com/1.exe", "url_status": "online"},
                {"url": "http://malware.example.com/2.exe", "url_status": "offline"},
            ],
        }
        mock_requests.post.return_value = mock_response

        result = check_host("malware.example.com")

        assert result["query_status"] == "ok"
        assert result["url_count"] == 5

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_host_not_found(self, mock_requests):
        """Test host not found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_requests.post.return_value = mock_response

        result = check_host("safe.example.com")

        assert result["query_status"] == "no_results"

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_request_error(self, mock_requests):
        """Test request error handling."""
        import requests as real_requests
        mock_requests.post.side_effect = real_requests.exceptions.RequestException("Network error")
        mock_requests.exceptions = real_requests.exceptions

        result = check_host("example.com")

        assert "error" in result


class TestCheckPayload:
    """Tests for check_payload function."""

    def test_no_hash(self):
        """Test when no hash provided."""
        result = check_payload()
        assert "error" in result
        assert "No hash" in result["error"]

    def test_invalid_hash_length(self):
        """Test invalid hash length."""
        result = check_payload(payload_hash="abc123")
        assert "error" in result
        assert "Invalid hash" in result["error"]

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.urlhaus.HAS_REQUESTS", False):
            result = check_payload(md5="d41d8cd98f00b204e9800998ecf8427e")
            assert "error" in result

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_md5_lookup(self, mock_requests):
        """Test MD5 hash lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "signature": "Mirai",
            "file_type": "elf",
            "firstseen": "2024-01-01",
            "url_count": 10,
        }
        mock_requests.post.return_value = mock_response

        result = check_payload(md5="d41d8cd98f00b204e9800998ecf8427e")

        assert result["query_status"] == "ok"
        assert result["hash_type"] == "md5_hash"

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_sha256_lookup(self, mock_requests):
        """Test SHA256 hash lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "signature": "Emotet",
            "file_type": "exe",
        }
        mock_requests.post.return_value = mock_response

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = check_payload(sha256=sha256)

        assert result["hash_type"] == "sha256_hash"

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_payload_not_found(self, mock_requests):
        """Test payload not found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "no_results",
        }
        mock_requests.post.return_value = mock_response

        result = check_payload(md5="00000000000000000000000000000000")

        assert result["query_status"] == "no_results"


class TestGetRecentUrls:
    """Tests for get_recent_urls function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.urlhaus.HAS_REQUESTS", False):
            result = get_recent_urls()
            assert result == []

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_get_recent(self, mock_requests):
        """Test getting recent URLs."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "urls": [
                {"url": "http://malware1.com/bad.exe", "threat": "malware_download"},
                {"url": "http://malware2.com/bad.exe", "threat": "malware_download"},
            ]
        }
        mock_requests.get.return_value = mock_response

        result = get_recent_urls(limit=10)

        assert len(result) == 2

    @patch("redops.modules.threat_intel.urlhaus.requests")
    def test_get_recent_error(self, mock_requests):
        """Test error handling."""
        mock_requests.get.side_effect = Exception("API error")

        result = get_recent_urls()

        assert result == []


class TestAnalyzeUrlhausResults:
    """Tests for analyze_urlhaus_results function."""

    def test_error_result(self):
        """Test no findings for error results."""
        result = {"error": "API failed"}
        findings = analyze_urlhaus_results(result, "http://example.com")
        assert len(findings) == 0

    def test_malicious_url_online(self):
        """Test finding for online malicious URL."""
        result = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "date_added": "2024-01-01",
            "tags": ["exe", "Emotet"],
        }

        findings = analyze_urlhaus_results(result, "http://malware.example.com")

        assert any("Malicious URL" in f.title for f in findings)
        assert any(f.severity.name == "CRITICAL" for f in findings)

    def test_malicious_url_offline(self):
        """Test finding for offline malicious URL."""
        result = {
            "query_status": "ok",
            "threat": "malware",
            "url_status": "offline",
            "date_added": "2024-01-01",
            "tags": [],
        }

        findings = analyze_urlhaus_results(result, "http://malware.example.com")

        assert any("Malicious URL" in f.title for f in findings)
        assert any(f.severity.name == "HIGH" for f in findings)

    def test_malware_distribution_site(self):
        """Test finding for malware distribution site."""
        result = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "date_added": "2024-01-01",
            "tags": [],
        }

        findings = analyze_urlhaus_results(result, "http://malware.example.com")

        assert any("Malware Distribution" in f.title for f in findings)

    def test_payloads_associated(self):
        """Test finding for associated payloads."""
        result = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "date_added": "2024-01-01",
            "tags": [],
            "payloads": [
                {"signature": "Mirai", "sha256_hash": "abc123"},
                {"signature": "Emotet", "sha256_hash": "def456"},
                {"signature": "Mirai", "sha256_hash": "ghi789"},
            ],
        }

        findings = analyze_urlhaus_results(result, "http://malware.example.com")

        assert any("Malware Payloads" in f.title for f in findings)
        payload_finding = next(f for f in findings if "Payloads" in f.title)
        assert "3 samples" in payload_finding.title

    def test_host_with_multiple_urls(self):
        """Test finding for host with multiple malicious URLs."""
        result = {
            "query_status": "ok",
            "url_count": 15,
            "urls": [
                {"url_status": "online"},
                {"url_status": "online"},
                {"url_status": "offline"},
            ],
        }

        findings = analyze_urlhaus_results(result, "malware.example.com")

        assert any("Malicious Host" in f.title for f in findings)

    def test_known_malware_payload(self):
        """Test finding for known malware payload."""
        result = {
            "query_status": "ok",
            "signature": "Mirai",
            "file_type": "elf",
            "firstseen": "2024-01-01",
            "url_count": 50,
            "queried_hash": "abc123def456",
        }

        findings = analyze_urlhaus_results(result, "abc123def456")

        assert any("Known Malware: Mirai" in f.title for f in findings)
        assert any(f.severity.name == "CRITICAL" for f in findings)


class TestGetUrlhausSummary:
    """Tests for get_urlhaus_summary function."""

    def test_with_url_results(self):
        """Test summary with URL results."""
        ctx = Context()
        ctx.add("urlhaus_result", {
            "queried_url": "http://malware.example.com/bad.exe",
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "date_added": "2024-01-01",
            "tags": ["exe", "Emotet"],
            "payloads": [{"signature": "Emotet"}],
            "query_timestamp": "2024-01-01T00:00:00",
        })

        summary = get_urlhaus_summary(ctx)

        assert summary["url"] == "http://malware.example.com/bad.exe"
        assert summary["query_status"] == "ok"
        assert summary["threat"] == "malware_download"
        assert summary["payload_count"] == 1

    def test_with_host_results(self):
        """Test summary with host results."""
        ctx = Context()
        ctx.add("urlhaus_result", {
            "queried_host": "malware.example.com",
            "query_status": "ok",
            "query_timestamp": "2024-01-01T00:00:00",
        })

        summary = get_urlhaus_summary(ctx)

        assert summary["url"] == "malware.example.com"

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_urlhaus_summary(ctx)

        assert summary["url"] == ""
        assert summary["query_status"] == ""
        assert summary["payload_count"] == 0
