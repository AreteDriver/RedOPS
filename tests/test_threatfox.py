"""Tests for the ThreatFox threat intelligence module."""

import pytest
from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.modules.threat_intel.threatfox import (
    query_ioc,
    search_malware,
    get_recent_iocs,
    get_ioc_by_id,
    get_tag_iocs,
    analyze_threatfox_results,
    get_threatfox_summary,
)


class TestQueryIoc:
    """Tests for query_ioc function."""

    def test_no_target(self):
        """Test handling when no IOC specified."""
        ctx = Context()
        result = query_ioc(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No IOC specified" in log["message"] for log in warnings)

    def test_no_requests_library(self):
        """Test handling when requests library not available."""
        with patch("redops.modules.threat_intel.threatfox.HAS_REQUESTS", False):
            ctx = Context(target="example.com")
            result = query_ioc(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("requests library" in log["message"] for log in warnings)

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_successful_query(self, mock_api):
        """Test successful IOC query."""
        mock_api.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "evil.example.com",
                    "malware": "Emotet",
                    "threat_type": "botnet_cc",
                    "confidence_level": 90,
                    "first_seen": "2024-01-01",
                }
            ],
        }

        ctx = Context(target="evil.example.com")
        result = query_ioc(ctx)

        assert "threatfox_result" in result.data
        assert result.data["threatfox_ioc_count"] == 1

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_ioc_not_found(self, mock_api):
        """Test IOC not in database."""
        mock_api.return_value = {
            "query_status": "no_result",
            "data": [],
        }

        ctx = Context(target="clean.example.com")
        result = query_ioc(ctx)

        assert result.data["threatfox_ioc_count"] == 0

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_api_error(self, mock_api):
        """Test handling API errors."""
        mock_api.return_value = {"error": "API rate limit exceeded"}

        ctx = Context(target="example.com")
        result = query_ioc(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("failed" in log["message"] for log in warnings)


class TestSearchMalware:
    """Tests for search_malware function."""

    def test_no_malware_specified(self):
        """Test handling when no malware specified."""
        ctx = Context()
        result = search_malware(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No malware family" in log["message"] for log in warnings)

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_successful_search(self, mock_api):
        """Test successful malware search."""
        mock_api.return_value = {
            "query_status": "ok",
            "data": [
                {"ioc": "evil1.com", "malware": "Emotet"},
                {"ioc": "evil2.com", "malware": "Emotet"},
            ],
        }

        ctx = Context()
        result = search_malware(ctx, {"malware": "Emotet"})

        assert "threatfox_malware_result" in result.data
        assert result.data["threatfox_malware_iocs"] == 2


class TestGetRecentIocs:
    """Tests for get_recent_iocs function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.threatfox.HAS_REQUESTS", False):
            ctx = Context()
            result = get_recent_iocs(ctx)

            warnings = result.get_logs(level="WARNING")
            assert any("requests library" in log["message"] for log in warnings)

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_successful_recent(self, mock_api):
        """Test successful recent IOCs retrieval."""
        mock_api.return_value = {
            "query_status": "ok",
            "data": [{"ioc": f"ioc{i}.com"} for i in range(10)],
        }

        ctx = Context()
        result = get_recent_iocs(ctx, {"days": 1})

        assert "threatfox_recent_iocs" in result.data
        assert result.data["threatfox_recent_count"] == 10

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_days_clamped(self, mock_api):
        """Test days parameter is clamped to 1-7."""
        mock_api.return_value = {"query_status": "ok", "data": []}

        ctx = Context()
        # Should clamp to 7
        get_recent_iocs(ctx, {"days": 30})
        # Should clamp to 1
        get_recent_iocs(ctx, {"days": 0})


class TestGetIocById:
    """Tests for get_ioc_by_id function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.threatfox.HAS_REQUESTS", False):
            result = get_ioc_by_id("12345")
            assert "error" in result

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_successful_lookup(self, mock_api):
        """Test successful IOC ID lookup."""
        mock_api.return_value = {
            "query_status": "ok",
            "data": {"id": "12345", "ioc": "evil.com"},
        }

        result = get_ioc_by_id("12345")
        assert result["data"]["id"] == "12345"


class TestGetTagIocs:
    """Tests for get_tag_iocs function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.threatfox.HAS_REQUESTS", False):
            result = get_tag_iocs("c2")
            assert "error" in result

    @patch("redops.modules.threat_intel.threatfox._query_api")
    def test_successful_tag_lookup(self, mock_api):
        """Test successful tag IOC lookup."""
        mock_api.return_value = {
            "query_status": "ok",
            "data": [{"ioc": "evil.com", "tags": ["c2"]}],
        }

        result = get_tag_iocs("c2", limit=50)
        assert "data" in result


class TestAnalyzeThreatfoxResults:
    """Tests for analyze_threatfox_results function."""

    def test_error_result(self):
        """Test no findings for error results."""
        result = {"error": "API failed"}
        findings = analyze_threatfox_results(result, "example.com")
        assert len(findings) == 0

    def test_no_result(self):
        """Test no findings for empty results."""
        result = {"query_status": "no_result", "data": []}
        findings = analyze_threatfox_results(result, "example.com")
        assert len(findings) == 0

    def test_malware_ioc_finding(self):
        """Test finding for malware IOC."""
        result = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "evil.example.com",
                    "malware": "Emotet",
                    "threat_type": "botnet_cc",
                    "confidence_level": 90,
                    "first_seen": "2024-01-01",
                }
            ],
        }

        findings = analyze_threatfox_results(result, "evil.example.com")

        assert len(findings) >= 1
        assert any("Malware IOC" in f.title for f in findings)
        assert any("Emotet" in f.description for f in findings)

    def test_c2_finding(self):
        """Test finding for C2 infrastructure."""
        result = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "c2.example.com",
                    "malware": "Cobalt Strike",
                    "threat_type": "botnet_cc",
                    "confidence_level": 95,
                }
            ],
        }

        findings = analyze_threatfox_results(result, "c2.example.com")

        assert any("C2 Infrastructure" in f.title for f in findings)
        assert any(f.severity.name == "CRITICAL" for f in findings)

    def test_high_confidence_critical_severity(self):
        """Test CRITICAL severity for high confidence."""
        result = {
            "query_status": "ok",
            "data": [
                {"confidence_level": 85, "malware": "Ransomware"},
                {"confidence_level": 80, "malware": "Ransomware"},
            ],
        }

        findings = analyze_threatfox_results(result, "bad.com")

        malware_finding = next((f for f in findings if "Malware IOC" in f.title), None)
        assert malware_finding is not None
        assert malware_finding.severity.name == "CRITICAL"

    def test_medium_confidence_high_severity(self):
        """Test HIGH severity for medium confidence."""
        result = {
            "query_status": "ok",
            "data": [
                {"confidence_level": 60, "malware": "Trojan"},
            ],
        }

        findings = analyze_threatfox_results(result, "suspicious.com")

        malware_finding = next((f for f in findings if "Malware IOC" in f.title), None)
        assert malware_finding is not None
        assert malware_finding.severity.name == "HIGH"

    def test_low_confidence_low_severity(self):
        """Test LOW severity for low confidence."""
        result = {
            "query_status": "ok",
            "data": [
                {"confidence_level": 20, "malware": "Unknown"},
            ],
        }

        findings = analyze_threatfox_results(result, "maybe-bad.com")

        malware_finding = next((f for f in findings if "Malware IOC" in f.title), None)
        assert malware_finding is not None
        assert malware_finding.severity.name == "LOW"

    def test_multiple_malware_families(self):
        """Test findings with multiple malware families."""
        result = {
            "query_status": "ok",
            "data": [
                {"malware": "Emotet", "threat_type": "payload"},
                {"malware": "TrickBot", "threat_type": "payload"},
                {"malware": "Emotet", "threat_type": "c2"},
            ],
        }

        findings = analyze_threatfox_results(result, "multi.example.com")

        malware_finding = next((f for f in findings if "Malware IOC" in f.title), None)
        assert malware_finding is not None
        assert "Emotet" in malware_finding.description
        assert "TrickBot" in malware_finding.description


class TestGetThreatfoxSummary:
    """Tests for get_threatfox_summary function."""

    def test_with_results(self):
        """Test summary with results."""
        ctx = Context()
        ctx.add("threatfox_result", {
            "queried_ioc": "evil.com",
            "data": [
                {"malware": "Emotet", "threat_type": "botnet_cc"},
                {"malware": "TrickBot", "threat_type": "payload"},
            ],
            "query_timestamp": "2024-01-01T00:00:00",
        })

        summary = get_threatfox_summary(ctx)

        assert summary["queried_ioc"] == "evil.com"
        assert summary["entry_count"] == 2
        assert "Emotet" in summary["malware_families"]
        assert "TrickBot" in summary["malware_families"]

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_threatfox_summary(ctx)

        assert summary["queried_ioc"] == ""
        assert summary["entry_count"] == 0
        assert summary["malware_families"] == []

    def test_with_empty_data(self):
        """Test summary with empty data list."""
        ctx = Context()
        ctx.add("threatfox_result", {
            "queried_ioc": "clean.com",
            "data": [],
            "query_timestamp": "2024-01-01T00:00:00",
        })

        summary = get_threatfox_summary(ctx)

        assert summary["queried_ioc"] == "clean.com"
        assert summary["entry_count"] == 0

    def test_with_none_data(self):
        """Test summary with None data."""
        ctx = Context()
        ctx.add("threatfox_result", {
            "queried_ioc": "unknown.com",
            "data": None,
            "query_timestamp": "2024-01-01T00:00:00",
        })

        summary = get_threatfox_summary(ctx)

        assert summary["entry_count"] == 0
