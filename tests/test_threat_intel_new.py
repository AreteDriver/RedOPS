"""Tests for new threat intelligence modules: URLScan.io, PassiveDNS, AlienVault OTX."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from redops.core.context import Context


class TestURLScanModule:
    """Tests for URLScan.io integration."""

    def test_scan_url_no_requests(self):
        """Test scan_url when requests not available."""
        with patch("redops.modules.threat_intel.urlscan.HAS_REQUESTS", False):
            from redops.modules.threat_intel.urlscan import scan_url

            ctx = Context(target="https://example.com")
            result = scan_url(ctx, {})

            assert "urlscan_result" not in ctx.data

    def test_scan_url_no_url(self):
        """Test scan_url with no URL specified."""
        with patch("redops.modules.threat_intel.urlscan.HAS_REQUESTS", True):
            from redops.modules.threat_intel.urlscan import scan_url

            ctx = Context(target=None)
            result = scan_url(ctx, {})

            assert "urlscan_result" not in ctx.data

    def test_scan_url_no_api_key(self):
        """Test scan_url without API key."""
        with patch("redops.modules.threat_intel.urlscan.HAS_REQUESTS", True):
            with patch.dict("os.environ", {}, clear=True):
                from redops.modules.threat_intel.urlscan import scan_url

                ctx = Context(target="https://example.com")
                result = scan_url(ctx, {})

                assert ctx.get("urlscan_result", {}).get("error") == "API key required"

    @patch("redops.modules.threat_intel.urlscan.requests")
    def test_scan_url_success(self, mock_requests):
        """Test successful URL scan submission."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "uuid": "test-uuid-123",
            "result": "https://urlscan.io/result/test-uuid-123",
            "api": "https://urlscan.io/api/v1/result/test-uuid-123",
        }
        mock_requests.post.return_value = mock_response

        # Mock the wait for result
        mock_result_response = MagicMock()
        mock_result_response.status_code = 200
        mock_result_response.json.return_value = {
            "verdicts": {"overall": {"malicious": False}},
            "page": {"url": "https://example.com"},
        }
        mock_requests.get.return_value = mock_result_response

        with patch("redops.modules.threat_intel.urlscan.HAS_REQUESTS", True):
            from redops.modules.threat_intel.urlscan import scan_url

            ctx = Context(target="https://example.com")
            result = scan_url(ctx, {"api_key": "test-key", "wait_for_result": True})

            assert "urlscan_result" in ctx.data
            assert ctx.data["urlscan_result"]["uuid"] == "test-uuid-123"

    @patch("redops.modules.threat_intel.urlscan.requests")
    def test_scan_url_rate_limit(self, mock_requests):
        """Test rate limit handling."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.threat_intel.urlscan.HAS_REQUESTS", True):
            from redops.modules.threat_intel.urlscan import scan_url

            ctx = Context(target="https://example.com")
            result = scan_url(ctx, {"api_key": "test-key"})

            assert ctx.get("urlscan_result", {}).get("error") == "Rate limit exceeded"

    @patch("redops.modules.threat_intel.urlscan.requests")
    def test_search_urlscan_success(self, mock_requests):
        """Test URLScan.io search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"page": {"domain": "example.com"}, "verdicts": {"overall": {"malicious": False}}},
                {"page": {"domain": "example.com"}, "verdicts": {"overall": {"malicious": True}}},
            ],
            "total": 2,
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.urlscan.HAS_REQUESTS", True):
            from redops.modules.threat_intel.urlscan import search_urlscan

            ctx = Context(target="example.com")
            result = search_urlscan(ctx, {"api_key": "test-key"})

            assert "urlscan_search" in ctx.data
            assert ctx.data["urlscan_search"]["total"] == 2
            assert ctx.data["urlscan_search"]["malicious_count"] == 1

    def test_analyze_urlscan_results_malicious(self):
        """Test analysis of malicious URLScan results."""
        from redops.modules.threat_intel.urlscan import analyze_urlscan_results

        result = {
            "verdicts": {
                "overall": {"malicious": True, "score": 85},
                "urlscan": {"malicious": True, "categories": ["phishing"]},
            },
            "page": {"url": "https://bad.example.com", "title": "Login"},
            "lists": {
                "domains": ["evil.com", "bad.com"],
                "ips": ["1.2.3.4"],
            },
            "data": {"requests": [1, 2, 3]},
        }

        analysis = analyze_urlscan_results(result)

        assert analysis["is_malicious"] is True
        assert analysis["verdict"] == "malicious"
        assert analysis["score"] == 85
        assert "phishing" in analysis["categories"]

    def test_analyze_urlscan_results_clean(self):
        """Test analysis of clean URLScan results."""
        from redops.modules.threat_intel.urlscan import analyze_urlscan_results

        result = {
            "verdicts": {"overall": {"malicious": False}},
            "page": {"url": "https://good.example.com"},
        }

        analysis = analyze_urlscan_results(result)

        assert analysis["is_malicious"] is False
        assert analysis["verdict"] == "clean"

    def test_get_urlscan_summary(self):
        """Test summary generation."""
        from redops.modules.threat_intel.urlscan import get_urlscan_summary

        result = {
            "analysis": {
                "verdict": "malicious",
                "is_malicious": True,
                "score": 90,
                "threats": [{"source": "urlscan"}],
                "final_url": "https://example.com",
                "requests_count": 10,
                "domains_contacted": ["a.com"],
                "ips_contacted": ["1.2.3.4"],
            }
        }

        summary = get_urlscan_summary(result)

        assert "MALICIOUS" in summary
        assert "90/100" in summary


class TestPassiveDNSModule:
    """Tests for Passive DNS integration."""

    def test_query_passivedns_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", False):
            from redops.modules.threat_intel.passivedns import query_passivedns

            ctx = Context(target="example.com")
            result = query_passivedns(ctx, {})

            assert "passivedns_result" not in ctx.data

    def test_query_passivedns_no_query(self):
        """Test with no query specified."""
        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", True):
            from redops.modules.threat_intel.passivedns import query_passivedns

            ctx = Context(target=None)
            result = query_passivedns(ctx, {})

            assert "passivedns_result" not in ctx.data

    @patch("redops.modules.threat_intel.passivedns.requests")
    def test_query_passivedns_mnemonic_success(self, mock_requests):
        """Test successful Mnemonic query."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "query": "example.com",
                    "rrtype": "A",
                    "answer": "93.184.216.34",
                    "firstSeenTimestamp": "2020-01-01T00:00:00Z",
                    "lastSeenTimestamp": "2024-01-01T00:00:00Z",
                }
            ]
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", True):
            from redops.modules.threat_intel.passivedns import query_passivedns

            ctx = Context(target="example.com")
            result = query_passivedns(ctx, {"api_key": "test-key", "source": "mnemonic"})

            assert "passivedns_result" in ctx.data
            assert len(ctx.data["passivedns_result"]["records"]) == 1
            assert "mnemonic" in ctx.data["passivedns_result"]["sources"]

    @patch("redops.modules.threat_intel.passivedns.requests")
    def test_query_passivedns_circl_success(self, mock_requests):
        """Test successful CIRCL query."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"rrname": "example.com", "rrtype": "A", "rdata": "93.184.216.34"}'
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", True):
            from redops.modules.threat_intel.passivedns import query_passivedns

            ctx = Context(target="example.com")
            result = query_passivedns(ctx, {"source": "circl"})

            assert "passivedns_result" in ctx.data
            assert "circl" in ctx.data["passivedns_result"]["sources"]

    @patch("redops.modules.threat_intel.passivedns.requests")
    def test_query_passivedns_auth_required(self, mock_requests):
        """Test authentication required response."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", True):
            from redops.modules.threat_intel.passivedns import query_passivedns

            ctx = Context(target="example.com")
            result = query_passivedns(ctx, {"source": "mnemonic"})

            assert "passivedns_result" in ctx.data
            assert "mnemonic_error" in ctx.data["passivedns_result"]

    def test_detect_query_type_ipv4(self):
        """Test IP detection."""
        from redops.modules.threat_intel.passivedns import _detect_query_type

        assert _detect_query_type("192.168.1.1") == "ip"
        assert _detect_query_type("10.0.0.1") == "ip"

    def test_detect_query_type_ipv6(self):
        """Test IPv6 detection."""
        from redops.modules.threat_intel.passivedns import _detect_query_type

        assert _detect_query_type("2001:db8::1") == "ip"

    def test_detect_query_type_domain(self):
        """Test domain detection."""
        from redops.modules.threat_intel.passivedns import _detect_query_type

        assert _detect_query_type("example.com") == "domain"
        assert _detect_query_type("sub.example.com") == "domain"

    def test_analyze_passivedns_high_ip_churn(self):
        """Test detection of high IP churn."""
        from redops.modules.threat_intel.passivedns import analyze_passivedns_results

        results = {
            "query_type": "domain",
            "records": [
                {"rrname": "example.com", "rrtype": "A", "rdata": f"1.2.3.{i}"}
                for i in range(15)
            ],
        }

        analysis = analyze_passivedns_results(results)

        assert len(analysis["unique_ips"]) == 15
        assert any(p["type"] == "high_ip_churn" for p in analysis["suspicious_patterns"])

    def test_analyze_passivedns_high_domain_count(self):
        """Test detection of high domain count on IP."""
        from redops.modules.threat_intel.passivedns import analyze_passivedns_results

        results = {
            "query_type": "ip",
            "records": [
                {"rrname": f"domain{i}.com", "rrtype": "A", "rdata": "1.2.3.4"}
                for i in range(55)
            ],
        }

        analysis = analyze_passivedns_results(results)

        assert len(analysis["unique_domains"]) == 55
        assert any(p["type"] == "high_domain_count" for p in analysis["suspicious_patterns"])

    def test_get_passivedns_summary(self):
        """Test summary generation."""
        from redops.modules.threat_intel.passivedns import get_passivedns_summary

        result = {
            "query": "example.com",
            "analysis": {
                "total_records": 10,
                "unique_ips": ["1.2.3.4", "5.6.7.8"],
                "unique_domains": ["example.com"],
                "record_types": {"A": 5, "AAAA": 2, "MX": 3},
                "suspicious_patterns": [{"type": "test"}],
            },
        }

        summary = get_passivedns_summary(result)

        assert "example.com" in summary
        assert "Records: 10" in summary
        assert "Warnings: 1" in summary

    @patch("redops.modules.threat_intel.passivedns.requests")
    def test_get_domain_history_success(self, mock_requests):
        """Test getting domain IP history."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "query": "example.com",
                    "rrtype": "A",
                    "answer": "1.2.3.4",
                    "firstSeenTimestamp": "2020-01-01T00:00:00Z",
                    "lastSeenTimestamp": "2024-01-01T00:00:00Z",
                },
                {
                    "query": "example.com",
                    "rrtype": "A",
                    "answer": "5.6.7.8",
                    "firstSeenTimestamp": "2019-01-01T00:00:00Z",
                    "lastSeenTimestamp": "2020-01-01T00:00:00Z",
                },
            ]
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", True):
            from redops.modules.threat_intel.passivedns import get_domain_history

            ctx = Context(target="example.com")
            result = get_domain_history(ctx, {"api_key": "test-key"})

            assert "domain_ip_history" in ctx.data
            assert len(ctx.data["domain_ip_history"]["ip_addresses"]) == 2

    @patch("redops.modules.threat_intel.passivedns.requests")
    def test_get_ip_history_success(self, mock_requests):
        """Test getting IP domain history."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [
                {
                    "query": "domain1.com",
                    "rrtype": "A",
                    "answer": "1.2.3.4",
                },
                {
                    "query": "domain2.com",
                    "rrtype": "A",
                    "answer": "1.2.3.4",
                },
            ]
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.passivedns.HAS_REQUESTS", True):
            from redops.modules.threat_intel.passivedns import get_ip_history

            ctx = Context(target="1.2.3.4")
            result = get_ip_history(ctx, {"api_key": "test-key"})

            assert "ip_domain_history" in ctx.data
            assert len(ctx.data["ip_domain_history"]["domains"]) == 2


class TestAlienVaultOTXModule:
    """Tests for AlienVault OTX integration."""

    def test_get_indicator_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", False):
            from redops.modules.threat_intel.alienvault import get_indicator

            ctx = Context(target="1.2.3.4")
            result = get_indicator(ctx, {})

            assert "otx_indicator" not in ctx.data

    def test_get_indicator_no_indicator(self):
        """Test with no indicator specified."""
        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import get_indicator

            ctx = Context(target=None)
            result = get_indicator(ctx, {})

            assert "otx_indicator" not in ctx.data

    def test_get_indicator_no_api_key(self):
        """Test without API key."""
        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            with patch.dict("os.environ", {}, clear=True):
                from redops.modules.threat_intel.alienvault import get_indicator

                ctx = Context(target="1.2.3.4")
                result = get_indicator(ctx, {})

                assert ctx.get("otx_indicator", {}).get("error") == "API key required"

    @patch("redops.modules.threat_intel.alienvault.requests")
    def test_get_indicator_success(self, mock_requests):
        """Test successful indicator query."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {"tags": ["malware"], "malware_families": ["emotet"]},
                ],
            },
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import get_indicator

            ctx = Context(target="1.2.3.4")
            result = get_indicator(ctx, {"api_key": "test-key", "sections": ["general"]})

            assert "otx_indicator" in ctx.data
            assert ctx.data["otx_indicator"]["indicator"] == "1.2.3.4"

    def test_detect_indicator_type_ipv4(self):
        """Test IPv4 detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        assert _detect_indicator_type("1.2.3.4") == "IPv4"
        assert _detect_indicator_type("192.168.1.1") == "IPv4"

    def test_detect_indicator_type_ipv6(self):
        """Test IPv6 detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        assert _detect_indicator_type("2001:db8::1") == "IPv6"

    def test_detect_indicator_type_url(self):
        """Test URL detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        assert _detect_indicator_type("https://example.com/path") == "url"
        assert _detect_indicator_type("http://bad.com") == "url"

    def test_detect_indicator_type_md5(self):
        """Test MD5 hash detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        assert _detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "file"

    def test_detect_indicator_type_sha1(self):
        """Test SHA1 hash detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        assert _detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "file"

    def test_detect_indicator_type_sha256(self):
        """Test SHA256 hash detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        hash_256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _detect_indicator_type(hash_256) == "file"

    def test_detect_indicator_type_domain(self):
        """Test domain detection."""
        from redops.modules.threat_intel.alienvault import _detect_indicator_type

        assert _detect_indicator_type("example.com") == "domain"
        assert _detect_indicator_type("sub.example.com") == "domain"

    def test_analyze_otx_indicator_malicious(self):
        """Test analysis of malicious indicator."""
        from redops.modules.threat_intel.alienvault import analyze_otx_indicator

        result = {
            "sections": {
                "general": {
                    "pulse_info": {
                        "count": 5,
                        "pulses": [
                            {
                                "tags": ["malware", "emotet"],
                                "malware_families": ["emotet"],
                                "targeted_countries": ["US"],
                            }
                        ],
                    },
                },
                "malware": {"count": 3},
            }
        }

        analysis = analyze_otx_indicator(result)

        assert analysis["is_malicious"] is True
        assert analysis["pulse_count"] == 5
        assert analysis["malware_samples"] == 3
        assert "malware" in analysis["tags"]
        assert "emotet" in analysis["malware_families"]

    def test_analyze_otx_indicator_clean(self):
        """Test analysis of clean indicator."""
        from redops.modules.threat_intel.alienvault import analyze_otx_indicator

        result = {
            "sections": {
                "general": {
                    "pulse_info": {"count": 0, "pulses": []},
                },
            }
        }

        analysis = analyze_otx_indicator(result)

        assert analysis["is_malicious"] is False
        assert analysis["pulse_count"] == 0

    @patch("redops.modules.threat_intel.alienvault.requests")
    def test_get_pulses_success(self, mock_requests):
        """Test getting subscribed pulses."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "id": "pulse-1",
                    "name": "Test Pulse",
                    "description": "A test pulse",
                    "author_name": "test_author",
                    "indicators": [{"indicator": "1.2.3.4"}],
                    "tags": ["test"],
                }
            ],
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import get_pulses

            ctx = Context(target="test")
            result = get_pulses(ctx, {"api_key": "test-key"})

            assert "otx_pulses" in ctx.data
            assert ctx.data["otx_pulses"]["count"] == 1
            assert ctx.data["otx_pulses"]["pulses"][0]["name"] == "Test Pulse"

    @patch("redops.modules.threat_intel.alienvault.requests")
    def test_get_pulses_auth_failed(self, mock_requests):
        """Test authentication failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import get_pulses

            ctx = Context(target="test")
            result = get_pulses(ctx, {"api_key": "bad-key"})

            assert ctx.get("otx_pulses", {}).get("error") == "Authentication failed"

    @patch("redops.modules.threat_intel.alienvault.requests")
    def test_search_pulses_success(self, mock_requests):
        """Test pulse search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "id": "pulse-1",
                    "name": "APT28",
                    "description": "Russian APT",
                    "author_name": "researcher",
                    "indicators": [],
                    "tags": ["apt", "russia"],
                }
            ],
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import search_pulses

            ctx = Context(target="APT28")
            result = search_pulses(ctx, {"api_key": "test-key"})

            assert "otx_pulse_search" in ctx.data
            assert ctx.data["otx_pulse_search"]["count"] == 1

    @patch("redops.modules.threat_intel.alienvault.requests")
    def test_get_pulse_details_success(self, mock_requests):
        """Test getting pulse details."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "pulse-123",
            "name": "Test Pulse",
            "description": "Detailed description",
            "author_name": "researcher",
            "tags": ["malware"],
            "indicators": [
                {"type": "IPv4", "indicator": "1.2.3.4"},
                {"type": "domain", "indicator": "evil.com"},
            ],
            "references": ["https://example.com/report"],
        }
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import get_pulse_details

            ctx = Context(target="test")
            result = get_pulse_details(ctx, {"api_key": "test-key", "pulse_id": "pulse-123"})

            assert "otx_pulse_details" in ctx.data
            assert ctx.data["otx_pulse_details"]["indicator_count"] == 2
            assert "IPv4" in ctx.data["otx_pulse_details"]["indicators_by_type"]

    @patch("redops.modules.threat_intel.alienvault.requests")
    def test_get_pulse_details_not_found(self, mock_requests):
        """Test pulse not found."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        with patch("redops.modules.threat_intel.alienvault.HAS_REQUESTS", True):
            from redops.modules.threat_intel.alienvault import get_pulse_details

            ctx = Context(target="test")
            result = get_pulse_details(ctx, {"api_key": "test-key", "pulse_id": "invalid"})

            assert ctx.get("otx_pulse_details", {}).get("error") == "Pulse not found"

    def test_get_otx_summary_malicious(self):
        """Test malicious summary generation."""
        from redops.modules.threat_intel.alienvault import get_otx_summary

        result = {
            "indicator": "1.2.3.4",
            "analysis": {
                "is_malicious": True,
                "pulse_count": 10,
                "malware_samples": 5,
                "tags": ["emotet", "malware", "trojan"],
                "malware_families": ["emotet", "trickbot"],
                "country_code": "RU",
            },
        }

        summary = get_otx_summary(result)

        assert "1.2.3.4" in summary
        assert "MALICIOUS" in summary
        assert "Pulses: 10" in summary
        assert "emotet" in summary
        assert "RU" in summary

    def test_get_otx_summary_clean(self):
        """Test clean summary generation."""
        from redops.modules.threat_intel.alienvault import get_otx_summary

        result = {
            "indicator": "8.8.8.8",
            "analysis": {
                "is_malicious": False,
                "pulse_count": 0,
            },
        }

        summary = get_otx_summary(result)

        assert "Clean" in summary

    def test_get_otx_summary_error(self):
        """Test error summary."""
        from redops.modules.threat_intel.alienvault import get_otx_summary

        result = {"error": "API key required"}

        summary = get_otx_summary(result)

        assert "error" in summary.lower()


class TestModuleImports:
    """Test that all new modules are properly exported."""

    def test_urlscan_imports(self):
        """Test URLScan.io module imports."""
        from redops.modules.threat_intel import (
            scan_url,
            search_urlscan,
            get_scan_result,
            analyze_urlscan_results,
            get_urlscan_summary,
        )

        assert callable(scan_url)
        assert callable(search_urlscan)
        assert callable(get_scan_result)
        assert callable(analyze_urlscan_results)
        assert callable(get_urlscan_summary)

    def test_passivedns_imports(self):
        """Test PassiveDNS module imports."""
        from redops.modules.threat_intel import (
            query_passivedns,
            get_domain_history,
            get_ip_history,
            analyze_passivedns_results,
            get_passivedns_summary,
        )

        assert callable(query_passivedns)
        assert callable(get_domain_history)
        assert callable(get_ip_history)
        assert callable(analyze_passivedns_results)
        assert callable(get_passivedns_summary)

    def test_alienvault_imports(self):
        """Test AlienVault OTX module imports."""
        from redops.modules.threat_intel import (
            get_indicator,
            get_pulses,
            search_pulses,
            get_pulse_details,
            analyze_otx_indicator,
            get_otx_summary,
        )

        assert callable(get_indicator)
        assert callable(get_pulses)
        assert callable(search_pulses)
        assert callable(get_pulse_details)
        assert callable(analyze_otx_indicator)
        assert callable(get_otx_summary)
