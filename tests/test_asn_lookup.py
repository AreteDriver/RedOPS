"""Tests for the ASN lookup module."""

from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.modules.recon.asn_lookup import (
    lookup_asn,
    is_ip_address,
    is_asn,
    resolve_domain_to_ip,
    lookup_asn_bgpview,
    lookup_asn_cymru,
    lookup_asn_details,
    get_asn_prefixes,
    get_asn_peers,
    analyze_asn_info,
    get_asn_summary,
)


class TestIsIpAddress:
    """Tests for is_ip_address function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert is_ip_address("192.168.1.1") is True
        assert is_ip_address("8.8.8.8") is True
        assert is_ip_address("10.0.0.1") is True
        assert is_ip_address("255.255.255.255") is True

    def test_invalid_ipv4(self):
        """Test invalid IPv4 addresses."""
        assert is_ip_address("256.1.1.1") is False
        assert is_ip_address("1.2.3") is False
        assert is_ip_address("not.an.ip") is False

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert is_ip_address("::1") is True
        assert is_ip_address("2001:db8::1") is True

    def test_domain_not_ip(self):
        """Test that domains are not IPs."""
        assert is_ip_address("example.com") is False
        assert is_ip_address("www.google.com") is False


class TestIsAsn:
    """Tests for is_asn function."""

    def test_valid_asn_with_prefix(self):
        """Test valid ASN with AS prefix."""
        assert is_asn("AS12345") is True
        assert is_asn("as12345") is True

    def test_valid_asn_without_prefix(self):
        """Test valid ASN without prefix."""
        assert is_asn("12345") is True
        assert is_asn("1") is True

    def test_invalid_asn(self):
        """Test invalid ASN values."""
        assert is_asn("0") is False
        assert is_asn("-1") is False
        assert is_asn("not-an-asn") is False
        assert is_asn("AS") is False


class TestResolveDomainToIp:
    """Tests for resolve_domain_to_ip function."""

    @patch("socket.gethostbyname")
    def test_successful_resolution(self, mock_gethostbyname):
        """Test successful domain resolution."""
        mock_gethostbyname.return_value = "93.184.216.34"

        result = resolve_domain_to_ip("example.com")
        assert result == "93.184.216.34"

    @patch("socket.gethostbyname")
    def test_failed_resolution(self, mock_gethostbyname):
        """Test failed domain resolution."""
        mock_gethostbyname.side_effect = Exception("Host not found")

        result = resolve_domain_to_ip("nonexistent.example.com")
        assert result is None


class TestLookupAsn:
    """Tests for lookup_asn function."""

    def test_no_target(self):
        """Test handling when no target specified."""
        ctx = Context()
        result = lookup_asn(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No target" in log["message"] for log in warnings)

    @patch("redops.modules.recon.asn_lookup.lookup_asn_by_ip")
    def test_lookup_by_ip(self, mock_lookup):
        """Test ASN lookup by IP address."""
        mock_lookup.return_value = {
            "asn": 15169,
            "name": "GOOGLE",
            "ip": "8.8.8.8",
        }

        ctx = Context(target="8.8.8.8")
        result = lookup_asn(ctx)

        assert result.data["asn"] == 15169
        assert "GOOGLE" in result.data["asn_name"]

    @patch("redops.modules.recon.asn_lookup.lookup_asn_details")
    def test_lookup_by_asn(self, mock_lookup):
        """Test ASN lookup by ASN number."""
        mock_lookup.return_value = {
            "asn": 15169,
            "name": "GOOGLE",
        }

        ctx = Context(target="AS15169")
        result = lookup_asn(ctx)

        assert result.data["asn"] == 15169

    @patch("redops.modules.recon.asn_lookup.resolve_domain_to_ip")
    @patch("redops.modules.recon.asn_lookup.lookup_asn_by_ip")
    def test_lookup_by_domain(self, mock_lookup_ip, mock_resolve):
        """Test ASN lookup by domain."""
        mock_resolve.return_value = "8.8.8.8"
        mock_lookup_ip.return_value = {
            "asn": 15169,
            "name": "GOOGLE",
        }

        ctx = Context(target="dns.google")
        result = lookup_asn(ctx)

        assert result.data["asn"] == 15169

    @patch("redops.modules.recon.asn_lookup.resolve_domain_to_ip")
    def test_domain_resolution_failure(self, mock_resolve):
        """Test handling domain resolution failure."""
        mock_resolve.return_value = None

        ctx = Context(target="nonexistent-domain-12345.com")
        result = lookup_asn(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("resolve" in log["message"].lower() for log in warnings)


class TestLookupAsnBgpview:
    """Tests for lookup_asn_bgpview function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.recon.asn_lookup.HAS_REQUESTS", False):
            result = lookup_asn_bgpview("8.8.8.8")
            assert "error" in result

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_successful_lookup(self, mock_requests):
        """Test successful BGPView lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "ok",
            "data": {
                "prefixes": [
                    {
                        "prefix": "8.8.8.0/24",
                        "asn": {
                            "asn": 15169,
                            "name": "GOOGLE",
                            "description": "Google LLC",
                            "country_code": "US",
                        },
                    }
                ],
                "rir_allocation": {"rir_name": "ARIN"},
            },
        }
        mock_requests.get.return_value = mock_response

        result = lookup_asn_bgpview("8.8.8.8")

        assert result["asn"] == 15169
        assert "GOOGLE" in result["name"]

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_no_data(self, mock_requests):
        """Test when no data returned."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "ok", "data": {"prefixes": []}}
        mock_requests.get.return_value = mock_response

        result = lookup_asn_bgpview("8.8.8.8")
        assert "error" in result

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_api_error(self, mock_requests):
        """Test API error handling."""
        import requests

        mock_requests.get.side_effect = requests.exceptions.RequestException()
        mock_requests.exceptions = requests.exceptions

        result = lookup_asn_bgpview("8.8.8.8")
        assert "error" in result


class TestLookupAsnCymru:
    """Tests for lookup_asn_cymru function."""

    @patch("socket.gethostbyname_ex")
    def test_dns_lookup(self, mock_dns):
        """Test Cymru DNS lookup (basic structure)."""
        # This is a fallback method, just ensure it doesn't crash
        mock_dns.return_value = ("test", [], ["127.0.0.1"])
        result = lookup_asn_cymru("8.8.8.8")
        assert "ip" in result


class TestLookupAsnDetails:
    """Tests for lookup_asn_details function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.recon.asn_lookup.HAS_REQUESTS", False):
            result = lookup_asn_details("AS15169")
            assert "error" in result

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_successful_lookup(self, mock_requests):
        """Test successful ASN details lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "ok",
            "data": {
                "asn": 15169,
                "name": "GOOGLE",
                "description_short": "Google LLC",
                "country_code": "US",
                "website": "https://google.com",
                "email_contacts": ["noc@google.com"],
                "abuse_contacts": ["abuse@google.com"],
            },
        }
        mock_requests.get.return_value = mock_response

        result = lookup_asn_details("AS15169")

        assert result["asn"] == 15169
        assert result["name"] == "GOOGLE"

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_asn_not_found(self, mock_requests):
        """Test when ASN not found."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "error"}
        mock_requests.get.return_value = mock_response

        result = lookup_asn_details("AS999999999")
        assert "error" in result


class TestGetAsnPrefixes:
    """Tests for get_asn_prefixes function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.recon.asn_lookup.HAS_REQUESTS", False):
            result = get_asn_prefixes("15169")
            assert result == []

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_successful_lookup(self, mock_requests):
        """Test successful prefix lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "ok",
            "data": {
                "ipv4_prefixes": [
                    {"prefix": "8.8.8.0/24", "name": "GOOGLE", "country_code": "US"}
                ],
                "ipv6_prefixes": [
                    {"prefix": "2001:4860::/32", "name": "GOOGLE", "country_code": "US"}
                ],
            },
        }
        mock_requests.get.return_value = mock_response

        result = get_asn_prefixes("15169")

        assert len(result) == 2
        assert any(p["ip_version"] == 4 for p in result)
        assert any(p["ip_version"] == 6 for p in result)


class TestGetAsnPeers:
    """Tests for get_asn_peers function."""

    def test_no_requests(self):
        """Test when requests not available."""
        with patch("redops.modules.recon.asn_lookup.HAS_REQUESTS", False):
            result = get_asn_peers("15169")
            assert result == {"upstreams": [], "downstreams": [], "peers": []}

    @patch("redops.modules.recon.asn_lookup.requests")
    def test_successful_lookup(self, mock_requests):
        """Test successful peer lookup."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "ok",
            "data": {
                "ipv4_upstreams": [{"asn": 1234, "name": "UPSTREAM"}],
                "ipv4_downstreams": [{"asn": 5678, "name": "DOWNSTREAM"}],
                "ipv4_peers": [{"asn": 9012, "name": "PEER"}],
            },
        }
        mock_requests.get.return_value = mock_response

        result = get_asn_peers("15169")

        assert len(result["upstreams"]) == 1
        assert len(result["downstreams"]) == 1
        assert len(result["peers"]) == 1


class TestAnalyzeAsnInfo:
    """Tests for analyze_asn_info function."""

    def test_detects_cloud_provider(self):
        """Test detection of cloud providers."""
        asn_info = {"asn": 16509, "name": "AMAZON-02"}
        findings = analyze_asn_info(asn_info, "example.com")

        assert any("Cloud" in f.title or "Hosting" in f.title for f in findings)

    def test_detects_large_network(self):
        """Test detection of large networks."""
        asn_info = {"asn": 15169, "name": "GOOGLE", "prefixes": [{}] * 150}
        findings = analyze_asn_info(asn_info, "example.com")

        assert any("Large Network" in f.title for f in findings)

    def test_reports_abuse_contacts(self):
        """Test reporting of abuse contacts."""
        asn_info = {
            "asn": 15169,
            "name": "GOOGLE",
            "abuse_contacts": ["abuse@google.com"],
        }
        findings = analyze_asn_info(asn_info, "example.com")

        assert any("Abuse Contact" in f.title for f in findings)

    def test_no_findings_for_missing_asn(self):
        """Test no findings when ASN is missing."""
        asn_info = {"error": "lookup failed"}
        findings = analyze_asn_info(asn_info, "example.com")

        assert len(findings) == 0


class TestGetAsnSummary:
    """Tests for get_asn_summary function."""

    def test_with_results(self):
        """Test summary with results."""
        ctx = Context()
        ctx.add(
            "asn_lookup",
            {
                "asn": 15169,
                "name": "GOOGLE",
                "country": "US",
                "prefix_count": 100,
                "lookup_timestamp": "2024-01-01T00:00:00",
            },
        )

        summary = get_asn_summary(ctx)

        assert summary["asn"] == 15169
        assert summary["name"] == "GOOGLE"
        assert summary["prefix_count"] == 100

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_asn_summary(ctx)

        assert summary["asn"] is None
        assert summary["name"] == ""
