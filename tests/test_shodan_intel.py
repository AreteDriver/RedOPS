"""Tests for Shodan intelligence module."""

import pytest
from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.intel.shodan_intel import (
    query_shodan_host,
    query_shodan_dns,
    search_shodan,
    analyze_shodan_intel,
    _is_ip,
    _extract_domain,
    ShodanHost,
    ShodanDNS,
)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_is_ip_valid(self):
        """Test valid IP detection."""
        assert _is_ip("192.168.1.1") is True
        assert _is_ip("10.0.0.1") is True
        assert _is_ip("8.8.8.8") is True

    def test_is_ip_invalid(self):
        """Test invalid IP detection."""
        assert _is_ip("example.com") is False
        assert _is_ip("192.168.1") is False
        assert _is_ip("not.an.ip.address.really") is False

    def test_extract_domain(self):
        """Test domain extraction."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.example.com:8080/") == "sub.example.com"
        assert _extract_domain("example.com") == "example.com"


class TestShodanDataclasses:
    """Tests for Shodan dataclasses."""

    def test_shodan_host_to_dict(self):
        """Test ShodanHost serialization."""
        host = ShodanHost(
            ip="192.168.1.1",
            hostnames=["example.com"],
            ports=[80, 443],
            org="Example Org",
            vulns=["CVE-2021-1234"],
        )
        result = host.to_dict()

        assert result["ip"] == "192.168.1.1"
        assert result["hostnames"] == ["example.com"]
        assert result["ports"] == [80, 443]
        assert result["org"] == "Example Org"
        assert result["vulns"] == ["CVE-2021-1234"]

    def test_shodan_dns_to_dict(self):
        """Test ShodanDNS serialization."""
        dns = ShodanDNS(
            domain="example.com",
            subdomains=["www", "api", "mail"],
            tags=["has-ssl"],
        )
        result = dns.to_dict()

        assert result["domain"] == "example.com"
        assert result["subdomains"] == ["www", "api", "mail"]
        assert result["tags"] == ["has-ssl"]


class TestQueryShodanHost:
    """Tests for query_shodan_host."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_shodan_host(ctx)

        assert "shodan_host" not in result.data

    def test_no_client(self):
        """Test when Shodan client not available."""
        ctx = Context(target="example.com")

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=None):
            result = query_shodan_host(ctx)

        data = result.get("shodan_host")
        assert data is not None
        assert "not available" in data["error"]

    def test_successful_host_query(self):
        """Test successful host query."""
        ctx = Context(target="93.184.216.34")

        mock_client = MagicMock()
        mock_client.host.return_value = {
            "ip_str": "93.184.216.34",
            "hostnames": ["example.com"],
            "ports": [80, 443],
            "org": "Edgecast Inc.",
            "asn": "AS15133",
            "country_name": "United States",
            "vulns": {"CVE-2021-1234": {}},
            "data": [
                {"port": 80, "transport": "tcp", "product": "nginx"},
                {"port": 443, "transport": "tcp", "product": "nginx", "ssl": True},
            ],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            result = query_shodan_host(ctx)

        data = result.get("shodan_host")
        assert data is not None
        assert data["error"] is None
        assert len(data["hosts"]) == 1

        host = data["hosts"][0]
        assert host["ip"] == "93.184.216.34"
        assert 80 in host["ports"]
        assert 443 in host["ports"]
        assert "CVE-2021-1234" in host["vulns"]

    def test_domain_resolution(self):
        """Test domain to IP resolution."""
        ctx = Context(target="example.com")

        mock_client = MagicMock()
        mock_client.host.return_value = {
            "ip_str": "93.184.216.34",
            "ports": [80],
            "data": [],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                result = query_shodan_host(ctx)

        data = result.get("shodan_host")
        assert data["hosts"][0]["ip"] == "93.184.216.34"


class TestQueryShodanDNS:
    """Tests for query_shodan_dns."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_shodan_dns(ctx)

        # Should log warning but not crash
        assert "shodan_dns" not in result.data or result.get("shodan_dns") is None

    def test_successful_dns_query(self):
        """Test successful DNS query."""
        ctx = Context(target="example.com")

        mock_client = MagicMock()
        mock_client.dns.domain_info.return_value = {
            "subdomains": ["www", "api", "mail", "blog"],
            "tags": ["has-ssl", "ipv6"],
            "data": [],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            result = query_shodan_dns(ctx)

        data = result.get("shodan_dns")
        assert data is not None
        assert data["domain"] == "example.com"
        assert "www" in data["subdomains"]
        assert "api" in data["subdomains"]


class TestSearchShodan:
    """Tests for search_shodan."""

    def test_build_query_from_ip(self):
        """Test query building from IP target."""
        ctx = Context(target="192.168.1.1")

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "total": 0,
            "matches": [],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            result = search_shodan(ctx)

        data = result.get("shodan_search")
        assert "ip:192.168.1.1" in data["query"]

    def test_build_query_from_domain(self):
        """Test query building from domain target."""
        ctx = Context(target="example.com")

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "total": 0,
            "matches": [],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            result = search_shodan(ctx)

        data = result.get("shodan_search")
        assert "hostname:example.com" in data["query"]

    def test_successful_search(self):
        """Test successful search."""
        ctx = Context(target="example.com")

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "total": 100,
            "matches": [
                {
                    "ip_str": "93.184.216.34",
                    "port": 443,
                    "org": "Edgecast",
                    "hostnames": ["example.com"],
                    "location": {"country_name": "US", "city": "Los Angeles"},
                },
            ],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            result = search_shodan(ctx, {"query": "hostname:example.com"})

        data = result.get("shodan_search")
        assert data["total"] == 100
        assert len(data["results"]) == 1
        assert data["results"][0]["ip"] == "93.184.216.34"


class TestAnalyzeShodanIntel:
    """Tests for analyze_shodan_intel."""

    def test_comprehensive_analysis(self):
        """Test comprehensive Shodan analysis."""
        ctx = Context(target="example.com")

        mock_client = MagicMock()
        mock_client.host.return_value = {
            "ip_str": "93.184.216.34",
            "ports": [80, 443, 8080],
            "org": "Edgecast",
            "vulns": {"CVE-2021-1234": {}, "CVE-2021-5678": {}},
            "data": [],
        }
        mock_client.dns.domain_info.return_value = {
            "subdomains": ["www", "api"],
            "tags": [],
            "data": [],
        }

        with patch("redops.modules.intel.shodan_intel.get_shodan_client", return_value=mock_client):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                result = analyze_shodan_intel(ctx)

        intel = result.get("shodan_intel")
        assert intel is not None
        assert intel["summary"]["open_ports"] == 3
        assert intel["summary"]["vulnerabilities"] == 2
        assert intel["summary"]["organization"] == "Edgecast"
        assert intel["summary"]["subdomains_found"] == 2
