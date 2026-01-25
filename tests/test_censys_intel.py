"""Tests for Censys intelligence module."""

import pytest
from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.intel.censys_intel import (
    query_censys_host,
    query_censys_certificates,
    search_censys_hosts,
    analyze_censys_intel,
    _is_ip,
    _extract_domain,
    _parse_certificate,
    CensysHost,
    CensysCertificate,
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

    def test_extract_domain(self):
        """Test domain extraction."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.example.com:8080/") == "sub.example.com"
        assert _extract_domain("example.com") == "example.com"

    def test_parse_certificate(self):
        """Test certificate parsing."""
        data = {
            "fingerprint_sha256": "abc123",
            "names": ["example.com", "www.example.com"],
            "issuer_dn": "CN=Let's Encrypt Authority X3",
            "subject_dn": "CN=example.com",
            "validity": {"start": "2024-01-01", "end": "2025-01-01"},
            "public_key": {"algorithm": "RSA", "key_size": 2048},
        }
        cert = _parse_certificate(data)

        assert cert.fingerprint == "abc123"
        assert "example.com" in cert.names
        assert cert.issuer == "CN=Let's Encrypt Authority X3"
        assert cert.key_info["algorithm"] == "RSA"


class TestCensysDataclasses:
    """Tests for Censys dataclasses."""

    def test_censys_host_to_dict(self):
        """Test CensysHost serialization."""
        host = CensysHost(
            ip="192.168.1.1",
            services=[{"port": 80, "service_name": "HTTP"}],
            location={"country": "US"},
            autonomous_system={"asn": 12345, "name": "Example ASN"},
            operating_system="Linux",
        )
        result = host.to_dict()

        assert result["ip"] == "192.168.1.1"
        assert result["services"][0]["port"] == 80
        assert result["location"]["country"] == "US"
        assert result["operating_system"] == "Linux"

    def test_censys_certificate_to_dict(self):
        """Test CensysCertificate serialization."""
        cert = CensysCertificate(
            fingerprint="abc123",
            names=["example.com"],
            issuer="Let's Encrypt",
            subject="example.com",
            validity={"not_before": "2024-01-01", "not_after": "2025-01-01"},
            key_info={"algorithm": "RSA", "size": 2048},
        )
        result = cert.to_dict()

        assert result["fingerprint"] == "abc123"
        assert "example.com" in result["names"]
        assert result["issuer"] == "Let's Encrypt"
        assert result["key_info"]["algorithm"] == "RSA"


class TestQueryCensysHost:
    """Tests for query_censys_host."""

    def test_no_target(self):
        """Test with no target."""
        ctx = Context(target=None)
        result = query_censys_host(ctx)

        assert "censys_host" not in result.data

    def test_no_client(self):
        """Test when Censys client not available."""
        ctx = Context(target="example.com")

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(None, None)):
            result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert data is not None
        assert "not available" in data["error"]

    def test_successful_host_query(self):
        """Test successful host query."""
        ctx = Context(target="93.184.216.34")

        mock_hosts = MagicMock()
        mock_hosts.view.return_value = {
            "ip": "93.184.216.34",
            "location": {"country": "United States", "city": "Los Angeles"},
            "autonomous_system": {"asn": 15133, "name": "Edgecast"},
            "operating_system": {"product": "Linux"},
            "services": [
                {
                    "port": 80,
                    "transport_protocol": "TCP",
                    "service_name": "HTTP",
                },
                {
                    "port": 443,
                    "transport_protocol": "TCP",
                    "service_name": "HTTPS",
                    "tls": {
                        "certificates": {
                            "leaf_data": {
                                "fingerprint": "abc123",
                                "issuer_dn": "Let's Encrypt",
                                "names": ["example.com"],
                            }
                        }
                    },
                },
            ],
        }

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(mock_hosts, None)):
            result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert data is not None
        assert data["error"] is None
        assert len(data["hosts"]) == 1

        host = data["hosts"][0]
        assert host["ip"] == "93.184.216.34"
        assert len(host["services"]) == 2

    def test_domain_resolution(self):
        """Test domain to IP resolution."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.view.return_value = {
            "ip": "93.184.216.34",
            "services": [],
        }

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(mock_hosts, None)):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert data["hosts"][0]["ip"] == "93.184.216.34"


class TestQueryCensysCertificates:
    """Tests for query_censys_certificates."""

    def test_no_target(self):
        """Test with no domain or fingerprint."""
        ctx = Context(target=None)
        result = query_censys_certificates(ctx)

        # Should log warning
        assert "censys_certs" not in result.data or result.get("censys_certs") is None

    def test_successful_cert_query(self):
        """Test successful certificate query."""
        ctx = Context(target="example.com")

        mock_certs = MagicMock()
        # Simulate search results as iterator
        mock_certs.search.return_value = iter([
            {
                "fingerprint_sha256": "abc123",
                "names": ["example.com", "www.example.com"],
                "issuer_dn": "CN=Let's Encrypt",
            },
            {
                "fingerprint_sha256": "def456",
                "names": ["api.example.com"],
                "issuer_dn": "CN=DigiCert",
            },
        ])

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(None, mock_certs)):
            result = query_censys_certificates(ctx)

        data = result.get("censys_certs")
        assert data is not None
        assert data["total"] == 2
        assert len(data["certificates"]) == 2


class TestSearchCensysHosts:
    """Tests for search_censys_hosts."""

    def test_build_query_from_ip(self):
        """Test query building from IP target."""
        ctx = Context(target="192.168.1.1")

        mock_hosts = MagicMock()
        mock_hosts.search.return_value = iter([])

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(mock_hosts, None)):
            result = search_censys_hosts(ctx)

        data = result.get("censys_search")
        assert "ip: 192.168.1.1" in data["query"]

    def test_build_query_from_domain(self):
        """Test query building from domain target."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.search.return_value = iter([])

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(mock_hosts, None)):
            result = search_censys_hosts(ctx)

        data = result.get("censys_search")
        assert "example.com" in data["query"]

    def test_successful_search(self):
        """Test successful search."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.search.return_value = iter([
            {
                "ip": "93.184.216.34",
                "services": [{"port": 80}, {"port": 443}],
                "location": {"country": "US"},
                "autonomous_system": {"asn": 15133},
            },
        ])

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(mock_hosts, None)):
            result = search_censys_hosts(ctx, {"query": "services.tls.certificates.leaf_data.names: example.com"})

        data = result.get("censys_search")
        assert data["total"] == 1
        assert data["results"][0]["ip"] == "93.184.216.34"


class TestAnalyzeCensysIntel:
    """Tests for analyze_censys_intel."""

    def test_comprehensive_analysis(self):
        """Test comprehensive Censys analysis."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.view.return_value = {
            "ip": "93.184.216.34",
            "location": {"country": "US"},
            "autonomous_system": {"asn": 15133, "name": "Edgecast"},
            "operating_system": {"product": "Linux"},
            "services": [
                {"port": 80, "service_name": "HTTP"},
                {"port": 443, "service_name": "HTTPS"},
            ],
        }

        mock_certs = MagicMock()
        mock_certs.search.return_value = iter([
            {"fingerprint_sha256": "abc", "names": ["example.com", "www.example.com"]},
            {"fingerprint_sha256": "def", "names": ["api.example.com"]},
        ])

        with patch("redops.modules.intel.censys_intel.get_censys_client", return_value=(mock_hosts, mock_certs)):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                result = analyze_censys_intel(ctx)

        intel = result.get("censys_intel")
        assert intel is not None
        assert intel["summary"]["services_count"] == 2
        assert intel["summary"]["open_ports"] == [80, 443]
        assert intel["summary"]["certificates_found"] == 2
        assert "example.com" in intel["summary"]["certificate_names"]
