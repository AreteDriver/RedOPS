"""Tests for Censys intelligence module."""

import socket
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

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, None),
        ):
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

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
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

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
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
        mock_certs.search.return_value = iter(
            [
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
            ]
        )

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, mock_certs),
        ):
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

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = search_censys_hosts(ctx)

        data = result.get("censys_search")
        assert "ip: 192.168.1.1" in data["query"]

    def test_build_query_from_domain(self):
        """Test query building from domain target."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.search.return_value = iter([])

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = search_censys_hosts(ctx)

        data = result.get("censys_search")
        assert "example.com" in data["query"]

    def test_successful_search(self):
        """Test successful search."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.search.return_value = iter(
            [
                {
                    "ip": "93.184.216.34",
                    "services": [{"port": 80}, {"port": 443}],
                    "location": {"country": "US"},
                    "autonomous_system": {"asn": 15133},
                },
            ]
        )

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = search_censys_hosts(
                ctx, {"query": "services.tls.certificates.leaf_data.names: example.com"}
            )

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
        mock_certs.search.return_value = iter(
            [
                {
                    "fingerprint_sha256": "abc",
                    "names": ["example.com", "www.example.com"],
                },
                {"fingerprint_sha256": "def", "names": ["api.example.com"]},
            ]
        )

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, mock_certs),
        ):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                result = analyze_censys_intel(ctx)

        intel = result.get("censys_intel")
        assert intel is not None
        assert intel["summary"]["services_count"] == 2
        assert intel["summary"]["open_ports"] == [80, 443]
        assert intel["summary"]["certificates_found"] == 2
        assert "example.com" in intel["summary"]["certificate_names"]


class TestGetCensysClient:
    """Tests for get_censys_client function."""

    def test_import_error_returns_none(self):
        """Test that import error returns (None, None)."""
        # Mock sys.modules to force ImportError for censys.search
        MagicMock()
        mock_search = MagicMock()
        mock_search.CensysHosts = None
        mock_search.CensysCerts = None

        # Remove the module from sys.modules to force fresh import
        import sys

        original_modules = {}
        for mod in list(sys.modules.keys()):
            if mod.startswith("censys"):
                original_modules[mod] = sys.modules.pop(mod)

        try:
            # Reload the module
            from importlib import reload
            import redops.modules.intel.censys_intel as censys_mod

            reload(censys_mod)

            # The get_censys_client should return (None, None) when import fails
            result = censys_mod.get_censys_client()
            assert result == (None, None)
        finally:
            # Restore original modules
            sys.modules.update(original_modules)

    def test_no_credentials_returns_none(self):
        """Test that missing credentials returns (None, None)."""
        # Create mock censys module
        mock_search = MagicMock()

        import sys

        with patch.dict(
            sys.modules, {"censys": MagicMock(), "censys.search": mock_search}
        ):
            with patch.dict("os.environ", {}, clear=True):
                # Also mock the settings fallback to return None
                with patch("redops.cli.settings.get_api_key_direct", return_value=None):
                    from importlib import reload
                    import redops.modules.intel.censys_intel as censys_mod

                    reload(censys_mod)
                    result = censys_mod.get_censys_client()
                    assert result == (None, None)

    def test_credentials_from_env(self):
        """Test credentials loaded from environment."""
        mock_hosts_class = MagicMock()
        mock_certs_class = MagicMock()
        mock_hosts_instance = MagicMock()
        mock_certs_instance = MagicMock()
        mock_hosts_class.return_value = mock_hosts_instance
        mock_certs_class.return_value = mock_certs_instance

        mock_search = MagicMock()
        mock_search.CensysHosts = mock_hosts_class
        mock_search.CensysCerts = mock_certs_class

        import sys

        with patch.dict(
            sys.modules, {"censys": MagicMock(), "censys.search": mock_search}
        ):
            with patch.dict(
                "os.environ",
                {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            ):
                from importlib import reload
                import redops.modules.intel.censys_intel as censys_mod

                reload(censys_mod)
                result = censys_mod.get_censys_client()

                assert result[0] is mock_hosts_instance
                assert result[1] is mock_certs_instance
                mock_hosts_class.assert_called_with(
                    api_id="test-id", api_secret="test-secret"
                )

    def test_credentials_from_settings_fallback(self):
        """Test credentials loaded from settings when env not set."""
        mock_hosts_class = MagicMock()
        mock_certs_class = MagicMock()
        mock_hosts_instance = MagicMock()
        mock_certs_instance = MagicMock()
        mock_hosts_class.return_value = mock_hosts_instance
        mock_certs_class.return_value = mock_certs_instance

        mock_search = MagicMock()
        mock_search.CensysHosts = mock_hosts_class
        mock_search.CensysCerts = mock_certs_class

        import sys

        with patch.dict(
            sys.modules, {"censys": MagicMock(), "censys.search": mock_search}
        ):
            with patch.dict("os.environ", {}, clear=True):
                # Mock settings to return credentials
                def get_key_side_effect(key):
                    if key == "censys_id":
                        return "settings-id"
                    elif key == "censys_secret":
                        return "settings-secret"
                    return None

                with patch(
                    "redops.cli.settings.get_api_key_direct",
                    side_effect=get_key_side_effect,
                ):
                    from importlib import reload
                    import redops.modules.intel.censys_intel as censys_mod

                    reload(censys_mod)
                    result = censys_mod.get_censys_client()

                    assert result[0] is mock_hosts_instance
                    assert result[1] is mock_certs_instance

    def test_settings_fallback_exception(self):
        """Test that settings exception is handled gracefully."""
        mock_search = MagicMock()

        import sys

        with patch.dict(
            sys.modules, {"censys": MagicMock(), "censys.search": mock_search}
        ):
            with patch.dict("os.environ", {}, clear=True):
                # Mock settings to raise exception
                with patch(
                    "redops.cli.settings.get_api_key_direct",
                    side_effect=RuntimeError("Settings error"),
                ):
                    from importlib import reload
                    import redops.modules.intel.censys_intel as censys_mod

                    reload(censys_mod)
                    result = censys_mod.get_censys_client()
                    assert result == (None, None)

    def test_client_creation_exception_returns_none(self):
        """Test that client creation exception returns (None, None)."""
        mock_hosts_class = MagicMock(side_effect=RuntimeError("Auth failed"))
        mock_certs_class = MagicMock()

        mock_search = MagicMock()
        mock_search.CensysHosts = mock_hosts_class
        mock_search.CensysCerts = mock_certs_class

        import sys

        with patch.dict(
            sys.modules, {"censys": MagicMock(), "censys.search": mock_search}
        ):
            with patch.dict(
                "os.environ",
                {"CENSYS_API_ID": "test-id", "CENSYS_API_SECRET": "test-secret"},
            ):
                from importlib import reload
                import redops.modules.intel.censys_intel as censys_mod

                reload(censys_mod)
                result = censys_mod.get_censys_client()
                assert result == (None, None)


class TestQueryCensysHostEdgeCases:
    """Edge case tests for query_censys_host."""

    def test_domain_resolution_failure(self):
        """Test handling of domain resolution failure."""
        ctx = Context(target="nonexistent.invalid.domain")

        mock_hosts = MagicMock()

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            with patch(
                "socket.gethostbyname", side_effect=socket.gaierror("DNS resolution failed")
            ):
                result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert data is not None
        assert "Could not resolve domain" in data["error"]

    def test_services_with_software(self):
        """Test parsing services with software information."""
        ctx = Context(target="93.184.216.34")

        mock_hosts = MagicMock()
        mock_hosts.view.return_value = {
            "ip": "93.184.216.34",
            "services": [
                {
                    "port": 80,
                    "transport_protocol": "TCP",
                    "service_name": "HTTP",
                    "software": [
                        {
                            "product": "nginx",
                            "version": "1.19.0",
                            "vendor": "nginx Inc",
                        },
                        {"product": "OpenSSL", "version": "1.1.1g"},
                    ],
                },
            ],
        }

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert data is not None
        host = data["hosts"][0]
        assert len(host["services"]) == 1
        assert len(host["services"][0]["software"]) == 2
        assert host["services"][0]["software"][0]["product"] == "nginx"

    def test_404_error(self):
        """Test handling of 404 not found error."""
        ctx = Context(target="93.184.216.34")

        mock_hosts = MagicMock()
        mock_hosts.view.side_effect = RuntimeError("404 - Host not found")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert data is not None
        assert "No Censys data for" in data["error"]

    def test_not_found_error_lowercase(self):
        """Test handling of 'not found' error (lowercase)."""
        ctx = Context(target="10.0.0.1")

        mock_hosts = MagicMock()
        mock_hosts.view.side_effect = RuntimeError("Resource not found")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert "No Censys data for" in data["error"]

    def test_generic_api_error(self):
        """Test handling of generic API error."""
        ctx = Context(target="93.184.216.34")

        mock_hosts = MagicMock()
        mock_hosts.view.side_effect = RuntimeError("Rate limit exceeded")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = query_censys_host(ctx)

        data = result.get("censys_host")
        assert "Censys API error" in data["error"]


class TestQueryCensysCertificatesEdgeCases:
    """Edge case tests for query_censys_certificates."""

    def test_no_certs_client(self):
        """Test when certs client not available."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(MagicMock(), None),
        ):
            result = query_censys_certificates(ctx)

        data = result.get("censys_certs")
        assert data is not None
        assert "not available" in data["error"]

    def test_fingerprint_query(self):
        """Test querying specific certificate by fingerprint."""
        ctx = Context(target=None)

        mock_certs = MagicMock()
        mock_certs.view.return_value = {
            "fingerprint_sha256": "abc123def456",
            "names": ["example.com"],
            "issuer_dn": "CN=Let's Encrypt",
            "subject_dn": "CN=example.com",
            "validity": {"start": "2024-01-01", "end": "2025-01-01"},
            "public_key": {"algorithm": "RSA", "key_size": 2048},
        }

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, mock_certs),
        ):
            result = query_censys_certificates(ctx, {"fingerprint": "abc123def456"})

        data = result.get("censys_certs")
        assert data is not None
        assert data["total"] == 1
        assert data["certificates"][0]["fingerprint"] == "abc123def456"

    def test_cert_search_limit_reached(self):
        """Test certificate search stops at limit."""
        ctx = Context(target="example.com")

        mock_certs = MagicMock()
        # Return more certs than the limit
        mock_certs.search.return_value = iter(
            [
                {"fingerprint_sha256": f"cert{i}", "names": ["example.com"]}
                for i in range(100)
            ]
        )

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, mock_certs),
        ):
            result = query_censys_certificates(ctx, {"limit": 5})

        data = result.get("censys_certs")
        assert data["total"] == 5
        assert len(data["certificates"]) == 5

    def test_certificate_query_exception(self):
        """Test handling of certificate query exception."""
        ctx = Context(target="example.com")

        mock_certs = MagicMock()
        mock_certs.search.side_effect = RuntimeError("API timeout")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, mock_certs),
        ):
            result = query_censys_certificates(ctx)

        data = result.get("censys_certs")
        assert "Censys certificate error" in data["error"]


class TestSearchCensysHostsEdgeCases:
    """Edge case tests for search_censys_hosts."""

    def test_no_query_and_no_target(self):
        """Test search with no query and no target."""
        ctx = Context(target=None)
        result = search_censys_hosts(ctx)

        # Should log warning
        assert "censys_search" not in result.data

    def test_no_hosts_client(self):
        """Test when hosts client not available."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, MagicMock()),
        ):
            result = search_censys_hosts(ctx)

        data = result.get("censys_search")
        assert data is not None
        assert "not available" in data["error"]

    def test_search_limit_reached(self):
        """Test search stops at limit."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        # Return more hosts than the limit
        mock_hosts.search.return_value = iter(
            [
                {
                    "ip": f"192.168.1.{i}",
                    "services": [],
                    "location": {},
                    "autonomous_system": {},
                }
                for i in range(100)
            ]
        )

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = search_censys_hosts(ctx, {"query": "services.http", "limit": 10})

        data = result.get("censys_search")
        assert data["total"] == 10
        assert len(data["results"]) == 10

    def test_search_exception(self):
        """Test handling of search exception."""
        ctx = Context(target="example.com")

        mock_hosts = MagicMock()
        mock_hosts.search.side_effect = RuntimeError("Search failed")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = search_censys_hosts(ctx, {"query": "test"})

        data = result.get("censys_search")
        assert "Censys search error" in data["error"]


class TestAnalyzeCensysIntelEdgeCases:
    """Edge case tests for analyze_censys_intel."""

    def test_analysis_with_ip_target(self):
        """Test analysis with IP target (no cert query)."""
        ctx = Context(target="93.184.216.34")

        mock_hosts = MagicMock()
        mock_hosts.view.return_value = {
            "ip": "93.184.216.34",
            "location": {"country": "US"},
            "autonomous_system": {"asn": 15133, "name": "Edgecast"},
            "operating_system": {"product": "Linux"},
            "services": [
                {"port": 80},
                {"port": 443},
            ],
        }

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = analyze_censys_intel(ctx)

        intel = result.get("censys_intel")
        assert intel is not None
        assert intel["summary"]["services_count"] == 2
        # No certificates since target is IP
        assert (
            intel.get("certificates", {}).get("certificates", []) == []
            or "certificates_found" not in intel["summary"]
        )

    def test_analysis_with_no_hosts(self):
        """Test analysis when no hosts returned."""
        ctx = Context(target="example.com")

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(None, None),
        ):
            result = analyze_censys_intel(ctx)

        intel = result.get("censys_intel")
        assert intel is not None
        # Summary should be empty or minimal
        assert intel["summary"].get("services_count", 0) == 0

    def test_analysis_with_services_having_ports_with_none(self):
        """Test summary handles services without port field."""
        ctx = Context(target="93.184.216.34")

        mock_hosts = MagicMock()
        mock_hosts.view.return_value = {
            "ip": "93.184.216.34",
            "location": {"country": "US"},
            "autonomous_system": {"asn": 15133, "name": "Edgecast"},
            "services": [
                {"port": 80},
                {"port": None},  # Service with None port
                {"service_name": "unknown"},  # Service without port
            ],
        }

        with patch(
            "redops.modules.intel.censys_intel.get_censys_client",
            return_value=(mock_hosts, None),
        ):
            result = analyze_censys_intel(ctx)

        intel = result.get("censys_intel")
        # Only port 80 should be in open_ports
        assert intel["summary"]["open_ports"] == [80]


class TestParseCertificateEdgeCases:
    """Edge case tests for _parse_certificate."""

    def test_parse_certificate_fallback_fingerprint(self):
        """Test parsing certificate with fallback fingerprint field."""
        data = {
            "fingerprint": "fallback123",  # Uses fingerprint instead of fingerprint_sha256
            "names": ["example.com"],
        }
        cert = _parse_certificate(data)
        assert cert.fingerprint == "fallback123"

    def test_parse_certificate_fallback_issuer(self):
        """Test parsing certificate with fallback issuer field."""
        data = {
            "fingerprint_sha256": "abc",
            "issuer": {"common_name": "Test CA"},  # Uses nested issuer
        }
        cert = _parse_certificate(data)
        assert cert.issuer == "Test CA"

    def test_parse_certificate_fallback_subject(self):
        """Test parsing certificate with fallback subject field."""
        data = {
            "fingerprint_sha256": "abc",
            "subject": {"common_name": "test.example.com"},  # Uses nested subject
        }
        cert = _parse_certificate(data)
        assert cert.subject == "test.example.com"

    def test_parse_certificate_empty_data(self):
        """Test parsing certificate with minimal data."""
        data = {}
        cert = _parse_certificate(data)
        assert cert.fingerprint == ""
        assert cert.names == []
        assert cert.issuer is None
        assert cert.subject is None
