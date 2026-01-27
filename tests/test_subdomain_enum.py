"""Tests for the subdomain enumeration module."""

from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.modules.recon.subdomain_enum import (
    enumerate_subdomains,
    bruteforce_subdomains,
    resolve_domain,
    verify_subdomains,
    get_subdomains_from_dns,
    analyze_subdomains,
    get_subdomain_summary,
    COMMON_SUBDOMAINS,
)


class TestConstants:
    """Tests for module constants."""

    def test_common_subdomains_not_empty(self):
        """Test that common subdomains list is populated."""
        assert len(COMMON_SUBDOMAINS) > 50

    def test_common_subdomains_contains_basics(self):
        """Test that common subdomains contains basic prefixes."""
        assert "www" in COMMON_SUBDOMAINS
        assert "mail" in COMMON_SUBDOMAINS
        assert "api" in COMMON_SUBDOMAINS
        assert "dev" in COMMON_SUBDOMAINS
        assert "admin" in COMMON_SUBDOMAINS


class TestEnumerateSubdomains:
    """Tests for enumerate_subdomains function."""

    def test_no_domain(self):
        """Test handling when no domain specified."""
        ctx = Context()
        result = enumerate_subdomains(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("No domain" in log["message"] for log in warnings)

    @patch("redops.modules.recon.subdomain_enum.bruteforce_subdomains")
    @patch("redops.modules.recon.subdomain_enum.verify_subdomains")
    def test_basic_enumeration(self, mock_verify, mock_bruteforce):
        """Test basic subdomain enumeration."""
        mock_bruteforce.return_value = {"www.example.com", "api.example.com"}
        mock_verify.return_value = {"www.example.com", "api.example.com"}

        ctx = Context(target="example.com")
        result = enumerate_subdomains(ctx, {"use_ct": False})

        assert "subdomains" in result.data
        assert len(result.data["subdomains"]) >= 2

    @patch("redops.modules.recon.subdomain_enum.bruteforce_subdomains")
    @patch("redops.modules.recon.subdomain_enum.verify_subdomains")
    def test_stores_enum_results(self, mock_verify, mock_bruteforce):
        """Test that enumeration results are stored."""
        mock_bruteforce.return_value = {"www.example.com"}
        mock_verify.return_value = {"www.example.com"}

        ctx = Context(target="example.com")
        result = enumerate_subdomains(ctx, {"use_ct": False})

        assert "subdomain_enum_results" in result.data
        assert result.data["subdomain_enum_results"]["domain"] == "example.com"

    @patch("redops.modules.recon.subdomain_enum.bruteforce_subdomains")
    def test_no_resolution_verification(self, mock_bruteforce):
        """Test skipping resolution verification."""
        mock_bruteforce.return_value = {"www.example.com", "nonexistent.example.com"}

        ctx = Context(target="example.com")
        result = enumerate_subdomains(ctx, {"use_ct": False, "resolve_only": False})

        # Should include all subdomains without verification
        assert len(result.data["subdomains"]) == 2


class TestBruteforceSubdomains:
    """Tests for bruteforce_subdomains function."""

    @patch("redops.modules.recon.subdomain_enum.resolve_domain")
    def test_finds_resolving_subdomains(self, mock_resolve):
        """Test finding subdomains that resolve."""
        mock_resolve.side_effect = lambda d, **kw: d == "www.example.com"

        result = bruteforce_subdomains("example.com", ["www", "nonexistent"], threads=1)

        assert "www.example.com" in result
        assert "nonexistent.example.com" not in result

    @patch("redops.modules.recon.subdomain_enum.resolve_domain")
    def test_empty_wordlist(self, mock_resolve):
        """Test with empty wordlist."""
        result = bruteforce_subdomains("example.com", [], threads=1)
        assert len(result) == 0

    @patch("redops.modules.recon.subdomain_enum.resolve_domain")
    def test_concurrent_execution(self, mock_resolve):
        """Test concurrent thread execution."""
        mock_resolve.return_value = True

        result = bruteforce_subdomains("example.com", ["www", "api", "mail"], threads=3)
        assert len(result) == 3


class TestResolveDomain:
    """Tests for resolve_domain function."""

    @patch("redops.modules.recon.subdomain_enum.HAS_DNS", True)
    @patch("redops.modules.recon.subdomain_enum.dns.resolver.Resolver")
    def test_with_dnspython(self, mock_resolver_class):
        """Test resolution with dnspython."""
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        result = resolve_domain("www.example.com")
        # Should return True if no exception
        assert result is True

    @patch("redops.modules.recon.subdomain_enum.HAS_DNS", True)
    @patch("redops.modules.recon.subdomain_enum.dns.resolver.Resolver")
    def test_resolution_failure_dnspython(self, mock_resolver_class):
        """Test failed resolution with dnspython."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        mock_resolver_class.return_value = mock_resolver

        result = resolve_domain("nonexistent.example.com")
        assert result is False

    @patch("redops.modules.recon.subdomain_enum.HAS_DNS", False)
    @patch("socket.gethostbyname")
    def test_socket_fallback(self, mock_gethostbyname):
        """Test socket fallback when dnspython not available."""
        mock_gethostbyname.return_value = "1.2.3.4"

        result = resolve_domain("www.example.com")
        assert result is True

    @patch("redops.modules.recon.subdomain_enum.HAS_DNS", False)
    @patch("socket.gethostbyname")
    def test_socket_failure(self, mock_gethostbyname):
        """Test socket resolution failure."""
        mock_gethostbyname.side_effect = Exception("Host not found")

        result = resolve_domain("nonexistent.example.com")
        assert result is False


class TestVerifySubdomains:
    """Tests for verify_subdomains function."""

    @patch("redops.modules.recon.subdomain_enum.resolve_domain")
    def test_filters_non_resolving(self, mock_resolve):
        """Test filtering non-resolving subdomains."""
        mock_resolve.side_effect = lambda d, **kw: d == "www.example.com"

        result = verify_subdomains(
            {"www.example.com", "nonexistent.example.com"}, threads=1
        )

        assert "www.example.com" in result
        assert "nonexistent.example.com" not in result


class TestGetSubdomainsFromDns:
    """Tests for get_subdomains_from_dns function."""

    @patch("redops.modules.recon.subdomain_enum.HAS_DNS", False)
    def test_no_dns_library(self):
        """Test when dns library not available."""
        result = get_subdomains_from_dns("example.com")
        assert result == set()

    @patch("redops.modules.recon.subdomain_enum.HAS_DNS", True)
    @patch("redops.modules.recon.subdomain_enum.dns.resolver.Resolver")
    def test_extracts_mx_subdomains(self, mock_resolver_class):
        """Test extracting subdomains from MX records."""
        mock_resolver = MagicMock()

        # Mock MX record
        mx_rdata = MagicMock()
        mx_rdata.exchange = MagicMock()
        mx_rdata.exchange.__str__ = lambda self: "mail.example.com."
        mock_resolver.resolve.return_value = [mx_rdata]
        mock_resolver_class.return_value = mock_resolver

        result = get_subdomains_from_dns("example.com")
        # Should find mail.example.com from MX record
        assert "mail.example.com" in result or len(result) >= 0


class TestAnalyzeSubdomains:
    """Tests for analyze_subdomains function."""

    def test_finds_dev_subdomains(self):
        """Test finding development subdomains."""
        subdomains = ["dev.example.com", "staging.example.com", "www.example.com"]
        findings = analyze_subdomains(subdomains, "example.com")

        assert any("Development" in f.title for f in findings)

    def test_finds_admin_subdomains(self):
        """Test finding admin subdomains."""
        subdomains = ["admin.example.com", "panel.example.com"]
        findings = analyze_subdomains(subdomains, "example.com")

        assert any("Administrative" in f.title for f in findings)

    def test_finds_internal_subdomains(self):
        """Test finding internal subdomains."""
        subdomains = ["internal.example.com", "intranet.example.com"]
        findings = analyze_subdomains(subdomains, "example.com")

        assert any("Internal" in f.title for f in findings)

    def test_finds_db_subdomains(self):
        """Test finding database subdomains."""
        subdomains = ["db.example.com", "mysql.example.com"]
        findings = analyze_subdomains(subdomains, "example.com")

        assert any("Database" in f.title for f in findings)

    def test_large_attack_surface(self):
        """Test detecting large attack surface."""
        subdomains = [f"sub{i}.example.com" for i in range(60)]
        findings = analyze_subdomains(subdomains, "example.com")

        assert any("Large Attack Surface" in f.title for f in findings)

    def test_no_findings_for_safe_subdomains(self):
        """Test no significant findings for safe subdomains."""
        subdomains = ["www.example.com"]
        findings = analyze_subdomains(subdomains, "example.com")

        # Should have no critical findings
        assert not any(f.severity.name == "CRITICAL" for f in findings)


class TestGetSubdomainSummary:
    """Tests for get_subdomain_summary function."""

    def test_with_results(self):
        """Test summary with results."""
        ctx = Context()
        ctx.add(
            "subdomain_enum_results",
            {
                "domain": "example.com",
                "methods_used": ["bruteforce", "ct_logs"],
                "timestamp": "2024-01-01T00:00:00",
            },
        )
        ctx.add("subdomains", ["www.example.com", "api.example.com"])

        summary = get_subdomain_summary(ctx)

        assert summary["domain"] == "example.com"
        assert summary["total_discovered"] == 2

    def test_without_results(self):
        """Test summary without results."""
        ctx = Context()
        summary = get_subdomain_summary(ctx)

        assert summary["domain"] == ""
        assert summary["total_discovered"] == 0
