"""Tests for the Recon Domains module."""

from unittest.mock import patch
import pytest
from redops.core.context import Context
from redops.modules.recon.domains import (
    get_dns_records,
    get_all_dns_records,
    analyze_txt_records,
    profile_domain,
    enumerate_dns,
    discover_subdomains,
    check_zone_transfer,
    _get_dns_records_socket,
    DNS_AVAILABLE,
)


class TestGetDnsRecords:
    """Tests for get_dns_records function."""

    def test_get_dns_records_success(self):
        """Test successful DNS record retrieval."""
        with patch(
            "redops.modules.recon.domains._get_dns_records_dnspython"
        ) as mock_dns:
            mock_dns.return_value = ["93.184.216.34"]

            records = get_dns_records("example.com", "A")

            assert len(records) > 0
            assert "93.184.216.34" in records

    def test_get_dns_records_failure(self):
        """Test DNS record retrieval with failure."""
        with patch(
            "redops.modules.recon.domains._get_dns_records_dnspython"
        ) as mock_dns:
            mock_dns.return_value = []

            records = get_dns_records("nonexistent.invalid", "A")

            assert records == []

    def test_get_dns_records_mx(self):
        """Test MX record retrieval."""
        with patch(
            "redops.modules.recon.domains._get_dns_records_dnspython"
        ) as mock_dns:
            mock_dns.return_value = ["10 mail.example.com.", "20 mail2.example.com."]

            records = get_dns_records("example.com", "MX")

            assert len(records) == 2
            assert "10 mail.example.com." in records

    def test_get_dns_records_txt(self):
        """Test TXT record retrieval."""
        with patch(
            "redops.modules.recon.domains._get_dns_records_dnspython"
        ) as mock_dns:
            mock_dns.return_value = ["v=spf1 include:_spf.google.com ~all"]

            records = get_dns_records("example.com", "TXT")

            assert len(records) == 1
            assert "v=spf1" in records[0]

    def test_socket_fallback(self):
        """Test socket fallback for A records."""
        with patch("socket.gethostbyname_ex") as mock_socket:
            mock_socket.return_value = ("example.com", [], ["93.184.216.34"])

            records = _get_dns_records_socket("example.com")

            assert "93.184.216.34" in records

    def test_socket_fallback_failure(self):
        """Test socket fallback handles errors."""
        with patch("socket.gethostbyname_ex") as mock_socket:
            mock_socket.side_effect = Exception("DNS lookup failed")

            records = _get_dns_records_socket("nonexistent.invalid")

            assert records == []


class TestGetAllDnsRecords:
    """Tests for get_all_dns_records function."""

    def test_get_all_records(self):
        """Test fetching all record types."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:

            def side_effect(domain, rtype):
                if rtype == "A":
                    return ["93.184.216.34"]
                elif rtype == "MX":
                    return ["10 mail.example.com."]
                elif rtype == "TXT":
                    return ["v=spf1 -all"]
                return []

            mock_dns.side_effect = side_effect

            results = get_all_dns_records("example.com")

            assert "A" in results
            assert "MX" in results
            assert "TXT" in results
            assert "AAAA" not in results  # Empty results excluded


class TestAnalyzeTxtRecords:
    """Tests for TXT record analysis."""

    def test_analyze_spf(self):
        """Test SPF record detection."""
        txt_records = ["v=spf1 include:_spf.google.com ~all"]
        analysis = analyze_txt_records(txt_records)

        assert analysis["spf"] is not None
        assert "v=spf1" in analysis["spf"]

    def test_analyze_dmarc(self):
        """Test DMARC record detection."""
        txt_records = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        analysis = analyze_txt_records(txt_records)

        assert analysis["dmarc"] is not None

    def test_analyze_google_verification(self):
        """Test Google site verification detection."""
        txt_records = ["google-site-verification=abc123"]
        analysis = analyze_txt_records(txt_records)

        assert len(analysis["verification_records"]) == 1
        assert analysis["verification_records"][0][0] == "google"

    def test_analyze_microsoft_verification(self):
        """Test Microsoft verification detection."""
        txt_records = ["MS=ms12345678"]
        analysis = analyze_txt_records(txt_records)

        assert len(analysis["verification_records"]) == 1
        assert analysis["verification_records"][0][0] == "microsoft"

    def test_analyze_multiple_records(self):
        """Test analysis of multiple TXT records."""
        txt_records = [
            "v=spf1 -all",
            "google-site-verification=abc",
            "some-other-record",
        ]
        analysis = analyze_txt_records(txt_records)

        assert analysis["spf"] is not None
        assert len(analysis["verification_records"]) == 1
        assert len(analysis["other"]) == 1


class TestProfileDomain:
    """Tests for profile_domain function."""

    def test_profile_domain_success(self):
        """Test successful domain profiling."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {
                "A": ["93.184.216.34", "93.184.216.35"],
                "MX": ["10 mail.example.com."],
                "TXT": ["v=spf1 -all"],
                "NS": ["ns1.example.com.", "ns2.example.com."],
            }

            ctx = Context(target="example.com")
            result = profile_domain(ctx)

            assert result is not None
            assert "domain_profile" in result.data
            profile = result.data["domain_profile"]
            assert profile["domain"] == "example.com"
            assert "dns_records" in profile
            assert profile["has_spf"] is True

    def test_profile_domain_with_params(self):
        """Test domain profiling with explicit domain in params."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {"A": ["192.0.2.1"]}

            ctx = Context(target="default.com")
            result = profile_domain(ctx, params={"domain": "custom.com"})

            profile = result.data["domain_profile"]
            assert profile["domain"] == "custom.com"

    def test_profile_domain_no_target(self):
        """Test domain profiling without target."""
        ctx = Context()
        result = profile_domain(ctx)

        assert result is not None
        warnings = result.get_logs(level="WARNING")
        assert len(warnings) > 0

    def test_profile_domain_dns_error(self):
        """Test domain profiling with DNS errors."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.side_effect = Exception("DNS error")

            ctx = Context(target="example.com")
            result = profile_domain(ctx)

            assert result is not None
            errors = result.get_logs(level="ERROR")
            assert len(errors) > 0

    def test_profile_domain_creates_findings(self):
        """Test that domain profiling creates findings."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {"A": ["93.184.216.34"]}

            ctx = Context(target="test.com")
            result = profile_domain(ctx)

            # Check for finding in context data
            finding_keys = [
                key for key in result.data.keys() if key.startswith("finding_")
            ]
            assert len(finding_keys) > 0

    def test_profile_domain_missing_spf_finding(self):
        """Test that missing SPF creates a warning finding."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {
                "A": ["93.184.216.34"],
                "TXT": ["some-other-record"],  # No SPF
            }

            ctx = Context(target="test.com")
            result = profile_domain(ctx)

            # Should have a finding about missing SPF
            assert "finding_no_spf_test.com" in result.data

    def test_profile_domain_ipv6_detection(self):
        """Test IPv6 detection."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {
                "A": ["93.184.216.34"],
                "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            }

            ctx = Context(target="test.com")
            result = profile_domain(ctx)

            profile = result.data["domain_profile"]
            assert profile["has_ipv6"] is True


class TestEnumerateDns:
    """Tests for enumerate_dns function."""

    def test_enumerate_dns_success(self):
        """Test successful DNS enumeration."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:

            def side_effect(domain, rtype):
                if rtype == "A":
                    return ["93.184.216.34", "93.184.216.35"]
                return []

            mock_dns.side_effect = side_effect

            ctx = Context(target="example.com")
            result = enumerate_dns(ctx)

            assert result is not None
            assert "dns_enumeration" in result.data
            dns_data = result.data["dns_enumeration"]
            assert dns_data["domain"] == "example.com"
            assert "A" in dns_data
            assert len(dns_data["A"]) == 2

    def test_enumerate_dns_with_params(self):
        """Test DNS enumeration with custom domain."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:
            mock_dns.return_value = ["192.0.2.1"]

            ctx = Context(target="default.com")
            result = enumerate_dns(ctx, params={"domain": "custom.com"})

            dns_data = result.data["dns_enumeration"]
            assert dns_data["domain"] == "custom.com"

    def test_enumerate_dns_no_target(self):
        """Test DNS enumeration without target."""
        ctx = Context()
        result = enumerate_dns(ctx)

        assert result is not None
        warnings = result.get_logs(level="WARNING")
        assert any("no domain" in log["message"].lower() for log in warnings)

    def test_enumerate_dns_all_record_types(self):
        """Test that all record types are included."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:
            mock_dns.return_value = []

            ctx = Context(target="example.com")
            result = enumerate_dns(ctx)

            dns_data = result.data["dns_enumeration"]
            assert "A" in dns_data
            assert "AAAA" in dns_data
            assert "MX" in dns_data
            assert "TXT" in dns_data

    def test_enumerate_dns_custom_record_types(self):
        """Test enumeration with custom record types."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:
            mock_dns.return_value = ["record"]

            ctx = Context(target="example.com")
            result = enumerate_dns(ctx, params={"record_types": ["A", "MX"]})

            dns_data = result.data["dns_enumeration"]
            assert "A" in dns_data
            assert "MX" in dns_data
            # Should not query types not in the list
            assert mock_dns.call_count == 2

    def test_enumerate_dns_total_records(self):
        """Test total records count."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:

            def side_effect(domain, rtype):
                if rtype == "A":
                    return ["1.1.1.1", "2.2.2.2"]
                elif rtype == "MX":
                    return ["10 mail.example.com."]
                return []

            mock_dns.side_effect = side_effect

            ctx = Context(target="example.com")
            result = enumerate_dns(ctx)

            dns_data = result.data["dns_enumeration"]
            assert dns_data["total_records"] == 3


class TestDiscoverSubdomains:
    """Tests for discover_subdomains function."""

    def test_discover_subdomains_success(self):
        """Test successful subdomain discovery."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:

            def side_effect(subdomain, rtype):
                if subdomain == "www.example.com":
                    return ["93.184.216.34"]
                elif subdomain == "mail.example.com":
                    return ["93.184.216.35"]
                return []

            mock_dns.side_effect = side_effect

            ctx = Context(target="example.com")
            result = discover_subdomains(ctx)

            assert result is not None
            assert "subdomains" in result.data
            subdomains = result.data["subdomains"]
            assert len(subdomains) == 2

    def test_discover_subdomains_no_target(self):
        """Test subdomain discovery without target."""
        ctx = Context()
        result = discover_subdomains(ctx)

        assert result is not None
        warnings = result.get_logs(level="WARNING")
        assert len(warnings) > 0

    def test_discover_subdomains_with_params(self):
        """Test subdomain discovery with custom domain."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:
            mock_dns.return_value = []

            ctx = Context(target="default.com")
            result = discover_subdomains(ctx, params={"domain": "custom.com"})

            assert result is not None
            info_logs = result.get_logs(level="INFO")
            assert any("custom.com" in log["message"] for log in info_logs)

    def test_discover_subdomains_custom_wordlist(self):
        """Test subdomain discovery with custom wordlist."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:
            mock_dns.return_value = ["1.2.3.4"]

            ctx = Context(target="example.com")
            discover_subdomains(ctx, params={"wordlist": ["custom1", "custom2"]})

            # Should only check custom prefixes
            assert mock_dns.call_count == 2

    def test_discover_subdomains_creates_finding(self):
        """Test that finding subdomains creates a finding."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:

            def side_effect(subdomain, rtype):
                if subdomain == "www.example.com":
                    return ["1.2.3.4"]
                return []

            mock_dns.side_effect = side_effect

            ctx = Context(target="example.com")
            result = discover_subdomains(ctx)

            assert "finding_subdomains_example.com" in result.data


class TestCheckZoneTransfer:
    """Tests for check_zone_transfer function."""

    def test_zone_transfer_no_target(self):
        """Test zone transfer check without target."""
        ctx = Context()
        result = check_zone_transfer(ctx)

        warnings = result.get_logs(level="WARNING")
        assert len(warnings) > 0

    def test_zone_transfer_denied(self):
        """Test zone transfer check when denied (secure)."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_ns:
            mock_ns.return_value = ["ns1.example.com."]

            with patch("dns.zone.from_xfr") as mock_xfr:
                mock_xfr.side_effect = Exception("Transfer failed")

                ctx = Context(target="example.com")
                result = check_zone_transfer(ctx)

                zone_data = result.data["zone_transfer"]
                assert zone_data["vulnerable"] is False

    @pytest.mark.skipif(not DNS_AVAILABLE, reason="dnspython not available")
    def test_zone_transfer_skipped_without_dnspython(self):
        """Test zone transfer is skipped gracefully."""
        with patch("redops.modules.recon.domains.DNS_AVAILABLE", False):
            ctx = Context(target="example.com")

            # Re-import to get the patched version
            from redops.modules.recon import domains

            original = domains.DNS_AVAILABLE
            domains.DNS_AVAILABLE = False

            check_zone_transfer(ctx)

            domains.DNS_AVAILABLE = original

            # Should log a warning about dnspython


class TestLogging:
    """Tests for logging behavior."""

    def test_profile_domain_logging(self):
        """Test that domain profiling creates appropriate logs."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {"A": ["93.184.216.34"]}

            ctx = Context(target="example.com")
            result = profile_domain(ctx)

            info_logs = result.get_logs(level="INFO")
            assert len(info_logs) > 0
            assert any("profiling" in log["message"].lower() for log in info_logs)
            assert any("completed" in log["message"].lower() for log in info_logs)

    def test_enumerate_dns_logging(self):
        """Test that DNS enumeration creates appropriate logs."""
        with patch("redops.modules.recon.domains.get_dns_records") as mock_dns:
            mock_dns.return_value = ["93.184.216.34"]

            ctx = Context(target="example.com")
            result = enumerate_dns(ctx)

            info_logs = result.get_logs(level="INFO")
            assert any("enumerating" in log["message"].lower() for log in info_logs)
            assert any("completed" in log["message"].lower() for log in info_logs)
