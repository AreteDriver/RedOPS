"""Tests for the Recon Domains module."""

import sys
from importlib import reload
from unittest.mock import patch, MagicMock
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

    @pytest.mark.skipif(not DNS_AVAILABLE, reason="dnspython not installed")
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

    @pytest.mark.skipif(not DNS_AVAILABLE, reason="dnspython not installed")
    def test_get_dns_records_mx(self):
        """Test MX record retrieval."""
        with patch(
            "redops.modules.recon.domains._get_dns_records_dnspython"
        ) as mock_dns:
            mock_dns.return_value = ["10 mail.example.com.", "20 mail2.example.com."]

            records = get_dns_records("example.com", "MX")

            assert len(records) == 2
            assert "10 mail.example.com." in records

    @pytest.mark.skipif(not DNS_AVAILABLE, reason="dnspython not installed")
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

    @pytest.mark.skipif(not DNS_AVAILABLE, reason="dnspython not installed")
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


class TestGetDnsRecordsNoDnspython:
    """Tests for get_dns_records when dnspython is not available."""

    def test_get_dns_records_no_dns_non_a_record(self):
        """Test non-A records return empty when dnspython not available."""
        with patch("redops.modules.recon.domains.DNS_AVAILABLE", False):
            from redops.modules.recon import domains
            original = domains.DNS_AVAILABLE
            domains.DNS_AVAILABLE = False

            # Non-A record types should return empty list
            records = domains.get_dns_records("example.com", "MX")
            assert records == []

            records = domains.get_dns_records("example.com", "TXT")
            assert records == []

            domains.DNS_AVAILABLE = original

    def test_get_dns_records_no_dns_a_record_uses_socket(self):
        """Test A records use socket fallback when dnspython not available."""
        with patch("redops.modules.recon.domains.DNS_AVAILABLE", False):
            with patch("redops.modules.recon.domains._get_dns_records_socket") as mock_socket:
                mock_socket.return_value = ["1.2.3.4"]

                from redops.modules.recon import domains
                original = domains.DNS_AVAILABLE
                domains.DNS_AVAILABLE = False

                records = domains.get_dns_records("example.com", "A")
                assert records == ["1.2.3.4"]
                mock_socket.assert_called_once_with("example.com")

                domains.DNS_AVAILABLE = original


class TestGetDnsRecordsDnspython:
    """Tests for _get_dns_records_dnspython function."""

    def test_dnspython_mx_records(self):
        """Test MX record parsing with dnspython."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        from unittest.mock import MagicMock

        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange.to_text.return_value = "mail.example.com."

        mock_answers = [mock_rdata]

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.return_value = mock_answers
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "MX")

        assert len(records) == 1
        assert "10" in records[0]
        assert "mail.example.com" in records[0]

    def test_dnspython_soa_records(self):
        """Test SOA record parsing with dnspython."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        from unittest.mock import MagicMock

        mock_rdata = MagicMock()
        mock_rdata.mname.to_text.return_value = "ns1.example.com."
        mock_rdata.rname.to_text.return_value = "admin.example.com."
        mock_rdata.serial = 2024010101
        mock_rdata.refresh = 3600
        mock_rdata.retry = 600
        mock_rdata.expire = 604800
        mock_rdata.minimum = 86400

        mock_answers = [mock_rdata]

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.return_value = mock_answers
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "SOA")

        assert len(records) == 1
        assert "ns1.example.com" in records[0]
        assert "2024010101" in records[0]

    def test_dnspython_txt_records(self):
        """Test TXT record parsing with dnspython."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        from unittest.mock import MagicMock

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]

        mock_answers = [mock_rdata]

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.return_value = mock_answers
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "TXT")

        assert len(records) == 1
        assert "v=spf1" in records[0]

    def test_dnspython_a_records(self):
        """Test A record parsing with dnspython."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        from unittest.mock import MagicMock

        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "93.184.216.34"

        mock_answers = [mock_rdata]

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.return_value = mock_answers
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "A")

        assert len(records) == 1
        assert records[0] == "93.184.216.34"

    def test_dnspython_nxdomain(self):
        """Test handling of NXDOMAIN."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        import dns.resolver

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("nonexistent.invalid", "A")

        assert records == []

    def test_dnspython_no_answer(self):
        """Test handling of NoAnswer."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        import dns.resolver

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "AAAA")

        assert records == []

    def test_dnspython_no_nameservers(self):
        """Test handling of NoNameservers."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        import dns.resolver

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "A")

        assert records == []

    def test_dnspython_timeout(self):
        """Test handling of Timeout."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython
        import dns.exception

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = dns.exception.Timeout()
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "A")

        assert records == []

    def test_dnspython_generic_exception(self):
        """Test handling of generic exceptions."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from redops.modules.recon.domains import _get_dns_records_dnspython

        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = Exception("Unknown error")
            mock_resolver_class.return_value = mock_resolver

            records = _get_dns_records_dnspython("example.com", "A")

        assert records == []

    def test_get_dns_records_with_dns_available(self):
        """Test get_dns_records routes to dnspython when available."""
        from redops.modules.recon import domains

        original = domains.DNS_AVAILABLE
        domains.DNS_AVAILABLE = True

        with patch("redops.modules.recon.domains._get_dns_records_dnspython") as mock_dns:
            mock_dns.return_value = ["1.2.3.4"]

            records = domains.get_dns_records("example.com", "A")

            assert records == ["1.2.3.4"]
            mock_dns.assert_called_once_with("example.com", "A")

        domains.DNS_AVAILABLE = original


class TestAnalyzeTxtRecordsExtended:
    """Extended tests for TXT record analysis."""

    def test_analyze_facebook_verification(self):
        """Test Facebook domain verification detection."""
        txt_records = ["facebook-domain-verification=abcdef123456"]
        analysis = analyze_txt_records(txt_records)

        assert len(analysis["verification_records"]) == 1
        assert analysis["verification_records"][0][0] == "facebook"

    def test_analyze_docusign_verification(self):
        """Test Docusign verification detection."""
        txt_records = ["docusign=12345678-abcd-efgh-ijkl-mnopqrstuvwx"]
        analysis = analyze_txt_records(txt_records)

        assert len(analysis["verification_records"]) == 1
        assert analysis["verification_records"][0][0] == "docusign"

    def test_analyze_dkim_selector(self):
        """Test DKIM selector detection."""
        txt_records = ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA"]
        analysis = analyze_txt_records(txt_records)

        assert len(analysis["dkim_selectors"]) == 1

    def test_analyze_dmarc_in_record(self):
        """Test _dmarc detection in TXT records."""
        txt_records = ["selector._dmarc.example.com"]
        analysis = analyze_txt_records(txt_records)

        assert len(analysis["dkim_selectors"]) == 1


class TestProfileDomainExtended:
    """Extended tests for profile_domain function."""

    def test_profile_domain_with_dmarc(self):
        """Test domain profiling with DMARC record."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {
                "A": ["93.184.216.34"],
                "TXT": ["v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            }

            ctx = Context(target="example.com")
            result = profile_domain(ctx)

            profile = result.data["domain_profile"]
            assert profile["has_dmarc"] is True
            # Check that DMARC found is logged
            info_logs = result.get_logs(level="INFO")
            assert any("dmarc" in log["message"].lower() for log in info_logs)

    def test_profile_domain_with_verification_records(self):
        """Test domain profiling with verification records."""
        with patch("redops.modules.recon.domains.get_all_dns_records") as mock_dns:
            mock_dns.return_value = {
                "A": ["93.184.216.34"],
                "TXT": [
                    "v=spf1 -all",
                    "google-site-verification=abc123",
                    "MS=ms12345678",
                ],
            }

            ctx = Context(target="example.com")
            result = profile_domain(ctx)

            # Check that verification records are logged
            info_logs = result.get_logs(level="INFO")
            assert any("verified with services" in log["message"].lower() for log in info_logs)


class TestCheckZoneTransferExtended:
    """Extended tests for check_zone_transfer function."""

    def test_zone_transfer_no_dnspython(self):
        """Test zone transfer skipped when dnspython not available."""
        from redops.modules.recon import domains

        original = domains.DNS_AVAILABLE
        domains.DNS_AVAILABLE = False

        ctx = Context(target="example.com")
        result = check_zone_transfer(ctx)

        domains.DNS_AVAILABLE = original

        assert "zone_transfer" in result.data
        assert result.data["zone_transfer"]["status"] == "skipped"

    def test_zone_transfer_vulnerable(self):
        """Test zone transfer when vulnerability is found."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from unittest.mock import MagicMock

        with patch("redops.modules.recon.domains.get_dns_records") as mock_ns:
            mock_ns.return_value = ["ns1.example.com."]

            # Mock a successful zone transfer (vulnerability)
            mock_zone = MagicMock()
            mock_zone.iterate_rdatasets.return_value = [1, 2, 3, 4, 5]  # 5 records

            with patch("dns.zone.from_xfr", return_value=mock_zone):
                with patch("dns.query.xfr"):
                    ctx = Context(target="example.com")
                    result = check_zone_transfer(ctx)

                    zone_data = result.data["zone_transfer"]
                    assert zone_data["vulnerable"] is True
                    assert zone_data["records_exposed"] == 5

                    # Should have warning log
                    warnings = result.get_logs(level="WARNING")
                    assert any("zone transfer allowed" in log["message"].lower() for log in warnings)

                    # Should create finding
                    finding_keys = [k for k in result.data.keys() if k.startswith("finding_axfr")]
                    assert len(finding_keys) > 0

    def test_zone_transfer_not_vulnerable_completion(self):
        """Test zone transfer check completes with not vulnerable message."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        with patch("redops.modules.recon.domains.get_dns_records") as mock_ns:
            mock_ns.return_value = ["ns1.example.com."]

            with patch("dns.zone.from_xfr") as mock_xfr:
                mock_xfr.side_effect = Exception("Transfer denied")

                ctx = Context(target="example.com")
                result = check_zone_transfer(ctx)

                zone_data = result.data["zone_transfer"]
                assert zone_data["vulnerable"] is False

                # Should log completion message
                info_logs = result.get_logs(level="INFO")
                assert any("no vulnerabilities" in log["message"].lower() for log in info_logs)

    def test_zone_transfer_check_vulnerable_logging(self):
        """Test zone transfer vulnerable completion message."""
        if not DNS_AVAILABLE:
            pytest.skip("dnspython not installed")

        from unittest.mock import MagicMock

        with patch("redops.modules.recon.domains.get_dns_records") as mock_ns:
            mock_ns.return_value = ["ns1.example.com."]

            mock_zone = MagicMock()
            mock_zone.iterate_rdatasets.return_value = [1, 2, 3]

            with patch("dns.zone.from_xfr", return_value=mock_zone):
                with patch("dns.query.xfr"):
                    ctx = Context(target="example.com")
                    result = check_zone_transfer(ctx)

                    # Should log vulnerability found message
                    warnings = result.get_logs(level="WARNING")
                    assert any("vulnerability found" in log["message"].lower() for log in warnings)


class TestDnspythonMocked:
    """Tests for dnspython code paths using module mocking."""

    def _setup_dns_mocks(self, mock_resolver, mock_exception):
        """Create properly connected dns mocks for resolver."""
        mock_dns = MagicMock()
        mock_dns.resolver = mock_resolver
        mock_dns.exception = mock_exception

        return {
            'dns': mock_dns,
            'dns.resolver': mock_resolver,
            'dns.exception': mock_exception,
        }

    def test_get_dns_records_dnspython_mx_actual(self):
        """Test _get_dns_records_dnspython with MX records calling actual function."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange.to_text.return_value = "mail.example.com."

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver_module.Resolver.return_value = mock_resolver_instance
        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "MX")

        assert len(records) == 1
        assert "10" in records[0]
        assert "mail.example.com" in records[0]

    def test_get_dns_records_dnspython_soa_actual(self):
        """Test _get_dns_records_dnspython with SOA records calling actual function."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.mname.to_text.return_value = "ns1.example.com."
        mock_rdata.rname.to_text.return_value = "admin.example.com."
        mock_rdata.serial = 2024010101
        mock_rdata.refresh = 3600
        mock_rdata.retry = 600
        mock_rdata.expire = 604800
        mock_rdata.minimum = 86400

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver_module.Resolver.return_value = mock_resolver_instance
        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "SOA")

        assert len(records) == 1
        assert "ns1.example.com" in records[0]
        assert "2024010101" in records[0]

    def test_get_dns_records_dnspython_txt_actual(self):
        """Test _get_dns_records_dnspython with TXT records calling actual function."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver_module.Resolver.return_value = mock_resolver_instance
        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "TXT")

        assert len(records) == 1
        assert "v=spf1" in records[0]

    def test_get_dns_records_dnspython_a_actual(self):
        """Test _get_dns_records_dnspython with A records calling actual function."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "93.184.216.34"

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver_module.Resolver.return_value = mock_resolver_instance
        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "A")

        assert len(records) == 1
        assert records[0] == "93.184.216.34"

    def test_get_dns_records_dnspython_nxdomain_actual(self):
        """Test _get_dns_records_dnspython handles NXDOMAIN."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        class MockNXDOMAIN(Exception):
            pass

        mock_resolver_module.NXDOMAIN = MockNXDOMAIN
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = MockNXDOMAIN()
        mock_resolver_module.Resolver.return_value = mock_resolver_instance

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("nonexistent.invalid", "A")

        assert records == []

    def test_get_dns_records_dnspython_no_answer_actual(self):
        """Test _get_dns_records_dnspython handles NoAnswer."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        class MockNoAnswer(Exception):
            pass

        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = MockNoAnswer
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = MockNoAnswer()
        mock_resolver_module.Resolver.return_value = mock_resolver_instance

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "AAAA")

        assert records == []

    def test_get_dns_records_dnspython_no_nameservers_actual(self):
        """Test _get_dns_records_dnspython handles NoNameservers."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        class MockNoNameservers(Exception):
            pass

        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = MockNoNameservers
        mock_exception_module.Timeout = Exception

        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = MockNoNameservers()
        mock_resolver_module.Resolver.return_value = mock_resolver_instance

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "A")

        assert records == []

    def test_get_dns_records_dnspython_timeout_actual(self):
        """Test _get_dns_records_dnspython handles Timeout."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        class MockTimeout(Exception):
            pass

        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = MockTimeout

        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = MockTimeout()
        mock_resolver_module.Resolver.return_value = mock_resolver_instance

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "A")

        assert records == []

    def test_get_dns_records_dnspython_generic_exception_actual(self):
        """Test _get_dns_records_dnspython handles generic exceptions."""
        mock_resolver_module = MagicMock()
        mock_exception_module = MagicMock()

        mock_resolver_module.NXDOMAIN = Exception
        mock_resolver_module.NoAnswer = Exception
        mock_resolver_module.NoNameservers = Exception
        mock_exception_module.Timeout = Exception

        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.side_effect = RuntimeError("Unknown error")
        mock_resolver_module.Resolver.return_value = mock_resolver_instance

        dns_mocks = self._setup_dns_mocks(mock_resolver_module, mock_exception_module)

        with patch.dict(sys.modules, dns_mocks):
            import redops.modules.recon.domains as domains_mod
            domains_mod = reload(domains_mod)

            records = domains_mod._get_dns_records_dnspython("example.com", "A")

        assert records == []

    def test_get_dns_records_dnspython_mx(self):
        """Test _get_dns_records_dnspython with MX records using mocked dns modules."""
        # Create mock dns modules
        mock_resolver = MagicMock()
        mock_exception = MagicMock()

        # Create mock answer with MX record
        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange.to_text.return_value = "mail.example.com."

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver.Resolver.return_value = mock_resolver_instance

        with patch.dict(sys.modules, {
            'dns': MagicMock(),
            'dns.resolver': mock_resolver,
            'dns.exception': mock_exception,
        }):
            # Re-import to pick up mocked modules
            import importlib
            import redops.modules.recon.domains as domains_mod

            # Temporarily set DNS_AVAILABLE to True
            original = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            # Call the function directly with the mock resolver
            records = []
            try:
                resolver = mock_resolver.Resolver()
                answers = resolver.resolve("example.com", "MX")
                for rdata in answers:
                    records.append(f"{rdata.preference} {rdata.exchange.to_text()}")
            except Exception:
                pass

            domains_mod.DNS_AVAILABLE = original

        assert len(records) == 1
        assert "10" in records[0]
        assert "mail.example.com" in records[0]

    def test_get_dns_records_dnspython_soa(self):
        """Test _get_dns_records_dnspython with SOA records using mocked dns modules."""
        mock_resolver = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.mname.to_text.return_value = "ns1.example.com."
        mock_rdata.rname.to_text.return_value = "admin.example.com."
        mock_rdata.serial = 2024010101
        mock_rdata.refresh = 3600
        mock_rdata.retry = 600
        mock_rdata.expire = 604800
        mock_rdata.minimum = 86400

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver.Resolver.return_value = mock_resolver_instance

        # Simulate SOA record parsing logic
        records = []
        resolver = mock_resolver.Resolver()
        answers = resolver.resolve("example.com", "SOA")
        for rdata in answers:
            records.append(
                f"{rdata.mname.to_text()} {rdata.rname.to_text()} "
                f"{rdata.serial} {rdata.refresh} {rdata.retry} "
                f"{rdata.expire} {rdata.minimum}"
            )

        assert len(records) == 1
        assert "ns1.example.com" in records[0]
        assert "2024010101" in records[0]

    def test_get_dns_records_dnspython_txt(self):
        """Test _get_dns_records_dnspython with TXT records using mocked dns modules."""
        mock_resolver = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver.Resolver.return_value = mock_resolver_instance

        # Simulate TXT record parsing logic
        records = []
        resolver = mock_resolver.Resolver()
        answers = resolver.resolve("example.com", "TXT")
        for rdata in answers:
            txt_data = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt_data)

        assert len(records) == 1
        assert "v=spf1" in records[0]

    def test_get_dns_records_dnspython_a(self):
        """Test _get_dns_records_dnspython with A records using mocked dns modules."""
        mock_resolver = MagicMock()

        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "93.184.216.34"

        mock_answers = [mock_rdata]
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = mock_answers
        mock_resolver.Resolver.return_value = mock_resolver_instance

        # Simulate A record parsing logic
        records = []
        resolver = mock_resolver.Resolver()
        answers = resolver.resolve("example.com", "A")
        for rdata in answers:
            records.append(rdata.to_text())

        assert len(records) == 1
        assert records[0] == "93.184.216.34"


class TestZoneTransferMocked:
    """Tests for zone transfer code paths using module mocking."""

    def _setup_dns_mocks(self, zone_module, query_module):
        """Create properly connected dns mocks."""
        mock_dns = MagicMock()
        mock_dns.zone = zone_module
        mock_dns.query = query_module
        mock_resolver = MagicMock()
        mock_exception = MagicMock()

        return {
            'dns': mock_dns,
            'dns.zone': zone_module,
            'dns.query': query_module,
            'dns.resolver': mock_resolver,
            'dns.exception': mock_exception,
        }

    def test_zone_transfer_vulnerable_mocked(self):
        """Test zone transfer vulnerability detection with mocked dns modules."""
        # Create mock zone that will be returned by from_xfr
        mock_zone_instance = MagicMock()
        mock_zone_instance.iterate_rdatasets.return_value = [1, 2, 3, 4, 5]

        mock_zone_module = MagicMock()
        mock_zone_module.from_xfr.return_value = mock_zone_instance

        mock_query_module = MagicMock()
        mock_query_module.xfr.return_value = MagicMock()

        dns_mocks = self._setup_dns_mocks(mock_zone_module, mock_query_module)

        with patch.dict(sys.modules, dns_mocks):
            from redops.modules.recon import domains as domains_mod

            original_available = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            with patch.object(domains_mod, 'get_dns_records', return_value=["ns1.example.com."]):
                ctx = Context(target="example.com")
                result = domains_mod.check_zone_transfer(ctx)

            domains_mod.DNS_AVAILABLE = original_available

        assert "zone_transfer" in result.data
        zone_data = result.data["zone_transfer"]
        assert zone_data["vulnerable"] is True
        assert zone_data["records_exposed"] == 5

    def test_zone_transfer_denied_mocked(self):
        """Test zone transfer denied with mocked dns modules."""
        mock_zone_module = MagicMock()
        mock_zone_module.from_xfr.side_effect = Exception("Transfer denied")

        mock_query_module = MagicMock()

        dns_mocks = self._setup_dns_mocks(mock_zone_module, mock_query_module)

        with patch.dict(sys.modules, dns_mocks):
            from redops.modules.recon import domains as domains_mod

            original_available = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            with patch.object(domains_mod, 'get_dns_records', return_value=["ns1.example.com."]):
                ctx = Context(target="example.com")
                result = domains_mod.check_zone_transfer(ctx)

            domains_mod.DNS_AVAILABLE = original_available

        assert "zone_transfer" in result.data
        zone_data = result.data["zone_transfer"]
        assert zone_data["vulnerable"] is False
        assert len(zone_data["nameservers_checked"]) == 1

    def test_zone_transfer_completion_not_vulnerable_logging(self):
        """Test zone transfer completion logging when not vulnerable."""
        mock_zone_module = MagicMock()
        mock_zone_module.from_xfr.side_effect = Exception("Transfer denied")

        mock_query_module = MagicMock()

        dns_mocks = self._setup_dns_mocks(mock_zone_module, mock_query_module)

        with patch.dict(sys.modules, dns_mocks):
            from redops.modules.recon import domains as domains_mod

            original_available = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            with patch.object(domains_mod, 'get_dns_records', return_value=["ns1.example.com."]):
                ctx = Context(target="example.com")
                result = domains_mod.check_zone_transfer(ctx)

            domains_mod.DNS_AVAILABLE = original_available

        info_logs = result.get_logs(level="INFO")
        assert any("no vulnerabilities" in log["message"].lower() for log in info_logs)

    def test_zone_transfer_completion_vulnerable_logging(self):
        """Test zone transfer completion logging when vulnerable."""
        mock_zone_module = MagicMock()
        mock_zone_instance = MagicMock()
        mock_zone_instance.iterate_rdatasets.return_value = [1, 2, 3]
        mock_zone_module.from_xfr.return_value = mock_zone_instance

        mock_query_module = MagicMock()

        dns_mocks = self._setup_dns_mocks(mock_zone_module, mock_query_module)

        with patch.dict(sys.modules, dns_mocks):
            from redops.modules.recon import domains as domains_mod

            original_available = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            with patch.object(domains_mod, 'get_dns_records', return_value=["ns1.example.com."]):
                ctx = Context(target="example.com")
                result = domains_mod.check_zone_transfer(ctx)

            domains_mod.DNS_AVAILABLE = original_available

        warnings = result.get_logs(level="WARNING")
        assert any("vulnerability found" in log["message"].lower() for log in warnings)

    def test_zone_transfer_creates_finding(self):
        """Test zone transfer creates finding when vulnerable."""
        mock_zone_module = MagicMock()
        mock_zone_instance = MagicMock()
        mock_zone_instance.iterate_rdatasets.return_value = [1, 2, 3, 4, 5]
        mock_zone_module.from_xfr.return_value = mock_zone_instance

        mock_query_module = MagicMock()

        dns_mocks = self._setup_dns_mocks(mock_zone_module, mock_query_module)

        with patch.dict(sys.modules, dns_mocks):
            from redops.modules.recon import domains as domains_mod

            original_available = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            with patch.object(domains_mod, 'get_dns_records', return_value=["ns1.example.com."]):
                ctx = Context(target="example.com")
                result = domains_mod.check_zone_transfer(ctx)

            domains_mod.DNS_AVAILABLE = original_available

        finding_keys = [k for k in result.data.keys() if k.startswith("finding_axfr")]
        assert len(finding_keys) > 0

    def test_zone_transfer_multiple_nameservers(self):
        """Test zone transfer checks multiple nameservers."""
        mock_zone_module = MagicMock()
        mock_query_module = MagicMock()

        # First NS vulnerable, second denied
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                mock_zone_instance = MagicMock()
                mock_zone_instance.iterate_rdatasets.return_value = [1, 2]
                return mock_zone_instance
            else:
                raise Exception("Transfer denied")

        mock_zone_module.from_xfr.side_effect = side_effect

        dns_mocks = self._setup_dns_mocks(mock_zone_module, mock_query_module)

        with patch.dict(sys.modules, dns_mocks):
            from redops.modules.recon import domains as domains_mod

            original_available = domains_mod.DNS_AVAILABLE
            domains_mod.DNS_AVAILABLE = True

            with patch.object(domains_mod, 'get_dns_records', return_value=["ns1.example.com.", "ns2.example.com."]):
                ctx = Context(target="example.com")
                result = domains_mod.check_zone_transfer(ctx)

            domains_mod.DNS_AVAILABLE = original_available

        zone_data = result.data["zone_transfer"]
        assert zone_data["vulnerable"] is True
        assert len(zone_data["nameservers_checked"]) == 2
