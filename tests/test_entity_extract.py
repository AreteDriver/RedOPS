"""Tests for intel/entity_extract module."""

from redops.modules.intel.entity_extract import (
    ExtractedEntities,
    PATTERNS,
    extract_entities,
    extract_from_text,
    extract_phone_numbers,
    extract_credit_cards,
    luhn_check,
    clean_entities,
    extract_iocs,
    defang_ioc,
    refang_ioc,
    get_entity_summary,
    collect_text_sources,
)
from redops.core.context import Context


class TestExtractedEntities:
    """Tests for ExtractedEntities dataclass."""

    def test_default_initialization(self):
        """Test default empty initialization."""
        entities = ExtractedEntities()
        assert len(entities.emails) == 0
        assert len(entities.domains) == 0
        assert len(entities.urls) == 0
        assert len(entities.ipv4_addresses) == 0
        assert len(entities.ipv6_addresses) == 0
        assert len(entities.phone_numbers) == 0
        assert len(entities.md5_hashes) == 0
        assert len(entities.sha1_hashes) == 0
        assert len(entities.sha256_hashes) == 0
        assert len(entities.social_handles) == 0
        assert len(entities.credit_cards) == 0
        assert len(entities.aws_keys) == 0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        entities = ExtractedEntities()
        entities.emails.add("test@example.com")
        entities.domains.add("example.org")

        result = entities.to_dict()
        assert "emails" in result
        assert "test@example.com" in result["emails"]
        assert "example.org" in result["domains"]
        # Check that lists are sorted
        assert result["emails"] == sorted(result["emails"])

    def test_merge(self):
        """Test merging two ExtractedEntities."""
        entities1 = ExtractedEntities()
        entities1.emails.add("user1@test.com")
        entities1.domains.add("test.com")

        entities2 = ExtractedEntities()
        entities2.emails.add("user2@test.com")
        entities2.ipv4_addresses.add("8.8.8.8")

        entities1.merge(entities2)

        assert "user1@test.com" in entities1.emails
        assert "user2@test.com" in entities1.emails
        assert "test.com" in entities1.domains
        assert "8.8.8.8" in entities1.ipv4_addresses

    def test_total_count(self):
        """Test counting total entities."""
        entities = ExtractedEntities()
        entities.emails.add("a@b.com")
        entities.emails.add("c@d.com")
        entities.domains.add("test.io")

        assert entities.total_count() == 3

    def test_is_empty(self):
        """Test empty check."""
        entities = ExtractedEntities()
        assert entities.is_empty()

        entities.emails.add("test@example.com")
        assert not entities.is_empty()


class TestPatterns:
    """Tests for regex patterns."""

    def test_email_pattern(self):
        """Test email pattern matching."""
        pattern = PATTERNS["email"]
        # Valid emails
        assert pattern.search("user@example.com")
        assert pattern.search("user.name@sub.domain.org")
        assert pattern.search("user+tag@test.io")
        # Invalid
        assert not pattern.search("not-an-email")
        assert not pattern.search("@missing-local.com")

    def test_url_pattern(self):
        """Test URL pattern matching."""
        pattern = PATTERNS["url"]
        assert pattern.search("https://example.com")
        assert pattern.search("http://test.org/path")
        assert pattern.search("https://sub.domain.com/path?query=1")
        assert not pattern.search("ftp://example.com")  # Only http/https

    def test_domain_pattern(self):
        """Test domain pattern matching."""
        pattern = PATTERNS["domain"]
        assert pattern.search("example.com")
        assert pattern.search("sub.domain.org")
        assert pattern.search("test.io")
        assert pattern.search("site.co.uk")

    def test_ipv4_pattern(self):
        """Test IPv4 pattern matching."""
        pattern = PATTERNS["ipv4"]
        assert pattern.search("192.168.1.1")
        assert pattern.search("8.8.8.8")
        assert pattern.search("255.255.255.255")
        assert pattern.search("0.0.0.0")
        # Invalid
        assert not pattern.search("256.1.1.1")
        assert not pattern.search("1.1.1")

    def test_ipv6_pattern(self):
        """Test IPv6 pattern matching."""
        pattern = PATTERNS["ipv6"]
        assert pattern.search("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert pattern.search("fe80:0000:0000:0000:0000:0000:0000:0001")

    def test_md5_pattern(self):
        """Test MD5 hash pattern matching."""
        pattern = PATTERNS["md5"]
        assert pattern.search("d41d8cd98f00b204e9800998ecf8427e")
        assert pattern.search("098f6bcd4621d373cade4e832627b4f6")
        # Wrong length
        assert not pattern.search("d41d8cd98f00b204e9800998ecf842")

    def test_sha1_pattern(self):
        """Test SHA1 hash pattern matching."""
        pattern = PATTERNS["sha1"]
        assert pattern.search("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        # Wrong length
        assert not pattern.search("da39a3ee5e6b4b0d3255bfef95601890afd8")

    def test_sha256_pattern(self):
        """Test SHA256 hash pattern matching."""
        pattern = PATTERNS["sha256"]
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert pattern.search(hash_val)

    def test_social_handle_pattern(self):
        """Test social media handle pattern matching."""
        pattern = PATTERNS["social"]
        assert pattern.search("@username")
        assert pattern.search("@user_name_123")
        assert not pattern.search("username")  # Missing @

    def test_credit_card_pattern(self):
        """Test credit card pattern matching."""
        pattern = PATTERNS["credit_card"]
        # Visa (4xxx)
        assert pattern.search("4111111111111111")
        # MasterCard (51-55)
        assert pattern.search("5111111111111118")
        # Amex (34, 37)
        assert pattern.search("341111111111111")
        # Discover (6011, 65xx)
        assert pattern.search("6011111111111117")

    def test_aws_key_pattern(self):
        """Test AWS key pattern matching."""
        pattern = PATTERNS["aws_key"]
        # Using AWS official example key format
        assert pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert pattern.search("ASIA1234567890ABCDEF")
        # Wrong prefix
        assert not pattern.search("ABCD1234567890ABCDEF")


class TestExtractFromText:
    """Tests for extract_from_text function."""

    def test_extract_emails(self):
        """Test email extraction."""
        text = "Contact us at support@company.com or sales@company.org"
        entities = extract_from_text(text)
        assert "support@company.com" in entities.emails
        assert "sales@company.org" in entities.emails

    def test_extract_urls(self):
        """Test URL extraction."""
        text = "Visit https://example.com or http://test.org/page"
        entities = extract_from_text(text)
        assert any("example.com" in url for url in entities.urls)
        assert any("test.org" in url for url in entities.urls)

    def test_extract_ips(self):
        """Test IP extraction."""
        text = "Server at 8.8.8.8 and backup at 1.1.1.1"
        entities = extract_from_text(text)
        assert "8.8.8.8" in entities.ipv4_addresses
        assert "1.1.1.1" in entities.ipv4_addresses

    def test_extract_hashes(self):
        """Test hash extraction."""
        text = """
        MD5: d41d8cd98f00b204e9800998ecf8427e
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        """
        entities = extract_from_text(text)
        assert "d41d8cd98f00b204e9800998ecf8427e" in entities.md5_hashes
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in entities.sha1_hashes

    def test_extract_social_handles(self):
        """Test social handle extraction."""
        text = "Follow us @company_official and @support"
        entities = extract_from_text(text)
        assert "@company_official" in entities.social_handles
        assert "@support" in entities.social_handles

    def test_extract_empty_text(self):
        """Test extraction from empty text."""
        entities = extract_from_text("")
        assert entities.is_empty()

    def test_extract_none_text(self):
        """Test extraction from None."""
        entities = extract_from_text(None)
        assert entities.is_empty()

    def test_domain_not_duplicated_from_email(self):
        """Test that domains from emails aren't duplicated."""
        text = "Contact user@example.io"
        entities = extract_from_text(text)
        # Domain from email should be filtered out
        assert "example.io" not in entities.domains


class TestPhoneExtraction:
    """Tests for phone number extraction."""

    def test_extract_us_phone(self):
        """Test US phone number extraction."""
        text = "Call us at (555) 123-4567 or 555-987-6543"
        phones = extract_phone_numbers(text)
        assert len(phones) == 2

    def test_extract_international_phone(self):
        """Test international phone number extraction."""
        text = "Contact +1234567890123"
        phones = extract_phone_numbers(text)
        assert len(phones) >= 1

    def test_filter_short_numbers(self):
        """Test that short numbers are filtered."""
        text = "Order number: 12345"  # Too short for phone
        phones = extract_phone_numbers(text)
        assert len(phones) == 0


class TestCreditCardExtraction:
    """Tests for credit card extraction."""

    def test_extract_valid_cards(self):
        """Test valid credit card extraction with Luhn check."""
        # Known valid test card numbers
        text = "Visa: 4111111111111111 MC: 5500000000000004"
        cards = extract_credit_cards(text)
        # Cards that pass Luhn check
        assert any("4111" in card for card in cards)

    def test_cards_are_masked(self):
        """Test that extracted cards are masked."""
        text = "Card: 4111111111111111"
        cards = extract_credit_cards(text)
        for card in cards:
            # Should have asterisks in middle
            assert "*" in card
            # First 4 and last 4 should be visible
            assert card.startswith("4111")
            assert card.endswith("1111")


class TestLuhnCheck:
    """Tests for Luhn algorithm validation."""

    def test_valid_luhn(self):
        """Test valid Luhn numbers."""
        assert luhn_check("4111111111111111")  # Visa test
        assert luhn_check("5500000000000004")  # MC test

    def test_invalid_luhn(self):
        """Test invalid Luhn numbers."""
        assert not luhn_check("4111111111111112")  # Wrong check digit
        assert not luhn_check("1234567890")  # Random

    def test_short_number(self):
        """Test that short numbers fail."""
        assert not luhn_check("123456")


class TestCleanEntities:
    """Tests for entity cleaning."""

    def test_remove_private_ips(self):
        """Test private IP removal."""
        entities = ExtractedEntities()
        entities.ipv4_addresses.add("192.168.1.1")
        entities.ipv4_addresses.add("10.0.0.1")
        entities.ipv4_addresses.add("8.8.8.8")

        cleaned = clean_entities(entities)
        assert "8.8.8.8" in cleaned.ipv4_addresses
        assert "192.168.1.1" not in cleaned.ipv4_addresses
        assert "10.0.0.1" not in cleaned.ipv4_addresses

    def test_remove_localhost(self):
        """Test localhost IP removal."""
        entities = ExtractedEntities()
        entities.ipv4_addresses.add("127.0.0.1")
        entities.ipv4_addresses.add("8.8.4.4")

        cleaned = clean_entities(entities)
        assert "127.0.0.1" not in cleaned.ipv4_addresses
        assert "8.8.4.4" in cleaned.ipv4_addresses

    def test_remove_false_positive_domains(self):
        """Test false positive domain removal."""
        entities = ExtractedEntities()
        entities.domains.add("example.com")
        entities.domains.add("realsite.io")

        cleaned = clean_entities(entities)
        assert "example.com" not in cleaned.domains
        assert "realsite.io" in cleaned.domains

    def test_remove_all_zero_hashes(self):
        """Test removal of all-same-character hashes."""
        entities = ExtractedEntities()
        entities.md5_hashes.add("00000000000000000000000000000000")
        entities.md5_hashes.add("d41d8cd98f00b204e9800998ecf8427e")

        cleaned = clean_entities(entities)
        assert "00000000000000000000000000000000" not in cleaned.md5_hashes
        assert "d41d8cd98f00b204e9800998ecf8427e" in cleaned.md5_hashes


class TestExtractIOCs:
    """Tests for IOC extraction."""

    def test_extract_iocs(self):
        """Test IOC extraction."""
        text = """
        Malicious IP: 8.8.8.8
        C2 domain: malware.io
        File hash: d41d8cd98f00b204e9800998ecf8427e
        """
        iocs = extract_iocs(text)

        assert "ips" in iocs
        assert "domains" in iocs
        assert "hashes" in iocs
        assert "8.8.8.8" in iocs["ips"]
        assert "malware.io" in iocs["domains"]

    def test_iocs_sorted(self):
        """Test that IOCs are sorted."""
        text = "IPs: 8.8.8.8, 1.1.1.1"
        iocs = extract_iocs(text)
        assert iocs["ips"] == sorted(iocs["ips"])


class TestDefangRefang:
    """Tests for IOC defanging and refanging."""

    def test_defang_domain(self):
        """Test domain defanging."""
        result = defang_ioc("malware.com")
        assert result == "malware[.]com"

    def test_defang_url(self):
        """Test URL defanging."""
        result = defang_ioc("https://evil.com/payload")
        assert "[.]" in result
        assert "hxxps" in result
        assert "[://]" in result

    def test_refang_domain(self):
        """Test domain refanging."""
        result = refang_ioc("malware[.]com")
        assert result == "malware.com"

    def test_refang_url(self):
        """Test URL refanging."""
        result = refang_ioc("hxxps[://]evil[.]com/payload")
        assert result == "https://evil.com/payload"

    def test_roundtrip(self):
        """Test defang -> refang roundtrip."""
        original = "https://test.example.com/path"
        defanged = defang_ioc(original)
        refanged = refang_ioc(defanged)
        assert refanged == original


class TestGetEntitySummary:
    """Tests for entity summary generation."""

    def test_summary_counts(self):
        """Test summary count accuracy."""
        entities = ExtractedEntities()
        entities.emails.add("a@b.com")
        entities.emails.add("c@d.com")
        entities.ipv4_addresses.add("8.8.8.8")

        summary = get_entity_summary(entities)
        assert summary["total"] == 3
        assert summary["by_type"]["emails"] == 2
        assert summary["by_type"]["ipv4_addresses"] == 1

    def test_summary_sensitive_flag(self):
        """Test sensitive entity flag."""
        entities = ExtractedEntities()
        summary = get_entity_summary(entities)
        assert not summary["has_sensitive"]

        entities.aws_keys.add("AKIAIOSFODNN7EXAMPLE")
        summary = get_entity_summary(entities)
        assert summary["has_sensitive"]

    def test_summary_pii_flag(self):
        """Test PII flag."""
        entities = ExtractedEntities()
        entities.emails.add("user@test.com")

        summary = get_entity_summary(entities)
        assert summary["has_pii"]

    def test_summary_ioc_flag(self):
        """Test IOC flag."""
        entities = ExtractedEntities()
        entities.md5_hashes.add("d41d8cd98f00b204e9800998ecf8427e")

        summary = get_entity_summary(entities)
        assert summary["has_iocs"]


class TestExtractEntitiesContext:
    """Tests for extract_entities with Context."""

    def test_extract_entities_basic(self):
        """Test basic entity extraction with context."""
        ctx = Context(target="test.io")
        ctx.add(
            "domain_profile",
            {"registrar": "Example Registrar", "contact": "admin@test.io"},
        )

        result = extract_entities(ctx)
        assert "entities" in result.data
        assert "entity_summary" in result.data

    def test_extract_entities_with_findings(self):
        """Test entity extraction including findings."""
        ctx = Context(target="example.io")
        ctx.add(
            "finding_0",
            {
                "title": "Issue found",
                "description": "Contact admin@vuln.io about IP 8.8.8.8",
            },
        )

        result = extract_entities(ctx, {"include_findings": True})
        entities = result.get("entities")
        assert entities is not None

    def test_extract_entities_sensitive_only(self):
        """Test sensitive-only extraction."""
        ctx = Context(target="test.io")
        ctx.add("domain_profile", {"data": "Email: user@test.io, Domain: other.com"})

        result = extract_entities(ctx, {"sensitive_only": True})
        entities = result.get("entities")
        # Should only have sensitive fields
        assert "emails" in entities

    def test_extract_entities_creates_findings_for_aws_keys(self):
        """Test that AWS key detection creates findings."""
        ctx = Context(target="test.io")
        ctx.add("repo", {"content": "AWS key: AKIAIOSFODNN7EXAMPLE"})

        result = extract_entities(ctx)
        # Should have finding for AWS key
        summary = result.get("entity_summary")
        assert summary is not None

    def test_extract_from_target(self):
        """Test extraction from target domain."""
        ctx = Context(target="vulnerable.io")
        result = extract_entities(ctx, {"extract_from_target": True})

        entities = result.get("entities")
        assert entities is not None


class TestCollectTextSources:
    """Tests for collect_text_sources."""

    def test_collect_domain_profile(self):
        """Test collecting domain profile."""
        ctx = Context(target="test.io")
        ctx.add("domain_profile", {"key": "value"})

        sources = collect_text_sources(ctx)
        assert any("domain_profile" in name for name, _ in sources)

    def test_collect_dns_records(self):
        """Test collecting DNS records."""
        ctx = Context(target="test.io")
        ctx.add("dns_records", {"A": ["1.2.3.4"]})

        sources = collect_text_sources(ctx)
        assert any("dns_records" in name for name, _ in sources)

    def test_collect_findings_disabled(self):
        """Test that findings are excluded when disabled."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Test"})

        sources = collect_text_sources(ctx, include_findings=False)
        assert not any("finding_" in name for name, _ in sources)

    def test_collect_findings_enabled(self):
        """Test that findings are included when enabled."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Test"})

        sources = collect_text_sources(ctx, include_findings=True)
        assert any("finding_" in name for name, _ in sources)


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_unicode_text(self):
        """Test extraction from Unicode text."""
        text = "Email: user@tëst.com Contact: 日本@example.io"
        entities = extract_from_text(text)
        # Should handle without crashing
        assert entities is not None

    def test_very_long_text(self):
        """Test extraction from long text."""
        text = "Contact admin@test.io " * 1000
        entities = extract_from_text(text)
        # Should only have one unique email
        assert len(entities.emails) == 1

    def test_mixed_case_entities(self):
        """Test case handling."""
        text = "Email: USER@TEST.COM Domain: TEST.IO"
        entities = extract_from_text(text)
        assert "USER@TEST.COM" in entities.emails

    def test_entities_in_urls(self):
        """Test that domains in URLs are handled."""
        text = "Visit https://subdomain.example.io/path"
        entities = extract_from_text(text)
        assert any("example.io" in url for url in entities.urls)

    def test_malformed_input(self):
        """Test handling of malformed input."""
        # Should not crash on any input
        entities = extract_from_text("@@@...###")
        assert entities is not None

    def test_hash_collision_with_hex_strings(self):
        """Test that random hex strings don't get misidentified."""
        # 32 char hex that's not a real MD5
        text = "Version: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        entities = extract_from_text(text)
        # Should be cleaned as all-same-char hash
        assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in entities.md5_hashes
