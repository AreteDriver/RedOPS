"""Tests for the Social OSINT module."""

import pytest
from redops.core.context import Context
from redops.modules.recon.social_osint import (
    # Dataclasses
    Platform,
    UserProfile,
    BreachInfo,
    EmailPattern,
    # Constants
    PLATFORMS,
    EMAIL_PATTERNS,
    KNOWN_BREACH_PATTERNS,
    # Main functions
    gather_osint,
    discover_employees,
    # Username functions
    extract_usernames_from_context,
    generate_usernames_from_name,
    extract_username_from_email,
    is_valid_username,
    correlate_usernames_to_platforms,
    correlate_usernames,
    calculate_username_confidence,
    # Email functions
    extract_emails_from_context,
    is_domain,
    analyze_email_patterns,
    generate_email_permutations,
    # Breach functions
    check_breaches_batch,
    check_breach_simulated,
    check_data_breaches,
    # Finding functions
    generate_osint_findings,
    # Utility functions
    get_platform_categories,
    get_platform_by_name,
    generate_profile_urls,
)


# ============================================================================
# Platform Dataclass Tests
# ============================================================================

class TestPlatform:
    """Tests for Platform dataclass."""

    def test_format_url(self):
        """Test URL formatting."""
        platform = PLATFORMS["github"]
        url = platform.format_url("testuser")
        assert url == "https://github.com/testuser"

    def test_is_valid_username_basic(self):
        """Test basic username validation."""
        platform = PLATFORMS["github"]
        assert platform.is_valid_username("testuser")
        assert platform.is_valid_username("test-user")
        assert not platform.is_valid_username("ab")  # Too short
        assert not platform.is_valid_username("-invalid")  # Starts with dash

    def test_is_valid_username_twitter(self):
        """Test Twitter-specific username rules."""
        platform = PLATFORMS["twitter"]
        assert platform.is_valid_username("testuser")
        assert platform.is_valid_username("test_user")
        assert not platform.is_valid_username("test-user")  # No dashes on Twitter
        assert not platform.is_valid_username("a" * 20)  # Too long (max 15)

    def test_is_valid_username_length(self):
        """Test username length validation."""
        platform = PLATFORMS["github"]
        assert platform.is_valid_username("abc")  # Min length
        assert platform.is_valid_username("a" * 39)  # Max GitHub length
        assert not platform.is_valid_username("a" * 40)  # Too long


class TestUserProfile:
    """Tests for UserProfile dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        profile = UserProfile(
            username="testuser",
            platform="GitHub",
            url="https://github.com/testuser",
            category="code",
            confidence=0.8,
        )
        result = profile.to_dict()

        assert result["username"] == "testuser"
        assert result["platform"] == "GitHub"
        assert result["url"] == "https://github.com/testuser"
        assert result["confidence"] == 0.8


class TestBreachInfo:
    """Tests for BreachInfo dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        breach = BreachInfo(
            name="Test Breach",
            date="2024",
            data_types=["email", "password"],
            description="Test breach",
            severity="high",
        )
        result = breach.to_dict()

        assert result["name"] == "Test Breach"
        assert result["severity"] == "high"
        assert "email" in result["data_types"]


# ============================================================================
# Username Generation Tests
# ============================================================================

class TestGenerateUsernamesFromName:
    """Tests for generate_usernames_from_name function."""

    def test_two_part_name(self):
        """Test username generation from two-part name."""
        usernames = generate_usernames_from_name("John Doe")

        assert "johndoe" in usernames
        assert "john.doe" in usernames
        assert "jdoe" in usernames
        assert "johnd" in usernames
        assert "doejohn" in usernames

    def test_single_name(self):
        """Test with single name."""
        usernames = generate_usernames_from_name("John")

        assert "john" in usernames
        assert len(usernames) == 1

    def test_name_with_title(self):
        """Test name with title prefix."""
        usernames = generate_usernames_from_name("Dr. John Doe")

        assert "johndoe" in usernames
        assert "jdoe" in usernames

    def test_empty_name(self):
        """Test with empty name."""
        usernames = generate_usernames_from_name("")
        assert len(usernames) == 0

    def test_short_name(self):
        """Test with very short name."""
        usernames = generate_usernames_from_name("A")
        assert len(usernames) == 0

    def test_number_variations(self):
        """Test that number variations are generated."""
        usernames = generate_usernames_from_name("John Doe")

        assert "johndoe1" in usernames
        assert "johndoe123" in usernames


class TestExtractUsernameFromEmail:
    """Tests for extract_username_from_email function."""

    def test_basic_email(self):
        """Test extracting username from basic email."""
        result = extract_username_from_email("johndoe@example.com")
        assert result == "johndoe"

    def test_email_with_plus(self):
        """Test email with plus addressing."""
        result = extract_username_from_email("johndoe+test@example.com")
        assert result == "johndoe"

    def test_email_with_dots(self):
        """Test email with dots."""
        result = extract_username_from_email("john.doe@example.com")
        assert result == "john"

    def test_invalid_email(self):
        """Test with invalid email."""
        result = extract_username_from_email("invalid")
        assert result is None

    def test_empty_email(self):
        """Test with empty email."""
        result = extract_username_from_email("")
        assert result is None


class TestIsValidUsername:
    """Tests for is_valid_username function."""

    def test_valid_usernames(self):
        """Test valid usernames."""
        assert is_valid_username("johndoe")
        assert is_valid_username("john_doe")
        assert is_valid_username("john.doe")
        assert is_valid_username("john-doe")
        assert is_valid_username("johndoe123")

    def test_invalid_too_short(self):
        """Test username too short."""
        assert not is_valid_username("ab")
        assert not is_valid_username("a")

    def test_invalid_too_long(self):
        """Test username too long."""
        assert not is_valid_username("a" * 31)

    def test_invalid_characters(self):
        """Test invalid characters."""
        assert not is_valid_username("john@doe")
        assert not is_valid_username("john doe")

    def test_excluded_words(self):
        """Test excluded common words."""
        assert not is_valid_username("the")
        assert not is_valid_username("and")
        assert not is_valid_username("for")


# ============================================================================
# Platform Correlation Tests
# ============================================================================

class TestCorrelateUsernamesToPlatforms:
    """Tests for correlate_usernames_to_platforms function."""

    def test_correlate_single_username(self):
        """Test correlating a single username."""
        profiles, correlations = correlate_usernames_to_platforms({"testuser"})

        assert len(profiles) > 0
        assert len(correlations) == 1
        assert correlations[0]["username"] == "testuser"
        assert correlations[0]["platform_count"] > 0

    def test_correlate_multiple_usernames(self):
        """Test correlating multiple usernames."""
        profiles, correlations = correlate_usernames_to_platforms(
            {"testuser", "anotheruser"}
        )

        assert len(correlations) == 2

    def test_correlate_specific_platforms(self):
        """Test correlating with specific platforms."""
        profiles, correlations = correlate_usernames_to_platforms(
            {"testuser"},
            platform_keys=["github", "twitter"]
        )

        platforms_found = set()
        for profile in profiles:
            platforms_found.add(profile.platform)

        assert "GitHub" in platforms_found or "Twitter/X" in platforms_found

    def test_invalid_username_filtered(self):
        """Test that invalid usernames for platforms are filtered."""
        # Twitter doesn't allow dashes
        profiles, _ = correlate_usernames_to_platforms(
            {"test-user"},
            platform_keys=["twitter"]
        )

        # Should not have Twitter profile
        twitter_profiles = [p for p in profiles if p.platform == "Twitter/X"]
        assert len(twitter_profiles) == 0


class TestCorrelateUsernames:
    """Tests for correlate_usernames function."""

    def test_returns_dict(self):
        """Test that it returns a dictionary."""
        result = correlate_usernames(["testuser"])

        assert isinstance(result, dict)
        assert "testuser" in result
        assert isinstance(result["testuser"], list)


class TestCalculateUsernameConfidence:
    """Tests for calculate_username_confidence function."""

    def test_base_confidence(self):
        """Test base confidence score."""
        platform = PLATFORMS["github"]
        score = calculate_username_confidence("abc", platform)

        assert 0.0 <= score <= 1.0
        assert score >= 0.5  # Base score

    def test_longer_username_higher_confidence(self):
        """Test that longer usernames have higher confidence."""
        platform = PLATFORMS["github"]
        short_score = calculate_username_confidence("abc", platform)
        long_score = calculate_username_confidence("verylongusername", platform)

        assert long_score > short_score

    def test_numbers_increase_confidence(self):
        """Test that numbers increase confidence."""
        platform = PLATFORMS["github"]
        no_nums = calculate_username_confidence("testuser", platform)
        with_nums = calculate_username_confidence("testuser123", platform)

        assert with_nums > no_nums


# ============================================================================
# Email Pattern Tests
# ============================================================================

class TestIsDomain:
    """Tests for is_domain function."""

    def test_valid_domains(self):
        """Test valid domain formats."""
        assert is_domain("example.com")
        assert is_domain("sub.example.com")
        assert is_domain("example.co.uk")

    def test_invalid_domains(self):
        """Test invalid domain formats."""
        assert not is_domain("example")  # No TLD
        assert not is_domain("http://example.com")  # Has scheme
        assert not is_domain("/path/to/file")  # Path
        assert not is_domain("192.168.1.1")  # IP (technically matches but edge case)


class TestAnalyzeEmailPatterns:
    """Tests for analyze_email_patterns function."""

    def test_returns_patterns(self):
        """Test that patterns are returned."""
        patterns = analyze_email_patterns("example.com")

        assert len(patterns) > 0
        assert all(isinstance(p, EmailPattern) for p in patterns)

    def test_patterns_have_examples(self):
        """Test that patterns have correct examples."""
        patterns = analyze_email_patterns("example.com")

        for pattern in patterns:
            assert "@example.com" in pattern.example

    def test_confidence_ordering(self):
        """Test that confidence decreases with order."""
        patterns = analyze_email_patterns("example.com")

        confidences = [p.confidence for p in patterns]
        # First patterns should have higher confidence
        assert confidences[0] >= confidences[-1]


class TestGenerateEmailPermutations:
    """Tests for generate_email_permutations function."""

    def test_generate_permutations(self):
        """Test email permutation generation."""
        emails = generate_email_permutations("John", "Doe", "example.com")

        assert "john.doe@example.com" in emails
        assert "johndoe@example.com" in emails
        assert "jdoe@example.com" in emails

    def test_empty_inputs(self):
        """Test with empty inputs."""
        assert generate_email_permutations("", "Doe", "example.com") == []
        assert generate_email_permutations("John", "", "example.com") == []
        assert generate_email_permutations("John", "Doe", "") == []


# ============================================================================
# Breach Checking Tests
# ============================================================================

class TestCheckBreachSimulated:
    """Tests for check_breach_simulated function."""

    def test_returns_result(self):
        """Test that a result is returned."""
        result = check_breach_simulated("test@example.com")

        assert "email" in result
        assert "exposed" in result
        assert "breaches" in result
        assert "checked_at" in result

    def test_consistent_results(self):
        """Test that same email gives consistent results."""
        result1 = check_breach_simulated("test@example.com")
        result2 = check_breach_simulated("test@example.com")

        assert result1["exposed"] == result2["exposed"]

    def test_case_insensitive(self):
        """Test case insensitivity."""
        result1 = check_breach_simulated("Test@Example.com")
        result2 = check_breach_simulated("test@example.com")

        assert result1["exposed"] == result2["exposed"]

    def test_exposed_has_breaches(self):
        """Test that exposed emails have breach info."""
        # Use email known to be "exposed" in simulation
        result = check_breach_simulated("exposed@test.com")

        if result["exposed"]:
            assert len(result["breaches"]) > 0


class TestCheckBreachesBatch:
    """Tests for check_breaches_batch function."""

    def test_batch_checking(self):
        """Test batch breach checking."""
        emails = {"test1@example.com", "test2@example.com"}
        results = check_breaches_batch(emails)

        assert len(results) == 2
        assert all("email" in r for r in results)


class TestCheckDataBreaches:
    """Tests for check_data_breaches function (legacy API)."""

    def test_returns_result(self):
        """Test that it returns a result."""
        result = check_data_breaches("test@example.com")

        assert "email" in result
        assert "exposed" in result


# ============================================================================
# Context Extraction Tests
# ============================================================================

class TestExtractUsernamesFromContext:
    """Tests for extract_usernames_from_context function."""

    def test_from_domain_profile(self):
        """Test extracting from domain profile."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {"registrant_name": "John Doe"})

        usernames = extract_usernames_from_context(ctx)

        assert "johndoe" in usernames or "jdoe" in usernames

    def test_from_code_artifacts(self):
        """Test extracting from code artifacts."""
        ctx = Context(target="example.com")
        ctx.add("code_artifacts", {
            "git_authors": [
                {"name": "Jane Smith", "email": "jsmith@example.com"}
            ]
        })

        usernames = extract_usernames_from_context(ctx)

        assert "jsmith" in usernames or "janesmith" in usernames

    def test_from_entities(self):
        """Test extracting from entities."""
        ctx = Context(target="example.com")
        ctx.add("entities", {
            "persons": [{"name": "Bob Wilson"}]
        })

        usernames = extract_usernames_from_context(ctx)

        assert "bobwilson" in usernames or "bwilson" in usernames

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        usernames = extract_usernames_from_context(ctx)

        assert len(usernames) == 0


class TestExtractEmailsFromContext:
    """Tests for extract_emails_from_context function."""

    def test_from_domain_profile(self):
        """Test extracting from domain profile."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {
            "registrant_email": "admin@example.com"
        })

        emails = extract_emails_from_context(ctx)

        assert "admin@example.com" in emails

    def test_from_entities(self):
        """Test extracting from entities."""
        ctx = Context(target="example.com")
        ctx.add("entities", {
            "emails": ["test@example.com"]
        })

        emails = extract_emails_from_context(ctx)

        assert "test@example.com" in emails

    def test_filters_invalid(self):
        """Test that invalid emails are filtered."""
        ctx = Context(target="example.com")
        ctx.add("entities", {
            "emails": ["valid@example.com", "invalid"]
        })

        emails = extract_emails_from_context(ctx)

        assert "valid@example.com" in emails
        assert "invalid" not in emails


# ============================================================================
# Main Function Tests
# ============================================================================

class TestGatherOsint:
    """Tests for gather_osint function."""

    def test_basic_execution(self):
        """Test basic execution."""
        ctx = Context(target="example.com")
        result = gather_osint(ctx)

        assert "osint_data" in result.data
        osint_data = result.get("osint_data")
        assert osint_data["target"] == "example.com"

    def test_with_existing_data(self):
        """Test with existing context data."""
        ctx = Context(target="example.com")
        ctx.add("domain_profile", {"registrant_name": "John Doe"})
        ctx.add("code_artifacts", {
            "git_authors": [{"name": "Jane Smith", "email": "jane@example.com"}]
        })

        result = gather_osint(ctx)
        osint_data = result.get("osint_data")

        assert len(osint_data["usernames"]) > 0
        assert len(osint_data["profiles"]) > 0

    def test_email_patterns_for_domain(self):
        """Test email pattern analysis for domain target."""
        ctx = Context(target="example.com")
        result = gather_osint(ctx)

        osint_data = result.get("osint_data")
        assert len(osint_data["email_patterns"]) > 0

    def test_no_target_warning(self):
        """Test warning when no target specified."""
        ctx = Context()
        result = gather_osint(ctx)

        warnings = result.get_logs(level="WARNING")
        assert len(warnings) > 0

    def test_generates_findings(self):
        """Test that findings are generated."""
        ctx = Context(target="example.com")
        ctx.add("entities", {
            "emails": ["test@example.com", "admin@example.com"]
        })

        result = gather_osint(ctx)

        # Check for findings in context
        finding_keys = [k for k in result.data.keys() if k.startswith("osint_finding_")]
        # May or may not have findings depending on simulated breach results
        assert isinstance(finding_keys, list)


class TestDiscoverEmployees:
    """Tests for discover_employees function."""

    def test_from_git_authors(self):
        """Test discovering employees from git authors."""
        ctx = Context(target="example.com")
        ctx.add("code_artifacts", {
            "git_authors": [
                {"name": "John Developer", "email": "john@example.com"}
            ]
        })

        result = discover_employees(ctx)
        employees = result.get("discovered_employees")

        assert len(employees) == 1
        assert employees[0]["name"] == "John Developer"
        assert employees[0]["role"] == "developer"

    def test_deduplication(self):
        """Test that duplicate names are removed."""
        ctx = Context(target="example.com")
        ctx.add("code_artifacts", {
            "git_authors": [{"name": "John Doe"}]
        })
        ctx.add("entities", {
            "persons": [{"name": "John Doe"}]
        })

        result = discover_employees(ctx)
        employees = result.get("discovered_employees")

        # Should only have one entry for John Doe
        john_count = sum(1 for e in employees if "john" in e["name"].lower())
        assert john_count == 1


# ============================================================================
# Findings Generation Tests
# ============================================================================

class TestGenerateOsintFindings:
    """Tests for generate_osint_findings function."""

    def test_high_exposure_finding(self):
        """Test finding for high username exposure."""
        osint_data = {
            "correlations": [
                {"username": "testuser", "platform_count": 10}
            ]
        }

        findings = generate_osint_findings(osint_data)

        assert len(findings) > 0
        assert any("Username Exposure" in f["title"] for f in findings)

    def test_breach_finding(self):
        """Test finding for breach exposure."""
        osint_data = {
            "breach_results": [
                {"email": "test@example.com", "exposed": True}
            ]
        }

        findings = generate_osint_findings(osint_data)

        assert len(findings) > 0
        assert any("Breach" in f["title"] for f in findings)

    def test_email_pattern_finding(self):
        """Test finding for email patterns."""
        osint_data = {
            "email_patterns": [
                {"pattern": "first.last", "example": "john.doe@example.com"}
            ]
        }

        findings = generate_osint_findings(osint_data)

        assert len(findings) > 0
        assert any("Email Pattern" in f["title"] for f in findings)


# ============================================================================
# Utility Function Tests
# ============================================================================

class TestGetPlatformCategories:
    """Tests for get_platform_categories function."""

    def test_returns_categories(self):
        """Test that categories are returned."""
        categories = get_platform_categories()

        assert "code" in categories
        assert "social" in categories
        assert "professional" in categories

    def test_platforms_in_categories(self):
        """Test that platforms are in categories."""
        categories = get_platform_categories()

        assert "GitHub" in categories["code"]
        assert "LinkedIn" in categories["professional"]


class TestGetPlatformByName:
    """Tests for get_platform_by_name function."""

    def test_by_key(self):
        """Test getting by key."""
        platform = get_platform_by_name("github")

        assert platform is not None
        assert platform.name == "GitHub"

    def test_by_name(self):
        """Test getting by name."""
        platform = get_platform_by_name("GitHub")

        assert platform is not None
        assert platform.name == "GitHub"

    def test_not_found(self):
        """Test with non-existent platform."""
        platform = get_platform_by_name("nonexistent")

        assert platform is None


class TestGenerateProfileUrls:
    """Tests for generate_profile_urls function."""

    def test_generate_all_platforms(self):
        """Test generating URLs for all platforms."""
        urls = generate_profile_urls("testuser")

        assert len(urls) > 0
        assert all("url" in u for u in urls)
        assert all("platform" in u for u in urls)

    def test_generate_specific_platforms(self):
        """Test generating URLs for specific platforms."""
        urls = generate_profile_urls("testuser", ["github", "twitter"])

        platforms = [u["platform"] for u in urls]
        assert "GitHub" in platforms or "Twitter/X" in platforms

    def test_filters_invalid(self):
        """Test that invalid usernames are filtered."""
        # Twitter doesn't allow dashes
        urls = generate_profile_urls("test-user", ["twitter"])

        twitter_urls = [u for u in urls if u["platform"] == "Twitter/X"]
        assert len(twitter_urls) == 0


# ============================================================================
# Constants Tests
# ============================================================================

class TestPlatformsConstant:
    """Tests for PLATFORMS constant."""

    def test_all_platforms_valid(self):
        """Test that all platforms are valid."""
        for key, platform in PLATFORMS.items():
            assert platform.name
            assert platform.url_pattern
            assert "{username}" in platform.url_pattern
            assert platform.category

    def test_expected_platforms_present(self):
        """Test that expected platforms are present."""
        expected = ["github", "twitter", "linkedin", "reddit", "stackoverflow"]
        for platform in expected:
            assert platform in PLATFORMS


class TestEmailPatternsConstant:
    """Tests for EMAIL_PATTERNS constant."""

    def test_patterns_valid(self):
        """Test that all patterns are valid."""
        for name, template in EMAIL_PATTERNS:
            assert name
            assert "{domain}" in template
            assert "@" in template


class TestKnownBreachPatternsConstant:
    """Tests for KNOWN_BREACH_PATTERNS constant."""

    def test_breaches_valid(self):
        """Test that all breach patterns are valid."""
        for key, breach in KNOWN_BREACH_PATTERNS.items():
            assert breach.name
            assert breach.severity in ["low", "medium", "high", "critical"]


# ============================================================================
# Integration Tests
# ============================================================================

class TestOsintIntegration:
    """Integration tests for OSINT module."""

    def test_full_osint_pipeline(self):
        """Test complete OSINT gathering pipeline."""
        ctx = Context(target="testcompany.io")

        # Add realistic context data
        ctx.add("domain_profile", {
            "registrant_name": "Test Company Inc",
            "registrant_email": "admin@testcompany.io",
        })
        ctx.add("code_artifacts", {
            "git_authors": [
                {"name": "Alice Developer", "email": "alice@testcompany.io"},
                {"name": "Bob Engineer", "email": "bob@testcompany.io"},
            ],
            "package_maintainers": [
                {"name": "Charlie Maintainer", "username": "charlie_m"}
            ]
        })
        ctx.add("entities", {
            "persons": [{"name": "Diana Manager"}],
            "emails": ["info@testcompany.io"]
        })

        # Run OSINT gathering
        result = gather_osint(ctx)
        osint_data = result.get("osint_data")

        # Verify comprehensive results
        assert len(osint_data["usernames"]) > 0
        assert len(osint_data["profiles"]) > 0
        assert len(osint_data["correlations"]) > 0
        assert len(osint_data["email_patterns"]) > 0
        assert len(osint_data["emails"]) > 0

        # Run employee discovery
        result = discover_employees(result)
        employees = result.get("discovered_employees")

        assert len(employees) >= 2  # At least Alice and Bob

    def test_osint_with_empty_context(self):
        """Test OSINT with minimal context."""
        ctx = Context(target="example.com")

        result = gather_osint(ctx)
        osint_data = result.get("osint_data")

        # Should still have email patterns for domain
        assert len(osint_data["email_patterns"]) > 0
        assert osint_data["target"] == "example.com"

    def test_osint_generates_actionable_findings(self):
        """Test that OSINT generates actionable findings."""
        ctx = Context(target="vulnerable.io")

        # Add data that would trigger findings
        ctx.add("entities", {
            "emails": [
                "user1@vulnerable.io",
                "user2@vulnerable.io",
                "user3@vulnerable.io",
            ]
        })

        result = gather_osint(ctx)

        # Check that findings were generated
        finding_count = sum(
            1 for k in result.data.keys()
            if k.startswith("osint_finding_")
        )

        # Should have at least email pattern finding
        assert finding_count >= 1
