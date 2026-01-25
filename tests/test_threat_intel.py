"""Tests for intel/threat_intel module."""

from redops.modules.intel.threat_intel import (
    IOCType,
    ThreatLevel,
    ThreatCategory,
    ConfidenceLevel,
    IOC,
    ThreatActor,
    ThreatFeed,
    ThreatMatch,
    SUSPICIOUS_DOMAIN_PATTERNS,
    KNOWN_MALWARE_INDICATORS,
    THREAT_ACTORS_DB,
    THREAT_FEEDS,
    analyze_threat_intel,
    extract_indicators_from_context,
    check_domains_against_intel,
    check_ips_against_intel,
    check_urls_against_intel,
    check_hashes_against_intel,
    analyze_domain_reputation,
    analyze_ip_reputation,
    analyze_url_patterns,
    identify_threat_actors,
    calculate_reputation_score,
    generate_risk_indicators,
    generate_intel_summary,
    is_private_ip,
    is_bogon_ip,
    identify_hash_type,
    create_ioc,
    get_threat_actor,
    get_all_threat_actors,
    get_threat_feeds,
    get_ioc_types,
    get_threat_categories,
    validate_ioc,
    enrich_ioc,
)
from redops.core.context import Context


class TestIOCType:
    """Tests for IOCType enum."""

    def test_ioc_type_values(self):
        """Test all IOC types exist."""
        assert IOCType.IP_ADDRESS.value == "ip_address"
        assert IOCType.DOMAIN.value == "domain"
        assert IOCType.URL.value == "url"
        assert IOCType.FILE_HASH_MD5.value == "file_hash_md5"
        assert IOCType.FILE_HASH_SHA256.value == "file_hash_sha256"
        assert IOCType.CVE.value == "cve"

    def test_ioc_type_count(self):
        """Test number of IOC types."""
        assert len(IOCType) >= 10


class TestThreatLevel:
    """Tests for ThreatLevel enum."""

    def test_threat_level_values(self):
        """Test all threat levels exist."""
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.UNKNOWN.value == "unknown"

    def test_threat_level_count(self):
        """Test number of threat levels."""
        assert len(ThreatLevel) == 5


class TestThreatCategory:
    """Tests for ThreatCategory enum."""

    def test_category_values(self):
        """Test threat categories exist."""
        assert ThreatCategory.MALWARE.value == "malware"
        assert ThreatCategory.PHISHING.value == "phishing"
        assert ThreatCategory.BOTNET.value == "botnet"
        assert ThreatCategory.C2.value == "command_and_control"
        assert ThreatCategory.RANSOMWARE.value == "ransomware"
        assert ThreatCategory.APT.value == "advanced_persistent_threat"

    def test_category_count(self):
        """Test number of categories."""
        assert len(ThreatCategory) >= 10


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum."""

    def test_confidence_values(self):
        """Test confidence levels exist."""
        assert ConfidenceLevel.CONFIRMED.value == "confirmed"
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.UNVERIFIED.value == "unverified"


class TestIOC:
    """Tests for IOC dataclass."""

    def test_basic_creation(self):
        """Test basic IOC creation."""
        ioc = IOC(
            type=IOCType.DOMAIN,
            value="malicious.com",
        )
        assert ioc.type == IOCType.DOMAIN
        assert ioc.value == "malicious.com"
        assert ioc.threat_level == ThreatLevel.UNKNOWN

    def test_full_creation(self):
        """Test IOC with all fields."""
        ioc = IOC(
            type=IOCType.IP_ADDRESS,
            value="192.0.2.1",
            threat_level=ThreatLevel.HIGH,
            categories=[ThreatCategory.C2, ThreatCategory.MALWARE],
            confidence=ConfidenceLevel.HIGH,
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-15T00:00:00Z",
            source="threat_feed",
            tags=["apt", "targeted"],
            related_iocs=["malware.com"],
            metadata={"campaign": "test"},
        )
        assert ioc.threat_level == ThreatLevel.HIGH
        assert len(ioc.categories) == 2
        assert "apt" in ioc.tags

    def test_to_dict(self):
        """Test IOC to_dict method."""
        ioc = IOC(
            type=IOCType.DOMAIN,
            value="test.com",
            threat_level=ThreatLevel.MEDIUM,
            categories=[ThreatCategory.PHISHING],
        )
        result = ioc.to_dict()

        assert result["type"] == "domain"
        assert result["value"] == "test.com"
        assert result["threat_level"] == "medium"
        assert "phishing" in result["categories"]


class TestThreatActor:
    """Tests for ThreatActor dataclass."""

    def test_basic_creation(self):
        """Test basic threat actor creation."""
        actor = ThreatActor(name="Test Actor")
        assert actor.name == "Test Actor"
        assert actor.aliases == []

    def test_full_creation(self):
        """Test threat actor with all fields."""
        actor = ThreatActor(
            name="APT99",
            aliases=["FancyCat", "KittyHawk"],
            description="Test threat actor",
            motivation="espionage",
            sophistication="advanced",
            origin="Unknown",
            target_sectors=["government", "defense"],
            ttps=["T1566", "T1059"],
            tools=["Mimikatz", "Cobalt Strike"],
        )
        assert len(actor.aliases) == 2
        assert actor.motivation == "espionage"
        assert len(actor.ttps) == 2

    def test_to_dict(self):
        """Test threat actor to_dict method."""
        actor = ThreatActor(
            name="Test",
            aliases=["Alias1"],
            motivation="financial",
        )
        result = actor.to_dict()

        assert result["name"] == "Test"
        assert "Alias1" in result["aliases"]
        assert result["motivation"] == "financial"


class TestThreatFeed:
    """Tests for ThreatFeed dataclass."""

    def test_basic_creation(self):
        """Test basic feed creation."""
        feed = ThreatFeed(
            name="Test Feed",
            feed_type="ip",
        )
        assert feed.name == "Test Feed"
        assert feed.feed_type == "ip"
        assert feed.enabled is True

    def test_to_dict(self):
        """Test feed to_dict method."""
        feed = ThreatFeed(
            name="URLhaus",
            feed_type="url",
            update_frequency="hourly",
        )
        result = feed.to_dict()

        assert result["name"] == "URLhaus"
        assert result["feed_type"] == "url"
        assert result["update_frequency"] == "hourly"


class TestThreatMatch:
    """Tests for ThreatMatch dataclass."""

    def test_creation(self):
        """Test threat match creation."""
        ioc = IOC(type=IOCType.DOMAIN, value="malicious.com")
        match = ThreatMatch(
            ioc=ioc,
            matched_value="malicious.com",
            context="domain_check",
            match_type="exact",
            score=0.9,
        )
        assert match.matched_value == "malicious.com"
        assert match.score == 0.9

    def test_to_dict(self):
        """Test match to_dict method."""
        ioc = IOC(type=IOCType.IP_ADDRESS, value="1.2.3.4")
        match = ThreatMatch(
            ioc=ioc,
            matched_value="1.2.3.4",
            context="ip_check",
            match_type="exact",
        )
        result = match.to_dict()

        assert result["matched_value"] == "1.2.3.4"
        assert result["context"] == "ip_check"
        assert "ioc" in result


class TestSuspiciousDomainPatterns:
    """Tests for suspicious domain patterns."""

    def test_dga_pattern(self):
        """Test DGA-like domain detection."""
        import re

        pattern, desc, level = SUSPICIOUS_DOMAIN_PATTERNS[0]
        # Long random domain
        assert re.search(pattern, "abcdefghijklmnopqrstuvwxyz12345.com")

    def test_phishing_pattern(self):
        """Test phishing pattern detection."""
        import re

        pattern, desc, level = SUSPICIOUS_DOMAIN_PATTERNS[1]
        assert re.search(pattern, "login-secure.example.com")
        assert re.search(pattern, "account-verify.test.com")

    def test_brand_impersonation(self):
        """Test brand impersonation detection."""
        import re

        pattern, desc, level = SUSPICIOUS_DOMAIN_PATTERNS[3]
        assert re.search(pattern, "paypal-secure.com")
        assert re.search(pattern, "microsoft-update.com")


class TestKnownMalwareIndicators:
    """Tests for known malware indicators."""

    def test_ransomware_extensions(self):
        """Test ransomware extensions list."""
        extensions = KNOWN_MALWARE_INDICATORS["ransomware_extensions"]
        assert ".locky" in extensions
        assert ".wannacry" in extensions
        assert ".ryuk" in extensions

    def test_suspicious_file_names(self):
        """Test suspicious file names list."""
        names = KNOWN_MALWARE_INDICATORS["suspicious_file_names"]
        assert "mimikatz" in names
        assert "meterpreter" in names

    def test_c2_patterns(self):
        """Test C2 patterns list."""
        patterns = KNOWN_MALWARE_INDICATORS["c2_patterns"]
        assert any("gate" in p for p in patterns)
        assert any("panel" in p for p in patterns)


class TestThreatActorsDB:
    """Tests for threat actors database."""

    def test_apt28_exists(self):
        """Test APT28 is in database."""
        assert "APT28" in THREAT_ACTORS_DB
        apt28 = THREAT_ACTORS_DB["APT28"]
        assert "Fancy Bear" in apt28.aliases
        assert apt28.sophistication == "advanced"

    def test_apt29_exists(self):
        """Test APT29 is in database."""
        assert "APT29" in THREAT_ACTORS_DB
        apt29 = THREAT_ACTORS_DB["APT29"]
        assert "Cozy Bear" in apt29.aliases

    def test_lazarus_exists(self):
        """Test Lazarus Group is in database."""
        assert "Lazarus" in THREAT_ACTORS_DB
        lazarus = THREAT_ACTORS_DB["Lazarus"]
        assert lazarus.motivation == "financial"

    def test_actors_have_ttps(self):
        """Test all actors have TTPs."""
        for name, actor in THREAT_ACTORS_DB.items():
            assert len(actor.ttps) >= 1, f"{name} has no TTPs"


class TestThreatFeeds:
    """Tests for threat feeds configuration."""

    def test_urlhaus_exists(self):
        """Test URLhaus feed exists."""
        assert "abuse_ch_urlhaus" in THREAT_FEEDS
        feed = THREAT_FEEDS["abuse_ch_urlhaus"]
        assert feed.feed_type == "url"

    def test_feeds_have_required_fields(self):
        """Test all feeds have required fields."""
        for name, feed in THREAT_FEEDS.items():
            assert feed.name
            assert feed.feed_type
            assert feed.update_frequency


class TestAnalyzeThreatIntel:
    """Tests for analyze_threat_intel function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        result = analyze_threat_intel(ctx)

        assert "threat_intel" in result.data
        intel = result.get("threat_intel")
        assert intel["target"] == "example.com"
        assert "matches" in intel
        assert "summary" in intel

    def test_no_target_warning(self):
        """Test warning when no target."""
        ctx = Context(target="")
        result = analyze_threat_intel(ctx)

        warnings = result.get_logs(level="WARNING")
        assert len(warnings) >= 1

    def test_with_suspicious_domain(self):
        """Test with suspicious domain data."""
        ctx = Context(target="login-secure.malicious.com")
        result = analyze_threat_intel(ctx)

        intel = result.get("threat_intel")
        assert len(intel["matches"]) >= 1

    def test_with_context_data(self):
        """Test with context containing indicators."""
        ctx = Context(target="example.com")
        ctx.add("urls", ["https://malicious.tk/gate.php"])
        ctx.add("ips", ["10.0.0.1", "192.168.1.1"])

        result = analyze_threat_intel(ctx)
        intel = result.get("threat_intel")

        assert intel["ip_analysis"]["private_count"] >= 1

    def test_min_threat_level_filter(self):
        """Test minimum threat level filtering."""
        ctx = Context(target="example.com")
        ctx.add("ips", ["10.0.0.1"])  # Private IP = LOW threat

        # With low filter
        result1 = analyze_threat_intel(ctx, {"min_threat_level": "low"})
        intel1 = result1.get("threat_intel")

        # With high filter
        result2 = analyze_threat_intel(ctx, {"min_threat_level": "high"})
        intel2 = result2.get("threat_intel")

        assert len(intel2["matches"]) <= len(intel1["matches"])


class TestExtractIndicatorsFromContext:
    """Tests for extract_indicators_from_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        indicators = extract_indicators_from_context(ctx)

        assert "domains" in indicators
        assert "ips" in indicators
        assert "urls" in indicators
        assert "hashes" in indicators

    def test_extract_ips(self):
        """Test IP extraction."""
        ctx = Context(target="example.com")
        ctx.add("data", "Server at 192.168.1.1 and 10.0.0.1")

        indicators = extract_indicators_from_context(ctx)
        assert "192.168.1.1" in indicators["ips"]
        assert "10.0.0.1" in indicators["ips"]

    def test_extract_domains(self):
        """Test domain extraction."""
        ctx = Context(target="example.com")
        ctx.add("data", "Found malicious.com and test.org")

        indicators = extract_indicators_from_context(ctx)
        assert "malicious.com" in indicators["domains"]
        assert "test.org" in indicators["domains"]

    def test_extract_urls(self):
        """Test URL extraction."""
        ctx = Context(target="example.com")
        ctx.add("data", "Download from https://evil.com/malware.exe")

        indicators = extract_indicators_from_context(ctx)
        assert any("evil.com" in url for url in indicators["urls"])

    def test_extract_hashes(self):
        """Test hash extraction."""
        ctx = Context(target="example.com")
        ctx.add("data", "MD5: d41d8cd98f00b204e9800998ecf8427e")
        ctx.add(
            "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        indicators = extract_indicators_from_context(ctx)
        assert len(indicators["hashes"]) >= 1

    def test_extract_emails(self):
        """Test email extraction."""
        ctx = Context(target="example.com")
        ctx.add("data", "Contact: admin@example.com")

        indicators = extract_indicators_from_context(ctx)
        assert "admin@example.com" in indicators["emails"]


class TestCheckDomainsAgainstIntel:
    """Tests for check_domains_against_intel function."""

    def test_clean_domain(self):
        """Test clean domain."""
        matches = check_domains_against_intel(["google.com"])
        # Clean domains shouldn't match
        assert len(matches) == 0

    def test_suspicious_domain(self):
        """Test suspicious domain detection."""
        matches = check_domains_against_intel(["login-secure.test.com"])
        assert len(matches) >= 1
        assert matches[0].ioc.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]

    def test_free_tld_domain(self):
        """Test free TLD detection."""
        matches = check_domains_against_intel(["malicious.tk"])
        assert len(matches) >= 1

    def test_brand_impersonation(self):
        """Test brand impersonation detection."""
        matches = check_domains_against_intel(["paypal-login.com"])
        assert len(matches) >= 1
        assert matches[0].ioc.threat_level == ThreatLevel.CRITICAL


class TestCheckIpsAgainstIntel:
    """Tests for check_ips_against_intel function."""

    def test_private_ip(self):
        """Test private IP detection."""
        matches = check_ips_against_intel(["192.168.1.1"])
        assert len(matches) >= 1
        assert (
            "private" in matches[0].ioc.tags
            or matches[0].ioc.threat_level == ThreatLevel.LOW
        )

    def test_loopback_ip(self):
        """Test loopback IP detection."""
        matches = check_ips_against_intel(["127.0.0.1"])
        assert len(matches) >= 1

    def test_bogon_ip(self):
        """Test bogon IP detection."""
        matches = check_ips_against_intel(["0.0.0.1"])
        assert len(matches) >= 1
        assert matches[0].ioc.threat_level == ThreatLevel.MEDIUM

    def test_public_ip(self):
        """Test public IP (no automatic flags)."""
        matches = check_ips_against_intel(["8.8.8.8"])
        # Public IPs don't auto-flag unless in threat database
        assert len(matches) == 0


class TestCheckUrlsAgainstIntel:
    """Tests for check_urls_against_intel function."""

    def test_clean_url(self):
        """Test clean URL."""
        matches = check_urls_against_intel(["https://google.com/search"])
        assert len(matches) == 0

    def test_c2_pattern_url(self):
        """Test C2 pattern URL detection."""
        matches = check_urls_against_intel(["https://evil.com/gate.php"])
        assert len(matches) >= 1
        assert ThreatCategory.C2 in matches[0].ioc.categories

    def test_ransomware_url(self):
        """Test ransomware extension URL."""
        matches = check_urls_against_intel(["https://evil.com/file.locky"])
        assert len(matches) >= 1
        assert matches[0].ioc.threat_level == ThreatLevel.CRITICAL


class TestCheckHashesAgainstIntel:
    """Tests for check_hashes_against_intel function."""

    def test_md5_hash(self):
        """Test MD5 hash handling."""
        # Currently returns empty as no real DB lookup
        matches = check_hashes_against_intel(["d41d8cd98f00b204e9800998ecf8427e"])
        assert isinstance(matches, list)

    def test_sha256_hash(self):
        """Test SHA256 hash handling."""
        matches = check_hashes_against_intel(
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        )
        assert isinstance(matches, list)


class TestAnalyzeDomainReputation:
    """Tests for analyze_domain_reputation function."""

    def test_empty_list(self):
        """Test with empty list."""
        analysis = analyze_domain_reputation([])
        assert analysis["total_domains"] == 0

    def test_tld_analysis(self):
        """Test TLD breakdown."""
        analysis = analyze_domain_reputation(["test.com", "example.com", "sample.org"])
        assert analysis["by_tld"]["com"] == 2
        assert analysis["by_tld"]["org"] == 1

    def test_suspicious_detection(self):
        """Test suspicious domain counting."""
        analysis = analyze_domain_reputation(
            ["clean.com", "login-verify.test.com", "normal.org"]
        )
        assert analysis["suspicious_count"] >= 1
        assert analysis["clean_count"] >= 1


class TestAnalyzeIpReputation:
    """Tests for analyze_ip_reputation function."""

    def test_empty_list(self):
        """Test with empty list."""
        analysis = analyze_ip_reputation([])
        assert analysis["total_ips"] == 0

    def test_private_public_count(self):
        """Test private/public counting."""
        analysis = analyze_ip_reputation(
            ["192.168.1.1", "10.0.0.1", "8.8.8.8", "1.1.1.1"]
        )
        assert analysis["private_count"] == 2
        assert analysis["public_count"] == 2

    def test_ip_class_breakdown(self):
        """Test IP class breakdown."""
        analysis = analyze_ip_reputation(["1.1.1.1", "128.0.0.1", "192.0.0.1"])
        assert analysis["by_class"]["A"] >= 1
        assert analysis["by_class"]["B"] >= 1
        assert analysis["by_class"]["C"] >= 1


class TestAnalyzeUrlPatterns:
    """Tests for analyze_url_patterns function."""

    def test_empty_list(self):
        """Test with empty list."""
        analysis = analyze_url_patterns([])
        assert analysis["total_urls"] == 0

    def test_protocol_count(self):
        """Test HTTPS/HTTP counting."""
        analysis = analyze_url_patterns(
            ["https://secure.com", "http://insecure.com", "https://also-secure.com"]
        )
        assert analysis["https_count"] == 2
        assert analysis["http_count"] == 1

    def test_parameter_detection(self):
        """Test query parameter detection."""
        analysis = analyze_url_patterns(
            [
                "https://test.com?id=1",
                "https://test.com/page",
                "https://test.com?foo=bar",
            ]
        )
        assert analysis["parameters_detected"] == 2


class TestIdentifyThreatActors:
    """Tests for identify_threat_actors function."""

    def test_no_matches(self):
        """Test with no TTP overlap."""
        ctx = Context(target="example.com")
        matches = []
        actors = identify_threat_actors(ctx, matches)
        assert actors == []

    def test_ttp_matching(self):
        """Test TTP-based actor identification."""
        ctx = Context(target="example.com")
        ctx.add(
            "attack_paths", [{"mitre_techniques": ["T1566", "T1059", "T1053", "T1071"]}]
        )
        matches = []
        actors = identify_threat_actors(ctx, matches)

        # Should match APT28 which uses these TTPs
        assert len(actors) >= 1

    def test_tool_matching(self):
        """Test tool-based actor identification."""
        ctx = Context(target="example.com")
        ctx.add(
            "code_artifacts", {"files": ["path/to/Mimikatz.exe", "cobalt_strike.dll"]}
        )
        matches = []
        actors = identify_threat_actors(ctx, matches)

        # Should potentially match actors using these tools
        assert isinstance(actors, list)


class TestCalculateReputationScore:
    """Tests for calculate_reputation_score function."""

    def test_no_matches(self):
        """Test with no matches."""
        score = calculate_reputation_score([])
        assert score == 0.0

    def test_critical_match(self):
        """Test score with critical match."""
        ioc = IOC(
            type=IOCType.DOMAIN,
            value="test.com",
            threat_level=ThreatLevel.CRITICAL,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        match = ThreatMatch(
            ioc=ioc, matched_value="test.com", context="", match_type="exact"
        )

        score = calculate_reputation_score([match])
        assert score >= 20  # Critical with confirmed confidence

    def test_multiple_matches(self):
        """Test score with multiple matches."""
        matches = []
        for level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM, ThreatLevel.LOW]:
            ioc = IOC(type=IOCType.DOMAIN, value="test.com", threat_level=level)
            matches.append(
                ThreatMatch(ioc=ioc, matched_value="", context="", match_type="")
            )

        score = calculate_reputation_score(matches)
        assert score > 0

    def test_score_capped_at_100(self):
        """Test score is capped at 100."""
        matches = []
        for _ in range(20):
            ioc = IOC(
                type=IOCType.DOMAIN,
                value="test.com",
                threat_level=ThreatLevel.CRITICAL,
                confidence=ConfidenceLevel.CONFIRMED,
            )
            matches.append(
                ThreatMatch(ioc=ioc, matched_value="", context="", match_type="")
            )

        score = calculate_reputation_score(matches)
        assert score == 100.0


class TestGenerateRiskIndicators:
    """Tests for generate_risk_indicators function."""

    def test_no_indicators(self):
        """Test with no data."""
        indicators = generate_risk_indicators([], {}, {})
        assert indicators == []

    def test_critical_indicator(self):
        """Test critical threat indicator."""
        ioc = IOC(
            type=IOCType.DOMAIN, value="test.com", threat_level=ThreatLevel.CRITICAL
        )
        match = ThreatMatch(ioc=ioc, matched_value="", context="", match_type="")

        indicators = generate_risk_indicators([match], {}, {})
        assert any(i["severity"] == "critical" for i in indicators)

    def test_suspicious_domain_indicator(self):
        """Test suspicious domain indicator."""
        domain_analysis = {"suspicious_count": 5}
        indicators = generate_risk_indicators([], domain_analysis, {})

        assert any(i["indicator"] == "suspicious_domains" for i in indicators)


class TestGenerateIntelSummary:
    """Tests for generate_intel_summary function."""

    def test_empty_data(self):
        """Test with empty data."""
        summary = generate_intel_summary({"matches": [], "threat_actors": []})

        assert summary["total_matches"] == 0
        assert summary["risk_level"] == "clean"

    def test_critical_risk_level(self):
        """Test critical risk level."""
        intel_data = {
            "matches": [{"ioc": {"threat_level": "critical"}}],
            "threat_actors": [],
            "reputation_score": 50,
            "risk_indicators": [],
        }
        summary = generate_intel_summary(intel_data)

        assert summary["critical_count"] == 1
        assert summary["risk_level"] == "critical"


class TestIsPrivateIp:
    """Tests for is_private_ip function."""

    def test_class_a_private(self):
        """Test Class A private range."""
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("10.255.255.255")

    def test_class_b_private(self):
        """Test Class B private range."""
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("172.31.255.255")
        assert not is_private_ip("172.15.0.1")
        assert not is_private_ip("172.32.0.1")

    def test_class_c_private(self):
        """Test Class C private range."""
        assert is_private_ip("192.168.0.1")
        assert is_private_ip("192.168.255.255")

    def test_loopback(self):
        """Test loopback range."""
        assert is_private_ip("127.0.0.1")
        assert is_private_ip("127.255.255.255")

    def test_public_ip(self):
        """Test public IPs are not private."""
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("1.1.1.1")

    def test_invalid_ip(self):
        """Test invalid IP handling."""
        assert not is_private_ip("invalid")
        assert not is_private_ip("256.0.0.1")


class TestIsBogonIp:
    """Tests for is_bogon_ip function."""

    def test_zero_network(self):
        """Test 0.0.0.0/8 range."""
        assert is_bogon_ip("0.0.0.1")
        assert is_bogon_ip("0.255.255.255")

    def test_link_local(self):
        """Test link-local range."""
        assert is_bogon_ip("169.254.0.1")
        assert is_bogon_ip("169.254.255.255")

    def test_test_nets(self):
        """Test TEST-NET ranges."""
        assert is_bogon_ip("192.0.2.1")  # TEST-NET-1
        assert is_bogon_ip("198.51.100.1")  # TEST-NET-2
        assert is_bogon_ip("203.0.113.1")  # TEST-NET-3

    def test_multicast(self):
        """Test multicast range."""
        assert is_bogon_ip("224.0.0.1")
        assert is_bogon_ip("239.255.255.255")

    def test_reserved(self):
        """Test reserved range."""
        assert is_bogon_ip("240.0.0.1")
        assert is_bogon_ip("255.255.255.255")

    def test_normal_public(self):
        """Test normal public IPs are not bogon."""
        assert not is_bogon_ip("8.8.8.8")
        assert not is_bogon_ip("1.1.1.1")


class TestIdentifyHashType:
    """Tests for identify_hash_type function."""

    def test_md5(self):
        """Test MD5 identification."""
        result = identify_hash_type("d41d8cd98f00b204e9800998ecf8427e")
        assert result == IOCType.FILE_HASH_MD5

    def test_sha1(self):
        """Test SHA1 identification."""
        result = identify_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert result == IOCType.FILE_HASH_SHA1

    def test_sha256(self):
        """Test SHA256 identification."""
        result = identify_hash_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == IOCType.FILE_HASH_SHA256

    def test_invalid_hash(self):
        """Test invalid hash."""
        assert identify_hash_type("not-a-hash") is None
        assert identify_hash_type("") is None
        assert identify_hash_type("12345") is None


class TestCreateIoc:
    """Tests for create_ioc helper function."""

    def test_basic_creation(self):
        """Test basic IOC creation."""
        ioc = create_ioc(IOCType.DOMAIN, "test.com")

        assert ioc.type == IOCType.DOMAIN
        assert ioc.value == "test.com"
        assert ioc.first_seen is not None

    def test_with_options(self):
        """Test IOC creation with options."""
        ioc = create_ioc(
            IOCType.IP_ADDRESS,
            "1.2.3.4",
            threat_level=ThreatLevel.HIGH,
            categories=[ThreatCategory.C2],
            source="manual_entry",
            tags=["suspicious"],
        )

        assert ioc.threat_level == ThreatLevel.HIGH
        assert ThreatCategory.C2 in ioc.categories
        assert "suspicious" in ioc.tags


class TestGetThreatActor:
    """Tests for get_threat_actor function."""

    def test_by_name(self):
        """Test lookup by name."""
        actor = get_threat_actor("APT28")
        assert actor is not None
        assert actor.name == "APT28"

    def test_by_alias(self):
        """Test lookup by alias."""
        actor = get_threat_actor("Fancy Bear")
        assert actor is not None
        assert actor.name == "APT28"

    def test_case_insensitive(self):
        """Test case-insensitive lookup."""
        actor = get_threat_actor("apt28")
        assert actor is not None

    def test_not_found(self):
        """Test unknown actor."""
        actor = get_threat_actor("Unknown Actor")
        assert actor is None


class TestGetAllThreatActors:
    """Tests for get_all_threat_actors function."""

    def test_returns_list(self):
        """Test returns list of actors."""
        actors = get_all_threat_actors()
        assert isinstance(actors, list)
        assert len(actors) >= 4

    def test_actors_are_valid(self):
        """Test all actors are valid."""
        actors = get_all_threat_actors()
        for actor in actors:
            assert actor.name
            assert isinstance(actor, ThreatActor)


class TestGetThreatFeeds:
    """Tests for get_threat_feeds function."""

    def test_returns_dict(self):
        """Test returns dictionary."""
        feeds = get_threat_feeds()
        assert isinstance(feeds, dict)
        assert len(feeds) >= 1

    def test_returns_copy(self):
        """Test returns a copy."""
        feeds1 = get_threat_feeds()
        feeds2 = get_threat_feeds()

        feeds1["test"] = ThreatFeed(name="Test", feed_type="test")
        assert "test" not in feeds2


class TestGetIocTypes:
    """Tests for get_ioc_types function."""

    def test_returns_list(self):
        """Test returns list of types."""
        types = get_ioc_types()
        assert isinstance(types, list)
        assert "ip_address" in types
        assert "domain" in types


class TestGetThreatCategories:
    """Tests for get_threat_categories function."""

    def test_returns_list(self):
        """Test returns list of categories."""
        categories = get_threat_categories()
        assert isinstance(categories, list)
        assert "malware" in categories
        assert "phishing" in categories


class TestValidateIoc:
    """Tests for validate_ioc function."""

    def test_valid_ip(self):
        """Test valid IP validation."""
        is_valid, error = validate_ioc(IOCType.IP_ADDRESS, "192.168.1.1")
        assert is_valid
        assert error == ""

    def test_invalid_ip(self):
        """Test invalid IP validation."""
        is_valid, error = validate_ioc(IOCType.IP_ADDRESS, "999.999.999.999")
        assert not is_valid

    def test_valid_domain(self):
        """Test valid domain validation."""
        is_valid, error = validate_ioc(IOCType.DOMAIN, "example.com")
        assert is_valid

    def test_invalid_domain(self):
        """Test invalid domain validation."""
        is_valid, error = validate_ioc(IOCType.DOMAIN, "not a domain")
        assert not is_valid

    def test_valid_url(self):
        """Test valid URL validation."""
        is_valid, error = validate_ioc(IOCType.URL, "https://example.com/path")
        assert is_valid

    def test_valid_email(self):
        """Test valid email validation."""
        is_valid, error = validate_ioc(IOCType.EMAIL, "test@example.com")
        assert is_valid

    def test_valid_md5(self):
        """Test valid MD5 validation."""
        is_valid, error = validate_ioc(
            IOCType.FILE_HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e"
        )
        assert is_valid

    def test_invalid_md5(self):
        """Test invalid MD5 validation."""
        is_valid, error = validate_ioc(IOCType.FILE_HASH_MD5, "tooshort")
        assert not is_valid

    def test_valid_cve(self):
        """Test valid CVE validation."""
        is_valid, error = validate_ioc(IOCType.CVE, "CVE-2024-12345")
        assert is_valid

    def test_invalid_cve(self):
        """Test invalid CVE validation."""
        is_valid, error = validate_ioc(IOCType.CVE, "not-a-cve")
        assert not is_valid

    def test_empty_value(self):
        """Test empty value validation."""
        is_valid, error = validate_ioc(IOCType.DOMAIN, "")
        assert not is_valid


class TestEnrichIoc:
    """Tests for enrich_ioc function."""

    def test_adds_timestamp(self):
        """Test timestamp is added."""
        ioc = IOC(type=IOCType.DOMAIN, value="test.com")
        enriched = enrich_ioc(ioc)

        assert enriched.last_seen is not None

    def test_domain_enrichment(self):
        """Test domain-specific enrichment."""
        ioc = IOC(type=IOCType.DOMAIN, value="sub.example.com")
        enriched = enrich_ioc(ioc)

        assert enriched.metadata.get("tld") == "com"
        assert enriched.metadata.get("sld") == "example"

    def test_ip_enrichment(self):
        """Test IP-specific enrichment."""
        ioc = IOC(type=IOCType.IP_ADDRESS, value="192.168.1.1")
        enriched = enrich_ioc(ioc)

        assert "private" in enriched.tags

    def test_hash_enrichment(self):
        """Test hash-specific enrichment."""
        ioc = IOC(type=IOCType.FILE_HASH_MD5, value="d41d8cd98f00b204e9800998ecf8427e")
        enriched = enrich_ioc(ioc)

        assert enriched.metadata.get("hash_type") == "file_hash_md5"


class TestIntegration:
    """Integration tests for threat intelligence."""

    def test_full_analysis_workflow(self):
        """Test full analysis workflow."""
        ctx = Context(target="suspicious-login.malicious.tk")
        ctx.add("urls", ["https://evil.com/gate.php"])
        ctx.add("ips", ["192.168.1.1", "10.0.0.1"])
        ctx.add("attack_paths", [{"mitre_techniques": ["T1566", "T1059"]}])

        result = analyze_threat_intel(ctx)
        intel = result.get("threat_intel")

        # Should have matches
        assert len(intel["matches"]) >= 1

        # Should have summary
        assert intel["summary"]["total_matches"] >= 1
        assert intel["summary"]["risk_level"] != "clean"

        # Should have reputation score
        assert intel["reputation_score"] > 0

    def test_clean_target_analysis(self):
        """Test analysis of clean target."""
        ctx = Context(target="google.com")

        result = analyze_threat_intel(ctx)
        intel = result.get("threat_intel")

        # Should be mostly clean
        assert intel["summary"]["risk_level"] in ["clean", "low"]
