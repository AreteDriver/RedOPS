"""Tests for analysis/correlation_engine module."""

from redops.modules.analysis.correlation_engine import (
    CorrelationType,
    CorrelationStrength,
    FindingCategory,
    FindingSeverity,
    Finding,
    Correlation,
    CorrelationCluster,
    CorrelationInsight,
    ATTACK_PATTERNS,
    ENTITY_PATTERNS,
    CAUSAL_RELATIONSHIPS,
    correlate_findings,
    extract_findings_from_context,
    correlate_temporal,
    correlate_entities,
    correlate_attributes,
    correlate_causal,
    detect_attack_patterns,
    cluster_findings,
    generate_insights,
    build_correlation_graph,
    generate_correlation_summary,
    generate_correlation_id,
    calculate_strength,
    parse_severity,
    parse_timestamp,
    normalize_entity,
    extract_entities_from_text,
    deduplicate_correlations,
    generate_cluster_recommendations,
    get_correlation_types,
    get_finding_categories,
    get_severity_levels,
    get_attack_patterns,
    find_related_findings,
    get_finding_correlations,
    calculate_finding_centrality,
    get_high_centrality_findings,
    create_finding,
    merge_findings,
)
from redops.core.context import Context


class TestCorrelationType:
    """Tests for CorrelationType enum."""

    def test_type_values(self):
        """Test correlation type values."""
        assert CorrelationType.TEMPORAL.value == "temporal"
        assert CorrelationType.ENTITY.value == "entity"
        assert CorrelationType.CAUSAL.value == "causal"
        assert CorrelationType.PATTERN.value == "pattern"

    def test_type_count(self):
        """Test number of types."""
        assert len(CorrelationType) >= 5


class TestCorrelationStrength:
    """Tests for CorrelationStrength enum."""

    def test_strength_values(self):
        """Test strength values."""
        assert CorrelationStrength.STRONG.value == "strong"
        assert CorrelationStrength.MODERATE.value == "moderate"
        assert CorrelationStrength.WEAK.value == "weak"
        assert CorrelationStrength.POTENTIAL.value == "potential"


class TestFindingCategory:
    """Tests for FindingCategory enum."""

    def test_category_values(self):
        """Test category values."""
        assert FindingCategory.VULNERABILITY.value == "vulnerability"
        assert FindingCategory.EXPOSURE.value == "exposure"
        assert FindingCategory.CREDENTIAL.value == "credential"
        assert FindingCategory.COMPLIANCE.value == "compliance"

    def test_category_count(self):
        """Test number of categories."""
        assert len(FindingCategory) >= 8


class TestFindingSeverity:
    """Tests for FindingSeverity enum."""

    def test_severity_values(self):
        """Test severity values."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"


class TestFinding:
    """Tests for Finding dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        finding = Finding(
            id="FND-001",
            source_module="test",
            category=FindingCategory.VULNERABILITY,
            title="Test Finding",
        )
        assert finding.id == "FND-001"
        assert finding.category == FindingCategory.VULNERABILITY
        assert finding.entities == []

    def test_full_creation(self):
        """Test creation with all fields."""
        finding = Finding(
            id="FND-001",
            source_module="test",
            category=FindingCategory.EXPOSURE,
            title="Exposed API Key",
            description="API key found in public repo",
            severity=FindingSeverity.HIGH,
            entities=["api_key_123", "github.com"],
            attributes={"type": "api_key"},
        )
        assert len(finding.entities) == 2
        assert finding.severity == FindingSeverity.HIGH

    def test_to_dict(self):
        """Test to_dict method."""
        finding = Finding(
            id="FND-001",
            source_module="test",
            category=FindingCategory.VULNERABILITY,
            title="Test",
        )
        result = finding.to_dict()

        assert result["id"] == "FND-001"
        assert result["category"] == "vulnerability"


class TestCorrelation:
    """Tests for Correlation dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        corr = Correlation(
            id="COR-001",
            finding_ids=["FND-001", "FND-002"],
            correlation_type=CorrelationType.ENTITY,
            strength=CorrelationStrength.STRONG,
            confidence=0.85,
            reason="Shared entity",
        )
        assert len(corr.finding_ids) == 2
        assert corr.confidence == 0.85

    def test_to_dict(self):
        """Test to_dict method."""
        corr = Correlation(
            id="COR-001",
            finding_ids=["FND-001"],
            correlation_type=CorrelationType.TEMPORAL,
            strength=CorrelationStrength.MODERATE,
            confidence=0.6,
            reason="Time proximity",
        )
        result = corr.to_dict()

        assert result["correlation_type"] == "temporal"
        assert result["strength"] == "moderate"


class TestCorrelationCluster:
    """Tests for CorrelationCluster dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        cluster = CorrelationCluster(
            id="CLU-001",
            name="Test Cluster",
            finding_ids=["FND-001", "FND-002"],
            correlations=["COR-001"],
            primary_category=FindingCategory.VULNERABILITY,
            aggregate_severity=FindingSeverity.HIGH,
            confidence=0.75,
        )
        assert len(cluster.finding_ids) == 2
        assert cluster.aggregate_severity == FindingSeverity.HIGH

    def test_to_dict(self):
        """Test to_dict method."""
        cluster = CorrelationCluster(
            id="CLU-001",
            name="Test Cluster",
            finding_ids=["FND-001"],
            correlations=[],
            primary_category=FindingCategory.EXPOSURE,
            aggregate_severity=FindingSeverity.MEDIUM,
            confidence=0.5,
        )
        result = cluster.to_dict()

        assert result["primary_category"] == "exposure"


class TestCorrelationInsight:
    """Tests for CorrelationInsight dataclass."""

    def test_basic_creation(self):
        """Test basic creation."""
        insight = CorrelationInsight(
            id="INS-001",
            title="Test Insight",
            description="Important finding pattern",
            insight_type="attack_pattern",
            severity=FindingSeverity.HIGH,
            related_findings=["FND-001"],
            related_correlations=["COR-001"],
        )
        assert insight.confidence == 0.8  # Default
        assert len(insight.related_findings) == 1

    def test_to_dict(self):
        """Test to_dict method."""
        insight = CorrelationInsight(
            id="INS-001",
            title="Test",
            description="Test",
            insight_type="test",
            severity=FindingSeverity.MEDIUM,
            related_findings=[],
            related_correlations=[],
        )
        result = insight.to_dict()

        assert result["severity"] == "medium"


class TestAttackPatterns:
    """Tests for attack patterns."""

    def test_patterns_defined(self):
        """Test patterns are defined."""
        assert len(ATTACK_PATTERNS) >= 5
        assert "credential_stuffing" in ATTACK_PATTERNS
        assert "reconnaissance_chain" in ATTACK_PATTERNS

    def test_pattern_structure(self):
        """Test pattern structure."""
        for pattern_id, pattern in ATTACK_PATTERNS.items():
            assert "name" in pattern
            assert "categories" in pattern
            assert "indicators" in pattern
            assert "description" in pattern


class TestEntityPatterns:
    """Tests for entity patterns."""

    def test_patterns_defined(self):
        """Test patterns are defined."""
        assert "ip_address" in ENTITY_PATTERNS
        assert "domain" in ENTITY_PATTERNS
        assert "email" in ENTITY_PATTERNS
        assert "cve" in ENTITY_PATTERNS


class TestCausalRelationships:
    """Tests for causal relationships."""

    def test_relationships_defined(self):
        """Test relationships are defined."""
        assert FindingCategory.RECONNAISSANCE in CAUSAL_RELATIONSHIPS
        assert FindingCategory.EXPOSURE in CAUSAL_RELATIONSHIPS

    def test_relationship_targets(self):
        """Test relationship targets are valid categories."""
        for cause, effects in CAUSAL_RELATIONSHIPS.items():
            assert isinstance(effects, list)
            for effect in effects:
                assert isinstance(effect, FindingCategory)


class TestCorrelateFindings:
    """Tests for correlate_findings main function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        correlate_findings(ctx, {})

        corr_data = ctx.get("correlations", {})
        assert "findings" in corr_data
        assert "correlations" in corr_data

    def test_with_exposure_data(self):
        """Test with exposure data."""
        ctx = Context(target="example.com")
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {
                        "title": "Exposed API",
                        "severity": "high",
                        "description": "Public API",
                    },
                    {
                        "title": "Open Port",
                        "severity": "medium",
                        "description": "Port 22",
                    },
                ]
            },
        )

        correlate_findings(ctx, {})
        corr_data = ctx.get("correlations", {})

        assert len(corr_data["findings"]) == 2

    def test_min_confidence_filter(self):
        """Test minimum confidence filtering."""
        ctx = Context(target="example.com")
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {"title": "Finding 1", "severity": "high"},
                    {"title": "Finding 2", "severity": "high"},
                ]
            },
        )

        correlate_findings(ctx, {"min_confidence": 0.9})
        corr_data = ctx.get("correlations", {})

        # High confidence filter should reduce correlations
        for corr in corr_data["correlations"]:
            assert corr["confidence"] >= 0.9


class TestExtractFindingsFromContext:
    """Tests for extract_findings_from_context function."""

    def test_empty_context(self):
        """Test with empty context."""
        ctx = Context(target="example.com")
        findings = extract_findings_from_context(ctx)

        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_from_exposure_scan(self):
        """Test extraction from exposure scan."""
        ctx = Context(target="example.com")
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {
                        "title": "Test Exposure",
                        "severity": "high",
                        "description": "Test",
                    },
                ]
            },
        )

        findings = extract_findings_from_context(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.EXPOSURE

    def test_from_threat_intel(self):
        """Test extraction from threat intel."""
        ctx = Context(target="example.com")
        ctx.add(
            "threat_intel",
            {
                "iocs": [
                    {"type": "ip", "value": "1.2.3.4", "severity": "high"},
                ]
            },
        )

        findings = extract_findings_from_context(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.THREAT_INDICATOR

    def test_from_compliance(self):
        """Test extraction from compliance."""
        ctx = Context(target="example.com")
        ctx.add(
            "compliance",
            {
                "gaps": [
                    {"title": "Missing MFA", "priority": "high"},
                ]
            },
        )

        findings = extract_findings_from_context(ctx)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.COMPLIANCE


class TestCorrelateTemporal:
    """Tests for correlate_temporal function."""

    def test_empty_findings(self):
        """Test with no findings."""
        correlations = correlate_temporal([], 24)
        assert len(correlations) == 0

    def test_no_timestamps(self):
        """Test with findings without timestamps."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
            ),
        ]
        correlations = correlate_temporal(findings, 24)
        assert len(correlations) == 0

    def test_temporal_correlation(self):
        """Test temporal correlation detection."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
                timestamp="2025-01-01T10:00:00Z",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
                timestamp="2025-01-01T11:00:00Z",
            ),
        ]
        correlations = correlate_temporal(findings, 24)

        assert len(correlations) >= 1
        assert correlations[0].correlation_type == CorrelationType.TEMPORAL


class TestCorrelateEntities:
    """Tests for correlate_entities function."""

    def test_empty_findings(self):
        """Test with no findings."""
        correlations = correlate_entities([], ["ip_address"])
        assert len(correlations) == 0

    def test_shared_entities(self):
        """Test entity correlation with shared entities."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
                entities=["1.2.3.4", "example.com"],
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.EXPOSURE,
                title="T2",
                entities=["1.2.3.4", "other.com"],
            ),
        ]
        correlations = correlate_entities(findings, ["ip_address"])

        assert len(correlations) >= 1
        assert "1.2.3.4" in correlations[0].shared_entities

    def test_no_shared_entities(self):
        """Test with no shared entities."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
                entities=["a"],
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
                entities=["b"],
            ),
        ]
        correlations = correlate_entities(findings, ["ip_address"])

        assert len(correlations) == 0


class TestCorrelateAttributes:
    """Tests for correlate_attributes function."""

    def test_empty_findings(self):
        """Test with no findings."""
        correlations = correlate_attributes([])
        assert len(correlations) == 0

    def test_shared_attributes(self):
        """Test attribute correlation."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
                attributes={"port": 22, "protocol": "ssh"},
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
                attributes={"port": 22, "protocol": "tcp"},
            ),
        ]
        correlations = correlate_attributes(findings)

        assert len(correlations) >= 1
        assert "port" in correlations[0].shared_attributes


class TestCorrelateCausal:
    """Tests for correlate_causal function."""

    def test_empty_findings(self):
        """Test with no findings."""
        correlations = correlate_causal([])
        assert len(correlations) == 0

    def test_causal_relationship(self):
        """Test causal correlation detection."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.RECONNAISSANCE,
                title="Subdomain found",
                entities=["sub.example.com"],
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="Vuln on subdomain",
                entities=["sub.example.com"],
            ),
        ]
        correlations = correlate_causal(findings)

        assert len(correlations) >= 1
        assert correlations[0].correlation_type == CorrelationType.CAUSAL


class TestDetectAttackPatterns:
    """Tests for detect_attack_patterns function."""

    def test_empty_findings(self):
        """Test with no findings."""
        correlations = detect_attack_patterns([])
        assert len(correlations) == 0

    def test_credential_pattern(self):
        """Test credential stuffing pattern detection."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.CREDENTIAL,
                title="Leaked password",
                description="dark_web exposure",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.EXPOSURE,
                title="Credential reuse",
                description="password_reuse detected",
            ),
        ]
        correlations = detect_attack_patterns(findings)

        assert len(correlations) >= 1
        assert correlations[0].correlation_type == CorrelationType.PATTERN


class TestClusterFindings:
    """Tests for cluster_findings function."""

    def test_empty_input(self):
        """Test with empty input."""
        clusters = cluster_findings([], [])
        assert len(clusters) == 0

    def test_basic_clustering(self):
        """Test basic clustering."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
            ),
        ]
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1", "F2"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            )
        ]

        clusters = cluster_findings(findings, correlations)

        assert len(clusters) == 1
        assert len(clusters[0].finding_ids) == 2


class TestGenerateInsights:
    """Tests for generate_insights function."""

    def test_empty_input(self):
        """Test with empty input."""
        insights = generate_insights([], [], [])
        assert len(insights) == 0

    def test_pattern_insight(self):
        """Test pattern insight generation."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            )
        ]
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1"],
                correlation_type=CorrelationType.PATTERN,
                strength=CorrelationStrength.STRONG,
                confidence=0.9,
                reason="Pattern match",
                metadata={
                    "pattern_name": "Test Pattern",
                    "pattern_description": "Test",
                },
            )
        ]

        insights = generate_insights(findings, correlations, [])

        assert len(insights) >= 1
        assert insights[0].insight_type == "attack_pattern"


class TestBuildCorrelationGraph:
    """Tests for build_correlation_graph function."""

    def test_empty_input(self):
        """Test with empty input."""
        graph = build_correlation_graph([], [])

        assert graph["node_count"] == 0
        assert graph["edge_count"] == 0

    def test_basic_graph(self):
        """Test basic graph building."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.EXPOSURE,
                title="T2",
            ),
        ]
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1", "F2"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            )
        ]

        graph = build_correlation_graph(findings, correlations)

        assert graph["node_count"] == 2
        assert graph["edge_count"] == 1


class TestGenerateCorrelationSummary:
    """Tests for generate_correlation_summary function."""

    def test_empty_input(self):
        """Test with empty input."""
        summary = generate_correlation_summary([], [], [], [])

        assert summary["total_findings"] == 0
        assert summary["total_correlations"] == 0

    def test_with_data(self):
        """Test with data."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
                severity=FindingSeverity.HIGH,
            ),
        ]
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            )
        ]

        summary = generate_correlation_summary(findings, correlations, [], [])

        assert summary["total_findings"] == 1
        assert summary["high_severity_findings"] == 1


class TestGenerateCorrelationId:
    """Tests for generate_correlation_id function."""

    def test_deterministic(self):
        """Test ID is deterministic."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
            ),
        ]

        id1 = generate_correlation_id(findings, "test")
        id2 = generate_correlation_id(findings, "test")

        assert id1 == id2

    def test_format(self):
        """Test ID format."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            )
        ]
        corr_id = generate_correlation_id(findings, "test")

        assert corr_id.startswith("COR-")


class TestCalculateStrength:
    """Tests for calculate_strength function."""

    def test_strong(self):
        """Test strong confidence."""
        assert calculate_strength(0.9) == CorrelationStrength.STRONG
        assert calculate_strength(0.8) == CorrelationStrength.STRONG

    def test_moderate(self):
        """Test moderate confidence."""
        assert calculate_strength(0.7) == CorrelationStrength.MODERATE
        assert calculate_strength(0.6) == CorrelationStrength.MODERATE

    def test_weak(self):
        """Test weak confidence."""
        assert calculate_strength(0.5) == CorrelationStrength.WEAK
        assert calculate_strength(0.4) == CorrelationStrength.WEAK

    def test_potential(self):
        """Test potential confidence."""
        assert calculate_strength(0.3) == CorrelationStrength.POTENTIAL
        assert calculate_strength(0.1) == CorrelationStrength.POTENTIAL


class TestParseSeverity:
    """Tests for parse_severity function."""

    def test_valid_severities(self):
        """Test valid severity strings."""
        assert parse_severity("critical") == FindingSeverity.CRITICAL
        assert parse_severity("HIGH") == FindingSeverity.HIGH
        assert parse_severity("Medium") == FindingSeverity.MEDIUM

    def test_info_variants(self):
        """Test info variants."""
        assert parse_severity("info") == FindingSeverity.INFO
        assert parse_severity("informational") == FindingSeverity.INFO

    def test_unknown(self):
        """Test unknown defaults to medium."""
        assert parse_severity("unknown") == FindingSeverity.MEDIUM


class TestParseTimestamp:
    """Tests for parse_timestamp function."""

    def test_iso_format(self):
        """Test ISO format parsing."""
        ts = parse_timestamp("2025-01-01T10:00:00Z")
        assert ts is not None
        assert ts.year == 2025

    def test_various_formats(self):
        """Test various format parsing."""
        assert parse_timestamp("2025-01-01T10:00:00.123Z") is not None
        assert parse_timestamp("2025-01-01 10:00:00") is not None
        assert parse_timestamp("2025-01-01") is not None

    def test_invalid(self):
        """Test invalid timestamp."""
        assert parse_timestamp("not a date") is None
        assert parse_timestamp(None) is None


class TestNormalizeEntity:
    """Tests for normalize_entity function."""

    def test_basic_normalization(self):
        """Test basic normalization."""
        assert normalize_entity("  TEST  ") == "test"
        assert normalize_entity("Example") == "example"

    def test_skip_short(self):
        """Test skipping short entities."""
        assert normalize_entity("a") is None
        assert normalize_entity("ab") is None

    def test_skip_common(self):
        """Test skipping common non-entities."""
        assert normalize_entity("true") is None
        assert normalize_entity("null") is None
        assert normalize_entity("none") is None


class TestExtractEntitiesFromText:
    """Tests for extract_entities_from_text function."""

    def test_ip_extraction(self):
        """Test IP address extraction."""
        text = "Server at 192.168.1.1 responded"
        entities = extract_entities_from_text(text)

        assert "192.168.1.1" in entities

    def test_email_extraction(self):
        """Test email extraction."""
        text = "Contact: user@example.com for help"
        entities = extract_entities_from_text(text)

        assert "user@example.com" in entities

    def test_cve_extraction(self):
        """Test CVE extraction."""
        text = "Affected by CVE-2024-12345"
        entities = extract_entities_from_text(text)

        assert "CVE-2024-12345" in entities


class TestDeduplicateCorrelations:
    """Tests for deduplicate_correlations function."""

    def test_removes_duplicates(self):
        """Test duplicate removal."""
        correlations = [
            Correlation(
                id="C1",
                finding_ids=[],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            ),
            Correlation(
                id="C1",
                finding_ids=[],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            ),
        ]

        unique = deduplicate_correlations(correlations)

        assert len(unique) == 1


class TestGenerateClusterRecommendations:
    """Tests for generate_cluster_recommendations function."""

    def test_vulnerability_recommendations(self):
        """Test vulnerability recommendations."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            )
        ]
        recs = generate_cluster_recommendations(findings, FindingCategory.VULNERABILITY)

        assert len(recs) > 0
        assert any("patch" in r.lower() for r in recs)

    def test_critical_priority(self):
        """Test critical findings get priority."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
                severity=FindingSeverity.CRITICAL,
            )
        ]
        recs = generate_cluster_recommendations(findings, FindingCategory.VULNERABILITY)

        assert "URGENT" in recs[0]


class TestGetCorrelationTypes:
    """Tests for get_correlation_types function."""

    def test_returns_list(self):
        """Test returns list of strings."""
        types = get_correlation_types()

        assert isinstance(types, list)
        assert "temporal" in types
        assert "entity" in types


class TestGetFindingCategories:
    """Tests for get_finding_categories function."""

    def test_returns_list(self):
        """Test returns list of strings."""
        categories = get_finding_categories()

        assert isinstance(categories, list)
        assert "vulnerability" in categories


class TestGetSeverityLevels:
    """Tests for get_severity_levels function."""

    def test_returns_list(self):
        """Test returns list of strings."""
        levels = get_severity_levels()

        assert isinstance(levels, list)
        assert "critical" in levels
        assert "high" in levels


class TestGetAttackPatterns:
    """Tests for get_attack_patterns function."""

    def test_returns_dict(self):
        """Test returns dictionary."""
        patterns = get_attack_patterns()

        assert isinstance(patterns, dict)
        assert len(patterns) >= 5

    def test_pattern_format(self):
        """Test pattern format."""
        patterns = get_attack_patterns()

        for pid, pattern in patterns.items():
            assert "name" in pattern
            assert "description" in pattern
            assert "categories" in pattern
            assert isinstance(pattern["categories"], list)


class TestFindRelatedFindings:
    """Tests for find_related_findings function."""

    def test_finds_related(self):
        """Test finding related findings."""
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1", "F2", "F3"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            )
        ]

        related = find_related_findings("F1", correlations)

        assert "F2" in related
        assert "F3" in related
        assert "F1" not in related


class TestGetFindingCorrelations:
    """Tests for get_finding_correlations function."""

    def test_gets_correlations(self):
        """Test getting correlations for a finding."""
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1", "F2"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            ),
            Correlation(
                id="C2",
                finding_ids=["F2", "F3"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            ),
        ]

        result = get_finding_correlations("F1", correlations)

        assert len(result) == 1
        assert result[0].id == "C1"


class TestCalculateFindingCentrality:
    """Tests for calculate_finding_centrality function."""

    def test_high_centrality(self):
        """Test high centrality calculation."""
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1", "F2", "F3"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            ),
            Correlation(
                id="C2",
                finding_ids=["F1", "F4"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.9,
                reason="Test",
            ),
        ]

        centrality = calculate_finding_centrality("F1", correlations)

        assert centrality > 0

    def test_no_connections(self):
        """Test finding with no connections."""
        correlations = []
        centrality = calculate_finding_centrality("F1", correlations)

        assert centrality == 0.0


class TestGetHighCentralityFindings:
    """Tests for get_high_centrality_findings function."""

    def test_returns_sorted(self):
        """Test returns sorted by centrality."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T2",
            ),
        ]
        correlations = [
            Correlation(
                id="C1",
                finding_ids=["F1", "F2"],
                correlation_type=CorrelationType.ENTITY,
                strength=CorrelationStrength.STRONG,
                confidence=0.8,
                reason="Test",
            ),
        ]

        result = get_high_centrality_findings(findings, correlations, top_n=5)

        assert len(result) == 2
        assert result[0][1] >= result[1][1]  # Sorted descending


class TestCreateFinding:
    """Tests for create_finding function."""

    def test_basic_creation(self):
        """Test basic finding creation."""
        finding = create_finding(
            source_module="test",
            category="vulnerability",
            title="Test Finding",
        )

        assert finding.id.startswith("FND-")
        assert finding.category == FindingCategory.VULNERABILITY

    def test_with_custom_id(self):
        """Test with custom ID."""
        finding = create_finding(
            source_module="test",
            category="vulnerability",
            title="Test",
            finding_id="CUSTOM-001",
        )

        assert finding.id == "CUSTOM-001"

    def test_with_entities(self):
        """Test with entities."""
        finding = create_finding(
            source_module="test",
            category="exposure",
            title="Test",
            entities=["1.2.3.4", "example.com"],
        )

        assert len(finding.entities) == 2


class TestMergeFindings:
    """Tests for merge_findings function."""

    def test_no_duplicates(self):
        """Test with no duplicates."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="T1",
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.EXPOSURE,
                title="T2",
            ),
        ]

        merged = merge_findings(findings)

        assert len(merged) == 2

    def test_keep_highest_severity(self):
        """Test keeping highest severity."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="Same Title",
                severity=FindingSeverity.LOW,
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="Same Title",
                severity=FindingSeverity.HIGH,
            ),
        ]

        merged = merge_findings(findings, merge_strategy="keep_highest_severity")

        assert len(merged) == 1
        assert merged[0].severity == FindingSeverity.HIGH

    def test_keep_first(self):
        """Test keeping first."""
        findings = [
            Finding(
                id="F1",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="Same Title",
                severity=FindingSeverity.LOW,
            ),
            Finding(
                id="F2",
                source_module="test",
                category=FindingCategory.VULNERABILITY,
                title="Same Title",
                severity=FindingSeverity.HIGH,
            ),
        ]

        merged = merge_findings(findings, merge_strategy="keep_first")

        assert len(merged) == 1
        assert merged[0].id == "F1"


class TestIntegration:
    """Integration tests for correlation engine."""

    def test_full_correlation_flow(self):
        """Test complete correlation flow."""
        ctx = Context(target="example.com")

        # Add findings from multiple sources
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {
                        "title": "Exposed API",
                        "severity": "high",
                        "description": "API key at 192.168.1.1",
                    },
                ]
            },
        )
        ctx.add(
            "threat_intel",
            {
                "iocs": [
                    {"type": "ip", "value": "192.168.1.1", "severity": "critical"},
                ]
            },
        )
        ctx.add(
            "compliance",
            {
                "gaps": [
                    {"title": "Missing encryption", "priority": "medium"},
                ]
            },
        )

        # Run correlation
        correlate_findings(
            ctx,
            {
                "enable_patterns": True,
                "enable_clustering": True,
            },
        )

        corr_data = ctx.get("correlations", {})

        # Verify structure
        assert "findings" in corr_data
        assert "correlations" in corr_data
        assert "clusters" in corr_data
        assert "insights" in corr_data
        assert "summary" in corr_data
        assert "graph" in corr_data

        # Should find entity correlation on shared IP
        assert len(corr_data["findings"]) >= 3

    def test_attack_pattern_detection(self):
        """Test attack pattern detection in full flow."""
        ctx = Context(target="example.com")

        # Add findings matching credential stuffing pattern
        ctx.add(
            "exposure_scan",
            {
                "exposures": [
                    {
                        "title": "Leaked credentials",
                        "severity": "critical",
                        "description": "Found on dark_web marketplace",
                    },
                ]
            },
        )
        ctx.add(
            "code_artifacts",
            {
                "secrets": [
                    {
                        "type": "password",
                        "value": "exposed123",
                        "context": "password_reuse detected",
                    },
                ]
            },
        )

        correlate_findings(ctx, {"enable_patterns": True})
        corr_data = ctx.get("correlations", {})

        # Should detect credential stuffing pattern
        pattern_corrs = [
            c for c in corr_data["correlations"] if c["correlation_type"] == "pattern"
        ]
        assert len(pattern_corrs) >= 1
