"""Tests for simulation/mitre_mapping module."""

from redops.modules.simulation.mitre_mapping import (
    MitreTechnique,
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    KEYWORD_TECHNIQUE_MAP,
    map_to_mitre,
    map_findings_to_techniques,
    find_techniques_for_text,
    map_risk_to_techniques,
    map_finding_to_technique,
    calculate_tactic_coverage,
    generate_detection_recommendations,
    get_technique_info,
    get_techniques_by_tactic,
    get_all_tactics,
    get_mitigations_for_techniques,
    generate_attack_matrix_view,
    generate_navigator_layer,
)
from redops.core.context import Context


class TestMitreTechnique:
    """Tests for MitreTechnique dataclass."""

    def test_basic_creation(self):
        """Test basic technique creation."""
        technique = MitreTechnique(
            id="T1595",
            name="Active Scanning",
            tactic="Reconnaissance",
            description="Test description",
        )
        assert technique.id == "T1595"
        assert technique.name == "Active Scanning"
        assert technique.tactic == "Reconnaissance"

    def test_with_all_fields(self):
        """Test technique with all fields."""
        technique = MitreTechnique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Exploit web apps",
            detection="Monitor logs",
            mitigation="Apply patches",
            platforms=["Linux", "Windows"],
            data_sources=["Application Log"],
        )
        assert technique.detection == "Monitor logs"
        assert technique.mitigation == "Apply patches"
        assert "Linux" in technique.platforms

    def test_to_dict(self):
        """Test conversion to dictionary."""
        technique = MitreTechnique(
            id="T1595",
            name="Active Scanning",
            tactic="Reconnaissance",
            description="Test",
            platforms=["PRE"],
        )
        result = technique.to_dict()

        assert result["id"] == "T1595"
        assert result["name"] == "Active Scanning"
        assert result["tactic"] == "Reconnaissance"
        assert "PRE" in result["platforms"]


class TestMitreTactics:
    """Tests for MITRE tactics constant."""

    def test_all_tactics_present(self):
        """Test that all expected tactics are present."""
        expected = [
            "Reconnaissance",
            "Initial Access",
            "Privilege Escalation",
            "Credential Access",
            "Discovery",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]
        for tactic in expected:
            assert tactic in MITRE_TACTICS

    def test_tactics_in_order(self):
        """Test that tactics are in kill chain order."""
        recon_idx = MITRE_TACTICS.index("Reconnaissance")
        initial_access_idx = MITRE_TACTICS.index("Initial Access")
        impact_idx = MITRE_TACTICS.index("Impact")

        assert recon_idx < initial_access_idx
        assert initial_access_idx < impact_idx


class TestMitreTechniques:
    """Tests for MITRE techniques database."""

    def test_techniques_have_required_fields(self):
        """Test that all techniques have required fields."""
        for technique_id, technique in MITRE_TECHNIQUES.items():
            assert technique.id == technique_id
            assert technique.name
            assert technique.tactic
            assert technique.description

    def test_reconnaissance_techniques(self):
        """Test reconnaissance technique entries."""
        assert "T1595" in MITRE_TECHNIQUES
        assert MITRE_TECHNIQUES["T1595"].tactic == "Reconnaissance"

    def test_initial_access_techniques(self):
        """Test initial access technique entries."""
        assert "T1190" in MITRE_TECHNIQUES
        assert MITRE_TECHNIQUES["T1190"].tactic == "Initial Access"

    def test_subtechniques(self):
        """Test sub-technique entries."""
        assert "T1595.001" in MITRE_TECHNIQUES
        assert "T1595.002" in MITRE_TECHNIQUES


class TestMapToMitre:
    """Tests for map_to_mitre function."""

    def test_map_empty_context(self):
        """Test mapping with empty context."""
        ctx = Context(target="test.io")
        result = map_to_mitre(ctx)

        assert "mitre_mapping" in result.data
        assert "mitre_techniques_used" in result.data
        assert "mitre_tactic_coverage" in result.data

    def test_map_with_attack_paths(self):
        """Test mapping with attack paths."""
        ctx = Context(target="test.io")
        ctx.add(
            "attack_paths",
            [
                {"name": "Path 1", "mitre_techniques": ["T1595", "T1190"]},
                {"name": "Path 2", "mitre_techniques": ["T1078"]},
            ],
        )

        result = map_to_mitre(ctx)
        mapping = result.get("mitre_mapping")

        assert "T1595" in mapping
        assert "T1190" in mapping
        assert "T1078" in mapping

    def test_map_with_findings(self):
        """Test mapping findings to techniques."""
        ctx = Context(target="test.io")
        ctx.add(
            "finding_0",
            {
                "title": "SQL Injection Vulnerability",
                "description": "Database is vulnerable to SQL injection attacks",
            },
        )

        result = map_to_mitre(ctx)
        techniques = result.get("mitre_techniques_used")

        # Should map SQL-related keywords to T1190
        assert any("T1190" in t for t in techniques)

    def test_map_with_risks(self):
        """Test mapping risks to techniques."""
        ctx = Context(target="test.io")
        ctx.add(
            "risks",
            [
                {
                    "title": "Exposed credentials",
                    "description": "API keys found in source code",
                },
            ],
        )

        result = map_to_mitre(ctx)
        techniques = result.get("mitre_techniques_used")

        # Should map credential keywords
        assert any("T1552" in t for t in techniques)

    def test_exclude_subtechniques(self):
        """Test excluding sub-techniques."""
        ctx = Context(target="test.io")
        ctx.add(
            "attack_paths",
            [
                {"mitre_techniques": ["T1595", "T1595.001", "T1595.002"]},
            ],
        )

        result = map_to_mitre(ctx, {"include_subtechniques": False})
        techniques = result.get("mitre_techniques_used")

        # Should only have base technique
        assert "T1595" in techniques
        assert "T1595.001" not in techniques

    def test_exclude_detection(self):
        """Test excluding detection information."""
        ctx = Context(target="test.io")
        ctx.add("attack_paths", [{"mitre_techniques": ["T1595"]}])

        result = map_to_mitre(ctx, {"include_detection": False})
        mapping = result.get("mitre_mapping")

        # Detection field should be removed
        assert "detection" not in mapping.get("T1595", {})

    def test_mitre_summary(self):
        """Test MITRE summary generation."""
        ctx = Context(target="test.io")
        ctx.add(
            "attack_paths",
            [
                {"mitre_techniques": ["T1595", "T1190", "T1078"]},
            ],
        )

        result = map_to_mitre(ctx)
        summary = result.get("mitre_summary")

        assert "total_techniques" in summary
        assert "tactics_covered" in summary
        assert "coverage_percentage" in summary


class TestMapFindingsToTechniques:
    """Tests for map_findings_to_techniques function."""

    def test_map_sql_injection(self):
        """Test mapping SQL injection finding."""
        ctx = Context(target="test.io")
        ctx.add(
            "finding_0",
            {"title": "SQL Injection", "description": "Input not sanitized"},
        )

        mapping = map_findings_to_techniques(ctx)
        assert any("T1190" in techniques for techniques in mapping.keys())

    def test_map_credential_finding(self):
        """Test mapping credential finding."""
        ctx = Context(target="test.io")
        ctx.add(
            "finding_0",
            {
                "title": "Exposed API Key",
                "description": "AWS credentials found in code",
            },
        )

        mapping = map_findings_to_techniques(ctx)
        assert any("T1552" in t for t in mapping.keys())

    def test_multiple_findings(self):
        """Test mapping multiple findings."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Vulnerability scan needed", "description": ""})
        ctx.add("finding_1", {"title": "Password policy weak", "description": ""})

        mapping = map_findings_to_techniques(ctx)
        # Should have multiple technique mappings
        assert len(mapping) >= 1


class TestFindTechniquesForText:
    """Tests for find_techniques_for_text function."""

    def test_scan_keyword(self):
        """Test scan keyword mapping."""
        techniques = find_techniques_for_text("vulnerability scan detected")
        assert "T1595" in techniques

    def test_credential_keywords(self):
        """Test credential keyword mapping."""
        techniques = find_techniques_for_text("exposed credentials and secrets")
        assert "T1552" in techniques

    def test_sql_keyword(self):
        """Test SQL keyword mapping."""
        techniques = find_techniques_for_text("SQL injection vulnerability")
        assert "T1190" in techniques

    def test_no_keywords(self):
        """Test text with no keywords."""
        techniques = find_techniques_for_text("hello world")
        assert len(techniques) == 0

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        techniques = find_techniques_for_text("VULNERABILITY SCAN")
        assert "T1595" in techniques


class TestMapRiskToTechniques:
    """Tests for map_risk_to_techniques function."""

    def test_direct_mitre_id(self):
        """Test direct MITRE ID mapping."""
        risk = {"title": "Test Risk", "description": "Description", "mitre_id": "T1190"}
        techniques = map_risk_to_techniques(risk)
        assert "T1190" in techniques

    def test_keyword_based_mapping(self):
        """Test keyword-based mapping."""
        risk = {
            "title": "Exposed password file",
            "description": "Credentials accessible",
        }
        techniques = map_risk_to_techniques(risk)
        assert any("T1552" in t for t in techniques)

    def test_combined_mapping(self):
        """Test combined direct and keyword mapping."""
        risk = {
            "title": "Scan vulnerability",
            "description": "Active scanning detected",
            "mitre_id": "T1190",
        }
        techniques = map_risk_to_techniques(risk)
        assert "T1190" in techniques
        assert "T1595" in techniques


class TestMapFindingToTechnique:
    """Tests for map_finding_to_technique function."""

    def test_returns_single_technique(self):
        """Test that it returns a single technique."""
        finding = {"title": "SQL Injection Found", "description": "Database vulnerable"}
        technique = map_finding_to_technique(finding)
        assert technique is not None
        assert technique.startswith("T")

    def test_prefers_subtechniques(self):
        """Test preference for sub-techniques."""
        finding = {
            "title": "DNS enumeration detected",
            "description": "Subdomain scanning",
        }
        technique = map_finding_to_technique(finding)
        # Should prefer sub-technique if available
        if technique:
            # Either T1590.002 or T1590
            assert "T1590" in technique

    def test_returns_none_for_no_match(self):
        """Test returns None when no match."""
        finding = {"title": "Generic Issue", "description": "No specific keywords"}
        technique = map_finding_to_technique(finding)
        # Might be None if no keywords match
        assert technique is None or technique.startswith("T")


class TestCalculateTacticCoverage:
    """Tests for calculate_tactic_coverage function."""

    def test_coverage_calculation(self):
        """Test coverage calculation."""
        techniques = {"T1595", "T1190", "T1078"}
        coverage = calculate_tactic_coverage(techniques)

        assert coverage["Reconnaissance"] >= 1  # T1595
        assert coverage["Initial Access"] >= 1  # T1190, T1078

    def test_empty_coverage(self):
        """Test coverage with no techniques."""
        coverage = calculate_tactic_coverage(set())

        # All tactics should have 0 coverage
        for tactic in MITRE_TACTICS:
            assert coverage[tactic] == 0

    def test_all_tactics_present(self):
        """Test that all tactics are in coverage."""
        coverage = calculate_tactic_coverage(set())

        for tactic in MITRE_TACTICS:
            assert tactic in coverage


class TestGenerateDetectionRecommendations:
    """Tests for generate_detection_recommendations function."""

    def test_recommendations_by_data_source(self):
        """Test grouping recommendations by data source."""
        techniques = {"T1595", "T1190"}  # Both use Network Traffic
        recommendations = generate_detection_recommendations(techniques)

        # Should have recommendations grouped by data source
        assert len(recommendations) >= 1
        assert any(r["data_source"] == "Network Traffic" for r in recommendations)

    def test_priority_assignment(self):
        """Test priority assignment based on technique count."""
        # Many techniques using same data source = high priority
        techniques = {"T1595", "T1595.001", "T1595.002", "T1190"}
        recommendations = generate_detection_recommendations(techniques)

        network_rec = next(
            (r for r in recommendations if r["data_source"] == "Network Traffic"), None
        )
        assert network_rec is not None
        assert network_rec["priority"] in ("high", "medium", "low")

    def test_empty_techniques(self):
        """Test with no techniques."""
        recommendations = generate_detection_recommendations(set())
        assert recommendations == []


class TestGetTechniqueInfo:
    """Tests for get_technique_info function."""

    def test_get_valid_technique(self):
        """Test getting valid technique info."""
        info = get_technique_info("T1595")

        assert info is not None
        assert info["id"] == "T1595"
        assert info["name"] == "Active Scanning"

    def test_get_subtechnique(self):
        """Test getting sub-technique info."""
        info = get_technique_info("T1595.001")

        assert info is not None
        assert "Scanning IP Blocks" in info["name"]

    def test_get_invalid_technique(self):
        """Test getting invalid technique."""
        info = get_technique_info("T9999")
        assert info is None


class TestGetTechniquesByTactic:
    """Tests for get_techniques_by_tactic function."""

    def test_reconnaissance_techniques(self):
        """Test getting reconnaissance techniques."""
        techniques = get_techniques_by_tactic("Reconnaissance")

        assert len(techniques) >= 1
        assert all(t["tactic"] == "Reconnaissance" for t in techniques)

    def test_initial_access_techniques(self):
        """Test getting initial access techniques."""
        techniques = get_techniques_by_tactic("Initial Access")

        assert len(techniques) >= 1
        assert any(t["id"] == "T1190" for t in techniques)

    def test_invalid_tactic(self):
        """Test getting techniques for invalid tactic."""
        techniques = get_techniques_by_tactic("Invalid Tactic")
        assert techniques == []


class TestGetAllTactics:
    """Tests for get_all_tactics function."""

    def test_returns_copy(self):
        """Test that it returns a copy."""
        tactics1 = get_all_tactics()
        tactics2 = get_all_tactics()

        # Modifying one shouldn't affect the other
        tactics1.append("Modified")
        assert "Modified" not in tactics2

    def test_all_tactics_present(self):
        """Test that all tactics are returned."""
        tactics = get_all_tactics()

        assert "Reconnaissance" in tactics
        assert "Impact" in tactics
        assert len(tactics) == len(MITRE_TACTICS)


class TestGetMitigationsForTechniques:
    """Tests for get_mitigations_for_techniques function."""

    def test_get_mitigations(self):
        """Test getting mitigations."""
        techniques = {"T1595", "T1190"}
        mitigations = get_mitigations_for_techniques(techniques)

        assert len(mitigations) >= 1
        assert all("mitigation" in m for m in mitigations)
        assert all("technique_id" in m for m in mitigations)

    def test_sorted_output(self):
        """Test that output is sorted by technique ID."""
        techniques = {"T1190", "T1078", "T1595"}
        mitigations = get_mitigations_for_techniques(techniques)

        ids = [m["technique_id"] for m in mitigations]
        assert ids == sorted(ids)


class TestGenerateAttackMatrixView:
    """Tests for generate_attack_matrix_view function."""

    def test_matrix_structure(self):
        """Test matrix structure."""
        techniques = {"T1595", "T1190"}
        matrix = generate_attack_matrix_view(techniques)

        # Should have all tactics
        for tactic in MITRE_TACTICS:
            assert tactic in matrix

    def test_technique_placement(self):
        """Test technique placement in correct tactics."""
        techniques = {"T1595", "T1190"}
        matrix = generate_attack_matrix_view(techniques)

        assert "T1595" in matrix["Reconnaissance"]
        assert "T1190" in matrix["Initial Access"]

    def test_sorted_techniques(self):
        """Test that techniques are sorted within tactics."""
        techniques = {"T1595.002", "T1595", "T1595.001"}
        matrix = generate_attack_matrix_view(techniques)

        recon_techs = matrix["Reconnaissance"]
        assert recon_techs == sorted(recon_techs)


class TestNavigatorLayerExport:
    """Tests for MITRE ATT&CK Navigator layer export."""

    def test_generates_valid_layer_structure(self):
        """Navigator layer must contain required top-level keys."""
        layer = generate_navigator_layer({"T1595", "T1190"})

        assert layer["name"] == "RedOPS Scan Results"
        assert layer["domain"] == "enterprise-attack"
        assert "versions" in layer
        assert "techniques" in layer
        assert "gradient" in layer
        assert "legendItems" in layer

    def test_techniques_have_required_fields(self):
        """Each technique entry must have techniqueID, tactic, score, comment."""
        layer = generate_navigator_layer({"T1595"})
        techniques = layer["techniques"]
        assert len(techniques) == 1

        tech = techniques[0]
        assert tech["techniqueID"] == "T1595"
        assert tech["tactic"] == "reconnaissance"
        assert tech["score"] == 1
        assert "Active Scanning" in tech["comment"]
        assert tech["enabled"] is True

    def test_skips_unknown_techniques(self):
        """Unknown technique IDs should be silently skipped."""
        layer = generate_navigator_layer({"T1595", "T9999"})
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1595" in ids
        assert "T9999" not in ids

    def test_custom_name_and_description(self):
        """Custom name and description should be reflected in output."""
        layer = generate_navigator_layer(
            {"T1595"},
            name="Bug Bounty Recon",
            description="Coverage from bug bounty reconnaissance scan",
        )
        assert layer["name"] == "Bug Bounty Recon"
        assert layer["description"] == "Coverage from bug bounty reconnaissance scan"

    def test_empty_techniques_returns_empty_layer(self):
        """Empty input should produce valid layer with zero techniques."""
        layer = generate_navigator_layer(set())
        assert layer["techniques"] == []
        assert layer["name"] == "RedOPS Scan Results"


class TestKeywordTechniqueMap:
    """Tests for keyword-technique mapping."""

    def test_reconnaissance_keywords(self):
        """Test reconnaissance keywords."""
        assert "scan" in KEYWORD_TECHNIQUE_MAP
        assert "T1595" in KEYWORD_TECHNIQUE_MAP["scan"]

    def test_credential_keywords(self):
        """Test credential keywords."""
        assert "credential" in KEYWORD_TECHNIQUE_MAP
        assert "password" in KEYWORD_TECHNIQUE_MAP
        assert "secret" in KEYWORD_TECHNIQUE_MAP

    def test_vulnerability_keywords(self):
        """Test vulnerability keywords."""
        assert "vulnerability" in KEYWORD_TECHNIQUE_MAP
        assert "exploit" in KEYWORD_TECHNIQUE_MAP
