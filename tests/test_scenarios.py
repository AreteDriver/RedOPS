"""Tests for simulation/scenarios module."""

import pytest
from redops.modules.simulation.scenarios import (
    AttackScenario,
    THREAT_ACTORS,
    ATTACK_OBJECTIVES,
    RECOMMENDATION_TEMPLATES,
    generate_scenarios,
    create_attack_scenario,
    determine_threat_actor,
    determine_objective,
    extract_affected_assets,
    generate_detailed_steps,
    get_attack_phase,
    generate_recommendations,
    generate_executive_summary,
    generate_technical_details,
    generate_overall_summary,
    prioritize_scenarios,
    create_scenario_narrative,
    generate_narrative,
    get_scenario_by_id,
    export_scenarios_markdown,
)
from redops.core.context import Context


class TestAttackScenario:
    """Tests for AttackScenario dataclass."""

    def test_basic_creation(self):
        """Test basic scenario creation."""
        scenario = AttackScenario(
            id=1,
            title="Test Scenario",
            summary="Test summary",
            threat_actor="Opportunistic Attacker",
            objective="Data theft",
            likelihood=3,
            impact=4,
            steps=[],
            mitre_techniques=[],
            assets_affected=[],
            recommendations=[],
            executive_summary="",
            technical_details=""
        )
        assert scenario.id == 1
        assert scenario.title == "Test Scenario"
        assert scenario.likelihood == 3
        assert scenario.impact == 4

    def test_risk_score_property(self):
        """Test risk score calculation."""
        scenario = AttackScenario(
            id=1, title="", summary="", threat_actor="", objective="",
            likelihood=4, impact=5,
            steps=[], mitre_techniques=[], assets_affected=[],
            recommendations=[], executive_summary="", technical_details=""
        )
        assert scenario.risk_score == 20

    def test_risk_level_critical(self):
        """Test critical risk level."""
        scenario = AttackScenario(
            id=1, title="", summary="", threat_actor="", objective="",
            likelihood=5, impact=5,
            steps=[], mitre_techniques=[], assets_affected=[],
            recommendations=[], executive_summary="", technical_details=""
        )
        assert scenario.risk_level == "CRITICAL"

    def test_risk_level_high(self):
        """Test high risk level."""
        scenario = AttackScenario(
            id=1, title="", summary="", threat_actor="", objective="",
            likelihood=4, impact=4,
            steps=[], mitre_techniques=[], assets_affected=[],
            recommendations=[], executive_summary="", technical_details=""
        )
        assert scenario.risk_level == "HIGH"

    def test_risk_level_medium(self):
        """Test medium risk level."""
        scenario = AttackScenario(
            id=1, title="", summary="", threat_actor="", objective="",
            likelihood=3, impact=3,
            steps=[], mitre_techniques=[], assets_affected=[],
            recommendations=[], executive_summary="", technical_details=""
        )
        assert scenario.risk_level == "MEDIUM"

    def test_risk_level_low(self):
        """Test low risk level."""
        scenario = AttackScenario(
            id=1, title="", summary="", threat_actor="", objective="",
            likelihood=2, impact=2,
            steps=[], mitre_techniques=[], assets_affected=[],
            recommendations=[], executive_summary="", technical_details=""
        )
        assert scenario.risk_level == "LOW"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        scenario = AttackScenario(
            id=1,
            title="Test",
            summary="Summary",
            threat_actor="Actor",
            objective="Objective",
            likelihood=3,
            impact=4,
            steps=[{"step": 1}],
            mitre_techniques=["T1190"],
            assets_affected=["asset1"],
            recommendations=["rec1"],
            executive_summary="exec",
            technical_details="tech"
        )
        result = scenario.to_dict()

        assert result["id"] == 1
        assert result["title"] == "Test"
        assert result["risk_score"] == 12
        assert result["risk_level"] == "HIGH"
        assert len(result["steps"]) == 1


class TestThreatActors:
    """Tests for threat actor definitions."""

    def test_all_actors_have_required_fields(self):
        """Test that all actors have required fields."""
        for actor_key, actor in THREAT_ACTORS.items():
            assert "name" in actor
            assert "description" in actor
            assert "motivation" in actor
            assert "sophistication" in actor
            assert "typical_techniques" in actor

    def test_opportunistic_attacker(self):
        """Test opportunistic attacker profile."""
        actor = THREAT_ACTORS["opportunistic_attacker"]
        assert "low" in actor["sophistication"].lower()

    def test_nation_state_actor(self):
        """Test nation-state actor profile."""
        actor = THREAT_ACTORS["nation_state"]
        assert "high" in actor["sophistication"].lower()


class TestAttackObjectives:
    """Tests for attack objectives."""

    def test_data_theft(self):
        """Test data theft objective."""
        assert "data_theft" in ATTACK_OBJECTIVES
        assert "data" in ATTACK_OBJECTIVES["data_theft"].lower()

    def test_ransomware(self):
        """Test ransomware objective."""
        assert "ransomware" in ATTACK_OBJECTIVES
        assert "encrypt" in ATTACK_OBJECTIVES["ransomware"].lower()

    def test_credential_harvesting(self):
        """Test credential harvesting objective."""
        assert "credential_harvesting" in ATTACK_OBJECTIVES


class TestGenerateScenarios:
    """Tests for generate_scenarios function."""

    def test_generate_with_no_attack_paths(self):
        """Test generation with no attack paths."""
        ctx = Context(target="test.io")
        result = generate_scenarios(ctx)

        assert "scenarios" in result.data
        assert result.get("scenarios") == []

    def test_generate_with_attack_paths(self):
        """Test generation with attack paths."""
        ctx = Context(target="test.io")
        ctx.add("attack_paths", [
            {
                "name": "Path 1",
                "description": "Test path",
                "steps": ["Step 1", "Step 2"],
                "mitre_techniques": ["T1190"],
                "likelihood": 4,
                "impact": 4
            }
        ])

        result = generate_scenarios(ctx)
        scenarios = result.get("scenarios")

        assert len(scenarios) >= 1
        assert scenarios[0]["title"]

    def test_max_scenarios_parameter(self):
        """Test max_scenarios parameter."""
        ctx = Context(target="test.io")
        ctx.add("attack_paths", [
            {"name": f"Path {i}", "steps": [], "mitre_techniques": [], "likelihood": 3, "impact": 3}
            for i in range(10)
        ])

        result = generate_scenarios(ctx, {"max_scenarios": 3})
        scenarios = result.get("scenarios")

        assert len(scenarios) <= 3

    def test_scenario_summary_generated(self):
        """Test scenario summary generation."""
        ctx = Context(target="test.io")
        ctx.add("attack_paths", [
            {"name": "Path 1", "steps": [], "mitre_techniques": ["T1190"], "likelihood": 4, "impact": 4}
        ])

        result = generate_scenarios(ctx)
        summary = result.get("scenario_summary")

        assert "total_scenarios" in summary
        assert "risk_distribution" in summary


class TestCreateAttackScenario:
    """Tests for create_attack_scenario function."""

    def test_create_scenario(self):
        """Test scenario creation."""
        ctx = Context(target="test.io")
        attack_path = {
            "name": "Test Attack",
            "description": "Test description",
            "steps": ["Recon", "Exploit", "Exfiltrate"],
            "mitre_techniques": ["T1595", "T1190"],
            "likelihood": 4,
            "impact": 5
        }

        scenario = create_attack_scenario(1, attack_path, ctx)

        assert scenario.id == 1
        assert scenario.title == "Test Attack"
        assert scenario.likelihood == 4
        assert scenario.impact == 5

    def test_include_executive_summary(self):
        """Test executive summary inclusion."""
        ctx = Context(target="test.io")
        attack_path = {"name": "Test", "steps": [], "mitre_techniques": [], "likelihood": 3, "impact": 3}

        scenario = create_attack_scenario(1, attack_path, ctx, include_executive=True)
        assert scenario.executive_summary != ""

    def test_exclude_executive_summary(self):
        """Test executive summary exclusion."""
        ctx = Context(target="test.io")
        attack_path = {"name": "Test", "steps": [], "mitre_techniques": [], "likelihood": 3, "impact": 3}

        scenario = create_attack_scenario(1, attack_path, ctx, include_executive=False)
        assert scenario.executive_summary == ""


class TestDetermineThreatActor:
    """Tests for determine_threat_actor function."""

    def test_opportunistic_default(self):
        """Test default to opportunistic attacker."""
        actor = determine_threat_actor([])
        assert actor["name"] == "Opportunistic Attacker"

    def test_nation_state_detection(self):
        """Test nation-state actor detection."""
        techniques = ["T1199", "T1068", "T1071"]
        actor = determine_threat_actor(techniques)
        assert actor["name"] == "Nation-State Actor"

    def test_organized_crime_detection(self):
        """Test organized crime detection."""
        techniques = ["T1486", "T1041"]  # Ransomware techniques
        actor = determine_threat_actor(techniques)
        assert actor["name"] == "Organized Cybercrime Group"

    def test_insider_threat_detection(self):
        """Test insider threat detection."""
        techniques = ["T1078", "T1552"]
        actor = determine_threat_actor(techniques)
        assert actor["name"] == "Malicious Insider"


class TestDetermineObjective:
    """Tests for determine_objective function."""

    def test_ransomware_objective(self):
        """Test ransomware objective detection."""
        ctx = Context(target="test.io")
        objective = determine_objective([], ["T1486"], ctx)
        assert "encrypt" in objective.lower() or "ransom" in objective.lower()

    def test_disruption_objective(self):
        """Test disruption objective detection."""
        ctx = Context(target="test.io")
        objective = determine_objective([], ["T1498"], ctx)
        assert "disrupt" in objective.lower() or "denial" in objective.lower()

    def test_data_theft_objective(self):
        """Test data theft objective detection."""
        ctx = Context(target="test.io")
        objective = determine_objective([], ["T1041"], ctx)
        assert "data" in objective.lower() or "exfiltrate" in objective.lower()

    def test_credential_objective_from_findings(self):
        """Test credential objective from findings."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Exposed credentials found"})
        objective = determine_objective([], [], ctx)
        assert "credential" in objective.lower()


class TestExtractAffectedAssets:
    """Tests for extract_affected_assets function."""

    def test_extract_from_string_steps(self):
        """Test extraction from string steps."""
        attack_path = {"steps": ["Access www.test.io", "Reach database"]}
        ctx = Context(target="test.io")

        assets = extract_affected_assets(attack_path, ctx)
        assert len(assets) == 2

    def test_extract_from_dict_steps(self):
        """Test extraction from dict steps."""
        attack_path = {
            "steps": [
                {"node_type": "subdomain", "description": "api.test.io"},
                {"node_type": "technology", "action": "nginx server"},
            ]
        }
        ctx = Context(target="test.io")

        assets = extract_affected_assets(attack_path, ctx)
        assert len(assets) >= 1

    def test_deduplicate_assets(self):
        """Test asset deduplication."""
        attack_path = {"steps": ["Asset A", "Asset A", "Asset B"]}
        ctx = Context(target="test.io")

        assets = extract_affected_assets(attack_path, ctx)
        assert len(assets) == 2


class TestGenerateDetailedSteps:
    """Tests for generate_detailed_steps function."""

    def test_generate_steps(self):
        """Test detailed step generation."""
        steps = ["Reconnaissance", "Initial access", "Data exfiltration"]
        techniques = ["T1595", "T1190"]

        detailed = generate_detailed_steps(steps, techniques)

        assert len(detailed) == 3
        assert detailed[0]["number"] == 1
        assert detailed[0]["description"] == "Reconnaissance"
        assert "phase" in detailed[0]

    def test_technique_association(self):
        """Test technique association with steps."""
        steps = ["Scan", "Exploit"]
        techniques = ["T1595", "T1190"]

        detailed = generate_detailed_steps(steps, techniques)

        # First step should have T1595
        assert detailed[0]["technique"]["id"] == "T1595"

    def test_empty_techniques(self):
        """Test with no techniques."""
        steps = ["Step 1", "Step 2"]
        techniques = []

        detailed = generate_detailed_steps(steps, techniques)

        assert detailed[0]["technique"] is None


class TestGetAttackPhase:
    """Tests for get_attack_phase function."""

    def test_single_step(self):
        """Test phase for single step."""
        phase = get_attack_phase(0, 1)
        assert phase == "Execution"

    def test_early_phase(self):
        """Test early phase (reconnaissance)."""
        phase = get_attack_phase(0, 10)
        assert phase == "Reconnaissance"

    def test_late_phase(self):
        """Test late phase (objective)."""
        phase = get_attack_phase(9, 10)
        assert phase == "Objective"

    def test_middle_phases(self):
        """Test middle phases."""
        # Initial access phase
        phase = get_attack_phase(2, 10)
        assert phase in ("Reconnaissance", "Initial Access", "Privilege Escalation")


class TestGenerateRecommendations:
    """Tests for generate_recommendations function."""

    def test_technique_based_recommendations(self):
        """Test technique-based recommendations."""
        ctx = Context(target="test.io")
        recommendations = generate_recommendations(["T1190"], ctx)

        assert len(recommendations) >= 1
        assert any("WAF" in rec or "patch" in rec.lower() for rec in recommendations)

    def test_default_recommendations(self):
        """Test default recommendations when no techniques match."""
        ctx = Context(target="test.io")
        recommendations = generate_recommendations([], ctx)

        # Should have default recommendations
        assert len(recommendations) >= 3

    def test_finding_recommendations(self):
        """Test recommendations from findings."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {
            "title": "Test",
            "data": {"recommendation": "Custom recommendation"}
        })

        recommendations = generate_recommendations([], ctx)
        assert "Custom recommendation" in recommendations


class TestGenerateExecutiveSummary:
    """Tests for generate_executive_summary function."""

    def test_summary_content(self):
        """Test summary content."""
        actor = THREAT_ACTORS["opportunistic_attacker"]
        summary = generate_executive_summary(
            "Test Attack",
            actor,
            "Data theft objective",
            4, 5,
            ["Asset 1", "Asset 2"]
        )

        assert "CRITICAL" in summary  # 4*5=20
        assert "opportunistic" in summary.lower()
        assert "2 systems/assets" in summary

    def test_risk_level_in_summary(self):
        """Test risk level appears in summary."""
        actor = THREAT_ACTORS["opportunistic_attacker"]
        summary = generate_executive_summary("Test", actor, "Objective", 2, 2, [])

        assert "LOW" in summary or "MEDIUM" in summary


class TestGenerateTechnicalDetails:
    """Tests for generate_technical_details function."""

    def test_attack_chain_section(self):
        """Test attack chain section."""
        steps = [
            {"number": 1, "description": "Recon", "phase": "Reconnaissance", "technique": None}
        ]
        ctx = Context(target="test.io")

        details = generate_technical_details(steps, [], ctx)

        assert "Attack Chain" in details
        assert "Step 1" in details

    def test_mitre_mapping_table(self):
        """Test MITRE mapping table."""
        steps = []
        techniques = ["T1595", "T1190"]
        ctx = Context(target="test.io")

        details = generate_technical_details(steps, techniques, ctx)

        assert "MITRE ATT&CK Mapping" in details
        assert "T1595" in details
        assert "T1190" in details


class TestGenerateOverallSummary:
    """Tests for generate_overall_summary function."""

    def test_summary_with_scenarios(self):
        """Test summary with scenarios."""
        scenarios = [
            AttackScenario(
                id=1, title="", summary="", threat_actor="Actor A", objective="",
                likelihood=4, impact=5,
                steps=[], mitre_techniques=["T1190"],
                assets_affected=[], recommendations=[],
                executive_summary="", technical_details=""
            ),
            AttackScenario(
                id=2, title="", summary="", threat_actor="Actor B", objective="",
                likelihood=3, impact=3,
                steps=[], mitre_techniques=["T1078"],
                assets_affected=[], recommendations=[],
                executive_summary="", technical_details=""
            )
        ]
        ctx = Context(target="test.io")

        summary = generate_overall_summary(scenarios, ctx)

        assert summary["total_scenarios"] == 2
        assert "CRITICAL" in summary["risk_distribution"]
        assert summary["average_risk_score"] == (20 + 9) / 2

    def test_empty_summary(self):
        """Test summary with no scenarios."""
        ctx = Context(target="test.io")
        summary = generate_overall_summary([], ctx)

        assert summary["total_scenarios"] == 0


class TestPrioritizeScenarios:
    """Tests for prioritize_scenarios function."""

    def test_sort_by_risk(self):
        """Test sorting by risk score."""
        scenarios = [
            AttackScenario(
                id=1, title="Low", summary="", threat_actor="", objective="",
                likelihood=1, impact=1,
                steps=[], mitre_techniques=[], assets_affected=[],
                recommendations=[], executive_summary="", technical_details=""
            ),
            AttackScenario(
                id=2, title="High", summary="", threat_actor="", objective="",
                likelihood=5, impact=5,
                steps=[], mitre_techniques=[], assets_affected=[],
                recommendations=[], executive_summary="", technical_details=""
            ),
        ]

        prioritized = prioritize_scenarios(scenarios)

        assert prioritized[0].title == "High"
        assert prioritized[1].title == "Low"


class TestCreateScenarioNarrative:
    """Tests for create_scenario_narrative function (legacy)."""

    def test_creates_dict(self):
        """Test that it returns a dictionary."""
        attack_path = {
            "name": "Test",
            "steps": ["Step 1"],
            "mitre_techniques": [],
            "likelihood": 3,
            "impact": 3
        }
        ctx = Context(target="test.io")

        result = create_scenario_narrative(attack_path, ctx)

        assert isinstance(result, dict)
        assert "title" in result


class TestGenerateNarrative:
    """Tests for generate_narrative function (legacy)."""

    def test_with_steps(self):
        """Test narrative with steps."""
        attack_path = {"steps": ["Step 1", "Step 2", "Step 3"]}
        narrative = generate_narrative(attack_path)

        assert "3 steps" in narrative
        assert "1. Step 1" in narrative

    def test_without_steps(self):
        """Test narrative without steps."""
        attack_path = {"steps": []}
        narrative = generate_narrative(attack_path)

        assert "No detailed steps" in narrative

    def test_with_dict_steps(self):
        """Test narrative with dict steps."""
        attack_path = {
            "steps": [
                {"description": "First step"},
                {"action": "Second action"}
            ]
        }
        narrative = generate_narrative(attack_path)

        assert "First step" in narrative


class TestGetScenarioById:
    """Tests for get_scenario_by_id function."""

    def test_get_existing_scenario(self):
        """Test getting existing scenario."""
        ctx = Context(target="test.io")
        ctx.add("scenarios", [
            {"id": 1, "title": "First"},
            {"id": 2, "title": "Second"}
        ])

        result = get_scenario_by_id(ctx, 2)

        assert result is not None
        assert result["title"] == "Second"

    def test_get_nonexistent_scenario(self):
        """Test getting nonexistent scenario."""
        ctx = Context(target="test.io")
        ctx.add("scenarios", [{"id": 1, "title": "First"}])

        result = get_scenario_by_id(ctx, 999)

        assert result is None


class TestExportScenariosMarkdown:
    """Tests for export_scenarios_markdown function."""

    def test_export_format(self):
        """Test markdown export format."""
        scenarios = [
            {
                "title": "Test Scenario",
                "risk_level": "HIGH",
                "risk_score": 16,
                "threat_actor": "Test Actor",
                "objective": "Test Objective",
                "executive_summary": "Summary here",
                "recommendations": ["Rec 1", "Rec 2"],
                "technical_details": "Details here"
            }
        ]

        md = export_scenarios_markdown(scenarios)

        assert "# Attack Scenarios Report" in md
        assert "## Test Scenario" in md
        assert "HIGH" in md
        assert "Test Actor" in md
        assert "- Rec 1" in md

    def test_multiple_scenarios(self):
        """Test export with multiple scenarios."""
        scenarios = [
            {"title": "First", "risk_level": "HIGH", "risk_score": 16,
             "threat_actor": "", "objective": "", "recommendations": []},
            {"title": "Second", "risk_level": "MEDIUM", "risk_score": 9,
             "threat_actor": "", "objective": "", "recommendations": []},
        ]

        md = export_scenarios_markdown(scenarios)

        assert "## First" in md
        assert "## Second" in md
        assert md.count("---") >= 2  # Section separators
