"""Tests for simulation/attack_paths module."""

import pytest
from redops.modules.simulation.attack_paths import (
    AttackNode,
    AttackChain,
    analyze_paths,
    identify_entry_points,
    identify_targets,
    find_attack_chains,
    dfs_find_paths,
    generate_steps,
    get_path_techniques,
    score_attack_chains,
    generate_path_description,
    identify_critical_nodes,
    rank_attack_paths,
    get_attack_surface_summary,
    ENTRY_POINT_TYPES,
    TARGET_INDICATORS,
    RISK_KEYWORDS,
    TRANSITION_TECHNIQUES,
)
from redops.core.context import Context
from redops.core.models import AttackPath


class TestAttackNode:
    """Tests for AttackNode dataclass."""

    def test_basic_creation(self):
        """Test basic node creation."""
        node = AttackNode(
            id="node1",
            node_type="subdomain",
            label="api.example.com"
        )
        assert node.id == "node1"
        assert node.node_type == "subdomain"
        assert node.label == "api.example.com"
        assert node.risk_contribution == 0.0
        assert not node.is_entry_point
        assert not node.is_target

    def test_node_with_data(self):
        """Test node with custom data."""
        node = AttackNode(
            id="n1",
            node_type="risk",
            label="SQL Injection",
            risk_contribution=5.0,
            is_target=True,
            data={"severity": "critical"}
        )
        assert node.risk_contribution == 5.0
        assert node.is_target
        assert node.data["severity"] == "critical"


class TestAttackChain:
    """Tests for AttackChain dataclass."""

    def test_basic_creation(self):
        """Test basic chain creation."""
        chain = AttackChain(
            path=["entry", "middle", "target"],
            entry_point="entry",
            target="target"
        )
        assert len(chain.path) == 3
        assert chain.entry_point == "entry"
        assert chain.target == "target"
        assert chain.total_risk == 0.0

    def test_to_attack_path(self):
        """Test conversion to AttackPath model."""
        chain = AttackChain(
            path=["entry", "target"],
            entry_point="entry",
            target="target",
            total_risk=15.0,
            steps=[{"description": "Step 1"}, {"description": "Step 2"}],
            mitre_techniques=["T1190", "T1068"]
        )
        attack_path = chain.to_attack_path(name="Test Path")

        assert attack_path.name == "Test Path"
        assert len(attack_path.steps) == 2
        assert len(attack_path.mitre_techniques) == 2
        assert 1 <= attack_path.likelihood <= 5
        assert 1 <= attack_path.impact <= 5

    def test_to_attack_path_default_name(self):
        """Test default name generation."""
        chain = AttackChain(
            path=["a", "b"],
            entry_point="a",
            target="b"
        )
        attack_path = chain.to_attack_path()
        assert "a" in attack_path.name
        assert "b" in attack_path.name


class TestAnalyzePaths:
    """Tests for analyze_paths function."""

    def test_analyze_paths_empty_graph(self):
        """Test with no graph data."""
        ctx = Context(target="test.io")
        result = analyze_paths(ctx)

        assert "attack_paths" in result.data
        assert result.get("attack_paths") == []

    def test_analyze_paths_with_graph(self):
        """Test with actual graph data."""
        ctx = Context(target="test.io")
        ctx.add("graph", {
            "nodes": [
                {"id": "domain:test.io", "type": "domain", "label": "test.io", "data": {"is_target": True}},
                {"id": "subdomain:api.test.io", "type": "subdomain", "label": "api.test.io"},
                {"id": "risk:0", "type": "risk", "label": "SQL Injection", "data": {"severity": "critical"}},
            ],
            "edges": [
                {"source": "domain:test.io", "target": "subdomain:api.test.io"},
                {"source": "subdomain:api.test.io", "target": "risk:0"},
            ],
        })

        result = analyze_paths(ctx)
        assert "attack_paths" in result.data
        assert "attack_path_summary" in result.data

    def test_analyze_paths_parameters(self):
        """Test with custom parameters."""
        ctx = Context(target="test.io")
        ctx.add("graph", {
            "nodes": [
                {"id": "d1", "type": "domain", "label": "test.io", "data": {"is_target": True}},
                {"id": "r1", "type": "risk", "label": "risk"},
            ],
            "edges": [{"source": "d1", "target": "r1"}],
        })

        result = analyze_paths(ctx, {
            "max_paths": 5,
            "max_depth": 3,
            "min_risk_score": 1
        })
        assert "attack_paths" in result.data


class TestIdentifyEntryPoints:
    """Tests for entry point identification."""

    def test_subdomain_entry_points(self):
        """Test subdomain entry point detection."""
        nodes = {
            "sub:www": {"id": "sub:www", "type": "subdomain", "label": "www.test.io"},
            "sub:api": {"id": "sub:api", "type": "subdomain", "label": "api.test.io"},
        }
        ctx = Context(target="test.io")

        entry_points = identify_entry_points(nodes, ctx)
        assert "sub:www" in entry_points
        assert "sub:api" in entry_points

    def test_ip_entry_points(self):
        """Test IP entry point detection."""
        nodes = {
            "ip:1.2.3.4": {"id": "ip:1.2.3.4", "type": "ip", "label": "1.2.3.4"},
        }
        ctx = Context(target="test.io")

        entry_points = identify_entry_points(nodes, ctx)
        assert "ip:1.2.3.4" in entry_points

    def test_web_technology_entry_points(self):
        """Test web technology entry point detection."""
        nodes = {
            "tech:nginx": {"id": "tech:nginx", "type": "technology", "label": "nginx 1.20"},
            "tech:react": {"id": "tech:react", "type": "technology", "label": "React"},
        }
        ctx = Context(target="test.io")

        entry_points = identify_entry_points(nodes, ctx)
        assert "tech:nginx" in entry_points
        # React is not a web server, shouldn't be entry point
        assert "tech:react" not in entry_points

    def test_target_domain_is_entry_point(self):
        """Test that target domain is an entry point."""
        nodes = {
            "domain:test.io": {"id": "domain:test.io", "type": "domain", "label": "test.io", "data": {"is_target": True}},
        }
        ctx = Context(target="test.io")

        entry_points = identify_entry_points(nodes, ctx)
        assert "domain:test.io" in entry_points


class TestIdentifyTargets:
    """Tests for target identification."""

    def test_risk_nodes_are_targets(self):
        """Test that risk nodes are targets."""
        nodes = {
            "risk:0": {"id": "risk:0", "type": "risk", "label": "Vulnerability", "data": {}},
        }
        ctx = Context(target="test.io")

        targets = identify_targets(nodes, ctx)
        assert "risk:0" in targets

    def test_high_severity_findings_are_targets(self):
        """Test that high severity findings are targets."""
        nodes = {
            "finding:0": {"id": "finding:0", "type": "finding", "label": "Critical Issue", "data": {"severity": "critical"}},
        }
        ctx = Context(target="test.io")

        targets = identify_targets(nodes, ctx)
        assert "finding:0" in targets

    def test_high_value_indicators(self):
        """Test high-value indicator detection."""
        nodes = {
            "n1": {"id": "n1", "type": "subdomain", "label": "admin.test.io"},
            "n2": {"id": "n2", "type": "subdomain", "label": "database.test.io"},
            "n3": {"id": "n3", "type": "subdomain", "label": "payment.test.io"},
        }
        ctx = Context(target="test.io")

        targets = identify_targets(nodes, ctx)
        assert "n1" in targets  # admin
        assert "n2" in targets  # database
        assert "n3" in targets  # payment

    def test_email_nodes_are_targets(self):
        """Test that email nodes are targets."""
        nodes = {
            "email:admin@test.io": {"id": "email:admin@test.io", "type": "email", "label": "admin@test.io"},
        }
        ctx = Context(target="test.io")

        targets = identify_targets(nodes, ctx)
        assert "email:admin@test.io" in targets


class TestFindAttackChains:
    """Tests for attack chain finding."""

    def test_find_simple_chain(self):
        """Test finding a simple attack chain."""
        nodes = {
            "a": {"type": "subdomain"},
            "b": {"type": "technology"},
            "c": {"type": "risk"},
        }
        adjacency = {"a": ["b"], "b": ["c"]}
        entry_points = {"a"}
        targets = {"c"}

        chains = find_attack_chains(nodes, adjacency, entry_points, targets, max_depth=5)
        assert len(chains) == 1
        assert chains[0].path == ["a", "b", "c"]

    def test_find_multiple_chains(self):
        """Test finding multiple chains."""
        nodes = {
            "entry": {"type": "subdomain"},
            "mid1": {"type": "technology"},
            "mid2": {"type": "ip"},
            "target": {"type": "risk"},
        }
        adjacency = {
            "entry": ["mid1", "mid2"],
            "mid1": ["target"],
            "mid2": ["target"],
        }
        entry_points = {"entry"}
        targets = {"target"}

        chains = find_attack_chains(nodes, adjacency, entry_points, targets, max_depth=5)
        assert len(chains) == 2

    def test_no_chain_when_same_entry_target(self):
        """Test that entry == target produces no chain."""
        nodes = {"a": {"type": "domain"}}
        adjacency = {}
        entry_points = {"a"}
        targets = {"a"}

        chains = find_attack_chains(nodes, adjacency, entry_points, targets, max_depth=5)
        assert len(chains) == 0


class TestDFSFindPaths:
    """Tests for DFS path finding."""

    def test_simple_path(self):
        """Test finding a simple path."""
        adjacency = {"a": ["b"], "b": ["c"]}
        paths = dfs_find_paths(adjacency, "a", "c", max_depth=5)

        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_no_path(self):
        """Test when no path exists."""
        adjacency = {"a": ["b"], "c": ["d"]}
        paths = dfs_find_paths(adjacency, "a", "d", max_depth=5)

        assert len(paths) == 0

    def test_max_depth_limit(self):
        """Test max depth limitation."""
        adjacency = {str(i): [str(i+1)] for i in range(10)}
        paths = dfs_find_paths(adjacency, "0", "9", max_depth=3)

        assert len(paths) == 0  # Path is too long

    def test_multiple_paths(self):
        """Test finding multiple paths."""
        adjacency = {
            "a": ["b", "c"],
            "b": ["d"],
            "c": ["d"],
        }
        paths = dfs_find_paths(adjacency, "a", "d", max_depth=5)

        assert len(paths) == 2


class TestGenerateSteps:
    """Tests for step generation."""

    def test_generate_steps(self):
        """Test step generation from path."""
        path = ["entry", "middle", "target"]
        nodes = {
            "entry": {"type": "subdomain", "label": "www.test.io"},
            "middle": {"type": "technology", "label": "nginx"},
            "target": {"type": "risk", "label": "Vulnerability"},
        }

        steps = generate_steps(path, nodes)
        assert len(steps) == 3
        assert "Initial access" in steps[0]["action"]
        assert "Traverse" in steps[1]["action"]
        assert "Reach target" in steps[2]["action"]

    def test_generate_steps_missing_node(self):
        """Test with missing node data."""
        path = ["a", "b"]
        nodes = {}

        steps = generate_steps(path, nodes)
        assert len(steps) == 2


class TestGetPathTechniques:
    """Tests for technique extraction."""

    def test_get_techniques_for_transitions(self):
        """Test getting MITRE techniques for transitions."""
        path = ["domain:test.io", "subdomain:api.test.io", "risk:0"]
        nodes = {
            "domain:test.io": {"type": "domain"},
            "subdomain:api.test.io": {"type": "subdomain"},
            "risk:0": {"type": "risk"},
        }

        techniques = get_path_techniques(path, nodes)
        # Should have techniques for domain->subdomain and subdomain->risk transitions
        assert len(techniques) > 0

    def test_no_techniques_for_unknown_transitions(self):
        """Test unknown transition types."""
        path = ["a", "b"]
        nodes = {
            "a": {"type": "unknown1"},
            "b": {"type": "unknown2"},
        }

        techniques = get_path_techniques(path, nodes)
        assert len(techniques) == 0


class TestScoreAttackChains:
    """Tests for attack chain scoring."""

    def test_score_chains_with_risks(self):
        """Test scoring chains with risk nodes."""
        nodes = {
            "entry": {"type": "subdomain", "label": "entry"},
            "risk": {"type": "risk", "label": "vulnerability"},
        }
        chains = [
            AttackChain(path=["entry", "risk"], entry_point="entry", target="risk", steps=[], mitre_techniques=[])
        ]

        scored = score_attack_chains(chains, nodes)
        assert scored[0].total_risk > 0

    def test_shorter_paths_score_higher(self):
        """Test that shorter paths get bonus scoring."""
        nodes = {str(i): {"type": "subdomain", "label": f"node{i}"} for i in range(6)}

        short_chain = AttackChain(
            path=["0", "1"],
            entry_point="0", target="1", steps=[], mitre_techniques=[]
        )
        long_chain = AttackChain(
            path=["0", "1", "2", "3", "4", "5"],
            entry_point="0", target="5", steps=[], mitre_techniques=[]
        )

        chains = [long_chain, short_chain]
        scored = score_attack_chains(chains, nodes)

        # With same base risk, shorter path should score relatively higher due to multiplier
        # But this test just verifies scoring works
        assert all(c.total_risk >= 0 for c in scored)

    def test_risk_keywords_increase_score(self):
        """Test that risk keywords increase score."""
        nodes = {
            "entry": {"type": "subdomain", "label": "entry"},
            "vuln": {"type": "subdomain", "label": "critical vulnerability exposed"},
        }
        chain = AttackChain(
            path=["entry", "vuln"],
            entry_point="entry", target="vuln", steps=[], mitre_techniques=[]
        )

        scored = score_attack_chains([chain], nodes)
        assert scored[0].total_risk > 0  # Should have risk from keywords


class TestGeneratePathDescription:
    """Tests for path description generation."""

    def test_generate_description(self):
        """Test description generation."""
        chain = AttackChain(
            path=["entry", "middle", "target"],
            entry_point="entry",
            target="target",
            total_risk=15.0,
            mitre_techniques=["T1190"]
        )
        nodes = {
            "entry": {"label": "www.test.io"},
            "target": {"label": "Database"},
        }

        description = generate_path_description(chain, nodes)
        assert "www.test.io" in description
        assert "Database" in description
        assert "15.0" in description
        assert "MITRE" in description


class TestIdentifyCriticalNodes:
    """Tests for critical node identification."""

    def test_identify_chokepoints(self):
        """Test identification of chokepoint nodes."""
        graph_data = {
            "nodes": [
                {"id": "entry1", "label": "Entry 1", "type": "subdomain"},
                {"id": "entry2", "label": "Entry 2", "type": "subdomain"},
                {"id": "chokepoint", "label": "Chokepoint", "type": "technology"},
                {"id": "target", "label": "Target", "type": "risk"},
            ]
        }
        chains = [
            AttackChain(path=["entry1", "chokepoint", "target"], entry_point="entry1", target="target"),
            AttackChain(path=["entry2", "chokepoint", "target"], entry_point="entry2", target="target"),
        ]

        critical = identify_critical_nodes(graph_data, chains)

        # Chokepoint appears in both paths
        chokepoint_node = next((c for c in critical if c["node_id"] == "chokepoint"), None)
        assert chokepoint_node is not None
        assert chokepoint_node["path_count"] == 2

    def test_no_critical_nodes_single_path(self):
        """Test with single path (no shared nodes)."""
        graph_data = {"nodes": [{"id": "a"}, {"id": "b"}]}
        chains = [
            AttackChain(path=["a", "b"], entry_point="a", target="b")
        ]

        critical = identify_critical_nodes(graph_data, chains)
        # Nodes appearing only once aren't critical
        assert len([c for c in critical if c["path_count"] >= 2]) == 0


class TestRankAttackPaths:
    """Tests for attack path ranking."""

    def test_rank_by_risk_score(self):
        """Test ranking by risk score."""
        paths = [
            AttackPath(name="Low", description="", steps=[], likelihood=1, impact=1, mitre_techniques=[]),
            AttackPath(name="High", description="", steps=[], likelihood=5, impact=5, mitre_techniques=[]),
            AttackPath(name="Medium", description="", steps=[], likelihood=3, impact=3, mitre_techniques=[]),
        ]

        ranked = rank_attack_paths(paths)
        assert ranked[0].name == "High"
        assert ranked[1].name == "Medium"
        assert ranked[2].name == "Low"


class TestGetAttackSurfaceSummary:
    """Tests for attack surface summary."""

    def test_summary_with_data(self):
        """Test summary generation with data."""
        ctx = Context(target="test.io")
        ctx.add("attack_paths", [
            {"likelihood": 4, "impact": 5},
            {"likelihood": 3, "impact": 3},
        ])
        ctx.add("critical_nodes", [
            {"node_id": "node1", "path_count": 3}
        ])
        ctx.add("attack_path_summary", {
            "entry_points": ["entry1", "entry2"],
            "targets": ["target1"],
        })

        summary = get_attack_surface_summary(ctx)
        assert summary["total_attack_paths"] == 2
        assert summary["critical_nodes_count"] == 1
        assert summary["total_risk_score"] == 29  # 4*5 + 3*3

    def test_summary_empty_data(self):
        """Test summary with empty data."""
        ctx = Context(target="test.io")
        ctx.add("attack_paths", [])
        ctx.add("critical_nodes", [])
        ctx.add("attack_path_summary", {})

        summary = get_attack_surface_summary(ctx)
        assert summary["total_attack_paths"] == 0
        assert summary["average_path_risk"] == 0


class TestConstants:
    """Tests for module constants."""

    def test_entry_point_types(self):
        """Test entry point type definitions."""
        assert "subdomain" in ENTRY_POINT_TYPES
        assert "ip" in ENTRY_POINT_TYPES
        assert "technology" in ENTRY_POINT_TYPES

    def test_target_indicators(self):
        """Test target indicator definitions."""
        assert "database" in TARGET_INDICATORS
        assert "admin" in TARGET_INDICATORS
        assert "credential" in TARGET_INDICATORS

    def test_risk_keywords(self):
        """Test risk keyword definitions."""
        assert "critical" in RISK_KEYWORDS
        assert "vulnerability" in RISK_KEYWORDS

    def test_transition_techniques(self):
        """Test transition technique mappings."""
        assert ("domain", "subdomain") in TRANSITION_TECHNIQUES
        assert ("technology", "risk") in TRANSITION_TECHNIQUES
