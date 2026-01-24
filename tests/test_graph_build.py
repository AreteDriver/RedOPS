"""Tests for intel/graph_build module."""

import pytest
from redops.modules.intel.graph_build import (
    GraphNode,
    GraphEdge,
    AssetGraph,
    build_graph,
    build_domain_nodes,
    build_subdomain_nodes,
    build_dns_nodes,
    build_tech_nodes,
    build_entity_nodes,
    build_risk_nodes,
    build_finding_nodes,
    find_paths,
    find_shortest_path,
    get_subgraph,
)
from redops.core.context import Context


class TestGraphNode:
    """Tests for GraphNode dataclass."""

    def test_basic_creation(self):
        """Test basic node creation."""
        node = GraphNode(
            id="node1",
            node_type="domain",
            label="example.com"
        )
        assert node.id == "node1"
        assert node.node_type == "domain"
        assert node.label == "example.com"
        assert node.degree == 0

    def test_add_edges(self):
        """Test adding edges to node."""
        node = GraphNode(id="n1", node_type="domain", label="test")
        node.add_edge_to("n2")
        node.add_edge_from("n3")

        assert "n2" in node.edges_out
        assert "n3" in node.edges_in
        assert node.out_degree == 1
        assert node.in_degree == 1
        assert node.degree == 2

    def test_to_dict(self):
        """Test node to dictionary conversion."""
        node = GraphNode(
            id="n1",
            node_type="ip",
            label="8.8.8.8",
            data={"provider": "Google"}
        )
        node.add_edge_to("n2")

        result = node.to_dict()
        assert result["id"] == "n1"
        assert result["type"] == "ip"
        assert result["label"] == "8.8.8.8"
        assert result["data"]["provider"] == "Google"
        assert "n2" in result["edges_out"]
        assert result["degree"] == 1


class TestGraphEdge:
    """Tests for GraphEdge dataclass."""

    def test_basic_creation(self):
        """Test basic edge creation."""
        edge = GraphEdge(
            source="n1",
            target="n2",
            edge_type="resolves_to"
        )
        assert edge.source == "n1"
        assert edge.target == "n2"
        assert edge.edge_type == "resolves_to"
        assert edge.weight == 1.0

    def test_to_dict(self):
        """Test edge to dictionary conversion."""
        edge = GraphEdge(
            source="n1",
            target="n2",
            edge_type="uses",
            weight=0.5,
            data={"info": "test"}
        )
        result = edge.to_dict()

        assert result["source"] == "n1"
        assert result["target"] == "n2"
        assert result["type"] == "uses"
        assert result["weight"] == 0.5
        assert result["data"]["info"] == "test"


class TestAssetGraph:
    """Tests for AssetGraph class."""

    def test_empty_graph(self):
        """Test empty graph initialization."""
        graph = AssetGraph()
        assert graph.node_count() == 0
        assert graph.edge_count() == 0

    def test_add_node(self):
        """Test adding nodes."""
        graph = AssetGraph()
        node = graph.add_node("n1", "domain", label="test.com")

        assert graph.node_count() == 1
        assert node.id == "n1"
        assert graph.get_node("n1") is not None

    def test_add_node_updates_existing(self):
        """Test that adding existing node updates data."""
        graph = AssetGraph()
        graph.add_node("n1", "domain", data={"key1": "value1"})
        graph.add_node("n1", "domain", data={"key2": "value2"})

        node = graph.get_node("n1")
        assert node.data["key1"] == "value1"
        assert node.data["key2"] == "value2"
        assert graph.node_count() == 1

    def test_add_edge(self):
        """Test adding edges."""
        graph = AssetGraph()
        graph.add_node("n1", "domain")
        graph.add_node("n2", "ip")
        edge = graph.add_edge("n1", "n2", "resolves_to")

        assert graph.edge_count() == 1
        assert edge.source == "n1"
        assert edge.target == "n2"

    def test_add_edge_missing_nodes(self):
        """Test that edges fail if nodes don't exist."""
        graph = AssetGraph()
        graph.add_node("n1", "domain")
        edge = graph.add_edge("n1", "n2", "test")

        assert edge is None
        assert graph.edge_count() == 0

    def test_add_duplicate_edge(self):
        """Test that duplicate edges return existing edge."""
        graph = AssetGraph()
        graph.add_node("n1", "domain")
        graph.add_node("n2", "ip")
        edge1 = graph.add_edge("n1", "n2", "test")
        edge2 = graph.add_edge("n1", "n2", "test")

        assert edge1 is edge2
        assert graph.edge_count() == 1

    def test_get_neighbors_out(self):
        """Test getting outgoing neighbors."""
        graph = AssetGraph()
        graph.add_node("n1", "domain")
        graph.add_node("n2", "ip")
        graph.add_node("n3", "ip")
        graph.add_edge("n1", "n2")
        graph.add_edge("n1", "n3")

        neighbors = graph.get_neighbors("n1", "out")
        assert len(neighbors) == 2
        assert "n2" in neighbors
        assert "n3" in neighbors

    def test_get_neighbors_in(self):
        """Test getting incoming neighbors."""
        graph = AssetGraph()
        graph.add_node("n1", "domain")
        graph.add_node("n2", "ip")
        graph.add_node("n3", "mx")
        graph.add_edge("n2", "n1")
        graph.add_edge("n3", "n1")

        neighbors = graph.get_neighbors("n1", "in")
        assert len(neighbors) == 2

    def test_get_neighbors_both(self):
        """Test getting all neighbors."""
        graph = AssetGraph()
        graph.add_node("n1", "domain")
        graph.add_node("n2", "ip")
        graph.add_node("n3", "mx")
        graph.add_edge("n1", "n2")
        graph.add_edge("n3", "n1")

        neighbors = graph.get_neighbors("n1", "both")
        assert len(neighbors) == 2
        assert "n2" in neighbors
        assert "n3" in neighbors

    def test_get_neighbors_missing_node(self):
        """Test getting neighbors for missing node."""
        graph = AssetGraph()
        neighbors = graph.get_neighbors("missing")
        assert neighbors == []

    def test_get_nodes_by_type(self):
        """Test filtering nodes by type."""
        graph = AssetGraph()
        graph.add_node("d1", "domain")
        graph.add_node("d2", "domain")
        graph.add_node("i1", "ip")

        domains = graph.get_nodes_by_type("domain")
        assert len(domains) == 2
        assert all(n.node_type == "domain" for n in domains)

    def test_to_dict(self):
        """Test graph to dictionary conversion."""
        graph = AssetGraph()
        graph.add_node("n1", "domain", label="test.com")
        graph.add_node("n2", "ip", label="1.2.3.4")
        graph.add_edge("n1", "n2", "resolves_to")

        result = graph.to_dict()
        assert len(result["nodes"]) == 2
        assert len(result["edges"]) == 1
        assert result["stats"]["node_count"] == 2
        assert result["stats"]["edge_count"] == 1

    def test_get_node_type_counts(self):
        """Test counting nodes by type."""
        graph = AssetGraph()
        graph.add_node("d1", "domain")
        graph.add_node("d2", "domain")
        graph.add_node("i1", "ip")

        counts = graph.get_node_type_counts()
        assert counts["domain"] == 2
        assert counts["ip"] == 1

    def test_get_edge_type_counts(self):
        """Test counting edges by type."""
        graph = AssetGraph()
        graph.add_node("d1", "domain")
        graph.add_node("i1", "ip")
        graph.add_node("i2", "ip")
        graph.add_edge("d1", "i1", "resolves_to")
        graph.add_edge("d1", "i2", "resolves_to")

        counts = graph.get_edge_type_counts()
        assert counts["resolves_to"] == 2


class TestCentralityMetrics:
    """Tests for centrality calculations."""

    def test_degree_centrality(self):
        """Test degree centrality calculation."""
        graph = AssetGraph()
        graph.add_node("hub", "domain")
        graph.add_node("n1", "ip")
        graph.add_node("n2", "ip")
        graph.add_node("n3", "ip")
        graph.add_edge("hub", "n1")
        graph.add_edge("hub", "n2")
        graph.add_edge("hub", "n3")

        centrality = graph.calculate_degree_centrality()
        # Hub has highest centrality (3 edges / 3 other nodes = 1.0)
        assert centrality["hub"] == 1.0
        # Others have 1 edge each
        assert centrality["n1"] == pytest.approx(1/3)

    def test_degree_centrality_single_node(self):
        """Test centrality with single node."""
        graph = AssetGraph()
        graph.add_node("only", "domain")

        centrality = graph.calculate_degree_centrality()
        assert centrality["only"] == 0.0

    def test_in_degree_centrality(self):
        """Test in-degree centrality."""
        graph = AssetGraph()
        graph.add_node("target", "domain")
        graph.add_node("n1", "ip")
        graph.add_node("n2", "ip")
        graph.add_edge("n1", "target")
        graph.add_edge("n2", "target")

        centrality = graph.calculate_in_degree_centrality()
        # Target has 2 incoming edges
        assert centrality["target"] == 1.0
        assert centrality["n1"] == 0.0

    def test_out_degree_centrality(self):
        """Test out-degree centrality."""
        graph = AssetGraph()
        graph.add_node("source", "domain")
        graph.add_node("n1", "ip")
        graph.add_node("n2", "ip")
        graph.add_edge("source", "n1")
        graph.add_edge("source", "n2")

        centrality = graph.calculate_out_degree_centrality()
        # Source has 2 outgoing edges
        assert centrality["source"] == 1.0
        assert centrality["n1"] == 0.0

    def test_get_most_connected(self):
        """Test getting most connected nodes."""
        graph = AssetGraph()
        graph.add_node("hub", "domain")
        graph.add_node("n1", "ip")
        graph.add_node("n2", "ip")
        graph.add_edge("hub", "n1")
        graph.add_edge("hub", "n2")

        most_connected = graph.get_most_connected(2)
        assert len(most_connected) == 2
        assert most_connected[0][0] == "hub"
        assert most_connected[0][1] == 2


class TestGraphExport:
    """Tests for graph export formats."""

    def test_to_dot(self):
        """Test DOT format export."""
        graph = AssetGraph()
        graph.add_node("d1", "domain", label="test.com")
        graph.add_node("i1", "ip", label="1.2.3.4")
        graph.add_edge("d1", "i1", "resolves_to")

        dot = graph.to_dot()
        assert "digraph AssetGraph" in dot
        assert "d1" in dot
        assert "i1" in dot
        assert "resolves_to" in dot
        assert "lightblue" in dot  # Domain color
        assert "lightyellow" in dot  # IP color

    def test_to_cytoscape(self):
        """Test Cytoscape.js format export."""
        graph = AssetGraph()
        graph.add_node("d1", "domain", label="test.com")
        graph.add_node("i1", "ip", label="1.2.3.4")
        graph.add_edge("d1", "i1", "resolves_to")

        cyto = graph.to_cytoscape()
        assert "elements" in cyto
        elements = cyto["elements"]

        # Should have 2 nodes and 1 edge
        nodes = [e for e in elements if e["group"] == "nodes"]
        edges = [e for e in elements if e["group"] == "edges"]
        assert len(nodes) == 2
        assert len(edges) == 1

        # Check node structure
        node = nodes[0]
        assert "data" in node
        assert "id" in node["data"]
        assert "label" in node["data"]
        assert "type" in node["data"]


class TestBuildGraph:
    """Tests for build_graph function with Context."""

    def test_build_graph_empty_context(self):
        """Test building graph from empty context."""
        ctx = Context(target="test.io")
        result = build_graph(ctx)

        graph = result.get("graph")
        assert graph is not None
        # Should have at least the target domain node
        assert graph["stats"]["node_count"] >= 1

    def test_build_graph_with_subdomains(self):
        """Test building graph with subdomains."""
        ctx = Context(target="test.io")
        ctx.add("subdomains", [
            {"subdomain": "www.test.io", "ip": "1.2.3.4"},
            {"subdomain": "api.test.io", "ip": "1.2.3.5"}
        ])

        result = build_graph(ctx)
        graph = result.get("graph")

        # Should have domain + 2 subdomains + 2 IPs
        assert graph["stats"]["node_count"] >= 5

    def test_build_graph_with_dns(self):
        """Test building graph with DNS records."""
        ctx = Context(target="test.io")
        ctx.add("dns_records", {
            "A": ["1.2.3.4", "1.2.3.5"],
            "MX": ["mail.test.io"],
            "NS": ["ns1.test.io"]
        })

        result = build_graph(ctx)
        graph = result.get("graph")
        assert graph["stats"]["node_count"] >= 5

    def test_build_graph_with_tech_stack(self):
        """Test building graph with technology stack."""
        ctx = Context(target="test.io")
        ctx.add("tech_stack", {
            "technologies": [
                {"name": "nginx", "version": "1.20"},
                {"name": "React"}
            ]
        })

        result = build_graph(ctx)
        graph = result.get("graph")

        tech_nodes = [n for n in graph["nodes"] if n["type"] == "technology"]
        assert len(tech_nodes) >= 2

    def test_build_graph_with_entities(self):
        """Test building graph with extracted entities."""
        ctx = Context(target="test.io")
        ctx.add("entities", {
            "emails": ["admin@test.io"],
            "domains": ["related.io"],
            "ipv4_addresses": ["8.8.8.8"]
        })

        result = build_graph(ctx, {"include_entities": True})
        graph = result.get("graph")

        # Should have email and related domain nodes
        email_nodes = [n for n in graph["nodes"] if n["type"] == "email"]
        assert len(email_nodes) >= 1

    def test_build_graph_with_risks(self):
        """Test building graph with risks."""
        ctx = Context(target="test.io")
        ctx.add("risks", [
            {"title": "SSL Issue", "severity": "high", "score": 15},
            {"title": "Missing Header", "severity": "medium", "score": 8}
        ])

        result = build_graph(ctx, {"include_risks": True})
        graph = result.get("graph")

        risk_nodes = [n for n in graph["nodes"] if n["type"] == "risk"]
        assert len(risk_nodes) == 2

    def test_build_graph_with_findings(self):
        """Test building graph with findings."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {
            "title": "Vulnerability Found",
            "severity": "critical",
            "module": "scanner"
        })

        result = build_graph(ctx, {"include_findings": True})
        graph = result.get("graph")

        finding_nodes = [n for n in graph["nodes"] if n["type"] == "finding"]
        assert len(finding_nodes) == 1

    def test_build_graph_calculates_centrality(self):
        """Test that centrality is calculated."""
        ctx = Context(target="test.io")
        ctx.add("subdomains", [
            {"subdomain": "www.test.io"},
            {"subdomain": "api.test.io"}
        ])

        result = build_graph(ctx)
        assert "graph_centrality" in result.data
        assert "graph_most_connected" in result.data


class TestBuildNodeFunctions:
    """Tests for individual node building functions."""

    def test_build_domain_nodes_with_registrar(self):
        """Test domain node building with registrar."""
        ctx = Context(target="test.io")
        ctx.add("domain_profile", {"registrar": "Example Registrar"})

        graph = AssetGraph()
        graph.add_node("domain:test.io", "domain")
        build_domain_nodes(graph, ctx)

        # Should have registrar node
        assert graph.get_node("registrar:Example Registrar") is not None
        assert graph.edge_count() >= 1

    def test_build_subdomain_nodes_string_format(self):
        """Test subdomain building with string format."""
        ctx = Context(target="test.io")
        ctx.add("subdomains", ["www.test.io", "api.test.io"])

        graph = AssetGraph()
        graph.add_node("domain:test.io", "domain")
        build_subdomain_nodes(graph, ctx)

        assert graph.get_node("subdomain:www.test.io") is not None
        assert graph.get_node("subdomain:api.test.io") is not None

    def test_build_subdomain_nodes_with_ip(self):
        """Test subdomain building with IP associations."""
        ctx = Context(target="test.io")
        ctx.add("subdomains", [{"subdomain": "www.test.io", "ip": "1.2.3.4"}])

        graph = AssetGraph()
        graph.add_node("domain:test.io", "domain")
        build_subdomain_nodes(graph, ctx)

        # Should have IP node
        assert graph.get_node("ip:1.2.3.4") is not None

    def test_build_tech_nodes_string_format(self):
        """Test tech node building with string format."""
        ctx = Context(target="test.io")
        ctx.add("tech_stack", {"technologies": ["nginx", "React"]})

        graph = AssetGraph()
        graph.add_node("domain:test.io", "domain")
        build_tech_nodes(graph, ctx)

        assert graph.get_node("tech:nginx") is not None
        assert graph.get_node("tech:React") is not None


class TestPathFinding:
    """Tests for path finding functions."""

    def test_find_paths_simple(self):
        """Test finding paths in simple graph."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")
        graph.add_node("c", "tech")
        graph.add_edge("a", "b")
        graph.add_edge("b", "c")

        paths = find_paths(graph, "a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_find_paths_multiple(self):
        """Test finding multiple paths."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")
        graph.add_node("c", "ip")
        graph.add_node("d", "tech")
        graph.add_edge("a", "b")
        graph.add_edge("a", "c")
        graph.add_edge("b", "d")
        graph.add_edge("c", "d")

        paths = find_paths(graph, "a", "d")
        assert len(paths) == 2

    def test_find_paths_no_path(self):
        """Test when no path exists."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")

        paths = find_paths(graph, "a", "b")
        assert len(paths) == 0

    def test_find_paths_missing_nodes(self):
        """Test with missing nodes."""
        graph = AssetGraph()
        graph.add_node("a", "domain")

        paths = find_paths(graph, "a", "missing")
        assert paths == []

    def test_find_paths_max_depth(self):
        """Test max depth limiting."""
        graph = AssetGraph()
        for i in range(10):
            graph.add_node(str(i), "node")
        for i in range(9):
            graph.add_edge(str(i), str(i+1))

        # Path of length 10, but max_depth=5
        paths = find_paths(graph, "0", "9", max_depth=5)
        assert len(paths) == 0

    def test_find_shortest_path(self):
        """Test shortest path finding."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")
        graph.add_node("c", "ip")
        graph.add_node("d", "tech")
        # Long path: a -> b -> d
        graph.add_edge("a", "b")
        graph.add_edge("b", "d")
        # Short path: a -> c -> d
        graph.add_edge("a", "c")
        graph.add_edge("c", "d")

        path = find_shortest_path(graph, "a", "d")
        assert path is not None
        assert len(path) == 3

    def test_find_shortest_path_same_node(self):
        """Test shortest path to same node."""
        graph = AssetGraph()
        graph.add_node("a", "domain")

        path = find_shortest_path(graph, "a", "a")
        assert path == ["a"]

    def test_find_shortest_path_no_path(self):
        """Test shortest path when none exists."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")

        path = find_shortest_path(graph, "a", "b")
        assert path is None


class TestSubgraph:
    """Tests for subgraph extraction."""

    def test_get_subgraph(self):
        """Test subgraph extraction."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")
        graph.add_node("c", "ip")
        graph.add_edge("a", "b")
        graph.add_edge("a", "c")
        graph.add_edge("b", "c")

        subgraph = get_subgraph(graph, {"a", "b"})
        assert subgraph.node_count() == 2
        assert subgraph.edge_count() == 1  # Only a->b edge

    def test_get_subgraph_no_edges(self):
        """Test subgraph without edges."""
        graph = AssetGraph()
        graph.add_node("a", "domain")
        graph.add_node("b", "ip")
        graph.add_edge("a", "b")

        subgraph = get_subgraph(graph, {"a", "b"}, include_edges=False)
        assert subgraph.node_count() == 2
        assert subgraph.edge_count() == 0

    def test_get_subgraph_missing_nodes(self):
        """Test subgraph with non-existent nodes."""
        graph = AssetGraph()
        graph.add_node("a", "domain")

        subgraph = get_subgraph(graph, {"a", "missing"})
        assert subgraph.node_count() == 1


class TestEdgeCases:
    """Tests for edge cases."""

    def test_special_characters_in_labels(self):
        """Test handling special characters in labels."""
        graph = AssetGraph()
        node = graph.add_node("test", "domain", label='test "quoted"')

        dot = graph.to_dot()
        # Should escape quotes
        assert '\\"' in dot

    def test_large_graph(self):
        """Test with larger graph."""
        graph = AssetGraph()
        # Add 100 nodes
        for i in range(100):
            graph.add_node(f"n{i}", "node")
        # Add edges
        for i in range(99):
            graph.add_edge(f"n{i}", f"n{i+1}")

        assert graph.node_count() == 100
        assert graph.edge_count() == 99

        # Should still work for exports
        dot = graph.to_dot()
        assert len(dot) > 0

        cyto = graph.to_cytoscape()
        assert len(cyto["elements"]) == 199

    def test_empty_context_data(self):
        """Test with empty context data fields."""
        ctx = Context(target="test.io")
        ctx.add("subdomains", [])
        ctx.add("dns_records", {})
        ctx.add("tech_stack", {"technologies": []})

        result = build_graph(ctx)
        assert result.get("graph") is not None
