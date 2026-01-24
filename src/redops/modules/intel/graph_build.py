"""
Graph building module.

Builds directed graphs of assets, risks, and relationships for attack path analysis.
Supports export to common formats and centrality analysis.
"""

from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from redops.core.context import Context


@dataclass
class GraphNode:
    """Represents a node in the asset/risk graph."""

    id: str
    node_type: str
    label: str
    data: Dict[str, Any] = field(default_factory=dict)
    edges_out: Set[str] = field(default_factory=set)
    edges_in: Set[str] = field(default_factory=set)

    def add_edge_to(self, target_id: str) -> None:
        """Add an outgoing edge to another node."""
        self.edges_out.add(target_id)

    def add_edge_from(self, source_id: str) -> None:
        """Add an incoming edge from another node."""
        self.edges_in.add(source_id)

    @property
    def degree(self) -> int:
        """Total degree (in + out edges)."""
        return len(self.edges_out) + len(self.edges_in)

    @property
    def out_degree(self) -> int:
        """Number of outgoing edges."""
        return len(self.edges_out)

    @property
    def in_degree(self) -> int:
        """Number of incoming edges."""
        return len(self.edges_in)

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
            "data": self.data,
            "edges_out": list(self.edges_out),
            "edges_in": list(self.edges_in),
            "degree": self.degree,
        }


@dataclass
class GraphEdge:
    """Represents an edge in the graph."""

    source: str
    target: str
    edge_type: str
    weight: float = 1.0
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert edge to dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type,
            "weight": self.weight,
            "data": self.data,
        }


class AssetGraph:
    """Directed graph of assets and risks."""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._edge_index: Dict[Tuple[str, str], GraphEdge] = {}

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        """
        Add a node to the graph.

        Args:
            node_id: Unique node identifier
            node_type: Type of node (domain, ip, subdomain, technology, risk, etc.)
            label: Human-readable label
            data: Additional node data

        Returns:
            The created or existing node
        """
        if node_id in self.nodes:
            # Update existing node data
            if data:
                self.nodes[node_id].data.update(data)
            return self.nodes[node_id]

        node = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label or node_id,
            data=data or {},
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str = "relates_to",
        weight: float = 1.0,
        data: Optional[Dict[str, Any]] = None
    ) -> Optional[GraphEdge]:
        """
        Add an edge between two nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of relationship
            weight: Edge weight
            data: Additional edge data

        Returns:
            The created edge or None if nodes don't exist
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        # Check if edge already exists
        edge_key = (source_id, target_id)
        if edge_key in self._edge_index:
            return self._edge_index[edge_key]

        edge = GraphEdge(
            source=source_id,
            target=target_id,
            edge_type=edge_type,
            weight=weight,
            data=data or {},
        )
        self.edges.append(edge)
        self._edge_index[edge_key] = edge

        # Update node edge sets
        self.nodes[source_id].add_edge_to(target_id)
        self.nodes[target_id].add_edge_from(source_id)

        return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str, direction: str = "out") -> List[str]:
        """
        Get neighboring node IDs.

        Args:
            node_id: Node to get neighbors for
            direction: "out" for outgoing, "in" for incoming, "both" for all

        Returns:
            List of neighbor node IDs
        """
        node = self.nodes.get(node_id)
        if not node:
            return []

        if direction == "out":
            return list(node.edges_out)
        elif direction == "in":
            return list(node.edges_in)
        else:
            return list(node.edges_out | node.edges_in)

    def get_nodes_by_type(self, node_type: str) -> List[GraphNode]:
        """Get all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def node_count(self) -> int:
        """Get number of nodes."""
        return len(self.nodes)

    def edge_count(self) -> int:
        """Get number of edges."""
        return len(self.edges)

    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary representation."""
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges],
            "stats": {
                "node_count": self.node_count(),
                "edge_count": self.edge_count(),
                "node_types": self.get_node_type_counts(),
                "edge_types": self.get_edge_type_counts(),
            },
        }

    def get_node_type_counts(self) -> Dict[str, int]:
        """Count nodes by type."""
        counts: Dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            counts[node.node_type] += 1
        return dict(counts)

    def get_edge_type_counts(self) -> Dict[str, int]:
        """Count edges by type."""
        counts: Dict[str, int] = defaultdict(int)
        for edge in self.edges:
            counts[edge.edge_type] += 1
        return dict(counts)

    def calculate_degree_centrality(self) -> Dict[str, float]:
        """
        Calculate degree centrality for all nodes.

        Returns:
            Dictionary of node_id -> centrality score
        """
        n = len(self.nodes)
        if n <= 1:
            return {node_id: 0.0 for node_id in self.nodes}

        return {
            node_id: node.degree / (n - 1)
            for node_id, node in self.nodes.items()
        }

    def calculate_in_degree_centrality(self) -> Dict[str, float]:
        """Calculate in-degree centrality (nodes that are pointed to)."""
        n = len(self.nodes)
        if n <= 1:
            return {node_id: 0.0 for node_id in self.nodes}

        return {
            node_id: node.in_degree / (n - 1)
            for node_id, node in self.nodes.items()
        }

    def calculate_out_degree_centrality(self) -> Dict[str, float]:
        """Calculate out-degree centrality (nodes that point to others)."""
        n = len(self.nodes)
        if n <= 1:
            return {node_id: 0.0 for node_id in self.nodes}

        return {
            node_id: node.out_degree / (n - 1)
            for node_id, node in self.nodes.items()
        }

    def get_most_connected(self, n: int = 10) -> List[Tuple[str, int]]:
        """
        Get the n most connected nodes.

        Args:
            n: Number of nodes to return

        Returns:
            List of (node_id, degree) tuples sorted by degree
        """
        sorted_nodes = sorted(
            self.nodes.items(),
            key=lambda x: x[1].degree,
            reverse=True
        )
        return [(node_id, node.degree) for node_id, node in sorted_nodes[:n]]

    def to_dot(self) -> str:
        """
        Export graph to DOT format for Graphviz.

        Returns:
            DOT format string
        """
        lines = ["digraph AssetGraph {"]
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box];")

        # Add nodes with type-based styling
        type_colors = {
            "domain": "lightblue",
            "subdomain": "lightcyan",
            "ip": "lightyellow",
            "technology": "lightgreen",
            "risk": "lightcoral",
            "finding": "lightsalmon",
            "email": "lavender",
        }

        for node in self.nodes.values():
            color = type_colors.get(node.node_type, "white")
            label = node.label.replace('"', '\\"')
            lines.append(f'  "{node.id}" [label="{label}" fillcolor="{color}" style="filled"];')

        # Add edges
        for edge in self.edges:
            lines.append(f'  "{edge.source}" -> "{edge.target}" [label="{edge.edge_type}"];')

        lines.append("}")
        return "\n".join(lines)

    def to_cytoscape(self) -> Dict[str, Any]:
        """
        Export graph to Cytoscape.js format.

        Returns:
            Cytoscape.js compatible dictionary
        """
        elements = []

        for node in self.nodes.values():
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.node_type,
                    **node.data,
                },
                "group": "nodes",
            })

        for edge in self.edges:
            elements.append({
                "data": {
                    "id": f"{edge.source}->{edge.target}",
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.edge_type,
                    "weight": edge.weight,
                },
                "group": "edges",
            })

        return {"elements": elements}


def build_graph(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Build a graph from context data.

    Creates a directed graph of assets, risks, and their relationships
    based on data collected during reconnaissance.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - include_risks: Include risk nodes (default: True)
            - include_findings: Include finding nodes (default: True)
            - include_entities: Include extracted entities (default: True)

    Returns:
        Updated context with graph data
    """
    params = params or {}
    include_risks = params.get("include_risks", True)
    include_findings = params.get("include_findings", True)
    include_entities = params.get("include_entities", True)

    ctx.log("Building asset/risk graph", level="INFO")

    graph = AssetGraph()

    # Add target domain as root node
    if ctx.target:
        graph.add_node(
            f"domain:{ctx.target}",
            "domain",
            label=ctx.target,
            data={"is_target": True}
        )

    # Build nodes from domain profile
    build_domain_nodes(graph, ctx)

    # Build nodes from subdomains
    build_subdomain_nodes(graph, ctx)

    # Build nodes from DNS records
    build_dns_nodes(graph, ctx)

    # Build nodes from tech stack
    build_tech_nodes(graph, ctx)

    # Build nodes from extracted entities
    if include_entities:
        build_entity_nodes(graph, ctx)

    # Build nodes from risks
    if include_risks:
        build_risk_nodes(graph, ctx)

    # Build nodes from findings
    if include_findings:
        build_finding_nodes(graph, ctx)

    # Calculate centrality metrics
    centrality = graph.calculate_degree_centrality()
    most_connected = graph.get_most_connected(10)

    # Add to context
    ctx.add("graph", graph.to_dict())
    ctx.add("graph_centrality", centrality)
    ctx.add("graph_most_connected", most_connected)

    ctx.log(f"Graph built: {graph.node_count()} nodes, {graph.edge_count()} edges", level="INFO")

    return ctx


def build_domain_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from domain profile."""
    domain_profile = ctx.get("domain_profile")
    if not domain_profile:
        return

    target = ctx.target
    if not target:
        return

    domain_node_id = f"domain:{target}"

    # Add registrar info if available
    if domain_profile.get("registrar"):
        registrar_id = f"registrar:{domain_profile['registrar']}"
        graph.add_node(registrar_id, "registrar", label=domain_profile["registrar"])
        graph.add_edge(domain_node_id, registrar_id, "registered_with")


def build_subdomain_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from discovered subdomains."""
    subdomains = ctx.get("subdomains")
    if not subdomains or not isinstance(subdomains, list):
        return

    target = ctx.target
    domain_node_id = f"domain:{target}" if target else None

    for sub in subdomains:
        if isinstance(sub, dict):
            subdomain = sub.get("subdomain", "")
        else:
            subdomain = str(sub)

        if not subdomain:
            continue

        sub_node_id = f"subdomain:{subdomain}"
        graph.add_node(sub_node_id, "subdomain", label=subdomain)

        # Connect to main domain
        if domain_node_id and domain_node_id in graph.nodes:
            graph.add_edge(domain_node_id, sub_node_id, "has_subdomain")

        # Add IP associations if available
        if isinstance(sub, dict) and sub.get("ip"):
            ip = sub["ip"]
            ip_node_id = f"ip:{ip}"
            graph.add_node(ip_node_id, "ip", label=ip)
            graph.add_edge(sub_node_id, ip_node_id, "resolves_to")


def build_dns_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from DNS records."""
    dns_records = ctx.get("dns_records")
    if not dns_records or not isinstance(dns_records, dict):
        return

    target = ctx.target
    domain_node_id = f"domain:{target}" if target else None

    # A records (IPv4)
    for ip in dns_records.get("A", []):
        ip_node_id = f"ip:{ip}"
        graph.add_node(ip_node_id, "ip", label=ip, data={"record_type": "A"})
        if domain_node_id:
            graph.add_edge(domain_node_id, ip_node_id, "resolves_to")

    # AAAA records (IPv6)
    for ip in dns_records.get("AAAA", []):
        ip_node_id = f"ip:{ip}"
        graph.add_node(ip_node_id, "ip", label=ip, data={"record_type": "AAAA"})
        if domain_node_id:
            graph.add_edge(domain_node_id, ip_node_id, "resolves_to")

    # MX records
    for mx in dns_records.get("MX", []):
        if isinstance(mx, dict):
            mx_host = mx.get("host", str(mx))
        else:
            mx_host = str(mx)

        mx_node_id = f"mx:{mx_host}"
        graph.add_node(mx_node_id, "mx", label=mx_host)
        if domain_node_id:
            graph.add_edge(domain_node_id, mx_node_id, "mail_handled_by")

    # NS records
    for ns in dns_records.get("NS", []):
        ns_node_id = f"ns:{ns}"
        graph.add_node(ns_node_id, "ns", label=ns)
        if domain_node_id:
            graph.add_edge(domain_node_id, ns_node_id, "nameserver")


def build_tech_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from technology stack."""
    tech_stack = ctx.get("tech_stack")
    if not tech_stack or not isinstance(tech_stack, dict):
        return

    target = ctx.target
    domain_node_id = f"domain:{target}" if target else None

    technologies = tech_stack.get("technologies", [])
    for tech in technologies:
        if isinstance(tech, dict):
            tech_name = tech.get("name", str(tech))
            tech_version = tech.get("version")
        else:
            tech_name = str(tech)
            tech_version = None

        tech_id = f"tech:{tech_name}"
        label = f"{tech_name} {tech_version}" if tech_version else tech_name
        graph.add_node(tech_id, "technology", label=label, data={"version": tech_version})

        if domain_node_id:
            graph.add_edge(domain_node_id, tech_id, "uses_technology")


def build_entity_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from extracted entities."""
    entities = ctx.get("entities")
    if not entities or not isinstance(entities, dict):
        return

    target = ctx.target
    domain_node_id = f"domain:{target}" if target else None

    # Add email nodes
    for email in entities.get("emails", []):
        email_id = f"email:{email}"
        graph.add_node(email_id, "email", label=email)
        if domain_node_id:
            graph.add_edge(domain_node_id, email_id, "associated_email")

    # Add discovered domains
    for domain in entities.get("domains", []):
        ext_domain_id = f"domain:{domain}"
        if ext_domain_id not in graph.nodes:
            graph.add_node(ext_domain_id, "domain", label=domain, data={"discovered": True})
            if domain_node_id and domain_node_id != ext_domain_id:
                graph.add_edge(domain_node_id, ext_domain_id, "references")

    # Add IP addresses
    for ip in entities.get("ipv4_addresses", []):
        ip_id = f"ip:{ip}"
        if ip_id not in graph.nodes:
            graph.add_node(ip_id, "ip", label=ip, data={"discovered": True})


def build_risk_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from risks."""
    risks = ctx.get("risks")
    if not risks or not isinstance(risks, list):
        return

    target = ctx.target
    domain_node_id = f"domain:{target}" if target else None

    for i, risk in enumerate(risks):
        if isinstance(risk, dict):
            risk_id = f"risk:{i}"
            title = risk.get("title", f"Risk {i}")
            severity = risk.get("severity", risk.get("level", "unknown"))

            graph.add_node(
                risk_id,
                "risk",
                label=title[:50],
                data={
                    "severity": severity,
                    "full_title": title,
                    "score": risk.get("score"),
                }
            )

            if domain_node_id:
                graph.add_edge(domain_node_id, risk_id, "has_risk")


def build_finding_nodes(graph: AssetGraph, ctx: Context) -> None:
    """Build nodes from findings."""
    target = ctx.target
    domain_node_id = f"domain:{target}" if target else None

    for key in ctx.data.keys():
        if key.startswith("finding_"):
            finding = ctx.get(key)
            if not isinstance(finding, dict):
                continue

            finding_id = f"finding:{key}"
            title = finding.get("title", key)
            severity = finding.get("severity", "unknown")

            graph.add_node(
                finding_id,
                "finding",
                label=title[:50],
                data={
                    "severity": severity,
                    "full_title": title,
                    "module": finding.get("module"),
                }
            )

            if domain_node_id:
                graph.add_edge(domain_node_id, finding_id, "has_finding")


def find_paths(
    graph: AssetGraph,
    start_id: str,
    end_id: str,
    max_depth: int = 5
) -> List[List[str]]:
    """
    Find all paths between two nodes using DFS.

    Args:
        graph: The asset graph
        start_id: Starting node ID
        end_id: Ending node ID
        max_depth: Maximum path depth

    Returns:
        List of paths (each path is a list of node IDs)
    """
    if start_id not in graph.nodes or end_id not in graph.nodes:
        return []

    paths: List[List[str]] = []

    def dfs(current: str, target: str, path: List[str], depth: int) -> None:
        if depth > max_depth:
            return

        if current == target:
            paths.append(path[:])
            return

        node = graph.get_node(current)
        if not node:
            return

        for neighbor in node.edges_out:
            if neighbor not in path:
                path.append(neighbor)
                dfs(neighbor, target, path, depth + 1)
                path.pop()

    dfs(start_id, end_id, [start_id], 0)
    return paths


def find_shortest_path(
    graph: AssetGraph,
    start_id: str,
    end_id: str
) -> Optional[List[str]]:
    """
    Find shortest path between two nodes using BFS.

    Args:
        graph: The asset graph
        start_id: Starting node ID
        end_id: Ending node ID

    Returns:
        Shortest path as list of node IDs, or None if no path exists
    """
    if start_id not in graph.nodes or end_id not in graph.nodes:
        return None

    if start_id == end_id:
        return [start_id]

    visited = {start_id}
    queue = [[start_id]]

    while queue:
        path = queue.pop(0)
        current = path[-1]

        node = graph.get_node(current)
        if not node:
            continue

        for neighbor in node.edges_out:
            if neighbor == end_id:
                return path + [neighbor]

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])

    return None


def get_subgraph(
    graph: AssetGraph,
    node_ids: Set[str],
    include_edges: bool = True
) -> AssetGraph:
    """
    Extract a subgraph containing only specified nodes.

    Args:
        graph: Source graph
        node_ids: Set of node IDs to include
        include_edges: Include edges between selected nodes

    Returns:
        New AssetGraph with selected nodes
    """
    subgraph = AssetGraph()

    for node_id in node_ids:
        node = graph.get_node(node_id)
        if node:
            subgraph.add_node(node_id, node.node_type, node.label, node.data.copy())

    if include_edges:
        for edge in graph.edges:
            if edge.source in node_ids and edge.target in node_ids:
                subgraph.add_edge(
                    edge.source,
                    edge.target,
                    edge.edge_type,
                    edge.weight,
                    edge.data.copy()
                )

    return subgraph
