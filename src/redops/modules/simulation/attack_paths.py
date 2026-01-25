"""
Attack path analysis module.

Generates non-intrusive attack path models using graph analysis.
Identifies potential attack chains from entry points to high-value targets.
No exploitation or intrusion - textual analysis only.
"""

from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from collections import defaultdict
from redops.core.context import Context
from redops.core.models import AttackPath, RiskLevel


@dataclass
class AttackNode:
    """Represents a node in an attack path."""

    id: str
    node_type: str
    label: str
    risk_contribution: float = 0.0
    is_entry_point: bool = False
    is_target: bool = False
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Represents a chain of attack steps."""

    path: List[str]
    entry_point: str
    target: str
    total_risk: float = 0.0
    steps: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    def to_attack_path(self, name: str = "", description: str = "") -> AttackPath:
        """Convert to AttackPath model."""
        # Calculate likelihood and impact from risk
        likelihood = min(5, max(1, int(self.total_risk / 5) + 1))
        impact = min(5, max(1, int(self.total_risk / 4) + 1))

        step_descriptions = [
            s.get("description", s.get("action", "")) for s in self.steps
        ]

        return AttackPath(
            name=name or f"Path: {self.entry_point} -> {self.target}",
            description=description
            or f"Attack chain from {self.entry_point} to {self.target}",
            steps=step_descriptions,
            mitre_techniques=self.mitre_techniques,
            likelihood=likelihood,
            impact=impact,
        )


# Entry point indicators
ENTRY_POINT_TYPES = {
    "subdomain": 0.6,
    "ip": 0.5,
    "technology": 0.4,
    "mx": 0.3,
    "ns": 0.2,
}

# High-value target indicators
TARGET_INDICATORS = {
    "database": 1.0,
    "admin": 0.9,
    "api": 0.8,
    "internal": 0.8,
    "auth": 0.7,
    "login": 0.7,
    "payment": 1.0,
    "credential": 1.0,
    "secret": 1.0,
    "key": 0.8,
    "sensitive": 0.9,
}

# Risk keywords for nodes
RISK_KEYWORDS = {
    "critical": 5,
    "high": 4,
    "vulnerability": 4,
    "exposed": 3,
    "misconfigured": 3,
    "outdated": 3,
    "deprecated": 2,
    "warning": 2,
}

# MITRE technique mapping for common node transitions
TRANSITION_TECHNIQUES = {
    ("domain", "subdomain"): ["T1595.002"],  # Active Scanning: Vulnerability Scanning
    ("domain", "ip"): ["T1590.002"],  # Gather Victim Network Information: DNS
    ("subdomain", "ip"): ["T1590.002"],
    ("subdomain", "technology"): [
        "T1592.002"
    ],  # Gather Victim Host Information: Software
    ("ip", "technology"): ["T1592.002"],
    ("technology", "risk"): ["T1190"],  # Exploit Public-Facing Application
    ("technology", "finding"): ["T1190"],
    ("domain", "email"): [
        "T1589.002"
    ],  # Gather Victim Identity Information: Email Addresses
    ("domain", "risk"): ["T1190"],
    ("subdomain", "risk"): ["T1190"],
    ("ip", "risk"): ["T1190"],
}


def analyze_paths(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Analyze potential attack paths from context data.

    Uses graph analysis to identify chains from entry points to high-value targets.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - max_paths: Maximum number of paths to return (default: 10)
            - max_depth: Maximum path depth (default: 6)
            - min_risk_score: Minimum risk score to include path (default: 5)

    Returns:
        Updated context with attack paths
    """
    params = params or {}
    max_paths = params.get("max_paths", 10)
    max_depth = params.get("max_depth", 6)
    min_risk_score = params.get("min_risk_score", 5)

    ctx.log("Analyzing attack paths", level="INFO")

    # Get graph from context
    graph_data = ctx.get("graph", {})
    if not graph_data or not graph_data.get("nodes"):
        ctx.log("No graph data available for attack path analysis", level="WARNING")
        ctx.add("attack_paths", [])
        return ctx

    # Reconstruct graph structure
    nodes = {n["id"]: n for n in graph_data.get("nodes", [])}
    edges = graph_data.get("edges", [])

    # Build adjacency list
    adjacency = defaultdict(list)
    for edge in edges:
        adjacency[edge["source"]].append(edge["target"])

    # Identify entry points and targets
    entry_points = identify_entry_points(nodes, ctx)
    targets = identify_targets(nodes, ctx)

    ctx.log(
        f"Found {len(entry_points)} entry points, {len(targets)} targets", level="DEBUG"
    )

    # Find attack chains
    attack_chains = find_attack_chains(
        nodes, adjacency, entry_points, targets, max_depth
    )

    # Score and rank chains
    scored_chains = score_attack_chains(attack_chains, nodes)

    # Filter by minimum risk
    filtered_chains = [c for c in scored_chains if c.total_risk >= min_risk_score]

    # Convert to AttackPath models
    attack_paths = []
    for i, chain in enumerate(filtered_chains[:max_paths]):
        path = chain.to_attack_path(
            name=f"Attack Path {i + 1}",
            description=generate_path_description(chain, nodes),
        )
        attack_paths.append(path)

    # Identify critical nodes (chokepoints)
    critical_nodes = identify_critical_nodes(graph_data, attack_chains)

    ctx.add("attack_paths", [ap.model_dump() for ap in attack_paths])
    ctx.add(
        "attack_chains_raw",
        [
            {"path": c.path, "risk": c.total_risk, "techniques": c.mitre_techniques}
            for c in filtered_chains[:max_paths]
        ],
    )
    ctx.add("critical_nodes", critical_nodes)
    ctx.add(
        "attack_path_summary",
        {
            "total_paths_found": len(attack_chains),
            "paths_above_threshold": len(filtered_chains),
            "paths_reported": len(attack_paths),
            "entry_points": list(entry_points),
            "targets": list(targets),
            "critical_nodes": critical_nodes[:5],
        },
    )

    ctx.log(f"Identified {len(attack_paths)} potential attack paths", level="INFO")

    return ctx


def identify_entry_points(nodes: Dict[str, Dict], ctx: Context) -> Set[str]:
    """
    Identify potential entry points in the graph.

    Entry points are external-facing assets that could be initial access vectors.

    Args:
        nodes: Graph nodes
        ctx: Pipeline context

    Returns:
        Set of entry point node IDs
    """
    entry_points = set()

    for node_id, node in nodes.items():
        node_type = node.get("type", "")
        label = node.get("label", "").lower()

        # Check node type
        if node_type in ENTRY_POINT_TYPES:
            # Subdomains and IPs are common entry points
            if node_type in ("subdomain", "ip"):
                entry_points.add(node_id)
            # Technologies on external-facing systems
            elif node_type == "technology":
                # Check if it's a web-facing technology
                web_techs = [
                    "nginx",
                    "apache",
                    "iis",
                    "tomcat",
                    "express",
                    "flask",
                    "django",
                ]
                if any(t in label for t in web_techs):
                    entry_points.add(node_id)

        # Check if this is the target domain
        if node.get("data", {}).get("is_target"):
            entry_points.add(node_id)

    # Also check for exposed services
    findings = []
    for key in ctx.data.keys():
        if key.startswith("finding_"):
            finding = ctx.get(key)
            if finding:
                findings.append(finding)

    for finding in findings:
        title = finding.get("title", "").lower()
        if any(kw in title for kw in ["exposed", "public", "open", "external"]):
            # Find associated nodes
            for node_id in nodes:
                if any(part in node_id for part in title.split()):
                    entry_points.add(node_id)

    return entry_points


def identify_targets(nodes: Dict[str, Dict], ctx: Context) -> Set[str]:
    """
    Identify high-value targets in the graph.

    Targets are assets that attackers would want to reach.

    Args:
        nodes: Graph nodes
        ctx: Pipeline context

    Returns:
        Set of target node IDs
    """
    targets = set()

    for node_id, node in nodes.items():
        node_type = node.get("type", "")
        label = node.get("label", "").lower()
        data = node.get("data", {})

        # Risk and finding nodes are targets
        if node_type in ("risk", "finding"):
            severity = data.get("severity", "")
            if severity in ("critical", "high", RiskLevel.CRITICAL, RiskLevel.HIGH):
                targets.add(node_id)
            elif node_type == "risk":
                targets.add(node_id)

        # Check for high-value indicators in label
        for indicator, score in TARGET_INDICATORS.items():
            if indicator in label:
                targets.add(node_id)
                break

        # Email nodes with sensitive domains
        if node_type == "email":
            targets.add(node_id)

        # AWS keys or secrets
        if "aws" in label or "secret" in label or "key" in label:
            targets.add(node_id)

    return targets


def find_attack_chains(
    nodes: Dict[str, Dict],
    adjacency: Dict[str, List[str]],
    entry_points: Set[str],
    targets: Set[str],
    max_depth: int,
) -> List[AttackChain]:
    """
    Find attack chains from entry points to targets using DFS.

    Args:
        nodes: Graph nodes
        adjacency: Adjacency list
        entry_points: Set of entry point node IDs
        targets: Set of target node IDs
        max_depth: Maximum path depth

    Returns:
        List of attack chains
    """
    chains = []

    for entry in entry_points:
        for target in targets:
            if entry == target:
                continue

            # DFS to find paths
            paths = dfs_find_paths(adjacency, entry, target, max_depth)

            for path in paths:
                chain = AttackChain(
                    path=path,
                    entry_point=entry,
                    target=target,
                    steps=generate_steps(path, nodes),
                    mitre_techniques=get_path_techniques(path, nodes),
                )
                chains.append(chain)

    return chains


def dfs_find_paths(
    adjacency: Dict[str, List[str]], start: str, end: str, max_depth: int
) -> List[List[str]]:
    """
    Find all paths between two nodes using DFS.

    Args:
        adjacency: Adjacency list
        start: Starting node
        end: Ending node
        max_depth: Maximum depth

    Returns:
        List of paths
    """
    paths = []

    def dfs(current: str, target: str, path: List[str], depth: int):
        if depth > max_depth:
            return

        if current == target:
            paths.append(path[:])
            return

        for neighbor in adjacency.get(current, []):
            if neighbor not in path:
                path.append(neighbor)
                dfs(neighbor, target, path, depth + 1)
                path.pop()

    dfs(start, end, [start], 0)
    return paths


def generate_steps(path: List[str], nodes: Dict[str, Dict]) -> List[Dict[str, Any]]:
    """
    Generate step descriptions for a path.

    Args:
        path: List of node IDs
        nodes: Graph nodes

    Returns:
        List of step dictionaries
    """
    steps = []

    for i, node_id in enumerate(path):
        node = nodes.get(node_id, {})
        node_type = node.get("type", "unknown")
        label = node.get("label", node_id)

        if i == 0:
            action = f"Initial access via {node_type}: {label}"
        elif i == len(path) - 1:
            action = f"Reach target: {label}"
        else:
            action = f"Traverse to {node_type}: {label}"

        steps.append(
            {
                "node_id": node_id,
                "action": action,
                "description": action,
                "node_type": node_type,
            }
        )

    return steps


def get_path_techniques(path: List[str], nodes: Dict[str, Dict]) -> List[str]:
    """
    Get MITRE techniques for path transitions.

    Args:
        path: List of node IDs
        nodes: Graph nodes

    Returns:
        List of MITRE technique IDs
    """
    techniques = set()

    for i in range(len(path) - 1):
        source_type = nodes.get(path[i], {}).get("type", "")
        target_type = nodes.get(path[i + 1], {}).get("type", "")

        transition = (source_type, target_type)
        if transition in TRANSITION_TECHNIQUES:
            techniques.update(TRANSITION_TECHNIQUES[transition])

    return sorted(techniques)


def score_attack_chains(
    chains: List[AttackChain], nodes: Dict[str, Dict]
) -> List[AttackChain]:
    """
    Score attack chains by risk.

    Args:
        chains: List of attack chains
        nodes: Graph nodes

    Returns:
        Sorted list of scored chains
    """
    for chain in chains:
        risk = 0.0

        for node_id in chain.path:
            node = nodes.get(node_id, {})
            node_type = node.get("type", "")
            label = node.get("label", "").lower()
            data = node.get("data", {})

            # Base risk by node type
            if node_type == "risk":
                risk += 5
            elif node_type == "finding":
                severity = data.get("severity", "")
                if severity in ("critical", RiskLevel.CRITICAL):
                    risk += 5
                elif severity in ("high", RiskLevel.HIGH):
                    risk += 4
                elif severity in ("medium", RiskLevel.MEDIUM):
                    risk += 2
                else:
                    risk += 1

            # Risk keywords in label
            for keyword, score in RISK_KEYWORDS.items():
                if keyword in label:
                    risk += score
                    break

        # Bonus for shorter paths (more likely to be exploited)
        path_length = len(chain.path)
        if path_length <= 3:
            risk *= 1.5
        elif path_length <= 5:
            risk *= 1.2

        # Bonus for more MITRE techniques (more sophisticated attack)
        risk += len(chain.mitre_techniques) * 0.5

        chain.total_risk = risk

    return sorted(chains, key=lambda c: c.total_risk, reverse=True)


def generate_path_description(chain: AttackChain, nodes: Dict[str, Dict]) -> str:
    """
    Generate a description for an attack path.

    Args:
        chain: Attack chain
        nodes: Graph nodes

    Returns:
        Description string
    """
    entry_node = nodes.get(chain.entry_point, {})
    target_node = nodes.get(chain.target, {})

    entry_label = entry_node.get("label", chain.entry_point)
    target_label = target_node.get("label", chain.target)

    description = f"Attack chain starting from {entry_label} "
    description += f"traversing {len(chain.path) - 2} intermediate nodes "
    description += f"to reach {target_label}. "
    description += f"Risk score: {chain.total_risk:.1f}."

    if chain.mitre_techniques:
        description += (
            f" Involves {len(chain.mitre_techniques)} MITRE ATT&CK techniques."
        )

    return description


def identify_critical_nodes(
    graph_data: Dict[str, Any], chains: List[AttackChain]
) -> List[Dict[str, Any]]:
    """
    Identify critical nodes (chokepoints) in attack paths.

    Critical nodes appear on many attack paths and could be
    strategic points for defense.

    Args:
        graph_data: Graph data
        chains: List of attack chains

    Returns:
        List of critical node info
    """
    node_frequency = defaultdict(int)
    node_paths = defaultdict(list)

    for i, chain in enumerate(chains):
        for node_id in chain.path:
            node_frequency[node_id] += 1
            node_paths[node_id].append(i)

    # Find nodes that appear on multiple paths
    critical = []
    nodes = {n["id"]: n for n in graph_data.get("nodes", [])}

    for node_id, freq in sorted(
        node_frequency.items(), key=lambda x: x[1], reverse=True
    ):
        if freq >= 2:  # Appears on at least 2 paths
            node = nodes.get(node_id, {})
            critical.append(
                {
                    "node_id": node_id,
                    "label": node.get("label", node_id),
                    "type": node.get("type", "unknown"),
                    "path_count": freq,
                    "criticality_score": freq * 2 + node.get("degree", 0),
                }
            )

    return critical[:10]


def rank_attack_paths(paths: List[AttackPath]) -> List[AttackPath]:
    """
    Rank attack paths by risk score.

    Args:
        paths: List of attack paths

    Returns:
        Sorted list of attack paths (highest risk first)
    """
    return sorted(paths, key=lambda p: p.risk_score, reverse=True)


def get_attack_surface_summary(ctx: Context) -> Dict[str, Any]:
    """
    Generate a summary of the attack surface.

    Args:
        ctx: Pipeline context

    Returns:
        Attack surface summary
    """
    attack_paths = ctx.get("attack_paths", [])
    critical_nodes = ctx.get("critical_nodes", [])
    summary = ctx.get("attack_path_summary", {})

    total_risk = sum(p.get("likelihood", 0) * p.get("impact", 0) for p in attack_paths)

    return {
        "total_attack_paths": len(attack_paths),
        "critical_nodes_count": len(critical_nodes),
        "total_risk_score": total_risk,
        "average_path_risk": total_risk / len(attack_paths) if attack_paths else 0,
        "entry_points": summary.get("entry_points", []),
        "high_value_targets": summary.get("targets", []),
        "top_critical_nodes": critical_nodes[:3],
    }
