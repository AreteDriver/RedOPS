"""
Graph building module.

Builds directed graphs of assets, risks, and relationships for attack path analysis.
"""

from typing import Optional, Dict, Any, List, Tuple
from redops.core.context import Context


class GraphNode:
    """Represents a node in the asset/risk graph."""
    
    def __init__(self, node_id: str, node_type: str, data: Dict[str, Any]):
        self.id = node_id
        self.type = node_type
        self.data = data
        self.edges: List[str] = []
    
    def add_edge(self, target_id: str):
        """Add an edge to another node."""
        if target_id not in self.edges:
            self.edges.append(target_id)


class AssetGraph:
    """Directed graph of assets and risks."""
    
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
    
    def add_node(self, node_id: str, node_type: str, data: Dict[str, Any]) -> GraphNode:
        """Add a node to the graph."""
        node = GraphNode(node_id, node_type, data)
        self.nodes[node_id] = node
        return node
    
    def add_edge(self, source_id: str, target_id: str):
        """Add an edge between two nodes."""
        if source_id in self.nodes:
            self.nodes[source_id].add_edge(target_id)
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert graph to dictionary representation."""
        return {
            "nodes": {
                node_id: {
                    "type": node.type,
                    "data": node.data,
                    "edges": node.edges
                }
                for node_id, node in self.nodes.items()
            }
        }


def build_graph(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Build a graph from context data.
    
    Creates a directed graph of:
    - Assets
    - Risks
    - Relationships
    
    Args:
        ctx: Pipeline context
        params: Optional parameters
        
    Returns:
        Updated context
    """
    params = params or {}
    
    ctx.log("Building asset/risk graph", level="INFO")
    
    graph = AssetGraph()
    
    # Extract assets from context
    assets = ctx.get("assets", [])
    for i, asset in enumerate(assets):
        node_id = f"asset_{i}"
        graph.add_node(node_id, "asset", asset)
    
    # Extract risks from context
    risks = ctx.get("risks", [])
    for i, risk in enumerate(risks):
        node_id = f"risk_{i}"
        graph.add_node(node_id, "risk", risk)
    
    # Create relationships
    # Placeholder: Real implementation would infer relationships
    
    ctx.add("graph", graph.to_dict())
    ctx.log(f"Graph built with {len(graph.nodes)} nodes", level="INFO")
    
    return ctx


def find_paths(graph: AssetGraph, start_id: str, end_id: str, max_depth: int = 5) -> List[List[str]]:
    """
    Find all paths between two nodes.
    
    Args:
        graph: The asset graph
        start_id: Starting node ID
        end_id: Ending node ID
        max_depth: Maximum path depth
        
    Returns:
        List of paths (each path is a list of node IDs)
    """
    paths = []
    
    def dfs(current: str, target: str, path: List[str], depth: int):
        if depth > max_depth:
            return
        
        if current == target:
            paths.append(path[:])
            return
        
        node = graph.get_node(current)
        if not node:
            return
        
        for edge in node.edges:
            if edge not in path:
                path.append(edge)
                dfs(edge, target, path, depth + 1)
                path.pop()
    
    dfs(start_id, end_id, [start_id], 0)
    return paths
