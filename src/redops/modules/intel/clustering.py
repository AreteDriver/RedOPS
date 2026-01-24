"""
Clustering module for pattern recognition and grouping.

Groups similar findings, artifacts, and data points using lightweight
algorithms that don't require heavy ML dependencies.
"""

from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from redops.core.context import Context


@dataclass
class Cluster:
    """Represents a cluster of similar items."""

    id: int
    label: str
    items: List[int] = field(default_factory=list)
    centroid: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_item(self, item_idx: int) -> None:
        """Add an item index to the cluster."""
        if item_idx not in self.items:
            self.items.append(item_idx)

    @property
    def size(self) -> int:
        """Number of items in cluster."""
        return len(self.items)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "label": self.label,
            "size": self.size,
            "items": self.items,
            "centroid": self.centroid,
            "metadata": self.metadata,
        }


def cluster_findings(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Cluster findings and patterns in the context data.

    Groups findings by severity, category, and similarity.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - min_cluster_size: Minimum items per cluster (default: 2)
            - similarity_threshold: Threshold for text similarity (default: 0.3)

    Returns:
        Updated context with clustering results
    """
    params = params or {}
    min_cluster_size = params.get("min_cluster_size", 2)
    similarity_threshold = params.get("similarity_threshold", 0.3)

    ctx.log("Clustering findings and patterns", level="INFO")

    results = {
        "severity_clusters": [],
        "category_clusters": [],
        "similarity_clusters": [],
        "temporal_clusters": [],
        "technology_clusters": [],
    }

    # Collect all findings
    findings = collect_findings(ctx)

    if findings:
        # Cluster by severity
        severity_clusters = cluster_by_attribute(findings, "severity")
        results["severity_clusters"] = [c.to_dict() for c in severity_clusters]

        # Cluster by module/category
        category_clusters = cluster_by_attribute(findings, "module")
        results["category_clusters"] = [c.to_dict() for c in category_clusters]

        # Cluster by text similarity
        if len(findings) >= min_cluster_size:
            similarity_clusters = cluster_by_text_similarity(
                findings,
                threshold=similarity_threshold,
                min_cluster_size=min_cluster_size
            )
            results["similarity_clusters"] = [c.to_dict() for c in similarity_clusters]

    # Cluster technologies
    tech_stack = ctx.get("tech_stack")
    if tech_stack and isinstance(tech_stack, dict):
        technologies = tech_stack.get("technologies", [])
        if technologies:
            tech_clusters = cluster_technologies(technologies)
            results["technology_clusters"] = [c.to_dict() for c in tech_clusters]

    # Cluster risks by score
    risks = ctx.get("risks")
    if risks and isinstance(risks, list):
        risk_clusters = cluster_risks_by_score(risks)
        results["risk_clusters"] = [c.to_dict() for c in risk_clusters]

    ctx.add("clusters", results)

    # Add summary
    total_clusters = sum(len(v) for v in results.values())
    ctx.add("cluster_summary", {
        "total_clusters": total_clusters,
        "by_type": {k: len(v) for k, v in results.items()},
        "findings_clustered": len(findings),
    })

    ctx.log(f"Clustering completed: {total_clusters} clusters created", level="INFO")

    return ctx


def collect_findings(ctx: Context) -> List[Dict[str, Any]]:
    """
    Collect all findings from context.

    Args:
        ctx: Pipeline context

    Returns:
        List of finding dictionaries
    """
    findings = []

    for key in ctx.data.keys():
        if key.startswith("finding_"):
            finding = ctx.get(key)
            if isinstance(finding, dict):
                finding["_key"] = key
                findings.append(finding)

    return findings


def cluster_by_attribute(
    items: List[Dict[str, Any]],
    attribute: str
) -> List[Cluster]:
    """
    Cluster items by a specific attribute value.

    Args:
        items: List of items to cluster
        attribute: Attribute name to cluster by

    Returns:
        List of clusters
    """
    # Group by attribute value
    groups: Dict[str, List[int]] = defaultdict(list)

    for idx, item in enumerate(items):
        value = item.get(attribute, "unknown")
        if isinstance(value, (list, dict)):
            value = str(value)
        groups[str(value)].append(idx)

    # Create clusters
    clusters = []
    for cluster_id, (value, indices) in enumerate(groups.items()):
        cluster = Cluster(
            id=cluster_id,
            label=f"{attribute}:{value}",
            items=indices,
            metadata={"attribute": attribute, "value": value}
        )
        clusters.append(cluster)

    return clusters


def cluster_by_text_similarity(
    items: List[Dict[str, Any]],
    threshold: float = 0.3,
    min_cluster_size: int = 2
) -> List[Cluster]:
    """
    Cluster items by text similarity using Jaccard similarity.

    Args:
        items: List of items to cluster
        threshold: Similarity threshold (0-1)
        min_cluster_size: Minimum items per cluster

    Returns:
        List of similarity clusters
    """
    n = len(items)
    if n < min_cluster_size:
        return []

    # Extract text content from items
    texts = []
    for item in items:
        text_parts = []
        for key in ["title", "description", "message"]:
            if key in item and item[key]:
                text_parts.append(str(item[key]))
        texts.append(" ".join(text_parts).lower())

    # Convert to word sets
    word_sets = [set(text.split()) for text in texts]

    # Build similarity matrix and find clusters using single-linkage
    visited = set()
    clusters = []
    cluster_id = 0

    for i in range(n):
        if i in visited:
            continue

        # Start a new cluster
        cluster_items = [i]
        visited.add(i)

        # Find all similar items
        queue = [i]
        while queue:
            current = queue.pop(0)
            for j in range(n):
                if j not in visited:
                    sim = jaccard_similarity(word_sets[current], word_sets[j])
                    if sim >= threshold:
                        cluster_items.append(j)
                        visited.add(j)
                        queue.append(j)

        if len(cluster_items) >= min_cluster_size:
            # Find common words as cluster label
            common_words = word_sets[cluster_items[0]]
            for idx in cluster_items[1:]:
                common_words &= word_sets[idx]

            label = " ".join(sorted(common_words)[:5]) if common_words else f"cluster_{cluster_id}"

            cluster = Cluster(
                id=cluster_id,
                label=label,
                items=cluster_items,
                metadata={"similarity_threshold": threshold}
            )
            clusters.append(cluster)
            cluster_id += 1

    return clusters


def cluster_technologies(technologies: List[Any]) -> List[Cluster]:
    """
    Cluster technologies by category.

    Args:
        technologies: List of technology items

    Returns:
        List of technology clusters
    """
    # Define technology categories
    categories = {
        "frontend": {"react", "vue", "angular", "svelte", "jquery", "bootstrap", "tailwind"},
        "backend": {"django", "flask", "express", "rails", "spring", "laravel", "fastapi"},
        "database": {"mysql", "postgresql", "mongodb", "redis", "elasticsearch", "sqlite"},
        "server": {"nginx", "apache", "iis", "tomcat", "gunicorn", "uwsgi"},
        "cms": {"wordpress", "drupal", "joomla", "shopify", "magento", "wix"},
        "cloud": {"aws", "azure", "gcp", "cloudflare", "heroku", "vercel"},
        "security": {"waf", "firewall", "ssl", "tls", "oauth", "jwt"},
        "analytics": {"google analytics", "gtm", "hotjar", "mixpanel", "segment"},
    }

    # Classify each technology
    classified: Dict[str, List[int]] = defaultdict(list)

    for idx, tech in enumerate(technologies):
        if isinstance(tech, dict):
            tech_name = tech.get("name", "").lower()
        else:
            tech_name = str(tech).lower()

        categorized = False
        for category, keywords in categories.items():
            if any(kw in tech_name for kw in keywords):
                classified[category].append(idx)
                categorized = True
                break

        if not categorized:
            classified["other"].append(idx)

    # Create clusters
    clusters = []
    for cluster_id, (category, indices) in enumerate(classified.items()):
        if indices:
            cluster = Cluster(
                id=cluster_id,
                label=f"tech:{category}",
                items=indices,
                metadata={"category": category}
            )
            clusters.append(cluster)

    return clusters


def cluster_risks_by_score(risks: List[Dict[str, Any]]) -> List[Cluster]:
    """
    Cluster risks by score ranges.

    Args:
        risks: List of risk dictionaries

    Returns:
        List of risk clusters by severity
    """
    # Define score ranges
    ranges = [
        ("critical", 20, 26),
        ("high", 12, 20),
        ("medium", 6, 12),
        ("low", 3, 6),
        ("info", 0, 3),
    ]

    clusters = []
    cluster_id = 0

    for label, min_score, max_score in ranges:
        items = []
        for idx, risk in enumerate(risks):
            score = risk.get("score", 0)
            if isinstance(score, (int, float)) and min_score <= score < max_score:
                items.append(idx)

        if items:
            cluster = Cluster(
                id=cluster_id,
                label=f"risk:{label}",
                items=items,
                metadata={"score_range": f"{min_score}-{max_score}"}
            )
            clusters.append(cluster)
            cluster_id += 1

    return clusters


def jaccard_similarity(set1: Set[str], set2: Set[str]) -> float:
    """
    Calculate Jaccard similarity between two sets.

    Args:
        set1: First set
        set2: Second set

    Returns:
        Similarity score (0-1)
    """
    if not set1 or not set2:
        return 0.0

    intersection = len(set1 & set2)
    union = len(set1 | set2)

    return intersection / union if union > 0 else 0.0


def cosine_similarity_text(text1: str, text2: str) -> float:
    """
    Calculate cosine similarity between two text strings.

    Uses word frequency vectors.

    Args:
        text1: First text
        text2: Second text

    Returns:
        Similarity score (0-1)
    """
    # Tokenize
    words1 = text1.lower().split()
    words2 = text2.lower().split()

    # Build frequency vectors
    all_words = set(words1) | set(words2)

    if not all_words:
        return 0.0

    vec1 = [words1.count(w) for w in all_words]
    vec2 = [words2.count(w) for w in all_words]

    # Calculate cosine similarity
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    magnitude1 = sum(a * a for a in vec1) ** 0.5
    magnitude2 = sum(b * b for b in vec2) ** 0.5

    if magnitude1 == 0 or magnitude2 == 0:
        return 0.0

    return dot_product / (magnitude1 * magnitude2)


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate Levenshtein (edit) distance between two strings.

    Args:
        s1: First string
        s2: Second string

    Returns:
        Edit distance (number of operations)
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)

    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def levenshtein_similarity(s1: str, s2: str) -> float:
    """
    Calculate normalized Levenshtein similarity.

    Args:
        s1: First string
        s2: Second string

    Returns:
        Similarity score (0-1)
    """
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0

    distance = levenshtein_distance(s1, s2)
    return 1 - (distance / max_len)


def cluster_by_similarity(
    items: List[Dict[str, Any]],
    similarity_func: str = "jaccard",
    threshold: float = 0.5,
    text_key: str = "title"
) -> List[List[int]]:
    """
    Cluster items by similarity using specified function.

    Args:
        items: List of items to cluster
        similarity_func: "jaccard", "cosine", or "levenshtein"
        threshold: Similarity threshold
        text_key: Key to extract text from items

    Returns:
        List of clusters (each cluster is a list of item indices)
    """
    n = len(items)
    if n < 2:
        return [[i] for i in range(n)]

    # Extract text
    texts = []
    for item in items:
        if isinstance(item, dict):
            texts.append(str(item.get(text_key, "")))
        else:
            texts.append(str(item))

    # Select similarity function
    if similarity_func == "cosine":
        sim_func = cosine_similarity_text
    elif similarity_func == "levenshtein":
        sim_func = levenshtein_similarity
    else:
        # Default to jaccard
        def sim_func(a: str, b: str) -> float:
            return jaccard_similarity(set(a.lower().split()), set(b.lower().split()))

    # Build clusters using union-find approach
    parent = list(range(n))

    def find(x: int) -> int:
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(x: int, y: int) -> None:
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    # Compute similarities and union similar items
    for i in range(n):
        for j in range(i + 1, n):
            sim = sim_func(texts[i], texts[j])
            if sim >= threshold:
                union(i, j)

    # Group by cluster
    clusters_dict: Dict[int, List[int]] = defaultdict(list)
    for i in range(n):
        clusters_dict[find(i)].append(i)

    return list(clusters_dict.values())


def calculate_silhouette_score(
    items: List[Dict[str, Any]],
    clusters: List[List[int]],
    similarity_func=None
) -> float:
    """
    Calculate silhouette score for clustering quality.

    Higher scores indicate better-defined clusters.

    Args:
        items: Original items
        clusters: List of clusters (each is list of indices)
        similarity_func: Function to calculate similarity

    Returns:
        Silhouette score (-1 to 1)
    """
    if len(clusters) < 2:
        return 0.0

    n = len(items)
    if n < 2:
        return 0.0

    # Default similarity function
    if similarity_func is None:
        def similarity_func(i1: Dict, i2: Dict) -> float:
            t1 = str(i1.get("title", ""))
            t2 = str(i2.get("title", ""))
            return jaccard_similarity(set(t1.lower().split()), set(t2.lower().split()))

    # Build cluster membership
    cluster_of = {}
    for cluster_idx, cluster in enumerate(clusters):
        for item_idx in cluster:
            cluster_of[item_idx] = cluster_idx

    silhouette_scores = []

    for i in range(n):
        if i not in cluster_of:
            continue

        my_cluster = cluster_of[i]
        my_cluster_items = clusters[my_cluster]

        # Calculate a(i): average distance to items in same cluster
        if len(my_cluster_items) > 1:
            a_i = sum(
                1 - similarity_func(items[i], items[j])
                for j in my_cluster_items if j != i
            ) / (len(my_cluster_items) - 1)
        else:
            a_i = 0

        # Calculate b(i): minimum average distance to items in other clusters
        b_i = float('inf')
        for cluster_idx, cluster in enumerate(clusters):
            if cluster_idx != my_cluster and len(cluster) > 0:
                avg_dist = sum(
                    1 - similarity_func(items[i], items[j])
                    for j in cluster
                ) / len(cluster)
                b_i = min(b_i, avg_dist)

        if b_i == float('inf'):
            b_i = 0

        # Calculate silhouette
        if max(a_i, b_i) > 0:
            s_i = (b_i - a_i) / max(a_i, b_i)
        else:
            s_i = 0

        silhouette_scores.append(s_i)

    return sum(silhouette_scores) / len(silhouette_scores) if silhouette_scores else 0.0


def get_cluster_summary(clusters: List[Cluster]) -> Dict[str, Any]:
    """
    Generate summary statistics for clusters.

    Args:
        clusters: List of clusters

    Returns:
        Summary dictionary
    """
    if not clusters:
        return {
            "total_clusters": 0,
            "total_items": 0,
            "avg_cluster_size": 0,
            "largest_cluster": 0,
            "smallest_cluster": 0,
        }

    sizes = [c.size for c in clusters]

    return {
        "total_clusters": len(clusters),
        "total_items": sum(sizes),
        "avg_cluster_size": sum(sizes) / len(sizes),
        "largest_cluster": max(sizes),
        "smallest_cluster": min(sizes),
        "cluster_labels": [c.label for c in clusters],
    }
