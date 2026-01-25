"""Tests for intel/clustering module."""

import pytest
from redops.modules.intel.clustering import (
    Cluster,
    cluster_findings,
    collect_findings,
    cluster_by_attribute,
    cluster_by_text_similarity,
    cluster_technologies,
    cluster_risks_by_score,
    jaccard_similarity,
    cosine_similarity_text,
    levenshtein_distance,
    levenshtein_similarity,
    cluster_by_similarity,
    calculate_silhouette_score,
    get_cluster_summary,
)
from redops.core.context import Context


class TestCluster:
    """Tests for Cluster dataclass."""

    def test_basic_creation(self):
        """Test basic cluster creation."""
        cluster = Cluster(id=0, label="test_cluster")
        assert cluster.id == 0
        assert cluster.label == "test_cluster"
        assert cluster.size == 0
        assert cluster.items == []

    def test_add_item(self):
        """Test adding items to cluster."""
        cluster = Cluster(id=0, label="test")
        cluster.add_item(1)
        cluster.add_item(2)
        cluster.add_item(1)  # Duplicate

        assert cluster.size == 2
        assert 1 in cluster.items
        assert 2 in cluster.items

    def test_to_dict(self):
        """Test cluster to dictionary conversion."""
        cluster = Cluster(
            id=1,
            label="severity:high",
            items=[0, 1, 2],
            centroid={"avg": 10},
            metadata={"source": "test"},
        )
        result = cluster.to_dict()

        assert result["id"] == 1
        assert result["label"] == "severity:high"
        assert result["size"] == 3
        assert result["items"] == [0, 1, 2]
        assert result["centroid"]["avg"] == 10
        assert result["metadata"]["source"] == "test"


class TestJaccardSimilarity:
    """Tests for Jaccard similarity."""

    def test_identical_sets(self):
        """Test similarity of identical sets."""
        set1 = {"a", "b", "c"}
        set2 = {"a", "b", "c"}
        assert jaccard_similarity(set1, set2) == 1.0

    def test_disjoint_sets(self):
        """Test similarity of disjoint sets."""
        set1 = {"a", "b", "c"}
        set2 = {"d", "e", "f"}
        assert jaccard_similarity(set1, set2) == 0.0

    def test_partial_overlap(self):
        """Test similarity with partial overlap."""
        set1 = {"a", "b", "c"}
        set2 = {"b", "c", "d"}
        # Intersection: {b, c} = 2
        # Union: {a, b, c, d} = 4
        assert jaccard_similarity(set1, set2) == 0.5

    def test_empty_sets(self):
        """Test with empty sets."""
        assert jaccard_similarity(set(), set()) == 0.0
        assert jaccard_similarity({"a"}, set()) == 0.0
        assert jaccard_similarity(set(), {"a"}) == 0.0


class TestCosineSimilarity:
    """Tests for cosine similarity."""

    def test_identical_text(self):
        """Test similarity of identical text."""
        text = "hello world"
        sim = cosine_similarity_text(text, text)
        assert sim == pytest.approx(1.0)

    def test_completely_different(self):
        """Test completely different text."""
        text1 = "hello world"
        text2 = "goodbye universe"
        sim = cosine_similarity_text(text1, text2)
        assert sim == 0.0

    def test_partial_overlap(self):
        """Test text with partial overlap."""
        text1 = "hello world today"
        text2 = "hello world tomorrow"
        sim = cosine_similarity_text(text1, text2)
        assert 0 < sim < 1

    def test_empty_text(self):
        """Test with empty text."""
        assert cosine_similarity_text("", "") == 0.0
        assert cosine_similarity_text("hello", "") == 0.0


class TestLevenshteinDistance:
    """Tests for Levenshtein distance."""

    def test_identical_strings(self):
        """Test distance between identical strings."""
        assert levenshtein_distance("hello", "hello") == 0

    def test_empty_string(self):
        """Test with empty string."""
        assert levenshtein_distance("hello", "") == 5
        assert levenshtein_distance("", "hello") == 5
        assert levenshtein_distance("", "") == 0

    def test_single_edit(self):
        """Test single edit distance."""
        assert levenshtein_distance("cat", "bat") == 1  # Substitution
        assert levenshtein_distance("cat", "cats") == 1  # Insertion
        assert levenshtein_distance("cats", "cat") == 1  # Deletion

    def test_multiple_edits(self):
        """Test multiple edits."""
        assert levenshtein_distance("kitten", "sitting") == 3


class TestLevenshteinSimilarity:
    """Tests for Levenshtein similarity."""

    def test_identical_strings(self):
        """Test similarity of identical strings."""
        assert levenshtein_similarity("hello", "hello") == 1.0

    def test_empty_strings(self):
        """Test with empty strings."""
        assert levenshtein_similarity("", "") == 1.0

    def test_completely_different(self):
        """Test completely different strings."""
        sim = levenshtein_similarity("abc", "xyz")
        assert sim == 0.0

    def test_partial_similarity(self):
        """Test partial similarity."""
        sim = levenshtein_similarity("hello", "hallo")
        # 1 edit out of 5 chars = 80% similar
        assert sim == pytest.approx(0.8)


class TestClusterByAttribute:
    """Tests for attribute-based clustering."""

    def test_cluster_by_severity(self):
        """Test clustering by severity attribute."""
        items = [
            {"title": "Issue 1", "severity": "high"},
            {"title": "Issue 2", "severity": "high"},
            {"title": "Issue 3", "severity": "low"},
        ]
        clusters = cluster_by_attribute(items, "severity")

        assert len(clusters) == 2
        high_cluster = next(c for c in clusters if "high" in c.label)
        low_cluster = next(c for c in clusters if "low" in c.label)
        assert high_cluster.size == 2
        assert low_cluster.size == 1

    def test_cluster_by_missing_attribute(self):
        """Test clustering when attribute is missing."""
        items = [
            {"title": "Issue 1"},
            {"title": "Issue 2", "category": "test"},
        ]
        clusters = cluster_by_attribute(items, "category")

        # Missing attribute should use "unknown"
        assert len(clusters) == 2

    def test_cluster_by_complex_attribute(self):
        """Test clustering by complex (list/dict) attribute."""
        items = [
            {"title": "Issue 1", "tags": ["a", "b"]},
            {"title": "Issue 2", "tags": ["a", "b"]},
        ]
        clusters = cluster_by_attribute(items, "tags")

        # Complex values should be stringified
        assert len(clusters) >= 1


class TestClusterByTextSimilarity:
    """Tests for text similarity clustering."""

    def test_similar_items_clustered(self):
        """Test that similar items are clustered together."""
        items = [
            {
                "title": "SQL injection vulnerability found",
                "description": "Input not sanitized",
            },
            {
                "title": "SQL injection in login form",
                "description": "User input not validated",
            },
            {"title": "Missing HTTPS", "description": "Site uses HTTP"},
        ]
        clusters = cluster_by_text_similarity(items, threshold=0.3, min_cluster_size=2)

        # SQL injection items should cluster
        assert len(clusters) >= 1
        sql_cluster = next((c for c in clusters if c.size == 2), None)
        assert sql_cluster is not None

    def test_minimum_cluster_size(self):
        """Test minimum cluster size enforcement."""
        items = [
            {"title": "Unique issue one"},
            {"title": "Unique issue two"},
            {"title": "Unique issue three"},
        ]
        clusters = cluster_by_text_similarity(items, threshold=0.9, min_cluster_size=2)

        # No items should be similar enough at high threshold
        assert len(clusters) == 0

    def test_empty_items(self):
        """Test with empty items list."""
        clusters = cluster_by_text_similarity([], threshold=0.3)
        assert clusters == []

    def test_single_item(self):
        """Test with single item."""
        items = [{"title": "Only one"}]
        clusters = cluster_by_text_similarity(items, threshold=0.3, min_cluster_size=2)
        assert clusters == []


class TestClusterTechnologies:
    """Tests for technology clustering."""

    def test_frontend_technologies(self):
        """Test frontend technology clustering."""
        technologies = [
            {"name": "React", "version": "18.0"},
            {"name": "Vue.js"},
            {"name": "nginx"},
        ]
        clusters = cluster_technologies(technologies)

        frontend = next((c for c in clusters if "frontend" in c.label), None)
        server = next((c for c in clusters if "server" in c.label), None)

        assert frontend is not None
        assert server is not None

    def test_string_format_technologies(self):
        """Test with string format technologies."""
        technologies = ["React", "nginx", "PostgreSQL"]
        clusters = cluster_technologies(technologies)

        assert len(clusters) >= 2  # Should have at least frontend, server, database

    def test_uncategorized_technologies(self):
        """Test uncategorized technologies."""
        technologies = ["UnknownTech", "CustomLib"]
        clusters = cluster_technologies(technologies)

        other = next((c for c in clusters if "other" in c.label), None)
        assert other is not None
        assert other.size == 2


class TestClusterRisksByScore:
    """Tests for risk score clustering."""

    def test_cluster_by_score_ranges(self):
        """Test clustering into score ranges."""
        risks = [
            {"title": "Critical", "score": 22},
            {"title": "High 1", "score": 15},
            {"title": "High 2", "score": 14},
            {"title": "Medium", "score": 8},
            {"title": "Low", "score": 4},
            {"title": "Info", "score": 1},
        ]
        clusters = cluster_risks_by_score(risks)

        # Should have clusters for different severity levels
        labels = [c.label for c in clusters]
        assert any("critical" in label for label in labels)
        assert any("high" in label for label in labels)
        assert any("medium" in label for label in labels)

    def test_empty_risks(self):
        """Test with empty risks list."""
        clusters = cluster_risks_by_score([])
        assert clusters == []

    def test_missing_score(self):
        """Test handling missing score field."""
        risks = [{"title": "No score"}, {"title": "Has score", "score": 15}]
        clusters = cluster_risks_by_score(risks)
        # Items without score should go to info (0-3)
        assert len(clusters) >= 1


class TestClusterBySimilarity:
    """Tests for generic similarity clustering."""

    def test_jaccard_clustering(self):
        """Test Jaccard similarity clustering."""
        items = [
            {"title": "hello world test"},
            {"title": "hello world example"},
            {"title": "goodbye universe"},
        ]
        clusters = cluster_by_similarity(items, "jaccard", threshold=0.3)

        # First two should cluster
        assert any(len(c) == 2 for c in clusters)

    def test_cosine_clustering(self):
        """Test cosine similarity clustering."""
        items = [
            {"title": "machine learning model"},
            {"title": "machine learning algorithm"},
            {"title": "web development"},
        ]
        clusters = cluster_by_similarity(items, "cosine", threshold=0.5)
        assert len(clusters) >= 1

    def test_levenshtein_clustering(self):
        """Test Levenshtein similarity clustering."""
        items = [
            {"title": "test123"},
            {"title": "test124"},
            {"title": "abcdefg"},
        ]
        clusters = cluster_by_similarity(items, "levenshtein", threshold=0.8)

        # First two should cluster (very similar)
        assert any(len(c) == 2 for c in clusters)

    def test_single_item_clustering(self):
        """Test clustering with single item."""
        items = [{"title": "only one"}]
        clusters = cluster_by_similarity(items, "jaccard", threshold=0.5)
        assert len(clusters) == 1
        assert clusters[0] == [0]


class TestSilhouetteScore:
    """Tests for silhouette score calculation."""

    def test_perfect_clusters(self):
        """Test silhouette for well-separated clusters."""
        items = [
            {"title": "aaa bbb ccc"},
            {"title": "aaa bbb ddd"},
            {"title": "xxx yyy zzz"},
            {"title": "xxx yyy www"},
        ]
        clusters = [[0, 1], [2, 3]]

        score = calculate_silhouette_score(items, clusters)
        # Well-separated clusters should have positive score
        assert score > 0

    def test_single_cluster(self):
        """Test silhouette with single cluster."""
        items = [{"title": "a"}, {"title": "b"}]
        clusters = [[0, 1]]

        score = calculate_silhouette_score(items, clusters)
        assert score == 0.0

    def test_empty_clusters(self):
        """Test with empty clusters."""
        items = []
        clusters = []
        score = calculate_silhouette_score(items, clusters)
        assert score == 0.0


class TestGetClusterSummary:
    """Tests for cluster summary generation."""

    def test_summary_statistics(self):
        """Test summary statistics calculation."""
        clusters = [
            Cluster(id=0, label="a", items=[0, 1, 2]),
            Cluster(id=1, label="b", items=[3, 4]),
            Cluster(id=2, label="c", items=[5]),
        ]
        summary = get_cluster_summary(clusters)

        assert summary["total_clusters"] == 3
        assert summary["total_items"] == 6
        assert summary["avg_cluster_size"] == 2.0
        assert summary["largest_cluster"] == 3
        assert summary["smallest_cluster"] == 1
        assert "a" in summary["cluster_labels"]

    def test_empty_clusters_summary(self):
        """Test summary with no clusters."""
        summary = get_cluster_summary([])

        assert summary["total_clusters"] == 0
        assert summary["total_items"] == 0
        assert summary["avg_cluster_size"] == 0


class TestClusterFindings:
    """Tests for cluster_findings function with Context."""

    def test_cluster_findings_empty(self):
        """Test clustering with no findings."""
        ctx = Context(target="test.io")
        result = cluster_findings(ctx)

        assert "clusters" in result.data
        assert "cluster_summary" in result.data

    def test_cluster_findings_with_data(self):
        """Test clustering with findings data."""
        ctx = Context(target="test.io")
        ctx.add(
            "finding_0",
            {"title": "SQL Injection", "severity": "high", "module": "scanner"},
        )
        ctx.add(
            "finding_1",
            {"title": "SQL Injection variant", "severity": "high", "module": "scanner"},
        )
        ctx.add(
            "finding_2",
            {"title": "Missing HTTPS", "severity": "medium", "module": "network"},
        )

        result = cluster_findings(ctx)
        clusters = result.get("clusters")

        # Should have severity clusters
        assert len(clusters["severity_clusters"]) >= 2
        # Should have category clusters
        assert len(clusters["category_clusters"]) >= 2

    def test_cluster_findings_with_tech_stack(self):
        """Test clustering with technology stack."""
        ctx = Context(target="test.io")
        ctx.add(
            "tech_stack",
            {
                "technologies": [
                    {"name": "React"},
                    {"name": "nginx"},
                    {"name": "PostgreSQL"},
                ]
            },
        )

        result = cluster_findings(ctx)
        clusters = result.get("clusters")

        assert len(clusters["technology_clusters"]) >= 1

    def test_cluster_findings_with_risks(self):
        """Test clustering with risk data."""
        ctx = Context(target="test.io")
        ctx.add(
            "risks",
            [
                {"title": "Risk 1", "score": 20},
                {"title": "Risk 2", "score": 15},
                {"title": "Risk 3", "score": 5},
            ],
        )

        result = cluster_findings(ctx)
        clusters = result.get("clusters")

        assert "risk_clusters" in clusters
        assert len(clusters["risk_clusters"]) >= 1

    def test_cluster_findings_summary(self):
        """Test cluster summary generation."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Test", "severity": "high", "module": "test"})

        result = cluster_findings(ctx)
        summary = result.get("cluster_summary")

        assert "total_clusters" in summary
        assert "by_type" in summary
        assert "findings_clustered" in summary


class TestCollectFindings:
    """Tests for collect_findings function."""

    def test_collect_findings(self):
        """Test collecting findings from context."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", {"title": "Issue 1"})
        ctx.add("finding_1", {"title": "Issue 2"})
        ctx.add("other_data", {"not": "a finding"})

        findings = collect_findings(ctx)

        assert len(findings) == 2
        assert findings[0]["_key"] == "finding_0"

    def test_collect_findings_empty(self):
        """Test collecting with no findings."""
        ctx = Context(target="test.io")
        findings = collect_findings(ctx)
        assert findings == []

    def test_collect_findings_non_dict(self):
        """Test handling non-dict finding values."""
        ctx = Context(target="test.io")
        ctx.add("finding_0", "not a dict")
        ctx.add("finding_1", {"title": "Valid"})

        findings = collect_findings(ctx)
        # Should only include dict findings
        assert len(findings) == 1


class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_unicode_text_clustering(self):
        """Test clustering with Unicode text."""
        items = [
            {"title": "日本語テスト"},
            {"title": "日本語テスト2"},
            {"title": "English text"},
        ]
        # Should not crash
        clusters = cluster_by_text_similarity(items, threshold=0.3)
        assert isinstance(clusters, list)

    def test_empty_title_clustering(self):
        """Test clustering with empty titles."""
        items = [
            {"title": ""},
            {"title": ""},
            {"title": "actual content"},
        ]
        clusters = cluster_by_text_similarity(items, threshold=0.3)
        assert isinstance(clusters, list)

    def test_very_long_text_clustering(self):
        """Test clustering with very long text."""
        items = [
            {"title": "word " * 1000},
            {"title": "word " * 1000},
        ]
        clusters = cluster_by_text_similarity(items, threshold=0.5)
        assert isinstance(clusters, list)

    def test_special_characters_in_text(self):
        """Test handling special characters."""
        items = [
            {"title": "test!@#$%^&*()"},
            {"title": "test!@#$%^&*()2"},
        ]
        clusters = cluster_by_text_similarity(items, threshold=0.5)
        assert isinstance(clusters, list)

    def test_numerical_scores(self):
        """Test with various numerical score types."""
        risks = [
            {"title": "Int score", "score": 15},
            {"title": "Float score", "score": 15.5},
            {"title": "String score", "score": "not a number"},
        ]
        clusters = cluster_risks_by_score(risks)
        assert isinstance(clusters, list)
