"""Tests for surface summary module."""

from unittest.mock import MagicMock

from redops.modules.corp_assessment.surface_summary import (
    generate_summary,
    calculate_exposure_level,
    extract_key_findings,
    generate_recommendations,
)


class TestCalculateExposureLevel:
    """Tests for calculate_exposure_level function."""

    def test_no_risks_returns_low(self):
        """Test empty risks returns low exposure."""
        ctx = MagicMock()
        ctx.get.return_value = []

        level = calculate_exposure_level(ctx)
        assert level == "low"

    def test_critical_risk_returns_critical(self):
        """Test critical risk returns critical exposure."""
        ctx = MagicMock()
        ctx.get.return_value = [{"level": "critical"}]

        level = calculate_exposure_level(ctx)
        assert level == "critical"

    def test_multiple_high_risks_returns_high(self):
        """Test 4+ high risks returns high exposure."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
        ]

        level = calculate_exposure_level(ctx)
        assert level == "high"

    def test_few_high_risks_returns_medium(self):
        """Test 1-3 high risks returns medium exposure."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"level": "high"},
            {"level": "high"},
        ]

        level = calculate_exposure_level(ctx)
        assert level == "medium"

    def test_only_medium_returns_low(self):
        """Test only medium risks returns low exposure."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"level": "medium"},
            {"level": "medium"},
            {"level": "low"},
        ]

        level = calculate_exposure_level(ctx)
        assert level == "low"

    def test_critical_overrides_high(self):
        """Test critical takes precedence over high."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
            {"level": "critical"},
        ]

        level = calculate_exposure_level(ctx)
        assert level == "critical"


class TestExtractKeyFindings:
    """Tests for extract_key_findings function."""

    def test_empty_risks(self):
        """Test empty risks returns empty list."""
        ctx = MagicMock()
        ctx.get.return_value = []

        findings = extract_key_findings(ctx)
        assert findings == []

    def test_returns_titles(self):
        """Test returns risk titles."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"title": "SQL Injection", "score": 10},
            {"title": "XSS", "score": 8},
        ]

        findings = extract_key_findings(ctx)
        assert "SQL Injection" in findings
        assert "XSS" in findings

    def test_sorted_by_score(self):
        """Test findings sorted by score."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"title": "Low Risk", "score": 2},
            {"title": "High Risk", "score": 10},
            {"title": "Medium Risk", "score": 5},
        ]

        findings = extract_key_findings(ctx)
        assert findings[0] == "High Risk"
        assert findings[1] == "Medium Risk"
        assert findings[2] == "Low Risk"

    def test_respects_limit(self):
        """Test respects limit parameter."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"title": f"Risk {i}", "score": 10 - i} for i in range(10)
        ]

        findings = extract_key_findings(ctx, limit=3)
        assert len(findings) == 3

    def test_default_limit(self):
        """Test default limit is 5."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"title": f"Risk {i}", "score": 10 - i} for i in range(10)
        ]

        findings = extract_key_findings(ctx)
        assert len(findings) == 5

    def test_handles_missing_title(self):
        """Test handles missing title."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"score": 10},  # No title
        ]

        findings = extract_key_findings(ctx)
        assert findings[0] == "Unknown risk"


class TestGenerateRecommendations:
    """Tests for generate_recommendations function."""

    def test_critical_exposure_recommendations(self):
        """Test critical exposure adds urgent recommendations."""
        ctx = MagicMock()
        ctx.get.return_value = [{"level": "critical"}]

        recs = generate_recommendations(ctx)

        assert any("Immediate action" in r for r in recs)
        assert any("incident response" in r.lower() for r in recs)

    def test_high_exposure_recommendations(self):
        """Test high exposure adds appropriate recommendations."""
        ctx = MagicMock()
        ctx.get.return_value = [
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
            {"level": "high"},
        ]

        recs = generate_recommendations(ctx)

        assert any("audit" in r.lower() for r in recs)

    def test_medium_exposure_recommendations(self):
        """Test medium exposure adds policy recommendations."""
        ctx = MagicMock()
        ctx.get.return_value = [{"level": "high"}]

        recs = generate_recommendations(ctx)

        assert any("security policies" in r.lower() for r in recs)
        assert any("monitoring" in r.lower() for r in recs)

    def test_low_exposure_recommendations(self):
        """Test low exposure still provides base recommendations."""
        ctx = MagicMock()
        ctx.get.return_value = []

        recs = generate_recommendations(ctx)

        assert len(recs) > 0
        assert any("regular" in r.lower() for r in recs)
        assert any("training" in r.lower() for r in recs)

    def test_max_five_recommendations(self):
        """Test returns at most 5 recommendations."""
        ctx = MagicMock()
        ctx.get.return_value = [{"level": "critical"}]

        recs = generate_recommendations(ctx)

        assert len(recs) <= 5

    def test_always_includes_base_recommendations(self):
        """Test always includes base recommendations."""
        ctx = MagicMock()
        ctx.get.return_value = []

        recs = generate_recommendations(ctx)

        assert any("regular security assessments" in r.lower() for r in recs)
        assert any("asset inventory" in r.lower() for r in recs)


class TestGenerateSummary:
    """Tests for generate_summary function."""

    def test_returns_context(self):
        """Test returns context."""
        ctx = MagicMock()
        ctx.get.side_effect = lambda key, default=[]: default

        result = generate_summary(ctx)
        assert result == ctx

    def test_adds_summary_to_context(self):
        """Test adds surface_summary to context."""
        ctx = MagicMock()
        ctx.get.side_effect = lambda key, default=[]: default

        generate_summary(ctx)

        ctx.add.assert_called()
        call_args = ctx.add.call_args[0]
        assert call_args[0] == "surface_summary"
        assert isinstance(call_args[1], dict)

    def test_summary_structure(self):
        """Test summary has expected structure."""
        ctx = MagicMock()
        ctx.get.side_effect = lambda key, default=[]: default

        generate_summary(ctx)

        call_args = ctx.add.call_args[0]
        summary = call_args[1]

        assert "total_assets" in summary
        assert "total_risks" in summary
        assert "exposure_level" in summary
        assert "key_findings" in summary
        assert "recommendations" in summary

    def test_counts_assets(self):
        """Test counts assets."""
        ctx = MagicMock()

        def get_side_effect(key, default=[]):
            if key == "assets":
                return [{"id": 1}, {"id": 2}, {"id": 3}]
            return default

        ctx.get.side_effect = get_side_effect

        generate_summary(ctx)

        call_args = ctx.add.call_args[0]
        summary = call_args[1]
        assert summary["total_assets"] == 3

    def test_counts_risks(self):
        """Test counts risks."""
        ctx = MagicMock()

        def get_side_effect(key, default=[]):
            if key == "risks":
                return [{"level": "high"}, {"level": "medium"}]
            return default

        ctx.get.side_effect = get_side_effect

        generate_summary(ctx)

        call_args = ctx.add.call_args[0]
        summary = call_args[1]
        assert summary["total_risks"] == 2

    def test_logs_progress(self):
        """Test logs progress messages."""
        ctx = MagicMock()
        ctx.get.side_effect = lambda key, default=[]: default

        generate_summary(ctx)

        assert ctx.log.call_count >= 2

    def test_accepts_params(self):
        """Test accepts params parameter."""
        ctx = MagicMock()
        ctx.get.side_effect = lambda key, default=[]: default

        params = {"some_option": True}
        result = generate_summary(ctx, params)

        assert result == ctx

    def test_handles_none_params(self):
        """Test handles None params."""
        ctx = MagicMock()
        ctx.get.side_effect = lambda key, default=[]: default

        result = generate_summary(ctx, None)

        assert result == ctx


class TestIntegration:
    """Integration tests."""

    def test_full_summary_flow(self):
        """Test complete summary generation flow."""
        ctx = MagicMock()

        # Simulate real context data
        def get_side_effect(key, default=[]):
            if key == "assets":
                return [{"id": i} for i in range(10)]
            if key == "risks":
                return [
                    {"title": "Critical Issue", "level": "critical", "score": 10},
                    {"title": "High Risk 1", "level": "high", "score": 8},
                    {"title": "High Risk 2", "level": "high", "score": 7},
                    {"title": "Medium Risk", "level": "medium", "score": 5},
                ]
            return default

        ctx.get.side_effect = get_side_effect

        generate_summary(ctx)

        call_args = ctx.add.call_args[0]
        summary = call_args[1]

        assert summary["total_assets"] == 10
        assert summary["total_risks"] == 4
        assert summary["exposure_level"] == "critical"
        assert len(summary["key_findings"]) > 0
        assert len(summary["recommendations"]) > 0
        assert summary["key_findings"][0] == "Critical Issue"
