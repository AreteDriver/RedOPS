"""Tests for the OSCAL report module."""

import json
import tempfile
from pathlib import Path
from redops.core.context import Context
from redops.modules.reporting.oscal_report import (
    export_oscal,
    export_oscal_catalog,
    create_oscal_assessment_results,
    create_metadata,
    create_local_definitions,
    create_result,
    create_observation,
    create_finding,
    collect_findings,
    normalize_severity,
    severity_to_state,
    get_oscal_summary,
)


class TestExportOscal:
    """Tests for export_oscal function."""

    def test_export_empty_context(self):
        """Test exporting empty context."""
        ctx = Context(target="example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_oscal(ctx, {"output_dir": tmpdir})

            assert "oscal_export_path" in result.data
            output_path = Path(result.data["oscal_export_path"])
            assert output_path.exists()

    def test_export_with_findings(self):
        """Test exporting context with findings."""
        ctx = Context(target="example.com")
        ctx.add(
            "finding_test_0",
            {
                "module": "test.module",
                "title": "Test Finding",
                "description": "A test finding",
                "severity": "high",
                "data": {"ip": "1.2.3.4"},
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_oscal(ctx, {"output_dir": tmpdir})

            assert result.data["oscal_findings_count"] == 1
            assert result.data["oscal_observations_count"] == 1

            # Verify JSON is valid
            with open(result.data["oscal_export_path"]) as f:
                oscal = json.load(f)

            assert "assessment-results" in oscal

    def test_custom_organization(self):
        """Test custom organization name."""
        ctx = Context(target="example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_oscal(
                ctx,
                {
                    "output_dir": tmpdir,
                    "organization_name": "Test Org",
                },
            )

            with open(result.data["oscal_export_path"]) as f:
                oscal = json.load(f)

            parties = oscal["assessment-results"]["metadata"]["parties"]
            assert any(p["name"] == "Test Org" for p in parties)


class TestExportOscalCatalog:
    """Tests for export_oscal_catalog function."""

    def test_export_catalog(self):
        """Test exporting OSCAL catalog."""
        ctx = Context()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = export_oscal_catalog(ctx, {"output_dir": tmpdir})

            assert "oscal_catalog_path" in result.data
            output_path = Path(result.data["oscal_catalog_path"])
            assert output_path.exists()

            with open(output_path) as f:
                catalog = json.load(f)

            assert "catalog" in catalog
            assert "groups" in catalog["catalog"]


class TestCreateOscalAssessmentResults:
    """Tests for create_oscal_assessment_results function."""

    def test_document_structure(self):
        """Test basic document structure."""
        ctx = Context(target="example.com")

        doc = create_oscal_assessment_results(ctx)

        assert "assessment-results" in doc
        assert "uuid" in doc["assessment-results"]
        assert "metadata" in doc["assessment-results"]
        assert "results" in doc["assessment-results"]


class TestCreateMetadata:
    """Tests for create_metadata function."""

    def test_metadata_fields(self):
        """Test metadata has required fields."""
        metadata = create_metadata(
            "Test Assessment", "Test Org", "2024-01-01T00:00:00Z"
        )

        assert metadata["title"] == "Test Assessment"
        assert "roles" in metadata
        assert "parties" in metadata

    def test_oscal_version(self):
        """Test OSCAL version is included."""
        metadata = create_metadata("Test", "Org", "2024-01-01T00:00:00Z")

        assert "oscal-version" in metadata


class TestCreateLocalDefinitions:
    """Tests for create_local_definitions function."""

    def test_includes_component(self):
        """Test includes system component."""
        ctx = Context(target="example.com")

        definitions = create_local_definitions(ctx, "Test System")

        assert "components" in definitions
        assert len(definitions["components"]) > 0

    def test_includes_inventory_from_subdomains(self):
        """Test includes inventory from subdomains."""
        ctx = Context(target="example.com")
        ctx.add("subdomains", ["www.example.com", "api.example.com"])

        definitions = create_local_definitions(ctx, "Test System")

        assert len(definitions["inventory-items"]) == 2


class TestCreateResult:
    """Tests for create_result function."""

    def test_result_structure(self):
        """Test result has required structure."""
        findings = [
            {"module": "test", "title": "Finding", "severity": "high"},
        ]

        result = create_result(
            "test-uuid",
            findings,
            Context(target="example.com"),
            "2024-01-01T00:00:00Z",
        )

        assert result["uuid"] == "test-uuid"
        assert "observations" in result
        assert "findings" in result


class TestCreateObservation:
    """Tests for create_observation function."""

    def test_observation_fields(self):
        """Test observation has required fields."""
        finding = {
            "module": "test.module",
            "title": "Test Finding",
            "description": "Description",
            "severity": "high",
        }

        observation = create_observation(finding, "2024-01-01T00:00:00Z")

        assert "uuid" in observation
        assert observation["title"] == "Test Finding"
        assert "methods" in observation

    def test_observation_with_subjects(self):
        """Test observation includes subjects from data."""
        finding = {
            "module": "test",
            "title": "Finding",
            "severity": "high",
            "data": {"ip": "1.2.3.4", "domain": "example.com"},
        }

        observation = create_observation(finding, "2024-01-01T00:00:00Z")

        assert "subjects" in observation
        assert len(observation["subjects"]) >= 2


class TestCreateFinding:
    """Tests for create_finding function."""

    def test_finding_fields(self):
        """Test finding has required fields."""
        finding_data = {
            "title": "Test Finding",
            "description": "Description",
            "severity": "high",
        }

        finding = create_finding(finding_data, "obs-uuid", "2024-01-01T00:00:00Z")

        assert "uuid" in finding
        assert finding["title"] == "Test Finding"
        assert "target" in finding
        assert "related-observations" in finding

    def test_finding_status_from_severity(self):
        """Test finding status is set from severity."""
        finding_data = {
            "title": "Critical Finding",
            "severity": "critical",
        }

        finding = create_finding(finding_data, "obs-uuid", "2024-01-01T00:00:00Z")

        assert finding["target"]["status"]["state"] == "not-satisfied"


class TestCollectFindings:
    """Tests for collect_findings function."""

    def test_collect_findings(self):
        """Test collecting findings."""
        ctx = Context()
        ctx.add("finding_test_0", {"title": "Finding 1"})
        ctx.add("risks", [{"title": "Risk 1", "level": "high"}])

        findings = collect_findings(ctx)

        assert len(findings) == 2


class TestNormalizeSeverity:
    """Tests for normalize_severity function."""

    def test_string_severity(self):
        """Test string severity."""
        assert normalize_severity("HIGH") == "high"

    def test_enum_severity(self):
        """Test enum-like severity."""

        class MockSeverity:
            name = "CRITICAL"

        assert normalize_severity(MockSeverity()) == "critical"


class TestSeverityToState:
    """Tests for severity_to_state function."""

    def test_critical_not_satisfied(self):
        """Test critical maps to not-satisfied."""
        assert severity_to_state("critical") == "not-satisfied"

    def test_high_not_satisfied(self):
        """Test high maps to not-satisfied."""
        assert severity_to_state("high") == "not-satisfied"

    def test_medium_partially_satisfied(self):
        """Test medium maps to partially-satisfied."""
        assert severity_to_state("medium") == "partially-satisfied"

    def test_low_satisfied(self):
        """Test low maps to satisfied."""
        assert severity_to_state("low") == "satisfied"


class TestGetOscalSummary:
    """Tests for get_oscal_summary function."""

    def test_with_data(self):
        """Test summary with data."""
        ctx = Context()
        ctx.add("oscal_export_path", "/path/to/file.json")
        ctx.add("oscal_findings_count", 5)
        ctx.add("oscal_observations_count", 5)

        summary = get_oscal_summary(ctx)

        assert summary["export_path"] == "/path/to/file.json"
        assert summary["findings_count"] == 5

    def test_without_data(self):
        """Test summary without data."""
        ctx = Context()

        summary = get_oscal_summary(ctx)

        assert summary["export_path"] == ""
        assert summary["findings_count"] == 0
