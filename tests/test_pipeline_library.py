"""Tests for the example pipeline library.

Validates that all pipeline JSON files in config/pipelines/ load,
pass schema validation, and contain expected metadata and steps.
"""

import json
from pathlib import Path

import pytest

from redops.pipelines.schemas import Pipeline, PipelineStep


PIPELINES_DIR = Path(__file__).parents[1] / "config" / "pipelines"


def _load_pipeline(path: Path) -> Pipeline:
    """Load and validate a pipeline JSON file."""
    with open(path, "r") as f:
        data = json.load(f)
    return Pipeline(**data)


class TestPipelineLibrary:
    """Tests for all pipeline definitions in config/pipelines/."""

    @pytest.fixture(scope="class")
    def pipeline_paths(self):
        """Return all pipeline JSON files."""
        paths = sorted(PIPELINES_DIR.glob("*.json"))
        assert paths, f"No pipeline files found in {PIPELINES_DIR}"
        return paths

    def test_all_pipelines_load(self, pipeline_paths):
        """Every pipeline JSON file loads without error."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            assert pipeline is not None
            assert pipeline.metadata.name

    def test_all_pipelines_have_metadata(self, pipeline_paths):
        """Every pipeline has required metadata fields."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            assert pipeline.metadata.name
            assert pipeline.metadata.version
            assert pipeline.metadata.tags is not None

    def test_all_pipelines_have_at_least_one_step(self, pipeline_paths):
        """Every pipeline has at least one step."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            assert len(pipeline.steps) >= 1

    def test_all_pipelines_have_at_least_one_enabled_step(self, pipeline_paths):
        """Every pipeline has at least one enabled step."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            assert len(pipeline.enabled_steps) >= 1

    def test_all_steps_have_valid_module_paths(self, pipeline_paths):
        """Every step references a valid dotted module path."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            for step in pipeline.steps:
                assert "." in step.module or step.module.startswith("plugin:")
                assert step.name

    def test_pipelines_validate(self, pipeline_paths):
        """Every pipeline passes Pipeline.validate_pipeline()."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            assert pipeline.validate_pipeline() is True

    def test_no_duplicate_step_names(self, pipeline_paths):
        """No pipeline contains duplicate step names."""
        for path in pipeline_paths:
            pipeline = _load_pipeline(path)
            names = [step.name for step in pipeline.steps]
            assert len(names) == len(set(names)), f"Duplicate names in {path.name}"

    def test_pipeline_files_count(self, pipeline_paths):
        """Pipeline library has expected number of examples."""
        # Should have at least 9 pipeline files (existing 4 + new 5)
        assert len(pipeline_paths) >= 9


class TestSpecificPipelines:
    """Tests for individual pipeline content."""

    def test_bug_bounty_recon_exists(self):
        """Bug bounty recon pipeline exists and has expected steps."""
        path = PIPELINES_DIR / "bug_bounty_recon.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Bug Bounty Recon"
        modules = [step.module for step in pipeline.steps]
        assert "recon.subdomain_enum.enumerate_subdomains" in modules
        assert "recon.cert_transparency.query_ct_logs" in modules

    def test_incident_response_exists(self):
        """Incident response pipeline exists and has threat-intel steps."""
        path = PIPELINES_DIR / "incident_response.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Incident Response Triage"
        modules = [step.module for step in pipeline.steps]
        assert "threat_intel.abuseipdb.check_ip" in modules
        assert "threat_intel.greynoise.query_greynoise" in modules
        assert "intel.stix_export.export_stix" in modules

    def test_compliance_assessment_exists(self):
        """Compliance assessment pipeline exists and maps controls."""
        path = PIPELINES_DIR / "compliance_assessment.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Compliance Assessment"
        modules = [step.module for step in pipeline.steps]
        assert "compliance.compliance_map.map_controls" in modules
        assert "reporting.oscal_report.generate_oscal" in modules

    def test_wireless_recon_exists(self):
        """Wireless recon pipeline exists and requires authorization."""
        path = PIPELINES_DIR / "wireless_recon.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Wireless Reconnaissance"
        assert pipeline.config.get("requires_authorization") is True
        modules = [step.module for step in pipeline.steps]
        assert "active.wireless.scan.scan_access_points" in modules
        assert "active.wireless.monitor.enable_monitor_mode" in modules
        assert "active.wireless.monitor.disable_monitor_mode" in modules

    def test_quickstart_exists(self):
        """Quickstart pipeline exists and targets <60s runtime."""
        path = PIPELINES_DIR / "quickstart.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Quick Start"
        assert pipeline.config.get("timeout") == 60
        assert pipeline.config.get("strict_scope") is False
        assert len(pipeline.steps) <= 5

    def test_recon_pipeline_exists(self):
        """Original recon pipeline still validates."""
        path = PIPELINES_DIR / "recon_pipeline.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Reconnaissance Pipeline"
        assert pipeline.validate_pipeline() is True

    def test_corp_assessment_exists(self):
        """Original corporate assessment pipeline still validates."""
        path = PIPELINES_DIR / "corp_assessment.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Corporate Assessment Pipeline"
        assert pipeline.validate_pipeline() is True

    def test_forensic_pipeline_exists(self):
        """Original forensic pipeline still validates."""
        path = PIPELINES_DIR / "forensic_pipeline.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert pipeline.metadata.name == "Forensic Analysis Pipeline"
        assert pipeline.validate_pipeline() is True

    def test_active_chain_exists(self):
        """Original active chain pipeline still validates."""
        path = PIPELINES_DIR / "active_chain.json"
        assert path.exists()
        pipeline = _load_pipeline(path)
        assert "Active" in pipeline.metadata.name
        assert "Chain" in pipeline.metadata.name
        assert pipeline.validate_pipeline() is True
