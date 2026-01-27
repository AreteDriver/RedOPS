"""Tests for pipeline loader module."""

import pytest
import json

from redops.pipelines.loader import PipelineLoader
from redops.pipelines.schemas import Pipeline, PipelineStep, PipelineMetadata


class TestPipelineLoaderLoad:
    """Tests for PipelineLoader.load method."""

    def test_load_valid_pipeline(self, tmp_path):
        """Test loading a valid pipeline file."""
        pipeline_data = {
            "metadata": {
                "name": "test_pipeline",
                "description": "Test pipeline",
                "version": "1.0",
            },
            "steps": [
                {
                    "name": "Step 1",
                    "module": "recon.domains.profile_domain",
                    "params": {},
                }
            ],
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        pipeline = PipelineLoader.load(pipeline_file)

        assert isinstance(pipeline, Pipeline)
        assert pipeline.metadata.name == "test_pipeline"
        assert len(pipeline.steps) == 1

    def test_load_with_string_path(self, tmp_path):
        """Test loading with string path."""
        pipeline_data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [{"name": "Step", "module": "mod.func"}],
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        pipeline = PipelineLoader.load(str(pipeline_file))

        assert isinstance(pipeline, Pipeline)

    def test_load_file_not_found(self):
        """Test loading nonexistent file."""
        with pytest.raises(FileNotFoundError, match="Pipeline file not found"):
            PipelineLoader.load("/nonexistent/path/pipeline.json")

    def test_load_invalid_json(self, tmp_path):
        """Test loading invalid JSON file."""
        pipeline_file = tmp_path / "invalid.json"
        pipeline_file.write_text("{ invalid json }")

        with pytest.raises(ValueError, match="Invalid JSON"):
            PipelineLoader.load(pipeline_file)

    def test_load_validation_failure(self, tmp_path):
        """Test loading file that fails validation."""
        # Missing required 'metadata' field
        pipeline_data = {"steps": [{"name": "Step", "module": "mod.func"}]}

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        with pytest.raises(ValueError, match="validation failed"):
            PipelineLoader.load(pipeline_file)

    def test_load_empty_steps(self, tmp_path):
        """Test loading pipeline with no steps."""
        pipeline_data = {"metadata": {"name": "test", "version": "1.0"}, "steps": []}

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        with pytest.raises(ValueError):
            PipelineLoader.load(pipeline_file)

    def test_load_all_disabled_steps(self, tmp_path):
        """Test loading pipeline with all steps disabled."""
        pipeline_data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [{"name": "Step", "module": "mod.func", "enabled": False}],
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        with pytest.raises(ValueError):
            PipelineLoader.load(pipeline_file)

    def test_load_with_multiple_steps(self, tmp_path):
        """Test loading pipeline with multiple steps."""
        pipeline_data = {
            "metadata": {"name": "multi_step", "version": "1.0"},
            "steps": [
                {"name": "DNS", "module": "recon.dns.scan"},
                {"name": "Tech", "module": "recon.tech.detect"},
                {"name": "Vuln", "module": "vuln.scan.basic"},
            ],
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        pipeline = PipelineLoader.load(pipeline_file)

        assert len(pipeline.steps) == 3
        assert pipeline.steps[0].name == "DNS"
        assert pipeline.steps[1].name == "Tech"
        assert pipeline.steps[2].name == "Vuln"

    def test_load_with_params(self, tmp_path):
        """Test loading pipeline with step params."""
        pipeline_data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [
                {
                    "name": "Scan",
                    "module": "recon.scan.full",
                    "params": {
                        "depth": 3,
                        "timeout": 30,
                        "options": ["verbose", "force"],
                    },
                }
            ],
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        pipeline = PipelineLoader.load(pipeline_file)

        assert pipeline.steps[0].params["depth"] == 3
        assert pipeline.steps[0].params["timeout"] == 30
        assert "verbose" in pipeline.steps[0].params["options"]

    def test_load_with_config(self, tmp_path):
        """Test loading pipeline with config section."""
        pipeline_data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [{"name": "Step", "module": "mod.func"}],
            "config": {"max_retries": 3, "output_format": "json"},
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        pipeline = PipelineLoader.load(pipeline_file)

        assert pipeline.config["max_retries"] == 3
        assert pipeline.config["output_format"] == "json"

    def test_load_with_plugin_reference(self, tmp_path):
        """Test loading pipeline with plugin reference."""
        pipeline_data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [{"name": "Custom", "module": "plugin:my_custom_plugin"}],
        }

        pipeline_file = tmp_path / "pipeline.json"
        pipeline_file.write_text(json.dumps(pipeline_data))

        pipeline = PipelineLoader.load(pipeline_file)

        assert pipeline.steps[0].module == "plugin:my_custom_plugin"


class TestPipelineLoaderLoadFromDict:
    """Tests for PipelineLoader.load_from_dict method."""

    def test_load_from_dict_valid(self):
        """Test loading from valid dictionary."""
        data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [{"name": "Step", "module": "mod.func"}],
        }

        pipeline = PipelineLoader.load_from_dict(data)

        assert isinstance(pipeline, Pipeline)
        assert pipeline.metadata.name == "test"

    def test_load_from_dict_invalid(self):
        """Test loading from invalid dictionary."""
        data = {
            "steps": []  # Missing metadata and empty steps
        }

        with pytest.raises(Exception):
            PipelineLoader.load_from_dict(data)

    def test_load_from_dict_with_full_metadata(self):
        """Test loading with full metadata."""
        data = {
            "metadata": {
                "name": "full_meta",
                "description": "A complete description",
                "version": "2.5.1",
                "author": "Test Author",
                "tags": ["security", "recon", "automated"],
            },
            "steps": [{"name": "Step", "module": "mod.func"}],
        }

        pipeline = PipelineLoader.load_from_dict(data)

        assert pipeline.metadata.name == "full_meta"
        assert pipeline.metadata.description == "A complete description"
        assert pipeline.metadata.version == "2.5.1"
        assert pipeline.metadata.author == "Test Author"
        assert "security" in pipeline.metadata.tags

    def test_load_from_dict_with_continue_on_error(self):
        """Test loading steps with continue_on_error."""
        data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [
                {
                    "name": "Critical",
                    "module": "mod.critical",
                    "continue_on_error": False,
                },
                {
                    "name": "Optional",
                    "module": "mod.optional",
                    "continue_on_error": True,
                },
            ],
        }

        pipeline = PipelineLoader.load_from_dict(data)

        assert pipeline.steps[0].continue_on_error is False
        assert pipeline.steps[1].continue_on_error is True


class TestPipelineLoaderSave:
    """Tests for PipelineLoader.save method."""

    def test_save_pipeline(self, tmp_path):
        """Test saving a pipeline to file."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="saved_pipeline", version="1.0"),
            steps=[
                PipelineStep(name="Step 1", module="mod.step1"),
            ],
        )

        output_file = tmp_path / "output.json"
        PipelineLoader.save(pipeline, output_file)

        assert output_file.exists()

        saved_data = json.loads(output_file.read_text())
        assert saved_data["metadata"]["name"] == "saved_pipeline"
        assert len(saved_data["steps"]) == 1

    def test_save_with_string_path(self, tmp_path):
        """Test saving with string path."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="test", version="1.0"),
            steps=[PipelineStep(name="Step", module="mod.func")],
        )

        output_file = tmp_path / "output.json"
        PipelineLoader.save(pipeline, str(output_file))

        assert output_file.exists()

    def test_save_creates_parent_dirs(self, tmp_path):
        """Test save creates parent directories."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="test", version="1.0"),
            steps=[PipelineStep(name="Step", module="mod.func")],
        )

        output_file = tmp_path / "nested" / "path" / "output.json"
        PipelineLoader.save(pipeline, output_file)

        assert output_file.exists()
        assert (tmp_path / "nested" / "path").is_dir()

    def test_save_preserves_all_fields(self, tmp_path):
        """Test save preserves all pipeline fields."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(
                name="complete",
                description="Full description",
                version="3.0",
                author="Author",
                tags=["tag1", "tag2"],
            ),
            steps=[
                PipelineStep(
                    name="Full Step",
                    module="mod.full",
                    params={"key": "value"},
                    enabled=True,
                    continue_on_error=True,
                )
            ],
            config={"global_setting": "value"},
        )

        output_file = tmp_path / "output.json"
        PipelineLoader.save(pipeline, output_file)

        saved_data = json.loads(output_file.read_text())

        assert saved_data["metadata"]["name"] == "complete"
        assert saved_data["metadata"]["description"] == "Full description"
        assert saved_data["metadata"]["author"] == "Author"
        assert saved_data["metadata"]["tags"] == ["tag1", "tag2"]
        assert saved_data["steps"][0]["params"]["key"] == "value"
        assert saved_data["config"]["global_setting"] == "value"

    def test_save_is_indented(self, tmp_path):
        """Test saved JSON is indented for readability."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="test", version="1.0"),
            steps=[PipelineStep(name="Step", module="mod.func")],
        )

        output_file = tmp_path / "output.json"
        PipelineLoader.save(pipeline, output_file)

        content = output_file.read_text()
        # Should have multiple lines due to indentation
        assert content.count("\n") > 2

    def test_save_overwrites_existing(self, tmp_path):
        """Test save overwrites existing file."""
        output_file = tmp_path / "output.json"
        output_file.write_text('{"old": "data"}')

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="new", version="1.0"),
            steps=[PipelineStep(name="Step", module="mod.func")],
        )

        PipelineLoader.save(pipeline, output_file)

        saved_data = json.loads(output_file.read_text())
        assert saved_data["metadata"]["name"] == "new"
        assert "old" not in saved_data


class TestRoundTrip:
    """Tests for save/load round-trip."""

    def test_round_trip(self, tmp_path):
        """Test saving and loading produces same pipeline."""
        original = Pipeline(
            metadata=PipelineMetadata(
                name="round_trip",
                description="Test round trip",
                version="1.0",
                tags=["test"],
            ),
            steps=[
                PipelineStep(
                    name="Step 1", module="mod.step1", params={"param1": "value1"}
                ),
                PipelineStep(name="Step 2", module="mod.step2", enabled=False),
            ],
            config={"setting": True},
        )

        file_path = tmp_path / "round_trip.json"
        PipelineLoader.save(original, file_path)
        loaded = PipelineLoader.load(file_path)

        assert loaded.metadata.name == original.metadata.name
        assert loaded.metadata.description == original.metadata.description
        assert loaded.metadata.version == original.metadata.version
        assert len(loaded.steps) == len(original.steps)
        assert loaded.steps[0].params == original.steps[0].params
        assert loaded.steps[1].enabled == original.steps[1].enabled
        assert loaded.config == original.config

    def test_round_trip_with_plugin(self, tmp_path):
        """Test round trip with plugin references."""
        original = Pipeline(
            metadata=PipelineMetadata(name="plugin_test", version="1.0"),
            steps=[PipelineStep(name="Plugin", module="plugin:custom_scanner")],
        )

        file_path = tmp_path / "plugin_test.json"
        PipelineLoader.save(original, file_path)
        loaded = PipelineLoader.load(file_path)

        assert loaded.steps[0].module == "plugin:custom_scanner"


class TestEnabledSteps:
    """Tests for enabled_steps property after loading."""

    def test_enabled_steps_filters_disabled(self, tmp_path):
        """Test enabled_steps filters out disabled steps."""
        data = {
            "metadata": {"name": "test", "version": "1.0"},
            "steps": [
                {"name": "Enabled 1", "module": "mod.e1", "enabled": True},
                {"name": "Disabled", "module": "mod.d1", "enabled": False},
                {"name": "Enabled 2", "module": "mod.e2", "enabled": True},
            ],
        }

        pipeline = PipelineLoader.load_from_dict(data)

        assert len(pipeline.steps) == 3
        assert len(pipeline.enabled_steps) == 2
        assert all(s.name.startswith("Enabled") for s in pipeline.enabled_steps)
