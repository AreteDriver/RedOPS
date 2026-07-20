"""Tests for Click CLI commands (scan, report, etc.)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from redops.cli.main import cli


class TestScanListPipelines:
    """Tests for 'scan list-pipelines' command."""

    def test_list_pipelines_shows_available_pipelines(self, tmp_path):
        """list-pipelines should display available pipeline definitions."""
        runner = CliRunner()

        # Create a fake pipeline JSON in a temp dir
        pipelines_dir = tmp_path / "config" / "pipelines"
        pipelines_dir.mkdir(parents=True)
        pipeline_file = pipelines_dir / "quickstart.json"
        pipeline_file.write_text(json.dumps({
            "metadata": {
                "name": "Quick Start",
                "description": "Zero-config quickstart pipeline",
                "version": "1.0.0",
                "author": "test",
                "tags": ["quick", "starter"]
            },
            "steps": [
                {"name": "port_scan", "module": "redops.modules.port_scan"}
            ],
            "config": {"timeout": 60}
        }))

        with patch(
            "redops.cli.commands.scan.Path"
        ) as mock_path_cls:
            # Return our temp dir as the resolved pipelines directory
            mock_path_cls.return_value.parents.__getitem__ = lambda self, i: tmp_path if i == 3 else None
            mock_path_cls.return_value.exists.return_value = True
            with patch(
                "redops.pipelines.loader.PipelineLoader.load"
            ) as mock_load:
                mock_pipeline = MagicMock()
                mock_pipeline.metadata.name = "Quick Start"
                mock_pipeline.metadata.description = "Zero-config quickstart pipeline"
                mock_pipeline.steps = [MagicMock()]
                mock_pipeline.metadata.tags = ["quick", "starter"]
                mock_load.return_value = mock_pipeline
                result = runner.invoke(cli, ["scan", "list-pipelines"])

        assert result.exit_code == 0
        assert "Available Pipelines" in result.output
        assert "Quick Start" in result.output
        assert "Zero-config quickstart pipeline" in result.output

    def test_list_pipelines_empty_directory(self):
        """list-pipelines should handle empty pipeline directory gracefully."""
        runner = CliRunner()

        with patch(
            "redops.cli.commands.scan.Path"
        ) as mock_path_cls:
            instance = MagicMock()
            instance.parents = [None, None, None, Path("/nonexistent")]
            mock_path_cls.return_value = instance
            with patch.object(Path, "exists", return_value=False):
                result = runner.invoke(cli, ["scan", "list-pipelines"])

        assert result.exit_code == 0
        assert "Pipeline directory not found" in result.output


class TestScanRunLocal:
    """Tests for 'scan run --local' command."""

    def test_local_scan_runs_pipeline(self):
        """scan run --local should execute a pipeline locally without API calls."""
        runner = CliRunner()

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Quick Start"
        mock_pipeline.enabled_steps = ["port_scan"]
        mock_pipeline.steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {"findings": []}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch(
            "redops.cli.commands.scan._resolve_pipeline_file"
        ) as mock_resolve:
            mock_resolve.return_value = Path("config/pipelines/quickstart.json")
            with patch("redops.pipelines.loader.PipelineLoader.load") as mock_load:
                mock_load.return_value = mock_pipeline
                with patch(
                    "redops.pipelines.runner.PipelineRunner", return_value=mock_runner
                ):
                    result = runner.invoke(
                        cli, ["scan", "run", "--local", "example.com"]
                    )

        assert result.exit_code == 0
        assert "Starting local scan on example.com" in result.output
        assert "Quick Start" in result.output
        mock_runner.run.assert_called_once_with(target="example.com")

    def test_local_scan_unknown_pipeline(self):
        """scan run --local with unknown pipeline should exit with error."""
        runner = CliRunner()

        with patch(
            "redops.cli.commands.scan._resolve_pipeline_file"
        ) as mock_resolve:
            mock_resolve.return_value = None
            result = runner.invoke(
                cli, ["scan", "run", "--local", "-p", "nonexistent", "example.com"]
            )

        assert result.exit_code == 1
        assert "Pipeline 'nonexistent' not found" in result.output
        assert "list-pipelines" in result.output

    def test_local_scan_with_output_file(self, tmp_path):
        """scan run --local with -o should write JSON results."""
        runner = CliRunner()
        output_file = tmp_path / "results.json"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Quick Start"
        mock_pipeline.enabled_steps = ["port_scan"]
        mock_pipeline.steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {"findings": [{"title": "Open Port", "severity": "info"}]}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch(
            "redops.cli.commands.scan._resolve_pipeline_file"
        ) as mock_resolve:
            mock_resolve.return_value = Path("config/pipelines/quickstart.json")
            with patch("redops.pipelines.loader.PipelineLoader.load") as mock_load:
                mock_load.return_value = mock_pipeline
                with patch(
                    "redops.pipelines.runner.PipelineRunner", return_value=mock_runner
                ):
                    result = runner.invoke(
                        cli,
                        [
                            "scan",
                            "run",
                            "--local",
                            "-o",
                            str(output_file),
                            "example.com",
                        ],
                    )

        assert result.exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["target"] == "example.com"
        assert len(data["findings"]) == 1


class TestQuickScanLocal:
    """Tests for 'quick-scan --local' command."""

    def test_quick_scan_local(self):
        """quick-scan --local should delegate to local scan execution."""
        runner = CliRunner()

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Quick Start"
        mock_pipeline.enabled_steps = ["port_scan"]
        mock_pipeline.steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {"findings": []}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch(
            "redops.cli.commands.scan._resolve_pipeline_file"
        ) as mock_resolve:
            mock_resolve.return_value = Path("config/pipelines/quickstart.json")
            with patch("redops.pipelines.loader.PipelineLoader.load") as mock_load:
                mock_load.return_value = mock_pipeline
                with patch(
                    "redops.pipelines.runner.PipelineRunner", return_value=mock_runner
                ):
                    result = runner.invoke(
                        cli, ["quick-scan", "--local", "example.com"]
                    )

        assert result.exit_code == 0
        assert "Starting local scan on example.com" in result.output
        mock_runner.run.assert_called_once_with(target="example.com")

    def test_quick_scan_local_default_pipeline(self):
        """quick-scan --local should use 'quickstart' as default pipeline."""
        runner = CliRunner()

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Quick Start"
        mock_pipeline.enabled_steps = ["port_scan"]
        mock_pipeline.steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {"findings": []}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch(
            "redops.cli.commands.scan._resolve_pipeline_file"
        ) as mock_resolve:
            mock_resolve.return_value = Path("config/pipelines/quickstart.json")
            with patch("redops.pipelines.loader.PipelineLoader.load") as mock_load:
                mock_load.return_value = mock_pipeline
                with patch(
                    "redops.pipelines.runner.PipelineRunner", return_value=mock_runner
                ):
                    runner.invoke(cli, ["quick-scan", "--local", "example.com"])

        # _resolve_pipeline_file should be called with "default" which maps to "quickstart"
        mock_resolve.assert_called_once_with("default")
