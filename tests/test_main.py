"""Tests for RedOps main module."""

import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call
from io import StringIO


class TestRunPipeline:
    """Tests for run_pipeline function."""

    def test_run_pipeline_success(self):
        """Test successful pipeline execution."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./output"
        mock_config.output.verbose = False

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = ["step1", "step2"]

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {"result": "data"}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    result = run_pipeline("pipeline.json", "example.com")

        assert result == 0
        mock_loader.load.assert_called_once_with("pipeline.json")
        mock_runner.run.assert_called_once_with(target="example.com")

    def test_run_pipeline_with_config_file(self):
        """Test pipeline execution with config file."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./output"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_file.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    result = run_pipeline(
                        "pipeline.json",
                        "example.com",
                        config_path="/path/to/config.yaml"
                    )

        assert result == 0
        mock_config_class.from_file.assert_called_once()

    def test_run_pipeline_with_custom_output_dir(self):
        """Test pipeline execution with custom output directory."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./default"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    result = run_pipeline(
                        "pipeline.json",
                        "example.com",
                        output_dir="./custom_output"
                    )

        assert result == 0
        assert mock_config.output.output_dir == "./custom_output"

    def test_run_pipeline_with_errors_and_warnings(self, capsys):
        """Test pipeline execution that produces errors and warnings."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./output"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = [{"level": "ERROR"}, {"level": "WARNING"}]
        mock_ctx.data = {"report_path": "/path/to/report.html"}

        # Configure get_logs to return different values based on level
        def get_logs_side_effect(level=None):
            if level == "ERROR":
                return [{"message": "Error 1"}, {"message": "Error 2"}]
            elif level == "WARNING":
                return [{"message": "Warning 1"}]
            return []

        mock_ctx.get_logs.side_effect = get_logs_side_effect

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    result = run_pipeline("pipeline.json", "example.com")

        assert result == 0
        captured = capsys.readouterr()
        assert "Errors: 2" in captured.out
        assert "Warnings: 1" in captured.out
        assert "report_path" in captured.out

    def test_run_pipeline_exception(self, capsys):
        """Test pipeline execution with exception."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.verbose = False

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.side_effect = Exception("Pipeline load failed")
                result = run_pipeline("bad_pipeline.json", "example.com")

        assert result == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.err
        assert "Pipeline load failed" in captured.err

    def test_run_pipeline_exception_verbose(self, capsys):
        """Test pipeline execution with exception in verbose mode."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.verbose = True

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.side_effect = ValueError("Invalid pipeline")
                result = run_pipeline("bad_pipeline.json", "example.com")

        assert result == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.err

    def test_run_pipeline_no_output_dir(self):
        """Test pipeline execution with None output_dir."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./default"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {}
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    # Pass empty string for output_dir (falsy)
                    result = run_pipeline("pipeline.json", "example.com", output_dir="")

        assert result == 0
        # output_dir should not be changed when falsy
        assert mock_config.output.output_dir == "./default"


class TestListPipelines:
    """Tests for list_pipelines function."""

    def test_list_pipelines_success(self, tmp_path, capsys):
        """Test listing pipelines successfully."""
        from redops.main import list_pipelines

        # Create a mock pipeline file
        pipeline_dir = tmp_path / "pipelines"
        pipeline_dir.mkdir()
        (pipeline_dir / "test_pipeline.json").write_text("{}")

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.metadata.description = "A test pipeline"
        mock_pipeline.steps = ["step1", "step2"]

        with patch("redops.main.PipelineLoader") as mock_loader:
            mock_loader.load.return_value = mock_pipeline
            list_pipelines(str(pipeline_dir))

        captured = capsys.readouterr()
        assert "Test Pipeline" in captured.out
        assert "A test pipeline" in captured.out
        assert "Steps: 2" in captured.out

    def test_list_pipelines_no_description(self, tmp_path, capsys):
        """Test listing pipeline without description."""
        from redops.main import list_pipelines

        pipeline_dir = tmp_path / "pipelines"
        pipeline_dir.mkdir()
        (pipeline_dir / "test_pipeline.json").write_text("{}")

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Simple Pipeline"
        mock_pipeline.metadata.description = None
        mock_pipeline.steps = []

        with patch("redops.main.PipelineLoader") as mock_loader:
            mock_loader.load.return_value = mock_pipeline
            list_pipelines(str(pipeline_dir))

        captured = capsys.readouterr()
        assert "Simple Pipeline" in captured.out

    def test_list_pipelines_directory_not_found(self, capsys):
        """Test listing pipelines when directory doesn't exist."""
        from redops.main import list_pipelines

        list_pipelines("/nonexistent/directory")

        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_list_pipelines_load_error(self, tmp_path, capsys):
        """Test listing pipelines with load error."""
        from redops.main import list_pipelines

        pipeline_dir = tmp_path / "pipelines"
        pipeline_dir.mkdir()
        (pipeline_dir / "bad_pipeline.json").write_text("{invalid}")

        with patch("redops.main.PipelineLoader") as mock_loader:
            mock_loader.load.side_effect = Exception("Parse error")
            list_pipelines(str(pipeline_dir))

        captured = capsys.readouterr()
        assert "error loading" in captured.out
        assert "Parse error" in captured.out

    def test_list_pipelines_empty_directory(self, tmp_path, capsys):
        """Test listing pipelines from empty directory."""
        from redops.main import list_pipelines

        pipeline_dir = tmp_path / "pipelines"
        pipeline_dir.mkdir()

        list_pipelines(str(pipeline_dir))

        captured = capsys.readouterr()
        assert "Available pipelines" in captured.out


class TestMain:
    """Tests for main function."""

    def test_main_calls_cli(self):
        """Test main function calls CLI main."""
        from redops.main import main

        with patch("redops.cli.app.main", return_value=0) as mock_cli:
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0
        mock_cli.assert_called_once()

    def test_main_exits_with_cli_code(self):
        """Test main function exits with CLI return code."""
        from redops.main import main

        with patch("redops.cli.app.main", return_value=1) as mock_cli:
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1


class TestMainLegacy:
    """Tests for main_legacy function."""

    def test_main_legacy_run_command(self):
        """Test legacy main with run command."""
        from redops.main import main_legacy

        with patch("sys.argv", ["redops", "run", "pipeline.json", "example.com"]):
            with patch("redops.main.run_pipeline", return_value=0) as mock_run:
                with pytest.raises(SystemExit) as exc_info:
                    main_legacy()

        assert exc_info.value.code == 0
        mock_run.assert_called_once_with("pipeline.json", "example.com", "./output", None)

    def test_main_legacy_run_with_options(self):
        """Test legacy main with run command and options."""
        from redops.main import main_legacy

        with patch("sys.argv", [
            "redops", "run", "pipeline.json", "example.com",
            "--output-dir", "./reports",
            "--config", "config.yaml"
        ]):
            with patch("redops.main.run_pipeline", return_value=0) as mock_run:
                with pytest.raises(SystemExit) as exc_info:
                    main_legacy()

        assert exc_info.value.code == 0
        mock_run.assert_called_once_with(
            "pipeline.json", "example.com", "./reports", "config.yaml"
        )

    def test_main_legacy_list_command(self):
        """Test legacy main with list command."""
        from redops.main import main_legacy

        with patch("sys.argv", ["redops", "list"]):
            with patch("redops.main.list_pipelines") as mock_list:
                main_legacy()

        mock_list.assert_called_once_with("./config/pipelines")

    def test_main_legacy_list_with_dir(self):
        """Test legacy main with list command and custom directory."""
        from redops.main import main_legacy

        with patch("sys.argv", ["redops", "list", "--dir", "./custom/pipelines"]):
            with patch("redops.main.list_pipelines") as mock_list:
                main_legacy()

        mock_list.assert_called_once_with("./custom/pipelines")

    def test_main_legacy_no_command(self, capsys):
        """Test legacy main with no command shows help."""
        from redops.main import main_legacy

        with patch("sys.argv", ["redops"]):
            with pytest.raises(SystemExit) as exc_info:
                main_legacy()

        assert exc_info.value.code == 1

    def test_main_legacy_version(self, capsys):
        """Test legacy main with --version flag."""
        from redops.main import main_legacy, __version__

        with patch("sys.argv", ["redops", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main_legacy()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert __version__ in captured.out


class TestModuleLevelCode:
    """Tests for module-level code."""

    def test_version_defined(self):
        """Test __version__ is defined."""
        from redops.main import __version__

        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_if_name_main(self):
        """Test if __name__ == '__main__' block."""
        # This is tricky to test directly, but we can verify the module
        # can be imported without running main()
        import redops.main

        assert hasattr(redops.main, "main")
        assert hasattr(redops.main, "__version__")


class TestRunPipelineOutputPaths:
    """Tests for output path printing in run_pipeline."""

    def test_run_pipeline_prints_output_paths(self, capsys):
        """Test that output paths are printed."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./output"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {
            "html_report_path": "/output/report.html",
            "json_path": "/output/data.json",
            "other_data": "not a path"
        }
        mock_ctx.get_logs.return_value = []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    result = run_pipeline("pipeline.json", "example.com")

        assert result == 0
        captured = capsys.readouterr()
        assert "html_report_path" in captured.out
        assert "json_path" in captured.out
        # "other_data" doesn't contain "_path" so shouldn't be printed as output file
        assert "other_data" not in captured.out


class TestRunPipelineManyErrorsWarnings:
    """Tests for error/warning truncation in run_pipeline."""

    def test_run_pipeline_truncates_errors(self, capsys):
        """Test that only first 5 errors are printed."""
        from redops.main import run_pipeline

        mock_config = MagicMock()
        mock_config.output.output_dir = "./output"

        mock_pipeline = MagicMock()
        mock_pipeline.metadata.name = "Test Pipeline"
        mock_pipeline.enabled_steps = []

        mock_ctx = MagicMock()
        mock_ctx.target = "example.com"
        mock_ctx.logs = []
        mock_ctx.data = {}

        # Return 10 errors
        errors = [{"message": f"Error {i}"} for i in range(10)]
        mock_ctx.get_logs.side_effect = lambda level=None: errors if level == "ERROR" else []

        mock_runner = MagicMock()
        mock_runner.run.return_value = mock_ctx

        with patch("redops.main.RedOpsConfig") as mock_config_class:
            mock_config_class.from_env.return_value = mock_config
            with patch("redops.main.PipelineLoader") as mock_loader:
                mock_loader.load.return_value = mock_pipeline
                with patch("redops.main.PipelineRunner", return_value=mock_runner):
                    result = run_pipeline("pipeline.json", "example.com")

        assert result == 0
        captured = capsys.readouterr()
        assert "Errors: 10" in captured.out
        # Only first 5 should be shown
        assert "Error 0" in captured.out
        assert "Error 4" in captured.out
        # Error 5-9 should not be shown
        assert "Error 5" not in captured.out
