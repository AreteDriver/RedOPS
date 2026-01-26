"""Integration tests for full pipeline execution.

Tests end-to-end pipeline workflows, module chaining, error handling,
and data flow across pipeline steps.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from redops.pipelines.loader import PipelineLoader
from redops.pipelines.runner import PipelineRunner
from redops.pipelines.schemas import Pipeline, PipelineStep, PipelineMetadata
from redops.core.context import Context
from redops.core.config import RedOpsConfig


class TestPipelineLoading:
    """Tests for pipeline loading and validation."""

    def test_load_from_dict(self):
        """Test loading a pipeline from dictionary."""
        pipeline_def = {
            "metadata": {
                "name": "Test Pipeline",
                "version": "1.0",
                "description": "A test pipeline",
            },
            "steps": [
                {
                    "name": "Step 1",
                    "module": "recon.domains.enumerate_dns",
                    "enabled": True,
                }
            ],
        }

        pipeline = PipelineLoader.load_from_dict(pipeline_def)

        assert pipeline.metadata.name == "Test Pipeline"
        assert len(pipeline.steps) == 1
        assert pipeline.steps[0].name == "Step 1"

    def test_load_from_file(self):
        """Test loading a pipeline from JSON file."""
        pipeline_def = {
            "metadata": {
                "name": "File Pipeline",
                "version": "1.0",
            },
            "steps": [
                {
                    "name": "DNS Step",
                    "module": "recon.domains.enumerate_dns",
                }
            ],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(pipeline_def, f)
            f.flush()

            pipeline = PipelineLoader.load(f.name)

            assert pipeline.metadata.name == "File Pipeline"

    def test_load_invalid_json(self):
        """Test error handling for invalid JSON."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not valid json {{{")
            f.flush()

            with pytest.raises(ValueError, match="Invalid JSON"):
                PipelineLoader.load(f.name)

    def test_load_file_not_found(self):
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError, match="Pipeline file not found"):
            PipelineLoader.load("/nonexistent/path/pipeline.json")

    def test_load_invalid_schema(self):
        """Test error handling for invalid pipeline schema."""
        pipeline_def = {
            "metadata": {"name": "Bad Pipeline"},
            # Missing required 'steps' field
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(pipeline_def, f)
            f.flush()

            with pytest.raises(ValueError, match="validation failed"):
                PipelineLoader.load(f.name)

    def test_save_pipeline(self):
        """Test saving a pipeline to file."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Save Test", version="1.0"),
            steps=[
                PipelineStep(name="Step", module="recon.domains.enumerate_dns")
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "saved_pipeline.json"
            PipelineLoader.save(pipeline, path)

            assert path.exists()

            # Load it back
            loaded = PipelineLoader.load(path)
            assert loaded.metadata.name == "Save Test"


class TestPipelineValidation:
    """Tests for pipeline schema validation."""

    def test_empty_steps_rejected(self):
        """Test that empty steps list is rejected."""
        with pytest.raises(ValueError):
            Pipeline(
                metadata=PipelineMetadata(name="Empty"),
                steps=[],
            )

    def test_all_disabled_steps_rejected(self):
        """Test that all-disabled steps list is rejected."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Disabled"),
            steps=[
                PipelineStep(
                    name="Disabled Step",
                    module="recon.domains.enumerate_dns",
                    enabled=False,
                )
            ],
        )

        with pytest.raises(ValueError, match="at least one enabled step"):
            pipeline.validate_pipeline()

    def test_invalid_module_path(self):
        """Test that invalid module path is rejected."""
        with pytest.raises(ValueError, match="dotted path"):
            PipelineStep(name="Bad", module="nodots")

    def test_plugin_module_path_accepted(self):
        """Test that plugin: prefixed paths are accepted."""
        step = PipelineStep(name="Plugin", module="plugin:test_plugin")
        assert step.module == "plugin:test_plugin"

    def test_enabled_steps_property(self):
        """Test enabled_steps property filters correctly."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Mixed"),
            steps=[
                PipelineStep(name="Enabled", module="recon.domains.a", enabled=True),
                PipelineStep(name="Disabled", module="recon.domains.b", enabled=False),
                PipelineStep(name="Also Enabled", module="recon.domains.c", enabled=True),
            ],
        )

        enabled = pipeline.enabled_steps
        assert len(enabled) == 2
        assert enabled[0].name == "Enabled"
        assert enabled[1].name == "Also Enabled"


class TestPipelineExecution:
    """Tests for pipeline execution."""

    def test_simple_pipeline_execution(self):
        """Test execution of a simple single-step pipeline."""
        # Create a mock module function
        def mock_module(ctx, params):
            ctx.add("mock_result", {"status": "success"})
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Simple"),
            steps=[
                PipelineStep(name="Mock Step", module="recon.domains.mock_fn")
            ],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(
            runner, "_resolve_module_function", return_value=mock_module
        ):
            ctx = runner.run(target="example.com")

        assert ctx.target == "example.com"
        assert ctx.get("mock_result") == {"status": "success"}
        assert ctx.get("pipeline_name") == "Simple"

    def test_multi_step_pipeline(self):
        """Test execution with multiple steps and data flow."""
        step_order = []

        def step1(ctx, params):
            step_order.append("step1")
            ctx.add("step1_data", "from_step1")
            return ctx

        def step2(ctx, params):
            step_order.append("step2")
            # Access data from step1
            step1_data = ctx.get("step1_data")
            ctx.add("step2_data", f"received_{step1_data}")
            return ctx

        def step3(ctx, params):
            step_order.append("step3")
            ctx.add("step3_data", "final")
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Multi"),
            steps=[
                PipelineStep(name="Step 1", module="test.step1"),
                PipelineStep(name="Step 2", module="test.step2"),
                PipelineStep(name="Step 3", module="test.step3"),
            ],
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "step1" in path:
                return step1
            elif "step2" in path:
                return step2
            else:
                return step3

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(target="test.com")

        assert step_order == ["step1", "step2", "step3"]
        assert ctx.get("step1_data") == "from_step1"
        assert ctx.get("step2_data") == "received_from_step1"
        assert ctx.get("step3_data") == "final"

    def test_step_with_params(self):
        """Test that step params are passed correctly."""
        received_params = {}

        def mock_module(ctx, params):
            received_params.update(params or {})
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Params"),
            steps=[
                PipelineStep(
                    name="With Params",
                    module="test.module",
                    params={"key1": "value1", "key2": 42},
                )
            ],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            runner.run(target="test.com")

        assert received_params == {"key1": "value1", "key2": 42}

    def test_initial_context_preserved(self):
        """Test that initial context data is preserved."""
        def mock_module(ctx, params):
            ctx.add("new_data", "added")
            return ctx

        initial_ctx = Context(target="initial.com")
        initial_ctx.add("existing_data", "preserved")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Preserve"),
            steps=[PipelineStep(name="Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(initial_context=initial_ctx)

        assert ctx.get("existing_data") == "preserved"
        assert ctx.get("new_data") == "added"


class TestPipelineErrorHandling:
    """Tests for pipeline error handling."""

    def test_step_failure_stops_pipeline(self):
        """Test that step failure stops pipeline by default."""
        def failing_module(ctx, params):
            raise ValueError("Module failed")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Fail"),
            steps=[
                PipelineStep(
                    name="Failing Step",
                    module="test.fail",
                    continue_on_error=False,
                )
            ],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=failing_module):
            with pytest.raises(RuntimeError, match="Step failed"):
                runner.run(target="test.com")

    def test_continue_on_error(self):
        """Test that continue_on_error allows pipeline to proceed."""
        step_order = []

        def failing_module(ctx, params):
            step_order.append("fail")
            raise ValueError("Module failed")

        def success_module(ctx, params):
            step_order.append("success")
            ctx.add("success_data", True)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Continue"),
            steps=[
                PipelineStep(
                    name="Failing Step",
                    module="test.fail",
                    continue_on_error=True,
                ),
                PipelineStep(
                    name="Success Step",
                    module="test.success",
                ),
            ],
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "fail" in path:
                return failing_module
            return success_module

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(target="test.com")

        assert step_order == ["fail", "success"]
        assert ctx.get("success_data") is True

        # Verify error was logged
        error_logs = ctx.get_logs(level="ERROR")
        assert len(error_logs) >= 1
        assert "Step failed" in error_logs[0]["message"]

    def test_import_error_handling(self):
        """Test handling of module import errors."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Import"),
            steps=[
                PipelineStep(
                    name="Bad Import",
                    module="nonexistent.module.function",
                )
            ],
        )

        runner = PipelineRunner(pipeline)

        with pytest.raises(RuntimeError, match="Step failed"):
            runner.run(target="test.com")

    def test_attribute_error_handling(self):
        """Test handling of missing function in module."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Attr"),
            steps=[
                PipelineStep(
                    name="Bad Attr",
                    module="recon.domains.nonexistent_function",
                )
            ],
        )

        runner = PipelineRunner(pipeline)

        with pytest.raises(RuntimeError, match="Step failed"):
            runner.run(target="test.com")


class TestPipelineLogging:
    """Tests for pipeline logging."""

    def test_step_logs_captured(self):
        """Test that step execution logs are captured."""
        def mock_module(ctx, params):
            ctx.log("Custom log from module", level="INFO")
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Logging"),
            steps=[PipelineStep(name="Log Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(target="test.com")

        logs = ctx.get_logs()
        log_messages = [log["message"] for log in logs]

        assert any("Starting pipeline" in msg for msg in log_messages)
        assert any("Custom log from module" in msg for msg in log_messages)
        assert any("Pipeline completed" in msg for msg in log_messages)

    def test_error_logs_include_step_info(self):
        """Test that error logs include step information."""
        def failing_module(ctx, params):
            raise ValueError("Specific error")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="ErrorLog"),
            steps=[
                PipelineStep(
                    name="Error Step",
                    module="test.fail",
                    continue_on_error=True,
                )
            ],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=failing_module):
            ctx = runner.run(target="test.com")

        error_logs = ctx.get_logs(level="ERROR")
        assert len(error_logs) >= 1
        assert error_logs[0].get("step") == "Error Step"
        assert "Specific error" in error_logs[0].get("error", "")


class TestPipelineWithConfig:
    """Tests for pipeline execution with configuration."""

    def test_config_passed_to_context(self):
        """Test that config is passed to context."""
        config = RedOpsConfig.from_env()
        config.output.verbose = True

        def mock_module(ctx, params):
            assert ctx.config is not None
            assert ctx.config.output.verbose is True
            ctx.add("config_present", True)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Config"),
            steps=[PipelineStep(name="Config Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline, config=config)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(target="test.com")

        assert ctx.get("config_present") is True


class TestPipelinePluginIntegration:
    """Tests for pipeline plugin integration."""

    def test_plugin_module_detection(self):
        """Test that plugin: prefix is detected."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Plugin"),
            steps=[
                PipelineStep(name="Plugin Step", module="plugin:test_plugin")
            ],
        )

        runner = PipelineRunner(pipeline)

        # Without a registered plugin, should return None
        result = runner._get_plugin_module("plugin:test_plugin")
        assert result is None

    def test_non_plugin_module_ignored(self):
        """Test that regular modules are not treated as plugins."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Regular"),
            steps=[
                PipelineStep(name="Regular Step", module="recon.domains.enumerate_dns")
            ],
        )

        runner = PipelineRunner(pipeline)
        result = runner._get_plugin_module("recon.domains.enumerate_dns")
        assert result is None


class TestRealModuleExecution:
    """Integration tests with real module execution (mocked network)."""

    @patch("redops.modules.recon.domains.get_dns_records")
    def test_domain_profiling_pipeline(self, mock_dns):
        """Test domain profiling with mocked DNS."""
        mock_dns.return_value = ["192.0.2.1"]

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Domain Profile"),
            steps=[
                PipelineStep(
                    name="Profile Domain",
                    module="recon.domains.profile_domain",
                )
            ],
        )

        runner = PipelineRunner(pipeline)
        ctx = runner.run(target="example.com")

        assert ctx.get("domain_profile") is not None
        assert ctx.get("domain_profile")["domain"] == "example.com"

    @patch("redops.modules.recon.domains.get_dns_records")
    def test_dns_enumeration_pipeline(self, mock_dns):
        """Test DNS enumeration with mocked DNS."""
        mock_dns.return_value = ["192.0.2.1"]

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="DNS Enum"),
            steps=[
                PipelineStep(
                    name="Enumerate DNS",
                    module="recon.domains.enumerate_dns",
                )
            ],
        )

        runner = PipelineRunner(pipeline)
        ctx = runner.run(target="example.com")

        assert ctx.get("dns_enumeration") is not None
        assert ctx.get("dns_enumeration")["domain"] == "example.com"

    @patch("redops.modules.recon.domains.get_dns_records")
    def test_multi_module_data_flow(self, mock_dns):
        """Test data flow between multiple real modules."""
        mock_dns.return_value = ["192.0.2.1"]

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Multi Module"),
            steps=[
                PipelineStep(
                    name="Profile Domain",
                    module="recon.domains.profile_domain",
                ),
                PipelineStep(
                    name="Enumerate DNS",
                    module="recon.domains.enumerate_dns",
                ),
            ],
        )

        runner = PipelineRunner(pipeline)
        ctx = runner.run(target="example.com")

        # Both modules should have added their data
        assert ctx.get("domain_profile") is not None
        assert ctx.get("dns_enumeration") is not None


class TestPipelineNetworkErrors:
    """Tests for network error handling in pipelines."""

    @patch("redops.modules.recon.domains.get_dns_records")
    def test_network_timeout_handling(self, mock_dns):
        """Test handling of network timeouts."""
        import socket
        mock_dns.side_effect = socket.timeout("Connection timed out")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Timeout"),
            steps=[
                PipelineStep(
                    name="DNS Step",
                    module="recon.domains.enumerate_dns",
                    continue_on_error=True,
                )
            ],
        )

        runner = PipelineRunner(pipeline)
        ctx = runner.run(target="example.com")

        # Pipeline should complete with error logged
        error_logs = ctx.get_logs(level="ERROR")
        assert len(error_logs) >= 1

    @patch("redops.modules.recon.domains.get_dns_records")
    def test_connection_refused_handling(self, mock_dns):
        """Test handling of connection refused errors."""
        import socket
        mock_dns.side_effect = socket.error("Connection refused")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="ConnRefused"),
            steps=[
                PipelineStep(
                    name="DNS Step",
                    module="recon.domains.enumerate_dns",
                    continue_on_error=True,
                )
            ],
        )

        runner = PipelineRunner(pipeline)
        ctx = runner.run(target="example.com")

        # Pipeline should complete with error logged
        error_logs = ctx.get_logs(level="ERROR")
        assert len(error_logs) >= 1


class TestContextSerialization:
    """Tests for context serialization after pipeline execution."""

    def test_context_to_dict(self):
        """Test context serialization to dictionary."""
        def mock_module(ctx, params):
            ctx.add("result", {"key": "value"})
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Serialize"),
            steps=[PipelineStep(name="Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(target="test.com")

        result = ctx.to_dict()

        assert result["target"] == "test.com"
        assert "result" in result["data"]
        assert result["data"]["result"] == {"key": "value"}
        assert len(result["logs"]) > 0

    def test_context_to_json(self):
        """Test context serialization to JSON."""
        def mock_module(ctx, params):
            ctx.add("result", {"key": "value"})
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="JSON"),
            steps=[PipelineStep(name="Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(target="test.com")

        json_str = ctx.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["target"] == "test.com"
        assert "result" in parsed["data"]


class TestPipelineEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_target(self):
        """Test pipeline execution with no target."""
        def mock_module(ctx, params):
            ctx.add("no_target", ctx.target is None)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="NoTarget"),
            steps=[PipelineStep(name="Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run()  # No target specified

        assert ctx.target is None
        assert ctx.get("no_target") is True

    def test_very_long_pipeline(self):
        """Test pipeline with many steps."""
        step_count = 50
        execution_order = []

        def make_module(index):
            def module(ctx, params):
                execution_order.append(index)
                ctx.add(f"step_{index}", True)
                return ctx
            return module

        steps = [
            PipelineStep(name=f"Step {i}", module=f"test.step{i}")
            for i in range(step_count)
        ]

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Long"),
            steps=steps,
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            index = int(path.split("step")[1])
            return make_module(index)

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(target="test.com")

        assert len(execution_order) == step_count
        assert execution_order == list(range(step_count))

        for i in range(step_count):
            assert ctx.get(f"step_{i}") is True

    def test_special_characters_in_target(self):
        """Test handling of special characters in target."""
        def mock_module(ctx, params):
            ctx.add("target_received", ctx.target)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Special"),
            steps=[PipelineStep(name="Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        special_target = "example.com/path?query=value&other=123"

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(target=special_target)

        assert ctx.get("target_received") == special_target

    def test_unicode_in_results(self):
        """Test handling of unicode in results."""
        def mock_module(ctx, params):
            ctx.add("unicode_data", {"emoji": "🔒", "chinese": "安全", "arabic": "أمان"})
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Unicode"),
            steps=[PipelineStep(name="Step", module="test.module")],
        )

        runner = PipelineRunner(pipeline)

        with patch.object(runner, "_resolve_module_function", return_value=mock_module):
            ctx = runner.run(target="test.com")

        unicode_data = ctx.get("unicode_data")
        assert unicode_data["emoji"] == "🔒"
        assert unicode_data["chinese"] == "安全"
        assert unicode_data["arabic"] == "أمان"

        # Should serialize to JSON correctly and round-trip
        json_str = ctx.to_json()
        parsed = json.loads(json_str)
        assert parsed["data"]["unicode_data"]["emoji"] == "🔒"
        assert parsed["data"]["unicode_data"]["chinese"] == "安全"
        assert parsed["data"]["unicode_data"]["arabic"] == "أمان"
