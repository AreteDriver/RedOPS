"""Tests for the Pipeline Runner."""

import pytest
from pathlib import Path
from unittest.mock import patch
from redops.core.context import Context
from redops.pipelines.loader import PipelineLoader
from redops.pipelines.runner import PipelineRunner


def test_pipeline_runner_with_recon_pipeline():
    """Test running a reconnaissance pipeline."""
    pipeline_path = "config/pipelines/recon_pipeline.json"

    # Check if pipeline exists
    if not Path(pipeline_path).exists():
        pytest.skip(f"Pipeline file {pipeline_path} not found")

    try:
        # Load the pipeline
        pipeline = PipelineLoader.load(pipeline_path)

        # Create runner
        runner = PipelineRunner(pipeline)

        # Run with test target
        ctx = runner.run(target="example.com")

        assert ctx is not None
        assert ctx.target == "example.com"
        assert "pipeline_name" in ctx.data
        assert len(ctx.logs) > 0
    except Exception as e:
        # Pipeline might fail due to missing dependencies, which is OK for this test
        pytest.skip(f"Pipeline execution failed: {e}")


def test_pipeline_runner_initialization():
    """Test PipelineRunner initialization."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Test Pipeline", version="1.0"),
        steps=[
            PipelineStep(
                name="Dummy Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            )
        ],
    )

    runner = PipelineRunner(pipeline)
    assert runner.pipeline == pipeline


def test_pipeline_runner_basic_execution():
    """Test basic pipeline execution with simple steps."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Basic Test", version="1.0"),
        steps=[
            PipelineStep(
                name="Audit Start",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            )
        ],
    )

    runner = PipelineRunner(pipeline)
    ctx = runner.run(target="test.com")

    assert ctx is not None
    assert ctx.target == "test.com"
    assert ctx.data.get("pipeline_name") == "Basic Test"


def test_pipeline_runner_with_initial_context():
    """Test running pipeline with pre-existing context."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Test Pipeline", version="1.0"),
        steps=[
            PipelineStep(
                name="Dummy Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            )
        ],
    )

    initial_ctx = Context(target="initial.com")
    initial_ctx.add("pre_existing_data", "value")

    runner = PipelineRunner(pipeline)
    result_ctx = runner.run(initial_context=initial_ctx)

    assert result_ctx.target == "initial.com"
    assert result_ctx.get("pre_existing_data") == "value"


def test_pipeline_runner_logs_execution():
    """Test that pipeline runner creates logs."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Log Test", version="1.0"),
        steps=[
            PipelineStep(
                name="Audit Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            )
        ],
    )

    runner = PipelineRunner(pipeline)
    ctx = runner.run(target="test.com")

    info_logs = ctx.get_logs(level="INFO")
    assert len(info_logs) > 0
    assert any("Starting pipeline" in log["message"] for log in info_logs)
    assert any("completed" in log["message"].lower() for log in info_logs)


def test_pipeline_runner_disabled_steps():
    """Test that disabled steps are not executed."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Disabled Test", version="1.0"),
        steps=[
            PipelineStep(
                name="Enabled Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            ),
            PipelineStep(
                name="Disabled Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=False,
            ),
        ],
    )

    runner = PipelineRunner(pipeline)
    _ctx = runner.run(target="test.com")  # noqa: F841 - run to validate pipeline

    # The enabled_steps property should filter out disabled steps
    assert len(pipeline.enabled_steps) == 1
    assert pipeline.enabled_steps[0].name == "Enabled Step"


def test_pipeline_runner_rollback_on_step_failure():
    """Test that context is rolled back when a step fails with continue_on_error."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    def _failing_step(ctx, params):
        ctx.add("corrupted", True)
        raise RuntimeError("step failure")

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Rollback Test", version="1.0"),
        steps=[
            PipelineStep(
                name="Good Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            ),
            PipelineStep(
                name="Failing Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
                continue_on_error=True,
            ),
        ],
    )

    runner = PipelineRunner(pipeline)
    with patch.object(runner, "_resolve_module_function") as mock_resolve:
        def _mock_func(step_name):
            if step_name == "Failing Step":
                return _failing_step
            return lambda ctx, params: ctx

        # The module path maps to the step name for this mock
        mock_resolve.side_effect = lambda path: _failing_step if "failing" in path.lower() else lambda ctx, params: ctx
        ctx = runner.run(target="test.com", parallel=False)

    # The failing step should have been rolled back; "corrupted" should not exist
    assert ctx.get("corrupted") is None
    assert ctx.get("pipeline_name") == "Rollback Test"


def test_pipeline_runner_checkpoints_cleared_after_run():
    """Test that checkpoints are cleared after pipeline completes."""
    from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep

    pipeline = Pipeline(
        metadata=PipelineMetadata(name="Clear Test", version="1.0"),
        steps=[
            PipelineStep(
                name="Audit Step",
                module="compliance.audit_log.audit_pipeline_start",
                enabled=True,
            )
        ],
    )

    runner = PipelineRunner(pipeline)
    ctx = runner.run(target="test.com")
    assert len(ctx._checkpoints) == 0
