"""Tests for parallel pipeline execution."""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock

from redops.pipelines.loader import PipelineLoader
from redops.pipelines.runner import PipelineRunner
from redops.pipelines.schemas import Pipeline, PipelineStep, PipelineMetadata
from redops.core.context import Context


class TestParallelGrouping:
    """Tests for step grouping logic."""

    def test_all_sequential(self):
        """Test that steps without parallel_group stay sequential."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Sequential"),
            steps=[
                PipelineStep(name="Step 1", module="test.step1"),
                PipelineStep(name="Step 2", module="test.step2"),
                PipelineStep(name="Step 3", module="test.step3"),
            ],
        )

        runner = PipelineRunner(pipeline)
        batches = runner._group_steps_for_execution(pipeline.enabled_steps)

        assert len(batches) == 3
        assert all(len(batch) == 1 for batch in batches)

    def test_all_parallel(self):
        """Test that steps with same parallel_group are batched together."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Parallel"),
            steps=[
                PipelineStep(name="Step 1", module="test.step1", parallel_group="group1"),
                PipelineStep(name="Step 2", module="test.step2", parallel_group="group1"),
                PipelineStep(name="Step 3", module="test.step3", parallel_group="group1"),
            ],
        )

        runner = PipelineRunner(pipeline)
        batches = runner._group_steps_for_execution(pipeline.enabled_steps)

        assert len(batches) == 1
        assert len(batches[0]) == 3

    def test_mixed_sequential_and_parallel(self):
        """Test mixed sequential and parallel steps."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Mixed"),
            steps=[
                PipelineStep(name="Sequential 1", module="test.seq1"),
                PipelineStep(name="Parallel A1", module="test.a1", parallel_group="A"),
                PipelineStep(name="Parallel A2", module="test.a2", parallel_group="A"),
                PipelineStep(name="Sequential 2", module="test.seq2"),
                PipelineStep(name="Parallel B1", module="test.b1", parallel_group="B"),
                PipelineStep(name="Parallel B2", module="test.b2", parallel_group="B"),
            ],
        )

        runner = PipelineRunner(pipeline)
        batches = runner._group_steps_for_execution(pipeline.enabled_steps)

        assert len(batches) == 4
        assert len(batches[0]) == 1  # Sequential 1
        assert len(batches[1]) == 2  # Parallel A1, A2
        assert len(batches[2]) == 1  # Sequential 2
        assert len(batches[3]) == 2  # Parallel B1, B2

    def test_different_groups_separate_batches(self):
        """Test that different parallel groups create separate batches."""
        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Groups"),
            steps=[
                PipelineStep(name="Group A1", module="test.a1", parallel_group="A"),
                PipelineStep(name="Group A2", module="test.a2", parallel_group="A"),
                PipelineStep(name="Group B1", module="test.b1", parallel_group="B"),
                PipelineStep(name="Group B2", module="test.b2", parallel_group="B"),
            ],
        )

        runner = PipelineRunner(pipeline)
        batches = runner._group_steps_for_execution(pipeline.enabled_steps)

        assert len(batches) == 2
        assert batches[0][0].parallel_group == "A"
        assert batches[1][0].parallel_group == "B"


class TestParallelExecution:
    """Tests for parallel execution behavior."""

    def test_parallel_execution_runs_concurrently(self):
        """Test that parallel steps actually run concurrently."""
        execution_times = {}
        execution_threads = {}

        def slow_step1(ctx, params):
            execution_times["step1_start"] = time.time()
            execution_threads["step1"] = threading.current_thread().name
            time.sleep(0.1)
            execution_times["step1_end"] = time.time()
            ctx.add("step1_result", "done")
            return ctx

        def slow_step2(ctx, params):
            execution_times["step2_start"] = time.time()
            execution_threads["step2"] = threading.current_thread().name
            time.sleep(0.1)
            execution_times["step2_end"] = time.time()
            ctx.add("step2_result", "done")
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Concurrent"),
            steps=[
                PipelineStep(name="Slow 1", module="test.slow1", parallel_group="parallel"),
                PipelineStep(name="Slow 2", module="test.slow2", parallel_group="parallel"),
            ],
        )

        runner = PipelineRunner(pipeline, max_workers=2)

        def mock_resolve(path):
            if "slow1" in path:
                return slow_step1
            return slow_step2

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            start = time.time()
            ctx = runner.run(target="test.com")
            elapsed = time.time() - start

        # Both steps should be in context
        assert ctx.get("step1_result") == "done"
        assert ctx.get("step2_result") == "done"

        # Should run in ~0.1s (parallel) not ~0.2s (sequential)
        assert elapsed < 0.2, f"Parallel execution took {elapsed}s, expected <0.2s"

        # Steps should have started at nearly the same time
        assert abs(execution_times["step1_start"] - execution_times["step2_start"]) < 0.05

    def test_sequential_execution_flag(self):
        """Test that parallel=False forces sequential execution."""
        execution_order = []

        def step1(ctx, params):
            execution_order.append("step1")
            ctx.add("step1_result", True)
            return ctx

        def step2(ctx, params):
            execution_order.append("step2")
            ctx.add("step2_result", True)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Sequential Flag"),
            steps=[
                PipelineStep(name="Step 1", module="test.step1", parallel_group="group"),
                PipelineStep(name="Step 2", module="test.step2", parallel_group="group"),
            ],
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "step1" in path:
                return step1
            return step2

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(target="test.com", parallel=False)

        # Both should complete
        assert ctx.get("step1_result") is True
        assert ctx.get("step2_result") is True

    def test_parallel_results_merged(self):
        """Test that results from parallel steps are merged into context."""
        def step1(ctx, params):
            ctx.add("data_from_step1", {"key1": "value1"})
            ctx.add("shared_key", "from_step1")
            return ctx

        def step2(ctx, params):
            ctx.add("data_from_step2", {"key2": "value2"})
            ctx.add("other_key", "from_step2")
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Merge"),
            steps=[
                PipelineStep(name="Step 1", module="test.step1", parallel_group="parallel"),
                PipelineStep(name="Step 2", module="test.step2", parallel_group="parallel"),
            ],
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "step1" in path:
                return step1
            return step2

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(target="test.com")

        # Both step results should be merged
        assert ctx.get("data_from_step1") == {"key1": "value1"}
        assert ctx.get("data_from_step2") == {"key2": "value2"}
        assert ctx.get("other_key") == "from_step2"

    def test_parallel_error_with_continue_on_error(self):
        """Test that continue_on_error works in parallel execution."""
        def success_step(ctx, params):
            ctx.add("success_result", True)
            return ctx

        def failing_step(ctx, params):
            raise ValueError("Intentional failure")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="ErrorContinue"),
            steps=[
                PipelineStep(
                    name="Success",
                    module="test.success",
                    parallel_group="parallel",
                ),
                PipelineStep(
                    name="Failing",
                    module="test.failing",
                    parallel_group="parallel",
                    continue_on_error=True,
                ),
            ],
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "success" in path:
                return success_step
            return failing_step

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(target="test.com")

        # Success step should complete
        assert ctx.get("success_result") is True

    def test_parallel_error_without_continue_on_error(self):
        """Test that errors propagate when continue_on_error is False."""
        def success_step(ctx, params):
            time.sleep(0.05)  # Give failing step time to fail first
            ctx.add("success_result", True)
            return ctx

        def failing_step(ctx, params):
            raise ValueError("Intentional failure")

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="ErrorStop"),
            steps=[
                PipelineStep(
                    name="Success",
                    module="test.success",
                    parallel_group="parallel",
                ),
                PipelineStep(
                    name="Failing",
                    module="test.failing",
                    parallel_group="parallel",
                    continue_on_error=False,
                ),
            ],
        )

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "success" in path:
                return success_step
            return failing_step

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            with pytest.raises(RuntimeError, match="Parallel step failed"):
                runner.run(target="test.com")


class TestParallelWithRealModules:
    """Integration tests with real module execution."""

    @patch("redops.modules.recon.domains.get_dns_records")
    def test_parallel_recon_modules(self, mock_dns):
        """Test parallel execution of real recon modules."""
        mock_dns.return_value = ["192.0.2.1"]

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Parallel Recon"),
            steps=[
                PipelineStep(
                    name="Domain Profile",
                    module="recon.domains.profile_domain",
                    parallel_group="recon",
                ),
                PipelineStep(
                    name="DNS Enumeration",
                    module="recon.domains.enumerate_dns",
                    parallel_group="recon",
                ),
            ],
        )

        runner = PipelineRunner(pipeline)
        ctx = runner.run(target="example.com")

        # Both modules should have added their data
        assert ctx.get("domain_profile") is not None
        assert ctx.get("dns_enumeration") is not None


class TestMaxWorkers:
    """Tests for max_workers configuration."""

    def test_max_workers_limits_concurrency(self):
        """Test that max_workers limits concurrent execution."""
        concurrent_count = {"current": 0, "max": 0}
        lock = threading.Lock()

        def counting_step(ctx, params):
            with lock:
                concurrent_count["current"] += 1
                concurrent_count["max"] = max(
                    concurrent_count["max"],
                    concurrent_count["current"]
                )
            time.sleep(0.05)
            with lock:
                concurrent_count["current"] -= 1
            ctx.add(f"result_{params.get('id', 0)}", True)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Concurrency"),
            steps=[
                PipelineStep(name=f"Step {i}", module=f"test.step{i}", parallel_group="all", params={"id": i})
                for i in range(6)
            ],
        )

        runner = PipelineRunner(pipeline, max_workers=2)

        with patch.object(runner, "_resolve_module_function", return_value=counting_step):
            runner.run(target="test.com")

        # Should never exceed max_workers
        assert concurrent_count["max"] <= 2


class TestContextIsolation:
    """Tests for context isolation in parallel execution."""

    def test_parallel_steps_get_isolated_contexts(self):
        """Test that parallel steps don't interfere with each other."""
        def step1(ctx, params):
            # Modify context
            initial_value = ctx.get("shared_data", 0)
            time.sleep(0.02)  # Simulate work
            ctx.add("step1_saw", initial_value)
            ctx.add("shared_data", 100)
            return ctx

        def step2(ctx, params):
            # Modify context
            initial_value = ctx.get("shared_data", 0)
            time.sleep(0.02)  # Simulate work
            ctx.add("step2_saw", initial_value)
            ctx.add("shared_data", 200)
            return ctx

        pipeline = Pipeline(
            metadata=PipelineMetadata(name="Isolation"),
            steps=[
                PipelineStep(name="Step 1", module="test.step1", parallel_group="parallel"),
                PipelineStep(name="Step 2", module="test.step2", parallel_group="parallel"),
            ],
        )

        # Pre-populate context with shared data
        initial_ctx = Context(target="test.com")
        initial_ctx.add("shared_data", 42)

        runner = PipelineRunner(pipeline)

        def mock_resolve(path):
            if "step1" in path:
                return step1
            return step2

        with patch.object(runner, "_resolve_module_function", side_effect=mock_resolve):
            ctx = runner.run(initial_context=initial_ctx)

        # Both steps should have seen the original value
        assert ctx.get("step1_saw") == 42
        assert ctx.get("step2_saw") == 42


class TestSchemaParallelFields:
    """Tests for parallel-related schema fields."""

    def test_parallel_group_optional(self):
        """Test that parallel_group is optional."""
        step = PipelineStep(name="Test", module="test.module")
        assert step.parallel_group is None

    def test_parallel_group_set(self):
        """Test that parallel_group can be set."""
        step = PipelineStep(
            name="Test",
            module="test.module",
            parallel_group="my_group"
        )
        assert step.parallel_group == "my_group"

    def test_depends_on_default_empty(self):
        """Test that depends_on defaults to empty list."""
        step = PipelineStep(name="Test", module="test.module")
        assert step.depends_on == []

    def test_depends_on_can_be_set(self):
        """Test that depends_on can be set."""
        step = PipelineStep(
            name="Test",
            module="test.module",
            depends_on=["step1", "step2"]
        )
        assert step.depends_on == ["step1", "step2"]

    def test_pipeline_with_parallel_groups_from_dict(self):
        """Test loading a pipeline with parallel groups from dict."""
        pipeline_def = {
            "metadata": {"name": "Parallel Pipeline", "version": "1.0"},
            "steps": [
                {"name": "Setup", "module": "test.setup"},
                {"name": "Parallel A", "module": "test.a", "parallel_group": "group1"},
                {"name": "Parallel B", "module": "test.b", "parallel_group": "group1"},
                {"name": "Finalize", "module": "test.finalize"},
            ],
        }

        pipeline = PipelineLoader.load_from_dict(pipeline_def)

        assert pipeline.steps[0].parallel_group is None
        assert pipeline.steps[1].parallel_group == "group1"
        assert pipeline.steps[2].parallel_group == "group1"
        assert pipeline.steps[3].parallel_group is None
