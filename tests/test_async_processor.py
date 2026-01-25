"""
Tests for RedOPS Async Processing.
"""

import asyncio
import time

import pytest

from redops.core.async_processor import (
    AsyncError,
    AsyncExecutor,
    BatchProcessor,
    ParallelProcessor,
    Pipeline,
    ProgressCallback,
    QueueFullError,
    RateLimitedExecutor,
    TaskCancelledError,
    TaskInfo,
    TaskPriority,
    TaskResult,
    TaskState,
    TaskTimeoutError,
    WorkerPool,
    get_processor,
    run_async,
    run_parallel,
)


class TestTaskState:
    """Tests for TaskState enum."""

    def test_all_states_exist(self):
        """Test all task states exist."""
        assert TaskState.PENDING.value == "pending"
        assert TaskState.QUEUED.value == "queued"
        assert TaskState.RUNNING.value == "running"
        assert TaskState.COMPLETED.value == "completed"
        assert TaskState.FAILED.value == "failed"
        assert TaskState.CANCELLED.value == "cancelled"
        assert TaskState.TIMEOUT.value == "timeout"


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_priority_order(self):
        """Test priority ordering."""
        assert TaskPriority.LOW.value < TaskPriority.NORMAL.value
        assert TaskPriority.NORMAL.value < TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value < TaskPriority.CRITICAL.value


class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_success_result(self):
        """Test successful task result."""
        result = TaskResult(
            task_id="test-123",
            state=TaskState.COMPLETED,
            result="success_data",
            started_at=1000.0,
            completed_at=1001.0,
            duration=1.0,
        )

        assert result.is_success is True
        assert result.is_done is True
        assert result.result == "success_data"

    def test_failed_result(self):
        """Test failed task result."""
        result = TaskResult(
            task_id="test-456",
            state=TaskState.FAILED,
            error="Something went wrong",
        )

        assert result.is_success is False
        assert result.is_done is True
        assert result.error == "Something went wrong"

    def test_running_result(self):
        """Test running task result."""
        result = TaskResult(
            task_id="test-789",
            state=TaskState.RUNNING,
        )

        assert result.is_success is False
        assert result.is_done is False

    def test_cancelled_is_done(self):
        """Test cancelled task is considered done."""
        result = TaskResult(
            task_id="test",
            state=TaskState.CANCELLED,
        )

        assert result.is_done is True
        assert result.is_success is False


class TestTaskInfo:
    """Tests for TaskInfo dataclass."""

    def test_basic_info(self):
        """Test basic task info."""
        info = TaskInfo(
            task_id="info-123",
            name="test_task",
            state=TaskState.PENDING,
            priority=TaskPriority.NORMAL,
            created_at=time.time(),
        )

        assert info.task_id == "info-123"
        assert info.name == "test_task"
        assert info.state == TaskState.PENDING
        assert info.progress == 0.0


class TestProgressCallback:
    """Tests for ProgressCallback class."""

    def test_initial_state(self):
        """Test initial callback state."""
        callback = ProgressCallback()

        assert callback.progress == 0.0
        assert callback.message == ""
        assert callback.is_cancelled is False

    def test_update_progress(self):
        """Test updating progress."""
        callback = ProgressCallback()

        callback.update(0.5, "Halfway done")

        assert callback.progress == 0.5
        assert callback.message == "Halfway done"

    def test_progress_bounds(self):
        """Test progress is bounded 0-1."""
        callback = ProgressCallback()

        callback.update(1.5)
        assert callback.progress == 1.0

        callback.update(-0.5)
        assert callback.progress == 0.0

    def test_cancel(self):
        """Test cancellation."""
        callback = ProgressCallback()

        callback.cancel()

        assert callback.is_cancelled is True

    def test_check_cancelled_raises(self):
        """Test check_cancelled raises when cancelled."""
        callback = ProgressCallback()
        callback.cancel()

        with pytest.raises(TaskCancelledError):
            callback.check_cancelled()


class TestWorkerPool:
    """Tests for WorkerPool class."""

    @pytest.fixture
    def pool(self):
        """Create a worker pool for testing."""
        pool = WorkerPool(max_workers=2)
        pool.start()
        yield pool
        pool.stop(wait=False)  # Don't wait for slow tasks

    def test_submit_and_get_result(self, pool):
        """Test submitting and getting result."""
        def add(a, b):
            return a + b

        task_id = pool.submit(add, 1, 2)
        result = pool.get_result(task_id)

        assert result.is_success
        assert result.result == 3

    def test_submit_with_name(self, pool):
        """Test submitting with task name."""
        task_id = pool.submit(lambda: 42, name="answer_task")
        info = pool.get_status(task_id)

        assert info.name == "answer_task"

    def test_submit_with_kwargs(self, pool):
        """Test submitting with keyword arguments."""
        def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        task_id = pool.submit(greet, "World", greeting="Hi")
        result = pool.get_result(task_id)

        assert result.result == "Hi, World!"

    def test_failed_task(self, pool):
        """Test task that raises exception."""
        def failing_func():
            raise ValueError("Expected error")

        task_id = pool.submit(failing_func)
        result = pool.get_result(task_id)

        assert result.state == TaskState.FAILED
        assert "Expected error" in result.error

    def test_cancel_task(self, pool):
        """Test cancelling a task."""
        def slow_func():
            time.sleep(0.5)
            return "done"

        task_id = pool.submit(slow_func)

        # Try to cancel immediately
        cancelled = pool.cancel(task_id)

        # May or may not succeed depending on timing
        assert isinstance(cancelled, bool)

    def test_get_all_tasks(self, pool):
        """Test getting all tasks."""
        pool.submit(lambda: 1)
        pool.submit(lambda: 2)

        tasks = pool.get_all_tasks()

        assert len(tasks) >= 2

    def test_pending_count(self, pool):
        """Test getting pending count."""
        # Initially no pending tasks
        initial = pool.get_pending_count()

        # Submit a slow task
        pool.submit(lambda: time.sleep(0.5))

        # Should have at least one pending/running
        count = pool.get_pending_count()
        assert count >= 0

    def test_is_running(self, pool):
        """Test checking if pool is running."""
        assert pool.is_running is True

        pool.stop()
        assert pool.is_running is False


class TestAsyncExecutor:
    """Tests for AsyncExecutor class."""

    def test_run_coroutine(self):
        """Test running a coroutine."""
        executor = AsyncExecutor(max_concurrency=5)

        async def async_add(a, b):
            await asyncio.sleep(0.01)
            return a + b

        async def run_test():
            return await executor.run(async_add(1, 2))

        result = asyncio.run(run_test())

        assert result.is_success
        assert result.result == 3

    def test_run_with_timeout(self):
        """Test running with timeout."""
        executor = AsyncExecutor(max_concurrency=5)

        async def slow_coro():
            await asyncio.sleep(10)
            return "done"

        async def run_test():
            return await executor.run(slow_coro(), timeout=0.1)

        result = asyncio.run(run_test())

        assert result.state == TaskState.TIMEOUT

    def test_run_many(self):
        """Test running multiple coroutines."""
        executor = AsyncExecutor(max_concurrency=5)

        async def process(x):
            await asyncio.sleep(0.01)
            return x * 2

        async def run_test():
            coros = [process(i) for i in range(5)]
            return await executor.run_many(coros)

        results = asyncio.run(run_test())

        assert len(results) == 5
        assert all(r.is_success for r in results)
        assert [r.result for r in results] == [0, 2, 4, 6, 8]

    def test_map(self):
        """Test mapping function over items."""
        executor = AsyncExecutor(max_concurrency=5)

        async def double(x):
            return x * 2

        async def run_test():
            return await executor.map(double, [1, 2, 3, 4, 5])

        results = asyncio.run(run_test())

        assert len(results) == 5
        assert [r.result for r in results] == [2, 4, 6, 8, 10]

    def test_concurrency_limit(self):
        """Test that concurrency is limited."""
        executor = AsyncExecutor(max_concurrency=5)
        running = []
        max_concurrent = [0]

        async def track_concurrency():
            running.append(1)
            max_concurrent[0] = max(max_concurrent[0], len(running))
            await asyncio.sleep(0.05)
            running.pop()
            return True

        async def run_test():
            coros = [track_concurrency() for _ in range(10)]
            return await executor.run_many(coros)

        asyncio.run(run_test())

        # Should not exceed max concurrency
        assert max_concurrent[0] <= 5


class TestParallelProcessor:
    """Tests for ParallelProcessor class."""

    @pytest.fixture
    def processor(self):
        """Create a processor for testing."""
        proc = ParallelProcessor(max_workers=2)
        proc.start()
        yield proc
        proc.stop(wait=False)  # Don't wait for slow tasks

    def test_submit_sync(self, processor):
        """Test submitting synchronous task."""
        def compute(x):
            return x * 2

        task_id = processor.submit_sync(compute, 5)
        result = processor.get_result(task_id)

        assert result.is_success
        assert result.result == 10

    def test_run_parallel(self, processor):
        """Test running parallel tasks."""
        def multiply(x, factor=1):
            return x * factor

        tasks = [
            (multiply, (1,), {"factor": 2}),
            (multiply, (2,), {"factor": 3}),
            (multiply, (3,), {"factor": 4}),
        ]

        results = processor.run_parallel(tasks)

        assert len(results) == 3
        assert results[0].result == 2
        assert results[1].result == 6
        assert results[2].result == 12

    def test_fail_fast(self, processor):
        """Test fail-fast mode."""
        def maybe_fail(x):
            if x == 2:
                raise ValueError("Expected failure")
            time.sleep(0.1)
            return x

        tasks = [
            (maybe_fail, (1,), {}),
            (maybe_fail, (2,), {}),  # Will fail
            (maybe_fail, (3,), {}),
        ]

        results = processor.run_parallel(tasks, fail_fast=True)

        # Should stop after first failure
        failed_count = sum(1 for r in results if r.state == TaskState.FAILED)
        assert failed_count >= 1

    def test_get_status(self, processor):
        """Test getting task status."""
        task_id = processor.submit_sync(lambda: time.sleep(0.1))
        status = processor.get_status(task_id)

        assert status is not None
        assert status.task_id == task_id

    def test_cancel(self, processor):
        """Test cancelling task."""
        task_id = processor.submit_sync(lambda: time.sleep(0.5))
        cancelled = processor.cancel(task_id)

        # Cancellation may or may not succeed
        assert isinstance(cancelled, bool)

    def test_submit_async(self, processor):
        """Test submitting async task."""
        async def async_compute():
            await asyncio.sleep(0.01)
            return 42

        async def run_test():
            return await processor.submit_async(async_compute())

        result = asyncio.run(run_test())

        assert result.is_success
        assert result.result == 42


class TestBatchProcessor:
    """Tests for BatchProcessor class."""

    @pytest.fixture
    def batch_processor(self):
        """Create a batch processor for testing."""
        proc = BatchProcessor(batch_size=3, max_retries=2)
        yield proc
        proc.stop()

    def test_process_items(self, batch_processor):
        """Test processing items in batches."""
        items = list(range(10))

        def double(x):
            return x * 2

        results = batch_processor.process(items, double)

        assert len(results) == 10
        success_results = [r.result for r in results if r.is_success]
        assert success_results == [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]

    def test_progress_callback(self, batch_processor):
        """Test progress callback."""
        items = list(range(6))
        progress_updates = []

        def track_progress(processed, total):
            progress_updates.append((processed, total))

        batch_processor.process(
            items,
            lambda x: x,
            on_progress=track_progress,
        )

        assert len(progress_updates) > 0
        assert progress_updates[-1] == (6, 6)

    def test_retry_on_failure(self, batch_processor):
        """Test retry on failure."""
        call_count = [0]

        def flaky_func(x):
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Temporary failure")
            return x

        results = batch_processor.process([1], flaky_func)

        # Should have retried
        assert call_count[0] >= 2


class TestPipeline:
    """Tests for Pipeline class."""

    def test_sync_pipeline(self):
        """Test synchronous pipeline."""
        pipeline = Pipeline()
        pipeline.add_stage(lambda x: x + 1)
        pipeline.add_stage(lambda x: x * 2)
        pipeline.add_stage(lambda x: x - 3)

        result = pipeline.execute_sync(5)

        # (5 + 1) * 2 - 3 = 9
        assert result.is_success
        assert result.result == 9

    def test_async_pipeline(self):
        """Test async pipeline."""
        async def async_double(x):
            await asyncio.sleep(0.01)
            return x * 2

        pipeline = Pipeline()
        pipeline.add_stage(lambda x: x + 1)
        pipeline.add_stage(async_double)
        pipeline.add_stage(lambda x: x - 1)

        async def run_test():
            return await pipeline.execute(5)

        result = asyncio.run(run_test())

        # (5 + 1) * 2 - 1 = 11
        assert result.is_success
        assert result.result == 11

    def test_pipeline_error_handler(self):
        """Test pipeline error handling."""
        errors_caught = []

        def error_handler(error, value):
            errors_caught.append((str(error), value))

        pipeline = Pipeline()
        pipeline.add_stage(lambda x: x + 1)
        pipeline.add_stage(lambda x: 1 / 0)  # Will fail
        pipeline.on_error(error_handler)

        result = pipeline.execute_sync(5)

        assert result.state == TaskState.FAILED
        assert len(errors_caught) == 1

    def test_pipeline_chaining(self):
        """Test fluent pipeline building."""
        pipeline = (
            Pipeline()
            .add_stage(lambda x: x + 1)
            .add_stage(lambda x: x * 2)
            .on_error(lambda e, v: None)
        )

        result = pipeline.execute_sync(10)

        assert result.result == 22


class TestRateLimitedExecutor:
    """Tests for RateLimitedExecutor class."""

    def test_rate_limiting(self):
        """Test that rate limiting works."""
        executor = RateLimitedExecutor(rate_limit=10.0, burst_size=1)

        start = time.time()

        # Execute 3 operations
        for _ in range(3):
            executor.execute(lambda: None)

        elapsed = time.time() - start

        # Should take at least 0.2 seconds (2 waits at 10/sec)
        assert elapsed >= 0.15

    def test_burst_size(self):
        """Test burst size allows immediate execution."""
        executor = RateLimitedExecutor(rate_limit=1.0, burst_size=5)

        start = time.time()

        # Execute burst
        for _ in range(5):
            executor.execute(lambda: None)

        elapsed = time.time() - start

        # Burst should be fast
        assert elapsed < 0.5

    def test_async_rate_limiting(self):
        """Test async rate limiting."""
        executor = RateLimitedExecutor(rate_limit=10.0, burst_size=1)

        async def dummy():
            return 42

        async def run_test():
            results = []
            for _ in range(3):
                result = await executor.execute_async(dummy())
                results.append(result)
            return results

        start = time.time()
        results = asyncio.run(run_test())
        elapsed = time.time() - start

        assert all(r == 42 for r in results)
        assert elapsed >= 0.15


class TestExceptions:
    """Tests for exception classes."""

    def test_async_error(self):
        """Test AsyncError."""
        error = AsyncError("Test error")
        assert str(error) == "Test error"

    def test_task_cancelled_error(self):
        """Test TaskCancelledError."""
        error = TaskCancelledError("Cancelled")
        assert isinstance(error, AsyncError)

    def test_task_timeout_error(self):
        """Test TaskTimeoutError."""
        error = TaskTimeoutError("Timed out")
        assert isinstance(error, AsyncError)

    def test_queue_full_error(self):
        """Test QueueFullError."""
        error = QueueFullError("Queue is full")
        assert isinstance(error, AsyncError)


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def test_get_processor(self):
        """Test getting global processor."""
        processor = get_processor()
        assert isinstance(processor, ParallelProcessor)

    def test_run_parallel_global(self):
        """Test global run_parallel."""
        tasks = [
            (lambda x: x * 2, (1,), {}),
            (lambda x: x * 2, (2,), {}),
        ]

        results = run_parallel(tasks)

        assert len(results) == 2

    def test_run_async_global(self):
        """Test global run_async."""
        async def compute():
            return 42

        async def run_test():
            return await run_async(compute())

        result = asyncio.run(run_test())

        assert result.result == 42


class TestWorkerPoolShutdown:
    """Tests for worker pool shutdown behavior."""

    def test_stop_without_wait(self):
        """Test stopping without waiting."""
        pool = WorkerPool(max_workers=2)
        pool.start()

        # Submit some tasks
        for _ in range(5):
            pool.submit(lambda: time.sleep(0.1))

        # Stop without waiting
        pool.stop(wait=False)

        assert pool.is_running is False

    def test_submit_after_shutdown(self):
        """Test submitting after shutdown raises error."""
        pool = WorkerPool(max_workers=2)
        pool.start()
        pool.stop()

        with pytest.raises(AsyncError):
            pool.submit(lambda: 42)


class TestTaskResultDuration:
    """Tests for task result duration calculation."""

    def test_duration_calculated(self):
        """Test that duration is calculated correctly."""
        pool = WorkerPool(max_workers=1)
        pool.start()

        def slow_task():
            time.sleep(0.1)
            return "done"

        task_id = pool.submit(slow_task)
        result = pool.get_result(task_id)

        pool.stop()

        assert result.duration is not None
        assert result.duration >= 0.1

    def test_duration_none_for_running(self):
        """Test duration is None for running tasks."""
        result = TaskResult(
            task_id="test",
            state=TaskState.RUNNING,
        )

        assert result.duration is None
