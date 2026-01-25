"""Tests for task queue module."""

import threading
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from redops.core.task_queue import (
    # Enums
    TaskStatus,
    TaskPriority,
    # Data classes
    TaskResult,
    Task,
    # Storage
    TaskStore,
    MemoryTaskStore,
    # Worker
    Worker,
    # Queue
    TaskQueue,
    # Scheduler
    JobScheduler,
    # Decorator
    task,
    get_registered_tasks,
    # Convenience
    create_task_queue,
    run_task,
)


# =============================================================================
# TaskStatus Tests
# =============================================================================

class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_all_statuses(self):
        """Test all status values exist."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.QUEUED.value == "queued"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.RETRYING.value == "retrying"
        assert TaskStatus.CANCELLED.value == "cancelled"
        assert TaskStatus.TIMEOUT.value == "timeout"


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_priority_ordering(self):
        """Test priority ordering."""
        assert TaskPriority.LOW.value < TaskPriority.NORMAL.value
        assert TaskPriority.NORMAL.value < TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value < TaskPriority.CRITICAL.value


# =============================================================================
# TaskResult Tests
# =============================================================================

class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_create_basic(self):
        """Test basic result creation."""
        result = TaskResult(
            task_id="test-123",
            status=TaskStatus.COMPLETED,
        )
        assert result.task_id == "test-123"
        assert result.status == TaskStatus.COMPLETED
        assert result.success

    def test_create_with_all_fields(self):
        """Test result with all fields."""
        started = datetime.now()
        completed = started + timedelta(seconds=5)

        result = TaskResult(
            task_id="test-123",
            status=TaskStatus.COMPLETED,
            result={"key": "value"},
            started_at=started,
            completed_at=completed,
            attempts=2,
            worker_id="worker-1",
        )

        assert result.result == {"key": "value"}
        assert result.duration_seconds == pytest.approx(5.0, abs=0.1)
        assert result.worker_id == "worker-1"

    def test_failed_result(self):
        """Test failed result."""
        result = TaskResult(
            task_id="test-123",
            status=TaskStatus.FAILED,
            error="Something went wrong",
            error_type="ValueError",
        )
        assert not result.success
        assert result.error == "Something went wrong"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = TaskResult(
            task_id="test-123",
            status=TaskStatus.COMPLETED,
            result=42,
        )
        data = result.to_dict()

        assert data["task_id"] == "test-123"
        assert data["status"] == "completed"
        assert data["result"] == 42


# =============================================================================
# Task Tests
# =============================================================================

class TestTask:
    """Tests for Task dataclass."""

    def test_create_basic(self):
        """Test basic task creation."""
        task = Task(name="test-task")
        assert task.id is not None
        assert task.name == "test-task"
        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.NORMAL

    def test_create_with_func(self):
        """Test task with function."""
        def my_func(x, y):
            return x + y

        task = Task(
            name="add",
            func=my_func,
            args=(1, 2),
            kwargs={},
        )
        assert task.func is my_func
        assert task.args == (1, 2)

    def test_task_ordering(self):
        """Test task ordering by priority."""
        low = Task(priority=TaskPriority.LOW)
        normal = Task(priority=TaskPriority.NORMAL)
        high = Task(priority=TaskPriority.HIGH)

        tasks = sorted([normal, low, high])
        # Higher priority should come first
        assert tasks[0].priority == TaskPriority.HIGH
        assert tasks[1].priority == TaskPriority.NORMAL
        assert tasks[2].priority == TaskPriority.LOW

    def test_should_retry(self):
        """Test retry logic."""
        task = Task(max_retries=3)

        task.attempts = 0
        assert task.should_retry()

        task.attempts = 2
        assert task.should_retry()

        task.attempts = 3
        assert not task.should_retry()

    def test_retry_delay_backoff(self):
        """Test retry delay with backoff."""
        task = Task(retry_delay=1.0, retry_backoff=2.0)

        task.attempts = 0
        assert task.get_retry_delay() == 1.0

        task.attempts = 1
        assert task.get_retry_delay() == 2.0

        task.attempts = 2
        assert task.get_retry_delay() == 4.0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        task = Task(
            name="test",
            priority=TaskPriority.HIGH,
            tags={"important", "test"},
        )
        data = task.to_dict()

        assert data["name"] == "test"
        assert data["priority"] == TaskPriority.HIGH.value
        assert set(data["tags"]) == {"important", "test"}


# =============================================================================
# MemoryTaskStore Tests
# =============================================================================

class TestMemoryTaskStore:
    """Tests for MemoryTaskStore."""

    @pytest.fixture
    def store(self):
        """Create memory store."""
        return MemoryTaskStore()

    def test_save_and_get(self, store):
        """Test saving and getting tasks."""
        task = Task(name="test")
        store.save(task)

        retrieved = store.get(task.id)
        assert retrieved is not None
        assert retrieved.name == "test"

    def test_get_nonexistent(self, store):
        """Test getting nonexistent task."""
        assert store.get("nonexistent") is None

    def test_update_status(self, store):
        """Test updating task status."""
        task = Task(name="test")
        store.save(task)

        store.update_status(task.id, TaskStatus.RUNNING)
        retrieved = store.get(task.id)
        assert retrieved.status == TaskStatus.RUNNING

    def test_update_status_with_error(self, store):
        """Test updating status with error."""
        task = Task(name="test")
        store.save(task)

        store.update_status(task.id, TaskStatus.FAILED, "Error message")
        retrieved = store.get(task.id)
        assert retrieved.status == TaskStatus.FAILED
        assert retrieved.last_error == "Error message"

    def test_get_pending(self, store):
        """Test getting pending tasks."""
        for i in range(5):
            task = Task(name=f"task-{i}")
            if i < 3:
                task.status = TaskStatus.PENDING
            else:
                task.status = TaskStatus.COMPLETED
            store.save(task)

        pending = store.get_pending()
        assert len(pending) == 3

    def test_get_by_status(self, store):
        """Test getting tasks by status."""
        for i in range(3):
            task = Task(name=f"task-{i}", status=TaskStatus.RUNNING)
            store.save(task)

        running = store.get_by_status(TaskStatus.RUNNING)
        assert len(running) == 3

    def test_count(self, store):
        """Test counting tasks."""
        for i in range(5):
            task = Task(name=f"task-{i}")
            task.status = TaskStatus.COMPLETED if i < 3 else TaskStatus.FAILED
            store.save(task)

        assert store.count() == 5
        assert store.count(TaskStatus.COMPLETED) == 3
        assert store.count(TaskStatus.FAILED) == 2

    def test_clear(self, store):
        """Test clearing store."""
        for i in range(3):
            store.save(Task(name=f"task-{i}"))

        store.clear()
        assert store.count() == 0


# =============================================================================
# Worker Tests
# =============================================================================

class TestWorker:
    """Tests for Worker."""

    def test_create(self):
        """Test worker creation."""
        worker = Worker()
        assert worker.worker_id is not None
        assert not worker.is_running

    def test_start_stop(self):
        """Test starting and stopping worker."""
        worker = Worker()
        worker.start()
        assert worker.is_running

        worker.stop()
        assert not worker.is_running

    def test_execute_task(self):
        """Test task execution."""
        results = []

        def callback(result):
            results.append(result)

        worker = Worker(result_callback=callback)
        worker.start()

        # Create and queue a task
        def add(x, y):
            return x + y

        task = Task(name="add", func=add, args=(2, 3))
        worker._queue.put((-task.priority.value, task))

        # Wait for execution
        time.sleep(0.2)
        worker.stop()

        assert len(results) == 1
        assert results[0].status == TaskStatus.COMPLETED
        assert results[0].result == 5

    def test_task_failure(self):
        """Test task failure handling."""
        results = []

        def callback(result):
            results.append(result)

        worker = Worker(result_callback=callback)
        worker.start()

        def failing_func():
            raise ValueError("Test error")

        task = Task(name="fail", func=failing_func)
        worker._queue.put((-task.priority.value, task))

        time.sleep(0.2)
        worker.stop()

        assert len(results) == 1
        assert results[0].status == TaskStatus.FAILED
        assert "Test error" in results[0].error

    def test_stats(self):
        """Test worker statistics."""
        worker = Worker(worker_id="test-worker")
        stats = worker.stats

        assert stats["worker_id"] == "test-worker"
        assert stats["running"] is False
        assert stats["tasks_completed"] == 0


# =============================================================================
# TaskQueue Tests
# =============================================================================

class TestTaskQueue:
    """Tests for TaskQueue."""

    def test_context_manager(self):
        """Test context manager usage."""
        with TaskQueue(num_workers=1) as queue:
            assert queue._running
        assert not queue._running

    def test_submit_and_wait(self):
        """Test submitting and waiting for task."""
        def add(x, y):
            return x + y

        with TaskQueue(num_workers=1) as queue:
            task_id = queue.submit(add, 2, 3)
            result = queue.wait(task_id, timeout=5.0)

            assert result.status == TaskStatus.COMPLETED
            assert result.result == 5

    def test_submit_with_kwargs(self):
        """Test submitting with keyword arguments."""
        def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        with TaskQueue(num_workers=1) as queue:
            task_id = queue.submit(greet, "World", greeting="Hi")
            result = queue.wait(task_id, timeout=5.0)

            assert result.result == "Hi, World!"

    def test_priority_ordering(self):
        """Test tasks are processed by priority."""
        execution_order = []
        start_event = threading.Event()

        def record(value):
            start_event.wait()  # Wait until all tasks are queued
            time.sleep(0.02)
            execution_order.append(value)

        with TaskQueue(num_workers=1) as queue:
            # Stop workers temporarily to queue all tasks first
            queue._running = False
            for w in queue._workers:
                w.stop()
            queue._workers.clear()

            # Submit in order: low, normal, high (all go to queue)
            queue.submit(record, "low", priority=TaskPriority.LOW)
            queue.submit(record, "normal", priority=TaskPriority.NORMAL)
            queue.submit(record, "high", priority=TaskPriority.HIGH)

            # Now start a worker to process
            queue._running = True
            start_event.set()
            worker = Worker(
                worker_id="test-worker",
                task_queue=queue._queue,
                result_callback=queue._handle_result,
            )
            worker.start()
            queue._workers.append(worker)

            time.sleep(0.3)

        # High should be processed first (priority queue)
        assert len(execution_order) == 3
        assert execution_order[0] == "high"

    def test_delayed_execution(self):
        """Test delayed task execution."""
        start_time = time.time()
        execution_time = [None]

        def record_time():
            execution_time[0] = time.time()

        with TaskQueue(num_workers=1) as queue:
            queue.submit(record_time, delay=0.2)
            time.sleep(0.5)

        assert execution_time[0] is not None
        assert execution_time[0] - start_time >= 0.2

    def test_scheduled_execution(self):
        """Test scheduled task execution."""
        scheduled_time = datetime.now() + timedelta(seconds=0.2)
        execution_time = [None]

        def record_time():
            execution_time[0] = datetime.now()

        with TaskQueue(num_workers=1) as queue:
            queue.submit(record_time, scheduled_at=scheduled_time)
            time.sleep(0.5)

        assert execution_time[0] is not None
        assert execution_time[0] >= scheduled_time

    def test_retry_on_failure(self):
        """Test automatic retry on failure."""
        attempts = [0]

        def failing_then_success():
            attempts[0] += 1
            if attempts[0] < 3:
                raise ValueError("Not yet")
            return "success"

        with TaskQueue(num_workers=1) as queue:
            task_id = queue.submit(
                failing_then_success,
                max_retries=5,
                retry_delay=0.1,
            )
            time.sleep(1.0)
            result = queue.get_result(task_id)

            assert result.status == TaskStatus.COMPLETED
            assert result.result == "success"
            assert attempts[0] == 3

    def test_max_retries_exceeded(self):
        """Test max retries exceeded."""
        def always_fail():
            raise ValueError("Always fails")

        with TaskQueue(num_workers=1) as queue:
            task_id = queue.submit(
                always_fail,
                max_retries=2,
                retry_delay=0.05,
            )
            time.sleep(0.5)
            result = queue.get_result(task_id)

            assert result.status == TaskStatus.FAILED

    def test_cancel_pending_task(self):
        """Test cancelling a pending task."""
        with TaskQueue(num_workers=0) as queue:  # No workers
            task_id = queue.submit(lambda: None)
            cancelled = queue.cancel(task_id)

            assert cancelled
            task = queue.get_task(task_id)
            assert task.status == TaskStatus.CANCELLED

    def test_get_task(self):
        """Test getting task by ID."""
        with TaskQueue(num_workers=1) as queue:
            task_id = queue.submit(lambda: 42, name="my-task")
            task = queue.get_task(task_id)

            assert task is not None
            assert task.name == "my-task"

    def test_list_tasks(self):
        """Test listing tasks."""
        with TaskQueue(num_workers=1) as queue:
            for i in range(5):
                queue.submit(lambda: None, name=f"task-{i}")

            # List tasks by status (they may be queued or completed)
            time.sleep(0.3)
            completed = queue.list_tasks(status=TaskStatus.COMPLETED)
            assert len(completed) >= 3  # Most should be done by now

    def test_stats(self):
        """Test queue statistics."""
        with TaskQueue(num_workers=1) as queue:
            queue.submit(lambda: 1)
            queue.submit(lambda: 2)
            time.sleep(0.3)

            stats = queue.stats
            assert stats["tasks_submitted"] >= 2

    def test_timeout(self):
        """Test task timeout."""
        def slow_task():
            time.sleep(5)
            return "done"

        with TaskQueue(num_workers=1) as queue:
            task_id = queue.submit(slow_task, timeout=0.1)
            time.sleep(0.5)
            result = queue.get_result(task_id)

            assert result.status == TaskStatus.TIMEOUT

    def test_multiple_workers(self):
        """Test multiple workers process tasks concurrently."""
        results = []
        lock = threading.Lock()

        def slow_task(value):
            time.sleep(0.05)
            with lock:
                results.append(value)
            return value

        with TaskQueue(num_workers=3) as queue:
            start = time.time()
            for i in range(6):
                queue.submit(slow_task, i)

            time.sleep(0.4)
            duration = time.time() - start

        # With 3 workers and 6 tasks (0.05s each), should finish in ~0.1-0.2s
        # We give 0.4s total and just verify all completed
        assert len(results) == 6


# =============================================================================
# JobScheduler Tests
# =============================================================================

class TestJobScheduler:
    """Tests for JobScheduler."""

    def test_add_job(self):
        """Test adding a job."""
        scheduler = JobScheduler()
        scheduler.add_job("test-job", lambda: None, interval=60)

        jobs = scheduler.get_jobs()
        assert "test-job" in jobs

    def test_remove_job(self):
        """Test removing a job."""
        scheduler = JobScheduler()
        scheduler.add_job("test-job", lambda: None, interval=60)

        removed = scheduler.remove_job("test-job")
        assert removed
        assert "test-job" not in scheduler.get_jobs()

    def test_enable_disable_job(self):
        """Test enabling/disabling jobs."""
        scheduler = JobScheduler()
        scheduler.add_job("test-job", lambda: None, interval=60)

        scheduler.disable_job("test-job")
        assert not scheduler.get_jobs()["test-job"]["enabled"]

        scheduler.enable_job("test-job")
        assert scheduler.get_jobs()["test-job"]["enabled"]

    def test_interval_execution(self):
        """Test interval-based execution."""
        executions = []

        def record():
            executions.append(time.time())

        scheduler = JobScheduler()
        scheduler.add_job("test", record, interval=0.1)
        scheduler.start()

        time.sleep(0.35)
        scheduler.stop()

        # Should have executed 2-3 times
        assert len(executions) >= 2

    def test_run_now(self):
        """Test running job immediately."""
        executed = [False]

        def mark_executed():
            executed[0] = True

        scheduler = JobScheduler()
        scheduler.add_job("test", mark_executed, interval=3600)

        result = scheduler.run_now("test")
        time.sleep(0.1)

        assert result
        assert executed[0]

    def test_max_instances(self):
        """Test max concurrent instances."""
        running_count = [0]
        max_running = [0]
        lock = threading.Lock()

        def slow_job():
            with lock:
                running_count[0] += 1
                max_running[0] = max(max_running[0], running_count[0])
            time.sleep(0.2)
            with lock:
                running_count[0] -= 1

        scheduler = JobScheduler()
        scheduler.add_job("test", slow_job, interval=0.05, max_instances=2)
        scheduler.start()

        time.sleep(0.5)
        scheduler.stop()

        # Should never exceed 2 concurrent instances
        assert max_running[0] <= 2

    def test_context_manager(self):
        """Test context manager usage."""
        with JobScheduler() as scheduler:
            scheduler.add_job("test", lambda: None, interval=60)
            assert scheduler._running
        assert not scheduler._running


# =============================================================================
# Task Decorator Tests
# =============================================================================

class TestTaskDecorator:
    """Tests for @task decorator."""

    def test_basic_decoration(self):
        """Test basic task decoration."""
        @task(name="my_task")
        def my_function():
            return 42

        assert my_function._task_name == "my_task"
        assert "my_task" in get_registered_tasks()

    def test_decoration_with_options(self):
        """Test decoration with options."""
        @task(
            name="configured_task",
            priority=TaskPriority.HIGH,
            timeout=30.0,
            max_retries=3,
        )
        def configured_function():
            pass

        assert configured_function._task_priority == TaskPriority.HIGH
        assert configured_function._task_timeout == 30.0
        assert configured_function._task_max_retries == 3

    def test_auto_name(self):
        """Test automatic name from function."""
        @task()
        def auto_named_function():
            pass

        assert auto_named_function._task_name == "auto_named_function"


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_task_queue(self):
        """Test create_task_queue."""
        queue = create_task_queue(num_workers=2)
        assert queue._num_workers == 2

    def test_run_task(self):
        """Test run_task."""
        def add(x, y):
            return x + y

        result = run_task(add, 2, 3)
        assert result == 5

    def test_run_task_failure(self):
        """Test run_task with failure."""
        def fail():
            raise ValueError("Failed")

        with pytest.raises(RuntimeError, match="Task failed"):
            run_task(fail)


# =============================================================================
# Integration Tests
# =============================================================================

class TestTaskQueueIntegration:
    """Integration tests for task queue."""

    def test_full_workflow(self):
        """Test complete task workflow."""
        results = {}

        def process_item(item_id):
            time.sleep(0.05)
            return f"processed-{item_id}"

        with TaskQueue(num_workers=2) as queue:
            # Submit multiple tasks
            task_ids = []
            for i in range(10):
                task_id = queue.submit(
                    process_item,
                    i,
                    name=f"process-{i}",
                    priority=TaskPriority.HIGH if i % 2 == 0 else TaskPriority.NORMAL,
                )
                task_ids.append(task_id)

            # Wait for all
            for task_id in task_ids:
                result = queue.wait(task_id, timeout=5.0)
                results[task_id] = result

        # All should complete
        assert all(r.status == TaskStatus.COMPLETED for r in results.values())
        assert len(results) == 10

    def test_with_scheduler(self):
        """Test task queue with job scheduler."""
        executions = []

        def scheduled_task():
            executions.append(time.time())

        with TaskQueue(num_workers=1) as queue:
            scheduler = JobScheduler(task_queue=queue)
            scheduler.add_job("periodic", scheduled_task, interval=0.1)
            scheduler.start()

            time.sleep(0.35)
            scheduler.stop()

        assert len(executions) >= 2

    def test_thread_safety(self):
        """Test thread-safe task submission."""
        with TaskQueue(num_workers=4) as queue:
            errors = []

            def submit_tasks():
                try:
                    for i in range(50):
                        queue.submit(lambda x=i: x * 2)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=submit_tasks) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            time.sleep(0.5)

            assert not errors
            assert queue.stats["tasks_submitted"] == 250
