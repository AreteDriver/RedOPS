"""
Task Queue - Distributed task processing and job scheduling.
Provides async task execution, job scheduling, and worker management.
"""

import heapq
import logging
import queue
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Callable,
    TypeVar,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class TaskResult:
    """Result of task execution."""

    task_id: str
    status: TaskStatus
    result: Any = None
    error: str | None = None
    error_type: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attempts: int = 0
    worker_id: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        """Get task duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def success(self) -> bool:
        """Check if task succeeded."""
        return self.status == TaskStatus.COMPLETED

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "error_type": self.error_type,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "attempts": self.attempts,
            "duration_seconds": self.duration_seconds,
            "worker_id": self.worker_id,
        }


@dataclass
class Task:
    """
    Represents a task to be executed.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    func: Callable | None = None
    args: tuple = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    scheduled_at: datetime | None = None
    timeout: float | None = None
    max_retries: int = 0
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Execution state
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    last_error: str | None = None

    def __lt__(self, other: "Task") -> bool:
        """Compare for priority queue ordering."""
        # Higher priority first, then earlier scheduled time
        if self.priority.value != other.priority.value:
            return self.priority.value > other.priority.value
        self_time = self.scheduled_at or self.created_at
        other_time = other.scheduled_at or other.created_at
        return self_time < other_time

    def should_retry(self) -> bool:
        """Check if task should be retried."""
        return self.attempts < self.max_retries

    def get_retry_delay(self) -> float:
        """Calculate retry delay with backoff."""
        return self.retry_delay * (self.retry_backoff**self.attempts)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (without func)."""
        return {
            "id": self.id,
            "name": self.name,
            "args": list(self.args),
            "kwargs": self.kwargs,
            "priority": self.priority.value,
            "created_at": self.created_at.isoformat(),
            "scheduled_at": self.scheduled_at.isoformat()
            if self.scheduled_at
            else None,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "retry_backoff": self.retry_backoff,
            "tags": list(self.tags),
            "metadata": self.metadata,
            "status": self.status.value,
            "attempts": self.attempts,
            "last_error": self.last_error,
        }


class TaskStore(ABC):
    """Abstract base class for task storage."""

    @abstractmethod
    def save(self, task: Task) -> None:
        """Save a task."""
        pass

    @abstractmethod
    def get(self, task_id: str) -> Task | None:
        """Get a task by ID."""
        pass

    @abstractmethod
    def update_status(
        self, task_id: str, status: TaskStatus, error: str | None = None
    ) -> None:
        """Update task status."""
        pass

    @abstractmethod
    def get_pending(self, limit: int = 100) -> list[Task]:
        """Get pending tasks."""
        pass

    @abstractmethod
    def get_by_status(self, status: TaskStatus, limit: int = 100) -> list[Task]:
        """Get tasks by status."""
        pass


class MemoryTaskStore(TaskStore):
    """In-memory task storage."""

    def __init__(self):
        """Initialize memory store."""
        self._tasks: dict[str, Task] = {}
        self._lock = threading.RLock()

    def save(self, task: Task) -> None:
        """Save a task."""
        with self._lock:
            self._tasks[task.id] = task

    def get(self, task_id: str) -> Task | None:
        """Get a task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def update_status(
        self, task_id: str, status: TaskStatus, error: str | None = None
    ) -> None:
        """Update task status."""
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = status
                if error:
                    self._tasks[task_id].last_error = error

    def get_pending(self, limit: int = 100) -> list[Task]:
        """Get pending tasks."""
        with self._lock:
            pending = [
                t for t in self._tasks.values() if t.status == TaskStatus.PENDING
            ]
            return sorted(pending)[:limit]

    def get_by_status(self, status: TaskStatus, limit: int = 100) -> list[Task]:
        """Get tasks by status."""
        with self._lock:
            matching = [t for t in self._tasks.values() if t.status == status]
            return matching[:limit]

    def clear(self) -> None:
        """Clear all tasks."""
        with self._lock:
            self._tasks.clear()

    def count(self, status: TaskStatus | None = None) -> int:
        """Count tasks."""
        with self._lock:
            if status:
                return sum(1 for t in self._tasks.values() if t.status == status)
            return len(self._tasks)


class Worker:
    """
    Worker that executes tasks.
    """

    def __init__(
        self,
        worker_id: str | None = None,
        task_queue: queue.Queue | None = None,
        result_callback: Callable[[TaskResult], None] | None = None,
    ):
        """
        Initialize worker.
        Args:
            worker_id: Unique worker identifier
            task_queue: Queue to pull tasks from
            result_callback: Callback for task results
        """
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self._queue = task_queue or queue.Queue()
        self._result_callback = result_callback
        self._thread: threading.Thread | None = None
        self._running = False
        self._current_task: Task | None = None
        self._tasks_completed = 0
        self._tasks_failed = 0

    def start(self) -> None:
        """Start the worker."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name=self.worker_id,
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the worker."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run_loop(self) -> None:
        """Main worker loop."""
        while self._running:
            try:
                item = self._queue.get(timeout=0.5)
                if item is None:
                    break
                # Handle both tuple (priority, task) and plain task
                if isinstance(item, tuple):
                    _, task = item
                else:
                    task = item
                if task is None:
                    break
                self._execute_task(task)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {self.worker_id} error: {e}")

    def _execute_task(self, task: Task) -> None:
        """Execute a single task."""
        self._current_task = task
        task.status = TaskStatus.RUNNING
        task.attempts += 1
        result = TaskResult(
            task_id=task.id,
            status=TaskStatus.RUNNING,
            started_at=datetime.now(),
            attempts=task.attempts,
            worker_id=self.worker_id,
        )
        try:
            # Execute with timeout if specified
            if task.func is None:
                raise ValueError("Task has no function to execute")
            if task.timeout:
                output = self._execute_with_timeout(task)
            else:
                output = task.func(*task.args, **task.kwargs)
            result.result = output
            result.status = TaskStatus.COMPLETED
            task.status = TaskStatus.COMPLETED
            self._tasks_completed += 1
        except TimeoutError as e:
            result.status = TaskStatus.TIMEOUT
            result.error = str(e)
            result.error_type = "TimeoutError"
            task.status = TaskStatus.TIMEOUT
            task.last_error = str(e)
            self._tasks_failed += 1
        except Exception as e:
            result.error = str(e)
            result.error_type = type(e).__name__
            task.last_error = str(e)
            if task.should_retry():
                result.status = TaskStatus.RETRYING
                task.status = TaskStatus.RETRYING
                # Re-queue with delay
                delay = task.get_retry_delay()
                task.scheduled_at = datetime.now() + timedelta(seconds=delay)
            else:
                result.status = TaskStatus.FAILED
                task.status = TaskStatus.FAILED
                self._tasks_failed += 1
        finally:
            result.completed_at = datetime.now()
            self._current_task = None
            if self._result_callback:
                try:
                    self._result_callback(result)
                except Exception as e:
                    logger.error(f"Result callback failed: {e}")

    def _execute_with_timeout(self, task: Task) -> Any:
        """Execute task with timeout."""
        result_container = {"result": None, "error": None}

        def target():
            try:
                result_container["result"] = task.func(*task.args, **task.kwargs)
            except Exception as e:
                result_container["error"] = e

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout=task.timeout)
        if thread.is_alive():
            raise TimeoutError(f"Task timed out after {task.timeout} seconds")
        if result_container["error"]:
            raise result_container["error"]
        return result_container["result"]

    @property
    def is_running(self) -> bool:
        """Check if worker is running."""
        return self._running

    @property
    def is_busy(self) -> bool:
        """Check if worker is executing a task."""
        return self._current_task is not None

    @property
    def stats(self) -> dict[str, Any]:
        """Get worker statistics."""
        return {
            "worker_id": self.worker_id,
            "running": self._running,
            "busy": self.is_busy,
            "tasks_completed": self._tasks_completed,
            "tasks_failed": self._tasks_failed,
            "current_task": self._current_task.id if self._current_task else None,
        }


class TaskQueue:
    """
    Task queue for managing and executing tasks.
    Features:
    - Priority-based task ordering
    - Multiple workers
    - Retry logic with backoff
    - Task scheduling
    - Result tracking
    """

    def __init__(
        self,
        num_workers: int = 1,
        store: TaskStore | None = None,
        max_queue_size: int = 10000,
    ):
        """
        Initialize task queue.
        Args:
            num_workers: Number of worker threads
            store: Optional task store for persistence
            max_queue_size: Maximum queue size
        """
        self._num_workers = num_workers
        self._store = store or MemoryTaskStore()
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=max_queue_size)
        self._workers: list[Worker] = []
        self._results: dict[str, TaskResult] = {}
        self._result_events: dict[str, threading.Event] = {}
        self._running = False
        self._lock = threading.RLock()
        self._scheduler_thread: threading.Thread | None = None
        self._scheduled_tasks: list[Task] = []
        # Statistics
        self._stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "tasks_retried": 0,
        }

    def start(self) -> None:
        """Start the task queue and workers."""
        if self._running:
            return
        self._running = True
        # Start workers
        for i in range(self._num_workers):
            worker = Worker(
                worker_id=f"worker-{i}",
                task_queue=self._queue,
                result_callback=self._handle_result,
            )
            worker.start()
            self._workers.append(worker)
        # Start scheduler
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="task-scheduler",
            daemon=True,
        )
        self._scheduler_thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the task queue and workers."""
        self._running = False
        # Signal workers to stop
        for _ in self._workers:
            try:
                self._queue.put((float("inf"), None))
            except queue.Full:
                pass
        # Stop workers
        for worker in self._workers:
            worker.stop(timeout=timeout)
        self._workers.clear()
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=timeout)
            self._scheduler_thread = None

    def submit(
        self,
        func: Callable,
        *args,
        name: str | None = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: float | None = None,
        max_retries: int = 0,
        retry_delay: float = 1.0,
        delay: float | None = None,
        scheduled_at: datetime | None = None,
        tags: set[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs,
    ) -> str:
        """
        Submit a task for execution.
        Args:
            func: Function to execute
            *args: Positional arguments
            name: Task name
            priority: Task priority
            timeout: Execution timeout in seconds
            max_retries: Maximum retry attempts
            retry_delay: Initial retry delay
            delay: Delay before execution (seconds)
            scheduled_at: Specific time to execute
            tags: Task tags
            metadata: Task metadata
            **kwargs: Keyword arguments
        Returns:
            Task ID
        """
        task = Task(
            name=name or func.__name__,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            tags=tags or set(),
            metadata=metadata or {},
        )
        # Handle scheduling
        if scheduled_at:
            task.scheduled_at = scheduled_at
        elif delay:
            task.scheduled_at = datetime.now() + timedelta(seconds=delay)
        with self._lock:
            self._store.save(task)
            self._result_events[task.id] = threading.Event()
            self._stats["tasks_submitted"] += 1
            if task.scheduled_at and task.scheduled_at > datetime.now():
                # Schedule for later
                heapq.heappush(self._scheduled_tasks, task)
                task.status = TaskStatus.PENDING
            else:
                # Queue immediately
                self._enqueue(task)
        return task.id

    def _enqueue(self, task: Task) -> None:
        """Add task to queue."""
        task.status = TaskStatus.QUEUED
        self._store.update_status(task.id, TaskStatus.QUEUED)
        # Priority queue uses (priority_value, task) where lower = higher priority
        # We negate to make higher TaskPriority values process first
        self._queue.put((-task.priority.value, task))

    def _handle_result(self, result: TaskResult) -> None:
        """Handle task result."""
        with self._lock:
            self._results[result.task_id] = result
            self._store.update_status(result.task_id, result.status, result.error)
            if result.status == TaskStatus.COMPLETED:
                self._stats["tasks_completed"] += 1
            elif result.status == TaskStatus.FAILED:
                self._stats["tasks_failed"] += 1
            elif result.status == TaskStatus.RETRYING:
                self._stats["tasks_retried"] += 1
                # Re-schedule for retry
                task = self._store.get(result.task_id)
                if task:
                    heapq.heappush(self._scheduled_tasks, task)
            # Signal waiters
            event = self._result_events.get(result.task_id)
            if event:
                event.set()

    def _scheduler_loop(self) -> None:
        """Scheduler loop for delayed tasks."""
        while self._running:
            try:
                now = datetime.now()
                with self._lock:
                    # Check for tasks ready to run
                    while self._scheduled_tasks:
                        task = self._scheduled_tasks[0]
                        if task.scheduled_at and task.scheduled_at <= now:
                            heapq.heappop(self._scheduled_tasks)
                            if task.status in (TaskStatus.PENDING, TaskStatus.RETRYING):
                                self._enqueue(task)
                        else:
                            break
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

    def get_result(
        self, task_id: str, timeout: float | None = None
    ) -> TaskResult | None:
        """
        Get task result, optionally waiting for completion.
        Args:
            task_id: Task ID
            timeout: Maximum wait time in seconds
        Returns:
            TaskResult or None if not found/timed out
        """
        event = self._result_events.get(task_id)
        if event:
            event.wait(timeout=timeout)
        with self._lock:
            return self._results.get(task_id)

    def wait(self, task_id: str, timeout: float | None = None) -> TaskResult:
        """
        Wait for task to complete.
        Args:
            task_id: Task ID
            timeout: Maximum wait time
        Returns:
            TaskResult
        Raises:
            TimeoutError: If timeout exceeded
            KeyError: If task not found
        """
        result = self.get_result(task_id, timeout)
        if result is None:
            raise KeyError(f"Task {task_id} not found")
        if result.status in (TaskStatus.PENDING, TaskStatus.QUEUED, TaskStatus.RUNNING):
            raise TimeoutError(f"Task {task_id} did not complete in time")
        return result

    def cancel(self, task_id: str) -> bool:
        """
        Cancel a pending task.
        Args:
            task_id: Task ID
        Returns:
            True if cancelled, False if not found or already running
        """
        with self._lock:
            task = self._store.get(task_id)
            if task and task.status in (TaskStatus.PENDING, TaskStatus.QUEUED):
                task.status = TaskStatus.CANCELLED
                self._store.update_status(task_id, TaskStatus.CANCELLED)
                return True
            return False

    def get_task(self, task_id: str) -> Task | None:
        """Get a task by ID."""
        return self._store.get(task_id)

    def list_tasks(
        self,
        status: TaskStatus | None = None,
        limit: int = 100,
    ) -> list[Task]:
        """List tasks."""
        if status:
            return self._store.get_by_status(status, limit)
        return self._store.get_pending(limit)

    @property
    def queue_size(self) -> int:
        """Get current queue size."""
        return self._queue.qsize()

    @property
    def stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        with self._lock:
            return {
                **self._stats,
                "queue_size": self.queue_size,
                "scheduled_tasks": len(self._scheduled_tasks),
                "workers": [w.stats for w in self._workers],
            }

    def __enter__(self) -> "TaskQueue":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.stop()


class JobScheduler:
    """
    Job scheduler for recurring tasks.
    Supports cron-like scheduling and interval-based execution.
    """

    def __init__(self, task_queue: TaskQueue | None = None):
        """
        Initialize scheduler.
        Args:
            task_queue: Task queue for job execution
        """
        self._queue = task_queue
        self._jobs: dict[str, dict[str, Any]] = {}
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()

    def add_job(
        self,
        job_id: str,
        func: Callable,
        interval: float | None = None,
        cron: str | None = None,
        args: tuple = (),
        kwargs: dict[str, Any] | None = None,
        max_instances: int = 1,
        enabled: bool = True,
    ) -> None:
        """
        Add a scheduled job.
        Args:
            job_id: Unique job identifier
            func: Function to execute
            interval: Interval in seconds
            cron: Cron expression (simplified: "* * * * *")
            args: Function arguments
            kwargs: Function keyword arguments
            max_instances: Maximum concurrent instances
            enabled: Whether job is enabled
        """
        if not interval and not cron:
            raise ValueError("Either interval or cron must be specified")
        with self._lock:
            self._jobs[job_id] = {
                "func": func,
                "interval": interval,
                "cron": cron,
                "args": args,
                "kwargs": kwargs or {},
                "max_instances": max_instances,
                "enabled": enabled,
                "last_run": None,
                "next_run": self._calculate_next_run(interval, cron),
                "running_instances": 0,
            }

    def remove_job(self, job_id: str) -> bool:
        """Remove a job."""
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                return True
            return False

    def enable_job(self, job_id: str) -> None:
        """Enable a job."""
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["enabled"] = True

    def disable_job(self, job_id: str) -> None:
        """Disable a job."""
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["enabled"] = False

    def _calculate_next_run(
        self,
        interval: float | None,
        cron: str | None,
        last_run: datetime | None = None,
    ) -> datetime:
        """Calculate next run time."""
        now = datetime.now()
        if interval:
            if last_run:
                return last_run + timedelta(seconds=interval)
            # First run should happen immediately
            return now
        if cron:
            # Simplified cron parsing (minute, hour, day, month, weekday)
            # For now, just use interval-like behavior
            # Full cron parsing would require a library like croniter
            return now + timedelta(minutes=1)
        return now

    def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name="job-scheduler",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _run_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                now = datetime.now()
                with self._lock:
                    for job_id, job in self._jobs.items():
                        if not job["enabled"]:
                            continue
                        if job["next_run"] <= now:
                            if job["running_instances"] < job["max_instances"]:
                                self._execute_job(job_id, job)
                time.sleep(0.05)  # Check more frequently
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")

    def _execute_job(self, job_id: str, job: dict[str, Any]) -> None:
        """Execute a job."""
        job["running_instances"] += 1
        job["last_run"] = datetime.now()
        job["next_run"] = self._calculate_next_run(
            job["interval"],
            job["cron"],
            job["last_run"],
        )

        def run_job():
            try:
                if self._queue:
                    self._queue.submit(
                        job["func"],
                        *job["args"],
                        name=job_id,
                        **job["kwargs"],
                    )
                else:
                    job["func"](*job["args"], **job["kwargs"])
            except Exception as e:
                logger.error(f"Job {job_id} failed: {e}")
            finally:
                with self._lock:
                    if job_id in self._jobs:
                        self._jobs[job_id]["running_instances"] -= 1

        thread = threading.Thread(target=run_job, daemon=True)
        thread.start()

    def get_jobs(self) -> dict[str, dict[str, Any]]:
        """Get all jobs."""
        with self._lock:
            return {
                job_id: {
                    "interval": job["interval"],
                    "cron": job["cron"],
                    "enabled": job["enabled"],
                    "last_run": job["last_run"].isoformat()
                    if job["last_run"]
                    else None,
                    "next_run": job["next_run"].isoformat()
                    if job["next_run"]
                    else None,
                    "running_instances": job["running_instances"],
                }
                for job_id, job in self._jobs.items()
            }

    def run_now(self, job_id: str) -> bool:
        """Run a job immediately."""
        with self._lock:
            if job_id not in self._jobs:
                return False
            job = self._jobs[job_id]
            if job["running_instances"] < job["max_instances"]:
                self._execute_job(job_id, job)
                return True
            return False

    def __enter__(self) -> "JobScheduler":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.stop()


# Decorator for defining tasks
_task_registry: dict[str, Callable] = {}


def task(
    name: str | None = None,
    priority: TaskPriority = TaskPriority.NORMAL,
    timeout: float | None = None,
    max_retries: int = 0,
):
    """
    Decorator to register a function as a task.
    Usage:
        @task(name="my_task", max_retries=3)
        def my_function(arg1, arg2):
            return arg1 + arg2
    """

    def decorator(func: Callable) -> Callable:
        task_name = name or func.__name__
        _task_registry[task_name] = func
        # Store task metadata on function
        func._task_name = task_name
        func._task_priority = priority
        func._task_timeout = timeout
        func._task_max_retries = max_retries
        return func

    return decorator


def get_registered_tasks() -> dict[str, Callable]:
    """Get all registered tasks."""
    return _task_registry.copy()


# Convenience functions
def create_task_queue(
    num_workers: int = 2,
    max_queue_size: int = 10000,
) -> TaskQueue:
    """Create a task queue with common settings."""
    return TaskQueue(
        num_workers=num_workers,
        max_queue_size=max_queue_size,
    )


def run_task(
    func: Callable,
    *args,
    timeout: float | None = None,
    **kwargs,
) -> Any:
    """
    Run a task synchronously (blocking).
    Args:
        func: Function to execute
        *args: Positional arguments
        timeout: Execution timeout
        **kwargs: Keyword arguments
    Returns:
        Function result
    """
    with TaskQueue(num_workers=1) as queue:
        task_id = queue.submit(func, *args, timeout=timeout, **kwargs)
        result = queue.wait(task_id, timeout=timeout)
        if result.status == TaskStatus.COMPLETED:
            return result.result
        elif result.error:
            raise RuntimeError(f"Task failed: {result.error}")
        else:
            raise RuntimeError(f"Task ended with status: {result.status.value}")
