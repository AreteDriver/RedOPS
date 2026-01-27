"""
Async Processing for RedOPS.

Provides parallel module execution, async I/O, task queues,
and concurrency management.
"""

import asyncio
import concurrent.futures
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Generic, TypeVar

T = TypeVar("T")
R = TypeVar("R")


class TaskState(Enum):
    """Task execution states."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class TaskResult(Generic[T]):
    """Result of a task execution."""

    task_id: str
    state: TaskState
    result: T | None = None
    error: str | None = None
    started_at: float | None = None
    completed_at: float | None = None
    duration: float | None = None

    @property
    def is_success(self) -> bool:
        """Check if task completed successfully."""
        return self.state == TaskState.COMPLETED and self.error is None

    @property
    def is_done(self) -> bool:
        """Check if task is done (success or failure)."""
        return self.state in (
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELLED,
            TaskState.TIMEOUT,
        )


@dataclass
class TaskInfo:
    """Information about a queued task."""

    task_id: str
    name: str
    state: TaskState
    priority: TaskPriority
    created_at: float
    started_at: float | None = None
    completed_at: float | None = None
    progress: float = 0.0
    message: str = ""
    metadata: dict = field(default_factory=dict)


class AsyncError(Exception):
    """Base exception for async processing errors."""

    pass


class TaskCancelledError(AsyncError):
    """Raised when a task is cancelled."""

    pass


class TaskTimeoutError(AsyncError):
    """Raised when a task times out."""

    pass


class QueueFullError(AsyncError):
    """Raised when task queue is full."""

    pass


class ProgressCallback:
    """Callback interface for tracking task progress."""

    def __init__(self):
        self._progress = 0.0
        self._message = ""
        self._cancelled = False

    @property
    def progress(self) -> float:
        """Get current progress (0.0 to 1.0)."""
        return self._progress

    @property
    def message(self) -> str:
        """Get current status message."""
        return self._message

    @property
    def is_cancelled(self) -> bool:
        """Check if task was cancelled."""
        return self._cancelled

    def update(self, progress: float, message: str = "") -> None:
        """Update progress."""
        self._progress = min(1.0, max(0.0, progress))
        self._message = message

    def cancel(self) -> None:
        """Mark task as cancelled."""
        self._cancelled = True

    def check_cancelled(self) -> None:
        """Raise if cancelled."""
        if self._cancelled:
            raise TaskCancelledError("Task was cancelled")


class WorkerPool:
    """
    Thread-based worker pool for parallel execution.
    """

    def __init__(
        self,
        max_workers: int = 4,
        queue_size: int = 100,
        thread_name_prefix: str = "redops-worker",
    ):
        self._max_workers = max_workers
        self._queue_size = queue_size
        self._thread_name_prefix = thread_name_prefix

        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._tasks: dict[str, concurrent.futures.Future] = {}
        self._task_info: dict[str, TaskInfo] = {}
        self._lock = threading.RLock()
        self._shutdown = False

    def start(self) -> None:
        """Start the worker pool."""
        with self._lock:
            if self._executor is None:
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix=self._thread_name_prefix,
                )
                self._shutdown = False

    def stop(self, wait: bool = True, timeout: float | None = None) -> None:
        """Stop the worker pool."""
        with self._lock:
            self._shutdown = True
            if self._executor:
                self._executor.shutdown(wait=wait)
                self._executor = None

    def submit(
        self,
        func: Callable[..., T],
        *args,
        name: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: float | None = None,
        **kwargs,
    ) -> str:
        """
        Submit a task for execution.

        Args:
            func: Function to execute
            *args: Positional arguments
            name: Task name for tracking
            priority: Task priority
            timeout: Execution timeout in seconds
            **kwargs: Keyword arguments

        Returns:
            Task ID
        """
        if self._shutdown:
            raise AsyncError("Worker pool is shut down")

        if self._executor is None:
            self.start()

        task_id = str(uuid.uuid4())
        now = time.time()

        info = TaskInfo(
            task_id=task_id,
            name=name or func.__name__,
            state=TaskState.QUEUED,
            priority=priority,
            created_at=now,
        )

        with self._lock:
            self._task_info[task_id] = info

        def wrapper():
            with self._lock:
                info.state = TaskState.RUNNING
                info.started_at = time.time()

            try:
                if timeout:
                    # Use threading for timeout
                    result_container = [None]
                    error_container = [None]

                    def target():
                        try:
                            result_container[0] = func(*args, **kwargs)
                        except Exception as e:
                            error_container[0] = e

                    thread = threading.Thread(target=target)
                    thread.start()
                    thread.join(timeout=timeout)

                    if thread.is_alive():
                        raise TaskTimeoutError(f"Task {task_id} timed out")

                    if error_container[0]:
                        raise error_container[0]

                    return result_container[0]
                else:
                    return func(*args, **kwargs)

            except Exception:
                with self._lock:
                    info.state = TaskState.FAILED
                    info.completed_at = time.time()
                raise
            finally:
                with self._lock:
                    if info.state == TaskState.RUNNING:
                        info.state = TaskState.COMPLETED
                    info.completed_at = time.time()

        future = self._executor.submit(wrapper)

        with self._lock:
            self._tasks[task_id] = future

        return task_id

    def get_result(
        self,
        task_id: str,
        timeout: float | None = None,
    ) -> TaskResult:
        """
        Get the result of a task.

        Args:
            task_id: Task ID
            timeout: Maximum time to wait

        Returns:
            TaskResult with the outcome
        """
        with self._lock:
            if task_id not in self._tasks:
                return TaskResult(
                    task_id=task_id,
                    state=TaskState.FAILED,
                    error="Task not found",
                )

            future = self._tasks[task_id]
            info = self._task_info.get(task_id)

        try:
            result = future.result(timeout=timeout)
            return TaskResult(
                task_id=task_id,
                state=TaskState.COMPLETED,
                result=result,
                started_at=info.started_at if info else None,
                completed_at=info.completed_at if info else None,
                duration=(
                    info.completed_at - info.started_at
                    if info and info.started_at and info.completed_at
                    else None
                ),
            )
        except concurrent.futures.TimeoutError:
            return TaskResult(
                task_id=task_id,
                state=TaskState.RUNNING,
            )
        except concurrent.futures.CancelledError:
            return TaskResult(
                task_id=task_id,
                state=TaskState.CANCELLED,
                error="Task was cancelled",
            )
        except Exception as e:
            return TaskResult(
                task_id=task_id,
                state=TaskState.FAILED,
                error=str(e),
            )

    def cancel(self, task_id: str) -> bool:
        """
        Cancel a task.

        Args:
            task_id: Task ID

        Returns:
            True if task was cancelled
        """
        with self._lock:
            if task_id not in self._tasks:
                return False

            future = self._tasks[task_id]
            cancelled = future.cancel()

            if cancelled:
                info = self._task_info.get(task_id)
                if info:
                    info.state = TaskState.CANCELLED

            return cancelled

    def get_status(self, task_id: str) -> TaskInfo | None:
        """Get task status."""
        with self._lock:
            return self._task_info.get(task_id)

    def get_all_tasks(self) -> list[TaskInfo]:
        """Get all task info."""
        with self._lock:
            return list(self._task_info.values())

    def get_pending_count(self) -> int:
        """Get count of pending/running tasks."""
        with self._lock:
            return sum(
                1
                for info in self._task_info.values()
                if info.state
                in (TaskState.PENDING, TaskState.QUEUED, TaskState.RUNNING)
            )

    @property
    def is_running(self) -> bool:
        """Check if pool is running."""
        return self._executor is not None and not self._shutdown


class AsyncExecutor:
    """
    Asyncio-based executor for async/await operations.
    """

    def __init__(self, max_concurrency: int = 10):
        self._max_concurrency = max_concurrency
        self._semaphore: asyncio.Semaphore | None = None
        self._tasks: dict[str, asyncio.Task] = {}
        self._results: dict[str, TaskResult] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    async def _ensure_semaphore(self) -> asyncio.Semaphore:
        """Ensure semaphore is created."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrency)
        return self._semaphore

    async def run(
        self,
        coro: Coroutine[Any, Any, T],
        name: str = "",
        timeout: float | None = None,
    ) -> TaskResult[T]:
        """
        Run a coroutine with concurrency control.

        Args:
            coro: Coroutine to run
            name: Task name
            timeout: Execution timeout

        Returns:
            TaskResult with outcome
        """
        task_id = str(uuid.uuid4())
        semaphore = await self._ensure_semaphore()
        started_at = time.time()

        try:
            async with semaphore:
                if timeout:
                    result = await asyncio.wait_for(coro, timeout=timeout)
                else:
                    result = await coro

                completed_at = time.time()
                return TaskResult(
                    task_id=task_id,
                    state=TaskState.COMPLETED,
                    result=result,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration=completed_at - started_at,
                )

        except asyncio.TimeoutError:
            return TaskResult(
                task_id=task_id,
                state=TaskState.TIMEOUT,
                error="Task timed out",
                started_at=started_at,
            )
        except asyncio.CancelledError:
            return TaskResult(
                task_id=task_id,
                state=TaskState.CANCELLED,
                error="Task was cancelled",
                started_at=started_at,
            )
        except Exception as e:
            return TaskResult(
                task_id=task_id,
                state=TaskState.FAILED,
                error=str(e),
                started_at=started_at,
            )

    async def run_many(
        self,
        coros: list[Coroutine[Any, Any, T]],
        timeout: float | None = None,
        return_exceptions: bool = True,
    ) -> list[TaskResult[T]]:
        """
        Run multiple coroutines concurrently.

        Args:
            coros: List of coroutines
            timeout: Timeout for all tasks
            return_exceptions: Whether to return exceptions in results

        Returns:
            List of TaskResults
        """
        tasks = [self.run(coro, timeout=timeout) for coro in coros]
        return await asyncio.gather(*tasks, return_exceptions=return_exceptions)

    async def map(
        self,
        func: Callable[[T], Coroutine[Any, Any, R]],
        items: list[T],
        timeout: float | None = None,
    ) -> list[TaskResult[R]]:
        """
        Map an async function over items concurrently.

        Args:
            func: Async function to apply
            items: Items to process
            timeout: Per-item timeout

        Returns:
            List of TaskResults
        """
        coros = [func(item) for item in items]
        return await self.run_many(coros, timeout=timeout)


class ParallelProcessor:
    """
    High-level parallel processor for RedOPS modules.
    """

    def __init__(
        self,
        max_workers: int = 4,
        max_async_concurrency: int = 10,
    ):
        self._worker_pool = WorkerPool(max_workers=max_workers)
        self._async_executor = AsyncExecutor(max_concurrency=max_async_concurrency)
        self._progress_callbacks: dict[str, ProgressCallback] = {}

    def start(self) -> None:
        """Start the processor."""
        self._worker_pool.start()

    def stop(self, wait: bool = True) -> None:
        """Stop the processor."""
        self._worker_pool.stop(wait=wait)

    def submit_sync(
        self,
        func: Callable[..., T],
        *args,
        name: str = "",
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: float | None = None,
        progress_callback: ProgressCallback | None = None,
        **kwargs,
    ) -> str:
        """
        Submit a synchronous task.

        Args:
            func: Function to execute
            *args: Positional arguments
            name: Task name
            priority: Task priority
            timeout: Execution timeout
            progress_callback: Optional progress callback
            **kwargs: Keyword arguments

        Returns:
            Task ID
        """
        task_id = self._worker_pool.submit(
            func,
            *args,
            name=name,
            priority=priority,
            timeout=timeout,
            **kwargs,
        )

        if progress_callback:
            self._progress_callbacks[task_id] = progress_callback

        return task_id

    async def submit_async(
        self,
        coro: Coroutine[Any, Any, T],
        name: str = "",
        timeout: float | None = None,
    ) -> TaskResult[T]:
        """
        Submit an async task.

        Args:
            coro: Coroutine to execute
            name: Task name
            timeout: Execution timeout

        Returns:
            TaskResult with outcome
        """
        return await self._async_executor.run(coro, name=name, timeout=timeout)

    def run_parallel(
        self,
        tasks: list[tuple[Callable[..., T], tuple, dict]],
        timeout: float | None = None,
        fail_fast: bool = False,
    ) -> list[TaskResult[T]]:
        """
        Run multiple tasks in parallel.

        Args:
            tasks: List of (func, args, kwargs) tuples
            timeout: Total timeout
            fail_fast: Whether to stop on first failure

        Returns:
            List of TaskResults
        """
        task_ids = []
        for func, args, kwargs in tasks:
            task_id = self._worker_pool.submit(
                func,
                *args,
                timeout=timeout,
                **kwargs,
            )
            task_ids.append(task_id)

        results = []
        for task_id in task_ids:
            result = self._worker_pool.get_result(task_id, timeout=timeout)
            results.append(result)

            if fail_fast and not result.is_success:
                # Cancel remaining tasks
                for remaining_id in task_ids[len(results) :]:
                    self._worker_pool.cancel(remaining_id)
                break

        return results

    async def run_parallel_async(
        self,
        coros: list[Coroutine[Any, Any, T]],
        timeout: float | None = None,
    ) -> list[TaskResult[T]]:
        """
        Run multiple async tasks in parallel.

        Args:
            coros: List of coroutines
            timeout: Timeout for all tasks

        Returns:
            List of TaskResults
        """
        return await self._async_executor.run_many(coros, timeout=timeout)

    def get_result(self, task_id: str, timeout: float | None = None) -> TaskResult:
        """Get result of a task."""
        return self._worker_pool.get_result(task_id, timeout=timeout)

    def cancel(self, task_id: str) -> bool:
        """Cancel a task."""
        # Also cancel via progress callback if available
        if task_id in self._progress_callbacks:
            self._progress_callbacks[task_id].cancel()
        return self._worker_pool.cancel(task_id)

    def get_status(self, task_id: str) -> TaskInfo | None:
        """Get task status."""
        return self._worker_pool.get_status(task_id)

    def get_progress(self, task_id: str) -> float:
        """Get task progress."""
        if task_id in self._progress_callbacks:
            return self._progress_callbacks[task_id].progress
        return 0.0


class BatchProcessor:
    """
    Batch processing with chunking and retry support.
    """

    def __init__(
        self,
        batch_size: int = 10,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_workers: int = 4,
    ):
        self._batch_size = batch_size
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._processor = ParallelProcessor(max_workers=max_workers)
        self._processor.start()

    def process(
        self,
        items: list[T],
        processor_func: Callable[[T], R],
        on_progress: Callable[[int, int], None] | None = None,
    ) -> list[TaskResult[R]]:
        """
        Process items in batches.

        Args:
            items: Items to process
            processor_func: Function to apply to each item
            on_progress: Progress callback (processed, total)

        Returns:
            List of TaskResults
        """
        results = []
        total = len(items)

        for i in range(0, total, self._batch_size):
            batch = items[i : i + self._batch_size]
            batch_tasks = [(processor_func, (item,), {}) for item in batch]

            batch_results = self._processor.run_parallel(batch_tasks)

            # Retry failed items
            for j, result in enumerate(batch_results):
                if not result.is_success:
                    retried = self._retry_item(
                        processor_func,
                        batch[j],
                    )
                    batch_results[j] = retried

            results.extend(batch_results)

            if on_progress:
                on_progress(min(i + self._batch_size, total), total)

        return results

    def _retry_item(
        self,
        func: Callable[[T], R],
        item: T,
    ) -> TaskResult[R]:
        """Retry a failed item."""
        for attempt in range(self._max_retries):
            time.sleep(self._retry_delay * (attempt + 1))

            task_id = self._processor.submit_sync(func, item)
            result = self._processor.get_result(task_id)

            if result.is_success:
                return result

        return result  # Return last failed result

    def stop(self) -> None:
        """Stop the processor."""
        self._processor.stop()


class Pipeline:
    """
    Pipeline for chaining async operations.
    """

    def __init__(self):
        self._stages: list[Callable] = []
        self._error_handlers: list[Callable] = []

    def add_stage(self, func: Callable) -> "Pipeline":
        """Add a processing stage."""
        self._stages.append(func)
        return self

    def on_error(self, handler: Callable) -> "Pipeline":
        """Add error handler."""
        self._error_handlers.append(handler)
        return self

    async def execute(self, initial_value: Any) -> TaskResult:
        """
        Execute the pipeline.

        Args:
            initial_value: Initial input value

        Returns:
            TaskResult with final output
        """
        task_id = str(uuid.uuid4())
        started_at = time.time()
        current = initial_value

        try:
            for stage in self._stages:
                if asyncio.iscoroutinefunction(stage):
                    current = await stage(current)
                else:
                    current = stage(current)

            return TaskResult(
                task_id=task_id,
                state=TaskState.COMPLETED,
                result=current,
                started_at=started_at,
                completed_at=time.time(),
            )

        except Exception as e:
            for handler in self._error_handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(e, current)
                    else:
                        handler(e, current)
                except Exception:
                    pass  # Ignore handler errors

            return TaskResult(
                task_id=task_id,
                state=TaskState.FAILED,
                error=str(e),
                started_at=started_at,
                completed_at=time.time(),
            )

    def execute_sync(self, initial_value: Any) -> TaskResult:
        """
        Execute pipeline synchronously.

        Args:
            initial_value: Initial input value

        Returns:
            TaskResult with final output
        """
        return asyncio.run(self.execute(initial_value))


class RateLimitedExecutor:
    """
    Executor with rate limiting.
    """

    def __init__(
        self,
        rate_limit: float = 1.0,  # requests per second
        burst_size: int = 1,
    ):
        self._rate_limit = rate_limit
        self._burst_size = burst_size
        self._tokens = burst_size
        self._last_update = time.time()
        self._lock = threading.Lock()

    def _acquire_token(self) -> bool:
        """Try to acquire a rate limit token."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            self._last_update = now

            # Add tokens based on elapsed time
            self._tokens = min(
                self._burst_size,
                self._tokens + elapsed * self._rate_limit,
            )

            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False

    def _wait_for_token(self) -> None:
        """Wait until a token is available."""
        while not self._acquire_token():
            time.sleep(1.0 / self._rate_limit)

    def execute(
        self,
        func: Callable[..., T],
        *args,
        **kwargs,
    ) -> T:
        """
        Execute a function with rate limiting.

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result
        """
        self._wait_for_token()
        return func(*args, **kwargs)

    async def execute_async(
        self,
        coro: Coroutine[Any, Any, T],
    ) -> T:
        """
        Execute a coroutine with rate limiting.

        Args:
            coro: Coroutine to execute

        Returns:
            Coroutine result
        """
        while not self._acquire_token():
            await asyncio.sleep(1.0 / self._rate_limit)
        return await coro


# Convenience functions
_global_processor: ParallelProcessor | None = None


def get_processor() -> ParallelProcessor:
    """Get the global parallel processor."""
    global _global_processor
    if _global_processor is None:
        _global_processor = ParallelProcessor()
        _global_processor.start()
    return _global_processor


def run_parallel(
    tasks: list[tuple[Callable, tuple, dict]],
    timeout: float | None = None,
) -> list[TaskResult]:
    """Run tasks in parallel using global processor."""
    return get_processor().run_parallel(tasks, timeout=timeout)


async def run_async(
    coro: Coroutine[Any, Any, T],
    timeout: float | None = None,
) -> TaskResult[T]:
    """Run async task using global processor."""
    return await get_processor().submit_async(coro, timeout=timeout)
