"""
Job Queue - Core job definitions and queue interface.
"""

import json
import logging
import pickle
import signal
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar
from uuid import uuid4

logger = logging.getLogger(__name__)

T = TypeVar("T")


class JobStatus(Enum):
    """Job execution status."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class JobPriority(Enum):
    """Job priority levels."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class Job:
    """
    Represents a job to be executed.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    func_name: str = ""
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)

    # Scheduling
    priority: JobPriority = JobPriority.NORMAL
    queue: str = "default"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scheduled_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Execution
    timeout: Optional[float] = None  # seconds
    max_retries: int = 0
    retry_delay: float = 60.0  # seconds
    retry_backoff: float = 2.0
    attempts: int = 0

    # State
    status: JobStatus = JobStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    error_traceback: Optional[str] = None
    worker_id: Optional[str] = None

    # Metadata
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "func_name": self.func_name,
            "args": list(self.args),
            "kwargs": self.kwargs,
            "priority": self.priority.value,
            "queue": self.queue,
            "created_at": self.created_at.isoformat(),
            "scheduled_at": self.scheduled_at.isoformat() if self.scheduled_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "retry_backoff": self.retry_backoff,
            "attempts": self.attempts,
            "status": self.status.value,
            "error": self.error,
            "worker_id": self.worker_id,
            "tags": list(self.tags),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Job":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data.get("name", ""),
            func_name=data["func_name"],
            args=tuple(data.get("args", [])),
            kwargs=data.get("kwargs", {}),
            priority=JobPriority(data.get("priority", 1)),
            queue=data.get("queue", "default"),
            created_at=datetime.fromisoformat(data["created_at"]),
            scheduled_at=datetime.fromisoformat(data["scheduled_at"]) if data.get("scheduled_at") else None,
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            timeout=data.get("timeout"),
            max_retries=data.get("max_retries", 0),
            retry_delay=data.get("retry_delay", 60.0),
            retry_backoff=data.get("retry_backoff", 2.0),
            attempts=data.get("attempts", 0),
            status=JobStatus(data.get("status", "pending")),
            error=data.get("error"),
            worker_id=data.get("worker_id"),
            tags=set(data.get("tags", [])),
            metadata=data.get("metadata", {}),
        )

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get job duration."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def should_retry(self) -> bool:
        """Check if job should be retried."""
        return self.attempts < self.max_retries

    def get_retry_delay(self) -> float:
        """Calculate retry delay with exponential backoff."""
        return self.retry_delay * (self.retry_backoff ** self.attempts)


@dataclass
class JobResult:
    """Result of job execution."""

    job_id: str
    status: JobStatus
    result: Any = None
    error: Optional[str] = None
    error_traceback: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    attempts: int = 0
    worker_id: Optional[str] = None

    @property
    def success(self) -> bool:
        """Check if job succeeded."""
        return self.status == JobStatus.COMPLETED

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get execution duration."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "attempts": self.attempts,
            "worker_id": self.worker_id,
        }


class JobBackend(ABC):
    """Abstract base for job storage backends."""

    @abstractmethod
    def enqueue(self, job: Job) -> str:
        """Add job to queue."""
        pass

    @abstractmethod
    def dequeue(self, queue: str, timeout: float = 0) -> Optional[Job]:
        """Get next job from queue."""
        pass

    @abstractmethod
    def get(self, job_id: str) -> Optional[Job]:
        """Get job by ID."""
        pass

    @abstractmethod
    def update(self, job: Job) -> None:
        """Update job state."""
        pass

    @abstractmethod
    def delete(self, job_id: str) -> bool:
        """Delete a job."""
        pass

    @abstractmethod
    def list_jobs(
        self,
        queue: Optional[str] = None,
        status: Optional[JobStatus] = None,
        limit: int = 100,
    ) -> List[Job]:
        """List jobs."""
        pass


class MemoryJobBackend(JobBackend):
    """
    In-memory job backend.

    Suitable for single-process, testing, or development.
    """

    def __init__(self):
        self._jobs: Dict[str, Job] = {}
        self._queues: Dict[str, List[str]] = {}
        self._lock = threading.RLock()

    def enqueue(self, job: Job) -> str:
        """Add job to queue."""
        with self._lock:
            self._jobs[job.id] = job
            job.status = JobStatus.QUEUED

            if job.queue not in self._queues:
                self._queues[job.queue] = []

            # Insert by priority (higher priority first)
            queue = self._queues[job.queue]
            inserted = False
            for i, job_id in enumerate(queue):
                other = self._jobs.get(job_id)
                if other and job.priority.value > other.priority.value:
                    queue.insert(i, job.id)
                    inserted = True
                    break
            if not inserted:
                queue.append(job.id)

            return job.id

    def dequeue(self, queue: str, timeout: float = 0) -> Optional[Job]:
        """Get next job from queue."""
        start = time.time()
        while True:
            with self._lock:
                if queue in self._queues and self._queues[queue]:
                    job_id = self._queues[queue].pop(0)
                    job = self._jobs.get(job_id)
                    if job and job.status == JobStatus.QUEUED:
                        job.status = JobStatus.RUNNING
                        return job

            if timeout <= 0:
                return None
            if time.time() - start >= timeout:
                return None
            time.sleep(0.1)

    def get(self, job_id: str) -> Optional[Job]:
        """Get job by ID."""
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job: Job) -> None:
        """Update job state."""
        with self._lock:
            self._jobs[job.id] = job

    def delete(self, job_id: str) -> bool:
        """Delete a job."""
        with self._lock:
            if job_id in self._jobs:
                job = self._jobs[job_id]
                if job.queue in self._queues and job_id in self._queues[job.queue]:
                    self._queues[job.queue].remove(job_id)
                del self._jobs[job_id]
                return True
            return False

    def list_jobs(
        self,
        queue: Optional[str] = None,
        status: Optional[JobStatus] = None,
        limit: int = 100,
    ) -> List[Job]:
        """List jobs."""
        with self._lock:
            jobs = list(self._jobs.values())

            if queue:
                jobs = [j for j in jobs if j.queue == queue]
            if status:
                jobs = [j for j in jobs if j.status == status]

            return jobs[:limit]


# Registry of registered job functions
_job_registry: Dict[str, Callable] = {}


def job(
    name: Optional[str] = None,
    queue: str = "default",
    priority: JobPriority = JobPriority.NORMAL,
    timeout: Optional[float] = None,
    max_retries: int = 0,
    retry_delay: float = 60.0,
):
    """
    Decorator to register a function as a job.

    Usage:
        @job(name="send_email", queue="email", max_retries=3)
        def send_email(to: str, subject: str, body: str):
            # Send email
            pass

        # Queue the job
        queue = get_job_queue()
        queue.enqueue(send_email, "user@example.com", "Hello", "Body")
    """
    def decorator(func: Callable) -> Callable:
        job_name = name or func.__name__

        # Store in registry
        _job_registry[job_name] = func

        # Add metadata to function
        func._job_name = job_name
        func._job_queue = queue
        func._job_priority = priority
        func._job_timeout = timeout
        func._job_max_retries = max_retries
        func._job_retry_delay = retry_delay

        # Add delay method for easy queueing
        def delay(*args, **kwargs) -> str:
            """Queue the job for async execution."""
            q = get_job_queue()
            return q.enqueue(func, *args, **kwargs)

        func.delay = delay

        return func

    return decorator


def get_job_func(name: str) -> Optional[Callable]:
    """Get registered job function by name."""
    return _job_registry.get(name)


class JobQueue:
    """
    Job queue for managing async jobs.

    Supports multiple backends (memory, Redis).
    """

    def __init__(
        self,
        backend: Optional[JobBackend] = None,
        default_queue: str = "default",
    ):
        """
        Initialize job queue.

        Args:
            backend: Job storage backend
            default_queue: Default queue name
        """
        self._backend = backend or MemoryJobBackend()
        self._default_queue = default_queue

    def enqueue(
        self,
        func: Callable,
        *args,
        queue: Optional[str] = None,
        priority: Optional[JobPriority] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
        delay: Optional[float] = None,
        scheduled_at: Optional[datetime] = None,
        tags: Optional[Set[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> str:
        """
        Enqueue a job for execution.

        Args:
            func: Function to execute
            *args: Positional arguments
            queue: Queue name
            priority: Job priority
            timeout: Execution timeout
            max_retries: Max retry attempts
            retry_delay: Delay between retries
            delay: Delay before execution (seconds)
            scheduled_at: Specific execution time
            tags: Job tags
            metadata: Job metadata
            **kwargs: Keyword arguments

        Returns:
            Job ID
        """
        # Get job metadata from decorated function
        job_name = getattr(func, "_job_name", func.__name__)
        job_queue = queue or getattr(func, "_job_queue", self._default_queue)
        job_priority = priority or getattr(func, "_job_priority", JobPriority.NORMAL)
        job_timeout = timeout if timeout is not None else getattr(func, "_job_timeout", None)
        job_max_retries = max_retries if max_retries is not None else getattr(func, "_job_max_retries", 0)
        job_retry_delay = retry_delay if retry_delay is not None else getattr(func, "_job_retry_delay", 60.0)

        # Calculate scheduled time
        job_scheduled_at = scheduled_at
        if delay and not job_scheduled_at:
            job_scheduled_at = datetime.now(timezone.utc) + timedelta(seconds=delay)

        job = Job(
            name=job_name,
            func_name=job_name,
            args=args,
            kwargs=kwargs,
            queue=job_queue,
            priority=job_priority,
            timeout=job_timeout,
            max_retries=job_max_retries,
            retry_delay=job_retry_delay,
            scheduled_at=job_scheduled_at,
            tags=tags or set(),
            metadata=metadata or {},
        )

        return self._backend.enqueue(job)

    def enqueue_job(self, job: Job) -> str:
        """Enqueue an existing Job object."""
        return self._backend.enqueue(job)

    def dequeue(
        self,
        queue: Optional[str] = None,
        timeout: float = 0,
    ) -> Optional[Job]:
        """Get next job from queue."""
        return self._backend.dequeue(queue or self._default_queue, timeout)

    def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID."""
        return self._backend.get(job_id)

    def cancel(self, job_id: str) -> bool:
        """Cancel a pending job."""
        job = self._backend.get(job_id)
        if job and job.status in (JobStatus.PENDING, JobStatus.QUEUED):
            job.status = JobStatus.CANCELLED
            self._backend.update(job)
            return True
        return False

    def retry(self, job_id: str) -> bool:
        """Retry a failed job."""
        job = self._backend.get(job_id)
        if job and job.status in (JobStatus.FAILED, JobStatus.TIMEOUT):
            job.status = JobStatus.QUEUED
            job.error = None
            job.error_traceback = None
            self._backend.enqueue(job)
            return True
        return False

    def list_jobs(
        self,
        queue: Optional[str] = None,
        status: Optional[JobStatus] = None,
        limit: int = 100,
    ) -> List[Job]:
        """List jobs."""
        return self._backend.list_jobs(queue, status, limit)

    @property
    def backend(self) -> JobBackend:
        """Get backend."""
        return self._backend


class JobWorker:
    """
    Worker that processes jobs from queues.
    """

    def __init__(
        self,
        queue: JobQueue,
        queues: Optional[List[str]] = None,
        worker_id: Optional[str] = None,
        concurrency: int = 1,
    ):
        """
        Initialize worker.

        Args:
            queue: Job queue
            queues: Queue names to process
            worker_id: Worker identifier
            concurrency: Number of concurrent jobs
        """
        self._queue = queue
        self._queues = queues or ["default"]
        self._worker_id = worker_id or f"worker-{uuid4().hex[:8]}"
        self._concurrency = concurrency
        self._running = False
        self._threads: List[threading.Thread] = []
        self._current_jobs: Dict[str, Job] = {}
        self._shutdown_event = threading.Event()

    def start(self) -> None:
        """Start the worker."""
        if self._running:
            return

        self._running = True
        self._shutdown_event.clear()

        # Start worker threads
        for i in range(self._concurrency):
            thread = threading.Thread(
                target=self._run_loop,
                name=f"{self._worker_id}-{i}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

        logger.info(f"Worker {self._worker_id} started with {self._concurrency} threads")

    def stop(self, timeout: float = 30.0) -> None:
        """Stop the worker."""
        if not self._running:
            return

        logger.info(f"Worker {self._worker_id} stopping...")
        self._running = False
        self._shutdown_event.set()

        # Wait for threads
        for thread in self._threads:
            thread.join(timeout=timeout / len(self._threads))

        self._threads.clear()
        logger.info(f"Worker {self._worker_id} stopped")

    def _run_loop(self) -> None:
        """Main worker loop."""
        while self._running:
            job = None
            try:
                # Try each queue
                for queue_name in self._queues:
                    job = self._queue.dequeue(queue_name, timeout=1.0)
                    if job:
                        break

                if job:
                    self._execute_job(job)
                else:
                    # No jobs available, wait a bit
                    self._shutdown_event.wait(0.5)

            except Exception as e:
                logger.error(f"Worker error: {e}")
                if job:
                    self._handle_job_error(job, e)

    def _execute_job(self, job: Job) -> None:
        """Execute a single job."""
        self._current_jobs[threading.current_thread().name] = job

        job.started_at = datetime.now(timezone.utc)
        job.worker_id = self._worker_id
        job.attempts += 1

        logger.info(f"Executing job {job.id} ({job.name})")

        try:
            # Get function
            func = get_job_func(job.func_name)
            if not func:
                raise ValueError(f"Unknown job function: {job.func_name}")

            # Execute with timeout
            if job.timeout:
                result = self._execute_with_timeout(func, job.args, job.kwargs, job.timeout)
            else:
                result = func(*job.args, **job.kwargs)

            # Success
            job.status = JobStatus.COMPLETED
            job.result = result
            job.completed_at = datetime.now(timezone.utc)

            logger.info(f"Job {job.id} completed in {job.duration_seconds:.2f}s")

        except TimeoutError as e:
            job.status = JobStatus.TIMEOUT
            job.error = str(e)
            job.completed_at = datetime.now(timezone.utc)
            logger.warning(f"Job {job.id} timed out")

        except Exception as e:
            self._handle_job_error(job, e)

        finally:
            self._queue.backend.update(job)
            self._current_jobs.pop(threading.current_thread().name, None)

    def _execute_with_timeout(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        timeout: float,
    ) -> Any:
        """Execute function with timeout."""
        result_container = {"result": None, "error": None}

        def target():
            try:
                result_container["result"] = func(*args, **kwargs)
            except Exception as e:
                result_container["error"] = e

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            raise TimeoutError(f"Job timed out after {timeout}s")

        if result_container["error"]:
            raise result_container["error"]

        return result_container["result"]

    def _handle_job_error(self, job: Job, error: Exception) -> None:
        """Handle job execution error."""
        import traceback

        job.error = str(error)
        job.error_traceback = traceback.format_exc()
        job.completed_at = datetime.now(timezone.utc)

        if job.should_retry():
            job.status = JobStatus.RETRYING
            job.scheduled_at = datetime.now(timezone.utc) + timedelta(seconds=job.get_retry_delay())
            logger.warning(f"Job {job.id} failed, retrying in {job.get_retry_delay()}s")
            # Re-enqueue for retry
            self._queue.enqueue_job(job)
        else:
            job.status = JobStatus.FAILED
            logger.error(f"Job {job.id} failed: {error}")

    @property
    def worker_id(self) -> str:
        """Get worker ID."""
        return self._worker_id

    @property
    def is_running(self) -> bool:
        """Check if worker is running."""
        return self._running

    @property
    def current_jobs(self) -> Dict[str, Job]:
        """Get currently executing jobs."""
        return self._current_jobs.copy()


# Global job queue
_default_queue: Optional[JobQueue] = None


def get_job_queue() -> JobQueue:
    """Get the default job queue."""
    global _default_queue
    if _default_queue is None:
        _default_queue = JobQueue()
    return _default_queue


def set_job_queue(queue: JobQueue) -> None:
    """Set the default job queue."""
    global _default_queue
    _default_queue = queue
