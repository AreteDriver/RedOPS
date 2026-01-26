"""Tests for job queue system."""

import time
from datetime import datetime, timedelta

import pytest

from redops.jobs.queue import (
    Job,
    JobStatus,
    JobPriority,
    JobResult,
    JobQueue,
    JobWorker,
    MemoryJobBackend,
    job,
    get_job_func,
)
from redops.jobs.scheduler import (
    JobScheduler,
    ScheduledJob,
    IntervalSchedule,
    CronSchedule,
)


class TestJob:
    """Test Job class."""

    def test_create_job(self):
        """Create a job."""
        j = Job(
            name="test-job",
            func_name="test_func",
            args=(1, 2),
            kwargs={"key": "value"},
        )

        assert j.name == "test-job"
        assert j.func_name == "test_func"
        assert j.args == (1, 2)
        assert j.kwargs == {"key": "value"}
        assert j.status == JobStatus.PENDING

    def test_job_to_dict(self):
        """Serialize job to dict."""
        j = Job(
            name="test",
            func_name="func",
            priority=JobPriority.HIGH,
        )

        data = j.to_dict()

        assert data["name"] == "test"
        assert data["priority"] == 2  # HIGH = 2
        assert "id" in data

    def test_job_from_dict(self):
        """Deserialize job from dict."""
        data = {
            "id": "test-123",
            "name": "test",
            "func_name": "func",
            "args": [1, 2],
            "kwargs": {},
            "priority": 1,
            "queue": "default",
            "created_at": datetime.utcnow().isoformat(),
            "status": "pending",
            "attempts": 0,
        }

        j = Job.from_dict(data)

        assert j.id == "test-123"
        assert j.name == "test"
        assert j.args == (1, 2)

    def test_job_retry_logic(self):
        """Test retry logic."""
        j = Job(
            name="retry-test",
            func_name="func",
            max_retries=3,
            retry_delay=1.0,
            retry_backoff=2.0,
        )

        assert j.should_retry() is True
        assert j.get_retry_delay() == 1.0

        j.attempts = 1
        assert j.should_retry() is True
        assert j.get_retry_delay() == 2.0

        j.attempts = 3
        assert j.should_retry() is False


class TestJobResult:
    """Test JobResult class."""

    def test_success_result(self):
        """Successful job result."""
        result = JobResult(
            job_id="123",
            status=JobStatus.COMPLETED,
            result={"data": "value"},
        )

        assert result.success is True
        assert result.result == {"data": "value"}

    def test_failed_result(self):
        """Failed job result."""
        result = JobResult(
            job_id="123",
            status=JobStatus.FAILED,
            error="Something went wrong",
        )

        assert result.success is False
        assert result.error == "Something went wrong"


class TestMemoryJobBackend:
    """Test in-memory job backend."""

    def test_enqueue_dequeue(self):
        """Enqueue and dequeue jobs."""
        backend = MemoryJobBackend()

        job1 = Job(name="job1", func_name="func")
        job2 = Job(name="job2", func_name="func")

        backend.enqueue(job1)
        backend.enqueue(job2)

        # Dequeue in order
        dequeued = backend.dequeue("default")
        assert dequeued.name == "job1"

        dequeued = backend.dequeue("default")
        assert dequeued.name == "job2"

    def test_priority_ordering(self):
        """Higher priority jobs dequeue first."""
        backend = MemoryJobBackend()

        low = Job(name="low", func_name="func", priority=JobPriority.LOW)
        high = Job(name="high", func_name="func", priority=JobPriority.HIGH)
        normal = Job(name="normal", func_name="func", priority=JobPriority.NORMAL)

        backend.enqueue(low)
        backend.enqueue(high)
        backend.enqueue(normal)

        # High priority first
        assert backend.dequeue("default").name == "high"
        assert backend.dequeue("default").name == "normal"
        assert backend.dequeue("default").name == "low"

    def test_get_job(self):
        """Get job by ID."""
        backend = MemoryJobBackend()

        j = Job(name="test", func_name="func")
        backend.enqueue(j)

        retrieved = backend.get(j.id)
        assert retrieved.name == "test"

    def test_update_job(self):
        """Update job state."""
        backend = MemoryJobBackend()

        j = Job(name="test", func_name="func")
        backend.enqueue(j)

        j.status = JobStatus.COMPLETED
        backend.update(j)

        retrieved = backend.get(j.id)
        assert retrieved.status == JobStatus.COMPLETED

    def test_delete_job(self):
        """Delete a job."""
        backend = MemoryJobBackend()

        j = Job(name="test", func_name="func")
        backend.enqueue(j)

        assert backend.delete(j.id) is True
        assert backend.get(j.id) is None


# Test function for job decorator
@job(name="add_numbers", max_retries=2)
def add_numbers(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@job(name="failing_job")
def failing_job():
    """Job that always fails."""
    raise ValueError("Intentional failure")


class TestJobDecorator:
    """Test @job decorator."""

    def test_job_registration(self):
        """Job is registered."""
        func = get_job_func("add_numbers")
        assert func is not None
        assert func(2, 3) == 5

    def test_job_metadata(self):
        """Job has metadata."""
        assert add_numbers._job_name == "add_numbers"
        assert add_numbers._job_max_retries == 2


class TestJobQueue:
    """Test JobQueue."""

    def test_enqueue_function(self):
        """Enqueue a function."""
        queue = JobQueue()
        job_id = queue.enqueue(add_numbers, 1, 2)

        assert job_id is not None

        job = queue.get_job(job_id)
        assert job.func_name == "add_numbers"
        assert job.args == (1, 2)

    def test_enqueue_with_options(self):
        """Enqueue with options."""
        queue = JobQueue()
        job_id = queue.enqueue(
            add_numbers,
            1,
            2,
            priority=JobPriority.HIGH,
            timeout=30.0,
            max_retries=5,
        )

        job = queue.get_job(job_id)
        assert job.priority == JobPriority.HIGH
        assert job.timeout == 30.0
        assert job.max_retries == 5

    def test_cancel_job(self):
        """Cancel a pending job."""
        queue = JobQueue()
        job_id = queue.enqueue(add_numbers, 1, 2)

        assert queue.cancel(job_id) is True

        job = queue.get_job(job_id)
        assert job.status == JobStatus.CANCELLED


class TestJobWorker:
    """Test JobWorker."""

    def test_worker_executes_job(self):
        """Worker executes jobs."""
        queue = JobQueue()
        worker = JobWorker(queue, concurrency=1)

        job_id = queue.enqueue(add_numbers, 2, 3)

        worker.start()
        time.sleep(0.5)  # Wait for execution
        worker.stop()

        job = queue.get_job(job_id)
        assert job.status == JobStatus.COMPLETED
        assert job.result == 5


class TestIntervalSchedule:
    """Test interval schedule."""

    def test_interval_seconds(self):
        """Interval in seconds."""
        schedule = IntervalSchedule(seconds=30)
        assert schedule.total_seconds == 30

    def test_interval_combined(self):
        """Combined interval."""
        schedule = IntervalSchedule(hours=1, minutes=30)
        assert schedule.total_seconds == 5400

    def test_next_run(self):
        """Calculate next run time."""
        schedule = IntervalSchedule(minutes=5)
        now = datetime.utcnow()
        next_run = schedule.get_next_run(now)

        diff = (next_run - now).total_seconds()
        assert 299 <= diff <= 301  # ~5 minutes


class TestCronSchedule:
    """Test cron schedule."""

    def test_parse_cron_string(self):
        """Parse cron string."""
        schedule = CronSchedule.from_string("0 * * * *")  # Every hour

        assert schedule.minute == "0"
        assert schedule.hour == "*"

    def test_next_run_hourly(self):
        """Next run for hourly schedule."""
        schedule = CronSchedule(minute="0")  # Every hour at :00

        now = datetime(2025, 1, 1, 12, 30)
        next_run = schedule.get_next_run(now)

        assert next_run.hour == 13
        assert next_run.minute == 0

    def test_cron_to_dict(self):
        """Serialize cron schedule."""
        schedule = CronSchedule(minute="*/15", hour="9-17")
        data = schedule.to_dict()

        assert data["type"] == "cron"
        assert data["minute"] == "*/15"
        assert data["hour"] == "9-17"


class TestScheduledJob:
    """Test ScheduledJob."""

    def test_create_scheduled_job(self):
        """Create scheduled job."""
        schedule = IntervalSchedule(hours=1)
        job = ScheduledJob(
            name="hourly-job",
            func_name="test_func",
            schedule=schedule,
        )

        assert job.name == "hourly-job"
        assert job.next_run is not None
        assert job.enabled is True

    def test_scheduled_job_serialization(self):
        """Serialize and deserialize scheduled job."""
        schedule = IntervalSchedule(minutes=30)
        job = ScheduledJob(
            name="test",
            func_name="func",
            schedule=schedule,
            args=(1, 2),
        )

        data = job.to_dict()
        restored = ScheduledJob.from_dict(data)

        assert restored.name == "test"
        assert restored.func_name == "func"
        assert restored.args == (1, 2)


class TestJobScheduler:
    """Test JobScheduler."""

    def test_add_interval_job(self):
        """Add interval job."""
        scheduler = JobScheduler()
        job_id = scheduler.add_interval(
            add_numbers,
            minutes=5,
            name="five-minute-job",
            args=(1, 2),
        )

        job = scheduler.get_job(job_id)
        assert job is not None
        assert job.name == "five-minute-job"

    def test_add_cron_job(self):
        """Add cron job."""
        scheduler = JobScheduler()
        job_id = scheduler.add_cron(
            add_numbers,
            cron_string="0 * * * *",
            name="hourly-job",
        )

        job = scheduler.get_job(job_id)
        assert job is not None

    def test_remove_job(self):
        """Remove scheduled job."""
        scheduler = JobScheduler()
        job_id = scheduler.add_interval(add_numbers, hours=1)

        assert scheduler.remove(job_id) is True
        assert scheduler.get_job(job_id) is None

    def test_enable_disable_job(self):
        """Enable and disable job."""
        scheduler = JobScheduler()
        job_id = scheduler.add_interval(add_numbers, hours=1)

        scheduler.disable(job_id)
        job = scheduler.get_job(job_id)
        assert job.enabled is False

        scheduler.enable(job_id)
        job = scheduler.get_job(job_id)
        assert job.enabled is True

    def test_list_jobs(self):
        """List all scheduled jobs."""
        scheduler = JobScheduler()
        scheduler.add_interval(add_numbers, hours=1, name="job1")
        scheduler.add_interval(add_numbers, hours=2, name="job2")

        jobs = scheduler.list_jobs()
        assert len(jobs) == 2
        names = {j.name for j in jobs}
        assert "job1" in names
        assert "job2" in names
