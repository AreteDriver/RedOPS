"""
Job Scheduler.

Provides cron-like scheduling for recurring jobs.
"""

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from redops.jobs.queue import JobPriority, JobQueue, get_job_queue

logger = logging.getLogger(__name__)


class Schedule(ABC):
    """Abstract base for schedule definitions."""

    @abstractmethod
    def get_next_run(self, after: datetime) -> datetime:
        """Get next run time after the given time."""
        pass

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize schedule."""
        pass


@dataclass
class IntervalSchedule(Schedule):
    """
    Interval-based schedule.

    Runs job every N seconds/minutes/hours/days.
    """

    seconds: int = 0
    minutes: int = 0
    hours: int = 0
    days: int = 0

    @property
    def total_seconds(self) -> int:
        """Get total interval in seconds."""
        return self.seconds + self.minutes * 60 + self.hours * 3600 + self.days * 86400

    def get_next_run(self, after: datetime) -> datetime:
        """Get next run time."""
        return after + timedelta(seconds=self.total_seconds)

    def to_dict(self) -> dict[str, Any]:
        """Serialize schedule."""
        return {
            "type": "interval",
            "seconds": self.seconds,
            "minutes": self.minutes,
            "hours": self.hours,
            "days": self.days,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntervalSchedule":
        """Create from dict."""
        return cls(
            seconds=data.get("seconds", 0),
            minutes=data.get("minutes", 0),
            hours=data.get("hours", 0),
            days=data.get("days", 0),
        )


@dataclass
class CronSchedule(Schedule):
    """
    Cron-like schedule.

    Supports standard cron syntax: minute hour day month weekday
    """

    minute: str = "*"
    hour: str = "*"
    day: str = "*"
    month: str = "*"
    weekday: str = "*"

    def __post_init__(self):
        """Parse cron fields."""
        self._minute_set = self._parse_field(self.minute, 0, 59)
        self._hour_set = self._parse_field(self.hour, 0, 23)
        self._day_set = self._parse_field(self.day, 1, 31)
        self._month_set = self._parse_field(self.month, 1, 12)
        self._weekday_set = self._parse_field(self.weekday, 0, 6)

    def _parse_field(self, field: str, min_val: int, max_val: int) -> set[int]:
        """Parse a cron field into a set of values."""
        values = set()

        for part in field.split(","):
            if part == "*":
                values.update(range(min_val, max_val + 1))
            elif "/" in part:
                # Step values: */5 or 0-30/5
                base, step = part.split("/")
                step = int(step)
                if base == "*":
                    values.update(range(min_val, max_val + 1, step))
                elif "-" in base:
                    start, end = map(int, base.split("-"))
                    values.update(range(start, end + 1, step))
                else:
                    values.update(range(int(base), max_val + 1, step))
            elif "-" in part:
                # Ranges: 1-5
                start, end = map(int, part.split("-"))
                values.update(range(start, end + 1))
            else:
                # Single values
                values.add(int(part))

        return values

    def get_next_run(self, after: datetime) -> datetime:
        """Get next run time after the given time."""
        # Start from next minute
        dt = after.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Search for next matching time (max 1 year)
        max_iterations = 525600  # minutes in a year
        for _ in range(max_iterations):
            if (
                dt.minute in self._minute_set
                and dt.hour in self._hour_set
                and dt.day in self._day_set
                and dt.month in self._month_set
                and dt.weekday() in self._weekday_set
            ):
                return dt
            dt += timedelta(minutes=1)

        # Fallback - should not reach here
        return after + timedelta(hours=1)

    def to_dict(self) -> dict[str, Any]:
        """Serialize schedule."""
        return {
            "type": "cron",
            "minute": self.minute,
            "hour": self.hour,
            "day": self.day,
            "month": self.month,
            "weekday": self.weekday,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CronSchedule":
        """Create from dict."""
        return cls(
            minute=data.get("minute", "*"),
            hour=data.get("hour", "*"),
            day=data.get("day", "*"),
            month=data.get("month", "*"),
            weekday=data.get("weekday", "*"),
        )

    @classmethod
    def from_string(cls, cron_string: str) -> "CronSchedule":
        """
        Create from cron string.

        Args:
            cron_string: "minute hour day month weekday"
        """
        parts = cron_string.split()
        if len(parts) != 5:
            raise ValueError("Invalid cron string: expected 5 fields")

        return cls(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            weekday=parts[4],
        )


@dataclass
class ScheduledJob:
    """
    A scheduled job definition.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    func_name: str = ""
    args: tuple = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)
    schedule: Schedule | None = None
    queue: str = "default"
    priority: JobPriority = JobPriority.NORMAL
    timeout: float | None = None
    max_retries: int = 0

    enabled: bool = True
    last_run: datetime | None = None
    next_run: datetime | None = None
    run_count: int = 0
    error_count: int = 0
    last_error: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate next run time."""
        if self.schedule and not self.next_run:
            self.next_run = self.schedule.get_next_run(datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "id": self.id,
            "name": self.name,
            "func_name": self.func_name,
            "args": list(self.args),
            "kwargs": self.kwargs,
            "schedule": self.schedule.to_dict() if self.schedule else None,
            "queue": self.queue,
            "priority": self.priority.value,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScheduledJob":
        """Create from dict."""
        schedule = None
        if data.get("schedule"):
            sched_data = data["schedule"]
            if sched_data["type"] == "interval":
                schedule = IntervalSchedule.from_dict(sched_data)
            elif sched_data["type"] == "cron":
                schedule = CronSchedule.from_dict(sched_data)

        return cls(
            id=data["id"],
            name=data.get("name", ""),
            func_name=data["func_name"],
            args=tuple(data.get("args", [])),
            kwargs=data.get("kwargs", {}),
            schedule=schedule,
            queue=data.get("queue", "default"),
            priority=JobPriority(data.get("priority", 1)),
            timeout=data.get("timeout"),
            max_retries=data.get("max_retries", 0),
            enabled=data.get("enabled", True),
            last_run=datetime.fromisoformat(data["last_run"])
            if data.get("last_run")
            else None,
            next_run=datetime.fromisoformat(data["next_run"])
            if data.get("next_run")
            else None,
            run_count=data.get("run_count", 0),
            error_count=data.get("error_count", 0),
            last_error=data.get("last_error"),
            metadata=data.get("metadata", {}),
        )


class JobScheduler:
    """
    Scheduler for recurring jobs.

    Manages scheduled jobs and triggers them according to their schedules.
    """

    def __init__(
        self,
        queue: JobQueue | None = None,
        check_interval: float = 1.0,
    ):
        """
        Initialize scheduler.

        Args:
            queue: Job queue for enqueuing jobs
            check_interval: Interval for checking schedules (seconds)
        """
        self._queue = queue or get_job_queue()
        self._check_interval = check_interval
        self._jobs: dict[str, ScheduledJob] = {}
        self._running = False
        self._thread: threading.Thread | None = None
        self._shutdown_event = threading.Event()
        self._lock = threading.RLock()

    def add(
        self,
        func: Callable,
        schedule: Schedule,
        name: str | None = None,
        args: tuple = (),
        kwargs: dict[str, Any] | None = None,
        queue: str = "default",
        priority: JobPriority = JobPriority.NORMAL,
        timeout: float | None = None,
        max_retries: int = 0,
        enabled: bool = True,
    ) -> str:
        """
        Add a scheduled job.

        Args:
            func: Function to execute
            schedule: Schedule definition
            name: Job name
            args: Function arguments
            kwargs: Function keyword arguments
            queue: Target queue
            priority: Job priority
            timeout: Execution timeout
            max_retries: Max retries
            enabled: Whether job is enabled

        Returns:
            Scheduled job ID
        """
        func_name = getattr(func, "_job_name", func.__name__)

        job = ScheduledJob(
            name=name or func_name,
            func_name=func_name,
            args=args,
            kwargs=kwargs or {},
            schedule=schedule,
            queue=queue,
            priority=priority,
            timeout=timeout,
            max_retries=max_retries,
            enabled=enabled,
        )

        with self._lock:
            self._jobs[job.id] = job

        logger.info(f"Added scheduled job {job.id}: {job.name}")
        return job.id

    def add_interval(
        self,
        func: Callable,
        seconds: int = 0,
        minutes: int = 0,
        hours: int = 0,
        days: int = 0,
        **kwargs,
    ) -> str:
        """
        Add job with interval schedule.

        Args:
            func: Function to execute
            seconds: Interval seconds
            minutes: Interval minutes
            hours: Interval hours
            days: Interval days
            **kwargs: Additional job options

        Returns:
            Scheduled job ID
        """
        schedule = IntervalSchedule(
            seconds=seconds,
            minutes=minutes,
            hours=hours,
            days=days,
        )
        return self.add(func, schedule, **kwargs)

    def add_cron(
        self,
        func: Callable,
        cron_string: str | None = None,
        minute: str = "*",
        hour: str = "*",
        day: str = "*",
        month: str = "*",
        weekday: str = "*",
        **kwargs,
    ) -> str:
        """
        Add job with cron schedule.

        Args:
            func: Function to execute
            cron_string: Full cron string (overrides individual fields)
            minute: Minute field
            hour: Hour field
            day: Day field
            month: Month field
            weekday: Weekday field
            **kwargs: Additional job options

        Returns:
            Scheduled job ID
        """
        if cron_string:
            schedule = CronSchedule.from_string(cron_string)
        else:
            schedule = CronSchedule(
                minute=minute,
                hour=hour,
                day=day,
                month=month,
                weekday=weekday,
            )
        return self.add(func, schedule, **kwargs)

    def remove(self, job_id: str) -> bool:
        """Remove a scheduled job."""
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                logger.info(f"Removed scheduled job {job_id}")
                return True
            return False

    def enable(self, job_id: str) -> bool:
        """Enable a scheduled job."""
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].enabled = True
                return True
            return False

    def disable(self, job_id: str) -> bool:
        """Disable a scheduled job."""
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].enabled = False
                return True
            return False

    def run_now(self, job_id: str) -> str | None:
        """
        Trigger a scheduled job immediately.

        Returns:
            Job ID of enqueued job
        """
        with self._lock:
            scheduled_job = self._jobs.get(job_id)
            if not scheduled_job:
                return None

            return self._enqueue_job(scheduled_job)

    def _enqueue_job(self, scheduled_job: ScheduledJob) -> str:
        """Enqueue a scheduled job."""
        from redops.jobs.queue import get_job_func

        func = get_job_func(scheduled_job.func_name)
        if not func:
            raise ValueError(f"Unknown job function: {scheduled_job.func_name}")

        job_id = self._queue.enqueue(
            func,
            *scheduled_job.args,
            queue=scheduled_job.queue,
            priority=scheduled_job.priority,
            timeout=scheduled_job.timeout,
            max_retries=scheduled_job.max_retries,
            metadata={"scheduled_job_id": scheduled_job.id},
            **scheduled_job.kwargs,
        )

        # Update scheduled job stats
        scheduled_job.last_run = datetime.now(timezone.utc)
        scheduled_job.run_count += 1
        if scheduled_job.schedule:
            scheduled_job.next_run = scheduled_job.schedule.get_next_run(
                scheduled_job.last_run
            )

        return job_id

    def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            return

        self._running = True
        self._shutdown_event.clear()

        self._thread = threading.Thread(
            target=self._run_loop,
            name="job-scheduler",
            daemon=True,
        )
        self._thread.start()

        logger.info("Job scheduler started")

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the scheduler."""
        if not self._running:
            return

        logger.info("Job scheduler stopping...")
        self._running = False
        self._shutdown_event.set()

        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

        logger.info("Job scheduler stopped")

    def _run_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                now = datetime.now(timezone.utc)

                with self._lock:
                    for job in self._jobs.values():
                        if not job.enabled:
                            continue
                        if not job.next_run:
                            continue
                        if job.next_run <= now:
                            try:
                                self._enqueue_job(job)
                                logger.debug(
                                    f"Triggered scheduled job {job.id}: {job.name}"
                                )
                            except Exception as e:
                                job.error_count += 1
                                job.last_error = str(e)
                                logger.error(f"Failed to trigger job {job.id}: {e}")

            except Exception as e:
                logger.error(f"Scheduler error: {e}")

            self._shutdown_event.wait(self._check_interval)

    def get_job(self, job_id: str) -> ScheduledJob | None:
        """Get a scheduled job."""
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[ScheduledJob]:
        """List all scheduled jobs."""
        with self._lock:
            return list(self._jobs.values())

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    def __enter__(self) -> "JobScheduler":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.stop()
