"""
Data models for scheduled scanning.

Defines scan schedules, policies, and job tracking.
"""

from typing import Any
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import uuid


class ScheduleStatus(Enum):
    """Status of a scheduled scan."""

    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    EXPIRED = "expired"


class JobStatus(Enum):
    """Status of a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class RecurrenceType(Enum):
    """Type of schedule recurrence."""

    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CRON = "cron"


@dataclass
class ScanPolicy:
    """
    Policy defining how scans should be executed.

    Attributes:
        name: Policy name
        pipeline: Pipeline name to execute
        modules: List of modules to run (empty = all)
        params: Parameters to pass to modules
        timeout_minutes: Maximum scan duration
        retry_count: Number of retries on failure
        retry_delay_seconds: Delay between retries
        notify_on_complete: Send notification on completion
        notify_on_failure: Send notification on failure
        notify_channels: Notification channels (slack, email, etc.)
        min_severity: Minimum severity to report
        tags: Tags for categorization
    """

    name: str
    pipeline: str
    modules: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    timeout_minutes: int = 60
    retry_count: int = 2
    retry_delay_seconds: int = 300
    notify_on_complete: bool = True
    notify_on_failure: bool = True
    notify_channels: list[str] = field(default_factory=list)
    min_severity: str = "low"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "pipeline": self.pipeline,
            "modules": self.modules,
            "params": self.params,
            "timeout_minutes": self.timeout_minutes,
            "retry_count": self.retry_count,
            "retry_delay_seconds": self.retry_delay_seconds,
            "notify_on_complete": self.notify_on_complete,
            "notify_on_failure": self.notify_on_failure,
            "notify_channels": self.notify_channels,
            "min_severity": self.min_severity,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanPolicy":
        """Create from dictionary."""
        return cls(
            name=data.get("name", "default"),
            pipeline=data.get("pipeline", ""),
            modules=data.get("modules", []),
            params=data.get("params", {}),
            timeout_minutes=data.get("timeout_minutes", 60),
            retry_count=data.get("retry_count", 2),
            retry_delay_seconds=data.get("retry_delay_seconds", 300),
            notify_on_complete=data.get("notify_on_complete", True),
            notify_on_failure=data.get("notify_on_failure", True),
            notify_channels=data.get("notify_channels", []),
            min_severity=data.get("min_severity", "low"),
            tags=data.get("tags", []),
        )


@dataclass
class ScanSchedule:
    """
    Schedule for recurring scans.

    Attributes:
        id: Unique identifier
        name: Schedule name
        target: Target to scan (domain, IP, URL)
        policy: Scan policy to use
        recurrence: Type of recurrence
        cron_expression: Cron expression (for CRON type)
        interval_hours: Interval in hours (for simple types)
        start_time: When schedule becomes active
        end_time: When schedule expires (optional)
        status: Current schedule status
        last_run: Last execution time
        next_run: Next scheduled execution
        run_count: Total number of runs
        created_at: Creation timestamp
        updated_at: Last update timestamp
        metadata: Additional metadata
    """

    name: str
    target: str
    policy: ScanPolicy
    recurrence: RecurrenceType = RecurrenceType.DAILY
    cron_expression: str = ""
    interval_hours: int = 24
    start_time: datetime | None = None
    end_time: datetime | None = None
    status: ScheduleStatus = ScheduleStatus.ACTIVE
    last_run: datetime | None = None
    next_run: datetime | None = None
    run_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        """Set initial next_run if not provided."""
        if self.next_run is None and self.status == ScheduleStatus.ACTIVE:
            self.next_run = self.calculate_next_run()

    def calculate_next_run(self, from_time: datetime | None = None) -> datetime | None:
        """
        Calculate the next run time.

        Args:
            from_time: Base time to calculate from (default: now)

        Returns:
            Next run datetime or None if schedule is complete
        """
        base = from_time or datetime.now(timezone.utc)

        # Check if schedule has expired
        if self.end_time and base >= self.end_time:
            return None

        # Use start_time if in future
        if self.start_time and base < self.start_time:
            return self.start_time

        if self.recurrence == RecurrenceType.ONCE:
            if self.run_count > 0:
                return None
            return self.start_time or base

        if self.recurrence == RecurrenceType.HOURLY:
            return base + timedelta(hours=1)

        if self.recurrence == RecurrenceType.DAILY:
            return base + timedelta(days=1)

        if self.recurrence == RecurrenceType.WEEKLY:
            return base + timedelta(weeks=1)

        if self.recurrence == RecurrenceType.MONTHLY:
            # Simple approach: add 30 days
            return base + timedelta(days=30)

        if self.recurrence == RecurrenceType.CRON:
            return self._parse_cron_next(base)

        return base + timedelta(hours=self.interval_hours)

    def _parse_cron_next(self, base: datetime) -> datetime:
        """
        Parse cron expression and get next run time.

        Supports standard 5-field cron: minute hour day month weekday
        """
        try:
            from croniter import croniter

            cron = croniter(self.cron_expression, base)
            return cron.get_next(datetime)
        except ImportError:
            # Fallback to daily if croniter not installed
            return base + timedelta(days=1)
        except (ValueError, TypeError):
            return base + timedelta(days=1)

    def is_due(self, current_time: datetime | None = None) -> bool:
        """
        Check if schedule is due for execution.

        Args:
            current_time: Time to check against (default: now)

        Returns:
            True if schedule should run
        """
        if self.status != ScheduleStatus.ACTIVE:
            return False

        now = current_time or datetime.now(timezone.utc)

        # Check start time
        if self.start_time and now < self.start_time:
            return False

        # Check end time
        if self.end_time and now >= self.end_time:
            return False

        # Check next run
        if self.next_run and now >= self.next_run:
            return True

        return False

    def mark_run(self, run_time: datetime | None = None) -> None:
        """
        Mark schedule as having run.

        Args:
            run_time: Time of the run (default: now)
        """
        now = run_time or datetime.now(timezone.utc)
        self.last_run = now
        self.run_count += 1
        self.next_run = self.calculate_next_run(now)
        self.updated_at = now

        # Check if one-time schedule
        if self.recurrence == RecurrenceType.ONCE:
            self.status = ScheduleStatus.EXPIRED

        # Check if expired
        if self.end_time and now >= self.end_time:
            self.status = ScheduleStatus.EXPIRED

    def pause(self) -> None:
        """Pause the schedule."""
        self.status = ScheduleStatus.PAUSED
        self.updated_at = datetime.now(timezone.utc)

    def resume(self) -> None:
        """Resume a paused schedule."""
        if self.status == ScheduleStatus.PAUSED:
            self.status = ScheduleStatus.ACTIVE
            self.next_run = self.calculate_next_run()
            self.updated_at = datetime.now(timezone.utc)

    def disable(self) -> None:
        """Disable the schedule."""
        self.status = ScheduleStatus.DISABLED
        self.next_run = None
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "policy": self.policy.to_dict(),
            "recurrence": self.recurrence.value,
            "cron_expression": self.cron_expression,
            "interval_hours": self.interval_hours,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status.value,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanSchedule":
        """Create from dictionary."""

        def parse_dt(val):
            if val is None:
                return None
            if isinstance(val, datetime):
                return val
            return datetime.fromisoformat(val)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data["name"],
            target=data["target"],
            policy=ScanPolicy.from_dict(data["policy"]),
            recurrence=RecurrenceType(data.get("recurrence", "daily")),
            cron_expression=data.get("cron_expression", ""),
            interval_hours=data.get("interval_hours", 24),
            start_time=parse_dt(data.get("start_time")),
            end_time=parse_dt(data.get("end_time")),
            status=ScheduleStatus(data.get("status", "active")),
            last_run=parse_dt(data.get("last_run")),
            next_run=parse_dt(data.get("next_run")),
            run_count=data.get("run_count", 0),
            created_at=parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
            updated_at=parse_dt(data.get("updated_at")) or datetime.now(timezone.utc),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScanJob:
    """
    A scan job instance (actual execution of a schedule).

    Attributes:
        id: Unique job identifier
        schedule_id: Associated schedule ID
        target: Target being scanned
        policy: Policy used for this job
        status: Current job status
        started_at: Job start time
        completed_at: Job completion time
        result: Job result data
        error: Error message if failed
        retry_count: Number of retries attempted
        context_id: Associated context ID
        findings_count: Number of findings discovered
    """

    schedule_id: str
    target: str
    policy: ScanPolicy
    status: JobStatus = JobStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    retry_count: int = 0
    context_id: str | None = None
    findings_count: int = 0
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def start(self) -> None:
        """Mark job as started."""
        self.status = JobStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)

    def complete(self, result: dict[str, Any], findings_count: int = 0) -> None:
        """Mark job as completed."""
        self.status = JobStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.result = result
        self.findings_count = findings_count

    def fail(self, error: str) -> None:
        """Mark job as failed."""
        self.status = JobStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.error = error

    def cancel(self) -> None:
        """Cancel the job."""
        self.status = JobStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)

    def timeout(self) -> None:
        """Mark job as timed out."""
        self.status = JobStatus.TIMEOUT
        self.completed_at = datetime.now(timezone.utc)
        self.error = "Job exceeded timeout"

    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return (
            self.status in (JobStatus.FAILED, JobStatus.TIMEOUT)
            and self.retry_count < self.policy.retry_count
        )

    def increment_retry(self) -> None:
        """Increment retry count and reset for retry."""
        self.retry_count += 1
        self.status = JobStatus.PENDING
        self.started_at = None
        self.completed_at = None
        self.error = None

    @property
    def duration_seconds(self) -> float | None:
        """Get job duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "schedule_id": self.schedule_id,
            "target": self.target,
            "policy": self.policy.to_dict(),
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "result": self.result,
            "error": self.error,
            "retry_count": self.retry_count,
            "context_id": self.context_id,
            "findings_count": self.findings_count,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanJob":
        """Create from dictionary."""

        def parse_dt(val):
            if val is None:
                return None
            if isinstance(val, datetime):
                return val
            return datetime.fromisoformat(val)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            schedule_id=data["schedule_id"],
            target=data["target"],
            policy=ScanPolicy.from_dict(data["policy"]),
            status=JobStatus(data.get("status", "pending")),
            started_at=parse_dt(data.get("started_at")),
            completed_at=parse_dt(data.get("completed_at")),
            result=data.get("result", {}),
            error=data.get("error"),
            retry_count=data.get("retry_count", 0),
            context_id=data.get("context_id"),
            findings_count=data.get("findings_count", 0),
        )
