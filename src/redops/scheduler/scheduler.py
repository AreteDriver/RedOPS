"""
Scheduler engine for RedOPS.

Manages scheduled scans with cron-based timing and job execution.
"""

from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
import threading
import time
import json
import os
import logging

from .models import (
    ScanSchedule,
    ScanPolicy,
    ScanJob,
    ScheduleStatus,
    JobStatus,
    RecurrenceType,
)

logger = logging.getLogger(__name__)


@dataclass
class SchedulerConfig:
    """Scheduler configuration."""

    check_interval_seconds: int = 60
    max_concurrent_jobs: int = 5
    job_timeout_minutes: int = 120
    storage_path: str = ""
    auto_start: bool = True

    @classmethod
    def from_env(cls) -> "SchedulerConfig":
        """Create config from environment variables."""
        return cls(
            check_interval_seconds=int(os.environ.get("SCHEDULER_CHECK_INTERVAL", "60")),
            max_concurrent_jobs=int(os.environ.get("SCHEDULER_MAX_CONCURRENT", "5")),
            job_timeout_minutes=int(os.environ.get("SCHEDULER_JOB_TIMEOUT", "120")),
            storage_path=os.environ.get("SCHEDULER_STORAGE_PATH", ""),
            auto_start=os.environ.get("SCHEDULER_AUTO_START", "true").lower() == "true",
        )


class ScheduleStore:
    """
    Storage for schedules and jobs.

    Supports in-memory and file-based persistence.
    """

    def __init__(self, storage_path: str = ""):
        """
        Initialize the store.

        Args:
            storage_path: Path to storage file (empty for in-memory only)
        """
        self._schedules: Dict[str, ScanSchedule] = {}
        self._jobs: Dict[str, ScanJob] = {}
        self._storage_path = storage_path
        self._lock = threading.RLock()

        if storage_path and os.path.exists(storage_path):
            self._load_from_file()

    def _load_from_file(self) -> None:
        """Load schedules from file."""
        try:
            with open(self._storage_path, "r") as f:
                data = json.load(f)
                for schedule_data in data.get("schedules", []):
                    schedule = ScanSchedule.from_dict(schedule_data)
                    self._schedules[schedule.id] = schedule
                for job_data in data.get("jobs", []):
                    job = ScanJob.from_dict(job_data)
                    self._jobs[job.id] = job
            logger.info(f"Loaded {len(self._schedules)} schedules from {self._storage_path}")
        except Exception as e:
            logger.error(f"Failed to load schedules: {e}")

    def _save_to_file(self) -> None:
        """Save schedules to file."""
        if not self._storage_path:
            return

        try:
            data = {
                "schedules": [s.to_dict() for s in self._schedules.values()],
                "jobs": [j.to_dict() for j in self._jobs.values()],
            }
            with open(self._storage_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save schedules: {e}")

    def add_schedule(self, schedule: ScanSchedule) -> None:
        """Add a schedule."""
        with self._lock:
            self._schedules[schedule.id] = schedule
            self._save_to_file()

    def get_schedule(self, schedule_id: str) -> Optional[ScanSchedule]:
        """Get a schedule by ID."""
        with self._lock:
            return self._schedules.get(schedule_id)

    def update_schedule(self, schedule: ScanSchedule) -> None:
        """Update a schedule."""
        with self._lock:
            if schedule.id in self._schedules:
                self._schedules[schedule.id] = schedule
                self._save_to_file()

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        with self._lock:
            if schedule_id in self._schedules:
                del self._schedules[schedule_id]
                self._save_to_file()
                return True
            return False

    def list_schedules(
        self,
        status: Optional[ScheduleStatus] = None,
        target: Optional[str] = None,
    ) -> List[ScanSchedule]:
        """List schedules with optional filtering."""
        with self._lock:
            schedules = list(self._schedules.values())

            if status:
                schedules = [s for s in schedules if s.status == status]

            if target:
                schedules = [s for s in schedules if s.target == target]

            return sorted(schedules, key=lambda s: s.next_run or datetime.max.replace(tzinfo=timezone.utc))

    def get_due_schedules(self, current_time: Optional[datetime] = None) -> List[ScanSchedule]:
        """Get schedules that are due for execution."""
        with self._lock:
            return [s for s in self._schedules.values() if s.is_due(current_time)]

    def add_job(self, job: ScanJob) -> None:
        """Add a job."""
        with self._lock:
            self._jobs[job.id] = job
            self._save_to_file()

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Get a job by ID."""
        with self._lock:
            return self._jobs.get(job_id)

    def update_job(self, job: ScanJob) -> None:
        """Update a job."""
        with self._lock:
            if job.id in self._jobs:
                self._jobs[job.id] = job
                self._save_to_file()

    def list_jobs(
        self,
        schedule_id: Optional[str] = None,
        status: Optional[JobStatus] = None,
        limit: int = 100,
    ) -> List[ScanJob]:
        """List jobs with optional filtering."""
        with self._lock:
            jobs = list(self._jobs.values())

            if schedule_id:
                jobs = [j for j in jobs if j.schedule_id == schedule_id]

            if status:
                jobs = [j for j in jobs if j.status == status]

            # Sort by started_at descending
            jobs.sort(
                key=lambda j: j.started_at or datetime.min.replace(tzinfo=timezone.utc),
                reverse=True,
            )

            return jobs[:limit]

    def get_running_jobs(self) -> List[ScanJob]:
        """Get currently running jobs."""
        return self.list_jobs(status=JobStatus.RUNNING)

    def cleanup_old_jobs(self, days: int = 30) -> int:
        """Remove jobs older than specified days."""
        with self._lock:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            old_jobs = [
                j for j in self._jobs.values()
                if j.completed_at and j.completed_at < cutoff
            ]
            for job in old_jobs:
                del self._jobs[job.id]
            if old_jobs:
                self._save_to_file()
            return len(old_jobs)


class Scheduler:
    """
    Main scheduler for managing and executing scan schedules.

    Runs a background thread that checks for due schedules and
    dispatches jobs for execution.
    """

    def __init__(
        self,
        config: Optional[SchedulerConfig] = None,
        executor: Optional[Callable[[ScanJob], None]] = None,
    ):
        """
        Initialize the scheduler.

        Args:
            config: Scheduler configuration
            executor: Callable to execute jobs (receives ScanJob)
        """
        self.config = config or SchedulerConfig.from_env()
        self.store = ScheduleStore(self.config.storage_path)
        self._executor = executor
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._job_semaphore = threading.Semaphore(self.config.max_concurrent_jobs)

    def set_executor(self, executor: Callable[[ScanJob], None]) -> None:
        """Set the job executor function."""
        self._executor = executor

    def start(self) -> None:
        """Start the scheduler background thread."""
        with self._lock:
            if self._running:
                return

            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            logger.info("Scheduler started")

    def stop(self, wait: bool = True) -> None:
        """Stop the scheduler."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            if wait and self._thread:
                self._thread.join(timeout=10)
            logger.info("Scheduler stopped")

    def _run_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                self._check_and_dispatch()
                self._check_timeouts()
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

            # Sleep in small increments to allow quick shutdown
            for _ in range(self.config.check_interval_seconds):
                if not self._running:
                    break
                time.sleep(1)

    def _check_and_dispatch(self) -> None:
        """Check for due schedules and dispatch jobs."""
        due_schedules = self.store.get_due_schedules()

        for schedule in due_schedules:
            # Check concurrent job limit
            if not self._job_semaphore.acquire(blocking=False):
                logger.warning("Max concurrent jobs reached, skipping schedule")
                break

            try:
                self._dispatch_schedule(schedule)
            except Exception as e:
                logger.error(f"Failed to dispatch schedule {schedule.id}: {e}")
                self._job_semaphore.release()

    def _dispatch_schedule(self, schedule: ScanSchedule) -> None:
        """Dispatch a single schedule for execution."""
        # Create job
        job = ScanJob(
            schedule_id=schedule.id,
            target=schedule.target,
            policy=schedule.policy,
        )

        # Mark schedule as run (updates next_run)
        schedule.mark_run()
        self.store.update_schedule(schedule)

        # Store job
        self.store.add_job(job)

        # Execute in thread
        thread = threading.Thread(
            target=self._execute_job,
            args=(job,),
            daemon=True,
        )
        thread.start()

        logger.info(f"Dispatched job {job.id} for schedule {schedule.name}")

    def _execute_job(self, job: ScanJob) -> None:
        """Execute a job (runs in thread)."""
        try:
            job.start()
            self.store.update_job(job)

            if self._executor:
                self._executor(job)
            else:
                # Default: just mark as complete
                job.complete({}, 0)

            self.store.update_job(job)
            logger.info(f"Job {job.id} completed with {job.findings_count} findings")

        except Exception as e:
            job.fail(str(e))
            self.store.update_job(job)
            logger.error(f"Job {job.id} failed: {e}")

            # Check for retry
            if job.can_retry():
                self._retry_job(job)

        finally:
            self._job_semaphore.release()

    def _retry_job(self, job: ScanJob) -> None:
        """Retry a failed job."""
        delay = job.policy.retry_delay_seconds
        logger.info(f"Retrying job {job.id} in {delay} seconds")

        def delayed_retry():
            time.sleep(delay)
            if self._running:
                job.increment_retry()
                self.store.update_job(job)
                self._job_semaphore.acquire()
                self._execute_job(job)

        thread = threading.Thread(target=delayed_retry, daemon=True)
        thread.start()

    def _check_timeouts(self) -> None:
        """Check for and handle timed out jobs."""
        running_jobs = self.store.get_running_jobs()
        now = datetime.now(timezone.utc)

        for job in running_jobs:
            if job.started_at:
                elapsed = (now - job.started_at).total_seconds()
                timeout = job.policy.timeout_minutes * 60

                if elapsed > timeout:
                    job.timeout()
                    self.store.update_job(job)
                    logger.warning(f"Job {job.id} timed out after {elapsed}s")

    # Public API for schedule management

    def create_schedule(
        self,
        name: str,
        target: str,
        policy: ScanPolicy,
        recurrence: RecurrenceType = RecurrenceType.DAILY,
        cron_expression: str = "",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanSchedule:
        """
        Create a new schedule.

        Args:
            name: Schedule name
            target: Target to scan
            policy: Scan policy
            recurrence: Recurrence type
            cron_expression: Cron expression (for CRON type)
            start_time: When to start scheduling
            end_time: When schedule expires
            metadata: Additional metadata

        Returns:
            Created schedule
        """
        schedule = ScanSchedule(
            name=name,
            target=target,
            policy=policy,
            recurrence=recurrence,
            cron_expression=cron_expression,
            start_time=start_time,
            end_time=end_time,
            metadata=metadata or {},
        )

        self.store.add_schedule(schedule)
        logger.info(f"Created schedule {schedule.id}: {name}")
        return schedule

    def get_schedule(self, schedule_id: str) -> Optional[ScanSchedule]:
        """Get a schedule by ID."""
        return self.store.get_schedule(schedule_id)

    def list_schedules(
        self,
        status: Optional[ScheduleStatus] = None,
        target: Optional[str] = None,
    ) -> List[ScanSchedule]:
        """List schedules."""
        return self.store.list_schedules(status, target)

    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a schedule."""
        schedule = self.store.get_schedule(schedule_id)
        if schedule:
            schedule.pause()
            self.store.update_schedule(schedule)
            logger.info(f"Paused schedule {schedule_id}")
            return True
        return False

    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused schedule."""
        schedule = self.store.get_schedule(schedule_id)
        if schedule:
            schedule.resume()
            self.store.update_schedule(schedule)
            logger.info(f"Resumed schedule {schedule_id}")
            return True
        return False

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        return self.store.delete_schedule(schedule_id)

    def run_now(self, schedule_id: str) -> Optional[ScanJob]:
        """
        Immediately run a schedule (bypasses timing).

        Args:
            schedule_id: Schedule to run

        Returns:
            Created job or None if schedule not found
        """
        schedule = self.store.get_schedule(schedule_id)
        if not schedule:
            return None

        if not self._job_semaphore.acquire(blocking=False):
            logger.warning("Max concurrent jobs reached")
            return None

        job = ScanJob(
            schedule_id=schedule.id,
            target=schedule.target,
            policy=schedule.policy,
        )

        self.store.add_job(job)

        thread = threading.Thread(
            target=self._execute_job,
            args=(job,),
            daemon=True,
        )
        thread.start()

        logger.info(f"Triggered immediate run for schedule {schedule_id}")
        return job

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Get a job by ID."""
        return self.store.get_job(job_id)

    def list_jobs(
        self,
        schedule_id: Optional[str] = None,
        status: Optional[JobStatus] = None,
        limit: int = 100,
    ) -> List[ScanJob]:
        """List jobs."""
        return self.store.list_jobs(schedule_id, status, limit)

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job."""
        job = self.store.get_job(job_id)
        if job and job.status in (JobStatus.PENDING, JobStatus.RUNNING):
            job.cancel()
            self.store.update_job(job)
            logger.info(f"Cancelled job {job_id}")
            return True
        return False

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        schedules = self.store.list_schedules()
        jobs = self.store.list_jobs(limit=1000)

        active = sum(1 for s in schedules if s.status == ScheduleStatus.ACTIVE)
        running = sum(1 for j in jobs if j.status == JobStatus.RUNNING)
        completed = sum(1 for j in jobs if j.status == JobStatus.COMPLETED)
        failed = sum(1 for j in jobs if j.status == JobStatus.FAILED)

        return {
            "running": self._running,
            "schedules_total": len(schedules),
            "schedules_active": active,
            "jobs_running": running,
            "jobs_completed": completed,
            "jobs_failed": failed,
            "max_concurrent": self.config.max_concurrent_jobs,
        }


# Global scheduler instance
_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler
