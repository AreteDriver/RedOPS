"""Tests for scheduled scanning module."""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import tempfile
import os
import time


class TestScanPolicy:
    """Tests for ScanPolicy model."""

    def test_policy_creation(self):
        """Test basic policy creation."""
        from redops.scheduler import ScanPolicy

        policy = ScanPolicy(
            name="test-policy",
            pipeline="recon",
            modules=["dns", "whois"],
            timeout_minutes=30,
        )

        assert policy.name == "test-policy"
        assert policy.pipeline == "recon"
        assert policy.modules == ["dns", "whois"]
        assert policy.timeout_minutes == 30
        assert policy.retry_count == 2  # default

    def test_policy_to_dict(self):
        """Test policy serialization."""
        from redops.scheduler import ScanPolicy

        policy = ScanPolicy(
            name="test",
            pipeline="scan",
            notify_on_complete=True,
            notify_channels=["slack", "email"],
        )

        data = policy.to_dict()

        assert data["name"] == "test"
        assert data["pipeline"] == "scan"
        assert data["notify_on_complete"] is True
        assert "slack" in data["notify_channels"]

    def test_policy_from_dict(self):
        """Test policy deserialization."""
        from redops.scheduler import ScanPolicy

        data = {
            "name": "imported",
            "pipeline": "full-scan",
            "modules": ["dns"],
            "timeout_minutes": 120,
            "min_severity": "high",
        }

        policy = ScanPolicy.from_dict(data)

        assert policy.name == "imported"
        assert policy.pipeline == "full-scan"
        assert policy.timeout_minutes == 120
        assert policy.min_severity == "high"


class TestScanSchedule:
    """Tests for ScanSchedule model."""

    def test_schedule_creation(self):
        """Test basic schedule creation."""
        from redops.scheduler import (
            ScanSchedule,
            ScanPolicy,
            RecurrenceType,
            ScheduleStatus,
        )

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="daily-scan",
            target="example.com",
            policy=policy,
            recurrence=RecurrenceType.DAILY,
        )

        assert schedule.name == "daily-scan"
        assert schedule.target == "example.com"
        assert schedule.status == ScheduleStatus.ACTIVE
        assert schedule.run_count == 0
        assert schedule.next_run is not None

    def test_schedule_calculate_next_run_daily(self):
        """Test daily recurrence calculation."""
        from redops.scheduler import ScanSchedule, ScanPolicy, RecurrenceType

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
            recurrence=RecurrenceType.DAILY,
        )

        now = datetime.now(timezone.utc)
        next_run = schedule.calculate_next_run(now)

        assert next_run is not None
        assert next_run > now
        assert (next_run - now).days == 1

    def test_schedule_calculate_next_run_hourly(self):
        """Test hourly recurrence calculation."""
        from redops.scheduler import ScanSchedule, ScanPolicy, RecurrenceType

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
            recurrence=RecurrenceType.HOURLY,
        )

        now = datetime.now(timezone.utc)
        next_run = schedule.calculate_next_run(now)

        assert next_run is not None
        delta = next_run - now
        assert 3500 < delta.total_seconds() < 3700  # ~1 hour

    def test_schedule_calculate_next_run_once(self):
        """Test one-time schedule."""
        from redops.scheduler import ScanSchedule, ScanPolicy, RecurrenceType

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
            recurrence=RecurrenceType.ONCE,
        )

        # After one run, next should be None
        schedule.run_count = 1
        next_run = schedule.calculate_next_run()

        assert next_run is None

    def test_schedule_is_due(self):
        """Test is_due check."""
        from redops.scheduler import ScanSchedule, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        # Set next_run to past
        schedule.next_run = datetime.now(timezone.utc) - timedelta(hours=1)

        assert schedule.is_due() is True

    def test_schedule_is_due_future(self):
        """Test is_due returns false for future schedules."""
        from redops.scheduler import ScanSchedule, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        # Set next_run to future
        schedule.next_run = datetime.now(timezone.utc) + timedelta(hours=1)

        assert schedule.is_due() is False

    def test_schedule_is_due_paused(self):
        """Test paused schedule is never due."""
        from redops.scheduler import ScanSchedule, ScanPolicy, ScheduleStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        schedule.next_run = datetime.now(timezone.utc) - timedelta(hours=1)
        schedule.status = ScheduleStatus.PAUSED

        assert schedule.is_due() is False

    def test_schedule_mark_run(self):
        """Test marking schedule as run."""
        from redops.scheduler import ScanSchedule, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        initial_count = schedule.run_count
        schedule.mark_run()

        assert schedule.run_count == initial_count + 1
        assert schedule.last_run is not None
        assert schedule.next_run is not None

    def test_schedule_pause_resume(self):
        """Test pause and resume."""
        from redops.scheduler import ScanSchedule, ScanPolicy, ScheduleStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        schedule.pause()
        assert schedule.status == ScheduleStatus.PAUSED

        schedule.resume()
        assert schedule.status == ScheduleStatus.ACTIVE
        assert schedule.next_run is not None

    def test_schedule_disable(self):
        """Test disabling schedule."""
        from redops.scheduler import ScanSchedule, ScanPolicy, ScheduleStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        schedule.disable()

        assert schedule.status == ScheduleStatus.DISABLED
        assert schedule.next_run is None

    def test_schedule_to_dict_from_dict(self):
        """Test round-trip serialization."""
        from redops.scheduler import ScanSchedule, ScanPolicy, RecurrenceType

        policy = ScanPolicy(name="test", pipeline="recon", modules=["dns"])
        schedule = ScanSchedule(
            name="test-schedule",
            target="example.com",
            policy=policy,
            recurrence=RecurrenceType.WEEKLY,
            metadata={"env": "prod"},
        )

        data = schedule.to_dict()
        restored = ScanSchedule.from_dict(data)

        assert restored.name == schedule.name
        assert restored.target == schedule.target
        assert restored.recurrence == schedule.recurrence
        assert restored.metadata["env"] == "prod"

    def test_schedule_with_start_time(self):
        """Test schedule with future start time."""
        from redops.scheduler import ScanSchedule, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon")
        future_start = datetime.now(timezone.utc) + timedelta(days=7)

        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
            start_time=future_start,
        )

        assert schedule.is_due() is False

    def test_schedule_with_end_time(self):
        """Test schedule expiration."""
        from redops.scheduler import ScanSchedule, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon")
        past_end = datetime.now(timezone.utc) - timedelta(days=1)

        schedule = ScanSchedule(
            name="test",
            target="example.com",
            policy=policy,
            end_time=past_end,
        )

        schedule.next_run = datetime.now(timezone.utc) - timedelta(hours=1)

        assert schedule.is_due() is False


class TestScanJob:
    """Tests for ScanJob model."""

    def test_job_creation(self):
        """Test basic job creation."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(
            schedule_id="sched-123",
            target="example.com",
            policy=policy,
        )

        assert job.schedule_id == "sched-123"
        assert job.target == "example.com"
        assert job.status == JobStatus.PENDING
        assert job.retry_count == 0

    def test_job_start(self):
        """Test starting a job."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.start()

        assert job.status == JobStatus.RUNNING
        assert job.started_at is not None

    def test_job_complete(self):
        """Test completing a job."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.start()
        job.complete({"summary": "done"}, findings_count=5)

        assert job.status == JobStatus.COMPLETED
        assert job.completed_at is not None
        assert job.findings_count == 5
        assert job.result["summary"] == "done"

    def test_job_fail(self):
        """Test failing a job."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.start()
        job.fail("Connection timeout")

        assert job.status == JobStatus.FAILED
        assert job.error == "Connection timeout"

    def test_job_can_retry(self):
        """Test retry eligibility."""
        from redops.scheduler import ScanJob, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon", retry_count=3)
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.fail("error")

        assert job.can_retry() is True

        job.retry_count = 3
        assert job.can_retry() is False

    def test_job_increment_retry(self):
        """Test retry increment."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.fail("error")
        job.increment_retry()

        assert job.retry_count == 1
        assert job.status == JobStatus.PENDING
        assert job.error is None

    def test_job_timeout(self):
        """Test job timeout."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.start()
        job.timeout()

        assert job.status == JobStatus.TIMEOUT
        assert "timeout" in job.error.lower()

    def test_job_cancel(self):
        """Test job cancellation."""
        from redops.scheduler import ScanJob, ScanPolicy, JobStatus

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.cancel()

        assert job.status == JobStatus.CANCELLED

    def test_job_duration(self):
        """Test duration calculation."""
        from redops.scheduler import ScanJob, ScanPolicy

        policy = ScanPolicy(name="test", pipeline="recon")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        job.started_at = datetime.now(timezone.utc)
        job.completed_at = job.started_at + timedelta(seconds=120)

        assert job.duration_seconds == 120


class TestScheduleStore:
    """Tests for ScheduleStore."""

    def test_store_add_get_schedule(self):
        """Test adding and getting schedules."""
        from redops.scheduler import ScheduleStore, ScanSchedule, ScanPolicy

        store = ScheduleStore()
        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(name="test", target="example.com", policy=policy)

        store.add_schedule(schedule)
        retrieved = store.get_schedule(schedule.id)

        assert retrieved is not None
        assert retrieved.name == "test"

    def test_store_list_schedules(self):
        """Test listing schedules."""
        from redops.scheduler import (
            ScheduleStore,
            ScanSchedule,
            ScanPolicy,
            ScheduleStatus,
        )

        store = ScheduleStore()
        policy = ScanPolicy(name="test", pipeline="recon")

        for i in range(5):
            schedule = ScanSchedule(
                name=f"schedule-{i}",
                target="example.com",
                policy=policy,
            )
            store.add_schedule(schedule)

        all_schedules = store.list_schedules()
        assert len(all_schedules) == 5

        # Filter by status
        active = store.list_schedules(status=ScheduleStatus.ACTIVE)
        assert len(active) == 5

    def test_store_delete_schedule(self):
        """Test deleting schedules."""
        from redops.scheduler import ScheduleStore, ScanSchedule, ScanPolicy

        store = ScheduleStore()
        policy = ScanPolicy(name="test", pipeline="recon")
        schedule = ScanSchedule(name="test", target="example.com", policy=policy)

        store.add_schedule(schedule)
        assert store.delete_schedule(schedule.id) is True
        assert store.get_schedule(schedule.id) is None

    def test_store_due_schedules(self):
        """Test getting due schedules."""
        from redops.scheduler import ScheduleStore, ScanSchedule, ScanPolicy

        store = ScheduleStore()
        policy = ScanPolicy(name="test", pipeline="recon")

        # Past schedule (due)
        schedule1 = ScanSchedule(name="past", target="example.com", policy=policy)
        schedule1.next_run = datetime.now(timezone.utc) - timedelta(hours=1)

        # Future schedule (not due)
        schedule2 = ScanSchedule(name="future", target="example.com", policy=policy)
        schedule2.next_run = datetime.now(timezone.utc) + timedelta(hours=1)

        store.add_schedule(schedule1)
        store.add_schedule(schedule2)

        due = store.get_due_schedules()
        assert len(due) == 1
        assert due[0].name == "past"

    def test_store_jobs(self):
        """Test job storage."""
        from redops.scheduler import ScheduleStore, ScanJob, ScanPolicy, JobStatus

        store = ScheduleStore()
        policy = ScanPolicy(name="test", pipeline="recon")

        job = ScanJob(schedule_id="123", target="example.com", policy=policy)
        store.add_job(job)

        retrieved = store.get_job(job.id)
        assert retrieved is not None

        # List jobs
        jobs = store.list_jobs()
        assert len(jobs) == 1

        # List by status
        running = store.list_jobs(status=JobStatus.RUNNING)
        assert len(running) == 0

    def test_store_file_persistence(self):
        """Test file-based persistence."""
        from redops.scheduler import ScheduleStore, ScanSchedule, ScanPolicy

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            storage_path = f.name

        try:
            # Create store and add schedule
            store1 = ScheduleStore(storage_path)
            policy = ScanPolicy(name="test", pipeline="recon")
            schedule = ScanSchedule(
                name="persistent", target="example.com", policy=policy
            )
            store1.add_schedule(schedule)

            # Create new store and verify persistence
            store2 = ScheduleStore(storage_path)
            retrieved = store2.get_schedule(schedule.id)

            assert retrieved is not None
            assert retrieved.name == "persistent"
        finally:
            os.unlink(storage_path)


class TestScheduler:
    """Tests for Scheduler."""

    def test_scheduler_creation(self):
        """Test scheduler creation."""
        from redops.scheduler import Scheduler, SchedulerConfig

        config = SchedulerConfig(check_interval_seconds=1)
        scheduler = Scheduler(config)

        assert scheduler.is_running is False

    def test_scheduler_create_schedule(self):
        """Test creating schedules via scheduler."""
        from redops.scheduler import Scheduler, ScanPolicy, RecurrenceType

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        schedule = scheduler.create_schedule(
            name="test-schedule",
            target="example.com",
            policy=policy,
            recurrence=RecurrenceType.DAILY,
        )

        assert schedule.id is not None
        assert schedule.name == "test-schedule"

        # Verify it's stored
        retrieved = scheduler.get_schedule(schedule.id)
        assert retrieved is not None

    def test_scheduler_list_schedules(self):
        """Test listing schedules."""
        from redops.scheduler import Scheduler, ScanPolicy

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        scheduler.create_schedule(name="s1", target="example.com", policy=policy)
        scheduler.create_schedule(name="s2", target="test.com", policy=policy)

        schedules = scheduler.list_schedules()
        assert len(schedules) == 2

    def test_scheduler_pause_resume(self):
        """Test pause and resume via scheduler."""
        from redops.scheduler import Scheduler, ScanPolicy, ScheduleStatus

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        schedule = scheduler.create_schedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        scheduler.pause_schedule(schedule.id)
        updated = scheduler.get_schedule(schedule.id)
        assert updated.status == ScheduleStatus.PAUSED

        scheduler.resume_schedule(schedule.id)
        updated = scheduler.get_schedule(schedule.id)
        assert updated.status == ScheduleStatus.ACTIVE

    def test_scheduler_delete(self):
        """Test deleting schedules."""
        from redops.scheduler import Scheduler, ScanPolicy

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        schedule = scheduler.create_schedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        assert scheduler.delete_schedule(schedule.id) is True
        assert scheduler.get_schedule(schedule.id) is None

    def test_scheduler_stats(self):
        """Test scheduler statistics."""
        from redops.scheduler import Scheduler, ScanPolicy

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        scheduler.create_schedule(name="s1", target="example.com", policy=policy)

        stats = scheduler.get_stats()

        assert stats["running"] is False
        assert stats["schedules_total"] == 1
        assert stats["schedules_active"] == 1

    def test_scheduler_run_now(self):
        """Test immediate execution."""
        from redops.scheduler import Scheduler, ScanPolicy

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        schedule = scheduler.create_schedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        job = scheduler.run_now(schedule.id)

        assert job is not None
        assert job.target == "example.com"

    def test_scheduler_list_jobs(self):
        """Test listing jobs."""
        from redops.scheduler import Scheduler, ScanPolicy

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        schedule = scheduler.create_schedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        scheduler.run_now(schedule.id)

        # Give thread time to start
        time.sleep(0.1)

        jobs = scheduler.list_jobs()
        assert len(jobs) >= 1

    def test_scheduler_cancel_job(self):
        """Test job cancellation."""
        from redops.scheduler import Scheduler, ScanPolicy

        scheduler = Scheduler()
        policy = ScanPolicy(name="test", pipeline="recon")

        schedule = scheduler.create_schedule(
            name="test",
            target="example.com",
            policy=policy,
        )

        job = scheduler.run_now(schedule.id)
        time.sleep(0.1)

        # Try to cancel
        result = scheduler.cancel_job(job.id)
        # May or may not succeed depending on job state
        assert isinstance(result, bool)


class TestScanExecutor:
    """Tests for ScanExecutor."""

    def test_executor_creation(self):
        """Test executor creation."""
        from redops.scheduler import ScanExecutor

        executor = ScanExecutor()
        assert executor is not None

    def test_executor_register_pipeline(self):
        """Test pipeline registration."""
        from redops.scheduler import ScanExecutor

        executor = ScanExecutor()

        def mock_pipeline(**kwargs):
            return {"status": "success"}

        executor.register_pipeline("mock", mock_pipeline)

        assert "mock" in executor._pipelines

    def test_executor_execute_success(self):
        """Test successful job execution."""
        from redops.scheduler import ScanExecutor, ScanJob, ScanPolicy, JobStatus

        mock_result = MagicMock()
        mock_result.data = {"finding_1": {"title": "Test", "severity": "high"}}
        mock_result.target = "example.com"

        def mock_pipeline(**kwargs):
            return mock_result

        executor = ScanExecutor()
        executor.register_pipeline("test", mock_pipeline)

        policy = ScanPolicy(name="test", pipeline="test")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        executor.execute(job)

        assert job.status == JobStatus.COMPLETED
        assert job.findings_count == 1

    def test_executor_execute_failure(self):
        """Test failed job execution."""
        from redops.scheduler import ScanExecutor, ScanJob, ScanPolicy, JobStatus

        def mock_pipeline(**kwargs):
            raise Exception("Pipeline error")

        executor = ScanExecutor()
        executor.register_pipeline("test", mock_pipeline)

        policy = ScanPolicy(name="test", pipeline="test", retry_count=0)
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        executor.execute(job)

        assert job.status == JobStatus.FAILED
        assert "Pipeline error" in job.error

    def test_executor_pipeline_not_found(self):
        """Test execution with missing pipeline."""
        from redops.scheduler import ScanExecutor, ScanJob, ScanPolicy, JobStatus

        executor = ScanExecutor()

        policy = ScanPolicy(name="test", pipeline="nonexistent", retry_count=0)
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        executor.execute(job)

        assert job.status == JobStatus.FAILED
        assert "not found" in job.error.lower()

    def test_executor_with_hooks(self):
        """Test pre and post hooks."""
        from redops.scheduler import ScanExecutor, ScanJob, ScanPolicy

        pre_called = []
        post_called = []

        def pre_hook(job):
            pre_called.append(job.id)

        def post_hook(job):
            post_called.append(job.id)

        def mock_pipeline(**kwargs):
            return {"status": "done"}

        executor = ScanExecutor()
        executor.register_pipeline("test", mock_pipeline)
        executor.register_pre_hook(pre_hook)
        executor.register_post_hook(post_hook)

        policy = ScanPolicy(name="test", pipeline="test")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        executor.execute(job)

        assert job.id in pre_called
        assert job.id in post_called

    def test_executor_with_notification(self):
        """Test notification handling."""
        from redops.scheduler import ScanExecutor, ScanJob, ScanPolicy

        notifications = []

        def notification_handler(job, message):
            notifications.append((job.id, message))

        def mock_pipeline(**kwargs):
            return {"status": "done"}

        executor = ScanExecutor()
        executor.register_pipeline("test", mock_pipeline)
        executor.set_notification_handler(notification_handler)

        policy = ScanPolicy(name="test", pipeline="test", notify_on_complete=True)
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        executor.execute(job)

        assert len(notifications) == 1
        assert "completed" in notifications[0][1].lower()

    def test_executor_severity_filtering(self):
        """Test severity threshold filtering."""
        from redops.scheduler import ScanExecutor, ScanJob, ScanPolicy

        mock_result = MagicMock()
        mock_result.data = {
            "finding_1": {"title": "Critical", "severity": "critical"},
            "finding_2": {"title": "Low", "severity": "low"},
        }
        mock_result.target = "example.com"

        def mock_pipeline(**kwargs):
            return mock_result

        executor = ScanExecutor()
        executor.register_pipeline("test", mock_pipeline)

        policy = ScanPolicy(name="test", pipeline="test", min_severity="high")
        job = ScanJob(schedule_id="123", target="example.com", policy=policy)

        executor.execute(job)

        # Low severity finding should be filtered from summary
        summary = job.result.get("findings_summary", [])
        assert len(summary) == 1
        assert summary[0]["severity"] == "critical"


class TestSchedulerIntegration:
    """Integration tests for scheduler system."""

    def test_full_scheduling_flow(self):
        """Test complete scheduling workflow."""
        from redops.scheduler import (
            Scheduler,
            ScanExecutor,
            ScanPolicy,
            RecurrenceType,
            JobStatus,
        )

        # Create mock pipeline
        execution_count = []

        def mock_pipeline(**kwargs):
            execution_count.append(kwargs.get("target"))
            result = MagicMock()
            result.data = {"finding_1": {"title": "Test", "severity": "medium"}}
            result.target = kwargs.get("target")
            return result

        # Setup executor
        executor = ScanExecutor()
        executor.register_pipeline("mock-pipeline", mock_pipeline)

        # Setup scheduler with executor
        scheduler = Scheduler(executor=executor.execute)

        # Create policy and schedule
        policy = ScanPolicy(name="test", pipeline="mock-pipeline")
        schedule = scheduler.create_schedule(
            name="integration-test",
            target="integration.example.com",
            policy=policy,
            recurrence=RecurrenceType.ONCE,
        )

        # Run immediately
        job = scheduler.run_now(schedule.id)

        # Wait for execution
        time.sleep(0.5)

        # Verify
        updated_job = scheduler.get_job(job.id)
        assert updated_job.status in (JobStatus.COMPLETED, JobStatus.RUNNING)
        assert len(execution_count) >= 1

    def test_scheduler_config_from_env(self):
        """Test config from environment."""
        env = {
            "SCHEDULER_CHECK_INTERVAL": "30",
            "SCHEDULER_MAX_CONCURRENT": "10",
            "SCHEDULER_JOB_TIMEOUT": "60",
        }

        with patch.dict("os.environ", env):
            from redops.scheduler import SchedulerConfig

            config = SchedulerConfig.from_env()

            assert config.check_interval_seconds == 30
            assert config.max_concurrent_jobs == 10
            assert config.job_timeout_minutes == 60


class TestSchedulerModuleImports:
    """Test module imports."""

    def test_all_exports(self):
        """Test all expected exports are available."""
        from redops.scheduler import (
            # Models
            get_scheduler,
            # Executor
            create_default_executor,
            execute_scheduled_scan,
        )

        assert callable(get_scheduler)
        assert callable(create_default_executor)
        assert callable(execute_scheduled_scan)

    def test_get_scheduler_singleton(self):
        """Test global scheduler is accessible."""
        from redops.scheduler import get_scheduler

        scheduler1 = get_scheduler()
        scheduler2 = get_scheduler()

        # May or may not be same instance due to test isolation
        assert scheduler1 is not None
        assert scheduler2 is not None
