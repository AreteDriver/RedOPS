"""
Scan executor for scheduled jobs.

Bridges the scheduler with RedOPS pipeline execution.
"""

from typing import Any, Callable
from datetime import datetime, timezone
import logging
import traceback

from .models import ScanJob, ScanPolicy

logger = logging.getLogger(__name__)


class ScanExecutor:
    """
    Executes scheduled scan jobs using RedOPS pipelines.

    This class bridges the scheduler with the actual pipeline execution,
    handling job lifecycle, notifications, and result processing.
    """

    def __init__(
        self,
        pipeline_registry: dict[str, Callable] | None = None,
        notification_handler: Callable[[ScanJob, str], None] | None = None,
    ):
        """
        Initialize the executor.

        Args:
            pipeline_registry: Map of pipeline names to callables
            notification_handler: Function to send notifications
        """
        self._pipelines = pipeline_registry or {}
        self._notification_handler = notification_handler
        self._pre_hooks: list[Callable[[ScanJob], None]] = []
        self._post_hooks: list[Callable[[ScanJob], None]] = []

    def register_pipeline(self, name: str, pipeline: Callable) -> None:
        """
        Register a pipeline for execution.

        Args:
            name: Pipeline name
            pipeline: Callable that takes (target, **params) and returns Context
        """
        self._pipelines[name] = pipeline
        logger.info(f"Registered pipeline: {name}")

    def register_pre_hook(self, hook: Callable[[ScanJob], None]) -> None:
        """Register a pre-execution hook."""
        self._pre_hooks.append(hook)

    def register_post_hook(self, hook: Callable[[ScanJob], None]) -> None:
        """Register a post-execution hook."""
        self._post_hooks.append(hook)

    def set_notification_handler(
        self,
        handler: Callable[[ScanJob, str], None],
    ) -> None:
        """
        Set the notification handler.

        Args:
            handler: Function that takes (job, message) and sends notifications
        """
        self._notification_handler = handler

    def execute(self, job: ScanJob) -> None:
        """
        Execute a scan job.

        This is the main entry point called by the scheduler.

        Args:
            job: Job to execute
        """
        logger.info(f"Starting job {job.id} for target {job.target}")

        try:
            # Run pre-hooks
            for hook in self._pre_hooks:
                try:
                    hook(job)
                except (RuntimeError, TypeError, ValueError, OSError) as e:
                    logger.warning(f"Pre-hook error: {e}")

            # Get pipeline
            pipeline_name = job.policy.pipeline
            if pipeline_name not in self._pipelines:
                raise ValueError(f"Pipeline not found: {pipeline_name}")

            pipeline = self._pipelines[pipeline_name]

            # Build params
            params = dict(job.policy.params)
            params["target"] = job.target

            if job.policy.modules:
                params["modules"] = job.policy.modules

            # Execute pipeline
            logger.info(f"Executing pipeline {pipeline_name} for {job.target}")
            result = pipeline(**params)

            # Process result
            findings_count = self._count_findings(result)
            result_data = self._extract_result_data(result, job.policy)

            # Update job
            job.complete(result_data, findings_count)

            # Notify on completion
            if job.policy.notify_on_complete:
                self._send_notification(
                    job,
                    f"Scan completed for {job.target}: {findings_count} findings",
                )

            logger.info(f"Job {job.id} completed: {findings_count} findings")

        except (RuntimeError, ImportError, TypeError, ValueError, OSError, ConnectionError) as e:
            error_msg = str(e)
            logger.error(f"Job {job.id} failed: {error_msg}")
            logger.debug(traceback.format_exc())

            job.fail(error_msg)

            # Notify on failure
            if job.policy.notify_on_failure:
                self._send_notification(
                    job,
                    f"Scan failed for {job.target}: {error_msg}",
                )

        finally:
            # Run post-hooks
            for hook in self._post_hooks:
                try:
                    hook(job)
                except (RuntimeError, TypeError, ValueError, OSError) as e:
                    logger.warning(f"Post-hook error: {e}")

    def _count_findings(self, result: Any) -> int:
        """Count findings in result."""
        if result is None:
            return 0

        # Handle Context object
        if hasattr(result, "data"):
            return sum(1 for k in result.data if k.startswith("finding_"))

        # Handle dict
        if isinstance(result, dict):
            return sum(1 for k in result if k.startswith("finding_"))

        return 0

    def _extract_result_data(
        self,
        result: Any,
        policy: ScanPolicy,
    ) -> dict[str, Any]:
        """Extract relevant data from result."""
        data: dict[str, Any] = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
        }

        if result is None:
            return data

        # Get severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        findings = []
        result_data = (
            getattr(result, "data", result) if hasattr(result, "data") else result
        )

        if isinstance(result_data, dict):
            for key, value in result_data.items():
                if key.startswith("finding_") and isinstance(value, dict):
                    severity = value.get("severity", "info").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                    # Filter by min_severity
                    if self._severity_meets_threshold(severity, policy.min_severity):
                        findings.append(
                            {
                                "title": value.get("title", key),
                                "severity": severity,
                                "module": value.get("module", "unknown"),
                            }
                        )

        data["severity_counts"] = severity_counts
        data["findings_summary"] = findings
        data["target"] = getattr(result, "target", None)

        return data

    def _severity_meets_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets minimum threshold."""
        levels = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return levels.get(severity.lower(), 0) >= levels.get(threshold.lower(), 0)

    def _send_notification(self, job: ScanJob, message: str) -> None:
        """Send notification for job."""
        if self._notification_handler:
            try:
                self._notification_handler(job, message)
            except (RuntimeError, TypeError, ValueError, OSError, ConnectionError) as e:
                logger.error(f"Notification failed: {e}")


def create_default_executor() -> ScanExecutor:
    """
    Create an executor with default RedOPS pipelines.

    Returns:
        Configured ScanExecutor
    """
    executor = ScanExecutor()

    # Try to import and register standard pipelines
    try:
        from redops.pipelines import get_pipeline_registry

        registry = get_pipeline_registry()
        for name, pipeline in registry.items():
            executor.register_pipeline(name, pipeline)
    except ImportError:
        logger.warning("Could not import RedOPS pipelines")

    return executor


def execute_scheduled_scan(
    target: str,
    pipeline: str,
    modules: list[str] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Execute a one-off scheduled scan.

    Convenience function for running a scan with scheduling parameters
    without creating a full schedule.

    Args:
        target: Target to scan
        pipeline: Pipeline name
        modules: Specific modules to run
        params: Additional parameters

    Returns:
        Scan result data
    """
    from .models import ScanPolicy, ScanJob

    policy = ScanPolicy(
        name="adhoc",
        pipeline=pipeline,
        modules=modules or [],
        params=params or {},
    )

    job = ScanJob(
        schedule_id="adhoc",
        target=target,
        policy=policy,
    )

    executor = create_default_executor()
    executor.execute(job)

    return job.to_dict()
