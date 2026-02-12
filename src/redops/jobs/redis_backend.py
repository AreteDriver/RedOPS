"""
Redis Backend for Job Queue.

Provides distributed job processing using Redis.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from redops.jobs.queue import (
    Job,
    JobBackend,
    JobQueue,
    JobStatus,
    JobWorker,
)

logger = logging.getLogger(__name__)


class RedisJobBackend(JobBackend):
    """
    Redis-backed job storage.

    Uses Redis lists for queues and hashes for job data.
    Supports distributed workers and job persistence.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        redis_client: Any | None = None,
        key_prefix: str = "redops:jobs",
    ):
        """
        Initialize Redis backend.

        Args:
            redis_url: Redis connection URL
            redis_client: Existing Redis client
            key_prefix: Prefix for Redis keys
        """
        if redis_client:
            self._redis = redis_client
        else:
            try:
                import redis

                self._redis = redis.from_url(redis_url, decode_responses=True)
            except ImportError:
                raise ImportError("redis package required: pip install redis")

        self._prefix = key_prefix

    def _key(self, *parts: str) -> str:
        """Build Redis key."""
        return ":".join([self._prefix] + list(parts))

    def enqueue(self, job: Job) -> str:
        """Add job to queue."""
        # Store job data
        job_key = self._key("job", job.id)
        job.status = JobStatus.QUEUED

        self._redis.hset(
            job_key,
            mapping={
                "data": json.dumps(job.to_dict()),
                "status": job.status.value,
                "queue": job.queue,
                "priority": job.priority.value,
                "created_at": job.created_at.isoformat(),
            },
        )

        # Add to queue (use sorted set for priority)
        queue_key = self._key("queue", job.queue)
        # Score: negative priority (higher = processed first) + timestamp for ordering
        score = -job.priority.value * 1e10 + time.time()
        self._redis.zadd(queue_key, {job.id: score})

        # Handle scheduled jobs
        if job.scheduled_at and job.scheduled_at > datetime.now(timezone.utc):
            # Move to scheduled set
            self._redis.zrem(queue_key, job.id)
            scheduled_key = self._key("scheduled")
            self._redis.zadd(
                scheduled_key, {f"{job.queue}:{job.id}": job.scheduled_at.timestamp()}
            )

        logger.debug(f"Enqueued job {job.id} to queue {job.queue}")
        return job.id

    def dequeue(self, queue: str, timeout: float = 0) -> Job | None:
        """Get next job from queue."""
        queue_key = self._key("queue", queue)
        processing_key = self._key("processing", queue)

        start = time.time()
        while True:
            # Move job from queue to processing (atomic)
            # Using BZPOPMIN for blocking pop
            if timeout > 0:
                remaining = max(0.1, timeout - (time.time() - start))
                result = self._redis.bzpopmin(queue_key, timeout=remaining)
            else:
                result = self._redis.zpopmin(queue_key)

            if not result:
                if timeout <= 0:
                    return None
                if time.time() - start >= timeout:
                    return None
                continue

            # result is (key, member, score) for blocking or [(member, score)] for non-blocking
            if isinstance(result, tuple):
                job_id = result[1]
            else:
                job_id = result[0][0]

            # Get job data
            job = self.get(job_id)
            if not job:
                continue

            if job.status != JobStatus.QUEUED:
                continue

            # Mark as running
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(timezone.utc)
            self.update(job)

            # Add to processing set
            self._redis.zadd(processing_key, {job_id: time.time()})

            return job

    def get(self, job_id: str) -> Job | None:
        """Get job by ID."""
        job_key = self._key("job", job_id)
        data = self._redis.hget(job_key, "data")

        if not data:
            return None

        try:
            job_dict = json.loads(data)
            return Job.from_dict(job_dict)
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to deserialize job {job_id}: {e}")
            return None

    def update(self, job: Job) -> None:
        """Update job state."""
        job_key = self._key("job", job.id)

        self._redis.hset(
            job_key,
            mapping={
                "data": json.dumps(job.to_dict()),
                "status": job.status.value,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        # If completed/failed, remove from processing
        if job.status in (
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
            JobStatus.TIMEOUT,
        ):
            processing_key = self._key("processing", job.queue)
            self._redis.zrem(processing_key, job.id)

            # Add to completed set for history
            completed_key = self._key("completed")
            self._redis.zadd(completed_key, {job.id: time.time()})

            # Set TTL on job data (keep for 24 hours)
            self._redis.expire(job_key, 86400)

    def delete(self, job_id: str) -> bool:
        """Delete a job."""
        job = self.get(job_id)
        if not job:
            return False

        # Remove from all sets
        queue_key = self._key("queue", job.queue)
        processing_key = self._key("processing", job.queue)
        scheduled_key = self._key("scheduled")
        completed_key = self._key("completed")

        pipe = self._redis.pipeline()
        pipe.zrem(queue_key, job_id)
        pipe.zrem(processing_key, job_id)
        pipe.zrem(scheduled_key, f"{job.queue}:{job_id}")
        pipe.zrem(completed_key, job_id)
        pipe.delete(self._key("job", job_id))
        pipe.execute()

        return True

    def list_jobs(
        self,
        queue: str | None = None,
        status: JobStatus | None = None,
        limit: int = 100,
    ) -> list[Job]:
        """List jobs."""
        jobs = []

        # Get job IDs from relevant sets
        if status == JobStatus.QUEUED and queue:
            queue_key = self._key("queue", queue)
            job_ids = self._redis.zrange(queue_key, 0, limit - 1)
        elif status == JobStatus.RUNNING and queue:
            processing_key = self._key("processing", queue)
            job_ids = self._redis.zrange(processing_key, 0, limit - 1)
        elif status in (JobStatus.COMPLETED, JobStatus.FAILED):
            completed_key = self._key("completed")
            job_ids = self._redis.zrevrange(completed_key, 0, limit * 2 - 1)
        else:
            # Scan all jobs
            job_ids = []
            cursor = 0
            while len(job_ids) < limit:
                cursor, keys = self._redis.scan(
                    cursor,
                    match=f"{self._prefix}:job:*",
                    count=100,
                )
                for key in keys:
                    job_id = key.split(":")[-1]
                    job_ids.append(job_id)
                if cursor == 0:
                    break

        # Get job data
        for job_id in job_ids[:limit]:
            job = self.get(job_id)
            if job:
                if queue and job.queue != queue:
                    continue
                if status and job.status != status:
                    continue
                jobs.append(job)

        return jobs

    def process_scheduled(self) -> int:
        """
        Move scheduled jobs to their queues when ready.

        Returns:
            Number of jobs moved
        """
        scheduled_key = self._key("scheduled")
        now = time.time()

        # Get jobs ready to run
        ready = self._redis.zrangebyscore(scheduled_key, 0, now)

        count = 0
        for item in ready:
            queue_name, job_id = item.rsplit(":", 1)
            job = self.get(job_id)

            if job and job.status in (JobStatus.QUEUED, JobStatus.RETRYING):
                # Remove from scheduled
                self._redis.zrem(scheduled_key, item)

                # Add to queue
                queue_key = self._key("queue", queue_name)
                score = -job.priority.value * 1e10 + time.time()
                self._redis.zadd(queue_key, {job_id: score})

                job.status = JobStatus.QUEUED
                self.update(job)

                count += 1

        return count

    def cleanup_stale(self, timeout: int = 3600) -> int:
        """
        Clean up stale processing jobs.

        Jobs that have been processing for longer than timeout
        are moved back to queue or marked as failed.

        Args:
            timeout: Processing timeout in seconds

        Returns:
            Number of jobs cleaned up
        """
        count = 0
        cutoff = time.time() - timeout

        # Check all processing queues
        for key in self._redis.scan_iter(f"{self._prefix}:processing:*"):
            key.split(":")[-1]

            # Get stale jobs
            stale = self._redis.zrangebyscore(key, 0, cutoff)

            for job_id in stale:
                job = self.get(job_id)
                if not job:
                    self._redis.zrem(key, job_id)
                    continue

                if job.should_retry():
                    # Re-queue for retry
                    job.status = JobStatus.RETRYING
                    job.error = "Processing timeout - retrying"
                    self.enqueue(job)
                else:
                    # Mark as failed
                    job.status = JobStatus.FAILED
                    job.error = "Processing timeout - max retries exceeded"
                    job.completed_at = datetime.now(timezone.utc)
                    self.update(job)

                self._redis.zrem(key, job_id)
                count += 1

        return count

    def get_stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        stats = {
            "queues": {},
            "total_jobs": 0,
            "scheduled": 0,
            "completed": 0,
        }

        # Count scheduled
        scheduled_key = self._key("scheduled")
        stats["scheduled"] = self._redis.zcard(scheduled_key)

        # Count completed
        completed_key = self._key("completed")
        stats["completed"] = self._redis.zcard(completed_key)

        # Count per queue
        for key in self._redis.scan_iter(f"{self._prefix}:queue:*"):
            queue_name = key.split(":")[-1]
            queued = self._redis.zcard(key)
            processing_key = self._key("processing", queue_name)
            processing = self._redis.zcard(processing_key)

            stats["queues"][queue_name] = {
                "queued": queued,
                "processing": processing,
            }
            stats["total_jobs"] += queued + processing

        stats["total_jobs"] += stats["scheduled"]

        return stats


class RedisJobQueue(JobQueue):
    """
    Job queue with Redis backend.

    Convenience class for Redis-backed job queue.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        redis_client: Any | None = None,
        key_prefix: str = "redops:jobs",
        default_queue: str = "default",
    ):
        """
        Initialize Redis job queue.

        Args:
            redis_url: Redis connection URL
            redis_client: Existing Redis client
            key_prefix: Prefix for Redis keys
            default_queue: Default queue name
        """
        backend = RedisJobBackend(
            redis_url=redis_url,
            redis_client=redis_client,
            key_prefix=key_prefix,
        )
        super().__init__(backend=backend, default_queue=default_queue)

    def process_scheduled(self) -> int:
        """Process scheduled jobs."""
        if isinstance(self._backend, RedisJobBackend):
            return self._backend.process_scheduled()
        return 0

    def cleanup_stale(self, timeout: int = 3600) -> int:
        """Clean up stale jobs."""
        if isinstance(self._backend, RedisJobBackend):
            return self._backend.cleanup_stale(timeout)
        return 0

    def get_stats(self) -> dict[str, Any]:
        """Get queue statistics."""
        if isinstance(self._backend, RedisJobBackend):
            return self._backend.get_stats()
        return {}


class RedisJobWorker(JobWorker):
    """
    Job worker optimized for Redis backend.

    Includes scheduled job processing and stale job cleanup.
    """

    def __init__(
        self,
        queue: RedisJobQueue,
        queues: list[str] | None = None,
        worker_id: str | None = None,
        concurrency: int = 1,
        scheduler_interval: float = 1.0,
        cleanup_interval: float = 60.0,
    ):
        """
        Initialize Redis worker.

        Args:
            queue: Redis job queue
            queues: Queue names to process
            worker_id: Worker identifier
            concurrency: Number of concurrent jobs
            scheduler_interval: Interval for processing scheduled jobs
            cleanup_interval: Interval for cleaning stale jobs
        """
        super().__init__(queue, queues, worker_id, concurrency)
        self._scheduler_interval = scheduler_interval
        self._cleanup_interval = cleanup_interval
        self._scheduler_thread: Any | None = None
        self._cleanup_thread: Any | None = None

    def start(self) -> None:
        """Start worker with scheduler and cleanup threads."""
        super().start()

        import threading

        # Start scheduler thread
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name=f"{self._worker_id}-scheduler",
            daemon=True,
        )
        self._scheduler_thread.start()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name=f"{self._worker_id}-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()

    def stop(self, timeout: float = 30.0) -> None:
        """Stop worker and auxiliary threads."""
        super().stop(timeout)

        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5.0)
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)

    def _scheduler_loop(self) -> None:
        """Process scheduled jobs periodically."""
        while self._running:
            try:
                if isinstance(self._queue, RedisJobQueue):
                    count = self._queue.process_scheduled()
                    if count > 0:
                        logger.debug(f"Moved {count} scheduled jobs to queue")
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

            self._shutdown_event.wait(self._scheduler_interval)

    def _cleanup_loop(self) -> None:
        """Clean up stale jobs periodically."""
        while self._running:
            try:
                if isinstance(self._queue, RedisJobQueue):
                    count = self._queue.cleanup_stale()
                    if count > 0:
                        logger.info(f"Cleaned up {count} stale jobs")
            except Exception as e:
                logger.error(f"Cleanup error: {e}")

            self._shutdown_event.wait(self._cleanup_interval)
