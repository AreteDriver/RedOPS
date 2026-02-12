"""
Rate Limiting for RedOPS.

Provides request throttling, backoff strategies, quota management,
and various rate limiting algorithms.
"""

import random
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Callable, TypeVar

T = TypeVar("T")


class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


class BackoffStrategy(Enum):
    """Backoff strategies for rate limit handling."""

    NONE = "none"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    EXPONENTIAL_JITTER = "exponential_jitter"
    DECORRELATED_JITTER = "decorrelated_jitter"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    requests_per_second: float = 1.0
    burst_size: int = 1
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL_JITTER
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    timeout: float | None = None


@dataclass
class RateLimitState:
    """Current state of rate limiting."""

    tokens: float = 0.0
    last_update: float = field(default_factory=time.time)
    window_start: float = field(default_factory=time.time)
    request_count: int = 0
    request_times: deque = field(default_factory=lambda: deque(maxlen=1000))


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    wait_time: float = 0.0
    remaining: int = 0
    reset_at: float | None = None
    retry_after: float | None = None

    @property
    def headers(self) -> dict[str, str]:
        """Get rate limit headers."""
        headers = {
            "X-RateLimit-Remaining": str(self.remaining),
        }
        if self.reset_at:
            headers["X-RateLimit-Reset"] = str(int(self.reset_at))
        if self.retry_after and not self.allowed:
            headers["Retry-After"] = str(int(self.retry_after))
        return headers


@dataclass
class QuotaInfo:
    """Quota information for a resource."""

    limit: int
    used: int
    remaining: int
    reset_at: float
    period_seconds: int

    @property
    def is_exceeded(self) -> bool:
        """Check if quota is exceeded."""
        return self.remaining <= 0

    @property
    def usage_percent(self) -> float:
        """Get usage percentage."""
        if self.limit == 0:
            return 100.0
        return (self.used / self.limit) * 100


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        retry_after: float | None = None,
        result: RateLimitResult | None = None,
    ):
        super().__init__(message)
        self.retry_after = retry_after
        self.result = result


class QuotaExceededError(Exception):
    """Raised when quota is exceeded."""

    def __init__(self, message: str, quota_info: QuotaInfo | None = None):
        super().__init__(message)
        self.quota_info = quota_info


class BaseRateLimiter(ABC):
    """Abstract base class for rate limiters."""

    @abstractmethod
    def acquire(self, tokens: int = 1) -> RateLimitResult:
        """
        Try to acquire tokens.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            RateLimitResult indicating if allowed
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the rate limiter state."""
        pass

    def wait_and_acquire(self, tokens: int = 1, timeout: float | None = None) -> bool:
        """
        Wait until tokens are available, then acquire.

        Args:
            tokens: Number of tokens to acquire
            timeout: Maximum time to wait

        Returns:
            True if acquired, False if timeout
        """
        start = time.time()
        while True:
            result = self.acquire(tokens)
            if result.allowed:
                return True

            if timeout is not None:
                elapsed = time.time() - start
                if elapsed + result.wait_time > timeout:
                    return False

            time.sleep(min(result.wait_time, 0.1))


class TokenBucketLimiter(BaseRateLimiter):
    """
    Token bucket rate limiter.

    Tokens are added at a fixed rate up to a maximum bucket size.
    Requests consume tokens; if none available, request is denied.
    """

    def __init__(
        self,
        rate: float = 1.0,
        bucket_size: int = 10,
    ):
        self._rate = rate  # tokens per second
        self._bucket_size = bucket_size
        self._tokens = float(bucket_size)
        self._last_update = time.time()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1) -> RateLimitResult:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            self._last_update = now

            # Add tokens based on elapsed time
            self._tokens = min(
                self._bucket_size,
                self._tokens + elapsed * self._rate,
            )

            if self._tokens >= tokens:
                self._tokens -= tokens
                return RateLimitResult(
                    allowed=True,
                    remaining=int(self._tokens),
                )
            else:
                # Calculate wait time
                needed = tokens - self._tokens
                wait_time = needed / self._rate
                return RateLimitResult(
                    allowed=False,
                    wait_time=wait_time,
                    remaining=0,
                    retry_after=wait_time,
                )

    def reset(self) -> None:
        with self._lock:
            self._tokens = float(self._bucket_size)
            self._last_update = time.time()

    @property
    def available_tokens(self) -> float:
        """Get current available tokens."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            return min(
                self._bucket_size,
                self._tokens + elapsed * self._rate,
            )


class SlidingWindowLimiter(BaseRateLimiter):
    """
    Sliding window rate limiter.

    Tracks request timestamps within a sliding window.
    More accurate than fixed window but uses more memory.
    """

    def __init__(
        self,
        requests: int = 10,
        window_seconds: float = 1.0,
    ):
        self._max_requests = requests
        self._window_seconds = window_seconds
        self._request_times: deque = deque()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1) -> RateLimitResult:
        with self._lock:
            now = time.time()
            window_start = now - self._window_seconds

            # Remove old requests outside window
            while self._request_times and self._request_times[0] < window_start:
                self._request_times.popleft()

            current_count = len(self._request_times)

            if current_count + tokens <= self._max_requests:
                # Record request times
                for _ in range(tokens):
                    self._request_times.append(now)

                return RateLimitResult(
                    allowed=True,
                    remaining=self._max_requests - current_count - tokens,
                    reset_at=now + self._window_seconds,
                )
            else:
                # Calculate wait time until oldest request expires
                if self._request_times:
                    oldest = self._request_times[0]
                    wait_time = oldest + self._window_seconds - now
                else:
                    wait_time = 0

                return RateLimitResult(
                    allowed=False,
                    wait_time=max(0, wait_time),
                    remaining=0,
                    retry_after=max(0, wait_time),
                    reset_at=now + self._window_seconds,
                )

    def reset(self) -> None:
        with self._lock:
            self._request_times.clear()

    @property
    def current_count(self) -> int:
        """Get current request count in window."""
        with self._lock:
            now = time.time()
            window_start = now - self._window_seconds
            return sum(1 for t in self._request_times if t >= window_start)


class FixedWindowLimiter(BaseRateLimiter):
    """
    Fixed window rate limiter.

    Counts requests within fixed time windows.
    Simple but can allow bursts at window boundaries.
    """

    def __init__(
        self,
        requests: int = 10,
        window_seconds: float = 1.0,
    ):
        self._max_requests = requests
        self._window_seconds = window_seconds
        self._window_start = time.time()
        self._request_count = 0
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1) -> RateLimitResult:
        with self._lock:
            now = time.time()

            # Check if we need to start a new window
            if now >= self._window_start + self._window_seconds:
                self._window_start = now
                self._request_count = 0

            if self._request_count + tokens <= self._max_requests:
                self._request_count += tokens
                return RateLimitResult(
                    allowed=True,
                    remaining=self._max_requests - self._request_count,
                    reset_at=self._window_start + self._window_seconds,
                )
            else:
                wait_time = self._window_start + self._window_seconds - now
                return RateLimitResult(
                    allowed=False,
                    wait_time=max(0, wait_time),
                    remaining=0,
                    retry_after=max(0, wait_time),
                    reset_at=self._window_start + self._window_seconds,
                )

    def reset(self) -> None:
        with self._lock:
            self._window_start = time.time()
            self._request_count = 0


class LeakyBucketLimiter(BaseRateLimiter):
    """
    Leaky bucket rate limiter.

    Requests are queued and processed at a fixed rate.
    Provides smooth output rate regardless of input burstiness.
    """

    def __init__(
        self,
        rate: float = 1.0,
        bucket_size: int = 10,
    ):
        self._rate = rate  # requests per second
        self._bucket_size = bucket_size
        self._water_level = 0.0
        self._last_leak = time.time()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1) -> RateLimitResult:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_leak
            self._last_leak = now

            # Leak water based on elapsed time
            leaked = elapsed * self._rate
            self._water_level = max(0, self._water_level - leaked)

            if self._water_level + tokens <= self._bucket_size:
                self._water_level += tokens
                return RateLimitResult(
                    allowed=True,
                    remaining=int(self._bucket_size - self._water_level),
                )
            else:
                # Calculate wait time for water to leak enough
                overflow = self._water_level + tokens - self._bucket_size
                wait_time = overflow / self._rate
                return RateLimitResult(
                    allowed=False,
                    wait_time=wait_time,
                    remaining=0,
                    retry_after=wait_time,
                )

    def reset(self) -> None:
        with self._lock:
            self._water_level = 0.0
            self._last_leak = time.time()


class BackoffCalculator:
    """Calculates backoff delays using various strategies."""

    def __init__(
        self,
        strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL_JITTER,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        multiplier: float = 2.0,
    ):
        self._strategy = strategy
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._multiplier = multiplier
        self._last_delay = base_delay

    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for a given attempt number.

        Args:
            attempt: Attempt number (0-indexed)

        Returns:
            Delay in seconds
        """
        if self._strategy == BackoffStrategy.NONE:
            return 0.0

        elif self._strategy == BackoffStrategy.LINEAR:
            delay = self._base_delay * (attempt + 1)

        elif self._strategy == BackoffStrategy.EXPONENTIAL:
            delay = self._base_delay * (self._multiplier**attempt)

        elif self._strategy == BackoffStrategy.EXPONENTIAL_JITTER:
            # Full jitter: random between 0 and exponential delay
            exp_delay = self._base_delay * (self._multiplier**attempt)
            delay = random.uniform(0, exp_delay)

        elif self._strategy == BackoffStrategy.DECORRELATED_JITTER:
            # Decorrelated jitter: based on previous delay
            delay = random.uniform(self._base_delay, self._last_delay * 3)
            self._last_delay = delay

        else:
            delay = self._base_delay

        return min(delay, self._max_delay)

    def reset(self) -> None:
        """Reset the calculator state."""
        self._last_delay = self._base_delay


class QuotaManager:
    """
    Manages quotas for different resources.

    Tracks usage against limits with automatic reset.
    """

    def __init__(self):
        self._quotas: dict[str, dict] = {}
        self._lock = threading.Lock()

    def set_quota(
        self,
        resource: str,
        limit: int,
        period_seconds: int = 3600,
    ) -> None:
        """
        Set quota for a resource.

        Args:
            resource: Resource identifier
            limit: Maximum allowed usage
            period_seconds: Reset period in seconds
        """
        with self._lock:
            self._quotas[resource] = {
                "limit": limit,
                "used": 0,
                "period_seconds": period_seconds,
                "reset_at": time.time() + period_seconds,
            }

    def use(self, resource: str, amount: int = 1) -> QuotaInfo:
        """
        Use quota for a resource.

        Args:
            resource: Resource identifier
            amount: Amount to use

        Returns:
            QuotaInfo with current state

        Raises:
            QuotaExceededError: If quota is exceeded
        """
        with self._lock:
            if resource not in self._quotas:
                raise ValueError(f"Unknown resource: {resource}")

            quota = self._quotas[resource]
            now = time.time()

            # Check if period has reset
            if now >= quota["reset_at"]:
                quota["used"] = 0
                quota["reset_at"] = now + quota["period_seconds"]

            # Check if quota allows this usage
            if quota["used"] + amount > quota["limit"]:
                info = QuotaInfo(
                    limit=quota["limit"],
                    used=quota["used"],
                    remaining=max(0, quota["limit"] - quota["used"]),
                    reset_at=quota["reset_at"],
                    period_seconds=quota["period_seconds"],
                )
                raise QuotaExceededError(
                    f"Quota exceeded for {resource}",
                    quota_info=info,
                )

            quota["used"] += amount

            return QuotaInfo(
                limit=quota["limit"],
                used=quota["used"],
                remaining=quota["limit"] - quota["used"],
                reset_at=quota["reset_at"],
                period_seconds=quota["period_seconds"],
            )

    def get_info(self, resource: str) -> QuotaInfo | None:
        """Get quota info for a resource."""
        with self._lock:
            if resource not in self._quotas:
                return None

            quota = self._quotas[resource]
            now = time.time()

            # Check if period has reset
            if now >= quota["reset_at"]:
                quota["used"] = 0
                quota["reset_at"] = now + quota["period_seconds"]

            return QuotaInfo(
                limit=quota["limit"],
                used=quota["used"],
                remaining=quota["limit"] - quota["used"],
                reset_at=quota["reset_at"],
                period_seconds=quota["period_seconds"],
            )

    def reset(self, resource: str) -> None:
        """Reset quota for a resource."""
        with self._lock:
            if resource in self._quotas:
                quota = self._quotas[resource]
                quota["used"] = 0
                quota["reset_at"] = time.time() + quota["period_seconds"]

    def reset_all(self) -> None:
        """Reset all quotas."""
        with self._lock:
            now = time.time()
            for quota in self._quotas.values():
                quota["used"] = 0
                quota["reset_at"] = now + quota["period_seconds"]


class RateLimiter:
    """
    Main rate limiter class with multiple algorithm support.

    Combines rate limiting, backoff, and quota management.
    """

    def __init__(self, config: RateLimitConfig | None = None):
        self._config = config or RateLimitConfig()
        self._limiter = self._create_limiter()
        self._backoff = BackoffCalculator(
            strategy=self._config.backoff_strategy,
            base_delay=self._config.base_delay,
            max_delay=self._config.max_delay,
        )
        self._quotas = QuotaManager()
        self._attempt_counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def _create_limiter(self) -> BaseRateLimiter:
        """Create the appropriate limiter based on config."""
        if self._config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return TokenBucketLimiter(
                rate=self._config.requests_per_second,
                bucket_size=self._config.burst_size,
            )
        elif self._config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return SlidingWindowLimiter(
                requests=self._config.burst_size,
                window_seconds=1.0 / self._config.requests_per_second,
            )
        elif self._config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return FixedWindowLimiter(
                requests=self._config.burst_size,
                window_seconds=1.0 / self._config.requests_per_second,
            )
        elif self._config.algorithm == RateLimitAlgorithm.LEAKY_BUCKET:
            return LeakyBucketLimiter(
                rate=self._config.requests_per_second,
                bucket_size=self._config.burst_size,
            )
        else:
            return TokenBucketLimiter(
                rate=self._config.requests_per_second,
                bucket_size=self._config.burst_size,
            )

    def acquire(self, key: str = "default", tokens: int = 1) -> RateLimitResult:
        """
        Try to acquire tokens for a rate-limited operation.

        Args:
            key: Identifier for tracking attempts
            tokens: Number of tokens to acquire

        Returns:
            RateLimitResult
        """
        return self._limiter.acquire(tokens)

    def acquire_or_wait(
        self,
        key: str = "default",
        tokens: int = 1,
        timeout: float | None = None,
    ) -> RateLimitResult:
        """
        Acquire tokens, waiting if necessary.

        Args:
            key: Identifier for tracking
            tokens: Number of tokens
            timeout: Maximum wait time

        Returns:
            RateLimitResult

        Raises:
            RateLimitError: If timeout exceeded
        """
        timeout = timeout or self._config.timeout
        start = time.time()

        while True:
            result = self._limiter.acquire(tokens)
            if result.allowed:
                return result

            if timeout is not None:
                elapsed = time.time() - start
                if elapsed + result.wait_time > timeout:
                    raise RateLimitError(
                        "Rate limit timeout exceeded",
                        retry_after=result.retry_after,
                        result=result,
                    )

            time.sleep(min(result.wait_time, 0.1))

    def execute_with_retry(
        self,
        func: Callable[..., T],
        *args,
        key: str = "default",
        **kwargs,
    ) -> T:
        """
        Execute a function with rate limiting and retry.

        Args:
            func: Function to execute
            *args: Positional arguments
            key: Identifier for tracking
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            RateLimitError: If max retries exceeded
        """
        with self._lock:
            if key not in self._attempt_counts:
                self._attempt_counts[key] = 0

        for attempt in range(self._config.max_retries + 1):
            # Wait for rate limit
            self.acquire_or_wait(key)

            try:
                return func(*args, **kwargs)
            except Exception:
                with self._lock:
                    self._attempt_counts[key] = attempt + 1

                if attempt >= self._config.max_retries:
                    raise

                # Apply backoff
                delay = self._backoff.get_delay(attempt)
                time.sleep(delay)

        raise RateLimitError("Max retries exceeded")

    def set_quota(
        self,
        resource: str,
        limit: int,
        period_seconds: int = 3600,
    ) -> None:
        """Set quota for a resource."""
        self._quotas.set_quota(resource, limit, period_seconds)

    def use_quota(self, resource: str, amount: int = 1) -> QuotaInfo:
        """Use quota for a resource."""
        return self._quotas.use(resource, amount)

    def get_quota_info(self, resource: str) -> QuotaInfo | None:
        """Get quota info for a resource."""
        return self._quotas.get_info(resource)

    def reset(self) -> None:
        """Reset rate limiter state."""
        self._limiter.reset()
        self._backoff.reset()
        with self._lock:
            self._attempt_counts.clear()

    @property
    def config(self) -> RateLimitConfig:
        """Get the rate limit configuration."""
        return self._config


def rate_limited(
    requests_per_second: float = 1.0,
    burst_size: int = 1,
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.TOKEN_BUCKET,
    key_func: Callable[..., str] | None = None,
    on_limit: Callable[[RateLimitResult], None] | None = None,
) -> Callable:
    """
    Decorator for rate limiting function calls.

    Args:
        requests_per_second: Allowed requests per second
        burst_size: Maximum burst size
        algorithm: Rate limiting algorithm
        key_func: Function to generate rate limit key from args
        on_limit: Callback when rate limited

    Returns:
        Decorated function
    """
    config = RateLimitConfig(
        requests_per_second=requests_per_second,
        burst_size=burst_size,
        algorithm=algorithm,
    )
    limiter = RateLimiter(config)

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            key = "default"
            if key_func:
                key = key_func(*args, **kwargs)

            result = limiter.acquire(key)

            if not result.allowed:
                if on_limit:
                    on_limit(result)
                time.sleep(result.wait_time)
                limiter.acquire(key)

            return func(*args, **kwargs)

        wrapper._rate_limiter = limiter
        return wrapper

    return decorator


def with_backoff(
    max_retries: int = 3,
    strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL_JITTER,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: tuple = (Exception,),
) -> Callable:
    """
    Decorator for retry with backoff.

    Args:
        max_retries: Maximum number of retries
        strategy: Backoff strategy
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        exceptions: Exception types to catch and retry

    Returns:
        Decorated function
    """
    backoff = BackoffCalculator(
        strategy=strategy,
        base_delay=base_delay,
        max_delay=max_delay,
    )

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = backoff.get_delay(attempt)
                        time.sleep(delay)

            if last_exception is not None:
                raise last_exception
            raise RuntimeError(
                f"Retry failed: no attempts made (max_retries={max_retries})"
            )

        return wrapper

    return decorator


# Global rate limiter instance
_global_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Set the global rate limiter."""
    global _global_limiter
    _global_limiter = limiter


def acquire(key: str = "default", tokens: int = 1) -> RateLimitResult:
    """Acquire tokens from the global rate limiter."""
    return get_rate_limiter().acquire(key, tokens)
