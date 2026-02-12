"""
Redis-backed API Rate Limiting.

Provides distributed rate limiting for the REST API.
"""

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Any, Callable, TypeVar

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

T = TypeVar("T")


class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms."""

    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    requests: int  # Number of requests allowed
    window: int  # Time window in seconds
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    key_prefix: str = "ratelimit"
    include_headers: bool = True
    block_duration: int | None = None  # Additional block time when exceeded


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_at: int  # Unix timestamp
    retry_after: int | None = None

    @property
    def headers(self) -> dict[str, str]:
        """Get rate limit response headers."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(self.reset_at),
        }
        if self.retry_after is not None:
            headers["Retry-After"] = str(self.retry_after)
        return headers


class RateLimitBackend(ABC):
    """Abstract base for rate limit storage backends."""

    @abstractmethod
    def check_rate_limit(
        self,
        key: str,
        config: RateLimitConfig,
    ) -> RateLimitResult:
        """Check if request is allowed."""
        pass

    @abstractmethod
    def reset(self, key: str) -> None:
        """Reset rate limit for a key."""
        pass


class MemoryRateLimitBackend(RateLimitBackend):
    """
    In-memory rate limit backend.

    Suitable for single-process deployments.
    """

    def __init__(self):
        self._windows: dict[str, dict[str, Any]] = {}

    def check_rate_limit(
        self,
        key: str,
        config: RateLimitConfig,
    ) -> RateLimitResult:
        """Check rate limit using fixed window."""
        now = int(time.time())
        window_start = now - (now % config.window)
        window_key = f"{key}:{window_start}"

        if window_key not in self._windows:
            self._windows[window_key] = {"count": 0, "start": window_start}
            # Clean old windows
            self._cleanup_old_windows(key, window_start)

        window = self._windows[window_key]
        window["count"] += 1

        allowed = window["count"] <= config.requests
        remaining = max(0, config.requests - window["count"])
        reset_at = window_start + config.window

        return RateLimitResult(
            allowed=allowed,
            limit=config.requests,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=reset_at - now if not allowed else None,
        )

    def _cleanup_old_windows(self, key: str, current_start: int) -> None:
        """Remove old windows."""
        to_remove = []
        for window_key in self._windows:
            if window_key.startswith(key + ":"):
                try:
                    start = int(window_key.split(":")[-1])
                    if start < current_start:
                        to_remove.append(window_key)
                except ValueError:
                    pass

        for k in to_remove:
            del self._windows[k]

    def reset(self, key: str) -> None:
        """Reset rate limit for key."""
        to_remove = [k for k in self._windows if k.startswith(key + ":")]
        for k in to_remove:
            del self._windows[k]


class RedisRateLimitBackend(RateLimitBackend):
    """
    Redis-backed rate limit backend.

    Provides distributed rate limiting using Redis.
    Supports multiple algorithms.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        redis_client: Any | None = None,
    ):
        """
        Initialize Redis backend.

        Args:
            redis_url: Redis connection URL
            redis_client: Existing Redis client (optional)
        """
        if redis_client:
            self._redis = redis_client
        else:
            try:
                import redis

                self._redis = redis.from_url(redis_url, decode_responses=True)
            except ImportError:
                raise ImportError("redis package required: pip install redis")

    def check_rate_limit(
        self,
        key: str,
        config: RateLimitConfig,
    ) -> RateLimitResult:
        """Check rate limit using configured algorithm."""
        if config.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return self._fixed_window(key, config)
        elif config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return self._sliding_window(key, config)
        elif config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return self._token_bucket(key, config)
        else:
            return self._fixed_window(key, config)

    def _fixed_window(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Fixed window rate limiting."""
        now = int(time.time())
        window_start = now - (now % config.window)
        window_key = f"{config.key_prefix}:{key}:{window_start}"

        # Increment counter
        pipe = self._redis.pipeline()
        pipe.incr(window_key)
        pipe.expire(window_key, config.window * 2)  # Keep for 2 windows
        results = pipe.execute()

        count = results[0]
        allowed = count <= config.requests
        remaining = max(0, config.requests - count)
        reset_at = window_start + config.window

        return RateLimitResult(
            allowed=allowed,
            limit=config.requests,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=reset_at - now if not allowed else None,
        )

    def _sliding_window(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Sliding window rate limiting using sorted sets."""
        now = time.time()
        window_start = now - config.window
        window_key = f"{config.key_prefix}:sw:{key}"

        pipe = self._redis.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(window_key, 0, window_start)

        # Add current request
        request_id = f"{now}:{id(now)}"
        pipe.zadd(window_key, {request_id: now})

        # Count requests in window
        pipe.zcount(window_key, window_start, now)

        # Set expiry
        pipe.expire(window_key, config.window * 2)

        results = pipe.execute()
        count = results[2]

        allowed = count <= config.requests
        remaining = max(0, config.requests - count)
        reset_at = int(now) + config.window

        # If not allowed, remove the request we just added
        if not allowed:
            self._redis.zrem(window_key, request_id)

        return RateLimitResult(
            allowed=allowed,
            limit=config.requests,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=config.window if not allowed else None,
        )

    def _token_bucket(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """Token bucket rate limiting."""
        bucket_key = f"{config.key_prefix}:tb:{key}"
        now = time.time()

        # Token bucket parameters
        rate = config.requests / config.window  # Tokens per second
        bucket_size = config.requests

        # Lua script for atomic token bucket
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local rate = tonumber(ARGV[2])
        local bucket_size = tonumber(ARGV[3])
        local requested = tonumber(ARGV[4])

        local data = redis.call('HMGET', key, 'tokens', 'last_update')
        local tokens = tonumber(data[1]) or bucket_size
        local last_update = tonumber(data[2]) or now

        -- Add tokens based on elapsed time
        local elapsed = now - last_update
        tokens = math.min(bucket_size, tokens + (elapsed * rate))

        local allowed = 0
        if tokens >= requested then
            tokens = tokens - requested
            allowed = 1
        end

        -- Update bucket
        redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
        redis.call('EXPIRE', key, math.ceil(bucket_size / rate) * 2)

        return {allowed, math.floor(tokens)}
        """

        result = self._redis.eval(lua_script, 1, bucket_key, now, rate, bucket_size, 1)
        allowed = result[0] == 1
        remaining = result[1]

        return RateLimitResult(
            allowed=allowed,
            limit=config.requests,
            remaining=remaining,
            reset_at=int(now + (bucket_size - remaining) / rate),
            retry_after=int(1 / rate) if not allowed else None,
        )

    def reset(self, key: str) -> None:
        """Reset rate limit for key."""
        pattern = f"*:{key}:*"
        for k in self._redis.scan_iter(pattern):
            self._redis.delete(k)


class RateLimiter:
    """
    Main rate limiter class.

    Manages rate limiting with configurable backends and rules.
    """

    def __init__(
        self,
        backend: RateLimitBackend | None = None,
        default_config: RateLimitConfig | None = None,
    ):
        """
        Initialize rate limiter.

        Args:
            backend: Storage backend (default: memory)
            default_config: Default rate limit configuration
        """
        self._backend = backend or MemoryRateLimitBackend()
        self._default_config = default_config or RateLimitConfig(
            requests=100,
            window=60,
        )
        self._rules: dict[str, RateLimitConfig] = {}

    def add_rule(self, name: str, config: RateLimitConfig) -> None:
        """Add a named rate limit rule."""
        self._rules[name] = config

    def check(
        self,
        key: str,
        rule: str | None = None,
        config: RateLimitConfig | None = None,
    ) -> RateLimitResult:
        """
        Check if request is allowed.

        Args:
            key: Rate limit key (e.g., user ID, IP)
            rule: Named rule to use
            config: Custom config (overrides rule)

        Returns:
            RateLimitResult
        """
        if config is None:
            config = (
                self._rules.get(rule, self._default_config)
                if rule
                else self._default_config
            )

        return self._backend.check_rate_limit(key, config)

    def reset(self, key: str) -> None:
        """Reset rate limit for key."""
        self._backend.reset(key)

    @property
    def backend(self) -> RateLimitBackend:
        """Get the backend."""
        return self._backend


def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    # Check X-Forwarded-For header
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to client host
    return request.client.host if request.client else "unknown"


def get_rate_limit_key(
    request: Request,
    key_func: Callable[[Request], str] | None = None,
) -> str:
    """
    Generate rate limit key from request.

    Args:
        request: FastAPI request
        key_func: Custom key function

    Returns:
        Rate limit key string
    """
    if key_func:
        return key_func(request)

    # Default: use IP + path
    ip = get_client_ip(request)
    path = request.url.path
    return f"{ip}:{path}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for rate limiting.

    Applies rate limits to all requests based on configurable rules.
    """

    def __init__(
        self,
        app,
        limiter: RateLimiter | None = None,
        config: RateLimitConfig | None = None,
        key_func: Callable[[Request], str] | None = None,
        exclude_paths: list | None = None,
    ):
        """
        Initialize middleware.

        Args:
            app: FastAPI application
            limiter: Rate limiter instance
            config: Rate limit configuration
            key_func: Custom key function
            exclude_paths: Paths to exclude from rate limiting
        """
        super().__init__(app)
        self._limiter = limiter or RateLimiter()
        self._config = config
        self._key_func = key_func
        self._exclude_paths = set(exclude_paths or ["/health", "/metrics"])

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request with rate limiting."""
        # Skip excluded paths
        if request.url.path in self._exclude_paths:
            return await call_next(request)

        # Get rate limit key
        key = get_rate_limit_key(request, self._key_func)

        # Check rate limit
        result = self._limiter.check(key, config=self._config)

        # If blocked, return 429
        if not result.allowed:
            return Response(
                content='{"error": "Rate limit exceeded"}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers=result.headers,
                media_type="application/json",
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        if self._config and self._config.include_headers:
            for header, value in result.headers.items():
                response.headers[header] = value

        return response


def rate_limit(
    requests: int = 100,
    window: int = 60,
    key_func: Callable[[Request], str] | None = None,
    limiter: RateLimiter | None = None,
):
    """
    Decorator for rate limiting endpoints.

    Usage:
        @app.get("/api/data")
        @rate_limit(requests=10, window=60)
        async def get_data(request: Request):
            return {"data": "value"}
    """
    _limiter = limiter or RateLimiter()
    config = RateLimitConfig(requests=requests, window=window)

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find request in args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")

            if request:
                key = get_rate_limit_key(request, key_func)
                result = _limiter.check(key, config=config)

                if not result.allowed:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded",
                        headers=result.headers,
                    )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Per-user rate limiting for authenticated requests


class UserRateLimiter:
    """
    Rate limiter with per-user limits.

    Supports different limits for different user tiers/roles.
    """

    def __init__(
        self,
        backend: RateLimitBackend | None = None,
    ):
        """Initialize user rate limiter."""
        self._backend = backend or MemoryRateLimitBackend()
        self._tier_configs: dict[str, RateLimitConfig] = {
            "free": RateLimitConfig(requests=100, window=3600),  # 100/hour
            "basic": RateLimitConfig(requests=1000, window=3600),  # 1000/hour
            "pro": RateLimitConfig(requests=10000, window=3600),  # 10000/hour
            "enterprise": RateLimitConfig(requests=100000, window=3600),  # 100000/hour
        }

    def set_tier_config(self, tier: str, config: RateLimitConfig) -> None:
        """Set rate limit config for a tier."""
        self._tier_configs[tier] = config

    def check(
        self,
        user_id: str,
        tier: str = "free",
        endpoint: str | None = None,
    ) -> RateLimitResult:
        """
        Check rate limit for user.

        Args:
            user_id: User identifier
            tier: User tier/plan
            endpoint: Specific endpoint (for per-endpoint limits)

        Returns:
            RateLimitResult
        """
        config = self._tier_configs.get(tier, self._tier_configs["free"])

        key = f"user:{user_id}"
        if endpoint:
            key = f"{key}:{endpoint}"

        return self._backend.check_rate_limit(key, config)

    def reset_user(self, user_id: str) -> None:
        """Reset all rate limits for a user."""
        self._backend.reset(f"user:{user_id}")


# API key rate limiting


class APIKeyRateLimiter:
    """
    Rate limiter for API keys.

    Tracks usage per API key with configurable limits.
    """

    def __init__(
        self,
        backend: RateLimitBackend | None = None,
        default_limit: int = 1000,
        default_window: int = 3600,
    ):
        """Initialize API key rate limiter."""
        self._backend = backend or MemoryRateLimitBackend()
        self._default_config = RateLimitConfig(
            requests=default_limit,
            window=default_window,
        )
        self._key_limits: dict[str, RateLimitConfig] = {}

    def set_key_limit(
        self,
        api_key_hash: str,
        requests: int,
        window: int,
    ) -> None:
        """Set custom limit for an API key."""
        self._key_limits[api_key_hash] = RateLimitConfig(
            requests=requests,
            window=window,
        )

    def check(self, api_key: str) -> RateLimitResult:
        """
        Check rate limit for API key.

        Args:
            api_key: Full API key

        Returns:
            RateLimitResult
        """
        # Hash key for storage
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        config = self._key_limits.get(key_hash, self._default_config)

        return self._backend.check_rate_limit(f"apikey:{key_hash}", config)

    def reset_key(self, api_key: str) -> None:
        """Reset rate limit for API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        self._backend.reset(f"apikey:{key_hash}")
