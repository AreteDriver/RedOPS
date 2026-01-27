"""
Main cache interface for RedOPS.

Provides a unified caching API for threat intel lookups and rate limiting.
"""

from typing import Optional, Any, Dict, List, Callable, TypeVar
from dataclasses import dataclass
import os
import logging
import functools

from .backends import (
    CacheBackend,
    MemoryBackend,
    RedisBackend,
    TieredBackend,
    create_key,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class CacheConfig:
    """Cache configuration."""

    backend: str = "memory"  # memory, redis, tiered
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_prefix: str = "redops:"
    max_memory_entries: int = 10000
    default_ttl_seconds: Optional[int] = 3600  # 1 hour
    intel_ttl_seconds: int = 86400  # 24 hours for threat intel
    rate_limit_window_seconds: int = 60

    @classmethod
    def from_env(cls) -> "CacheConfig":
        """Create config from environment variables."""
        return cls(
            backend=os.environ.get("CACHE_BACKEND", "memory"),
            redis_host=os.environ.get("REDIS_HOST", "localhost"),
            redis_port=int(os.environ.get("REDIS_PORT", "6379")),
            redis_db=int(os.environ.get("REDIS_DB", "0")),
            redis_password=os.environ.get("REDIS_PASSWORD"),
            redis_prefix=os.environ.get("REDIS_PREFIX", "redops:"),
            max_memory_entries=int(os.environ.get("CACHE_MAX_ENTRIES", "10000")),
            default_ttl_seconds=int(os.environ.get("CACHE_DEFAULT_TTL", "3600")),
            intel_ttl_seconds=int(os.environ.get("CACHE_INTEL_TTL", "86400")),
            rate_limit_window_seconds=int(os.environ.get("RATE_LIMIT_WINDOW", "60")),
        )


class Cache:
    """
    Main cache interface.

    Provides caching for threat intel lookups, API responses, and rate limiting.
    """

    def __init__(self, config: Optional[CacheConfig] = None):
        """
        Initialize cache.

        Args:
            config: Cache configuration
        """
        self.config = config or CacheConfig.from_env()
        self._backend = self._create_backend()

    def _create_backend(self) -> CacheBackend:
        """Create the appropriate backend."""
        backend_type = self.config.backend.lower()

        if backend_type == "redis":
            return RedisBackend(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                prefix=self.config.redis_prefix,
                default_ttl=self.config.default_ttl_seconds,
            )

        if backend_type == "tiered":
            memory = MemoryBackend(
                max_size=self.config.max_memory_entries,
                default_ttl=self.config.default_ttl_seconds,
            )
            redis = RedisBackend(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                prefix=self.config.redis_prefix,
                default_ttl=self.config.default_ttl_seconds,
            )
            return TieredBackend(memory, redis)

        # Default to memory
        return MemoryBackend(
            max_size=self.config.max_memory_entries,
            default_ttl=self.config.default_ttl_seconds,
        )

    def get(self, key: str) -> Optional[Any]:
        """
        Get a cached value.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        entry = self._backend.get(key)
        return entry.value if entry else None

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Set a cached value.

        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds (None = use default)
            tags: Optional tags for grouping
        """
        self._backend.set(key, value, ttl, tags)

    def delete(self, key: str) -> bool:
        """Delete a cached value."""
        return self._backend.delete(key)

    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self._backend.exists(key)

    def clear(self) -> int:
        """Clear all cached values."""
        return self._backend.clear()

    def invalidate_tag(self, tag: str) -> int:
        """Invalidate all entries with a tag."""
        return self._backend.delete_by_tag(tag)

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], T],
        ttl: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> T:
        """
        Get cached value or compute and cache it.

        Args:
            key: Cache key
            factory: Callable to produce value if not cached
            ttl: TTL in seconds
            tags: Optional tags

        Returns:
            Cached or computed value
        """
        value = self.get(key)
        if value is not None:
            return value

        value = factory()
        self.set(key, value, ttl, tags)
        return value

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self._backend.get_stats()

    # Threat Intel caching methods

    def cache_intel(
        self,
        source: str,
        indicator: str,
        result: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> None:
        """
        Cache threat intel result.

        Args:
            source: Intel source (greynoise, abuseipdb, etc.)
            indicator: The indicator (IP, domain, hash)
            result: Intel result data
            ttl: Optional custom TTL
        """
        key = f"intel:{source}:{indicator}"
        cache_ttl = ttl or self.config.intel_ttl_seconds
        self.set(key, result, cache_ttl, tags=["intel", f"intel:{source}"])

    def get_intel(self, source: str, indicator: str) -> Optional[Dict[str, Any]]:
        """
        Get cached threat intel result.

        Args:
            source: Intel source
            indicator: The indicator

        Returns:
            Cached result or None
        """
        key = f"intel:{source}:{indicator}"
        return self.get(key)

    def invalidate_intel(self, source: Optional[str] = None) -> int:
        """
        Invalidate intel cache.

        Args:
            source: Specific source to invalidate (None = all)

        Returns:
            Number of entries invalidated
        """
        if source:
            return self.invalidate_tag(f"intel:{source}")
        return self.invalidate_tag("intel")

    # Rate limiting methods

    def check_rate_limit(
        self,
        identifier: str,
        limit: int,
        window: Optional[int] = None,
    ) -> tuple[bool, int]:
        """
        Check and update rate limit.

        Args:
            identifier: Rate limit identifier (e.g., "api:greynoise")
            limit: Maximum requests in window
            window: Window size in seconds (uses config default if None)

        Returns:
            Tuple of (allowed, remaining)
        """
        window_seconds = window or self.config.rate_limit_window_seconds
        key = f"ratelimit:{identifier}"

        entry = self._backend.get(key)

        if entry is None:
            # First request in window
            self.set(key, {"count": 1, "reset": window_seconds}, window_seconds)
            return True, limit - 1

        count = entry.value.get("count", 0)

        if count >= limit:
            return False, 0

        # Increment counter
        entry.value["count"] = count + 1
        self._backend.set(
            key,
            entry.value,
            entry.ttl_seconds,
        )

        return True, limit - count - 1

    def get_rate_limit_status(self, identifier: str, limit: int) -> Dict[str, Any]:
        """
        Get rate limit status without incrementing.

        Args:
            identifier: Rate limit identifier
            limit: Configured limit

        Returns:
            Rate limit status dict
        """
        key = f"ratelimit:{identifier}"
        entry = self._backend.get(key)

        if entry is None:
            return {
                "identifier": identifier,
                "limit": limit,
                "remaining": limit,
                "reset_seconds": 0,
            }

        count = entry.value.get("count", 0)
        reset = entry.ttl_seconds or 0

        return {
            "identifier": identifier,
            "limit": limit,
            "used": count,
            "remaining": max(0, limit - count),
            "reset_seconds": reset,
        }

    def reset_rate_limit(self, identifier: str) -> bool:
        """Reset a rate limit."""
        key = f"ratelimit:{identifier}"
        return self.delete(key)


# Global cache instance
_cache: Optional[Cache] = None


def get_cache() -> Cache:
    """Get the global cache instance."""
    global _cache
    if _cache is None:
        _cache = Cache()
    return _cache


def cached(
    ttl: Optional[int] = None,
    key_prefix: str = "",
    tags: Optional[List[str]] = None,
    key_builder: Optional[Callable[..., str]] = None,
):
    """
    Decorator to cache function results.

    Args:
        ttl: TTL in seconds
        key_prefix: Prefix for cache key
        tags: Tags for the cached entry
        key_builder: Custom function to build cache key

    Returns:
        Decorated function
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            cache = get_cache()

            # Build cache key
            if key_builder:
                key = key_builder(*args, **kwargs)
            else:
                key = create_key(func.__module__, func.__name__, *args, **kwargs)

            if key_prefix:
                key = f"{key_prefix}:{key}"

            # Check cache
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value

            # Call function
            result = func(*args, **kwargs)

            # Cache result
            cache.set(key, result, ttl, tags)

            return result

        return wrapper

    return decorator


def rate_limited(
    identifier: str,
    limit: int,
    window: Optional[int] = None,
    on_exceeded: Optional[Callable[[], Any]] = None,
):
    """
    Decorator to apply rate limiting to a function.

    Args:
        identifier: Rate limit identifier
        limit: Maximum calls in window
        window: Window size in seconds
        on_exceeded: Function to call when limit exceeded

    Returns:
        Decorated function
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            cache = get_cache()

            allowed, remaining = cache.check_rate_limit(identifier, limit, window)

            if not allowed:
                if on_exceeded:
                    return on_exceeded()
                raise RateLimitExceeded(identifier, limit)

            return func(*args, **kwargs)

        return wrapper

    return decorator


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(self, identifier: str, limit: int):
        self.identifier = identifier
        self.limit = limit
        super().__init__(f"Rate limit exceeded for {identifier}: {limit} requests")


class IntelCache:
    """
    Specialized cache for threat intelligence lookups.

    Provides source-specific caching with automatic key generation.
    """

    def __init__(self, cache: Optional[Cache] = None):
        """Initialize with optional custom cache."""
        self._cache = cache or get_cache()

    def get(self, source: str, indicator: str) -> Optional[Dict[str, Any]]:
        """Get cached intel for an indicator."""
        return self._cache.get_intel(source, indicator)

    def set(
        self,
        source: str,
        indicator: str,
        result: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> None:
        """Cache intel result."""
        self._cache.cache_intel(source, indicator, result, ttl)

    def get_or_fetch(
        self,
        source: str,
        indicator: str,
        fetcher: Callable[[], Dict[str, Any]],
        ttl: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get cached intel or fetch and cache it.

        Args:
            source: Intel source name
            indicator: The indicator
            fetcher: Function to fetch intel if not cached
            ttl: Optional custom TTL

        Returns:
            Intel result
        """
        cached = self.get(source, indicator)
        if cached is not None:
            return cached

        result = fetcher()
        self.set(source, indicator, result, ttl)
        return result

    def invalidate(self, source: Optional[str] = None) -> int:
        """Invalidate cached intel."""
        return self._cache.invalidate_intel(source)

    def check_rate_limit(self, source: str, limit: int) -> tuple[bool, int]:
        """Check rate limit for a source."""
        return self._cache.check_rate_limit(f"intel:{source}", limit)


def get_intel_cache() -> IntelCache:
    """Get a specialized intel cache instance."""
    return IntelCache()
