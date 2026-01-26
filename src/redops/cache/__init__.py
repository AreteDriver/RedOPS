"""
Caching layer for RedOPS.

Provides memory and Redis caching with rate limiting support.
"""

from .backends import (
    CacheBackend,
    CacheEntry,
    MemoryBackend,
    RedisBackend,
    TieredBackend,
    create_key,
)
from .cache import (
    Cache,
    CacheConfig,
    IntelCache,
    RateLimitExceeded,
    get_cache,
    get_intel_cache,
    cached,
    rate_limited,
)

__all__ = [
    # Backends
    "CacheBackend",
    "CacheEntry",
    "MemoryBackend",
    "RedisBackend",
    "TieredBackend",
    "create_key",
    # Cache
    "Cache",
    "CacheConfig",
    "IntelCache",
    "RateLimitExceeded",
    "get_cache",
    "get_intel_cache",
    # Decorators
    "cached",
    "rate_limited",
]
