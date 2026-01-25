"""
Caching Layer for RedOPS.

Provides result caching with TTL management, multiple backends,
and cache invalidation strategies.
"""

import hashlib
import json
import os
import pickle
import shutil
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")


class CacheBackend(Enum):
    """Available cache backends."""
    MEMORY = "memory"
    FILE = "file"
    HYBRID = "hybrid"  # Memory with file persistence


class InvalidationStrategy(Enum):
    """Cache invalidation strategies."""
    TTL = "ttl"              # Time-based expiration
    LRU = "lru"              # Least recently used
    LFU = "lfu"              # Least frequently used
    FIFO = "fifo"            # First in, first out
    MANUAL = "manual"        # Manual invalidation only


@dataclass
class CacheEntry:
    """Represents a cached value with metadata."""
    key: str
    value: Any
    created_at: float
    expires_at: float | None
    access_count: int = 0
    last_accessed: float = field(default_factory=time.time)
    size_bytes: int = 0
    tags: list[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        """Check if the entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def ttl_remaining(self) -> float | None:
        """Get remaining TTL in seconds."""
        if self.expires_at is None:
            return None
        remaining = self.expires_at - time.time()
        return max(0, remaining)

    def touch(self) -> None:
        """Update access metadata."""
        self.access_count += 1
        self.last_accessed = time.time()


@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    size_bytes: int = 0
    entry_count: int = 0
    oldest_entry: float | None = None
    newest_entry: float | None = None

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "hit_rate": round(self.hit_rate, 4),
            "size_bytes": self.size_bytes,
            "entry_count": self.entry_count,
            "oldest_entry": self.oldest_entry,
            "newest_entry": self.newest_entry,
        }


class CacheError(Exception):
    """Base exception for cache errors."""
    pass


class CacheKeyError(CacheError):
    """Raised when there's an issue with cache key."""
    pass


class CacheStorageError(CacheError):
    """Raised when there's a storage error."""
    pass


class BaseCacheBackend(ABC):
    """Abstract base class for cache backends."""

    @abstractmethod
    def get(self, key: str) -> CacheEntry | None:
        """Get an entry from the cache."""
        pass

    @abstractmethod
    def set(self, entry: CacheEntry) -> None:
        """Set an entry in the cache."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete an entry from the cache."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        pass

    @abstractmethod
    def clear(self) -> int:
        """Clear all entries. Returns number of entries cleared."""
        pass

    @abstractmethod
    def keys(self) -> list[str]:
        """Get all cache keys."""
        pass

    @abstractmethod
    def size(self) -> int:
        """Get number of entries in cache."""
        pass


class MemoryCacheBackend(BaseCacheBackend):
    """In-memory cache backend."""

    def __init__(self, max_size: int = 1000):
        self._cache: dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._max_size = max_size

    def get(self, key: str) -> CacheEntry | None:
        with self._lock:
            return self._cache.get(key)

    def set(self, entry: CacheEntry) -> None:
        with self._lock:
            self._cache[entry.key] = entry

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def exists(self, key: str) -> bool:
        with self._lock:
            return key in self._cache

    def clear(self) -> int:
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def keys(self) -> list[str]:
        with self._lock:
            return list(self._cache.keys())

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def get_all_entries(self) -> list[CacheEntry]:
        """Get all cache entries."""
        with self._lock:
            return list(self._cache.values())


class FileCacheBackend(BaseCacheBackend):
    """File-based cache backend."""

    def __init__(self, cache_dir: str | Path = "./.cache/redops"):
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _key_to_path(self, key: str) -> Path:
        """Convert cache key to file path."""
        # Hash the key to create a valid filename
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self._cache_dir / f"{key_hash}.cache"

    def get(self, key: str) -> CacheEntry | None:
        path = self._key_to_path(key)
        with self._lock:
            if not path.exists():
                return None
            try:
                with open(path, "rb") as f:
                    return pickle.load(f)
            except Exception:
                return None

    def set(self, entry: CacheEntry) -> None:
        path = self._key_to_path(entry.key)
        with self._lock:
            try:
                with open(path, "wb") as f:
                    pickle.dump(entry, f)
            except Exception as e:
                raise CacheStorageError(f"Failed to write cache: {e}")

    def delete(self, key: str) -> bool:
        path = self._key_to_path(key)
        with self._lock:
            if path.exists():
                path.unlink()
                return True
            return False

    def exists(self, key: str) -> bool:
        return self._key_to_path(key).exists()

    def clear(self) -> int:
        with self._lock:
            count = 0
            for path in self._cache_dir.glob("*.cache"):
                path.unlink()
                count += 1
            return count

    def keys(self) -> list[str]:
        # For file backend, we need to store keys separately or read all files
        # Here we return file hashes as a simplified approach
        with self._lock:
            return [p.stem for p in self._cache_dir.glob("*.cache")]

    def size(self) -> int:
        return len(list(self._cache_dir.glob("*.cache")))

    def get_cache_dir(self) -> Path:
        """Get the cache directory path."""
        return self._cache_dir

    def get_disk_usage(self) -> int:
        """Get total disk usage in bytes."""
        total = 0
        for path in self._cache_dir.glob("*.cache"):
            total += path.stat().st_size
        return total


class HybridCacheBackend(BaseCacheBackend):
    """Hybrid cache with memory front and file persistence."""

    def __init__(
        self,
        cache_dir: str | Path = "./.cache/redops",
        memory_max_size: int = 1000,
    ):
        self._memory = MemoryCacheBackend(memory_max_size)
        self._file = FileCacheBackend(cache_dir)
        self._lock = threading.RLock()

    def get(self, key: str) -> CacheEntry | None:
        with self._lock:
            # Try memory first
            entry = self._memory.get(key)
            if entry:
                return entry

            # Fall back to file
            entry = self._file.get(key)
            if entry:
                # Promote to memory
                self._memory.set(entry)
            return entry

    def set(self, entry: CacheEntry) -> None:
        with self._lock:
            self._memory.set(entry)
            self._file.set(entry)

    def delete(self, key: str) -> bool:
        with self._lock:
            mem_deleted = self._memory.delete(key)
            file_deleted = self._file.delete(key)
            return mem_deleted or file_deleted

    def exists(self, key: str) -> bool:
        with self._lock:
            return self._memory.exists(key) or self._file.exists(key)

    def clear(self) -> int:
        with self._lock:
            mem_count = self._memory.clear()
            file_count = self._file.clear()
            return max(mem_count, file_count)

    def keys(self) -> list[str]:
        with self._lock:
            mem_keys = set(self._memory.keys())
            file_keys = set(self._file.keys())
            return list(mem_keys | file_keys)

    def size(self) -> int:
        # Memory is authoritative for hybrid
        return self._memory.size()


class Cache:
    """
    Main cache interface for RedOPS.

    Provides a unified API for caching with multiple backends,
    TTL management, and invalidation strategies.
    """

    def __init__(
        self,
        backend: CacheBackend = CacheBackend.MEMORY,
        default_ttl: int | None = 3600,
        max_size: int = 1000,
        max_size_bytes: int | None = None,
        cache_dir: str | Path = "./.cache/redops",
        invalidation_strategy: InvalidationStrategy = InvalidationStrategy.TTL,
        namespace: str = "default",
    ):
        self._default_ttl = default_ttl
        self._max_size = max_size
        self._max_size_bytes = max_size_bytes
        self._invalidation_strategy = invalidation_strategy
        self._namespace = namespace
        self._stats = CacheStats()
        self._lock = threading.RLock()

        # Initialize backend
        if backend == CacheBackend.MEMORY:
            self._backend = MemoryCacheBackend(max_size)
        elif backend == CacheBackend.FILE:
            self._backend = FileCacheBackend(cache_dir)
        elif backend == CacheBackend.HYBRID:
            self._backend = HybridCacheBackend(cache_dir, max_size)
        else:
            raise ValueError(f"Unknown backend: {backend}")

    def _make_key(self, key: str) -> str:
        """Create namespaced cache key."""
        return f"{self._namespace}:{key}"

    def _estimate_size(self, value: Any) -> int:
        """Estimate size of a value in bytes."""
        try:
            return len(pickle.dumps(value))
        except Exception:
            return 0

    def get(self, key: str, default: T = None) -> T | Any:
        """
        Get a value from the cache.

        Args:
            key: Cache key
            default: Default value if not found

        Returns:
            Cached value or default
        """
        full_key = self._make_key(key)

        with self._lock:
            entry = self._backend.get(full_key)

            if entry is None:
                self._stats.misses += 1
                return default

            if entry.is_expired:
                self._backend.delete(full_key)
                self._stats.misses += 1
                self._stats.expirations += 1
                return default

            entry.touch()
            self._backend.set(entry)  # Update access metadata
            self._stats.hits += 1
            return entry.value

    def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """
        Set a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (None for default, 0 for no expiration)
            tags: Optional tags for grouping cache entries
        """
        full_key = self._make_key(key)

        # Determine TTL
        if ttl is None:
            ttl = self._default_ttl

        now = time.time()
        expires_at = None if ttl == 0 or ttl is None else now + ttl

        entry = CacheEntry(
            key=full_key,
            value=value,
            created_at=now,
            expires_at=expires_at,
            size_bytes=self._estimate_size(value),
            tags=tags or [],
        )

        with self._lock:
            # Check if we need to evict
            self._maybe_evict()

            self._backend.set(entry)
            self._update_stats()

    def delete(self, key: str) -> bool:
        """
        Delete a value from the cache.

        Args:
            key: Cache key

        Returns:
            True if the key was deleted
        """
        full_key = self._make_key(key)
        with self._lock:
            result = self._backend.delete(full_key)
            if result:
                self._update_stats()
            return result

    def exists(self, key: str) -> bool:
        """
        Check if a key exists in the cache.

        Args:
            key: Cache key

        Returns:
            True if key exists and is not expired
        """
        full_key = self._make_key(key)
        with self._lock:
            entry = self._backend.get(full_key)
            if entry is None:
                return False
            if entry.is_expired:
                self._backend.delete(full_key)
                return False
            return True

    def get_or_set(
        self,
        key: str,
        factory: Callable[[], T],
        ttl: int | None = None,
        tags: list[str] | None = None,
    ) -> T:
        """
        Get a value from cache, or compute and cache it.

        Args:
            key: Cache key
            factory: Function to compute the value if not cached
            ttl: Time to live in seconds
            tags: Optional tags

        Returns:
            Cached or computed value
        """
        value = self.get(key)
        if value is not None:
            return value

        value = factory()
        self.set(key, value, ttl=ttl, tags=tags)
        return value

    def clear(self) -> int:
        """
        Clear all entries from the cache.

        Returns:
            Number of entries cleared
        """
        with self._lock:
            count = self._backend.clear()
            self._stats = CacheStats()
            return count

    def clear_expired(self) -> int:
        """
        Clear all expired entries.

        Returns:
            Number of entries cleared
        """
        cleared = 0
        with self._lock:
            for key in self._backend.keys():
                entry = self._backend.get(key)
                if entry and entry.is_expired:
                    self._backend.delete(key)
                    cleared += 1
                    self._stats.expirations += 1

            self._update_stats()
        return cleared

    def clear_by_tag(self, tag: str) -> int:
        """
        Clear all entries with a specific tag.

        Args:
            tag: Tag to match

        Returns:
            Number of entries cleared
        """
        cleared = 0
        with self._lock:
            for key in self._backend.keys():
                entry = self._backend.get(key)
                if entry and tag in entry.tags:
                    self._backend.delete(key)
                    cleared += 1

            self._update_stats()
        return cleared

    def clear_by_prefix(self, prefix: str) -> int:
        """
        Clear all entries with keys matching a prefix.

        Args:
            prefix: Key prefix to match

        Returns:
            Number of entries cleared
        """
        full_prefix = self._make_key(prefix)
        cleared = 0

        with self._lock:
            for key in self._backend.keys():
                if key.startswith(full_prefix):
                    self._backend.delete(key)
                    cleared += 1

            self._update_stats()
        return cleared

    def get_ttl(self, key: str) -> float | None:
        """
        Get remaining TTL for a key.

        Args:
            key: Cache key

        Returns:
            Remaining TTL in seconds, None if no expiration, -1 if not found
        """
        full_key = self._make_key(key)
        with self._lock:
            entry = self._backend.get(full_key)
            if entry is None:
                return -1
            return entry.ttl_remaining

    def set_ttl(self, key: str, ttl: int) -> bool:
        """
        Update the TTL for an existing key.

        Args:
            key: Cache key
            ttl: New TTL in seconds

        Returns:
            True if TTL was updated
        """
        full_key = self._make_key(key)
        with self._lock:
            entry = self._backend.get(full_key)
            if entry is None:
                return False

            entry.expires_at = time.time() + ttl if ttl > 0 else None
            self._backend.set(entry)
            return True

    def touch(self, key: str, ttl: int | None = None) -> bool:
        """
        Update access time and optionally extend TTL.

        Args:
            key: Cache key
            ttl: Optional new TTL

        Returns:
            True if key was touched
        """
        full_key = self._make_key(key)
        with self._lock:
            entry = self._backend.get(full_key)
            if entry is None or entry.is_expired:
                return False

            entry.touch()
            if ttl is not None:
                entry.expires_at = time.time() + ttl if ttl > 0 else None

            self._backend.set(entry)
            return True

    def keys(self, pattern: str | None = None) -> list[str]:
        """
        Get all cache keys, optionally filtered by pattern.

        Args:
            pattern: Optional prefix pattern to match

        Returns:
            List of cache keys (without namespace prefix)
        """
        prefix = f"{self._namespace}:"
        with self._lock:
            all_keys = self._backend.keys()
            result = []
            for key in all_keys:
                if key.startswith(prefix):
                    short_key = key[len(prefix):]
                    if pattern is None or short_key.startswith(pattern):
                        result.append(short_key)
            return result

    def size(self) -> int:
        """Get number of entries in cache."""
        return self._backend.size()

    def stats(self) -> CacheStats:
        """Get cache statistics."""
        with self._lock:
            self._update_stats()
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                expirations=self._stats.expirations,
                size_bytes=self._stats.size_bytes,
                entry_count=self._stats.entry_count,
                oldest_entry=self._stats.oldest_entry,
                newest_entry=self._stats.newest_entry,
            )

    def _update_stats(self) -> None:
        """Update cache statistics."""
        self._stats.entry_count = self._backend.size()

        # Calculate size and find oldest/newest
        if isinstance(self._backend, MemoryCacheBackend):
            entries = self._backend.get_all_entries()
            self._stats.size_bytes = sum(e.size_bytes for e in entries)
            if entries:
                self._stats.oldest_entry = min(e.created_at for e in entries)
                self._stats.newest_entry = max(e.created_at for e in entries)
        elif isinstance(self._backend, FileCacheBackend):
            self._stats.size_bytes = self._backend.get_disk_usage()

    def _maybe_evict(self) -> None:
        """Evict entries if cache is full."""
        if self._backend.size() < self._max_size:
            return

        # First, clear expired entries
        self.clear_expired()

        if self._backend.size() < self._max_size:
            return

        # Apply invalidation strategy
        if self._invalidation_strategy == InvalidationStrategy.LRU:
            self._evict_lru()
        elif self._invalidation_strategy == InvalidationStrategy.LFU:
            self._evict_lfu()
        elif self._invalidation_strategy == InvalidationStrategy.FIFO:
            self._evict_fifo()
        else:
            # Default to LRU for TTL strategy when full
            self._evict_lru()

    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not isinstance(self._backend, MemoryCacheBackend):
            return

        entries = self._backend.get_all_entries()
        if not entries:
            return

        # Find LRU entry
        lru_entry = min(entries, key=lambda e: e.last_accessed)
        self._backend.delete(lru_entry.key)
        self._stats.evictions += 1

    def _evict_lfu(self) -> None:
        """Evict least frequently used entry."""
        if not isinstance(self._backend, MemoryCacheBackend):
            return

        entries = self._backend.get_all_entries()
        if not entries:
            return

        # Find LFU entry
        lfu_entry = min(entries, key=lambda e: e.access_count)
        self._backend.delete(lfu_entry.key)
        self._stats.evictions += 1

    def _evict_fifo(self) -> None:
        """Evict oldest entry."""
        if not isinstance(self._backend, MemoryCacheBackend):
            return

        entries = self._backend.get_all_entries()
        if not entries:
            return

        # Find oldest entry
        oldest_entry = min(entries, key=lambda e: e.created_at)
        self._backend.delete(oldest_entry.key)
        self._stats.evictions += 1


def generate_cache_key(*args, **kwargs) -> str:
    """
    Generate a cache key from arguments.

    Args:
        *args: Positional arguments to include in key
        **kwargs: Keyword arguments to include in key

    Returns:
        Cache key string
    """
    key_parts = [str(arg) for arg in args]
    key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
    key_string = ":".join(key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:32]


def cached(
    ttl: int | None = 3600,
    key_prefix: str | None = None,
    cache_instance: Cache | None = None,
    tags: list[str] | None = None,
) -> Callable:
    """
    Decorator for caching function results.

    Args:
        ttl: Time to live in seconds
        key_prefix: Optional prefix for cache key
        cache_instance: Cache instance to use (creates new if None)
        tags: Optional tags for the cached entries

    Returns:
        Decorated function
    """
    _cache = cache_instance or Cache()

    def decorator(func: Callable) -> Callable:
        prefix = key_prefix or func.__name__

        def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{prefix}:{generate_cache_key(*args, **kwargs)}"

            # Check cache
            result = _cache.get(key)
            if result is not None:
                return result

            # Compute and cache
            result = func(*args, **kwargs)
            _cache.set(key, result, ttl=ttl, tags=tags)
            return result

        wrapper.__wrapped__ = func
        return wrapper

    return decorator


# Global cache instance
_global_cache: Cache | None = None


def get_cache() -> Cache:
    """Get the global cache instance."""
    global _global_cache
    if _global_cache is None:
        _global_cache = Cache()
    return _global_cache


def set_global_cache(cache: Cache) -> None:
    """Set the global cache instance."""
    global _global_cache
    _global_cache = cache
