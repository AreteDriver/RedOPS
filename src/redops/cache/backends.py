"""
Cache backend implementations.

Supports in-memory and Redis backends.
"""

from typing import Any
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
import threading
import json
import hashlib
import logging

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cached item with metadata."""

    key: str
    value: Any
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    ttl_seconds: int | None = None
    hits: int = 0
    tags: list[str] = field(default_factory=list)

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at

    def touch(self) -> None:
        """Increment hit count."""
        self.hits += 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "key": self.key,
            "value": self.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "ttl_seconds": self.ttl_seconds,
            "hits": self.hits,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CacheEntry":
        """Deserialize from dictionary."""

        def parse_dt(val):
            if val is None:
                return None
            return datetime.fromisoformat(val)

        return cls(
            key=data["key"],
            value=data["value"],
            created_at=parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
            expires_at=parse_dt(data.get("expires_at")),
            ttl_seconds=data.get("ttl_seconds"),
            hits=data.get("hits", 0),
            tags=data.get("tags", []),
        )


class CacheBackend(ABC):
    """Abstract base class for cache backends."""

    @abstractmethod
    def get(self, key: str) -> CacheEntry | None:
        """Get a cache entry."""
        pass

    @abstractmethod
    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Set a cache entry."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a cache entry."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass

    @abstractmethod
    def clear(self) -> int:
        """Clear all entries."""
        pass

    @abstractmethod
    def keys(self, pattern: str = "*") -> list[str]:
        """List keys matching pattern."""
        pass

    def delete_by_tag(self, tag: str) -> int:
        """Delete all entries with a specific tag."""
        count = 0
        for key in self.keys():
            entry = self.get(key)
            if entry and tag in entry.tags:
                if self.delete(key):
                    count += 1
        return count

    def get_stats(self) -> dict[str, Any]:
        """Get backend statistics."""
        return {
            "backend": self.__class__.__name__,
            "keys": len(self.keys()),
        }


class MemoryBackend(CacheBackend):
    """
    In-memory cache backend.

    Thread-safe implementation with LRU eviction.
    """

    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: int | None = None,
    ):
        """
        Initialize memory backend.

        Args:
            max_size: Maximum number of entries
            default_ttl: Default TTL in seconds (None = no expiry)
        """
        self._cache: dict[str, CacheEntry] = {}
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> CacheEntry | None:
        """Get a cache entry."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            if entry.is_expired():
                del self._cache[key]
                self._misses += 1
                return None

            entry.touch()
            self._hits += 1
            return entry

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Set a cache entry."""
        with self._lock:
            # Evict if at capacity
            if len(self._cache) >= self._max_size and key not in self._cache:
                self._evict_lru()

            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
            expires_at = None
            if ttl is not None:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

            entry = CacheEntry(
                key=key,
                value=value,
                ttl_seconds=ttl,
                expires_at=expires_at,
                tags=tags or [],
            )
            self._cache[key] = entry

    def delete(self, key: str) -> bool:
        """Delete a cache entry."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if entry.is_expired():
                del self._cache[key]
                return False
            return True

    def clear(self) -> int:
        """Clear all entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def keys(self, pattern: str = "*") -> list[str]:
        """List keys matching pattern."""
        with self._lock:
            # Clean expired entries
            self._cleanup_expired()

            if pattern == "*":
                return list(self._cache.keys())

            # Simple glob matching
            import fnmatch

            return [k for k in self._cache.keys() if fnmatch.fnmatch(k, pattern)]

    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._cache:
            return

        # Find entry with lowest hit count
        lru_key = min(self._cache.keys(), key=lambda k: self._cache[k].hits)
        del self._cache[lru_key]

    def _cleanup_expired(self) -> int:
        """Remove expired entries."""
        now = datetime.now(timezone.utc)
        expired = [k for k, v in self._cache.items() if v.is_expired(now)]
        for key in expired:
            del self._cache[key]
        return len(expired)

    def get_stats(self) -> dict[str, Any]:
        """Get backend statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0.0
            return {
                "backend": "memory",
                "keys": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 3),
            }


class RedisBackend(CacheBackend):
    """
    Redis cache backend.

    Requires redis-py package.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str | None = None,
        prefix: str = "redops:",
        default_ttl: int | None = None,
        connection_pool: Any | None = None,
    ):
        """
        Initialize Redis backend.

        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            prefix: Key prefix
            default_ttl: Default TTL in seconds
            connection_pool: Optional connection pool
        """
        self._prefix = prefix
        self._default_ttl = default_ttl
        self._client = None

        try:
            import redis

            if connection_pool:
                self._client = redis.Redis(connection_pool=connection_pool)
            else:
                self._client = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    password=password,
                    decode_responses=False,
                )
            self._available = True
        except ImportError:
            logger.warning("redis package not installed, RedisBackend unavailable")
            self._available = False

    @property
    def is_available(self) -> bool:
        """Check if Redis is available."""
        if not self._available or not self._client:
            return False
        try:
            self._client.ping()
            return True
        except (ConnectionError, TimeoutError, OSError):
            return False

    def _make_key(self, key: str) -> str:
        """Add prefix to key."""
        return f"{self._prefix}{key}"

    def _strip_prefix(self, key: str) -> str:
        """Remove prefix from key."""
        if key.startswith(self._prefix):
            return key[len(self._prefix) :]
        return key

    def get(self, key: str) -> CacheEntry | None:
        """Get a cache entry."""
        if not self._available or not self._client:
            return None

        try:
            full_key = self._make_key(key)
            data = self._client.get(full_key)
            if data is None:
                return None

            entry_dict = json.loads(data.decode("utf-8"))
            entry = CacheEntry.from_dict(entry_dict)

            # Update hits
            entry.touch()
            self._client.set(
                full_key,
                json.dumps(entry.to_dict()),
                keepttl=True,
            )

            return entry
        except (ConnectionError, TimeoutError, OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Redis get error: {e}")
            return None

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Set a cache entry."""
        if not self._available or not self._client:
            return

        try:
            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
            expires_at = None
            if ttl is not None:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

            entry = CacheEntry(
                key=key,
                value=value,
                ttl_seconds=ttl,
                expires_at=expires_at,
                tags=tags or [],
            )

            full_key = self._make_key(key)
            data = json.dumps(entry.to_dict())

            if ttl:
                self._client.setex(full_key, ttl, data)
            else:
                self._client.set(full_key, data)

            # Store tag mappings
            for tag in entry.tags:
                tag_key = self._make_key(f"_tags:{tag}")
                self._client.sadd(tag_key, key)
                if ttl:
                    self._client.expire(tag_key, ttl)

        except (ConnectionError, TimeoutError, OSError, TypeError) as e:
            logger.error(f"Redis set error: {e}")

    def delete(self, key: str) -> bool:
        """Delete a cache entry."""
        if not self._available or not self._client:
            return False

        try:
            full_key = self._make_key(key)
            return self._client.delete(full_key) > 0
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Redis delete error: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists."""
        if not self._available or not self._client:
            return False

        try:
            full_key = self._make_key(key)
            return self._client.exists(full_key) > 0
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Redis exists error: {e}")
            return False

    def clear(self) -> int:
        """Clear all entries with prefix."""
        if not self._available or not self._client:
            return 0

        try:
            pattern = self._make_key("*")
            keys = list(self._client.scan_iter(pattern))
            if keys:
                return self._client.delete(*keys)
            return 0
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Redis clear error: {e}")
            return 0

    def keys(self, pattern: str = "*") -> list[str]:
        """List keys matching pattern."""
        if not self._available or not self._client:
            return []

        try:
            full_pattern = self._make_key(pattern)
            keys = list(self._client.scan_iter(full_pattern))
            return [self._strip_prefix(k.decode("utf-8")) for k in keys]
        except (ConnectionError, TimeoutError, OSError, UnicodeDecodeError) as e:
            logger.error(f"Redis keys error: {e}")
            return []

    def delete_by_tag(self, tag: str) -> int:
        """Delete all entries with a specific tag."""
        if not self._available or not self._client:
            return 0

        try:
            tag_key = self._make_key(f"_tags:{tag}")
            members = self._client.smembers(tag_key)
            count = 0
            for key in members:
                if self.delete(key.decode("utf-8")):
                    count += 1
            self._client.delete(tag_key)
            return count
        except (ConnectionError, TimeoutError, OSError, UnicodeDecodeError) as e:
            logger.error(f"Redis delete_by_tag error: {e}")
            return 0

    def get_stats(self) -> dict[str, Any]:
        """Get backend statistics."""
        if not self._available or not self._client:
            return {"backend": "redis", "available": False}

        try:
            info = self._client.info()
            keys = len(self.keys())
            return {
                "backend": "redis",
                "available": True,
                "keys": keys,
                "used_memory": info.get("used_memory_human", "unknown"),
                "connected_clients": info.get("connected_clients", 0),
                "uptime_days": info.get("uptime_in_days", 0),
            }
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Redis stats error: {e}")
            return {"backend": "redis", "available": False, "error": str(e)}


class TieredBackend(CacheBackend):
    """
    Two-tier cache backend.

    Uses fast local memory cache backed by slower persistent cache (e.g., Redis).
    """

    def __init__(
        self,
        l1_backend: CacheBackend,
        l2_backend: CacheBackend,
        l1_ttl_fraction: float = 0.5,
    ):
        """
        Initialize tiered backend.

        Args:
            l1_backend: Level 1 (fast) backend
            l2_backend: Level 2 (persistent) backend
            l1_ttl_fraction: Fraction of TTL to use for L1
        """
        self._l1 = l1_backend
        self._l2 = l2_backend
        self._l1_ttl_fraction = l1_ttl_fraction

    def get(self, key: str) -> CacheEntry | None:
        """Get from L1, fall back to L2."""
        # Try L1 first
        entry = self._l1.get(key)
        if entry:
            return entry

        # Fall back to L2
        entry = self._l2.get(key)
        if entry:
            # Promote to L1
            l1_ttl = None
            if entry.ttl_seconds:
                l1_ttl = int(entry.ttl_seconds * self._l1_ttl_fraction)
            self._l1.set(key, entry.value, l1_ttl, entry.tags)
            return entry

        return None

    def set(
        self,
        key: str,
        value: Any,
        ttl_seconds: int | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Set in both L1 and L2."""
        # Set in L2
        self._l2.set(key, value, ttl_seconds, tags)

        # Set in L1 with shorter TTL
        l1_ttl = None
        if ttl_seconds:
            l1_ttl = int(ttl_seconds * self._l1_ttl_fraction)
        self._l1.set(key, value, l1_ttl, tags)

    def delete(self, key: str) -> bool:
        """Delete from both tiers."""
        l1_result = self._l1.delete(key)
        l2_result = self._l2.delete(key)
        return l1_result or l2_result

    def exists(self, key: str) -> bool:
        """Check if key exists in either tier."""
        return self._l1.exists(key) or self._l2.exists(key)

    def clear(self) -> int:
        """Clear both tiers."""
        l1_count = self._l1.clear()
        l2_count = self._l2.clear()
        return l1_count + l2_count

    def keys(self, pattern: str = "*") -> list[str]:
        """Get keys from L2 (authoritative)."""
        return self._l2.keys(pattern)

    def get_stats(self) -> dict[str, Any]:
        """Get combined statistics."""
        return {
            "backend": "tiered",
            "l1": self._l1.get_stats(),
            "l2": self._l2.get_stats(),
        }


def create_key(*args, **kwargs) -> str:
    """
    Create a cache key from arguments.

    Args:
        *args: Positional arguments to include in key
        **kwargs: Keyword arguments to include in key

    Returns:
        MD5 hash key
    """
    key_parts = [str(arg) for arg in args]
    for k, v in sorted(kwargs.items()):
        key_parts.append(f"{k}={v}")

    key_str = ":".join(key_parts)
    return hashlib.md5(key_str.encode()).hexdigest()
