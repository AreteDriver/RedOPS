"""
Tests for RedOPS Caching Layer.
"""

import tempfile
import time
from pathlib import Path

import pytest

from redops.core.cache import (
    Cache,
    CacheBackend,
    CacheEntry,
    CacheError,
    CacheKeyError,
    CacheStats,
    CacheStorageError,
    FileCacheBackend,
    HybridCacheBackend,
    InvalidationStrategy,
    MemoryCacheBackend,
    cached,
    generate_cache_key,
    get_cache,
    set_global_cache,
)


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_basic_creation(self):
        """Test basic entry creation."""
        entry = CacheEntry(
            key="test_key",
            value="test_value",
            created_at=time.time(),
            expires_at=time.time() + 3600,
        )

        assert entry.key == "test_key"
        assert entry.value == "test_value"
        assert entry.access_count == 0
        assert not entry.is_expired

    def test_expired_entry(self):
        """Test expired entry detection."""
        entry = CacheEntry(
            key="expired",
            value="old_value",
            created_at=time.time() - 100,
            expires_at=time.time() - 1,  # Expired 1 second ago
        )

        assert entry.is_expired is True

    def test_no_expiration(self):
        """Test entry with no expiration."""
        entry = CacheEntry(
            key="forever",
            value="eternal",
            created_at=time.time(),
            expires_at=None,
        )

        assert entry.is_expired is False
        assert entry.ttl_remaining is None

    def test_ttl_remaining(self):
        """Test TTL remaining calculation."""
        entry = CacheEntry(
            key="ttl_test",
            value="value",
            created_at=time.time(),
            expires_at=time.time() + 100,
        )

        ttl = entry.ttl_remaining
        assert ttl is not None
        assert 99 <= ttl <= 100

    def test_touch(self):
        """Test touch updates access metadata."""
        entry = CacheEntry(
            key="touch_test",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )

        original_access_count = entry.access_count
        original_last_accessed = entry.last_accessed

        time.sleep(0.01)
        entry.touch()

        assert entry.access_count == original_access_count + 1
        assert entry.last_accessed > original_last_accessed


class TestCacheStats:
    """Tests for CacheStats dataclass."""

    def test_default_values(self):
        """Test default stats values."""
        stats = CacheStats()

        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.evictions == 0
        assert stats.hit_rate == 0.0

    def test_hit_rate_calculation(self):
        """Test hit rate calculation."""
        stats = CacheStats(hits=75, misses=25)
        assert stats.hit_rate == 0.75

    def test_hit_rate_zero_total(self):
        """Test hit rate with zero requests."""
        stats = CacheStats(hits=0, misses=0)
        assert stats.hit_rate == 0.0

    def test_to_dict(self):
        """Test converting stats to dict."""
        stats = CacheStats(
            hits=100,
            misses=20,
            evictions=5,
            size_bytes=1024,
        )

        result = stats.to_dict()

        assert result["hits"] == 100
        assert result["misses"] == 20
        assert result["hit_rate"] == 0.8333  # Rounded


class TestMemoryCacheBackend:
    """Tests for MemoryCacheBackend."""

    def test_set_and_get(self):
        """Test basic set and get."""
        backend = MemoryCacheBackend()

        entry = CacheEntry(
            key="test",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )

        backend.set(entry)
        result = backend.get("test")

        assert result is not None
        assert result.value == "value"

    def test_get_nonexistent(self):
        """Test getting nonexistent key."""
        backend = MemoryCacheBackend()
        assert backend.get("nonexistent") is None

    def test_delete(self):
        """Test deleting entry."""
        backend = MemoryCacheBackend()

        entry = CacheEntry(
            key="delete_me",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )
        backend.set(entry)

        assert backend.delete("delete_me") is True
        assert backend.get("delete_me") is None

    def test_delete_nonexistent(self):
        """Test deleting nonexistent key."""
        backend = MemoryCacheBackend()
        assert backend.delete("nonexistent") is False

    def test_exists(self):
        """Test exists check."""
        backend = MemoryCacheBackend()

        entry = CacheEntry(
            key="exists_test",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )
        backend.set(entry)

        assert backend.exists("exists_test") is True
        assert backend.exists("nonexistent") is False

    def test_clear(self):
        """Test clearing all entries."""
        backend = MemoryCacheBackend()

        for i in range(5):
            entry = CacheEntry(
                key=f"key_{i}",
                value=f"value_{i}",
                created_at=time.time(),
                expires_at=None,
            )
            backend.set(entry)

        count = backend.clear()

        assert count == 5
        assert backend.size() == 0

    def test_keys(self):
        """Test getting all keys."""
        backend = MemoryCacheBackend()

        for i in range(3):
            entry = CacheEntry(
                key=f"key_{i}",
                value=f"value_{i}",
                created_at=time.time(),
                expires_at=None,
            )
            backend.set(entry)

        keys = backend.keys()

        assert len(keys) == 3
        assert "key_0" in keys
        assert "key_1" in keys
        assert "key_2" in keys

    def test_size(self):
        """Test getting cache size."""
        backend = MemoryCacheBackend()

        assert backend.size() == 0

        entry = CacheEntry(
            key="test",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )
        backend.set(entry)

        assert backend.size() == 1


class TestFileCacheBackend:
    """Tests for FileCacheBackend."""

    @pytest.fixture
    def cache_dir(self):
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_set_and_get(self, cache_dir):
        """Test basic set and get."""
        backend = FileCacheBackend(cache_dir)

        entry = CacheEntry(
            key="test",
            value={"data": "value"},
            created_at=time.time(),
            expires_at=None,
        )

        backend.set(entry)
        result = backend.get("test")

        assert result is not None
        assert result.value == {"data": "value"}

    def test_get_nonexistent(self, cache_dir):
        """Test getting nonexistent key."""
        backend = FileCacheBackend(cache_dir)
        assert backend.get("nonexistent") is None

    def test_delete(self, cache_dir):
        """Test deleting entry."""
        backend = FileCacheBackend(cache_dir)

        entry = CacheEntry(
            key="delete_me",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )
        backend.set(entry)

        assert backend.delete("delete_me") is True
        assert backend.get("delete_me") is None

    def test_persistence(self, cache_dir):
        """Test that entries persist across backend instances."""
        backend1 = FileCacheBackend(cache_dir)

        entry = CacheEntry(
            key="persistent",
            value="survives_restart",
            created_at=time.time(),
            expires_at=None,
        )
        backend1.set(entry)

        # Create new backend instance
        backend2 = FileCacheBackend(cache_dir)
        result = backend2.get("persistent")

        assert result is not None
        assert result.value == "survives_restart"

    def test_clear(self, cache_dir):
        """Test clearing all entries."""
        backend = FileCacheBackend(cache_dir)

        for i in range(3):
            entry = CacheEntry(
                key=f"key_{i}",
                value=f"value_{i}",
                created_at=time.time(),
                expires_at=None,
            )
            backend.set(entry)

        count = backend.clear()

        assert count == 3
        assert backend.size() == 0


class TestHybridCacheBackend:
    """Tests for HybridCacheBackend."""

    @pytest.fixture
    def cache_dir(self):
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_set_and_get(self, cache_dir):
        """Test basic set and get."""
        backend = HybridCacheBackend(cache_dir)

        entry = CacheEntry(
            key="test",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )

        backend.set(entry)
        result = backend.get("test")

        assert result is not None
        assert result.value == "value"

    def test_memory_promotion(self, cache_dir):
        """Test that file entries are promoted to memory."""
        # Set via one instance
        backend1 = HybridCacheBackend(cache_dir)
        entry = CacheEntry(
            key="promote",
            value="value",
            created_at=time.time(),
            expires_at=None,
        )
        backend1.set(entry)

        # Clear memory but keep file
        backend1._memory.clear()

        # Get should promote from file to memory
        result = backend1.get("promote")
        assert result is not None

        # Should now be in memory
        assert backend1._memory.exists("promote")


class TestCache:
    """Tests for main Cache class."""

    def test_basic_set_get(self):
        """Test basic set and get."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("key", "value")
        result = cache.get("key")

        assert result == "value"

    def test_get_default(self):
        """Test get with default value."""
        cache = Cache(backend=CacheBackend.MEMORY)

        result = cache.get("nonexistent", default="default_value")

        assert result == "default_value"

    def test_ttl_expiration(self):
        """Test TTL expiration."""
        cache = Cache(backend=CacheBackend.MEMORY, default_ttl=1)

        cache.set("expires", "value", ttl=1)

        # Should exist immediately
        assert cache.get("expires") == "value"

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get("expires") is None

    def test_no_expiration(self):
        """Test setting with no expiration."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("forever", "value", ttl=0)

        assert cache.get("forever") == "value"

    def test_delete(self):
        """Test deleting entry."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("delete_me", "value")
        assert cache.delete("delete_me") is True
        assert cache.get("delete_me") is None

    def test_exists(self):
        """Test exists check."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("exists", "value")

        assert cache.exists("exists") is True
        assert cache.exists("nonexistent") is False

    def test_get_or_set(self):
        """Test get_or_set pattern."""
        cache = Cache(backend=CacheBackend.MEMORY)
        call_count = 0

        def factory():
            nonlocal call_count
            call_count += 1
            return "computed_value"

        # First call computes
        result1 = cache.get_or_set("computed", factory)
        assert result1 == "computed_value"
        assert call_count == 1

        # Second call uses cache
        result2 = cache.get_or_set("computed", factory)
        assert result2 == "computed_value"
        assert call_count == 1  # Factory not called again

    def test_clear(self):
        """Test clearing cache."""
        cache = Cache(backend=CacheBackend.MEMORY)

        for i in range(5):
            cache.set(f"key_{i}", f"value_{i}")

        count = cache.clear()

        assert count == 5
        assert cache.size() == 0

    def test_clear_expired(self):
        """Test clearing expired entries."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("expires", "value", ttl=1)
        cache.set("stays", "value", ttl=100)

        time.sleep(1.1)

        cleared = cache.clear_expired()

        assert cleared == 1
        assert cache.get("stays") == "value"

    def test_clear_by_tag(self):
        """Test clearing by tag."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("tagged1", "value", tags=["group_a"])
        cache.set("tagged2", "value", tags=["group_a"])
        cache.set("other", "value", tags=["group_b"])

        cleared = cache.clear_by_tag("group_a")

        assert cleared == 2
        assert cache.get("tagged1") is None
        assert cache.get("other") == "value"

    def test_clear_by_prefix(self):
        """Test clearing by prefix."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("user:1", "value")
        cache.set("user:2", "value")
        cache.set("other:1", "value")

        cleared = cache.clear_by_prefix("user:")

        assert cleared == 2
        assert cache.get("user:1") is None
        assert cache.get("other:1") == "value"

    def test_get_ttl(self):
        """Test getting remaining TTL."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("ttl_test", "value", ttl=100)

        ttl = cache.get_ttl("ttl_test")
        assert ttl is not None
        assert 99 <= ttl <= 100

    def test_get_ttl_not_found(self):
        """Test getting TTL for nonexistent key."""
        cache = Cache(backend=CacheBackend.MEMORY)

        ttl = cache.get_ttl("nonexistent")
        assert ttl == -1

    def test_set_ttl(self):
        """Test updating TTL."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("extend", "value", ttl=10)
        cache.set_ttl("extend", 100)

        ttl = cache.get_ttl("extend")
        assert ttl is not None
        assert ttl > 50

    def test_touch(self):
        """Test touching entry."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("touch_me", "value", ttl=10)

        result = cache.touch("touch_me", ttl=100)

        assert result is True
        assert cache.get_ttl("touch_me") > 50

    def test_keys(self):
        """Test getting keys."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("key_a", "value")
        cache.set("key_b", "value")
        cache.set("other", "value")

        all_keys = cache.keys()
        assert len(all_keys) == 3

        filtered_keys = cache.keys(pattern="key_")
        assert len(filtered_keys) == 2

    def test_stats(self):
        """Test cache statistics."""
        cache = Cache(backend=CacheBackend.MEMORY)

        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("nonexistent")  # Miss

        stats = cache.stats()

        assert stats.hits == 2
        assert stats.misses == 1
        assert stats.entry_count == 1

    def test_namespace(self):
        """Test namespace isolation."""
        cache1 = Cache(backend=CacheBackend.MEMORY, namespace="ns1")
        cache2 = Cache(backend=CacheBackend.MEMORY, namespace="ns2")

        cache1.set("key", "value1")
        cache2.set("key", "value2")

        assert cache1.get("key") == "value1"
        assert cache2.get("key") == "value2"

    def test_lru_eviction(self):
        """Test LRU eviction."""
        cache = Cache(
            backend=CacheBackend.MEMORY,
            max_size=3,
            invalidation_strategy=InvalidationStrategy.LRU,
        )

        cache.set("a", "1")
        cache.set("b", "2")
        cache.set("c", "3")

        # Access 'a' to make it recently used
        cache.get("a")

        # Add new item, should evict 'b' (least recently used)
        cache.set("d", "4")

        assert cache.get("a") == "1"  # Recently used, kept
        assert cache.get("b") is None  # Evicted
        assert cache.get("c") == "3"  # Kept
        assert cache.get("d") == "4"  # New

    def test_fifo_eviction(self):
        """Test FIFO eviction."""
        cache = Cache(
            backend=CacheBackend.MEMORY,
            max_size=3,
            invalidation_strategy=InvalidationStrategy.FIFO,
        )

        cache.set("first", "1")
        time.sleep(0.01)
        cache.set("second", "2")
        time.sleep(0.01)
        cache.set("third", "3")

        # Add new item, should evict 'first' (oldest)
        cache.set("fourth", "4")

        assert cache.get("first") is None  # Evicted (oldest)
        assert cache.get("second") == "2"


class TestFileCacheIntegration:
    """Integration tests for file-based caching."""

    @pytest.fixture
    def cache_dir(self):
        """Create temporary cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_file_cache_basic(self, cache_dir):
        """Test basic file cache operations."""
        cache = Cache(backend=CacheBackend.FILE, cache_dir=cache_dir)

        cache.set("file_key", {"complex": "data", "number": 42})
        result = cache.get("file_key")

        assert result == {"complex": "data", "number": 42}

    def test_file_cache_persistence(self, cache_dir):
        """Test file cache persists."""
        cache1 = Cache(backend=CacheBackend.FILE, cache_dir=cache_dir)
        cache1.set("persistent", "value")

        # Create new cache instance
        cache2 = Cache(backend=CacheBackend.FILE, cache_dir=cache_dir)
        result = cache2.get("persistent")

        assert result == "value"


class TestCacheDecorator:
    """Tests for @cached decorator."""

    def test_basic_caching(self):
        """Test basic function caching."""
        call_count = 0

        @cached(ttl=100)
        def expensive_function(x, y):
            nonlocal call_count
            call_count += 1
            return x + y

        result1 = expensive_function(1, 2)
        result2 = expensive_function(1, 2)

        assert result1 == 3
        assert result2 == 3
        assert call_count == 1  # Only called once

    def test_different_args(self):
        """Test caching with different arguments."""
        call_count = 0

        @cached(ttl=100)
        def compute(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        compute(1)
        compute(2)
        compute(1)  # Cached

        assert call_count == 2  # Only 2 unique calls

    def test_custom_prefix(self):
        """Test custom key prefix."""
        @cached(ttl=100, key_prefix="custom")
        def my_function():
            return "result"

        result = my_function()
        assert result == "result"


class TestGenerateCacheKey:
    """Tests for generate_cache_key function."""

    def test_positional_args(self):
        """Test key generation from positional args."""
        key1 = generate_cache_key("a", "b", "c")
        key2 = generate_cache_key("a", "b", "c")
        key3 = generate_cache_key("a", "b", "d")

        assert key1 == key2
        assert key1 != key3

    def test_keyword_args(self):
        """Test key generation from keyword args."""
        key1 = generate_cache_key(x=1, y=2)
        key2 = generate_cache_key(y=2, x=1)  # Order shouldn't matter
        key3 = generate_cache_key(x=1, y=3)

        assert key1 == key2  # Same regardless of order
        assert key1 != key3

    def test_mixed_args(self):
        """Test key generation from mixed args."""
        key1 = generate_cache_key("a", "b", x=1, y=2)
        key2 = generate_cache_key("a", "b", x=1, y=2)

        assert key1 == key2


class TestGlobalCache:
    """Tests for global cache functions."""

    def test_get_cache(self):
        """Test getting global cache."""
        cache = get_cache()
        assert isinstance(cache, Cache)

    def test_set_global_cache(self):
        """Test setting global cache."""
        custom_cache = Cache(backend=CacheBackend.MEMORY, namespace="custom")
        set_global_cache(custom_cache)

        assert get_cache() is custom_cache


class TestCacheBackendEnum:
    """Tests for CacheBackend enum."""

    def test_backends(self):
        """Test all backends exist."""
        assert CacheBackend.MEMORY.value == "memory"
        assert CacheBackend.FILE.value == "file"
        assert CacheBackend.HYBRID.value == "hybrid"


class TestInvalidationStrategyEnum:
    """Tests for InvalidationStrategy enum."""

    def test_strategies(self):
        """Test all strategies exist."""
        assert InvalidationStrategy.TTL.value == "ttl"
        assert InvalidationStrategy.LRU.value == "lru"
        assert InvalidationStrategy.LFU.value == "lfu"
        assert InvalidationStrategy.FIFO.value == "fifo"
        assert InvalidationStrategy.MANUAL.value == "manual"


class TestCacheExceptions:
    """Tests for cache exceptions."""

    def test_cache_error(self):
        """Test base CacheError."""
        error = CacheError("Test error")
        assert str(error) == "Test error"

    def test_cache_key_error(self):
        """Test CacheKeyError."""
        error = CacheKeyError("Invalid key")
        assert isinstance(error, CacheError)

    def test_cache_storage_error(self):
        """Test CacheStorageError."""
        error = CacheStorageError("Storage failed")
        assert isinstance(error, CacheError)
