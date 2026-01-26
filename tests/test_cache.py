"""Tests for caching layer."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import time


class TestCacheEntry:
    """Tests for CacheEntry."""

    def test_entry_creation(self):
        """Test basic entry creation."""
        from redops.cache import CacheEntry

        entry = CacheEntry(
            key="test-key",
            value={"data": "value"},
        )

        assert entry.key == "test-key"
        assert entry.value == {"data": "value"}
        assert entry.hits == 0
        assert entry.expires_at is None

    def test_entry_with_expiry(self):
        """Test entry with expiration."""
        from redops.cache import CacheEntry

        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        entry = CacheEntry(
            key="test",
            value="data",
            expires_at=expires,
            ttl_seconds=3600,
        )

        assert entry.expires_at == expires
        assert entry.ttl_seconds == 3600
        assert entry.is_expired() is False

    def test_entry_expired(self):
        """Test expired entry detection."""
        from redops.cache import CacheEntry

        past = datetime.now(timezone.utc) - timedelta(hours=1)
        entry = CacheEntry(
            key="test",
            value="data",
            expires_at=past,
        )

        assert entry.is_expired() is True

    def test_entry_touch(self):
        """Test hit counter increment."""
        from redops.cache import CacheEntry

        entry = CacheEntry(key="test", value="data")

        assert entry.hits == 0
        entry.touch()
        assert entry.hits == 1
        entry.touch()
        assert entry.hits == 2

    def test_entry_with_tags(self):
        """Test entry with tags."""
        from redops.cache import CacheEntry

        entry = CacheEntry(
            key="test",
            value="data",
            tags=["intel", "dns"],
        )

        assert "intel" in entry.tags
        assert "dns" in entry.tags

    def test_entry_to_dict_from_dict(self):
        """Test serialization round-trip."""
        from redops.cache import CacheEntry

        entry = CacheEntry(
            key="test",
            value={"nested": {"data": 123}},
            ttl_seconds=3600,
            tags=["tag1"],
        )

        data = entry.to_dict()
        restored = CacheEntry.from_dict(data)

        assert restored.key == entry.key
        assert restored.value == entry.value
        assert restored.ttl_seconds == entry.ttl_seconds
        assert restored.tags == entry.tags


class TestMemoryBackend:
    """Tests for MemoryBackend."""

    def test_backend_get_set(self):
        """Test basic get/set operations."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("key1", "value1")
        entry = backend.get("key1")

        assert entry is not None
        assert entry.value == "value1"

    def test_backend_get_missing(self):
        """Test get on missing key."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        entry = backend.get("nonexistent")
        assert entry is None

    def test_backend_set_with_ttl(self):
        """Test set with TTL."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("key1", "value1", ttl_seconds=3600)
        entry = backend.get("key1")

        assert entry is not None
        assert entry.ttl_seconds == 3600
        assert entry.expires_at is not None

    def test_backend_expired_entry(self):
        """Test expired entries are not returned."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        # Set with very short TTL
        backend.set("key1", "value1", ttl_seconds=0)

        # Should not return expired entry
        entry = backend.get("key1")
        assert entry is None

    def test_backend_delete(self):
        """Test delete operation."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("key1", "value1")
        assert backend.exists("key1") is True

        result = backend.delete("key1")
        assert result is True
        assert backend.exists("key1") is False

    def test_backend_delete_missing(self):
        """Test delete on missing key."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        result = backend.delete("nonexistent")
        assert result is False

    def test_backend_exists(self):
        """Test exists check."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        assert backend.exists("key1") is False
        backend.set("key1", "value1")
        assert backend.exists("key1") is True

    def test_backend_clear(self):
        """Test clear operation."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("key1", "value1")
        backend.set("key2", "value2")
        backend.set("key3", "value3")

        count = backend.clear()
        assert count == 3
        assert len(backend.keys()) == 0

    def test_backend_keys(self):
        """Test keys listing."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("user:1", "data1")
        backend.set("user:2", "data2")
        backend.set("config:app", "data3")

        all_keys = backend.keys()
        assert len(all_keys) == 3

        user_keys = backend.keys("user:*")
        assert len(user_keys) == 2

    def test_backend_lru_eviction(self):
        """Test LRU eviction at capacity."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend(max_size=3)

        backend.set("key1", "value1")
        backend.set("key2", "value2")
        backend.set("key3", "value3")

        # Access key1 and key2 to increase their hit counts
        backend.get("key1")
        backend.get("key2")

        # Add key4, should evict key3 (lowest hits)
        backend.set("key4", "value4")

        assert backend.exists("key1") is True
        assert backend.exists("key2") is True
        assert backend.exists("key3") is False
        assert backend.exists("key4") is True

    def test_backend_default_ttl(self):
        """Test default TTL."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend(default_ttl=3600)

        backend.set("key1", "value1")
        entry = backend.get("key1")

        assert entry.ttl_seconds == 3600

    def test_backend_stats(self):
        """Test statistics."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("key1", "value1")
        backend.get("key1")  # hit
        backend.get("key2")  # miss

        stats = backend.get_stats()

        assert stats["backend"] == "memory"
        assert stats["keys"] == 1
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5

    def test_backend_tags(self):
        """Test tag-based deletion."""
        from redops.cache import MemoryBackend

        backend = MemoryBackend()

        backend.set("key1", "value1", tags=["group1"])
        backend.set("key2", "value2", tags=["group1", "group2"])
        backend.set("key3", "value3", tags=["group2"])

        count = backend.delete_by_tag("group1")

        assert count == 2
        assert backend.exists("key1") is False
        assert backend.exists("key2") is False
        assert backend.exists("key3") is True


class TestRedisBackend:
    """Tests for RedisBackend (without real Redis)."""

    def test_backend_unavailable(self):
        """Test backend when Redis not available."""
        from redops.cache import RedisBackend

        backend = RedisBackend()
        backend._available = False
        backend._client = None

        # Should gracefully handle unavailable Redis
        assert backend.get("key") is None
        backend.set("key", "value")  # Should not raise
        assert backend.exists("key") is False

    def test_backend_mock_operations(self):
        """Test operations with mocked Redis client."""
        from redops.cache.backends import RedisBackend

        backend = RedisBackend()

        mock_redis = MagicMock()
        mock_redis.get.return_value = None

        backend._client = mock_redis
        backend._available = True

        # Test get
        backend.get("test-key")
        mock_redis.get.assert_called()

    def test_backend_stats_unavailable(self):
        """Test stats when unavailable."""
        from redops.cache import RedisBackend

        backend = RedisBackend()
        backend._available = False

        stats = backend.get_stats()

        assert stats["backend"] == "redis"
        assert stats["available"] is False


class TestTieredBackend:
    """Tests for TieredBackend."""

    def test_tiered_get_l1_hit(self):
        """Test L1 cache hit."""
        from redops.cache import MemoryBackend, TieredBackend

        l1 = MemoryBackend()
        l2 = MemoryBackend()
        tiered = TieredBackend(l1, l2)

        # Set in L1 only
        l1.set("key1", "value1")

        entry = tiered.get("key1")

        assert entry is not None
        assert entry.value == "value1"

    def test_tiered_get_l2_fallback(self):
        """Test L2 fallback and L1 promotion."""
        from redops.cache import MemoryBackend, TieredBackend

        l1 = MemoryBackend()
        l2 = MemoryBackend()
        tiered = TieredBackend(l1, l2)

        # Set in L2 only
        l2.set("key1", "value1", ttl_seconds=3600)

        # Get should find in L2 and promote to L1
        entry = tiered.get("key1")

        assert entry is not None
        assert entry.value == "value1"

        # Should now be in L1
        assert l1.exists("key1") is True

    def test_tiered_set(self):
        """Test set writes to both tiers."""
        from redops.cache import MemoryBackend, TieredBackend

        l1 = MemoryBackend()
        l2 = MemoryBackend()
        tiered = TieredBackend(l1, l2)

        tiered.set("key1", "value1", ttl_seconds=3600)

        # Should be in both
        assert l1.exists("key1") is True
        assert l2.exists("key1") is True

    def test_tiered_delete(self):
        """Test delete removes from both tiers."""
        from redops.cache import MemoryBackend, TieredBackend

        l1 = MemoryBackend()
        l2 = MemoryBackend()
        tiered = TieredBackend(l1, l2)

        tiered.set("key1", "value1")
        tiered.delete("key1")

        assert l1.exists("key1") is False
        assert l2.exists("key1") is False

    def test_tiered_stats(self):
        """Test combined statistics."""
        from redops.cache import MemoryBackend, TieredBackend

        l1 = MemoryBackend()
        l2 = MemoryBackend()
        tiered = TieredBackend(l1, l2)

        stats = tiered.get_stats()

        assert stats["backend"] == "tiered"
        assert "l1" in stats
        assert "l2" in stats


class TestCreateKey:
    """Tests for key creation utility."""

    def test_create_key_args(self):
        """Test key creation from args."""
        from redops.cache import create_key

        key1 = create_key("module", "func", "arg1")
        key2 = create_key("module", "func", "arg1")
        key3 = create_key("module", "func", "arg2")

        assert key1 == key2  # Same args = same key
        assert key1 != key3  # Different args = different key

    def test_create_key_kwargs(self):
        """Test key creation from kwargs."""
        from redops.cache import create_key

        key1 = create_key(a=1, b=2)
        key2 = create_key(b=2, a=1)  # Order shouldn't matter

        assert key1 == key2


class TestCache:
    """Tests for main Cache class."""

    def test_cache_creation(self):
        """Test cache creation."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        assert cache is not None

    def test_cache_get_set(self):
        """Test basic get/set."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        cache.set("key1", {"data": "value"})
        value = cache.get("key1")

        assert value == {"data": "value"}

    def test_cache_get_missing(self):
        """Test get on missing key."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        value = cache.get("nonexistent")
        assert value is None

    def test_cache_delete(self):
        """Test delete."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        cache.set("key1", "value1")
        assert cache.exists("key1") is True

        cache.delete("key1")
        assert cache.exists("key1") is False

    def test_cache_get_or_set(self):
        """Test get_or_set."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        call_count = []

        def factory():
            call_count.append(1)
            return {"computed": True}

        # First call should invoke factory
        value1 = cache.get_or_set("key1", factory)
        assert value1 == {"computed": True}
        assert len(call_count) == 1

        # Second call should return cached value
        value2 = cache.get_or_set("key1", factory)
        assert value2 == {"computed": True}
        assert len(call_count) == 1  # Factory not called again

    def test_cache_intel(self):
        """Test intel caching methods."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory", intel_ttl_seconds=3600)
        cache = Cache(config)

        intel_data = {"noise": True, "classification": "malicious"}
        cache.cache_intel("greynoise", "1.2.3.4", intel_data)

        result = cache.get_intel("greynoise", "1.2.3.4")
        assert result == intel_data

        # Different indicator should not match
        result2 = cache.get_intel("greynoise", "5.6.7.8")
        assert result2 is None

    def test_cache_invalidate_intel(self):
        """Test intel invalidation."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        cache.cache_intel("greynoise", "1.2.3.4", {"data": "gn"})
        cache.cache_intel("abuseipdb", "1.2.3.4", {"data": "abuse"})

        # Invalidate just greynoise
        count = cache.invalidate_intel("greynoise")
        assert count == 1

        assert cache.get_intel("greynoise", "1.2.3.4") is None
        assert cache.get_intel("abuseipdb", "1.2.3.4") is not None

    def test_cache_rate_limit(self):
        """Test rate limiting."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory", rate_limit_window_seconds=60)
        cache = Cache(config)

        # First requests should be allowed
        allowed1, remaining1 = cache.check_rate_limit("api:test", limit=3)
        assert allowed1 is True
        assert remaining1 == 2

        allowed2, remaining2 = cache.check_rate_limit("api:test", limit=3)
        assert allowed2 is True
        assert remaining2 == 1

        allowed3, remaining3 = cache.check_rate_limit("api:test", limit=3)
        assert allowed3 is True
        assert remaining3 == 0

        # Fourth request should be denied
        allowed4, remaining4 = cache.check_rate_limit("api:test", limit=3)
        assert allowed4 is False
        assert remaining4 == 0

    def test_cache_rate_limit_status(self):
        """Test rate limit status."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        # Make some requests
        cache.check_rate_limit("api:test", limit=10)
        cache.check_rate_limit("api:test", limit=10)

        status = cache.get_rate_limit_status("api:test", limit=10)

        assert status["identifier"] == "api:test"
        assert status["limit"] == 10
        assert status["used"] == 2
        assert status["remaining"] == 8

    def test_cache_reset_rate_limit(self):
        """Test rate limit reset."""
        from redops.cache import Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)

        # Use up some limit
        cache.check_rate_limit("api:test", limit=3)
        cache.check_rate_limit("api:test", limit=3)
        cache.check_rate_limit("api:test", limit=3)

        # Reset
        cache.reset_rate_limit("api:test")

        # Should have full limit again
        allowed, remaining = cache.check_rate_limit("api:test", limit=3)
        assert allowed is True
        assert remaining == 2


class TestCacheDecorators:
    """Tests for caching decorators."""

    def test_cached_decorator(self):
        """Test @cached decorator."""
        from redops.cache import cached, get_cache

        # Reset global cache
        import redops.cache.cache as cache_module
        cache_module._cache = None

        call_count = []

        @cached(ttl=3600)
        def expensive_function(x, y):
            call_count.append(1)
            return x + y

        # First call computes
        result1 = expensive_function(1, 2)
        assert result1 == 3
        assert len(call_count) == 1

        # Second call uses cache
        result2 = expensive_function(1, 2)
        assert result2 == 3
        assert len(call_count) == 1

        # Different args computes again
        result3 = expensive_function(2, 3)
        assert result3 == 5
        assert len(call_count) == 2

    def test_cached_with_prefix(self):
        """Test @cached with key prefix."""
        from redops.cache import cached, get_cache

        import redops.cache.cache as cache_module
        cache_module._cache = None

        @cached(ttl=3600, key_prefix="myprefix")
        def my_function(x):
            return x * 2

        result = my_function(5)
        assert result == 10

    def test_rate_limited_decorator(self):
        """Test @rate_limited decorator."""
        from redops.cache import rate_limited, RateLimitExceeded

        import redops.cache.cache as cache_module
        cache_module._cache = None

        @rate_limited(identifier="test-func", limit=2)
        def limited_function():
            return "success"

        # First two calls succeed
        assert limited_function() == "success"
        assert limited_function() == "success"

        # Third call should raise
        with pytest.raises(RateLimitExceeded) as exc_info:
            limited_function()

        assert exc_info.value.identifier == "test-func"
        assert exc_info.value.limit == 2

    def test_rate_limited_with_handler(self):
        """Test @rate_limited with custom handler."""
        from redops.cache import rate_limited

        import redops.cache.cache as cache_module
        cache_module._cache = None

        def on_limit():
            return "rate limited"

        @rate_limited(identifier="test-handler", limit=1, on_exceeded=on_limit)
        def limited_function():
            return "success"

        assert limited_function() == "success"
        assert limited_function() == "rate limited"


class TestIntelCache:
    """Tests for IntelCache."""

    def test_intel_cache_get_set(self):
        """Test basic intel cache operations."""
        from redops.cache import IntelCache, Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)
        intel_cache = IntelCache(cache)

        intel_cache.set("greynoise", "1.2.3.4", {"noise": True})
        result = intel_cache.get("greynoise", "1.2.3.4")

        assert result == {"noise": True}

    def test_intel_cache_get_or_fetch(self):
        """Test get_or_fetch."""
        from redops.cache import IntelCache, Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)
        intel_cache = IntelCache(cache)

        fetch_count = []

        def fetcher():
            fetch_count.append(1)
            return {"fetched": True}

        # First call fetches
        result1 = intel_cache.get_or_fetch("source", "indicator", fetcher)
        assert result1 == {"fetched": True}
        assert len(fetch_count) == 1

        # Second call uses cache
        result2 = intel_cache.get_or_fetch("source", "indicator", fetcher)
        assert result2 == {"fetched": True}
        assert len(fetch_count) == 1

    def test_intel_cache_invalidate(self):
        """Test intel cache invalidation."""
        from redops.cache import IntelCache, Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)
        intel_cache = IntelCache(cache)

        intel_cache.set("greynoise", "1.2.3.4", {"data": 1})
        intel_cache.set("abuseipdb", "1.2.3.4", {"data": 2})

        # Invalidate specific source
        count = intel_cache.invalidate("greynoise")
        assert count == 1

        assert intel_cache.get("greynoise", "1.2.3.4") is None
        assert intel_cache.get("abuseipdb", "1.2.3.4") is not None

    def test_intel_cache_rate_limit(self):
        """Test intel source rate limiting."""
        from redops.cache import IntelCache, Cache, CacheConfig

        config = CacheConfig(backend="memory")
        cache = Cache(config)
        intel_cache = IntelCache(cache)

        allowed, remaining = intel_cache.check_rate_limit("greynoise", limit=5)

        assert allowed is True
        assert remaining == 4


class TestCacheConfig:
    """Tests for CacheConfig."""

    def test_config_defaults(self):
        """Test default configuration."""
        from redops.cache import CacheConfig

        config = CacheConfig()

        assert config.backend == "memory"
        assert config.redis_host == "localhost"
        assert config.redis_port == 6379
        assert config.default_ttl_seconds == 3600
        assert config.intel_ttl_seconds == 86400

    def test_config_from_env(self):
        """Test configuration from environment."""
        env = {
            "CACHE_BACKEND": "redis",
            "REDIS_HOST": "redis.local",
            "REDIS_PORT": "6380",
            "CACHE_DEFAULT_TTL": "7200",
            "CACHE_INTEL_TTL": "43200",
        }

        with patch.dict("os.environ", env):
            from redops.cache import CacheConfig
            config = CacheConfig.from_env()

            assert config.backend == "redis"
            assert config.redis_host == "redis.local"
            assert config.redis_port == 6380
            assert config.default_ttl_seconds == 7200
            assert config.intel_ttl_seconds == 43200


class TestCacheModuleImports:
    """Test module imports."""

    def test_all_exports(self):
        """Test all expected exports."""
        from redops.cache import (
            # Backends
            CacheBackend,
            CacheEntry,
            MemoryBackend,
            RedisBackend,
            TieredBackend,
            create_key,
            # Cache
            Cache,
            CacheConfig,
            IntelCache,
            RateLimitExceeded,
            get_cache,
            get_intel_cache,
            # Decorators
            cached,
            rate_limited,
        )

        assert callable(get_cache)
        assert callable(get_intel_cache)
        assert callable(cached)
        assert callable(rate_limited)

    def test_get_cache_singleton(self):
        """Test global cache accessor."""
        import redops.cache.cache as cache_module
        cache_module._cache = None

        from redops.cache import get_cache

        cache1 = get_cache()
        cache2 = get_cache()

        assert cache1 is cache2
