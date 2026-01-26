"""Tests for rate limiting."""

import time

import pytest

from redops.api.ratelimit import (
    RateLimitConfig,
    RateLimitResult,
    RateLimitAlgorithm,
    MemoryRateLimitBackend,
    RateLimiter,
    UserRateLimiter,
    APIKeyRateLimiter,
)


class TestRateLimitConfig:
    """Test rate limit configuration."""

    def test_default_config(self):
        """Default configuration values."""
        config = RateLimitConfig(requests=100, window=60)

        assert config.requests == 100
        assert config.window == 60
        assert config.algorithm == RateLimitAlgorithm.SLIDING_WINDOW

    def test_custom_config(self):
        """Custom configuration."""
        config = RateLimitConfig(
            requests=1000,
            window=3600,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            key_prefix="custom",
        )

        assert config.requests == 1000
        assert config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET


class TestRateLimitResult:
    """Test rate limit result."""

    def test_allowed_result(self):
        """Allowed request result."""
        result = RateLimitResult(
            allowed=True,
            limit=100,
            remaining=99,
            reset_at=int(time.time()) + 60,
        )

        assert result.allowed is True
        assert result.remaining == 99
        assert "X-RateLimit-Limit" in result.headers
        assert "Retry-After" not in result.headers

    def test_blocked_result(self):
        """Blocked request result."""
        result = RateLimitResult(
            allowed=False,
            limit=100,
            remaining=0,
            reset_at=int(time.time()) + 60,
            retry_after=30,
        )

        assert result.allowed is False
        assert result.remaining == 0
        assert result.headers["Retry-After"] == "30"


class TestMemoryRateLimitBackend:
    """Test in-memory rate limit backend."""

    def test_basic_rate_limiting(self):
        """Basic rate limiting works."""
        backend = MemoryRateLimitBackend()
        config = RateLimitConfig(requests=3, window=60)

        # First 3 requests should be allowed
        for i in range(3):
            result = backend.check_rate_limit("test", config)
            assert result.allowed is True
            assert result.remaining == 2 - i

        # 4th request should be blocked
        result = backend.check_rate_limit("test", config)
        assert result.allowed is False
        assert result.remaining == 0

    def test_different_keys(self):
        """Different keys have separate limits."""
        backend = MemoryRateLimitBackend()
        config = RateLimitConfig(requests=1, window=60)

        result1 = backend.check_rate_limit("user1", config)
        result2 = backend.check_rate_limit("user2", config)

        assert result1.allowed is True
        assert result2.allowed is True

    def test_reset(self):
        """Reset clears rate limit."""
        backend = MemoryRateLimitBackend()
        config = RateLimitConfig(requests=1, window=60)

        # Use up limit
        backend.check_rate_limit("test", config)
        result = backend.check_rate_limit("test", config)
        assert result.allowed is False

        # Reset
        backend.reset("test")

        # Should be allowed again
        result = backend.check_rate_limit("test", config)
        assert result.allowed is True


class TestRateLimiter:
    """Test main rate limiter."""

    def test_basic_usage(self):
        """Basic rate limiter usage."""
        limiter = RateLimiter(
            default_config=RateLimitConfig(requests=5, window=60)
        )

        for i in range(5):
            result = limiter.check("test-key")
            assert result.allowed is True

        result = limiter.check("test-key")
        assert result.allowed is False

    def test_named_rules(self):
        """Named rate limit rules."""
        limiter = RateLimiter()
        limiter.add_rule("strict", RateLimitConfig(requests=1, window=60))
        limiter.add_rule("relaxed", RateLimitConfig(requests=100, window=60))

        # Strict rule
        result = limiter.check("key1", rule="strict")
        assert result.allowed is True
        result = limiter.check("key1", rule="strict")
        assert result.allowed is False

        # Relaxed rule still allows
        result = limiter.check("key1", rule="relaxed")
        assert result.allowed is True

    def test_custom_config_override(self):
        """Custom config overrides rules."""
        limiter = RateLimiter()

        custom = RateLimitConfig(requests=2, window=60)
        result = limiter.check("key", config=custom)
        assert result.allowed is True
        assert result.limit == 2


class TestUserRateLimiter:
    """Test user-based rate limiting."""

    def test_tier_limits(self):
        """Different tiers have different limits."""
        limiter = UserRateLimiter()

        # Free tier (default: 100/hour)
        for _ in range(100):
            result = limiter.check("user1", tier="free")
            assert result.allowed is True

        result = limiter.check("user1", tier="free")
        assert result.allowed is False

    def test_custom_tier(self):
        """Custom tier configuration."""
        limiter = UserRateLimiter()
        limiter.set_tier_config(
            "vip",
            RateLimitConfig(requests=5, window=60)
        )

        for _ in range(5):
            result = limiter.check("vip-user", tier="vip")
            assert result.allowed is True

        result = limiter.check("vip-user", tier="vip")
        assert result.allowed is False

    def test_per_endpoint_limits(self):
        """Per-endpoint limits."""
        limiter = UserRateLimiter()
        limiter.set_tier_config(
            "test",
            RateLimitConfig(requests=2, window=60)
        )

        # Same user, different endpoints
        limiter.check("user1", tier="test", endpoint="/api/a")
        limiter.check("user1", tier="test", endpoint="/api/a")
        result = limiter.check("user1", tier="test", endpoint="/api/a")
        assert result.allowed is False

        # Different endpoint still allowed
        result = limiter.check("user1", tier="test", endpoint="/api/b")
        assert result.allowed is True


class TestAPIKeyRateLimiter:
    """Test API key rate limiting."""

    def test_default_limit(self):
        """Default API key limit."""
        limiter = APIKeyRateLimiter(default_limit=5, default_window=60)

        for _ in range(5):
            result = limiter.check("api_key_123")
            assert result.allowed is True

        result = limiter.check("api_key_123")
        assert result.allowed is False

    def test_custom_key_limit(self):
        """Custom limit for specific key."""
        limiter = APIKeyRateLimiter(default_limit=1, default_window=60)

        # Set custom limit for a key (using hash)
        import hashlib
        key_hash = hashlib.sha256("premium_key".encode()).hexdigest()[:16]
        limiter.set_key_limit(key_hash, requests=100, window=60)

        # Premium key has higher limit
        for _ in range(100):
            result = limiter.check("premium_key")
            assert result.allowed is True

    def test_reset_key(self):
        """Reset API key limit."""
        limiter = APIKeyRateLimiter(default_limit=1, default_window=60)

        limiter.check("test_key")
        result = limiter.check("test_key")
        assert result.allowed is False

        limiter.reset_key("test_key")

        result = limiter.check("test_key")
        assert result.allowed is True
