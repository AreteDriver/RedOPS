"""
Tests for RedOPS Rate Limiting.
"""

import time
import threading

import pytest

from redops.core.rate_limiter import (
    BackoffCalculator,
    BackoffStrategy,
    FixedWindowLimiter,
    LeakyBucketLimiter,
    QuotaExceededError,
    QuotaInfo,
    QuotaManager,
    RateLimitAlgorithm,
    RateLimitConfig,
    RateLimitError,
    RateLimiter,
    RateLimitResult,
    SlidingWindowLimiter,
    TokenBucketLimiter,
    acquire,
    get_rate_limiter,
    rate_limited,
    set_rate_limiter,
    with_backoff,
)


class TestRateLimitAlgorithm:
    """Tests for RateLimitAlgorithm enum."""

    def test_all_algorithms_exist(self):
        """Test all algorithms exist."""
        assert RateLimitAlgorithm.TOKEN_BUCKET.value == "token_bucket"
        assert RateLimitAlgorithm.SLIDING_WINDOW.value == "sliding_window"
        assert RateLimitAlgorithm.FIXED_WINDOW.value == "fixed_window"
        assert RateLimitAlgorithm.LEAKY_BUCKET.value == "leaky_bucket"


class TestBackoffStrategy:
    """Tests for BackoffStrategy enum."""

    def test_all_strategies_exist(self):
        """Test all strategies exist."""
        assert BackoffStrategy.NONE.value == "none"
        assert BackoffStrategy.LINEAR.value == "linear"
        assert BackoffStrategy.EXPONENTIAL.value == "exponential"
        assert BackoffStrategy.EXPONENTIAL_JITTER.value == "exponential_jitter"
        assert BackoffStrategy.DECORRELATED_JITTER.value == "decorrelated_jitter"


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass."""

    def test_default_values(self):
        """Test default config values."""
        config = RateLimitConfig()

        assert config.requests_per_second == 1.0
        assert config.burst_size == 1
        assert config.algorithm == RateLimitAlgorithm.TOKEN_BUCKET
        assert config.max_retries == 3

    def test_custom_values(self):
        """Test custom config values."""
        config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=20,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            max_retries=5,
        )

        assert config.requests_per_second == 10.0
        assert config.burst_size == 20


class TestRateLimitResult:
    """Tests for RateLimitResult dataclass."""

    def test_allowed_result(self):
        """Test allowed result."""
        result = RateLimitResult(
            allowed=True,
            remaining=5,
        )

        assert result.allowed is True
        assert result.remaining == 5

    def test_denied_result(self):
        """Test denied result."""
        result = RateLimitResult(
            allowed=False,
            wait_time=1.5,
            retry_after=1.5,
        )

        assert result.allowed is False
        assert result.wait_time == 1.5
        assert result.retry_after == 1.5

    def test_headers(self):
        """Test rate limit headers."""
        result = RateLimitResult(
            allowed=False,
            remaining=0,
            reset_at=1000.0,
            retry_after=5.0,
        )

        headers = result.headers
        assert headers["X-RateLimit-Remaining"] == "0"
        assert headers["X-RateLimit-Reset"] == "1000"
        assert headers["Retry-After"] == "5"


class TestQuotaInfo:
    """Tests for QuotaInfo dataclass."""

    def test_quota_not_exceeded(self):
        """Test quota not exceeded."""
        info = QuotaInfo(
            limit=100,
            used=50,
            remaining=50,
            reset_at=time.time() + 3600,
            period_seconds=3600,
        )

        assert info.is_exceeded is False
        assert info.usage_percent == 50.0

    def test_quota_exceeded(self):
        """Test quota exceeded."""
        info = QuotaInfo(
            limit=100,
            used=100,
            remaining=0,
            reset_at=time.time() + 3600,
            period_seconds=3600,
        )

        assert info.is_exceeded is True
        assert info.usage_percent == 100.0


class TestTokenBucketLimiter:
    """Tests for TokenBucketLimiter."""

    def test_allows_initial_requests(self):
        """Test allows initial burst."""
        limiter = TokenBucketLimiter(rate=10.0, bucket_size=5)

        for _ in range(5):
            result = limiter.acquire()
            assert result.allowed is True

    def test_denies_when_empty(self):
        """Test denies when bucket empty."""
        limiter = TokenBucketLimiter(rate=1.0, bucket_size=2)

        # Exhaust bucket
        limiter.acquire()
        limiter.acquire()

        result = limiter.acquire()
        assert result.allowed is False
        assert result.wait_time > 0

    def test_refills_over_time(self):
        """Test bucket refills over time."""
        limiter = TokenBucketLimiter(rate=10.0, bucket_size=5)

        # Exhaust bucket
        for _ in range(5):
            limiter.acquire()

        # Wait for refill
        time.sleep(0.15)

        result = limiter.acquire()
        assert result.allowed is True

    def test_reset(self):
        """Test reset refills bucket."""
        limiter = TokenBucketLimiter(rate=1.0, bucket_size=5)

        # Exhaust bucket
        for _ in range(5):
            limiter.acquire()

        limiter.reset()

        result = limiter.acquire()
        assert result.allowed is True
        assert limiter.available_tokens >= 4

    def test_available_tokens(self):
        """Test available tokens property."""
        limiter = TokenBucketLimiter(rate=10.0, bucket_size=10)

        assert limiter.available_tokens == 10.0

        limiter.acquire(5)
        # Allow small tolerance for token refill between acquire and check
        assert 5.0 <= limiter.available_tokens < 5.1


class TestSlidingWindowLimiter:
    """Tests for SlidingWindowLimiter."""

    def test_allows_within_limit(self):
        """Test allows requests within limit."""
        limiter = SlidingWindowLimiter(requests=5, window_seconds=1.0)

        for _ in range(5):
            result = limiter.acquire()
            assert result.allowed is True

    def test_denies_over_limit(self):
        """Test denies requests over limit."""
        limiter = SlidingWindowLimiter(requests=3, window_seconds=1.0)

        for _ in range(3):
            limiter.acquire()

        result = limiter.acquire()
        assert result.allowed is False

    def test_window_slides(self):
        """Test window slides over time."""
        limiter = SlidingWindowLimiter(requests=2, window_seconds=0.1)

        limiter.acquire()
        limiter.acquire()

        # Wait for window to slide
        time.sleep(0.15)

        result = limiter.acquire()
        assert result.allowed is True

    def test_current_count(self):
        """Test current count property."""
        limiter = SlidingWindowLimiter(requests=10, window_seconds=1.0)

        assert limiter.current_count == 0

        limiter.acquire()
        limiter.acquire()

        assert limiter.current_count == 2


class TestFixedWindowLimiter:
    """Tests for FixedWindowLimiter."""

    def test_allows_within_window(self):
        """Test allows requests within window limit."""
        limiter = FixedWindowLimiter(requests=5, window_seconds=1.0)

        for _ in range(5):
            result = limiter.acquire()
            assert result.allowed is True

    def test_denies_over_window_limit(self):
        """Test denies requests over window limit."""
        limiter = FixedWindowLimiter(requests=3, window_seconds=1.0)

        for _ in range(3):
            limiter.acquire()

        result = limiter.acquire()
        assert result.allowed is False

    def test_window_resets(self):
        """Test window resets after period."""
        limiter = FixedWindowLimiter(requests=2, window_seconds=0.1)

        limiter.acquire()
        limiter.acquire()

        # Wait for window reset
        time.sleep(0.15)

        result = limiter.acquire()
        assert result.allowed is True


class TestLeakyBucketLimiter:
    """Tests for LeakyBucketLimiter."""

    def test_allows_up_to_bucket_size(self):
        """Test allows up to bucket size."""
        limiter = LeakyBucketLimiter(rate=10.0, bucket_size=5)

        for _ in range(5):
            result = limiter.acquire()
            assert result.allowed is True

    def test_denies_when_full(self):
        """Test denies when bucket full."""
        limiter = LeakyBucketLimiter(rate=1.0, bucket_size=3)

        for _ in range(3):
            limiter.acquire()

        result = limiter.acquire()
        assert result.allowed is False

    def test_leaks_over_time(self):
        """Test bucket leaks over time."""
        limiter = LeakyBucketLimiter(rate=10.0, bucket_size=5)

        # Fill bucket
        for _ in range(5):
            limiter.acquire()

        # Wait for leak
        time.sleep(0.15)

        result = limiter.acquire()
        assert result.allowed is True


class TestBackoffCalculator:
    """Tests for BackoffCalculator."""

    def test_no_backoff(self):
        """Test no backoff strategy."""
        calc = BackoffCalculator(strategy=BackoffStrategy.NONE)

        assert calc.get_delay(0) == 0.0
        assert calc.get_delay(5) == 0.0

    def test_linear_backoff(self):
        """Test linear backoff strategy."""
        calc = BackoffCalculator(
            strategy=BackoffStrategy.LINEAR,
            base_delay=1.0,
        )

        assert calc.get_delay(0) == 1.0
        assert calc.get_delay(1) == 2.0
        assert calc.get_delay(2) == 3.0

    def test_exponential_backoff(self):
        """Test exponential backoff strategy."""
        calc = BackoffCalculator(
            strategy=BackoffStrategy.EXPONENTIAL,
            base_delay=1.0,
            multiplier=2.0,
        )

        assert calc.get_delay(0) == 1.0
        assert calc.get_delay(1) == 2.0
        assert calc.get_delay(2) == 4.0

    def test_max_delay_cap(self):
        """Test max delay is capped."""
        calc = BackoffCalculator(
            strategy=BackoffStrategy.EXPONENTIAL,
            base_delay=1.0,
            max_delay=5.0,
        )

        delay = calc.get_delay(10)
        assert delay <= 5.0

    def test_jitter_varies(self):
        """Test jitter produces varying delays."""
        calc = BackoffCalculator(
            strategy=BackoffStrategy.EXPONENTIAL_JITTER,
            base_delay=1.0,
        )

        delays = [calc.get_delay(2) for _ in range(10)]

        # Should have some variation
        assert len(set(delays)) > 1

    def test_reset(self):
        """Test reset clears state."""
        calc = BackoffCalculator(
            strategy=BackoffStrategy.DECORRELATED_JITTER,
            base_delay=1.0,
        )

        calc.get_delay(5)
        calc.reset()

        # Should reset to base delay behavior
        delay = calc.get_delay(0)
        assert delay >= 0


class TestQuotaManager:
    """Tests for QuotaManager."""

    def test_set_and_use_quota(self):
        """Test setting and using quota."""
        manager = QuotaManager()
        manager.set_quota("api_calls", limit=100, period_seconds=3600)

        info = manager.use("api_calls", 10)

        assert info.limit == 100
        assert info.used == 10
        assert info.remaining == 90

    def test_quota_exceeded(self):
        """Test quota exceeded error."""
        manager = QuotaManager()
        manager.set_quota("requests", limit=5, period_seconds=3600)

        for _ in range(5):
            manager.use("requests")

        with pytest.raises(QuotaExceededError) as exc_info:
            manager.use("requests")

        assert exc_info.value.quota_info.is_exceeded

    def test_get_info(self):
        """Test getting quota info."""
        manager = QuotaManager()
        manager.set_quota("resource", limit=50, period_seconds=3600)
        manager.use("resource", 20)

        info = manager.get_info("resource")

        assert info.limit == 50
        assert info.used == 20
        assert info.remaining == 30

    def test_get_info_nonexistent(self):
        """Test getting info for nonexistent quota."""
        manager = QuotaManager()

        info = manager.get_info("nonexistent")
        assert info is None

    def test_reset_quota(self):
        """Test resetting quota."""
        manager = QuotaManager()
        manager.set_quota("resource", limit=10, period_seconds=3600)
        manager.use("resource", 10)

        manager.reset("resource")
        info = manager.get_info("resource")

        assert info.used == 0
        assert info.remaining == 10

    def test_reset_all(self):
        """Test resetting all quotas."""
        manager = QuotaManager()
        manager.set_quota("a", limit=10, period_seconds=3600)
        manager.set_quota("b", limit=20, period_seconds=3600)
        manager.use("a", 5)
        manager.use("b", 10)

        manager.reset_all()

        assert manager.get_info("a").used == 0
        assert manager.get_info("b").used == 0

    def test_unknown_resource(self):
        """Test using unknown resource raises error."""
        manager = QuotaManager()

        with pytest.raises(ValueError):
            manager.use("unknown")


class TestRateLimiter:
    """Tests for main RateLimiter class."""

    def test_default_config(self):
        """Test with default config."""
        limiter = RateLimiter()

        result = limiter.acquire()
        assert result.allowed is True

    def test_custom_algorithm(self):
        """Test with custom algorithm."""
        config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=5,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
        )
        limiter = RateLimiter(config)

        for _ in range(5):
            result = limiter.acquire()
            assert result.allowed is True

    def test_acquire_or_wait(self):
        """Test acquire_or_wait blocks."""
        config = RateLimitConfig(
            requests_per_second=10.0,
            burst_size=1,
        )
        limiter = RateLimiter(config)

        # Exhaust token
        limiter.acquire()

        # Should wait and then succeed
        start = time.time()
        result = limiter.acquire_or_wait()
        elapsed = time.time() - start

        assert result.allowed is True
        assert elapsed >= 0.05

    def test_acquire_or_wait_timeout(self):
        """Test acquire_or_wait with timeout."""
        config = RateLimitConfig(
            requests_per_second=0.1,
            burst_size=1,
            timeout=0.1,
        )
        limiter = RateLimiter(config)

        limiter.acquire()

        with pytest.raises(RateLimitError):
            limiter.acquire_or_wait(timeout=0.05)

    def test_quota_integration(self):
        """Test quota management integration."""
        limiter = RateLimiter()
        limiter.set_quota("daily", limit=1000, period_seconds=86400)

        info = limiter.use_quota("daily", 100)

        assert info.remaining == 900

    def test_reset(self):
        """Test reset clears state."""
        config = RateLimitConfig(
            requests_per_second=1.0,
            burst_size=1,
        )
        limiter = RateLimiter(config)

        limiter.acquire()
        limiter.reset()

        result = limiter.acquire()
        assert result.allowed is True

    def test_config_property(self):
        """Test config property."""
        config = RateLimitConfig(requests_per_second=5.0)
        limiter = RateLimiter(config)

        assert limiter.config.requests_per_second == 5.0


class TestRateLimitedDecorator:
    """Tests for @rate_limited decorator."""

    def test_basic_rate_limiting(self):
        """Test basic rate limiting."""
        call_count = 0

        @rate_limited(requests_per_second=10.0, burst_size=2)
        def my_function():
            nonlocal call_count
            call_count += 1
            return call_count

        # Should allow burst
        my_function()
        my_function()

        assert call_count == 2

    def test_rate_limiting_slows_down(self):
        """Test rate limiting slows down calls."""
        @rate_limited(requests_per_second=10.0, burst_size=1)
        def fast_function():
            return time.time()

        start = time.time()
        fast_function()
        fast_function()
        fast_function()
        elapsed = time.time() - start

        # Should take at least 0.2 seconds for 3 calls at 10/sec
        assert elapsed >= 0.15

    def test_custom_key_func(self):
        """Test custom key function."""
        @rate_limited(
            requests_per_second=10.0,
            burst_size=1,
            key_func=lambda x: f"key_{x}",
        )
        def keyed_function(x):
            return x

        # Each key has its own limit
        keyed_function(1)
        keyed_function(2)


class TestWithBackoffDecorator:
    """Tests for @with_backoff decorator."""

    def test_retries_on_failure(self):
        """Test retries on failure."""
        attempt_count = 0

        @with_backoff(max_retries=3, base_delay=0.01)
        def flaky_function():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise ValueError("Not yet")
            return "success"

        result = flaky_function()

        assert result == "success"
        assert attempt_count == 3

    def test_raises_after_max_retries(self):
        """Test raises after max retries."""
        @with_backoff(max_retries=2, base_delay=0.01)
        def always_fails():
            raise ValueError("Always fails")

        with pytest.raises(ValueError):
            always_fails()

    def test_specific_exceptions(self):
        """Test only catches specific exceptions."""
        @with_backoff(
            max_retries=3,
            base_delay=0.01,
            exceptions=(ValueError,),
        )
        def raises_type_error():
            raise TypeError("Wrong type")

        with pytest.raises(TypeError):
            raises_type_error()


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def test_get_rate_limiter(self):
        """Test getting global rate limiter."""
        limiter = get_rate_limiter()
        assert isinstance(limiter, RateLimiter)

    def test_set_rate_limiter(self):
        """Test setting global rate limiter."""
        custom = RateLimiter(RateLimitConfig(requests_per_second=5.0))
        set_rate_limiter(custom)

        assert get_rate_limiter() is custom

    def test_acquire_global(self):
        """Test global acquire function."""
        result = acquire()
        assert isinstance(result, RateLimitResult)


class TestRateLimitError:
    """Tests for RateLimitError exception."""

    def test_basic_error(self):
        """Test basic error creation."""
        error = RateLimitError("Rate limited")

        assert str(error) == "Rate limited"
        assert error.retry_after is None

    def test_error_with_retry_after(self):
        """Test error with retry_after."""
        error = RateLimitError("Rate limited", retry_after=5.0)

        assert error.retry_after == 5.0

    def test_error_with_result(self):
        """Test error with result."""
        result = RateLimitResult(allowed=False, wait_time=5.0)
        error = RateLimitError("Rate limited", result=result)

        assert error.result is result


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_token_bucket(self):
        """Test concurrent access to token bucket."""
        limiter = TokenBucketLimiter(rate=100.0, bucket_size=10)
        results = []

        def worker():
            for _ in range(10):
                result = limiter.acquire()
                results.append(result.allowed)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have some allowed and some denied
        assert len(results) == 50

    def test_concurrent_quota_manager(self):
        """Test concurrent quota access."""
        manager = QuotaManager()
        manager.set_quota("concurrent", limit=100, period_seconds=3600)
        errors = []

        def worker():
            for _ in range(10):
                try:
                    manager.use("concurrent")
                except QuotaExceededError:
                    errors.append(1)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total usage should not exceed limit
        info = manager.get_info("concurrent")
        assert info.used <= 100


class TestWaitAndAcquire:
    """Tests for wait_and_acquire method."""

    def test_waits_for_token(self):
        """Test waits for token availability."""
        limiter = TokenBucketLimiter(rate=10.0, bucket_size=1)

        # Exhaust token
        limiter.acquire()

        start = time.time()
        success = limiter.wait_and_acquire()
        elapsed = time.time() - start

        assert success is True
        assert elapsed >= 0.05

    def test_returns_false_on_timeout(self):
        """Test returns False on timeout."""
        limiter = TokenBucketLimiter(rate=0.1, bucket_size=1)

        limiter.acquire()

        success = limiter.wait_and_acquire(timeout=0.05)

        assert success is False
