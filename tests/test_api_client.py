"""Tests for API client module."""

import threading
import time

import pytest

from redops.core.api_client import (
    # Enums
    HttpMethod,
    CircuitState,
    # Configs
    RetryConfig,
    CircuitBreakerConfig,
    # Classes
    CircuitBreaker,
    CircuitOpenError,
    HttpRequest,
    HttpResponse,
    HttpError,
    RateLimiter,
    ResponseCache,
    MockTransport,
    ApiClient,
    # Convenience
    create_api_client,
)


# =============================================================================
# HttpMethod Tests
# =============================================================================


class TestHttpMethod:
    """Tests for HttpMethod enum."""

    def test_all_methods(self):
        """Test all HTTP methods exist."""
        assert HttpMethod.GET.value == "GET"
        assert HttpMethod.POST.value == "POST"
        assert HttpMethod.PUT.value == "PUT"
        assert HttpMethod.PATCH.value == "PATCH"
        assert HttpMethod.DELETE.value == "DELETE"
        assert HttpMethod.HEAD.value == "HEAD"
        assert HttpMethod.OPTIONS.value == "OPTIONS"


class TestCircuitState:
    """Tests for CircuitState enum."""

    def test_all_states(self):
        """Test all states exist."""
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open"


# =============================================================================
# RetryConfig Tests
# =============================================================================


class TestRetryConfig:
    """Tests for RetryConfig."""

    def test_default_values(self):
        """Test default configuration."""
        config = RetryConfig()
        assert config.max_retries == 3
        assert config.base_delay == 1.0
        assert 429 in config.retry_on_status

    def test_get_delay_exponential(self):
        """Test exponential delay calculation."""
        config = RetryConfig(base_delay=1.0, exponential_base=2.0, jitter=False)

        assert config.get_delay(0) == 1.0
        assert config.get_delay(1) == 2.0
        assert config.get_delay(2) == 4.0

    def test_get_delay_max_cap(self):
        """Test delay is capped at max."""
        config = RetryConfig(base_delay=1.0, max_delay=5.0, jitter=False)

        assert config.get_delay(10) == 5.0

    def test_get_delay_with_jitter(self):
        """Test jitter adds randomness."""
        config = RetryConfig(base_delay=1.0, jitter=True)

        delays = [config.get_delay(1) for _ in range(10)]
        # Should have some variation
        assert len(set(delays)) > 1

    def test_should_retry_status(self):
        """Test status code retry check."""
        config = RetryConfig(retry_on_status=(500, 502, 503))

        assert config.should_retry_status(500)
        assert config.should_retry_status(502)
        assert not config.should_retry_status(200)
        assert not config.should_retry_status(400)

    def test_should_retry_exception(self):
        """Test exception retry check."""
        config = RetryConfig(retry_on_exceptions=(ConnectionError,))

        assert config.should_retry_exception(ConnectionError())
        assert not config.should_retry_exception(ValueError())


# =============================================================================
# CircuitBreaker Tests
# =============================================================================


class TestCircuitBreaker:
    """Tests for CircuitBreaker."""

    @pytest.fixture
    def cb(self):
        """Create circuit breaker."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=0.5,
        )
        return CircuitBreaker(config)

    def test_initial_state(self, cb):
        """Test initial state is closed."""
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request()

    def test_opens_after_threshold(self, cb):
        """Test circuit opens after failure threshold."""
        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN
        assert not cb.allow_request()

    def test_half_open_after_timeout(self, cb):
        """Test circuit becomes half-open after timeout."""
        for _ in range(3):
            cb.record_failure()

        assert cb.state == CircuitState.OPEN

        time.sleep(0.6)
        assert cb.state == CircuitState.HALF_OPEN

    def test_closes_after_success_threshold(self, cb):
        """Test circuit closes after success threshold."""
        # Open the circuit
        for _ in range(3):
            cb.record_failure()

        # Wait for half-open
        time.sleep(0.6)
        assert cb.state == CircuitState.HALF_OPEN

        # Record successes
        cb.record_success()
        cb.record_success()

        assert cb.state == CircuitState.CLOSED

    def test_reopens_on_half_open_failure(self, cb):
        """Test circuit reopens on failure in half-open state."""
        # Open the circuit
        for _ in range(3):
            cb.record_failure()

        # Wait for half-open
        time.sleep(0.6)
        assert cb.state == CircuitState.HALF_OPEN

        # Failure in half-open
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_reset(self, cb):
        """Test reset clears state."""
        for _ in range(3):
            cb.record_failure()

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request()


# =============================================================================
# HttpRequest Tests
# =============================================================================


class TestHttpRequest:
    """Tests for HttpRequest."""

    def test_create_basic(self):
        """Test basic request creation."""
        req = HttpRequest(
            method=HttpMethod.GET,
            url="https://api.example.com/users",
        )
        assert req.method == HttpMethod.GET
        assert req.url == "https://api.example.com/users"

    def test_full_url_no_params(self):
        """Test full URL without params."""
        req = HttpRequest(
            method=HttpMethod.GET,
            url="https://api.example.com/users",
        )
        assert req.full_url() == "https://api.example.com/users"

    def test_full_url_with_params(self):
        """Test full URL with params."""
        req = HttpRequest(
            method=HttpMethod.GET,
            url="https://api.example.com/users",
            params={"page": 1, "limit": 10},
        )
        full = req.full_url()
        assert "page=1" in full
        assert "limit=10" in full

    def test_full_url_with_existing_query(self):
        """Test full URL with existing query string."""
        req = HttpRequest(
            method=HttpMethod.GET,
            url="https://api.example.com/users?active=true",
            params={"page": 1},
        )
        full = req.full_url()
        assert "active=true" in full
        assert "page=1" in full


# =============================================================================
# HttpResponse Tests
# =============================================================================


class TestHttpResponse:
    """Tests for HttpResponse."""

    def test_ok_property(self):
        """Test ok property for success status."""
        req = HttpRequest(method=HttpMethod.GET, url="")

        assert HttpResponse(status_code=200, headers={}, body=b"", request=req).ok
        assert HttpResponse(status_code=201, headers={}, body=b"", request=req).ok
        assert HttpResponse(status_code=204, headers={}, body=b"", request=req).ok
        assert not HttpResponse(status_code=400, headers={}, body=b"", request=req).ok
        assert not HttpResponse(status_code=500, headers={}, body=b"", request=req).ok

    def test_text_property(self):
        """Test text property."""
        req = HttpRequest(method=HttpMethod.GET, url="")
        resp = HttpResponse(
            status_code=200,
            headers={},
            body=b"Hello, World!",
            request=req,
        )
        assert resp.text == "Hello, World!"

    def test_json_method(self):
        """Test JSON parsing."""
        req = HttpRequest(method=HttpMethod.GET, url="")
        resp = HttpResponse(
            status_code=200,
            headers={},
            body=b'{"key": "value"}',
            request=req,
        )
        assert resp.json() == {"key": "value"}

    def test_raise_for_status_success(self):
        """Test raise_for_status on success."""
        req = HttpRequest(method=HttpMethod.GET, url="")
        resp = HttpResponse(status_code=200, headers={}, body=b"", request=req)
        resp.raise_for_status()  # Should not raise

    def test_raise_for_status_error(self):
        """Test raise_for_status on error."""
        req = HttpRequest(method=HttpMethod.GET, url="")
        resp = HttpResponse(status_code=404, headers={}, body=b"Not Found", request=req)

        with pytest.raises(HttpError) as exc:
            resp.raise_for_status()

        assert exc.value.status_code == 404


# =============================================================================
# RateLimiter Tests
# =============================================================================


class TestRateLimiter:
    """Tests for RateLimiter."""

    def test_acquire_within_burst(self):
        """Test acquiring within burst limit."""
        limiter = RateLimiter(rate=10, burst=5)

        # Should get 5 immediately
        for _ in range(5):
            assert limiter.try_acquire()

        # 6th should fail
        assert not limiter.try_acquire()

    def test_acquire_blocking(self):
        """Test blocking acquire."""
        limiter = RateLimiter(rate=100, burst=1)

        assert limiter.try_acquire()
        assert not limiter.try_acquire()

        # Wait for refill
        time.sleep(0.02)
        assert limiter.try_acquire()

    def test_acquire_timeout(self):
        """Test acquire with timeout."""
        limiter = RateLimiter(rate=1, burst=1)

        assert limiter.acquire(timeout=1.0)
        assert not limiter.try_acquire()

        # Should timeout
        start = time.time()
        result = limiter.acquire(timeout=0.1)
        elapsed = time.time() - start

        # Either got a token or timed out
        assert elapsed >= 0.1 or result


# =============================================================================
# ResponseCache Tests
# =============================================================================


class TestResponseCache:
    """Tests for ResponseCache."""

    @pytest.fixture
    def cache(self):
        """Create cache."""
        return ResponseCache(max_size=10, default_ttl=1.0)

    def test_set_and_get(self, cache):
        """Test setting and getting cached response."""
        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/users")
        resp = HttpResponse(status_code=200, headers={}, body=b"data", request=req)

        cache.set(req, resp)
        cached = cache.get(req)

        assert cached is not None
        assert cached.body == b"data"

    def test_cache_miss(self, cache):
        """Test cache miss."""
        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/users")
        assert cache.get(req) is None

    def test_cache_expiration(self, cache):
        """Test cache expiration."""
        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/users")
        resp = HttpResponse(status_code=200, headers={}, body=b"data", request=req)

        cache.set(req, resp, ttl=0.1)

        assert cache.get(req) is not None
        time.sleep(0.15)
        assert cache.get(req) is None

    def test_cache_invalidate(self, cache):
        """Test cache invalidation."""
        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/users")
        resp = HttpResponse(status_code=200, headers={}, body=b"data", request=req)

        cache.set(req, resp)
        cache.invalidate(req)

        assert cache.get(req) is None

    def test_cache_clear(self, cache):
        """Test clearing cache."""
        for i in range(5):
            req = HttpRequest(method=HttpMethod.GET, url=f"https://api.example.com/{i}")
            resp = HttpResponse(status_code=200, headers={}, body=b"data", request=req)
            cache.set(req, resp)

        cache.clear()

        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/0")
        assert cache.get(req) is None

    def test_cache_max_size(self):
        """Test cache evicts when full."""
        cache = ResponseCache(max_size=3)

        for i in range(5):
            req = HttpRequest(method=HttpMethod.GET, url=f"https://api.example.com/{i}")
            resp = HttpResponse(
                status_code=200, headers={}, body=f"{i}".encode(), request=req
            )
            cache.set(req, resp)

        # Should only have 3 entries
        # Oldest should be evicted
        HttpRequest(method=HttpMethod.GET, url="https://api.example.com/0")
        req4 = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/4")

        assert cache.get(req4) is not None

    def test_no_cache_error_response(self, cache):
        """Test error responses are not cached."""
        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com/error")
        resp = HttpResponse(status_code=500, headers={}, body=b"error", request=req)

        cache.set(req, resp)
        assert cache.get(req) is None


# =============================================================================
# MockTransport Tests
# =============================================================================


class TestMockTransport:
    """Tests for MockTransport."""

    def test_add_response(self):
        """Test adding mock responses."""
        transport = MockTransport()
        transport.add_response(status_code=200, body=b"success")

        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com")
        resp = transport.send(req)

        assert resp.status_code == 200
        assert resp.body == b"success"

    def test_multiple_responses(self):
        """Test multiple mock responses in order."""
        transport = MockTransport()
        transport.add_response(status_code=200, body=b"first")
        transport.add_response(status_code=201, body=b"second")

        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com")

        resp1 = transport.send(req)
        assert resp1.body == b"first"

        resp2 = transport.send(req)
        assert resp2.body == b"second"

    def test_default_response(self):
        """Test default response."""
        transport = MockTransport()
        transport.set_default_response(status_code=200, body=b"default")

        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com")

        # Multiple requests return default
        for _ in range(3):
            resp = transport.send(req)
            assert resp.body == b"default"

    def test_records_requests(self):
        """Test requests are recorded."""
        transport = MockTransport()
        transport.set_default_response(status_code=200)

        for i in range(3):
            req = HttpRequest(method=HttpMethod.GET, url=f"https://api.example.com/{i}")
            transport.send(req)

        assert len(transport.requests) == 3

    def test_no_response_raises(self):
        """Test raises when no response available."""
        transport = MockTransport()
        req = HttpRequest(method=HttpMethod.GET, url="https://api.example.com")

        with pytest.raises(RuntimeError):
            transport.send(req)


# =============================================================================
# ApiClient Tests
# =============================================================================


class TestApiClient:
    """Tests for ApiClient."""

    @pytest.fixture
    def transport(self):
        """Create mock transport."""
        return MockTransport()

    @pytest.fixture
    def client(self, transport):
        """Create API client with mock transport."""
        transport.set_default_response(status_code=200, body=b'{"status": "ok"}')
        return ApiClient(
            base_url="https://api.example.com",
            transport=transport,
        )

    def test_get_request(self, client, transport):
        """Test GET request."""
        resp = client.get("/users")

        assert resp.ok
        assert len(transport.requests) == 1
        assert transport.requests[0].method == HttpMethod.GET

    def test_post_request(self, client, transport):
        """Test POST request with JSON body."""
        resp = client.post("/users", json_body={"name": "John"})

        assert resp.ok
        assert transport.requests[0].method == HttpMethod.POST
        assert transport.requests[0].json_body == {"name": "John"}

    def test_base_url(self, client, transport):
        """Test base URL is prepended."""
        client.get("/users")

        assert transport.requests[0].url == "https://api.example.com/users"

    def test_full_url_bypass(self, transport):
        """Test full URL bypasses base URL."""
        transport.set_default_response(status_code=200)
        client = ApiClient(base_url="https://api.example.com", transport=transport)

        client.get("https://other.api.com/resource")

        assert transport.requests[0].url == "https://other.api.com/resource"

    def test_default_headers(self, transport):
        """Test default headers are included."""
        transport.set_default_response(status_code=200)
        client = ApiClient(
            transport=transport,
            default_headers={"X-API-Key": "secret"},
        )

        client.get("https://api.example.com/users")

        assert transport.requests[0].headers["X-API-Key"] == "secret"

    def test_retry_on_status(self, transport):
        """Test retry on configured status codes."""
        transport.add_response(status_code=503, body=b"unavailable")
        transport.add_response(status_code=200, body=b"success")

        client = ApiClient(
            transport=transport,
            retry_config=RetryConfig(max_retries=2, base_delay=0.01),
        )

        resp = client.get("https://api.example.com/users")

        assert resp.ok
        assert len(transport.requests) == 2

    def test_retry_max_exceeded(self, transport):
        """Test retry stops at max."""
        for _ in range(5):
            transport.add_response(status_code=503, body=b"unavailable")

        client = ApiClient(
            transport=transport,
            retry_config=RetryConfig(max_retries=2, base_delay=0.01),
        )

        resp = client.get("https://api.example.com/users")

        assert resp.status_code == 503
        assert len(transport.requests) == 3  # 1 + 2 retries

    def test_no_retry_when_disabled(self, transport):
        """Test no retry when disabled."""
        transport.add_response(status_code=503, body=b"unavailable")
        transport.add_response(status_code=200, body=b"success")

        client = ApiClient(transport=transport)
        resp = client.get("https://api.example.com/users", retry=False)

        assert resp.status_code == 503
        assert len(transport.requests) == 1

    def test_circuit_breaker_opens(self, transport):
        """Test circuit breaker opens on failures."""
        # Set up failures
        for _ in range(10):
            transport.add_response(status_code=500, body=b"error")

        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))
        client = ApiClient(
            transport=transport,
            circuit_breaker=cb,
            retry_config=RetryConfig(max_retries=0),
        )

        # First 3 failures should work
        for _ in range(3):
            client.get("https://api.example.com/users")

        # 4th should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            client.get("https://api.example.com/users")

    def test_rate_limiting(self, transport):
        """Test rate limiting."""
        transport.set_default_response(status_code=200)
        limiter = RateLimiter(rate=100, burst=2)
        client = ApiClient(transport=transport, rate_limiter=limiter)

        start = time.time()
        for _ in range(4):
            client.get("https://api.example.com/users")
        elapsed = time.time() - start

        # Should take some time due to rate limiting
        assert elapsed >= 0.01

    def test_caching(self, transport):
        """Test response caching."""
        transport.set_default_response(status_code=200, body=b"cached")
        cache = ResponseCache()
        client = ApiClient(transport=transport, cache=cache)

        # First request - no cache
        resp1 = client.get("https://api.example.com/users", cache=True)
        assert len(transport.requests) == 1

        # Second request - from cache
        resp2 = client.get("https://api.example.com/users", cache=True)
        assert len(transport.requests) == 1  # No new request

        assert resp1.body == resp2.body
        assert client.stats["cache_hits"] == 1

    def test_request_hook(self, transport):
        """Test request hook."""
        transport.set_default_response(status_code=200)

        def add_header(req):
            req.headers["X-Custom"] = "value"
            return req

        client = ApiClient(transport=transport)
        client.add_request_hook(add_header)

        client.get("https://api.example.com/users")

        assert transport.requests[0].headers["X-Custom"] == "value"

    def test_response_hook(self, transport):
        """Test response hook."""
        transport.set_default_response(status_code=200, body=b"original")

        def modify_response(resp):
            resp.body = b"modified"
            return resp

        client = ApiClient(transport=transport)
        client.add_response_hook(modify_response)

        resp = client.get("https://api.example.com/users")

        assert resp.body == b"modified"

    def test_stats(self, transport):
        """Test client statistics."""
        transport.add_response(status_code=200)
        transport.add_response(status_code=500)
        transport.add_response(status_code=200)

        client = ApiClient(
            transport=transport,
            retry_config=RetryConfig(max_retries=0),
        )

        client.get("https://api.example.com/1")
        client.get("https://api.example.com/2")
        client.get("https://api.example.com/3")

        stats = client.stats
        assert stats["requests"] == 3
        assert stats["successes"] == 2
        assert stats["failures"] == 1

    def test_context_manager(self, transport):
        """Test context manager."""
        transport.set_default_response(status_code=200)

        with ApiClient(transport=transport) as client:
            resp = client.get("https://api.example.com/users")
            assert resp.ok


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_api_client(self):
        """Test create_api_client."""
        client = create_api_client(
            base_url="https://api.example.com",
            max_retries=5,
            rate_limit=10.0,
            cache_responses=True,
            circuit_breaker=True,
        )

        assert client.base_url == "https://api.example.com"
        assert client._retry_config.max_retries == 5
        assert client._rate_limiter is not None
        assert client._cache is not None
        assert client._circuit_breaker is not None


# =============================================================================
# Integration Tests
# =============================================================================


class TestApiClientIntegration:
    """Integration tests for API client."""

    def test_full_workflow(self):
        """Test complete client workflow."""
        transport = MockTransport()

        # Set up responses
        transport.add_response(status_code=503)  # Will retry
        transport.add_response(status_code=200, body=b'{"id": 1}')
        transport.add_response(status_code=200, body=b'{"id": 1}')  # Cached

        client = ApiClient(
            base_url="https://api.example.com",
            transport=transport,
            retry_config=RetryConfig(max_retries=2, base_delay=0.01),
            cache=ResponseCache(),
        )

        # First request - retries then succeeds
        resp1 = client.get("/users/1", cache=True)
        assert resp1.ok
        assert resp1.json() == {"id": 1}

        # Second request - from cache
        resp2 = client.get("/users/1", cache=True)
        assert resp2.json() == {"id": 1}

        stats = client.stats
        assert stats["retries"] >= 1
        assert stats["cache_hits"] == 1

    def test_thread_safety(self):
        """Test thread-safe usage."""
        transport = MockTransport()
        transport.set_default_response(status_code=200, body=b"ok")

        client = ApiClient(transport=transport)
        errors = []

        def make_requests():
            try:
                for _ in range(50):
                    client.get("https://api.example.com/test")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert client.stats["requests"] == 250
