"""
API Client - HTTP client with retry, circuit breaker, and connection pooling.

Provides a robust HTTP client for making API requests.
"""

import hashlib
import json
import logging
import random
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Callable,
    Type,
)
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


class HttpMethod(Enum):
    """HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    retry_on_exceptions: tuple[Type[Exception], ...] = (
        ConnectionError,
        TimeoutError,
    )

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        delay = min(
            self.base_delay * (self.exponential_base**attempt),
            self.max_delay,
        )
        if self.jitter:
            delay = delay * (0.5 + random.random())
        return delay

    def should_retry_status(self, status_code: int) -> bool:
        """Check if status code should trigger retry."""
        return status_code in self.retry_on_status

    def should_retry_exception(self, exc: Exception) -> bool:
        """Check if exception should trigger retry."""
        return isinstance(exc, self.retry_on_exceptions)


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5
    success_threshold: int = 2
    timeout: float = 30.0
    half_open_max_calls: int = 3


class CircuitBreaker:
    """
    Circuit breaker for preventing cascading failures.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failing, requests are blocked
    - HALF_OPEN: Testing if service recovered
    """

    def __init__(self, config: CircuitBreakerConfig | None = None):
        """Initialize circuit breaker."""
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._half_open_calls = 0
        self._lock = threading.RLock()

    @property
    def state(self) -> CircuitState:
        """Get current state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                # Check if timeout has passed
                if self._last_failure_time:
                    elapsed = time.time() - self._last_failure_time
                    if elapsed >= self.config.timeout:
                        self._state = CircuitState.HALF_OPEN
                        self._half_open_calls = 0
                        self._success_count = 0
            return self._state

    def record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN

    def allow_request(self) -> bool:
        """Check if request should be allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.OPEN:
            return False
        if state == CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
        return False

    def reset(self) -> None:
        """Reset circuit breaker."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None
            self._half_open_calls = 0


class CircuitOpenError(Exception):
    """Raised when circuit is open."""

    pass


@dataclass
class HttpRequest:
    """HTTP request representation."""

    method: HttpMethod
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    body: Any | None = None
    json_body: Any | None = None
    timeout: float = 30.0
    auth: tuple[str, str] | None = None

    def full_url(self) -> str:
        """Get full URL with query parameters."""
        if not self.params:
            return self.url
        separator = "&" if "?" in self.url else "?"
        return f"{self.url}{separator}{urlencode(self.params)}"


@dataclass
class HttpResponse:
    """HTTP response representation."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    request: HttpRequest
    elapsed_seconds: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Check if response was successful."""
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        """Get response body as text."""
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Parse response body as JSON."""
        return json.loads(self.body)

    def raise_for_status(self) -> None:
        """Raise exception if status indicates error."""
        if not self.ok:
            raise HttpError(
                f"HTTP {self.status_code}: {self.text[:200]}",
                response=self,
            )


class HttpError(Exception):
    """HTTP error with response details."""

    def __init__(self, message: str, response: HttpResponse | None = None):
        """Initialize HTTP error."""
        super().__init__(message)
        self.response = response
        self.status_code = response.status_code if response else None


class RateLimiter:
    """
    Token bucket rate limiter.
    """

    def __init__(
        self,
        rate: float = 10.0,
        burst: int = 10,
    ):
        """
        Initialize rate limiter.

        Args:
            rate: Requests per second
            burst: Maximum burst size
        """
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_update = time.time()
        self._lock = threading.RLock()

    def acquire(self, timeout: float | None = None) -> bool:
        """
        Acquire a token, blocking if necessary.

        Args:
            timeout: Maximum wait time (None = wait forever)

        Returns:
            True if token acquired, False if timeout
        """
        start = time.time()

        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self._last_update
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                self._last_update = now

                if self._tokens >= 1:
                    self._tokens -= 1
                    return True

            # Check timeout
            if timeout is not None:
                if time.time() - start >= timeout:
                    return False

            # Wait for token refill
            time.sleep(1 / self.rate)

    def try_acquire(self) -> bool:
        """Try to acquire a token without blocking."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_update = now

            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


class ResponseCache:
    """
    Simple in-memory response cache.
    """

    def __init__(self, max_size: int = 1000, default_ttl: float = 300):
        """
        Initialize cache.

        Args:
            max_size: Maximum cache entries
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: dict[str, tuple[HttpResponse, float]] = {}
        self._lock = threading.RLock()

    def _make_key(self, request: HttpRequest) -> str:
        """Create cache key from request."""
        key_parts = [
            request.method.value,
            request.full_url(),
            json.dumps(dict(sorted(request.headers.items())), sort_keys=True),
        ]
        return hashlib.md5("".join(key_parts).encode()).hexdigest()

    def get(self, request: HttpRequest) -> HttpResponse | None:
        """Get cached response."""
        key = self._make_key(request)
        with self._lock:
            if key in self._cache:
                response, expires_at = self._cache[key]
                if time.time() < expires_at:
                    return response
                del self._cache[key]
        return None

    def set(
        self,
        request: HttpRequest,
        response: HttpResponse,
        ttl: float | None = None,
    ) -> None:
        """Cache a response."""
        if not response.ok:
            return

        key = self._make_key(request)
        expires_at = time.time() + (ttl or self.default_ttl)

        with self._lock:
            # Evict if over size
            if len(self._cache) >= self.max_size:
                # Remove oldest
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]

            self._cache[key] = (response, expires_at)

    def invalidate(self, request: HttpRequest) -> None:
        """Invalidate cached response."""
        key = self._make_key(request)
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached responses."""
        with self._lock:
            self._cache.clear()


class HttpTransport(ABC):
    """Abstract base class for HTTP transports."""

    @abstractmethod
    def send(self, request: HttpRequest) -> HttpResponse:
        """Send an HTTP request."""
        pass

    def close(self) -> None:
        """Close the transport."""
        pass


class UrllibTransport(HttpTransport):
    """HTTP transport using urllib."""

    def send(self, request: HttpRequest) -> HttpResponse:
        """Send request using urllib."""
        import urllib.request
        import urllib.error

        start_time = time.time()

        # Build request
        url = request.full_url()
        data = None

        if request.json_body is not None:
            data = json.dumps(request.json_body).encode()
            request.headers.setdefault("Content-Type", "application/json")
        elif request.body is not None:
            if isinstance(request.body, str):
                data = request.body.encode()
            else:
                data = request.body

        req = urllib.request.Request(
            url,
            data=data,
            headers=request.headers,
            method=request.method.value,
        )

        # Add auth
        if request.auth:
            import base64

            credentials = f"{request.auth[0]}:{request.auth[1]}"
            encoded = base64.b64encode(credentials.encode()).decode()
            req.add_header("Authorization", f"Basic {encoded}")

        try:
            with urllib.request.urlopen(req, timeout=request.timeout) as resp:
                body = resp.read()
                headers = dict(resp.headers)
                status = resp.status

                return HttpResponse(
                    status_code=status,
                    headers=headers,
                    body=body,
                    request=request,
                    elapsed_seconds=time.time() - start_time,
                )

        except urllib.error.HTTPError as e:
            body = e.read() if e.fp else b""
            headers = dict(e.headers) if e.headers else {}

            return HttpResponse(
                status_code=e.code,
                headers=headers,
                body=body,
                request=request,
                elapsed_seconds=time.time() - start_time,
                error=str(e),
            )

        except urllib.error.URLError as e:
            raise ConnectionError(f"Connection failed: {e.reason}")


class MockTransport(HttpTransport):
    """Mock transport for testing."""

    def __init__(self):
        """Initialize mock transport."""
        self._responses: list[HttpResponse] = []
        self._requests: list[HttpRequest] = []
        self._default_response: HttpResponse | None = None

    def add_response(
        self,
        status_code: int = 200,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Add a mock response."""
        self._responses.append(
            HttpResponse(
                status_code=status_code,
                body=body,
                headers=headers or {},
                request=HttpRequest(method=HttpMethod.GET, url=""),
            )
        )

    def set_default_response(
        self,
        status_code: int = 200,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Set default response when queue is empty."""
        self._default_response = HttpResponse(
            status_code=status_code,
            body=body,
            headers=headers or {},
            request=HttpRequest(method=HttpMethod.GET, url=""),
        )

    def send(self, request: HttpRequest) -> HttpResponse:
        """Send mock request."""
        self._requests.append(request)

        if self._responses:
            response = self._responses.pop(0)
            response.request = request
            return response

        if self._default_response:
            response = HttpResponse(
                status_code=self._default_response.status_code,
                body=self._default_response.body,
                headers=self._default_response.headers.copy(),
                request=request,
            )
            return response

        raise RuntimeError("No mock response available")

    @property
    def requests(self) -> list[HttpRequest]:
        """Get recorded requests."""
        return self._requests.copy()

    def clear(self) -> None:
        """Clear recorded requests and responses."""
        self._requests.clear()
        self._responses.clear()


class ApiClient:
    """
    HTTP API client with retry, circuit breaker, rate limiting, and caching.

    Features:
    - Automatic retries with exponential backoff
    - Circuit breaker for failure handling
    - Rate limiting
    - Response caching
    - Request/response hooks
    - Base URL support
    - Default headers
    """

    def __init__(
        self,
        base_url: str = "",
        transport: HttpTransport | None = None,
        retry_config: RetryConfig | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        rate_limiter: RateLimiter | None = None,
        cache: ResponseCache | None = None,
        default_headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        auth: tuple[str, str] | None = None,
    ):
        """
        Initialize API client.

        Args:
            base_url: Base URL for all requests
            transport: HTTP transport (default: UrllibTransport)
            retry_config: Retry configuration
            circuit_breaker: Circuit breaker instance
            rate_limiter: Rate limiter instance
            cache: Response cache
            default_headers: Headers to include in all requests
            timeout: Default request timeout
            auth: Default basic auth credentials
        """
        self.base_url = base_url.rstrip("/")
        self._transport = transport or UrllibTransport()
        self._retry_config = retry_config or RetryConfig()
        self._circuit_breaker = circuit_breaker
        self._rate_limiter = rate_limiter
        self._cache = cache
        self._default_headers = default_headers or {}
        self._default_timeout = timeout
        self._default_auth = auth

        # Hooks
        self._request_hooks: list[Callable[[HttpRequest], HttpRequest]] = []
        self._response_hooks: list[Callable[[HttpResponse], HttpResponse]] = []

        # Statistics
        self._stats = {
            "requests": 0,
            "successes": 0,
            "failures": 0,
            "retries": 0,
            "cache_hits": 0,
            "circuit_breaks": 0,
        }
        self._lock = threading.RLock()

    def add_request_hook(self, hook: Callable[[HttpRequest], HttpRequest]) -> None:
        """Add a request hook."""
        self._request_hooks.append(hook)

    def add_response_hook(self, hook: Callable[[HttpResponse], HttpResponse]) -> None:
        """Add a response hook."""
        self._response_hooks.append(hook)

    def _build_url(self, path: str) -> str:
        """Build full URL from path."""
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def _build_request(
        self,
        method: HttpMethod,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        body: Any | None = None,
        json_body: Any | None = None,
        timeout: float | None = None,
        auth: tuple[str, str] | None = None,
    ) -> HttpRequest:
        """Build an HTTP request."""
        merged_headers = {**self._default_headers}
        if headers:
            merged_headers.update(headers)

        return HttpRequest(
            method=method,
            url=self._build_url(path),
            headers=merged_headers,
            params=params or {},
            body=body,
            json_body=json_body,
            timeout=timeout or self._default_timeout,
            auth=auth or self._default_auth,
        )

    def request(
        self,
        method: HttpMethod,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        body: Any | None = None,
        json_body: Any | None = None,
        timeout: float | None = None,
        auth: tuple[str, str] | None = None,
        retry: bool = True,
        cache: bool = False,
        cache_ttl: float | None = None,
    ) -> HttpResponse:
        """
        Make an HTTP request.

        Args:
            method: HTTP method
            path: URL path
            headers: Request headers
            params: Query parameters
            body: Request body
            json_body: JSON request body
            timeout: Request timeout
            auth: Basic auth credentials
            retry: Whether to retry on failure
            cache: Whether to cache response
            cache_ttl: Cache time-to-live

        Returns:
            HTTP response
        """
        request = self._build_request(
            method, path, headers, params, body, json_body, timeout, auth
        )

        # Apply request hooks
        for hook in self._request_hooks:
            request = hook(request)

        # Check cache
        if cache and self._cache and method == HttpMethod.GET:
            cached = self._cache.get(request)
            if cached:
                with self._lock:
                    self._stats["cache_hits"] += 1
                return cached

        # Check circuit breaker
        if self._circuit_breaker and not self._circuit_breaker.allow_request():
            with self._lock:
                self._stats["circuit_breaks"] += 1
            raise CircuitOpenError("Circuit breaker is open")

        # Rate limiting
        if self._rate_limiter:
            self._rate_limiter.acquire()

        # Execute with retry
        response = self._execute_with_retry(request, retry)

        # Cache response
        if cache and self._cache and method == HttpMethod.GET and response.ok:
            self._cache.set(request, response, cache_ttl)

        # Apply response hooks
        for hook in self._response_hooks:
            response = hook(response)

        return response

    def _execute_with_retry(self, request: HttpRequest, retry: bool) -> HttpResponse:
        """Execute request with retry logic."""
        last_exception: Exception | None = None
        last_response: HttpResponse | None = None

        max_attempts = self._retry_config.max_retries + 1 if retry else 1

        for attempt in range(max_attempts):
            with self._lock:
                self._stats["requests"] += 1
                if attempt > 0:
                    self._stats["retries"] += 1

            try:
                response = self._transport.send(request)
                last_response = response

                # Check if should retry based on status
                if retry and attempt < max_attempts - 1:
                    if self._retry_config.should_retry_status(response.status_code):
                        delay = self._retry_config.get_delay(attempt)
                        logger.warning(
                            f"Retrying request after {delay:.2f}s "
                            f"(status {response.status_code})"
                        )
                        time.sleep(delay)
                        continue

                # Record success/failure
                if self._circuit_breaker:
                    if response.ok:
                        self._circuit_breaker.record_success()
                    else:
                        self._circuit_breaker.record_failure()

                with self._lock:
                    if response.ok:
                        self._stats["successes"] += 1
                    else:
                        self._stats["failures"] += 1

                return response

            except (OSError, RuntimeError, ConnectionError, TimeoutError, HttpError) as e:
                last_exception = e

                if self._circuit_breaker:
                    self._circuit_breaker.record_failure()

                if retry and attempt < max_attempts - 1:
                    if self._retry_config.should_retry_exception(e):
                        delay = self._retry_config.get_delay(attempt)
                        logger.warning(f"Retrying request after {delay:.2f}s ({e})")
                        time.sleep(delay)
                        continue

                with self._lock:
                    self._stats["failures"] += 1

                raise

        # Return last response or raise last exception
        if last_response:
            return last_response
        if last_exception:
            raise last_exception
        raise RuntimeError("No response or exception")

    # Convenience methods

    def get(self, path: str, **kwargs) -> HttpResponse:
        """Make a GET request."""
        return self.request(HttpMethod.GET, path, **kwargs)

    def post(self, path: str, **kwargs) -> HttpResponse:
        """Make a POST request."""
        return self.request(HttpMethod.POST, path, **kwargs)

    def put(self, path: str, **kwargs) -> HttpResponse:
        """Make a PUT request."""
        return self.request(HttpMethod.PUT, path, **kwargs)

    def patch(self, path: str, **kwargs) -> HttpResponse:
        """Make a PATCH request."""
        return self.request(HttpMethod.PATCH, path, **kwargs)

    def delete(self, path: str, **kwargs) -> HttpResponse:
        """Make a DELETE request."""
        return self.request(HttpMethod.DELETE, path, **kwargs)

    def head(self, path: str, **kwargs) -> HttpResponse:
        """Make a HEAD request."""
        return self.request(HttpMethod.HEAD, path, **kwargs)

    @property
    def stats(self) -> dict[str, int]:
        """Get client statistics."""
        with self._lock:
            return self._stats.copy()

    def close(self) -> None:
        """Close the client."""
        self._transport.close()

    def __enter__(self) -> "ApiClient":
        """Context manager entry."""
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.close()


# Convenience functions


def create_api_client(
    base_url: str = "",
    timeout: float = 30.0,
    max_retries: int = 3,
    rate_limit: float | None = None,
    cache_responses: bool = False,
    circuit_breaker: bool = False,
) -> ApiClient:
    """
    Create an API client with common configuration.

    Args:
        base_url: Base URL for requests
        timeout: Request timeout
        max_retries: Maximum retry attempts
        rate_limit: Requests per second (None = no limit)
        cache_responses: Whether to cache responses
        circuit_breaker: Whether to use circuit breaker
    """
    retry_config = RetryConfig(max_retries=max_retries)
    rate_limiter = RateLimiter(rate=rate_limit) if rate_limit else None
    cache = ResponseCache() if cache_responses else None
    cb = CircuitBreaker() if circuit_breaker else None

    return ApiClient(
        base_url=base_url,
        retry_config=retry_config,
        rate_limiter=rate_limiter,
        cache=cache,
        circuit_breaker=cb,
        timeout=timeout,
    )


def simple_get(url: str, timeout: float = 30.0) -> HttpResponse:
    """Make a simple GET request."""
    client = ApiClient(timeout=timeout)
    return client.get(url)


def simple_post(
    url: str,
    json_body: Any | None = None,
    timeout: float = 30.0,
) -> HttpResponse:
    """Make a simple POST request."""
    client = ApiClient(timeout=timeout)
    return client.post(url, json_body=json_body)
