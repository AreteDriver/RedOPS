"""
API middleware for RedOPS.

Provides request logging, rate limiting, and other cross-cutting concerns.
"""

import logging
import time
import uuid
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all API requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log details."""
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id

        start_time = time.time()

        # Log request
        logger.info(
            f"[{request_id}] {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )

        response = await call_next(request)

        # Calculate duration
        duration = (time.time() - start_time) * 1000

        # Log response
        logger.info(f"[{request_id}] {response.status_code} in {duration:.2f}ms")

        # Add headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration:.2f}ms"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit API requests."""

    def __init__(
        self,
        app,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self._minute_counts: dict = defaultdict(list)
        self._hour_counts: dict = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Check rate limits before processing request."""
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean old entries
        self._minute_counts[client_ip] = [
            t for t in self._minute_counts[client_ip] if now - t < 60
        ]
        self._hour_counts[client_ip] = [
            t for t in self._hour_counts[client_ip] if now - t < 3600
        ]

        # Check limits
        if len(self._minute_counts[client_ip]) >= self.requests_per_minute:
            return Response(
                content='{"error": "rate_limit_exceeded", "message": "Too many requests per minute"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )

        if len(self._hour_counts[client_ip]) >= self.requests_per_hour:
            return Response(
                content='{"error": "rate_limit_exceeded", "message": "Too many requests per hour"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": "3600",
                    "X-RateLimit-Limit": str(self.requests_per_hour),
                    "X-RateLimit-Remaining": "0",
                },
            )

        # Record request
        self._minute_counts[client_ip].append(now)
        self._hour_counts[client_ip].append(now)

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            self.requests_per_minute - len(self._minute_counts[client_ip])
        )

        return response
