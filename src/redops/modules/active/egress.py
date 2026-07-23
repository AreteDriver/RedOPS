"""Egress enforcement for active chain execution.

Blocks HTTP/HTTPS requests to non-local destinations while active
authorization is in scope. Ensures active modules can only reach
localhost services (e.g. Ollama) and cannot leak data to cloud APIs.
"""

from __future__ import annotations

import ipaddress
import threading
from contextlib import contextmanager
from typing import Any, Callable
from urllib.parse import urlparse

from redops.modules.active.exceptions import EgressBlockedError

# Thread-local flag indicating whether egress blocking is active
_egress_local = threading.local()

# Hostnames and IPs considered "local" — always allowed
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_local_url(url: str) -> bool:
    """Return True if the URL points to a local/loopback destination."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname in _LOCAL_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_loopback
    except ValueError:
        # Not an IP — could be a local domain like my-service.local
        return hostname.endswith(".local") or hostname.endswith(".localhost")


def _is_egress_blocked() -> bool:
    """Return True if egress blocking is currently active in this thread."""
    return getattr(_egress_local, "depth", 0) > 0


def _assert_local_url(url: str) -> None:
    """Raise EgressBlockedError if url is non-local while blocking is active."""
    if _is_egress_blocked() and not _is_local_url(url):
        raise EgressBlockedError(
            f"Egress blocked: active chain execution prevented external request to {url}. "
            "Only localhost/loopback endpoints are permitted during active operations."
        )


# Storage for original references so we can restore precisely
_request_patches: dict[str, Any] = {}  # type: ignore[name-defined]


def _wrap_requests() -> None:
    """Monkey-patch requests to enforce egress policy (idempotent)."""
    try:
        import requests
    except ImportError:
        return

    if _request_patches:
        return  # Already patched

    _request_patches["Session.request"] = requests.Session.request

    def _patched_request(
        self,
        method: str,
        url: str,
        *args,
        **kwargs,
    ):
        _assert_local_url(url)
        return _request_patches["Session.request"](self, method, url, *args, **kwargs)

    requests.Session.request = _patched_request  # type: ignore[method-assign]

    _request_patches["get"] = requests.get
    _request_patches["post"] = requests.post

    def _patched_get(url, **kwargs):
        _assert_local_url(url)
        return _request_patches["get"](url, **kwargs)

    def _patched_post(url, **kwargs):
        _assert_local_url(url)
        return _request_patches["post"](url, **kwargs)

    requests.get = _patched_get  # type: ignore[method-assign]
    requests.post = _patched_post  # type: ignore[method-assign]


def _unwrap_requests() -> None:
    """Remove monkey-patches from requests."""
    global _request_patches
    try:
        import requests
    except ImportError:
        return

    if not _request_patches:
        return

    requests.Session.request = _request_patches["Session.request"]  # type: ignore[method-assign]
    requests.get = _request_patches["get"]  # type: ignore[method-assign]
    requests.post = _request_patches["post"]  # type: ignore[method-assign]
    _request_patches.clear()


@contextmanager
def block_external_egress():
    """Context manager that blocks external HTTP egress for the active chain.

    Supports nested usage via a thread-local reference count.

    Usage::

        with block_external_egress():
            # Any non-local requests here will raise EgressBlockedError
            requests.post("http://localhost:11434/api/generate")  # OK
            requests.get("https://api.openai.com/v1/chat")       # Raises

    Yields:
        None

    Raises:
        EgressBlockedError: If a non-local HTTP request is attempted.
    """
    # Track nesting depth per thread
    depth = getattr(_egress_local, "depth", 0)
    if depth == 0:
        _wrap_requests()
    _egress_local.depth = depth + 1
    try:
        yield
    finally:
        _egress_local.depth = max(0, getattr(_egress_local, "depth", 1) - 1)
        if getattr(_egress_local, "depth", 0) == 0:
            _unwrap_requests()
