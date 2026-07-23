"""Tests for egress blocking during active chain execution.

Ensures that non-local HTTP requests are rejected while active authorization
is in scope, preventing cloud API leakage.
"""

import pytest
import requests

from redops.modules.active.egress import (
    EgressBlockedError,
    _is_local_url,
    block_external_egress,
)


class TestIsLocalUrl:
    """Unit tests for the local-url classifier."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:11434/api/generate",
            "http://127.0.0.1:8000/health",
            "http://[::1]:8080/metrics",
            "http://my-service.local/status",
            "http://0.0.0.0:9000",
        ],
    )
    def test_local_urls_allowed(self, url):
        assert _is_local_url(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.openai.com/v1/chat/completions",
            "https://api.anthropic.com/v1/messages",
            "http://example.com",
            "https://8.8.8.8",
            "https://google.com",
        ],
    )
    def test_non_local_urls_blocked(self, url):
        assert _is_local_url(url) is False


class TestBlockExternalEgress:
    """Integration tests for the egress blocking context manager."""

    def test_allows_local_requests(self):
        """Local requests should succeed while blocking is active."""
        with block_external_egress():
            # We cannot guarantee a local server is running, but we can verify
            # the patch is applied by checking the thread-local flag.
            from redops.modules.active.egress import _is_egress_blocked

            assert _is_egress_blocked() is True

    def test_blocks_external_requests(self):
        """External requests should raise EgressBlockedError."""
        with block_external_egress():
            with pytest.raises(EgressBlockedError, match="Egress blocked"):
                requests.get("https://api.openai.com/v1/models", timeout=1)

    def test_blocks_external_post(self):
        """External POST requests should also raise."""
        with block_external_egress():
            with pytest.raises(EgressBlockedError, match="Egress blocked"):
                requests.post(
                    "https://api.anthropic.com/v1/messages",
                    json={"model": "claude", "messages": []},
                    timeout=1,
                )

    def test_releases_after_context_exit(self):
        """After exiting the context manager, external requests should work again."""
        with block_external_egress():
            pass
        # We do not actually make an external request here to avoid network
        # dependency in tests; instead we verify the thread-local flag is clear.
        from redops.modules.active.egress import _is_egress_blocked

        assert _is_egress_blocked() is False

    def test_nested_context_managers(self):
        """Nested block_external_egress calls should not double-unblock."""
        with block_external_egress():
            with block_external_egress():
                from redops.modules.active.egress import _is_egress_blocked

                assert _is_egress_blocked() is True
                with pytest.raises(EgressBlockedError):
                    requests.get("https://example.com", timeout=1)
            # After inner exit, outer should still block
            assert _is_egress_blocked() is True
            with pytest.raises(EgressBlockedError):
                requests.get("https://example.com", timeout=1)
        # After outer exit, should be fully released
        assert _is_egress_blocked() is False

    def test_allows_localhost_requests_inside_block(self):
        """Requests to localhost should not raise even while blocking is active."""
        with block_external_egress():
            # This will raise ConnectionError because no server is listening,
            # but it should NOT raise EgressBlockedError.
            with pytest.raises(requests.ConnectionError):
                requests.get("http://localhost:59999/health", timeout=1)
