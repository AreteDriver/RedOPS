"""Tests for the active module authorization gate.

Enforces that every module under ``modules/active/`` refuses to execute
without recorded operator consent.
"""

from datetime import datetime, timedelta, timezone

import pytest

from redops.core.context import Context
from redops.modules.active.authorization import (
    ActiveAuthorization,
    assert_active_authorized,
    is_active_authorized,
    record_authorization,
)
from redops.modules.active.exceptions import ActiveAuthorizationError
from redops.modules.active.exploit.cve_check import check_cves
from redops.modules.active.network.arp_scan import discover_hosts
from redops.modules.active.network.port_scan import scan_ports
from redops.modules.active.wireless.deauth import deauth_flood
from redops.modules.active.wireless.evil_twin import start_evil_twin
from redops.modules.active.wireless.monitor import disable_monitor_mode, enable_monitor_mode
from redops.modules.active.wireless.scan import scan_access_points


@pytest.fixture
def authorized_context():
    """A context with a valid active authorization."""
    ctx = Context(target="192.168.99.0/24")
    ctx.authorization = ActiveAuthorization(
        operator="test-operator",
        target_assertion="192.168.99.0/24",
        consent_text="I consent to testing my own lab network.",
    )
    return ctx


@pytest.fixture
def expired_context():
    """A context with an expired active authorization."""
    ctx = Context(target="192.168.99.0/24")
    ctx.authorization = ActiveAuthorization(
        operator="test-operator",
        target_assertion="192.168.99.0/24",
        consent_text="I consent to testing my own lab network.",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    return ctx


class TestActiveAuthorizationModel:
    """Unit tests for ActiveAuthorization data model."""

    def test_is_valid_when_not_expired(self):
        auth = ActiveAuthorization(
            operator="alice",
            target_assertion="10.0.0.0/24",
            consent_text="I consent.",
        )
        assert auth.is_valid() is True
        assert auth.is_expired() is False

    def test_is_expired_when_past_expiry(self):
        auth = ActiveAuthorization(
            operator="alice",
            target_assertion="10.0.0.0/24",
            consent_text="I consent.",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        assert auth.is_expired() is True
        assert auth.is_valid() is False

    def test_authorization_id_is_uuid(self):
        auth = ActiveAuthorization(
            operator="alice",
            target_assertion="10.0.0.0/24",
            consent_text="I consent.",
        )
        assert len(auth.authorization_id) == 36


class TestAssertActiveAuthorized:
    """Tests for the authorization assertion helper."""

    def test_raises_when_no_authorization(self):
        ctx = Context(target="example.com")
        with pytest.raises(ActiveAuthorizationError, match="no operator authorization"):
            assert_active_authorized(ctx)

    def test_raises_when_expired(self, expired_context):
        with pytest.raises(ActiveAuthorizationError, match="expired"):
            assert_active_authorized(expired_context)

    def test_raises_when_malformed_authorization(self):
        ctx = Context(target="example.com")
        ctx.authorization = "not-an-authorization-object"
        with pytest.raises(ActiveAuthorizationError, match="malformed"):
            assert_active_authorized(ctx)

    def test_passes_with_valid_authorization(self, authorized_context):
        # Should not raise
        assert_active_authorized(authorized_context)


class TestIsActiveAuthorized:
    """Tests for the boolean check helper."""

    def test_false_when_no_authorization(self):
        ctx = Context(target="example.com")
        assert is_active_authorized(ctx) is False

    def test_false_when_expired(self, expired_context):
        assert is_active_authorized(expired_context) is False

    def test_true_when_valid(self, authorized_context):
        assert is_active_authorized(authorized_context) is True


class TestRecordAuthorization:
    """Tests for recording authorization in context."""

    def test_records_in_context(self):
        ctx = Context(target="192.168.99.0/24")
        auth = record_authorization(
            ctx,
            operator="alice",
            target_assertion="192.168.99.0/24",
            consent_text="I consent.",
            duration_hours=2,
        )
        assert ctx.authorization == auth
        assert auth.operator == "alice"
        assert auth.is_valid() is True
        # Should expire roughly 2 hours from now
        assert auth.expires_at > datetime.now(timezone.utc) + timedelta(hours=1)

    def test_default_duration_24h(self):
        ctx = Context(target="192.168.99.0/24")
        auth = record_authorization(
            ctx,
            operator="alice",
            target_assertion="192.168.99.0/24",
        )
        assert auth.expires_at > datetime.now(timezone.utc) + timedelta(hours=23)


class TestActiveModuleAuthorizationRefusal:
    """Tests that every active module refuses to run without authorization."""

    def _assert_refused(self, fn, ctx, params=None):
        """Helper: call fn with unauth context and assert it refuses."""
        with pytest.raises(ActiveAuthorizationError, match="refused"):
            fn(ctx, params or {})

    def test_deauth_flood_refuses(self):
        self._assert_refused(deauth_flood, Context(target="00:11:22:33:44:55"))

    def test_start_evil_twin_refuses(self):
        self._assert_refused(start_evil_twin, Context(target="TestAP"))

    def test_scan_access_points_refuses(self):
        self._assert_refused(scan_access_points, Context(target="wlan1mon"))

    def test_enable_monitor_mode_refuses(self):
        self._assert_refused(enable_monitor_mode, Context(target="wlan1"))

    def test_disable_monitor_mode_refuses(self):
        self._assert_refused(disable_monitor_mode, Context(target="wlan1mon"))

    def test_discover_hosts_refuses(self):
        self._assert_refused(discover_hosts, Context(target="192.168.99.0/24"))

    def test_scan_ports_refuses(self):
        self._assert_refused(scan_ports, Context(target="192.168.99.1"))

    def test_check_cves_refuses(self):
        self._assert_refused(check_cves, Context(target="192.168.99.1"))


class TestActiveModuleRunsWithAuthorization:
    """Tests that active modules proceed when authorization is present.

    These tests verify that the authorization check is the only gate; actual
    hardware-dependent behavior is not exercised.
    """

    def test_deauth_flood_returns_early_with_auth(self, authorized_context):
        # Scapy is likely not installed in test env; function returns early
        result = deauth_flood(authorized_context, {"duration": 1})
        assert result.get("deauth_active") is False  # Scapy not available

    def test_evil_twin_returns_early_with_auth(self, authorized_context):
        authorized_context.add("access_points", [])
        result = start_evil_twin(authorized_context)
        # No access points means early return
        assert result is authorized_context

    def test_scan_access_points_returns_with_auth(self, authorized_context):
        # Will fail because airodump-ng is not available, but authorization passes
        authorized_context.add("monitor_interface", "wlan1mon")
        result = scan_access_points(authorized_context, {"duration": 1})
        assert result is authorized_context

    def test_port_scan_no_hosts_with_auth(self, authorized_context):
        # No live_hosts in context → early return
        result = scan_ports(authorized_context)
        assert result is authorized_context

    def test_arp_scan_no_hosts_with_auth(self, authorized_context):
        result = discover_hosts(authorized_context, {"wait": 0})
        assert result is authorized_context

    def test_cve_check_no_results_with_auth(self, authorized_context):
        result = check_cves(authorized_context)
        assert result is authorized_context
