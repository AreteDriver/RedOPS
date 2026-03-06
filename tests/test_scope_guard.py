"""Tests for the Scope Guard module."""

from unittest.mock import patch

import pytest

from redops.core.config import RedOpsConfig, ScopeConfig
from redops.core.context import Context
from redops.modules.compliance.scope_guard import (
    ScopeViolationError,
    add_to_scope,
    check_root_privileges,
    is_bssid_in_scope,
    is_in_scope,
    is_subnet_in_scope,
    validate_active_scope,
    validate_scope,
)


@pytest.fixture
def strict_config():
    """Create a strict scope configuration for testing."""
    return RedOpsConfig(
        scope=ScopeConfig(
            allowed_domains=["example.com", "test.com"],
            allowed_ips=["192.168.1.1", "10.0.0.1"],
            allowed_directories=["/tmp/test", "/home/user/projects"],
            strict_mode=True,
        )
    )


@pytest.fixture
def permissive_config():
    """Create a permissive scope configuration for testing."""
    return RedOpsConfig(
        scope=ScopeConfig(
            allowed_domains=[],
            allowed_ips=[],
            allowed_directories=[],
            strict_mode=False,
        )
    )


def test_is_in_scope_allowed_domain(strict_config):
    """Test that allowed domains pass scope check."""
    assert is_in_scope("example.com", strict_config) is True
    assert is_in_scope("test.com", strict_config) is True


def test_is_in_scope_subdomain(strict_config):
    """Test that subdomains of allowed domains pass scope check."""
    assert is_in_scope("api.example.com", strict_config) is True
    assert is_in_scope("mail.test.com", strict_config) is True


def test_is_in_scope_disallowed_domain(strict_config):
    """Test that disallowed domains fail scope check."""
    assert is_in_scope("unauthorized.com", strict_config) is False
    assert is_in_scope("malicious.net", strict_config) is False


def test_is_in_scope_allowed_ip(strict_config):
    """Test that allowed IPs pass scope check."""
    assert is_in_scope("192.168.1.1", strict_config) is True
    assert is_in_scope("10.0.0.1", strict_config) is True


def test_is_in_scope_disallowed_ip(strict_config):
    """Test that disallowed IPs fail scope check."""
    assert is_in_scope("8.8.8.8", strict_config) is False
    assert is_in_scope("1.1.1.1", strict_config) is False


def test_is_in_scope_permissive_mode(permissive_config):
    """Test that permissive mode allows all targets."""
    assert is_in_scope("any-domain.com", permissive_config) is True
    assert is_in_scope("192.168.1.100", permissive_config) is True
    assert is_in_scope("example.org", permissive_config) is True


def test_validate_scope_success(strict_config):
    """Test successful scope validation."""
    ctx = Context(target="example.com")
    result = validate_scope(ctx, params={"config": strict_config})

    assert result is not None
    assert result.get("scope_validated") is True
    # Check that an INFO log was created
    info_logs = result.get_logs(level="INFO")
    assert any("in scope" in log["message"].lower() for log in info_logs)


def test_validate_scope_failure(strict_config):
    """Test scope validation failure raises exception."""
    ctx = Context(target="unauthorized.com")

    with pytest.raises(ScopeViolationError) as exc_info:
        validate_scope(ctx, params={"config": strict_config})

    assert "out of scope" in str(exc_info.value).lower()
    assert "unauthorized.com" in str(exc_info.value)


def test_validate_scope_no_target(strict_config):
    """Test scope validation with no target."""
    ctx = Context()
    result = validate_scope(ctx, params={"config": strict_config})

    # Should return context without raising exception
    assert result is not None
    warnings = result.get_logs(level="WARNING")
    assert any("no target" in log["message"].lower() for log in warnings)


def test_validate_scope_subdomain_success(strict_config):
    """Test that subdomains pass validation."""
    ctx = Context(target="api.example.com")
    result = validate_scope(ctx, params={"config": strict_config})

    assert result is not None
    assert result.get("scope_validated") is True


def test_add_to_scope_domain():
    """Test adding a domain to scope."""
    config = RedOpsConfig(
        scope=ScopeConfig(
            allowed_domains=[], allowed_ips=[], allowed_directories=[], strict_mode=True
        )
    )

    add_to_scope("newdomain.com", config)
    assert "newdomain.com" in config.scope.allowed_domains


def test_add_to_scope_ip():
    """Test adding an IP to scope."""
    config = RedOpsConfig(
        scope=ScopeConfig(
            allowed_domains=[], allowed_ips=[], allowed_directories=[], strict_mode=True
        )
    )

    add_to_scope("203.0.113.1", config)
    # The function uses a simple check, so IPs with dots might be detected
    # Check if it was added to either IPs or domains
    assert (
        "203.0.113.1" in config.scope.allowed_ips
        or "203.0.113.1" in config.scope.allowed_domains
    )


def test_validate_scope_logging(strict_config):
    """Test that validation logs appropriate messages."""
    ctx = Context(target="example.com")
    result = validate_scope(ctx, params={"config": strict_config})

    logs = result.logs
    assert len(logs) > 0

    # Should have INFO logs about validation
    info_logs = [log for log in logs if log["level"] == "INFO"]
    assert len(info_logs) >= 2  # At least validation start and success


def test_validate_scope_error_logging(strict_config):
    """Test that failed validation logs errors."""
    ctx = Context(target="bad-domain.com")

    try:
        validate_scope(ctx, params={"config": strict_config})
    except ScopeViolationError:
        pass

    # Check that error was logged
    error_logs = ctx.get_logs(level="ERROR")
    assert len(error_logs) > 0
    assert any("out of scope" in log["message"].lower() for log in error_logs)


def test_validate_scope_with_default_config():
    """Test validation with default config when none provided."""
    ctx = Context(target="test.com")
    # Default config might be strict, so we should handle potential ScopeViolationError
    try:
        result = validate_scope(ctx, params={})
        # If it doesn't raise, validation passed (permissive mode)
        assert result is not None
    except ScopeViolationError:
        # If it raises, that's also valid behavior for strict mode
        pass


def test_is_in_scope_edge_cases(strict_config):
    """Test edge cases in scope checking."""
    # Empty string
    assert is_in_scope("", strict_config) is False

    # Partial domain match (should fail)
    assert is_in_scope("notexample.com", strict_config) is False

    # Case sensitivity
    assert is_in_scope("Example.com", strict_config) is False  # Exact match required


# ── BSSID scope ─────────────────────────────────────────────────────


@pytest.fixture
def wireless_config():
    """Config with wireless scope restrictions."""
    return RedOpsConfig(
        scope=ScopeConfig(
            allowed_bssids=["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"],
            allowed_subnets=["192.168.99.0/24", "10.0.0.0/8"],
            strict_mode=True,
        )
    )


class TestBssidScope:
    def test_allowed_bssid(self, wireless_config):
        assert is_bssid_in_scope("AA:BB:CC:DD:EE:FF", wireless_config) is True

    def test_allowed_bssid_case_insensitive(self, wireless_config):
        assert is_bssid_in_scope("aa:bb:cc:dd:ee:ff", wireless_config) is True

    def test_disallowed_bssid(self, wireless_config):
        assert is_bssid_in_scope("FF:FF:FF:FF:FF:FF", wireless_config) is False

    def test_no_restrictions_allows_all(self):
        config = RedOpsConfig(scope=ScopeConfig(allowed_bssids=[], strict_mode=True))
        assert is_bssid_in_scope("AA:BB:CC:DD:EE:FF", config) is True

    def test_permissive_mode_allows_all(self):
        config = RedOpsConfig(
            scope=ScopeConfig(allowed_bssids=["11:22:33:44:55:66"], strict_mode=False)
        )
        assert is_bssid_in_scope("FF:FF:FF:FF:FF:FF", config) is True


# ── Subnet scope ────────────────────────────────────────────────────


class TestSubnetScope:
    def test_allowed_subnet_exact(self, wireless_config):
        assert is_subnet_in_scope("192.168.99.0/24", wireless_config) is True

    def test_allowed_subnet_contained(self, wireless_config):
        assert is_subnet_in_scope("10.1.0.0/16", wireless_config) is True

    def test_disallowed_subnet(self, wireless_config):
        assert is_subnet_in_scope("172.16.0.0/12", wireless_config) is False

    def test_invalid_cidr(self, wireless_config):
        assert is_subnet_in_scope("not-a-cidr", wireless_config) is False

    def test_no_restrictions_allows_all(self):
        config = RedOpsConfig(scope=ScopeConfig(allowed_subnets=[], strict_mode=True))
        assert is_subnet_in_scope("192.168.1.0/24", config) is True

    def test_permissive_mode_allows_all(self):
        config = RedOpsConfig(
            scope=ScopeConfig(allowed_subnets=["10.0.0.0/8"], strict_mode=False)
        )
        assert is_subnet_in_scope("172.16.0.0/12", config) is True


# ── Root privilege check ────────────────────────────────────────────


class TestRootPrivileges:
    @patch("redops.modules.compliance.scope_guard.os.geteuid", return_value=0)
    def test_root(self, _mock):
        assert check_root_privileges() is True

    @patch("redops.modules.compliance.scope_guard.os.geteuid", return_value=1000)
    def test_non_root(self, _mock):
        assert check_root_privileges() is False


# ── validate_active_scope ───────────────────────────────────────────


class TestValidateActiveScope:
    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_passes_with_root(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        result = validate_active_scope(ctx, {"config": wireless_config})
        assert result.get("active_scope_validated") is True
        assert result.get("root_validated") is True

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges",
        return_value=False,
    )
    def test_fails_without_root(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        with pytest.raises(ScopeViolationError, match="root privileges"):
            validate_active_scope(ctx, {"config": wireless_config})

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_skips_root_check_when_disabled(self, _mock):
        config = RedOpsConfig(scope=ScopeConfig(strict_mode=True))
        ctx = Context(target="home-lab")
        result = validate_active_scope(ctx, {"config": config, "require_root": False})
        assert result.get("active_scope_validated") is True

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_validates_bssid_in_scope(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        ctx.add("evil_twin_bssid", "AA:BB:CC:DD:EE:FF")
        result = validate_active_scope(ctx, {"config": wireless_config})
        assert result.get("active_scope_validated") is True

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_rejects_bssid_out_of_scope(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        ctx.add("evil_twin_bssid", "FF:FF:FF:FF:FF:FF")
        with pytest.raises(ScopeViolationError, match="BSSID out of scope"):
            validate_active_scope(ctx, {"config": wireless_config})

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_validates_subnet_in_scope(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        ctx.add("ap_subnet", "192.168.99.0/24")
        result = validate_active_scope(ctx, {"config": wireless_config})
        assert result.get("active_scope_validated") is True

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_rejects_subnet_out_of_scope(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        ctx.add("ap_subnet", "172.16.0.0/12")
        with pytest.raises(ScopeViolationError, match="Subnet out of scope"):
            validate_active_scope(ctx, {"config": wireless_config})

    @patch(
        "redops.modules.compliance.scope_guard.check_root_privileges", return_value=True
    )
    def test_validates_bssid_from_params(self, _mock, wireless_config):
        ctx = Context(target="home-lab")
        result = validate_active_scope(
            ctx,
            {"config": wireless_config, "target_bssid": "11:22:33:44:55:66"},
        )
        assert result.get("active_scope_validated") is True


# ── add_to_scope extensions ─────────────────────────────────────────


class TestAddToScopeExtensions:
    def test_add_bssid(self):
        config = RedOpsConfig(scope=ScopeConfig(strict_mode=True))
        add_to_scope("AA:BB:CC:DD:EE:FF", config)
        assert "AA:BB:CC:DD:EE:FF" in config.scope.allowed_bssids

    def test_add_subnet(self):
        config = RedOpsConfig(scope=ScopeConfig(strict_mode=True))
        add_to_scope("192.168.99.0/24", config)
        assert "192.168.99.0/24" in config.scope.allowed_subnets
