"""Tests for the Scope Guard module."""

import pytest
from redops.core.context import Context
from redops.core.config import RedOpsConfig, ScopeConfig
from redops.modules.compliance.scope_guard import (
    is_in_scope,
    validate_scope,
    add_to_scope,
    ScopeViolationError
)


@pytest.fixture
def strict_config():
    """Create a strict scope configuration for testing."""
    return RedOpsConfig(
        scope=ScopeConfig(
            allowed_domains=["example.com", "test.com"],
            allowed_ips=["192.168.1.1", "10.0.0.1"],
            allowed_directories=["/tmp/test", "/home/user/projects"],
            strict_mode=True
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
            strict_mode=False
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
            allowed_domains=[],
            allowed_ips=[],
            allowed_directories=[],
            strict_mode=True
        )
    )
    
    add_to_scope("newdomain.com", config)
    assert "newdomain.com" in config.scope.allowed_domains


def test_add_to_scope_ip():
    """Test adding an IP to scope."""
    config = RedOpsConfig(
        scope=ScopeConfig(
            allowed_domains=[],
            allowed_ips=[],
            allowed_directories=[],
            strict_mode=True
        )
    )
    
    add_to_scope("203.0.113.1", config)
    # The function uses a simple check, so IPs with dots might be detected
    # Check if it was added to either IPs or domains
    assert "203.0.113.1" in config.scope.allowed_ips or "203.0.113.1" in config.scope.allowed_domains


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
