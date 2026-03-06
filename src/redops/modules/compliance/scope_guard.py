"""
Scope Guard - Validates that targets are within allowed scope.

RedOps only runs on explicitly allowed domains or offline local directories.
Active chain modules additionally validate BSSIDs, subnets, and root privileges.
If target is out of scope → raise exception and stop the pipeline.
"""

import ipaddress
import os
import re
from pathlib import Path
from typing import Any

from redops.core.config import RedOpsConfig, default_config
from redops.core.context import Context

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class ScopeViolationError(Exception):
    """Raised when a target is out of scope."""

    pass


def is_bssid_in_scope(bssid: str, config: RedOpsConfig = default_config) -> bool:
    """
    Check if a BSSID is within the allowed wireless scope.

    Args:
        bssid: MAC address to check (e.g. 'AA:BB:CC:DD:EE:FF')
        config: Configuration containing scope rules

    Returns:
        True if in scope (or no BSSID restrictions configured), False otherwise
    """
    scope = config.scope

    if not scope.strict_mode:
        return True

    if not scope.allowed_bssids:
        return True

    bssid_upper = bssid.upper()
    return bssid_upper in [b.upper() for b in scope.allowed_bssids]


def is_subnet_in_scope(subnet: str, config: RedOpsConfig = default_config) -> bool:
    """
    Check if a subnet is within the allowed network scope.

    Args:
        subnet: CIDR notation (e.g. '192.168.99.0/24')
        config: Configuration containing scope rules

    Returns:
        True if in scope (or no subnet restrictions configured), False otherwise
    """
    scope = config.scope

    if not scope.strict_mode:
        return True

    if not scope.allowed_subnets:
        return True

    try:
        target_net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False

    for allowed in scope.allowed_subnets:
        try:
            allowed_net = ipaddress.ip_network(allowed, strict=False)
            if target_net.subnet_of(allowed_net) or target_net == allowed_net:
                return True
        except ValueError:
            continue

    return False


def check_root_privileges() -> bool:
    """Check if the current process has root/sudo privileges."""
    return os.geteuid() == 0


def is_in_scope(target: str, config: RedOpsConfig = default_config) -> bool:
    """
    Check if a target is within the allowed scope.

    Args:
        target: The target to check
        config: Configuration containing scope rules

    Returns:
        True if in scope, False otherwise
    """
    scope = config.scope

    # If not in strict mode, allow everything
    if not scope.strict_mode:
        return True

    # Check if target is a local directory
    if Path(target).exists():
        target_path = Path(target).resolve()
        for allowed_dir in scope.allowed_directories:
            allowed_path = Path(allowed_dir).resolve()
            if str(target_path).startswith(str(allowed_path)):
                return True

    # Check if target is an allowed domain
    for allowed_domain in scope.allowed_domains:
        if target == allowed_domain or target.endswith(f".{allowed_domain}"):
            return True

    # Check if target is an allowed IP
    if target in scope.allowed_ips:
        return True

    return False


def validate_scope(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Pipeline module that validates target scope.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'config'

    Returns:
        Updated context

    Raises:
        ScopeViolationError: If target is out of scope
    """
    params = params or {}
    # Prefer config from context (passed via CLI), fall back to params, then default
    config = (
        ctx.config if ctx.config is not None else params.get("config", default_config)
    )

    target = ctx.target

    if not target:
        ctx.log("No target specified, skipping scope validation", level="WARNING")
        return ctx

    ctx.log(f"Validating scope for target: {target}", level="INFO")

    if is_in_scope(target, config):
        ctx.log(f"Target is in scope: {target}", level="INFO")
        ctx.add("scope_validated", True)
        return ctx
    else:
        error_msg = f"Target out of scope: {target}. Add to allowed_domains, allowed_ips, or allowed_directories in config."
        ctx.log(error_msg, level="ERROR")
        raise ScopeViolationError(error_msg)


def validate_active_scope(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Pipeline module that validates scope for active attack chain modules.

    Checks root privileges, BSSID allowlist, and subnet fencing.
    Use this as the first step in active_chain pipelines instead of
    (or in addition to) validate_scope.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'config', 'require_root'

    Returns:
        Updated context

    Raises:
        ScopeViolationError: If any active scope check fails
    """
    params = params or {}
    config = (
        ctx.config if ctx.config is not None else params.get("config", default_config)
    )
    require_root = params.get("require_root", True)

    ctx.log("Validating active chain scope", level="INFO")

    # Root privilege check — active modules require sudo
    if require_root and not check_root_privileges():
        error_msg = "Active chain requires root privileges. Run with sudo."
        ctx.log(error_msg, level="ERROR")
        raise ScopeViolationError(error_msg)

    ctx.add("root_validated", True)
    ctx.log("Root privileges confirmed", level="INFO")

    # Validate BSSID if one is already targeted
    target_bssid = ctx.get("evil_twin_bssid") or params.get("target_bssid")
    if target_bssid:
        if not is_bssid_in_scope(target_bssid, config):
            error_msg = (
                f"BSSID out of scope: {target_bssid}. Add to allowed_bssids in config."
            )
            ctx.log(error_msg, level="ERROR")
            raise ScopeViolationError(error_msg)
        ctx.log(f"BSSID in scope: {target_bssid}", level="INFO")

    # Validate subnet if already determined
    ap_subnet = ctx.get("ap_subnet") or params.get("subnet")
    if ap_subnet:
        if not is_subnet_in_scope(ap_subnet, config):
            error_msg = (
                f"Subnet out of scope: {ap_subnet}. Add to allowed_subnets in config."
            )
            ctx.log(error_msg, level="ERROR")
            raise ScopeViolationError(error_msg)
        ctx.log(f"Subnet in scope: {ap_subnet}", level="INFO")

    ctx.add("active_scope_validated", True)
    ctx.log("Active chain scope validation passed", level="INFO")
    return ctx


def add_to_scope(target: str, config: RedOpsConfig = default_config) -> None:
    """
    Add a target to the allowed scope.

    Args:
        target: The target to add
        config: Configuration to update
    """
    if Path(target).exists():
        config.scope.allowed_directories.append(str(Path(target).resolve()))
    elif _MAC_RE.match(target):
        config.scope.allowed_bssids.append(target.upper())
    elif "/" in target and _is_cidr(target):
        config.scope.allowed_subnets.append(target)
    elif target.replace(".", "").replace(":", "").isdigit():
        # Looks like an IP
        config.scope.allowed_ips.append(target)
    else:
        # Assume it's a domain
        config.scope.allowed_domains.append(target)


def _is_cidr(value: str) -> bool:
    """Check if a string is valid CIDR notation."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False
