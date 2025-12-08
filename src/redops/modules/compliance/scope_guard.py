"""
Scope Guard - Validates that targets are within allowed scope.

RedOps only runs on explicitly allowed domains or offline local directories.
If target is out of scope → raise exception and stop the pipeline.
"""

from typing import Optional, Dict, Any
from pathlib import Path
from redops.core.context import Context
from redops.core.config import RedOpsConfig, default_config


class ScopeViolationError(Exception):
    """Raised when a target is out of scope."""
    pass


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


def validate_scope(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
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
    config = params.get('config', default_config)
    
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


def add_to_scope(target: str, config: RedOpsConfig = default_config) -> None:
    """
    Add a target to the allowed scope.
    
    Args:
        target: The target to add
        config: Configuration to update
    """
    if Path(target).exists():
        config.scope.allowed_directories.append(str(Path(target).resolve()))
    elif target.replace('.', '').replace(':', '').isdigit():
        # Looks like an IP
        config.scope.allowed_ips.append(target)
    else:
        # Assume it's a domain
        config.scope.allowed_domains.append(target)
