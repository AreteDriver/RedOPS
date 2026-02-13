"""
Audit logging module for RedOps.

Maintains detailed audit logs of all operations performed.
"""

from typing import Any
from datetime import datetime, timezone
from pathlib import Path
import json
from redops.core.context import Context


def create_audit_entry(
    action: str,
    target: str,
    user: str = "system",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Create an audit log entry.

    Args:
        action: The action being performed
        target: The target of the action
        user: The user performing the action
        metadata: Additional metadata

    Returns:
        Audit log entry
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "target": target,
        "user": user,
        "metadata": metadata or {},
    }


def log_to_file(entry: dict[str, Any], log_file: Path) -> None:
    """
    Append an audit entry to a log file.

    Args:
        entry: The audit log entry
        log_file: Path to the log file
    """
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")


def audit_pipeline_start(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Log the start of a pipeline execution.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}

    entry = create_audit_entry(
        action="pipeline_start",
        target=ctx.target or "N/A",
        metadata={
            "pipeline": ctx.get("pipeline_name"),
            "version": ctx.get("pipeline_version"),
        },
    )

    ctx.add("audit_start", entry)
    ctx.log("Pipeline execution started (audit logged)", level="INFO")

    # Optionally write to file
    if params.get("log_file"):
        log_to_file(entry, Path(params["log_file"]))

    return ctx


def audit_pipeline_end(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Log the end of a pipeline execution.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}

    entry = create_audit_entry(
        action="pipeline_end",
        target=ctx.target or "N/A",
        metadata={
            "pipeline": ctx.get("pipeline_name"),
            "version": ctx.get("pipeline_version"),
            "log_count": len(ctx.logs),
            "data_keys": list(ctx.data.keys()),
        },
    )

    ctx.add("audit_end", entry)
    ctx.log("Pipeline execution completed (audit logged)", level="INFO")

    # Optionally write to file
    if params.get("log_file"):
        log_to_file(entry, Path(params["log_file"]))

    return ctx
