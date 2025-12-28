"""
Export utilities for RedOps.

Handles exporting data in various formats (JSON, CSV, etc.).
"""

from typing import Optional, Dict, Any
from pathlib import Path
import json
import csv
from datetime import datetime
from redops.core.context import Context


def export_json(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Export context data as JSON.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.log("Exporting data as JSON", level="INFO")

    # Export full context
    output_path = output_dir / f"data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(output_path, "w") as f:
        json.dump(ctx.to_dict(), f, indent=2, default=str)

    ctx.add("json_export_path", str(output_path))
    ctx.log(f"JSON export saved to {output_path}", level="INFO")

    return ctx


def export_csv(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Export findings/risks as CSV.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'output_path' and 'data_key'

    Returns:
        Updated context
    """
    params = params or {}
    output_dir = Path(params.get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    data_key = params.get("data_key", "risks")

    ctx.log(f"Exporting {data_key} as CSV", level="INFO")

    data = ctx.get(data_key, [])

    if not data:
        ctx.log(f"No data found for key: {data_key}", level="WARNING")
        return ctx

    output_path = (
        output_dir / f"{data_key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

    # Write CSV
    if isinstance(data, list) and len(data) > 0:
        if isinstance(data[0], dict):
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        else:
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([data_key])
                for item in data:
                    writer.writerow([item])

    ctx.add(f"{data_key}_csv_path", str(output_path))
    ctx.log(f"CSV export saved to {output_path}", level="INFO")

    return ctx


def export_all(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Export all data in multiple formats.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    ctx.log("Exporting all data", level="INFO")

    # Export JSON
    ctx = export_json(ctx, params)

    # Export risks as CSV if present
    if ctx.get("risks"):
        ctx = export_csv(ctx, {**params, "data_key": "risks"})

    ctx.log("All exports completed", level="INFO")

    return ctx
