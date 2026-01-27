"""
CLI utilities for RedOPS.

Provides common functions for output, formatting, and configuration.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

# Global console instance
console = Console()

# Progress bar for long operations
progress = Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    console=console,
)


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Set up logging configuration.

    Args:
        verbose: Enable debug logging
        quiet: Suppress info logging
    """
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def load_config(path: str) -> Dict[str, Any]:
    """Load configuration from file.

    Args:
        path: Path to config file (YAML or JSON)

    Returns:
        Configuration dictionary
    """
    config_path = Path(path)

    if not config_path.exists():
        console.print(f"[red]Config file not found: {path}[/red]")
        return {}

    content = config_path.read_text()

    if config_path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(content) or {}
    elif config_path.suffix == ".json":
        return json.loads(content)
    else:
        console.print(f"[yellow]Unknown config format: {config_path.suffix}[/yellow]")
        return {}


def output_result(
    data: Any,
    format: str = "text",
    title: Optional[str] = None,
) -> None:
    """Output result in specified format.

    Args:
        data: Data to output
        format: Output format (text, json, table)
        title: Optional title for output
    """
    if format == "json":
        output_json(data)
    elif format == "table":
        output_table(data, title=title)
    else:
        output_text(data, title=title)


def output_json(data: Any) -> None:
    """Output data as JSON."""
    if hasattr(data, "to_dict"):
        data = data.to_dict()
    elif hasattr(data, "__dict__"):
        data = data.__dict__

    console.print_json(json.dumps(data, default=str, indent=2))


def output_table(
    data: Any,
    title: Optional[str] = None,
    columns: Optional[List[str]] = None,
) -> None:
    """Output data as a table.

    Args:
        data: List of dictionaries or objects
        title: Table title
        columns: Column names to display
    """
    if not data:
        console.print("[dim]No data to display[/dim]")
        return

    # Convert to list of dicts
    if isinstance(data, dict):
        data = [data]

    if hasattr(data[0], "__dict__"):
        data = [item.__dict__ for item in data]

    # Determine columns
    if not columns:
        columns = list(data[0].keys())

    # Create table
    table = Table(title=title, show_header=True, header_style="bold")

    for col in columns:
        table.add_column(col.replace("_", " ").title())

    for item in data:
        row = []
        for col in columns:
            value = item.get(col, "")
            if isinstance(value, datetime):
                value = value.strftime("%Y-%m-%d %H:%M")
            elif isinstance(value, (list, dict)):
                value = json.dumps(value)[:50]
            row.append(str(value))
        table.add_row(*row)

    console.print(table)


def output_text(data: Any, title: Optional[str] = None) -> None:
    """Output data as formatted text.

    Args:
        data: Data to output
        title: Optional title
    """
    if title:
        console.print(f"\n[bold]{title}[/bold]")

    if isinstance(data, str):
        console.print(data)
    elif isinstance(data, dict):
        for key, value in data.items():
            console.print(f"  [cyan]{key}:[/cyan] {value}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                console.print("  ---")
                for key, value in item.items():
                    console.print(f"  [cyan]{key}:[/cyan] {value}")
            else:
                console.print(f"  • {item}")
    else:
        console.print(str(data))


def print_findings(findings: List[Dict[str, Any]], verbose: bool = False) -> None:
    """Print findings in a formatted way.

    Args:
        findings: List of finding dictionaries
        verbose: Include detailed information
    """
    if not findings:
        console.print("[green]No findings[/green]")
        return

    severity_colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    # Group by severity
    by_severity = {}
    for finding in findings:
        sev = finding.get("severity", "unknown").lower()
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(finding)

    # Print summary
    console.print(f"\n[bold]Findings Summary ({len(findings)} total)[/bold]")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_severity:
            color = severity_colors.get(sev, "white")
            count = len(by_severity[sev])
            console.print(f"  [{color}]● {sev.upper()}: {count}[/{color}]")

    # Print details
    console.print("\n[bold]Details:[/bold]")
    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "unknown").lower()
        color = severity_colors.get(sev, "white")
        title = finding.get("title", "Unknown")

        console.print(f"\n  [{color}][{sev.upper()}][/{color}] {title}")

        if verbose:
            if finding.get("description"):
                console.print(f"    [dim]{finding['description'][:200]}[/dim]")
            if finding.get("module"):
                console.print(f"    Module: {finding['module']}")
            if finding.get("remediation"):
                console.print(f"    [green]Fix: {finding['remediation'][:100]}[/green]")


def print_scan_result(result: Dict[str, Any], verbose: bool = False) -> None:
    """Print scan result summary.

    Args:
        result: Scan result dictionary
        verbose: Include detailed information
    """
    # Header
    status = result.get("status", "unknown")
    status_color = (
        "green" if status == "completed" else "yellow" if status == "running" else "red"
    )

    panel_content = f"""[bold]Scan ID:[/bold] {result.get("scan_id", "N/A")}
[bold]Target:[/bold] {result.get("target", "N/A")}
[bold]Pipeline:[/bold] {result.get("pipeline", "N/A")}
[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]
[bold]Started:[/bold] {result.get("started_at", "N/A")}
[bold]Completed:[/bold] {result.get("completed_at", "N/A")}"""

    console.print(Panel(panel_content, title="Scan Result", border_style="blue"))

    # Findings
    findings = result.get("findings", [])
    print_findings(findings, verbose=verbose)


def confirm_action(message: str, default: bool = False) -> bool:
    """Ask for confirmation.

    Args:
        message: Confirmation message
        default: Default response

    Returns:
        True if confirmed
    """
    return console.input(f"{message} [{'Y/n' if default else 'y/N'}]: ").lower() in (
        "y",
        "yes",
        "" if default else None,
    )


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "5m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def format_datetime(dt: datetime) -> str:
    """Format datetime for display.

    Args:
        dt: Datetime object

    Returns:
        Formatted string
    """
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def print_error(message: str, details: Optional[str] = None) -> None:
    """Print error message.

    Args:
        message: Error message
        details: Additional details
    """
    console.print(f"[red]Error:[/red] {message}")
    if details:
        console.print(f"[dim]{details}[/dim]")


def print_success(message: str) -> None:
    """Print success message.

    Args:
        message: Success message
    """
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    """Print warning message.

    Args:
        message: Warning message
    """
    console.print(f"[yellow]Warning:[/yellow] {message}")
