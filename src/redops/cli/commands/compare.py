"""Compare commands for RedOPS CLI."""

import json
import sys
from pathlib import Path

import click
import httpx

from ..utils import (
    console,
    print_error,
    print_success,
)


@click.command()
@click.argument("baseline_scan_id")
@click.argument("current_scan_id")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "markdown"]),
    default="text",
    help="Output format",
)
@click.option("--show-unchanged", is_flag=True, help="Show unchanged findings")
@click.pass_context
def compare(
    ctx, baseline_scan_id, current_scan_id, output, output_format, show_unchanged
):
    """Compare two scans to identify changes.

    Shows new, resolved, and modified findings between scans.

    \b
    BASELINE_SCAN_ID: The earlier/reference scan
    CURRENT_SCAN_ID: The later/current scan

    \b
    Examples:
        redops compare scan-001 scan-002
        redops compare scan-001 scan-002 --format json -o diff.json
        redops compare scan-001 scan-002 --show-unchanged
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    console.print("[bold]Comparing scans[/bold]")
    console.print(f"  Baseline: {baseline_scan_id}")
    console.print(f"  Current:  {current_scan_id}")
    console.print()

    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(
                f"{api_url}/api/v1/scans/compare",
                json={
                    "baseline_scan_id": baseline_scan_id,
                    "current_scan_id": current_scan_id,
                },
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error("One or both scans not found")
        else:
            print_error(f"API error: {e.response.status_code}")
            if e.response.text:
                console.print(f"[dim]{e.response.text}[/dim]")
        sys.exit(1)

    # Format and display output
    if output_format == "json":
        formatted = json.dumps(result, indent=2, default=str)
        if output:
            Path(output).write_text(formatted)
            print_success(f"Comparison saved to {output}")
        else:
            console.print_json(formatted)

    elif output_format == "markdown":
        md = _format_markdown(result, show_unchanged)
        if output:
            Path(output).write_text(md)
            print_success(f"Comparison saved to {output}")
        else:
            console.print(md)

    else:  # text
        _print_comparison(result, show_unchanged)
        if output:
            # Also save as JSON for text output
            Path(output).write_text(json.dumps(result, indent=2, default=str))
            print_success(f"Comparison saved to {output}")


def _print_comparison(result: dict, show_unchanged: bool = False) -> None:
    """Print comparison results in text format."""
    summary = result.get("summary", {})

    # Summary stats
    console.print("[bold]Summary[/bold]")
    console.print(f"  Baseline findings: {summary.get('baseline_total', 0)}")
    console.print(f"  Current findings:  {summary.get('current_total', 0)}")
    console.print(f"  Remediation rate:  {summary.get('remediation_rate', 0):.1f}%")
    console.print()

    # Changes overview
    console.print("[bold]Changes[/bold]")

    new_count = summary.get("new", 0)
    resolved_count = summary.get("resolved", 0)
    modified_count = summary.get("modified", 0)
    unchanged_count = summary.get("unchanged", 0)
    regressions_count = summary.get("regressions", 0)

    if new_count:
        console.print(f"  [red]+ New findings: {new_count}[/red]")
    if resolved_count:
        console.print(f"  [green]- Resolved: {resolved_count}[/green]")
    if modified_count:
        console.print(f"  [yellow]~ Modified: {modified_count}[/yellow]")
    if regressions_count:
        console.print(f"  [red]! Regressions: {regressions_count}[/red]")
    if show_unchanged:
        console.print(f"  [dim]= Unchanged: {unchanged_count}[/dim]")

    console.print()

    # New findings details
    new_findings = result.get("new_findings", [])
    if new_findings:
        console.print("[bold red]New Findings[/bold red]")
        _print_findings_list(new_findings)
        console.print()

    # Resolved findings
    resolved_findings = result.get("resolved_findings", [])
    if resolved_findings:
        console.print("[bold green]Resolved Findings[/bold green]")
        _print_findings_list(resolved_findings)
        console.print()

    # Modified findings
    modified_findings = result.get("modified_findings", [])
    if modified_findings:
        console.print("[bold yellow]Modified Findings[/bold yellow]")
        for item in modified_findings:
            finding = item.get("finding", {})
            changes = item.get("changes", {})
            severity = finding.get("severity", "unknown").lower()
            console.print(
                f"  [{_severity_color(severity)}]● {finding.get('title')}[/{_severity_color(severity)}]"
            )
            for change_key, change_val in changes.items():
                old_val, new_val = (
                    change_val
                    if isinstance(change_val, (list, tuple))
                    else (change_val, change_val)
                )
                console.print(f"    [dim]{change_key}: {old_val} → {new_val}[/dim]")
        console.print()

    # Regressions
    regressions = result.get("regression_findings", [])
    if regressions:
        console.print("[bold red]Regressions (Previously Resolved)[/bold red]")
        _print_findings_list(regressions)
        console.print()

    # Unchanged (if requested)
    if show_unchanged:
        unchanged_findings = result.get("unchanged_findings", [])
        if unchanged_findings:
            console.print("[bold dim]Unchanged Findings[/bold dim]")
            _print_findings_list(unchanged_findings, dim=True)


def _print_findings_list(findings: list, dim: bool = False) -> None:
    """Print a list of findings."""

    for item in findings[:20]:  # Limit to 20
        finding = item.get("finding", item)
        severity = finding.get("severity", "unknown").lower()
        title = finding.get("title", "Unknown")

        if dim:
            console.print(f"  [dim]● [{severity.upper()}] {title}[/dim]")
        else:
            console.print(
                f"  [{_severity_color(severity)}]● [{severity.upper()}] {title}[/{_severity_color(severity)}]"
            )

    if len(findings) > 20:
        console.print(f"  [dim]... and {len(findings) - 20} more[/dim]")


def _severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


def _format_markdown(result: dict, show_unchanged: bool = False) -> str:
    """Format comparison as markdown."""
    summary = result.get("summary", {})

    lines = [
        "# Scan Comparison Report",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Baseline Findings | {summary.get('baseline_total', 0)} |",
        f"| Current Findings | {summary.get('current_total', 0)} |",
        f"| New Findings | {summary.get('new', 0)} |",
        f"| Resolved | {summary.get('resolved', 0)} |",
        f"| Modified | {summary.get('modified', 0)} |",
        f"| Regressions | {summary.get('regressions', 0)} |",
        f"| Remediation Rate | {summary.get('remediation_rate', 0):.1f}% |",
        "",
    ]

    # New findings
    new_findings = result.get("new_findings", [])
    if new_findings:
        lines.extend(
            [
                "## New Findings",
                "",
                "| Severity | Title |",
                "|----------|-------|",
            ]
        )
        for item in new_findings:
            finding = item.get("finding", item)
            lines.append(
                f"| {finding.get('severity', 'N/A').upper()} | {finding.get('title', 'N/A')} |"
            )
        lines.append("")

    # Resolved findings
    resolved_findings = result.get("resolved_findings", [])
    if resolved_findings:
        lines.extend(
            [
                "## Resolved Findings",
                "",
                "| Severity | Title |",
                "|----------|-------|",
            ]
        )
        for item in resolved_findings:
            finding = item.get("finding", item)
            lines.append(
                f"| {finding.get('severity', 'N/A').upper()} | {finding.get('title', 'N/A')} |"
            )
        lines.append("")

    # Regressions
    regressions = result.get("regression_findings", [])
    if regressions:
        lines.extend(
            [
                "## Regressions",
                "",
                "| Severity | Title |",
                "|----------|-------|",
            ]
        )
        for item in regressions:
            finding = item.get("finding", item)
            lines.append(
                f"| {finding.get('severity', 'N/A').upper()} | {finding.get('title', 'N/A')} |"
            )
        lines.append("")

    return "\n".join(lines)
