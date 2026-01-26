"""Report commands for RedOPS CLI."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
import httpx

from ..utils import (
    console,
    output_result,
    print_error,
    print_success,
)


@click.group()
def report():
    """Report generation commands.

    \b
    Examples:
        redops report generate scan-123
        redops report generate scan-123 --format pdf --type executive
        redops report list
    """
    pass


@report.command("generate")
@click.argument("scan_id")
@click.option(
    "-t", "--type",
    "report_type",
    type=click.Choice(["executive", "detailed", "compliance", "comparison"]),
    default="executive",
    help="Report type"
)
@click.option(
    "-f", "--format",
    "report_format",
    type=click.Choice(["pdf", "html", "markdown", "json"]),
    default="pdf",
    help="Output format"
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    help="Output file path"
)
@click.option(
    "--title",
    help="Custom report title"
)
@click.option(
    "--organization",
    help="Organization name for report"
)
@click.option(
    "--include-remediation/--no-remediation",
    default=True,
    help="Include remediation guidance"
)
@click.pass_context
def generate_cmd(ctx, scan_id, report_type, report_format, output, title, organization, include_remediation):
    """Generate a report from scan results.

    \b
    Report Types:
        executive   - High-level summary for management
        detailed    - Full technical details with evidence
        compliance  - Framework mapping (OWASP, PCI-DSS, etc.)
        comparison  - Compare with previous scan

    \b
    Examples:
        redops report generate scan-123
        redops report generate scan-123 --type detailed --format pdf
        redops report generate scan-123 -o report.pdf --title "Q1 Assessment"
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    # Determine output path
    if not output:
        output = f"redops_report_{scan_id}_{report_type}.{report_format}"

    console.print(f"[bold]Generating {report_type} report[/bold]")
    console.print(f"  Scan ID: {scan_id}")
    console.print(f"  Format: {report_format}")
    console.print(f"  Output: {output}")

    # Build request payload
    payload = {
        "scan_id": scan_id,
        "report_type": report_type,
        "format": report_format,
        "options": {
            "include_remediation": include_remediation,
        },
    }

    if title:
        payload["title"] = title
    if organization:
        payload["organization"] = organization

    try:
        with httpx.Client(timeout=120) as client:
            response = client.post(
                f"{api_url}/api/v1/reports",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()

            # Check if response is JSON (metadata) or binary (file)
            content_type = response.headers.get("content-type", "")

            if "application/json" in content_type:
                result = response.json()

                # Report might be generated async
                if result.get("status") == "generating":
                    report_id = result.get("report_id")
                    console.print(f"  Report ID: {report_id}")
                    console.print("[dim]Report is being generated...[/dim]")

                    # Poll for completion
                    import time

                    for _ in range(60):  # Max 5 minutes
                        time.sleep(5)
                        status_response = client.get(
                            f"{api_url}/api/v1/reports/{report_id}",
                            headers=headers,
                        )
                        status_result = status_response.json()

                        if status_result.get("status") == "completed":
                            # Download the report
                            download_response = client.get(
                                f"{api_url}/api/v1/reports/{report_id}/download",
                                headers=headers,
                            )
                            Path(output).write_bytes(download_response.content)
                            break
                        elif status_result.get("status") == "failed":
                            print_error("Report generation failed")
                            sys.exit(1)
                    else:
                        print_error("Report generation timed out")
                        sys.exit(1)
                else:
                    # Report data returned directly
                    Path(output).write_text(json.dumps(result, indent=2))
            else:
                # Binary file response
                Path(output).write_bytes(response.content)

        print_success(f"Report saved to {output}")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Scan not found: {scan_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
            if e.response.text:
                console.print(f"[dim]{e.response.text}[/dim]")
        sys.exit(1)


@report.command("list")
@click.option(
    "--scan-id",
    help="Filter by scan ID"
)
@click.option(
    "--type",
    "report_type",
    type=click.Choice(["executive", "detailed", "compliance", "comparison"]),
    help="Filter by report type"
)
@click.option(
    "--limit",
    type=int,
    default=20,
    help="Maximum number of results"
)
@click.pass_context
def list_cmd(ctx, scan_id, report_type, limit):
    """List generated reports.

    \b
    Examples:
        redops report list
        redops report list --scan-id scan-123
        redops report list --type executive
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    params = {"limit": limit}
    if scan_id:
        params["scan_id"] = scan_id
    if report_type:
        params["report_type"] = report_type

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{api_url}/api/v1/reports",
                params=params,
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        print_error(f"API error: {e.response.status_code}")
        sys.exit(1)

    reports = result.get("reports", [])

    if not reports:
        console.print("[dim]No reports found[/dim]")
        return

    output_result(
        reports,
        format=ctx.output_format,
        title="Reports",
    )


@report.command("download")
@click.argument("report_id")
@click.option(
    "-o", "--output",
    type=click.Path(),
    help="Output file path"
)
@click.pass_context
def download_cmd(ctx, report_id, output):
    """Download a generated report.

    \b
    Examples:
        redops report download rpt-123
        redops report download rpt-123 -o my_report.pdf
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=60) as client:
            # Get report metadata first
            meta_response = client.get(
                f"{api_url}/api/v1/reports/{report_id}",
                headers=headers,
            )
            meta_response.raise_for_status()
            metadata = meta_response.json()

            # Determine output filename
            if not output:
                output = metadata.get("filename", f"report_{report_id}.pdf")

            # Download file
            download_response = client.get(
                f"{api_url}/api/v1/reports/{report_id}/download",
                headers=headers,
            )
            download_response.raise_for_status()

            Path(output).write_bytes(download_response.content)

        print_success(f"Report downloaded to {output}")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Report not found: {report_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)


@report.command("delete")
@click.argument("report_id")
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Force delete without confirmation"
)
@click.pass_context
def delete_cmd(ctx, report_id, force):
    """Delete a generated report.

    \b
    Examples:
        redops report delete rpt-123
        redops report delete rpt-123 --force
    """
    ctx = ctx.obj

    if not force:
        if not click.confirm(f"Delete report {report_id}?"):
            console.print("Aborted")
            return

    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.delete(
                f"{api_url}/api/v1/reports/{report_id}",
                headers=headers,
            )
            response.raise_for_status()

        print_success(f"Report {report_id} deleted")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Report not found: {report_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)
