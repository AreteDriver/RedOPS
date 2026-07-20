"""Scan commands for RedOPS CLI."""

import json
import sys
import time
from datetime import datetime
from pathlib import Path

import click
import httpx

from ..utils import (
    console,
    progress,
    output_result,
    print_scan_result,
    print_error,
    print_success,
    format_duration,
)


# ---------------------------------------------------------------------------
# Local execution helpers (zero-config quickstart)
# ---------------------------------------------------------------------------

def _resolve_pipeline_file(pipeline_name: str) -> Path | None:
    """Resolve a pipeline name to a JSON file in config/pipelines/."""
    if pipeline_name == "default":
        pipeline_name = "quickstart"

    pipelines_dir = Path(__file__).parents[3] / "config" / "pipelines"
    if not pipelines_dir.exists():
        return None

    # Exact match first
    exact = pipelines_dir / f"{pipeline_name}.json"
    if exact.exists():
        return exact

    # Suffix match
    for path in pipelines_dir.glob("*.json"):
        if path.stem == pipeline_name or pipeline_name in path.stem:
            return path

    return None


def _run_local_scan(
    target: str,
    pipeline_name: str = "quickstart",
    output: str | None = None,
    timeout: int = 60,
) -> int:
    """Run a scan locally using PipelineRunner (no API server required).

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    from redops.pipelines.loader import PipelineLoader
    from redops.pipelines.runner import PipelineRunner
    from redops.core.config import RedOpsConfig
    from redops.core.context import Context

    pipeline_path = _resolve_pipeline_file(pipeline_name)
    if pipeline_path is None:
        print_error(f"Pipeline '{pipeline_name}' not found in config/pipelines/")
        console.print(
            "[dim]Run 'redops scan list-pipelines' to see available pipelines.[/dim]"
        )
        return 1

    try:
        config = RedOpsConfig.from_env()
    except Exception:
        config = RedOpsConfig()

    console.print(f"[bold]Starting local scan on {target}[/bold]")
    console.print(f"  Pipeline: {pipeline_name} ({pipeline_path.name})")
    console.print(f"  Timeout: {timeout}s")
    console.print()

    try:
        pipeline = PipelineLoader.load(pipeline_path)
        runner = PipelineRunner(pipeline, config=config)

        console.print(f"[dim]Executing {len(pipeline.enabled_steps)} steps...[/dim]")
        console.print()

        start_time = time.time()
        ctx = runner.run(target=target)
        elapsed = time.time() - start_time

        # Build a result dict compatible with print_scan_result
        result = {
            "scan_id": "local",
            "target": target,
            "pipeline": pipeline.metadata.name,
            "status": "completed",
            "started_at": datetime.fromtimestamp(start_time).isoformat(),
            "completed_at": datetime.now().isoformat(),
            "findings": _extract_findings_from_context(ctx),
            "logs": ctx.logs,
            "data_keys": list(ctx.data.keys()),
        }

        print_scan_result(result, verbose=False)
        console.print(f"\n[dim]Completed in {format_duration(elapsed)}[/dim]")

        if output:
            output_path = Path(output)
            output_path.write_text(json.dumps(result, indent=2, default=str))
            print_success(f"Results saved to {output}")

        return 0

    except Exception as e:
        print_error(f"Local scan failed: {e}")
        return 1


def _extract_findings_from_context(ctx) -> list[dict]:
    """Extract findings from pipeline context for display."""
    findings = []
    for key, value in ctx.data.items():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "severity" in item:
                    findings.append(item)
                elif isinstance(item, dict) and "title" in item:
                    findings.append(item)
        elif isinstance(value, dict) and "severity" in value:
            findings.append(value)
    return findings


@click.group()
def scan():
    """Scan management commands.

    \b
    Examples:
        redops scan run https://example.com
        redops scan list
        redops scan status scan-123
        redops scan cancel scan-123
    """
    pass


@scan.command("run")
@click.argument("target")
@click.option("-p", "--pipeline", default="default", help="Scan pipeline to use")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option("--async", "async_mode", is_flag=True, help="Run scan asynchronously")
@click.option("--timeout", type=int, default=3600, help="Scan timeout in seconds")
@click.option("--modules", help="Comma-separated list of modules to run")
@click.option("--exclude-modules", help="Comma-separated list of modules to exclude")
@click.option(
    "--tag", multiple=True, help="Tags to add to scan (can be used multiple times)"
)
@click.option(
    "--local",
    "local_mode",
    is_flag=True,
    help="Run scan locally without an API server (zero-config mode)",
)
@click.pass_context
def run_cmd(
    ctx,
    target,
    pipeline,
    output,
    async_mode,
    timeout,
    modules,
    exclude_modules,
    tag,
    local_mode,
):
    """Run a security scan on a target.

    TARGET can be a URL, IP address, or domain name.

    \b
    Examples:
        redops scan run https://example.com
        redops scan run -p web_full example.com
        redops scan run --local example.com
    """
    if local_mode:
        sys.exit(
            _run_local_scan(
                target=target,
                pipeline_name=pipeline,
                output=output,
                timeout=timeout,
            )
        )

    run_scan(
        ctx=ctx.obj,
        target=target,
        pipeline=pipeline,
        output=output,
        async_mode=async_mode,
        timeout=timeout,
        modules=modules,
        exclude_modules=exclude_modules,
        tags=list(tag),
    )


def run_scan(
    ctx,
    target: str,
    pipeline: str = "default",
    output: str | None = None,
    async_mode: bool = False,
    timeout: int = 3600,
    modules: str | None = None,
    exclude_modules: str | None = None,
    tags: list | None = None,
) -> None:
    """Execute a scan (shared logic for run command and quick-scan)."""
    console.print(f"[bold]Starting scan on {target}[/bold]")
    console.print(f"  Pipeline: {pipeline}")
    console.print(f"  Timeout: {timeout}s")

    # Build request payload
    payload = {
        "target": target,
        "pipeline": pipeline,
        "timeout": timeout,
        "tags": tags or [],
    }

    if modules:
        payload["modules"] = modules.split(",")
    if exclude_modules:
        payload["exclude_modules"] = exclude_modules.split(",")

    # Make API request
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{api_url}/api/v1/scans",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()
    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        print_error("Make sure the RedOPS API server is running.")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        print_error(f"API error: {e.response.status_code}")
        if e.response.text:
            console.print(f"[dim]{e.response.text}[/dim]")
        sys.exit(1)

    scan_id = result.get("scan_id")
    console.print(f"  Scan ID: [cyan]{scan_id}[/cyan]")

    if async_mode:
        print_success("Scan started in background")
        console.print(f"  Use 'redops scan status {scan_id}' to check progress")
        return

    # Wait for scan to complete
    console.print("\n[dim]Waiting for scan to complete...[/dim]")

    start_time = time.time()
    with progress:
        task = progress.add_task("Scanning...", total=100)

        while True:
            try:
                with httpx.Client(timeout=30) as client:
                    status_response = client.get(
                        f"{api_url}/api/v1/scans/{scan_id}",
                        headers=headers,
                    )
                    status_response.raise_for_status()
                    scan_result = status_response.json()
            except httpx.HTTPError as e:
                print_error(f"Error checking scan status: {e}")
                sys.exit(1)

            status = scan_result.get("status")

            # Update progress based on scan metadata
            scan_progress = scan_result.get("metadata", {}).get("progress", 0)
            progress.update(task, completed=scan_progress)

            if status in ("completed", "failed", "cancelled"):
                progress.update(task, completed=100)
                break

            elapsed = time.time() - start_time
            if elapsed > timeout:
                print_error("Scan timed out")
                console.print(f"  Use 'redops scan cancel {scan_id}' to cancel")
                sys.exit(1)

            time.sleep(2)

    # Print results
    elapsed = time.time() - start_time
    console.print(f"\n[dim]Scan completed in {format_duration(elapsed)}[/dim]\n")

    print_scan_result(scan_result, verbose=ctx.verbose)

    # Save output if requested
    if output:
        output_path = Path(output)
        output_path.write_text(json.dumps(scan_result, indent=2, default=str))
        print_success(f"Results saved to {output}")


@scan.command("list")
@click.option(
    "--status",
    type=click.Choice(["pending", "running", "completed", "failed", "cancelled"]),
    help="Filter by status",
)
@click.option("--target", help="Filter by target")
@click.option("--limit", type=int, default=20, help="Maximum number of results")
@click.option("--offset", type=int, default=0, help="Offset for pagination")
@click.pass_context
def list_cmd(ctx, status, target, limit, offset):
    """List scans.

    \b
    Examples:
        redops scan list
        redops scan list --status completed
        redops scan list --target example.com --limit 10
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    # Build query params
    params = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    if target:
        params["target"] = target

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{api_url}/api/v1/scans",
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

    scans = result.get("scans", [])

    if not scans:
        console.print("[dim]No scans found[/dim]")
        return

    output_result(
        scans,
        format=ctx.output_format,
        title="Scans",
    )


@scan.command("status")
@click.argument("scan_id")
@click.option("--watch", "-w", is_flag=True, help="Watch for status changes")
@click.pass_context
def status_cmd(ctx, scan_id, watch):
    """Get scan status.

    \b
    Examples:
        redops scan status scan-123
        redops scan status scan-123 --watch
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    def get_status():
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{api_url}/api/v1/scans/{scan_id}",
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    try:
        if watch:
            console.print(f"[dim]Watching scan {scan_id}... (Ctrl+C to stop)[/dim]\n")
            last_status = None

            while True:
                result = get_status()
                status = result.get("status")

                if status != last_status:
                    console.print(
                        f"[{datetime.now().strftime('%H:%M:%S')}] "
                        f"Status: [bold]{status}[/bold]"
                    )
                    last_status = status

                if status in ("completed", "failed", "cancelled"):
                    print_scan_result(result, verbose=ctx.verbose)
                    break

                time.sleep(2)
        else:
            result = get_status()
            print_scan_result(result, verbose=ctx.verbose)

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Scan not found: {scan_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching[/dim]")


@scan.command("list-pipelines")
def list_pipelines_cmd():
    """List available pipeline definitions."""
    pipelines_dir = Path(__file__).parents[3] / "config" / "pipelines"
    if not pipelines_dir.exists():
        console.print("[yellow]Pipeline directory not found.[/yellow]")
        return

    console.print("[bold]Available Pipelines[/bold]\n")
    from redops.pipelines.loader import PipelineLoader

    for path in sorted(pipelines_dir.glob("*.json")):
        try:
            pipeline = PipelineLoader.load(path)
            console.print(f"  [cyan]{path.stem}[/cyan]")
            console.print(f"    {pipeline.metadata.name}")
            if pipeline.metadata.description:
                console.print(f"    [dim]{pipeline.metadata.description}[/dim]")
            console.print(f"    Steps: {len(pipeline.steps)} | Tags: {', '.join(pipeline.metadata.tags)}")
            console.print()
        except Exception as e:
            console.print(f"  [red]{path.name}[/red] — error: {e}")
            console.print()


@scan.command("cancel")
@click.argument("scan_id")
@click.option("--force", "-f", is_flag=True, help="Force cancel without confirmation")
@click.pass_context
def cancel_cmd(ctx, scan_id, force):
    """Cancel a running scan.

    \b
    Examples:
        redops scan cancel scan-123
        redops scan cancel scan-123 --force
    """
    ctx = ctx.obj

    if not force:
        if not click.confirm(f"Cancel scan {scan_id}?"):
            console.print("Aborted")
            return

    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{api_url}/api/v1/scans/{scan_id}/cancel",
                headers=headers,
            )
            response.raise_for_status()

        print_success(f"Scan {scan_id} cancelled")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Scan not found: {scan_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)


@scan.command("delete")
@click.argument("scan_id")
@click.option("--force", "-f", is_flag=True, help="Force delete without confirmation")
@click.pass_context
def delete_cmd(ctx, scan_id, force):
    """Delete a scan and its findings.

    \b
    Examples:
        redops scan delete scan-123
        redops scan delete scan-123 --force
    """
    ctx = ctx.obj

    if not force:
        if not click.confirm(f"Delete scan {scan_id}? This cannot be undone."):
            console.print("Aborted")
            return

    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.delete(
                f"{api_url}/api/v1/scans/{scan_id}",
                headers=headers,
            )
            response.raise_for_status()

        print_success(f"Scan {scan_id} deleted")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Scan not found: {scan_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)
