"""Schedule commands for RedOPS CLI."""

import sys

import click
import httpx

from ..utils import (
    console,
    output_result,
    print_error,
    print_success,
)


@click.group()
def schedule():
    """Schedule management commands.

    \b
    Examples:
        redops schedule create "Daily Scan" https://example.com --cron "0 0 * * *"
        redops schedule list
        redops schedule pause sched-123
    """
    pass


@schedule.command("create")
@click.argument("name")
@click.argument("target")
@click.option("-p", "--pipeline", default="default", help="Scan pipeline to use")
@click.option(
    "--cron", help="Cron expression (e.g., '0 0 * * *' for daily at midnight)"
)
@click.option(
    "--recurrence",
    type=click.Choice(["daily", "weekly", "monthly", "custom"]),
    default="daily",
    help="Recurrence pattern",
)
@click.option("--enabled/--disabled", default=True, help="Enable or disable schedule")
@click.pass_context
def create_cmd(ctx, name, target, pipeline, cron, recurrence, enabled):
    """Create a new scan schedule.

    \b
    Examples:
        redops schedule create "Daily Scan" https://example.com
        redops schedule create "Weekly Full" example.com -p full --recurrence weekly
        redops schedule create "Custom" example.com --cron "0 2 * * 1-5"
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    payload = {
        "name": name,
        "target": target,
        "pipeline": pipeline,
        "recurrence": recurrence if not cron else "custom",
        "status": "active" if enabled else "paused",
    }

    if cron:
        payload["cron_expression"] = cron

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{api_url}/api/v1/schedules",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()

        print_success(f"Schedule created: {result.get('id')}")
        console.print(f"  Name: {name}")
        console.print(f"  Target: {target}")
        console.print(f"  Recurrence: {recurrence}")
        if result.get("next_run"):
            console.print(f"  Next run: {result.get('next_run')}")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        print_error(f"API error: {e.response.status_code}")
        if e.response.text:
            console.print(f"[dim]{e.response.text}[/dim]")
        sys.exit(1)


@schedule.command("list")
@click.option(
    "--status",
    type=click.Choice(["active", "paused", "disabled", "expired"]),
    help="Filter by status",
)
@click.option("--target", help="Filter by target")
@click.pass_context
def list_cmd(ctx, status, target):
    """List scan schedules.

    \b
    Examples:
        redops schedule list
        redops schedule list --status active
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    params = {}
    if status:
        params["status"] = status
    if target:
        params["target"] = target

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{api_url}/api/v1/schedules",
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

    schedules = result.get("schedules", [])

    if not schedules:
        console.print("[dim]No schedules found[/dim]")
        return

    output_result(
        schedules,
        format=ctx.output_format,
        title="Schedules",
    )


@schedule.command("show")
@click.argument("schedule_id")
@click.pass_context
def show_cmd(ctx, schedule_id):
    """Show schedule details.

    \b
    Examples:
        redops schedule show sched-123
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{api_url}/api/v1/schedules/{schedule_id}",
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()

        output_result(result, format=ctx.output_format, title=f"Schedule {schedule_id}")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Schedule not found: {schedule_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)


@schedule.command("pause")
@click.argument("schedule_id")
@click.pass_context
def pause_cmd(ctx, schedule_id):
    """Pause a schedule.

    \b
    Examples:
        redops schedule pause sched-123
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.patch(
                f"{api_url}/api/v1/schedules/{schedule_id}",
                json={"status": "paused"},
                headers=headers,
            )
            response.raise_for_status()

        print_success(f"Schedule {schedule_id} paused")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Schedule not found: {schedule_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)


@schedule.command("resume")
@click.argument("schedule_id")
@click.pass_context
def resume_cmd(ctx, schedule_id):
    """Resume a paused schedule.

    \b
    Examples:
        redops schedule resume sched-123
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.patch(
                f"{api_url}/api/v1/schedules/{schedule_id}",
                json={"status": "active"},
                headers=headers,
            )
            response.raise_for_status()

        print_success(f"Schedule {schedule_id} resumed")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Schedule not found: {schedule_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)


@schedule.command("delete")
@click.argument("schedule_id")
@click.option("--force", "-f", is_flag=True, help="Force delete without confirmation")
@click.pass_context
def delete_cmd(ctx, schedule_id, force):
    """Delete a schedule.

    \b
    Examples:
        redops schedule delete sched-123
        redops schedule delete sched-123 --force
    """
    ctx = ctx.obj

    if not force:
        if not click.confirm(f"Delete schedule {schedule_id}?"):
            console.print("Aborted")
            return

    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.delete(
                f"{api_url}/api/v1/schedules/{schedule_id}",
                headers=headers,
            )
            response.raise_for_status()

        print_success(f"Schedule {schedule_id} deleted")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Schedule not found: {schedule_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)


@schedule.command("run")
@click.argument("schedule_id")
@click.pass_context
def run_cmd(ctx, schedule_id):
    """Trigger a scheduled scan immediately.

    \b
    Examples:
        redops schedule run sched-123
    """
    ctx = ctx.obj
    api_url = ctx.api_url
    headers = {}
    if ctx.api_key:
        headers["Authorization"] = f"Bearer {ctx.api_key}"

    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                f"{api_url}/api/v1/schedules/{schedule_id}/run",
                headers=headers,
            )
            response.raise_for_status()
            result = response.json()

        print_success(f"Scan triggered for schedule {schedule_id}")
        if result.get("scan_id"):
            console.print(f"  Scan ID: {result.get('scan_id')}")

    except httpx.ConnectError:
        print_error(f"Cannot connect to API at {api_url}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            print_error(f"Schedule not found: {schedule_id}")
        else:
            print_error(f"API error: {e.response.status_code}")
        sys.exit(1)
