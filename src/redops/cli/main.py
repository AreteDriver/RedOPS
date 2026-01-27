"""
Main CLI entry point for RedOPS.

Provides commands for scanning, reporting, and management.
"""

import sys
from pathlib import Path

import click

from .commands import scan, report, compare, schedule, config
from .utils import console, setup_logging, load_config


class RedOPSContext:
    """Context object for CLI commands."""

    def __init__(self):
        self.config = {}
        self.verbose = False
        self.quiet = False
        self.output_format = "text"
        self.api_url = None
        self.api_key = None


pass_context = click.make_pass_decorator(RedOPSContext, ensure=True)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-essential output")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "table"]),
    default="text",
    help="Output format",
)
@click.option(
    "--config",
    "config_file",
    type=click.Path(exists=True),
    envvar="REDOPS_CONFIG",
    help="Path to config file",
)
@click.option("--api-url", envvar="REDOPS_API_URL", help="RedOPS API URL")
@click.option("--api-key", envvar="REDOPS_API_KEY", help="RedOPS API key")
@click.version_option(version="1.5.0", prog_name="redops")
@pass_context
def cli(ctx, verbose, quiet, output_format, config_file, api_url, api_key):
    """RedOPS - Security Assessment Framework.

    A comprehensive security scanning and vulnerability management tool.

    \b
    Examples:
        redops scan https://example.com
        redops scan --pipeline web_full example.com
        redops report generate scan-123 --format pdf
        redops compare scan-001 scan-002
    """
    ctx.verbose = verbose
    ctx.quiet = quiet
    ctx.output_format = output_format
    ctx.api_url = api_url or "http://localhost:8000"
    ctx.api_key = api_key

    # Set up logging
    setup_logging(verbose=verbose, quiet=quiet)

    # Load config file if provided
    if config_file:
        ctx.config = load_config(config_file)


# Register command groups
cli.add_command(scan.scan)
cli.add_command(report.report)
cli.add_command(compare.compare)
cli.add_command(schedule.schedule)
cli.add_command(config.config)


@cli.command()
@pass_context
def status(ctx):
    """Show RedOPS status and configuration."""
    console.print("[bold]RedOPS Status[/bold]")
    console.print(f"  API URL: {ctx.api_url}")
    console.print(f"  API Key: {'configured' if ctx.api_key else 'not set'}")
    console.print(f"  Output Format: {ctx.output_format}")
    console.print(f"  Verbose: {ctx.verbose}")


@cli.command()
@click.argument("target")
@click.option("-p", "--pipeline", default="default", help="Scan pipeline to use")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option("--async", "async_mode", is_flag=True, help="Run scan asynchronously")
@click.option("--timeout", type=int, default=3600, help="Scan timeout in seconds")
@pass_context
def quick_scan(ctx, target, pipeline, output, async_mode, timeout):
    """Run a quick scan on a target.

    This is a shortcut for 'redops scan run'.

    \b
    Examples:
        redops quick-scan https://example.com
        redops quick-scan -p web_full example.com -o results.json
    """
    from .commands.scan import run_scan

    run_scan(
        ctx=ctx,
        target=target,
        pipeline=pipeline,
        output=output,
        async_mode=async_mode,
        timeout=timeout,
    )


@cli.command()
def init():
    """Initialize RedOPS configuration.

    Creates a default configuration file in the current directory.
    """
    config_path = Path("redops.yaml")

    if config_path.exists():
        if not click.confirm("Config file already exists. Overwrite?"):
            console.print("Aborted.")
            return

    default_config = """# RedOPS Configuration
# https://github.com/example/redops

api:
  url: http://localhost:8000
  # key: your-api-key-here

scan:
  default_pipeline: web_security
  timeout: 3600
  parallel_modules: 4

output:
  format: text
  color: true

logging:
  level: INFO
  file: redops.log

pipelines:
  quick:
    modules:
      - port_scan
      - header_check
    timeout: 300

  web_security:
    modules:
      - port_scan
      - ssl_check
      - header_check
      - xss_scan
      - sql_injection
    timeout: 1800

  full:
    modules:
      - port_scan
      - ssl_check
      - header_check
      - xss_scan
      - sql_injection
      - directory_enum
      - subdomain_enum
      - vulnerability_scan
    timeout: 7200
"""

    config_path.write_text(default_config)
    console.print(f"[green]Created {config_path}[/green]")
    console.print("Edit this file to configure RedOPS.")


@cli.command()
@click.option("--check", is_flag=True, help="Check dependencies without installing")
def doctor(check):
    """Check RedOPS installation and dependencies.

    Verifies that all required tools and dependencies are available.
    """
    console.print("[bold]RedOPS Doctor[/bold]\n")

    checks = [
        ("Python version", _check_python),
        ("Required packages", _check_packages),
        ("Nmap", _check_nmap),
        ("Network connectivity", _check_network),
        ("Database connection", _check_database),
    ]

    all_passed = True
    for name, check_func in checks:
        try:
            passed, message = check_func()
            status = "[green]✓[/green]" if passed else "[red]✗[/red]"
            console.print(f"  {status} {name}: {message}")
            if not passed:
                all_passed = False
        except Exception as e:
            console.print(f"  [red]✗[/red] {name}: Error - {e}")
            all_passed = False

    console.print()
    if all_passed:
        console.print("[green]All checks passed![/green]")
    else:
        console.print("[yellow]Some checks failed. See above for details.[/yellow]")
        sys.exit(1)


def _check_python():
    """Check Python version."""
    version = sys.version_info
    if version >= (3, 10):
        return True, f"{version.major}.{version.minor}.{version.micro}"
    return False, f"{version.major}.{version.minor} (requires 3.10+)"


def _check_packages():
    """Check required packages."""
    required = ["click", "httpx", "rich", "pydantic"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        return False, f"Missing: {', '.join(missing)}"
    return True, "All installed"


def _check_nmap():
    """Check nmap installation."""
    import shutil

    if shutil.which("nmap"):
        return True, "Found"
    return False, "Not found (optional, for port scanning)"


def _check_network():
    """Check network connectivity."""
    try:
        import socket

        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True, "Connected"
    except OSError:
        return False, "No internet connection"


def _check_database():
    """Check database connection."""
    try:
        from redops.db import get_database

        db = get_database()
        if db.check_connection():
            return True, "Connected"
        return False, "Connection failed"
    except Exception as e:
        return False, f"Not configured ({e})"


# Alias for the CLI
app = cli


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
