"""Config commands for RedOPS CLI."""

import os
import sys
from pathlib import Path
from typing import Optional

import click
import yaml

from ..utils import (
    console,
    output_result,
    print_error,
    print_success,
    load_config,
)


CONFIG_PATHS = [
    Path("redops.yaml"),
    Path("redops.yml"),
    Path(".redops.yaml"),
    Path.home() / ".config" / "redops" / "config.yaml",
    Path.home() / ".redops.yaml",
]


@click.group()
def config():
    """Configuration management commands.

    \b
    Examples:
        redops config show
        redops config set api.url http://localhost:8000
        redops config get api.url
    """
    pass


@config.command("show")
@click.option(
    "--path",
    type=click.Path(exists=True),
    help="Config file path"
)
@click.pass_context
def show_cmd(ctx, path):
    """Show current configuration.

    \b
    Examples:
        redops config show
        redops config show --path custom.yaml
    """
    ctx = ctx.obj

    # Find config file
    config_path = _find_config_file(path)

    if config_path:
        console.print(f"[dim]Config file: {config_path}[/dim]\n")
        config_data = load_config(str(config_path))
        output_result(config_data, format=ctx.output_format, title="Configuration")
    else:
        console.print("[yellow]No config file found[/yellow]")
        console.print("\nUsing defaults:")
        console.print(f"  API URL: {ctx.api_url}")
        console.print(f"  API Key: {'set' if ctx.api_key else 'not set'}")
        console.print("\nRun 'redops init' to create a config file.")


@config.command("get")
@click.argument("key")
@click.option(
    "--path",
    type=click.Path(exists=True),
    help="Config file path"
)
def get_cmd(key, path):
    """Get a configuration value.

    KEY is a dot-separated path (e.g., api.url)

    \b
    Examples:
        redops config get api.url
        redops config get scan.timeout
    """
    config_path = _find_config_file(path)

    if not config_path:
        print_error("No config file found")
        sys.exit(1)

    config_data = load_config(str(config_path))

    # Navigate to key
    parts = key.split(".")
    value = config_data

    try:
        for part in parts:
            value = value[part]
        console.print(str(value))
    except (KeyError, TypeError):
        print_error(f"Key not found: {key}")
        sys.exit(1)


@config.command("set")
@click.argument("key")
@click.argument("value")
@click.option(
    "--path",
    type=click.Path(),
    help="Config file path"
)
def set_cmd(key, value, path):
    """Set a configuration value.

    KEY is a dot-separated path (e.g., api.url)
    VALUE is the new value to set

    \b
    Examples:
        redops config set api.url http://localhost:8000
        redops config set scan.timeout 7200
    """
    config_path = _find_config_file(path)

    if not config_path:
        # Create default config file
        config_path = Path("redops.yaml")
        config_data = {}
    else:
        config_data = load_config(str(config_path))

    # Set value
    parts = key.split(".")
    current = config_data

    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]

    # Try to convert value to appropriate type
    final_value = _parse_value(value)
    current[parts[-1]] = final_value

    # Write config
    config_path.write_text(yaml.dump(config_data, default_flow_style=False))
    print_success(f"Set {key} = {final_value}")


@config.command("unset")
@click.argument("key")
@click.option(
    "--path",
    type=click.Path(exists=True),
    help="Config file path"
)
def unset_cmd(key, path):
    """Remove a configuration value.

    KEY is a dot-separated path (e.g., api.url)

    \b
    Examples:
        redops config unset api.key
    """
    config_path = _find_config_file(path)

    if not config_path:
        print_error("No config file found")
        sys.exit(1)

    config_data = load_config(str(config_path))

    # Navigate to parent and delete key
    parts = key.split(".")
    current = config_data

    try:
        for part in parts[:-1]:
            current = current[part]
        del current[parts[-1]]
    except (KeyError, TypeError):
        print_error(f"Key not found: {key}")
        sys.exit(1)

    # Write config
    config_path.write_text(yaml.dump(config_data, default_flow_style=False))
    print_success(f"Removed {key}")


@config.command("path")
def path_cmd():
    """Show config file search paths.

    \b
    Examples:
        redops config path
    """
    console.print("[bold]Config file search paths:[/bold]\n")

    for i, p in enumerate(CONFIG_PATHS, 1):
        exists = p.exists()
        status = "[green]✓ exists[/green]" if exists else "[dim]not found[/dim]"
        console.print(f"  {i}. {p} {status}")

    console.print("\n[dim]First found file will be used.[/dim]")

    # Check environment variable
    env_config = os.environ.get("REDOPS_CONFIG")
    if env_config:
        console.print(f"\n[yellow]REDOPS_CONFIG env var: {env_config}[/yellow]")


@config.command("validate")
@click.option(
    "--path",
    type=click.Path(exists=True),
    help="Config file path"
)
def validate_cmd(path):
    """Validate configuration file.

    \b
    Examples:
        redops config validate
        redops config validate --path custom.yaml
    """
    config_path = _find_config_file(path)

    if not config_path:
        print_error("No config file found")
        sys.exit(1)

    console.print(f"[dim]Validating: {config_path}[/dim]\n")

    try:
        config_data = load_config(str(config_path))
    except Exception as e:
        print_error(f"Failed to parse config: {e}")
        sys.exit(1)

    errors = []
    warnings = []

    # Validate required fields
    if "api" in config_data:
        api = config_data["api"]
        if "url" in api and not api["url"].startswith(("http://", "https://")):
            errors.append("api.url must start with http:// or https://")

    # Validate scan config
    if "scan" in config_data:
        scan = config_data["scan"]
        if "timeout" in scan:
            if not isinstance(scan["timeout"], int) or scan["timeout"] < 0:
                errors.append("scan.timeout must be a positive integer")
        if "parallel_modules" in scan:
            if not isinstance(scan["parallel_modules"], int) or scan["parallel_modules"] < 1:
                errors.append("scan.parallel_modules must be a positive integer")

    # Validate pipelines
    if "pipelines" in config_data:
        for name, pipeline in config_data["pipelines"].items():
            if not isinstance(pipeline, dict):
                errors.append(f"pipeline '{name}' must be a dictionary")
            elif "modules" not in pipeline:
                warnings.append(f"pipeline '{name}' has no modules defined")

    # Report results
    if errors:
        console.print("[red]Errors:[/red]")
        for error in errors:
            console.print(f"  [red]✗[/red] {error}")

    if warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for warning in warnings:
            console.print(f"  [yellow]![/yellow] {warning}")

    if not errors and not warnings:
        print_success("Configuration is valid")
    elif not errors:
        console.print("\n[yellow]Configuration has warnings but is valid[/yellow]")
    else:
        console.print("\n[red]Configuration has errors[/red]")
        sys.exit(1)


def _find_config_file(explicit_path: Optional[str] = None) -> Optional[Path]:
    """Find the config file to use."""
    if explicit_path:
        return Path(explicit_path)

    # Check environment variable
    env_path = os.environ.get("REDOPS_CONFIG")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    # Search standard paths
    for p in CONFIG_PATHS:
        if p.exists():
            return p

    return None


def _parse_value(value: str):
    """Parse a string value to appropriate type."""
    # Boolean
    if value.lower() in ("true", "yes", "on"):
        return True
    if value.lower() in ("false", "no", "off"):
        return False

    # Integer
    try:
        return int(value)
    except ValueError:
        pass

    # Float
    try:
        return float(value)
    except ValueError:
        pass

    # String
    return value
