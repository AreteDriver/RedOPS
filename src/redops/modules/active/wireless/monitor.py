"""
Monitor mode control for wireless interface.

Wraps airmon-ng for adapter state management.
Requires: aircrack-ng suite, root privileges.
"""

import re
import subprocess
from typing import Any

from redops.core.context import Context


def get_wireless_interfaces() -> list[str]:
    """Return list of available wireless interface names."""
    result = subprocess.run(
        ["iwconfig"],
        capture_output=True,
        text=True,  # noqa: S603, S607
    )
    return re.findall(r"^(\w+)\s+IEEE", result.stdout, re.MULTILINE)


def enable_monitor_mode(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Switch wireless adapter to monitor mode via airmon-ng.

    Params:
        interface: Wireless interface name. Default: 'wlan1'

    Adds to context:
        monitor_interface: Monitor mode interface name (e.g. wlan1mon)
        monitor_ready: True if mode switch succeeded
    """
    params = params or {}
    interface = params.get("interface", "wlan1")

    ctx.log("Killing interfering processes", level="INFO")
    subprocess.run(
        ["sudo", "airmon-ng", "check", "kill"],  # noqa: S603, S607
        capture_output=True,
    )

    ctx.log(f"Enabling monitor mode on {interface}", level="INFO")
    subprocess.run(
        ["sudo", "airmon-ng", "start", interface],  # noqa: S603, S607
        capture_output=True,
        text=True,
    )

    monitor_iface = interface + "mon"

    verify = subprocess.run(
        ["iwconfig", monitor_iface],  # noqa: S603, S607
        capture_output=True,
        text=True,
    )
    if "Monitor" in verify.stdout:
        ctx.add("monitor_interface", monitor_iface)
        ctx.add("monitor_ready", True)
        ctx.log(f"Monitor mode active: {monitor_iface}", level="INFO")
    else:
        ctx.add("monitor_ready", False)
        ctx.log(f"Monitor mode failed on {interface}", level="ERROR")

    return ctx


def disable_monitor_mode(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Restore adapter to managed mode.

    Params:
        interface: Monitor interface to stop. Default: reads from context.
    """
    params = params or {}
    monitor_iface = params.get("interface") or ctx.get("monitor_interface", "wlan1mon")

    subprocess.run(
        ["sudo", "airmon-ng", "stop", monitor_iface],  # noqa: S603, S607
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "service", "NetworkManager", "restart"],  # noqa: S603, S607
        capture_output=True,
    )

    ctx.log("Monitor mode disabled, NetworkManager restarted", level="INFO")
    ctx.add("monitor_ready", False)
    return ctx
