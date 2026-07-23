"""
ARP host discovery on captured subnet.

Identifies live hosts after clients connect to evil twin.
"""

import re
import subprocess
import time
from typing import Any

from redops.core.context import Context
from redops.modules.active.authorization import assert_active_authorized


def discover_hosts(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Run ARP scan on evil twin subnet to discover connected hosts.

    Params:
        subnet: CIDR range. Default: reads from context (ap_subnet)
        wait: Seconds to wait for clients before scanning. Default: 15

    Adds to context:
        live_hosts: list of dicts with ip, mac, vendor
    """
    assert_active_authorized(ctx)
    params = params or {}
    subnet = params.get("subnet") or ctx.get("ap_subnet", "192.168.99.0/24")
    wait = params.get("wait", 15)

    ctx.log(f"Waiting {wait}s for clients to connect...", level="INFO")
    time.sleep(wait)

    ctx.log(f"ARP scanning {subnet}", level="INFO")
    result = subprocess.run(
        ["sudo", "arp-scan", "--localnet", subnet],  # noqa: S603, S607
        capture_output=True,
        text=True,
    )

    hosts: list[dict] = []
    for line in result.stdout.splitlines():
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)", line)
        if match:
            hosts.append(
                {
                    "ip": match.group(1),
                    "mac": match.group(2),
                    "vendor": match.group(3).strip(),
                }
            )

    ctx.add("live_hosts", hosts)
    ctx.log(f"Discovered {len(hosts)} live hosts", level="INFO")
    return ctx
