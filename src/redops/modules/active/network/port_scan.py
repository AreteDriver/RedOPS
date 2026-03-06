"""
nmap port scan + service version detection on discovered hosts.
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import Any

from redops.core.context import Context

NMAP_TIMEOUT = 120


def scan_ports(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Run nmap service scan on live hosts.

    Params:
        ports: Port range. Default: 'T:1-1024,U:23,2323'
        timing: nmap timing template. Default: 'T4'

    Adds to context:
        port_scan_results: list of dicts with ip, open_ports
    """
    params = params or {}
    ports = params.get("ports", "T:1-1024,U:23,2323")
    timing = params.get("timing", "T4")

    hosts = ctx.get("live_hosts", [])
    if not hosts:
        ctx.log("No live hosts in context. Run arp_scan first.", level="ERROR")
        return ctx

    results: list[dict] = []

    for host in hosts:
        ip = host["ip"]
        ctx.log(f"Port scanning {ip}", level="INFO")
        cmd = [
            "sudo",
            "nmap",
            "-sV",
            "-sU",
            "-p",
            ports,
            f"-{timing}",
            "-oX",
            "-",
            ip,
        ]
        result = subprocess.run(
            cmd,  # noqa: S603
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
        )

        open_ports = _parse_nmap_xml(result.stdout)
        results.append({"ip": ip, "open_ports": open_ports})
        ctx.log(f"{ip}: {len(open_ports)} open ports", level="INFO")

    ctx.add("port_scan_results", results)
    return ctx


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    """Parse nmap XML output into structured port list."""
    ports: list[dict] = []
    try:
        root = ET.fromstring(xml_output)  # noqa: S314
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                service = port.find("service")
                ports.append(
                    {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "service": service.get("name", "")
                        if service is not None
                        else "",
                        "version": service.get("version", "")
                        if service is not None
                        else "",
                        "product": service.get("product", "")
                        if service is not None
                        else "",
                    }
                )
    except ET.ParseError:
        pass
    return ports
