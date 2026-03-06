"""
Passive AP and client enumeration via airodump-ng.

Produces structured AP list for evil twin targeting.
Requires: aircrack-ng suite, monitor mode active.
"""

import csv
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from redops.core.context import Context


def scan_access_points(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Passive scan for nearby APs and connected clients.

    Params:
        duration: Scan duration in seconds. Default: 30
        channel: Lock to specific channel. Default: None (all channels)

    Adds to context:
        access_points: list of dicts with bssid, essid, channel, signal, encryption
        clients: list of dicts with mac, associated_bssid, signal
        scan_complete: bool
    """
    params = params or {}
    duration = params.get("duration", 30)
    channel = params.get("channel")
    monitor_iface = ctx.get("monitor_interface", "wlan1mon")

    with tempfile.TemporaryDirectory() as tmpdir:
        output_prefix = str(Path(tmpdir) / "scan")

        cmd = [
            "sudo",
            "airodump-ng",
            "--output-format",
            "csv",
            "--write",
            output_prefix,
        ]
        if channel:
            cmd += ["--channel", str(channel)]
        cmd.append(monitor_iface)

        ctx.log(f"Scanning for {duration}s on {monitor_iface}", level="INFO")

        proc = subprocess.Popen(
            cmd,  # noqa: S603
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait()

        csv_file = output_prefix + "-01.csv"
        access_points, clients = _parse_airodump_csv(csv_file)

    ctx.add("access_points", access_points)
    ctx.add("clients", clients)
    ctx.add("scan_complete", True)

    ctx.log(
        f"Found {len(access_points)} APs, {len(clients)} clients",
        level="INFO",
    )
    return ctx


def _parse_airodump_csv(filepath: str) -> tuple[list[dict], list[dict]]:
    """Parse airodump-ng CSV output into structured AP and client lists."""
    access_points: list[dict] = []
    clients: list[dict] = []

    if not Path(filepath).exists():
        return access_points, clients

    content = Path(filepath).read_bytes().decode("utf-8", errors="replace")

    # airodump CSV has two sections separated by blank line
    # Normalize line endings first (real airodump uses \r\n)
    content = content.replace("\r\n", "\n")
    sections = content.split("\n\n")
    if len(sections) < 1:
        return access_points, clients

    # Parse APs (first section)
    ap_lines = sections[0].strip().splitlines()
    if len(ap_lines) > 1:
        ap_fields = [
            "BSSID",
            "First time seen",
            "Last time seen",
            "channel",
            "Speed",
            "Privacy",
            "Cipher",
            "Authentication",
            "Power",
            "beacons",
            "IV",
            "LAN IP",
            "ID-length",
            "ESSID",
            "Key",
        ]
        reader = csv.DictReader(ap_lines[1:], fieldnames=ap_fields)
        for row in reader:
            bssid = (row.get("BSSID") or "").strip()
            essid = (row.get("ESSID") or "").strip()
            if bssid and len(bssid) == 17:
                access_points.append(
                    {
                        "bssid": bssid,
                        "essid": essid,
                        "channel": (row.get("channel") or "").strip(),
                        "signal": (row.get("Power") or "").strip(),
                        "encryption": (row.get("Privacy") or "").strip(),
                    }
                )

    # Parse clients (second section)
    if len(sections) > 1:
        client_lines = sections[1].strip().splitlines()
        if len(client_lines) > 1:
            client_fields = [
                "Station MAC",
                "First time seen",
                "Last time seen",
                "Power",
                "packets",
                "BSSID",
                "Probed ESSIDs",
            ]
            reader = csv.DictReader(client_lines[1:], fieldnames=client_fields)
            for row in reader:
                mac = (row.get("Station MAC") or "").strip()
                if mac and len(mac) == 17:
                    clients.append(
                        {
                            "mac": mac,
                            "associated_bssid": (row.get("BSSID") or "").strip(),
                            "signal": (row.get("Power") or "").strip(),
                        }
                    )

    return access_points, clients
