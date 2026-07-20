"""
Tool registry for the Ollama agent.

Maps tool names to RedOPS module functions.
Agent calls these by name in its ReAct loop.
"""

from redops.modules.active.exploit.cve_check import check_cves
from redops.modules.active.network.arp_scan import discover_hosts
from redops.modules.active.network.port_scan import scan_ports
from redops.modules.active.wireless.deauth import deauth_flood
from redops.modules.active.wireless.evil_twin import start_evil_twin
from redops.modules.active.wireless.scan import scan_access_points

TOOL_REGISTRY: dict[str, dict] = {
    "scan_access_points": {
        "fn": scan_access_points,
        "description": "Passive WiFi scan. Returns list of APs and clients.",
        "params": ["duration (int, seconds)", "channel (optional, int)"],
        "requires_authorization": True,
    },
    "start_evil_twin": {
        "fn": start_evil_twin,
        "description": "Clone target AP and start rogue access point.",
        "params": ["target_bssid (optional)", "ap_interface (str)"],
        "requires_authorization": True,
    },
    "deauth_flood": {
        "fn": deauth_flood,
        "description": "Deauth flood target AP clients.",
        "params": ["duration (int, seconds)", "count (int, frames per burst)"],
        "requires_authorization": True,
    },
    "discover_hosts": {
        "fn": discover_hosts,
        "description": "ARP scan evil twin subnet for live hosts.",
        "params": ["wait (int, seconds before scan)"],
        "requires_authorization": True,
    },
    "scan_ports": {
        "fn": scan_ports,
        "description": "nmap service scan on live hosts.",
        "params": ["ports (str, range)", "timing (str, T1-T5)"],
        "requires_authorization": True,
    },
    "check_cves": {
        "fn": check_cves,
        "description": "Cross-reference discovered services against known CVEs.",
        "params": [],
        "requires_authorization": True,
    },
}


def get_tool_descriptions() -> str:
    """Return formatted tool list for agent system prompt."""
    lines = []
    for name, info in TOOL_REGISTRY.items():
        params = ", ".join(info["params"]) if info["params"] else "none"
        lines.append(f"- {name}: {info['description']} | params: {params}")
    return "\n".join(lines)
