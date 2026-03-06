"""
Attack surface summarizer for agent context window.

Converts raw Context findings into a structured prompt the agent can reason over.
"""

from redops.core.context import Context

MAX_ITEMS_PER_SECTION = 10


def build_attack_surface_summary(ctx: Context) -> str:
    """
    Produce a structured text summary of all findings for the agent prompt.
    Keeps it dense — agent needs signal, not noise.
    """
    lines = ["=== CURRENT ATTACK SURFACE ==="]

    aps = ctx.get("access_points", [])
    if aps:
        lines.append(f"\nACCESS POINTS ({len(aps)} found):")
        for ap in aps[:MAX_ITEMS_PER_SECTION]:
            lines.append(
                f"  {ap['bssid']} | {ap['essid']} | ch{ap['channel']} | "
                f"{ap['encryption']} | {ap['signal']}dBm"
            )

    clients = ctx.get("clients", [])
    if clients:
        lines.append(f"\nCLIENTS ({len(clients)} found):")
        for c in clients[:MAX_ITEMS_PER_SECTION]:
            lines.append(f"  {c['mac']} -> {c['associated_bssid']} | {c['signal']}dBm")

    hosts = ctx.get("live_hosts", [])
    if hosts:
        lines.append(f"\nLIVE HOSTS ({len(hosts)} on evil twin subnet):")
        for h in hosts:
            lines.append(f"  {h['ip']} | {h['mac']} | {h['vendor']}")

    scan_results = ctx.get("port_scan_results", [])
    if scan_results:
        lines.append("\nOPEN PORTS:")
        for host in scan_results:
            for p in host["open_ports"]:
                lines.append(
                    f"  {host['ip']}:{p['port']}/{p['protocol']} "
                    f"| {p['service']} {p['version']}"
                )

    cves = ctx.get("cve_findings", [])
    if cves:
        lines.append(f"\nCVE FINDINGS ({len(cves)}):")
        for c in cves:
            lines.append(
                f"  [{c['cvss']} CVSS] {c['id']} @ {c['ip']}:{c['port']} "
                f"-- {c['description']}"
            )

    hvt = ctx.get("high_value_targets", [])
    if hvt:
        lines.append(f"\nHIGH VALUE TARGETS ({len(hvt)}):")
        for t in hvt:
            lines.append(
                f"  *** {t['ip']}:{t['port']} -> {t['id']} (CVSS {t['cvss']}) ***"
            )

    lines.append("\n=== END ATTACK SURFACE ===")
    return "\n".join(lines)
