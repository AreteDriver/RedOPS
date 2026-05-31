"""
Wireless interface management for RF operations.

Enumerates, configures, and controls wireless adapters
including monitor mode, channel selection, and MAC spoofing.

Requires: iw, ip, aircrack-ng suite, macchanger.
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _run_cmd(
    cmd: list[str],
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command with standard options.

    Args:
        cmd: Command and arguments to execute.
        timeout: Maximum seconds to wait for completion.

    Returns:
        CompletedProcess with captured stdout/stderr.
    """
    logger.debug("Executing command: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,  # noqa: S603
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0 and result.stderr.strip():
        logger.warning(
            "Command '%s' exited %d: %s",
            " ".join(cmd),
            result.returncode,
            result.stderr.strip(),
        )
    return result


def list_wireless_interfaces() -> list[dict[str, str]]:
    """Enumerate available wireless interfaces with metadata.

    Combines output from ``iw dev`` (interface name, mode, channel, MAC)
    and ``ip link`` (driver via ethtool fallback) to build a complete
    picture of each wireless adapter.

    Returns:
        List of dicts with keys: name, mac, mode, driver, chipset, phy.
        Returns empty list if enumeration fails or no interfaces found.
    """
    interfaces: list[dict[str, str]] = []

    # --- Parse iw dev output ---
    iw_result = _run_cmd(["iw", "dev"])
    if iw_result.returncode != 0:
        logger.error("Failed to enumerate wireless interfaces via 'iw dev'")
        return interfaces

    current_phy: str = ""
    current_iface: dict[str, str] = {}

    for line in iw_result.stdout.splitlines():
        line = line.strip()

        phy_match = re.match(r"^phy#(\d+)$", line)
        if phy_match:
            if current_iface.get("name"):
                interfaces.append(current_iface)
            current_phy = f"phy{phy_match.group(1)}"
            current_iface = {"phy": current_phy}
            continue

        iface_match = re.match(r"^Interface\s+(\S+)$", line)
        if iface_match:
            if current_iface.get("name"):
                interfaces.append(current_iface)
                current_iface = {"phy": current_phy}
            current_iface["name"] = iface_match.group(1)
            continue

        addr_match = re.match(r"^addr\s+([0-9a-fA-F:]{17})$", line)
        if addr_match:
            current_iface["mac"] = addr_match.group(1).lower()
            continue

        type_match = re.match(r"^type\s+(\S+)$", line)
        if type_match:
            current_iface["mode"] = type_match.group(1)
            continue

        channel_match = re.match(r"^channel\s+(\d+)", line)
        if channel_match:
            current_iface["channel"] = channel_match.group(1)
            continue

    if current_iface.get("name"):
        interfaces.append(current_iface)

    # --- Enrich with driver info via ethtool -i ---
    for iface in interfaces:
        name = iface.get("name", "")
        driver_info = _get_driver_info(name)
        iface.setdefault("driver", driver_info.get("driver", "unknown"))
        iface.setdefault("chipset", driver_info.get("chipset", "unknown"))
        iface.setdefault("mac", "")
        iface.setdefault("mode", "unknown")

    logger.info(
        "Discovered %d wireless interface(s): %s",
        len(interfaces),
        [i["name"] for i in interfaces],
    )
    return interfaces


def _get_driver_info(interface: str) -> dict[str, str]:
    """Retrieve driver and chipset info for an interface.

    Args:
        interface: Network interface name.

    Returns:
        Dict with 'driver' and 'chipset' keys.
    """
    info: dict[str, str] = {}

    # Try ethtool first
    result = _run_cmd(["ethtool", "-i", interface])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if line.startswith("driver:"):
                info["driver"] = line.split(":", 1)[1].strip()
            elif line.startswith("firmware-version:"):
                info["chipset"] = line.split(":", 1)[1].strip()

    # Fallback: read from sysfs
    if "driver" not in info:
        driver_path = Path(f"/sys/class/net/{interface}/device/driver")
        if driver_path.is_symlink() or driver_path.exists():
            try:
                info["driver"] = driver_path.resolve().name
            except OSError:
                pass

    return info


def enable_monitor_mode(
    interface: str,
    channel: int | None = None,
) -> str:
    """Switch a wireless interface to monitor mode.

    Kills interfering processes (NetworkManager, wpa_supplicant, etc.)
    then invokes ``airmon-ng start`` to enable monitor mode.

    Args:
        interface: Managed-mode wireless interface name (e.g. "wlan0").
        channel: Optional channel to lock to during mode switch.

    Returns:
        Name of the monitor-mode interface (e.g. "wlan0mon").

    Raises:
        RuntimeError: If monitor mode could not be verified.
    """
    logger.info("Enabling monitor mode on %s", interface)

    # Kill interfering processes
    kill_result = _run_cmd(["sudo", "airmon-ng", "check", "kill"])
    if kill_result.returncode == 0:
        logger.info("Killed interfering processes")
    else:
        logger.warning("Could not kill interfering processes, continuing anyway")

    # Build airmon-ng start command
    cmd = ["sudo", "airmon-ng", "start", interface]
    if channel is not None:
        cmd.append(str(channel))

    start_result = _run_cmd(cmd)

    # Determine the monitor interface name from output
    monitor_iface = _parse_monitor_interface(start_result.stdout, interface)

    # Verify monitor mode is active
    verify_result = _run_cmd(["iw", "dev", monitor_iface, "info"])
    if "monitor" in verify_result.stdout.lower():
        logger.info("Monitor mode active on %s", monitor_iface)
    else:
        # Try the alternate naming convention
        alt_name = interface + "mon"
        if alt_name != monitor_iface:
            verify_alt = _run_cmd(["iw", "dev", alt_name, "info"])
            if "monitor" in verify_alt.stdout.lower():
                monitor_iface = alt_name
                logger.info("Monitor mode active on %s (alternate name)", monitor_iface)
            else:
                raise RuntimeError(
                    f"Failed to verify monitor mode on {interface}. "
                    f"Tried '{monitor_iface}' and '{alt_name}'."
                )
        else:
            raise RuntimeError(
                f"Failed to verify monitor mode on {monitor_iface}. "
                f"iw output: {verify_result.stdout.strip()}"
            )

    # Set channel if requested and not already set during start
    if channel is not None:
        set_channel(monitor_iface, channel)

    return monitor_iface


def _parse_monitor_interface(
    airmon_output: str,
    original_interface: str,
) -> str:
    """Extract the monitor interface name from airmon-ng output.

    Args:
        airmon_output: stdout from airmon-ng start.
        original_interface: Original interface name before mode switch.

    Returns:
        Detected monitor interface name, or conventional default.
    """
    # airmon-ng often prints: "(monitor mode vif enabled on wlan0mon)"
    match = re.search(
        r"monitor mode (?:vif )?enabled (?:for|on) \[?(\S+?)\]?\)?$",
        airmon_output,
        re.MULTILINE | re.IGNORECASE,
    )
    if match:
        name = match.group(1).rstrip(")")
        logger.debug("Parsed monitor interface from output: %s", name)
        return name

    # Fallback: conventional naming
    default = original_interface + "mon"
    logger.debug(
        "Could not parse monitor iface from output, using default: %s",
        default,
    )
    return default


def disable_monitor_mode(interface: str) -> bool:
    """Restore a monitor-mode interface to managed mode.

    Invokes ``airmon-ng stop`` and restarts NetworkManager to restore
    normal connectivity.

    Args:
        interface: Monitor-mode interface name (e.g. "wlan0mon").

    Returns:
        True if mode was successfully restored, False otherwise.
    """
    logger.info("Disabling monitor mode on %s", interface)

    stop_result = _run_cmd(["sudo", "airmon-ng", "stop", interface])

    # Restart NetworkManager so managed connections come back
    nm_result = _run_cmd(["sudo", "systemctl", "restart", "NetworkManager"])
    if nm_result.returncode != 0:
        # Try service command as fallback
        _run_cmd(["sudo", "service", "NetworkManager", "restart"])

    # Verify interface is back in managed mode
    # The original interface name is typically the mon name minus "mon"
    managed_iface = interface.replace("mon", "")
    verify = _run_cmd(["iw", "dev", managed_iface, "info"])

    if "managed" in verify.stdout.lower():
        logger.info("Interface %s restored to managed mode", managed_iface)
        return True

    if stop_result.returncode == 0:
        logger.info(
            "airmon-ng stop succeeded but could not verify managed mode on %s",
            managed_iface,
        )
        return True

    logger.error("Failed to disable monitor mode on %s", interface)
    return False


def set_channel(interface: str, channel: int) -> bool:
    """Set the operating channel of a wireless interface.

    Args:
        interface: Wireless interface name (monitor or managed mode).
        channel: WiFi channel number (1-196).

    Returns:
        True if channel was set successfully, False otherwise.
    """
    if not 1 <= channel <= 196:
        logger.error("Invalid channel number: %d (must be 1-196)", channel)
        return False

    logger.info("Setting %s to channel %d", interface, channel)
    result = _run_cmd(["sudo", "iw", "dev", interface, "set", "channel", str(channel)])

    if result.returncode == 0:
        logger.info("Channel %d set on %s", channel, interface)
        return True

    logger.error(
        "Failed to set channel %d on %s: %s",
        channel,
        interface,
        result.stderr.strip(),
    )
    return False


def spoof_mac(interface: str) -> str:
    """Randomize the MAC address of a wireless interface.

    Brings the interface down, applies a random MAC via ``macchanger -r``,
    then brings it back up.

    Args:
        interface: Network interface name.

    Returns:
        The new randomized MAC address string.

    Raises:
        RuntimeError: If MAC spoofing fails.
    """
    logger.info("Spoofing MAC address on %s", interface)

    # Bring interface down first
    down_result = _run_cmd(["sudo", "ip", "link", "set", interface, "down"])
    if down_result.returncode != 0:
        raise RuntimeError(
            f"Failed to bring down {interface}: {down_result.stderr.strip()}"
        )

    # Randomize MAC
    spoof_result = _run_cmd(["sudo", "macchanger", "-r", interface])
    if spoof_result.returncode != 0:
        # Bring interface back up before raising
        _run_cmd(["sudo", "ip", "link", "set", interface, "up"])
        raise RuntimeError(
            f"macchanger failed on {interface}: {spoof_result.stderr.strip()}"
        )

    # Parse the new MAC from macchanger output
    new_mac = _parse_macchanger_output(spoof_result.stdout)

    # Bring interface back up
    up_result = _run_cmd(["sudo", "ip", "link", "set", interface, "up"])
    if up_result.returncode != 0:
        logger.warning("Failed to bring %s back up after MAC spoof", interface)

    logger.info("MAC address on %s spoofed to %s", interface, new_mac)
    return new_mac


def _parse_macchanger_output(output: str) -> str:
    """Extract the new MAC address from macchanger output.

    Args:
        output: stdout from macchanger command.

    Returns:
        New MAC address string, or "unknown" if parsing fails.
    """
    # macchanger prints: "New MAC:   xx:xx:xx:xx:xx:xx (vendor)"
    match = re.search(
        r"New\s+MAC:\s+([0-9a-fA-F:]{17})",
        output,
    )
    if match:
        return match.group(1).lower()

    logger.warning("Could not parse new MAC from macchanger output")
    return "unknown"


def get_interface_status(interface: str) -> dict[str, Any]:
    """Get comprehensive status information for a wireless interface.

    Queries ``iw dev <iface> info``, ``iw dev <iface> link``, and
    ``ip link show <iface>`` to collect mode, channel, signal strength,
    MAC address, and operational state.

    Args:
        interface: Wireless interface name.

    Returns:
        Dict with keys: name, mac, mode, channel, frequency, signal,
        tx_power, state, ssid. Missing fields default to None.
    """
    status: dict[str, Any] = {
        "name": interface,
        "mac": None,
        "mode": None,
        "channel": None,
        "frequency": None,
        "signal": None,
        "tx_power": None,
        "state": None,
        "ssid": None,
    }

    # --- iw dev info ---
    info_result = _run_cmd(["iw", "dev", interface, "info"])
    if info_result.returncode == 0:
        _parse_iw_info(info_result.stdout, status)

    # --- iw dev link (for signal/ssid when associated) ---
    link_result = _run_cmd(["iw", "dev", interface, "link"])
    if link_result.returncode == 0:
        _parse_iw_link(link_result.stdout, status)

    # --- ip link for MAC and state ---
    ip_result = _run_cmd(["ip", "link", "show", interface])
    if ip_result.returncode == 0:
        _parse_ip_link(ip_result.stdout, status)

    logger.debug("Interface status for %s: %s", interface, status)
    return status


def _parse_iw_info(output: str, status: dict[str, Any]) -> None:
    """Parse ``iw dev <iface> info`` output into status dict.

    Args:
        output: stdout from iw dev info.
        status: Status dict to update in-place.
    """
    for line in output.splitlines():
        line = line.strip()

        if line.startswith("type "):
            status["mode"] = line.split(None, 1)[1]
        elif line.startswith("channel "):
            # "channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz"
            ch_match = re.match(r"channel\s+(\d+)\s+\((\d+)\s+MHz\)", line)
            if ch_match:
                status["channel"] = int(ch_match.group(1))
                status["frequency"] = int(ch_match.group(2))
        elif line.startswith("txpower "):
            tp_match = re.match(r"txpower\s+([\d.]+)\s+dBm", line)
            if tp_match:
                status["tx_power"] = float(tp_match.group(1))
        elif line.startswith("addr "):
            status["mac"] = line.split(None, 1)[1].lower()


def _parse_iw_link(output: str, status: dict[str, Any]) -> None:
    """Parse ``iw dev <iface> link`` output into status dict.

    Args:
        output: stdout from iw dev link.
        status: Status dict to update in-place.
    """
    for line in output.splitlines():
        line = line.strip()

        if line.startswith("signal:"):
            sig_match = re.match(r"signal:\s*(-?\d+)\s*dBm", line)
            if sig_match:
                status["signal"] = int(sig_match.group(1))
        elif line.startswith("SSID:"):
            status["ssid"] = line.split(":", 1)[1].strip()


def _parse_ip_link(output: str, status: dict[str, Any]) -> None:
    """Parse ``ip link show <iface>`` output into status dict.

    Args:
        output: stdout from ip link show.
        status: Status dict to update in-place.
    """
    # State: look for <...,UP,...> or state UP/DOWN
    state_match = re.search(r"state\s+(\S+)", output)
    if state_match:
        status["state"] = state_match.group(1)

    # MAC address from link/ether line
    mac_match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", output)
    if mac_match and status["mac"] is None:
        status["mac"] = mac_match.group(1).lower()
