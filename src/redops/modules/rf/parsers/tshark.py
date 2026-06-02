"""Parser for tshark JSON output and pcap analysis.

Builds tshark commands, parses -T ek JSON output, and provides
pcap summary statistics without loading captures into Python memory.
"""

import json
import logging
import subprocess
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)


def build_tshark_stats_command(
    interface: str,
    duration: int,
) -> list[str]:
    """Build a tshark command for capture statistics.

    Constructs a command list suitable for subprocess that will
    capture on the given interface for the specified duration
    and output in Elasticsearch JSON format.

    Args:
        interface: Network interface name (e.g., 'wlan0mon').
        duration: Capture duration in seconds.

    Returns:
        List of command arguments for subprocess.

    Raises:
        ValueError: If interface is empty or duration is not positive.
    """
    if not interface or not interface.strip():
        raise ValueError("Interface must not be empty")
    if duration <= 0:
        raise ValueError("Duration must be a positive integer")

    return [
        "tshark",
        "-i",
        interface.strip(),
        "-a",
        f"duration:{duration}",
        "-T",
        "ek",
        "-l",
    ]


def parse_tshark_json(json_line: str) -> dict | None:
    """Parse a single tshark -T ek JSON line.

    Tshark's Elasticsearch (-T ek) output produces one JSON
    object per line. This function parses a single line and
    extracts commonly useful fields.

    Args:
        json_line: A single line of tshark -T ek JSON output.

    Returns:
        Dict with parsed packet data, or None if the line is
        not a valid packet record. Keys may include:
        - timestamp: str
        - layers: dict (protocol layer data)
        - src_ip: str | None
        - dst_ip: str | None
        - src_mac: str | None
        - dst_mac: str | None
        - protocol: str | None
        - length: int | None
    """
    if not json_line or not json_line.strip():
        return None

    try:
        data = json.loads(json_line.strip())
    except json.JSONDecodeError:
        logger.debug("Invalid JSON line: %.100s", json_line)
        return None

    # tshark -T ek produces index lines and packet lines
    # Skip index/metadata lines
    if "index" in data or "layers" not in data:
        return None

    layers = data.get("layers", {})
    result: dict = {
        "timestamp": data.get("timestamp"),
        "layers": layers,
    }

    # Extract common fields from layers
    frame = layers.get("frame", {})
    if frame:
        length_val = frame.get("frame_frame_len")
        if isinstance(length_val, list):
            length_val = length_val[0] if length_val else None
        try:
            result["length"] = int(length_val) if length_val else None
        except (ValueError, TypeError):
            result["length"] = None

        protocols = frame.get("frame_frame_protocols")
        if isinstance(protocols, list):
            protocols = protocols[0] if protocols else None
        result["protocol"] = protocols

    # Ethernet layer
    eth = layers.get("eth", {})
    if eth:
        src_mac = eth.get("eth_eth_src")
        dst_mac = eth.get("eth_eth_dst")
        result["src_mac"] = src_mac[0] if isinstance(src_mac, list) else src_mac
        result["dst_mac"] = dst_mac[0] if isinstance(dst_mac, list) else dst_mac

    # IP layer
    ip_layer = layers.get("ip", {})
    if ip_layer:
        src_ip = ip_layer.get("ip_ip_src")
        dst_ip = ip_layer.get("ip_ip_dst")
        result["src_ip"] = src_ip[0] if isinstance(src_ip, list) else src_ip
        result["dst_ip"] = dst_ip[0] if isinstance(dst_ip, list) else dst_ip

    return result


def get_pcap_summary(
    pcap_path: Path,
    max_packets: int = 1000,
) -> dict:
    """Generate summary statistics for a pcap file.

    Runs tshark as a subprocess to analyze the pcap without
    loading it into Python memory. Extracts packet counts,
    protocol distribution, and top source/destination addresses.

    Args:
        pcap_path: Path to the pcap/pcapng file.
        max_packets: Maximum number of packets to analyze.
            Defaults to 1000.

    Returns:
        Dict with summary statistics:
        - file: str (path analyzed)
        - packet_count: int
        - protocols: dict[str, int] (protocol name to count)
        - top_talkers: dict[str, int] (IP/MAC to packet count)
        - error: str | None

    Raises:
        FileNotFoundError: If the pcap file does not exist.
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap file not found: {pcap_path}")

    result: dict = {
        "file": str(pcap_path),
        "packet_count": 0,
        "protocols": {},
        "top_talkers": {},
        "error": None,
    }

    cmd = [
        "tshark",
        "-r",
        str(pcap_path),
        "-c",
        str(max_packets),
        "-T",
        "ek",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        if proc.returncode != 0 and not proc.stdout:
            result["error"] = (
                f"tshark exited with code {proc.returncode}: {proc.stderr[:200]}"
            )
            return result

        protocols: Counter[str] = Counter()
        talkers: Counter[str] = Counter()
        packet_count = 0

        for line in proc.stdout.splitlines():
            parsed = parse_tshark_json(line)
            if parsed is None:
                continue

            packet_count += 1

            # Count protocols
            proto = parsed.get("protocol")
            if proto:
                # Use the highest-layer protocol
                proto_parts = proto.split(":")
                top_proto = proto_parts[-1] if proto_parts else proto
                protocols[top_proto] += 1

            # Count talkers by IP (preferred) or MAC
            src = parsed.get("src_ip") or parsed.get("src_mac")
            if src:
                talkers[src] += 1

        result["packet_count"] = packet_count
        result["protocols"] = dict(protocols.most_common(20))
        result["top_talkers"] = dict(talkers.most_common(20))

    except FileNotFoundError:
        result["error"] = "tshark not found in PATH"
        logger.error("tshark binary not found")
    except subprocess.TimeoutExpired:
        result["error"] = "tshark timed out after 120s"
        logger.error("tshark timed out on %s", pcap_path)

    logger.info(
        "pcap summary for %s: %d packets, %d protocols",
        pcap_path.name,
        result["packet_count"],
        len(result["protocols"]),
    )

    return result
