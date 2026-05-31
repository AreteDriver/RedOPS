"""Parser for airodump-ng CSV output.

Handles the two-section CSV format produced by airodump-ng:
access points section, followed by a blank line, then clients section.
"""

import csv
import io
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _clean_field(value: str) -> str:
    """Strip whitespace from a CSV field value.

    Args:
        value: Raw field value from CSV.

    Returns:
        Stripped string.
    """
    return value.strip() if value else ""


def _parse_int(value: str, default: int = 0) -> int:
    """Safely parse an integer from a string.

    Args:
        value: String to parse.
        default: Value to return on failure.

    Returns:
        Parsed integer or default.
    """
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


def _parse_ap_row(row: list[str]) -> dict | None:
    """Parse a single access point row from airodump CSV.

    Args:
        row: List of field values from CSV reader.

    Returns:
        Dict with AP data, or None if row is invalid.
    """
    if len(row) < 14:
        return None

    bssid = _clean_field(row[0])
    if not bssid or len(bssid) != 17:
        return None

    return {
        "bssid": bssid,
        "first_seen": _clean_field(row[1]),
        "last_seen": _clean_field(row[2]),
        "channel": _parse_int(row[3]),
        "speed": _parse_int(row[4]),
        "encryption": _clean_field(row[5]),
        "cipher": _clean_field(row[6]),
        "authentication": _clean_field(row[7]),
        "signal": _parse_int(row[8]),
        "beacons": _parse_int(row[9]),
        "data_frames": _parse_int(row[10]),
        "wps": _clean_field(row[11]) if len(row) > 11 else "",
        "essid": _clean_field(row[13]) if len(row) > 13 else "",
    }


def _parse_client_row(row: list[str]) -> dict | None:
    """Parse a single client row from airodump CSV.

    Args:
        row: List of field values from CSV reader.

    Returns:
        Dict with client data, or None if row is invalid.
    """
    if len(row) < 6:
        return None

    mac = _clean_field(row[0])
    if not mac or len(mac) != 17:
        return None

    probes_raw = _clean_field(row[6]) if len(row) > 6 else ""
    probes = [p.strip() for p in probes_raw.split(",") if p.strip()]

    return {
        "mac": mac,
        "first_seen": _clean_field(row[1]),
        "last_seen": _clean_field(row[2]),
        "signal": _parse_int(row[3]),
        "packets": _parse_int(row[4]),
        "bssid": _clean_field(row[5]),
        "probes": probes,
    }


def parse_airodump_csv(
    filepath: Path,
) -> tuple[list[dict], list[dict]]:
    """Parse an airodump-ng CSV file into structured data.

    Airodump-ng produces a CSV with two sections separated by a blank
    line. The first section contains access points, the second contains
    associated and unassociated clients.

    Args:
        filepath: Path to the airodump-ng CSV file.

    Returns:
        Tuple of (access_points, clients) where each is a list of dicts.
        AP dict keys: bssid, essid, channel, signal, encryption, wps,
            first_seen, last_seen, beacons, data_frames.
        Client dict keys: mac, bssid, signal, probes, first_seen,
            last_seen, packets.

    Raises:
        FileNotFoundError: If the CSV file does not exist.
        PermissionError: If the file cannot be read.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"Airodump CSV not found: {filepath}")

    content = filepath.read_text(encoding="utf-8", errors="replace")
    sections = content.split("\n\n")

    access_points: list[dict] = []
    clients: list[dict] = []

    # Parse access points section
    if len(sections) >= 1:
        ap_section = sections[0].strip()
        if ap_section:
            reader = csv.reader(io.StringIO(ap_section))
            for i, row in enumerate(reader):
                if i == 0:
                    # Skip header row
                    continue
                ap = _parse_ap_row(row)
                if ap is not None:
                    access_points.append(ap)

    # Parse clients section
    if len(sections) >= 2:
        client_section = sections[1].strip()
        if client_section:
            reader = csv.reader(io.StringIO(client_section))
            for i, row in enumerate(reader):
                if i == 0:
                    # Skip header row
                    continue
                client = _parse_client_row(row)
                if client is not None:
                    clients.append(client)

    logger.info(
        "Parsed airodump CSV: %d APs, %d clients from %s",
        len(access_points),
        len(clients),
        filepath,
    )

    return access_points, clients
