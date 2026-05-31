"""Parser for hcxdumptool status output and capture detection.

Parses real-time status lines from hcxdumptool and uses hcxpcapngtool
to analyze pcapng files for PMKID and handshake captures.
"""

import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Patterns for hcxdumptool status lines
_STATUS_PATTERNS: dict[str, re.Pattern[str]] = {
    "packets": re.compile(
        r"^\[(\d+)\]\s+packets:\s*(\d+)",
    ),
    "essid": re.compile(
        r"ESSID:\s*(.+?)(?:\s+BSSID:|$)",
    ),
    "bssid": re.compile(
        r"BSSID:\s*([0-9a-fA-F:]{17})",
    ),
    "client": re.compile(
        r"CLIENT:\s*([0-9a-fA-F:]{17})",
    ),
    "pmkid": re.compile(
        r"PMKID",
        re.IGNORECASE,
    ),
    "eapol": re.compile(
        r"EAPOL",
        re.IGNORECASE,
    ),
}


def parse_hcx_status(line: str) -> dict | None:
    """Parse a single hcxdumptool status output line.

    Extracts packet counts, BSSID/ESSID references, and capture
    event indicators from hcxdumptool's stdout.

    Args:
        line: A single line of hcxdumptool stdout output.

    Returns:
        Dict with parsed fields, or None if the line is not
        a recognized status format. Possible keys:
        - timestamp: int (seconds since start)
        - packets: int (total packet count)
        - bssid: str (target BSSID if present)
        - essid: str (target ESSID if present)
        - client: str (client MAC if present)
        - pmkid_detected: bool
        - eapol_detected: bool
    """
    if not line or not line.strip():
        return None

    line = line.strip()
    result: dict = {}

    # Check for packet count line
    packets_match = _STATUS_PATTERNS["packets"].search(line)
    if packets_match:
        result["timestamp"] = int(packets_match.group(1))
        result["packets"] = int(packets_match.group(2))

    # Extract BSSID
    bssid_match = _STATUS_PATTERNS["bssid"].search(line)
    if bssid_match:
        result["bssid"] = bssid_match.group(1).upper()

    # Extract ESSID
    essid_match = _STATUS_PATTERNS["essid"].search(line)
    if essid_match:
        result["essid"] = essid_match.group(1).strip()

    # Extract client MAC
    client_match = _STATUS_PATTERNS["client"].search(line)
    if client_match:
        result["client"] = client_match.group(1).upper()

    # Detect capture events
    result["pmkid_detected"] = bool(_STATUS_PATTERNS["pmkid"].search(line))
    result["eapol_detected"] = bool(_STATUS_PATTERNS["eapol"].search(line))

    if not result:
        return None

    return result


def check_for_captures(pcapng_path: Path) -> dict:
    """Analyze a pcapng file for PMKID and handshake captures.

    Runs hcxpcapngtool with --info=stdout to extract summary
    information about captured authentication material.

    Args:
        pcapng_path: Path to the pcapng capture file.

    Returns:
        Dict with capture analysis results:
        - file: str (path analyzed)
        - pmkids: int (count of PMKIDs found)
        - handshakes: int (count of EAPOL handshakes found)
        - best_handshakes: int (count of complete 4-way handshakes)
        - error: str | None (error message if analysis failed)

    Raises:
        FileNotFoundError: If the pcapng file does not exist.
    """
    pcapng_path = Path(pcapng_path)
    if not pcapng_path.exists():
        raise FileNotFoundError(f"pcapng file not found: {pcapng_path}")

    result: dict = {
        "file": str(pcapng_path),
        "pmkids": 0,
        "handshakes": 0,
        "best_handshakes": 0,
        "error": None,
    }

    cmd = [
        "hcxpcapngtool",
        "--info=stdout",
        str(pcapng_path),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        output = proc.stdout + proc.stderr

        # Parse PMKID count
        pmkid_match = re.search(r"PMKID.*?:\s*(\d+)", output, re.IGNORECASE)
        if pmkid_match:
            result["pmkids"] = int(pmkid_match.group(1))

        # Parse handshake count
        hs_match = re.search(r"EAPOL.*?:\s*(\d+)", output, re.IGNORECASE)
        if hs_match:
            result["handshakes"] = int(hs_match.group(1))

        # Parse best/complete handshakes
        best_match = re.search(
            r"best.*?handshake.*?:\s*(\d+)",
            output,
            re.IGNORECASE,
        )
        if best_match:
            result["best_handshakes"] = int(best_match.group(1))

        if proc.returncode != 0 and not any(
            result[k] for k in ("pmkids", "handshakes")
        ):
            result["error"] = f"hcxpcapngtool exited with code {proc.returncode}"

    except FileNotFoundError:
        result["error"] = "hcxpcapngtool not found in PATH"
        logger.error("hcxpcapngtool binary not found")
    except subprocess.TimeoutExpired:
        result["error"] = "hcxpcapngtool timed out after 60s"
        logger.error("hcxpcapngtool timed out on %s", pcapng_path)

    logger.info(
        "Capture analysis for %s: %d PMKIDs, %d handshakes",
        pcapng_path.name,
        result["pmkids"],
        result["handshakes"],
    )

    return result
