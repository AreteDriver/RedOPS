"""Parser for reaver stdout output.

Parses reaver's progress output to track WPS PIN attempts, detect
success conditions, and extract recovered WPA credentials.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Reaver output patterns
_PIN_ATTEMPT = re.compile(
    r"Trying pin\s+(\d+)"
)
_PIN_PROGRESS = re.compile(
    r"(\d+\.?\d*)%\s+complete"
)
_WPS_PIN_FOUND = re.compile(
    r"WPS PIN:\s*'?(\d+)'?"
)
_WPA_PSK_FOUND = re.compile(
    r"WPA PSK:\s*'(.+?)'"
)
_AP_SSID = re.compile(
    r"Associated with\s+(\S+)\s+\(ESSID:\s*(.+?)\)"
)
_TIMEOUT = re.compile(
    r"WARNING.*timeout",
    re.IGNORECASE,
)
_LOCKED = re.compile(
    r"WARNING.*WPS.*locked",
    re.IGNORECASE,
)
_RATE_LIMITED = re.compile(
    r"WARNING.*rate.?limit",
    re.IGNORECASE,
)
_FAILED = re.compile(
    r"FAILED|WPS transaction failed",
    re.IGNORECASE,
)


def parse_reaver_line(line: str) -> dict | None:
    """Parse a single line of reaver stdout output.

    Extracts progress information, PIN attempts, WPS state
    changes, and success/failure conditions from reaver output.

    Args:
        line: A single line of reaver stdout output.

    Returns:
        Dict with parsed data, or None if the line is not a
        recognized reaver output format. Possible keys:
        - type: str ('attempt', 'progress', 'success',
            'warning', 'association', 'failure')
        - pin: str (current PIN being tried)
        - progress: float (completion percentage)
        - wps_pin: str (recovered WPS PIN, on success)
        - wpa_psk: str (recovered WPA passphrase, on success)
        - bssid: str (associated AP BSSID)
        - essid: str (associated AP ESSID)
        - warning: str ('timeout', 'locked', 'rate_limited')
    """
    if not line or not line.strip():
        return None

    line = line.strip()

    # Check for WPS PIN success (highest priority)
    wps_match = _WPS_PIN_FOUND.search(line)
    if wps_match:
        result: dict = {
            "type": "success",
            "wps_pin": wps_match.group(1),
        }
        logger.info("WPS PIN recovered: %s", wps_match.group(1))
        return result

    # Check for WPA PSK extraction
    psk_match = _WPA_PSK_FOUND.search(line)
    if psk_match:
        result = {
            "type": "success",
            "wpa_psk": psk_match.group(1),
        }
        logger.info("WPA PSK extracted")
        return result

    # Check for PIN attempt
    pin_match = _PIN_ATTEMPT.search(line)
    if pin_match:
        result = {
            "type": "attempt",
            "pin": pin_match.group(1),
        }

        # Also check for progress on the same line
        progress_match = _PIN_PROGRESS.search(line)
        if progress_match:
            result["progress"] = float(progress_match.group(1))

        return result

    # Check for progress update (standalone)
    progress_match = _PIN_PROGRESS.search(line)
    if progress_match:
        return {
            "type": "progress",
            "progress": float(progress_match.group(1)),
        }

    # Check for AP association
    ap_match = _AP_SSID.search(line)
    if ap_match:
        return {
            "type": "association",
            "bssid": ap_match.group(1),
            "essid": ap_match.group(2),
        }

    # Check for warnings
    if _LOCKED.search(line):
        logger.warning("WPS locked detected")
        return {
            "type": "warning",
            "warning": "locked",
        }

    if _RATE_LIMITED.search(line):
        logger.warning("Rate limiting detected")
        return {
            "type": "warning",
            "warning": "rate_limited",
        }

    if _TIMEOUT.search(line):
        return {
            "type": "warning",
            "warning": "timeout",
        }

    # Check for failure
    if _FAILED.search(line):
        return {
            "type": "failure",
        }

    return None
