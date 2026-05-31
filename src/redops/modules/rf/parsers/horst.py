"""Parser for horst (Highly Optimized Radio Scanning Tool) stdout.

Parses structured output lines from horst into dicts with node MAC,
signal strength, channel, and frame type information.
"""

import logging
import re

logger = logging.getLogger(__name__)

# horst outputs tab-separated or space-delimited lines
# Typical format: <timestamp> <signal> <channel> <type> <MAC> [extra]
_HORST_LINE_PATTERN = re.compile(
    r"^\s*"
    r"(?P<timestamp>\d+(?:\.\d+)?)\s+"
    r"(?P<signal>-?\d+)\s+"
    r"(?P<channel>\d+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<mac>[0-9a-fA-F:]{17})"
    r"(?:\s+(?P<extra>.+))?"
    r"\s*$"
)

# Alternative format with brackets
_HORST_BRACKET_PATTERN = re.compile(
    r"\["
    r"(?P<channel>\d+)"
    r"\]\s+"
    r"(?P<signal>-?\d+)dBm\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<mac>[0-9a-fA-F:]{17})"
    r"(?:\s+(?P<extra>.+))?"
)


def parse_horst_line(line: str) -> dict | None:
    """Parse a single line of horst stdout output.

    Handles multiple horst output formats and extracts structured
    data about detected wireless nodes.

    Args:
        line: A single line of horst stdout output.

    Returns:
        Dict with parsed fields, or None if the line does not
        match a recognized format. Keys:
        - mac: str (node MAC address, uppercase)
        - signal: int (signal strength in dBm)
        - channel: int (wireless channel number)
        - type: str (frame type, e.g., 'BEACON', 'DATA', 'PROBE')
        - extra: str | None (additional info if present)
    """
    if not line or not line.strip():
        return None

    line = line.strip()

    # Skip header lines and separators
    if line.startswith("#") or line.startswith("-"):
        return None

    # Try standard format
    match = _HORST_LINE_PATTERN.match(line)
    if match:
        return {
            "mac": match.group("mac").upper(),
            "signal": int(match.group("signal")),
            "channel": int(match.group("channel")),
            "type": match.group("type").upper(),
            "extra": match.group("extra"),
        }

    # Try bracket format
    match = _HORST_BRACKET_PATTERN.search(line)
    if match:
        return {
            "mac": match.group("mac").upper(),
            "signal": int(match.group("signal")),
            "channel": int(match.group("channel")),
            "type": match.group("type").upper(),
            "extra": match.group("extra"),
        }

    logger.debug("Unrecognized horst line: %s", line)
    return None
