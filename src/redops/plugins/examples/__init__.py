"""
Example plugins for RedOPS.

These plugins demonstrate how to build scanner plugins.
"""

from redops.plugins.examples.port_scanner import PortScannerPlugin
from redops.plugins.examples.header_scanner import HeaderScannerPlugin

__all__ = [
    "PortScannerPlugin",
    "HeaderScannerPlugin",
]
