"""
Example Port Scanner Plugin.

Demonstrates building a network scanner plugin.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Set

from redops.plugins.scanner import (
    Finding,
    ScannerCapability,
    ScannerConfig,
    ScannerPlugin,
    ScannerResult,
    ScanPhase,
    Severity,
)


class PortScannerPlugin(ScannerPlugin):
    """
    Simple TCP port scanner plugin.

    Scans common ports to identify open services.
    """

    # Common ports to scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
    ]

    # Service names for common ports
    PORT_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPC",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
    }

    # Ports that may be security concerns
    RISKY_PORTS = {
        21: "FTP allows unencrypted file transfer",
        23: "Telnet transmits credentials in plaintext",
        135: "MSRPC can be exploited for remote code execution",
        139: "NetBIOS may expose sensitive information",
        445: "SMB has been target of major exploits",
        3389: "RDP can be brute-forced if exposed",
        5900: "VNC may have weak authentication",
    }

    @classmethod
    def get_name(cls) -> str:
        return "port-scanner"

    @classmethod
    def get_version(cls) -> str:
        return "1.0.0"

    @classmethod
    def get_description(cls) -> str:
        return "TCP port scanner for identifying open services"

    @classmethod
    def get_capabilities(cls) -> Set[ScannerCapability]:
        return {ScannerCapability.NETWORK_SCAN}

    @classmethod
    def get_phases(cls) -> List[ScanPhase]:
        return [ScanPhase.DISCOVERY, ScanPhase.ENUMERATION]

    @classmethod
    def get_config_schema(cls) -> Dict:
        return {
            "type": "object",
            "properties": {
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Ports to scan (default: common ports)",
                },
                "timeout": {
                    "type": "number",
                    "description": "Connection timeout in seconds",
                    "default": 1.0,
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of concurrent threads",
                    "default": 10,
                },
            },
        }

    def validate_target(self, target: str) -> bool:
        """Validate target is a hostname or IP."""
        # Simple validation - could be enhanced
        if not target:
            return False
        # Remove protocol prefix if present
        if "://" in target:
            target = target.split("://")[1]
        target = target.split("/")[0].split(":")[0]
        return len(target) > 0

    def scan(
        self,
        target: str,
        config: Optional[ScannerConfig] = None,
    ) -> ScannerResult:
        """
        Scan target for open ports.

        Args:
            target: Hostname or IP address
            config: Scanner configuration

        Returns:
            ScannerResult with findings
        """
        config = config or self.config
        self._trigger_hook("before_scan", target, config)

        result = self._create_result(target)

        # Parse target
        host = self._parse_host(target)

        # Get ports to scan
        ports = config.custom.get("ports", self.COMMON_PORTS)
        timeout = config.custom.get("timeout", 1.0)
        threads = config.custom.get("threads", config.max_concurrent)

        # Scan ports
        open_ports = self._scan_ports(host, ports, timeout, threads)

        # Create findings for open ports
        for port in open_ports:
            service = self.PORT_SERVICES.get(port, "Unknown")
            severity = Severity.INFO

            # Check if port is risky
            if port in self.RISKY_PORTS:
                severity = Severity.MEDIUM
                description = self.RISKY_PORTS[port]
            else:
                description = f"Port {port} ({service}) is open"

            finding = self._create_finding(
                title=f"Open Port: {port}/{service}",
                severity=severity,
                target=target,
                description=description,
                location=f"{host}:{port}",
                category="network",
                phase=ScanPhase.DISCOVERY,
                evidence=f"TCP connection successful to {host}:{port}",
                metadata={
                    "port": port,
                    "service": service,
                    "protocol": "tcp",
                },
            )

            if port in self.RISKY_PORTS:
                finding.remediation = (
                    f"Consider restricting access to port {port} or using "
                    f"a more secure alternative."
                )

            result.findings.append(finding)

        # Add stats
        result.stats = {
            "ports_scanned": len(ports),
            "ports_open": len(open_ports),
            "open_ports": open_ports,
        }

        result.completed_at = datetime.now()
        self._trigger_hook("after_scan", result)

        return result

    def _parse_host(self, target: str) -> str:
        """Extract hostname from target."""
        if "://" in target:
            target = target.split("://")[1]
        return target.split("/")[0].split(":")[0]

    def _scan_ports(
        self,
        host: str,
        ports: List[int],
        timeout: float,
        threads: int,
    ) -> List[int]:
        """Scan ports for open connections."""
        open_ports = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_port, host, port, timeout): port
                for port in ports
            }

            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass

        return sorted(open_ports)

    def _check_port(self, host: str, port: int, timeout: float) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, socket.timeout):
            return False
