"""
Additional SIEM/SOAR export formats.

Provides CEF, LEEF, and other standard security formats.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """Standardized security event for export."""

    event_id: str
    timestamp: datetime
    severity: str  # critical, high, medium, low, info
    event_type: str
    source: str = "RedOPS"

    # Target info
    target_host: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    target_url: Optional[str] = None

    # Finding details
    title: str = ""
    description: str = ""
    category: str = ""
    technique_id: Optional[str] = None  # MITRE ATT&CK
    cve_id: Optional[str] = None

    # Additional context
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def get_severity_numeric(self) -> int:
        """Get numeric severity (0-10)."""
        mapping = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }
        return mapping.get(self.severity.lower(), 1)


class CEFExporter:
    """
    Common Event Format (CEF) exporter.

    CEF is widely supported by SIEM platforms including ArcSight, Splunk, and QRadar.
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """

    CEF_VERSION = "0"
    VENDOR = "RedOPS"
    PRODUCT = "Security Assessment"
    VERSION = "1.0"

    # Severity mapping (CEF uses 0-10 scale)
    SEVERITY_MAP = {
        "critical": "10",
        "high": "8",
        "medium": "5",
        "low": "3",
        "info": "1",
    }

    def __init__(
        self,
        vendor: str = "RedOPS",
        product: str = "Security Assessment",
        version: str = "1.0",
    ):
        """Initialize CEF exporter."""
        self.vendor = vendor
        self.product = product
        self.version = version

    def _escape_value(self, value: str) -> str:
        """Escape CEF special characters."""
        if not value:
            return ""
        # Escape backslash, equals, and pipe
        value = value.replace("\\", "\\\\")
        value = value.replace("=", "\\=")
        value = value.replace("|", "\\|")
        value = value.replace("\n", "\\n")
        value = value.replace("\r", "\\r")
        return value

    def _escape_header(self, value: str) -> str:
        """Escape CEF header special characters."""
        if not value:
            return ""
        value = value.replace("\\", "\\\\")
        value = value.replace("|", "\\|")
        return value

    def export_event(self, event: SecurityEvent) -> str:
        """
        Export a single event to CEF format.

        Args:
            event: Security event to export

        Returns:
            CEF formatted string
        """
        severity = self.SEVERITY_MAP.get(event.severity.lower(), "1")

        # Build extension fields
        extensions = []

        # Standard CEF extension fields
        if event.target_host:
            extensions.append(f"dhost={self._escape_value(event.target_host)}")
        if event.target_ip:
            extensions.append(f"dst={self._escape_value(event.target_ip)}")
        if event.target_port:
            extensions.append(f"dpt={event.target_port}")
        if event.target_url:
            extensions.append(f"request={self._escape_value(event.target_url)}")

        # Custom extension fields
        if event.description:
            extensions.append(f"msg={self._escape_value(event.description)}")
        if event.category:
            extensions.append(f"cat={self._escape_value(event.category)}")
        if event.technique_id:
            extensions.append(f"cs1={self._escape_value(event.technique_id)}")
            extensions.append("cs1Label=MITRE_ATT&CK_ID")
        if event.cve_id:
            extensions.append(f"cs2={self._escape_value(event.cve_id)}")
            extensions.append("cs2Label=CVE_ID")

        # Timestamp
        epoch_ms = int(event.timestamp.timestamp() * 1000)
        extensions.append(f"rt={epoch_ms}")

        # Build CEF line
        cef_parts = [
            f"CEF:{self.CEF_VERSION}",
            self._escape_header(self.vendor),
            self._escape_header(self.product),
            self._escape_header(self.version),
            self._escape_header(event.event_id),
            self._escape_header(event.title),
            severity,
            " ".join(extensions),
        ]

        return "|".join(cef_parts)

    def export_events(self, events: List[SecurityEvent]) -> str:
        """
        Export multiple events to CEF format.

        Args:
            events: List of security events

        Returns:
            CEF formatted string (newline separated)
        """
        return "\n".join(self.export_event(e) for e in events)


class LEEFExporter:
    """
    Log Event Extended Format (LEEF) exporter.

    LEEF is IBM QRadar's native format.
    Format: LEEF:Version|Vendor|Product|Version|EventID|Key1=Value1<tab>Key2=Value2
    """

    LEEF_VERSION = "2.0"
    DELIMITER = "\t"  # Tab delimiter for LEEF 2.0

    # Severity mapping
    SEVERITY_MAP = {
        "critical": "10",
        "high": "8",
        "medium": "5",
        "low": "3",
        "info": "1",
    }

    def __init__(
        self,
        vendor: str = "RedOPS",
        product: str = "Security Assessment",
        version: str = "1.0",
    ):
        """Initialize LEEF exporter."""
        self.vendor = vendor
        self.product = product
        self.version = version

    def _escape_value(self, value: str) -> str:
        """Escape LEEF special characters."""
        if not value:
            return ""
        # Escape tab, carriage return, newline
        value = value.replace("\t", "\\t")
        value = value.replace("\r", "\\r")
        value = value.replace("\n", "\\n")
        return value

    def export_event(self, event: SecurityEvent) -> str:
        """
        Export a single event to LEEF format.

        Args:
            event: Security event to export

        Returns:
            LEEF formatted string
        """
        # Build attributes
        attrs = []

        # Standard LEEF attributes
        attrs.append(f"cat={self._escape_value(event.category or event.event_type)}")
        attrs.append(f"sev={self.SEVERITY_MAP.get(event.severity.lower(), '1')}")

        if event.target_host:
            attrs.append(f"dstHost={self._escape_value(event.target_host)}")
        if event.target_ip:
            attrs.append(f"dst={self._escape_value(event.target_ip)}")
        if event.target_port:
            attrs.append(f"dstPort={event.target_port}")
        if event.target_url:
            attrs.append(f"url={self._escape_value(event.target_url)}")

        if event.description:
            attrs.append(f"msg={self._escape_value(event.description)}")
        if event.technique_id:
            attrs.append(f"mitreAttackId={self._escape_value(event.technique_id)}")
        if event.cve_id:
            attrs.append(f"cveId={self._escape_value(event.cve_id)}")

        # Timestamp (LEEF uses devTime in epoch milliseconds)
        epoch_ms = int(event.timestamp.timestamp() * 1000)
        attrs.append(f"devTime={epoch_ms}")

        # Build LEEF line
        header = f"LEEF:{self.LEEF_VERSION}|{self.vendor}|{self.product}|{self.version}|{event.event_id}|"
        attributes = self.DELIMITER.join(attrs)

        return header + attributes

    def export_events(self, events: List[SecurityEvent]) -> str:
        """
        Export multiple events to LEEF format.

        Args:
            events: List of security events

        Returns:
            LEEF formatted string (newline separated)
        """
        return "\n".join(self.export_event(e) for e in events)


class SyslogExporter:
    """
    RFC 5424 Syslog format exporter.

    Compatible with rsyslog, syslog-ng, and most SIEM platforms.
    """

    # Syslog severity levels (RFC 5424)
    SEVERITY_MAP = {
        "critical": 2,  # Critical
        "high": 3,      # Error
        "medium": 4,    # Warning
        "low": 5,       # Notice
        "info": 6,      # Informational
    }

    # Facility: local0 (16) for custom applications
    FACILITY = 16

    def __init__(
        self,
        app_name: str = "RedOPS",
        hostname: str = "-",
    ):
        """Initialize Syslog exporter."""
        self.app_name = app_name
        self.hostname = hostname

    def _calculate_priority(self, severity: str) -> int:
        """Calculate syslog priority value."""
        sev_num = self.SEVERITY_MAP.get(severity.lower(), 6)
        return (self.FACILITY * 8) + sev_num

    def export_event(self, event: SecurityEvent) -> str:
        """
        Export a single event to syslog format (RFC 5424).

        Args:
            event: Security event to export

        Returns:
            Syslog formatted string
        """
        priority = self._calculate_priority(event.severity)
        timestamp = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        proc_id = "-"
        msg_id = event.event_type.upper().replace(" ", "_")[:32]

        # Structured data (SD-ELEMENT)
        sd_elements = []

        # Security finding SD
        sd_params = []
        if event.target_host:
            sd_params.append(f'host="{event.target_host}"')
        if event.target_ip:
            sd_params.append(f'ip="{event.target_ip}"')
        if event.technique_id:
            sd_params.append(f'mitre="{event.technique_id}"')
        if event.cve_id:
            sd_params.append(f'cve="{event.cve_id}"')
        sd_params.append(f'severity="{event.severity}"')

        if sd_params:
            sd_elements.append(f'[redops@32473 {" ".join(sd_params)}]')

        structured_data = "".join(sd_elements) if sd_elements else "-"

        # Message
        message = f"{event.title}: {event.description}" if event.description else event.title

        # Build syslog message
        return f"<{priority}>1 {timestamp} {self.hostname} {self.app_name} - {msg_id} {structured_data} {message}"

    def export_events(self, events: List[SecurityEvent]) -> str:
        """
        Export multiple events to syslog format.

        Args:
            events: List of security events

        Returns:
            Syslog formatted string (newline separated)
        """
        return "\n".join(self.export_event(e) for e in events)


class JSONLExporter:
    """
    JSON Lines (JSONL) exporter.

    One JSON object per line, widely supported by modern SIEM platforms.
    """

    def __init__(
        self,
        include_raw: bool = True,
        timestamp_format: str = "iso",
    ):
        """
        Initialize JSONL exporter.

        Args:
            include_raw: Include raw data in output
            timestamp_format: 'iso', 'epoch', or 'epoch_ms'
        """
        self.include_raw = include_raw
        self.timestamp_format = timestamp_format

    def _format_timestamp(self, dt: datetime) -> Any:
        """Format timestamp according to configured format."""
        if self.timestamp_format == "epoch":
            return int(dt.timestamp())
        elif self.timestamp_format == "epoch_ms":
            return int(dt.timestamp() * 1000)
        else:
            return dt.isoformat()

    def export_event(self, event: SecurityEvent) -> str:
        """
        Export a single event to JSON format.

        Args:
            event: Security event to export

        Returns:
            JSON string
        """
        data = {
            "event_id": event.event_id,
            "timestamp": self._format_timestamp(event.timestamp),
            "severity": event.severity,
            "severity_numeric": event.get_severity_numeric(),
            "event_type": event.event_type,
            "source": event.source,
            "title": event.title,
            "description": event.description,
            "category": event.category,
            "target": {
                "host": event.target_host,
                "ip": event.target_ip,
                "port": event.target_port,
                "url": event.target_url,
            },
            "tags": event.tags,
        }

        if event.technique_id:
            data["mitre_attack_id"] = event.technique_id
        if event.cve_id:
            data["cve_id"] = event.cve_id

        if self.include_raw and event.raw_data:
            data["raw_data"] = event.raw_data

        return json.dumps(data, default=str)

    def export_events(self, events: List[SecurityEvent]) -> str:
        """
        Export multiple events to JSONL format.

        Args:
            events: List of security events

        Returns:
            JSONL formatted string (newline separated JSON objects)
        """
        return "\n".join(self.export_event(e) for e in events)


class SentinelExporter:
    """
    Microsoft Sentinel (Azure Sentinel) format exporter.

    Produces JSON compatible with Sentinel's custom log format.
    """

    def __init__(self, log_type: str = "RedOPS_SecurityFindings"):
        """
        Initialize Sentinel exporter.

        Args:
            log_type: Custom log type name in Sentinel
        """
        self.log_type = log_type

    def export_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Export a single event for Sentinel.

        Args:
            event: Security event to export

        Returns:
            Dictionary for Sentinel ingestion
        """
        return {
            "TimeGenerated": event.timestamp.isoformat() + "Z",
            "EventId": event.event_id,
            "Severity": event.severity.capitalize(),
            "SeverityLevel": event.get_severity_numeric(),
            "EventType": event.event_type,
            "Title": event.title,
            "Description": event.description,
            "Category": event.category,
            "TargetHost": event.target_host or "",
            "TargetIP": event.target_ip or "",
            "TargetPort": event.target_port,
            "TargetURL": event.target_url or "",
            "MITREAttackId": event.technique_id or "",
            "CVEId": event.cve_id or "",
            "Tags": ",".join(event.tags) if event.tags else "",
            "Source": event.source,
            "RawData": json.dumps(event.raw_data) if event.raw_data else "",
        }

    def export_events(self, events: List[SecurityEvent]) -> str:
        """
        Export multiple events for Sentinel.

        Args:
            events: List of security events

        Returns:
            JSON array string for Sentinel ingestion
        """
        records = [self.export_event(e) for e in events]
        return json.dumps(records, indent=2)


# Convenience functions
def export_to_cef(events: List[SecurityEvent], **kwargs) -> str:
    """Export events to CEF format."""
    exporter = CEFExporter(**kwargs)
    return exporter.export_events(events)


def export_to_leef(events: List[SecurityEvent], **kwargs) -> str:
    """Export events to LEEF format."""
    exporter = LEEFExporter(**kwargs)
    return exporter.export_events(events)


def export_to_syslog(events: List[SecurityEvent], **kwargs) -> str:
    """Export events to syslog format."""
    exporter = SyslogExporter(**kwargs)
    return exporter.export_events(events)


def export_to_jsonl(events: List[SecurityEvent], **kwargs) -> str:
    """Export events to JSONL format."""
    exporter = JSONLExporter(**kwargs)
    return exporter.export_events(events)


def export_to_sentinel(events: List[SecurityEvent], **kwargs) -> str:
    """Export events for Microsoft Sentinel."""
    exporter = SentinelExporter(**kwargs)
    return exporter.export_events(events)
