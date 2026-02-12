"""
Splunk HTTP Event Collector (HEC) integration.

Exports RedOPS findings and scan results to Splunk for SIEM integration.
"""

from typing import Any
from datetime import datetime, timezone
import os
import json
from dataclasses import dataclass
from redops.core.context import Context
from redops.core.models import Finding

# Try to import requests
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class SplunkConfig:
    """Splunk HEC configuration."""

    hec_url: str
    hec_token: str
    index: str = "main"
    source: str = "redops"
    sourcetype: str = "redops:scan"
    verify_ssl: bool = True
    batch_size: int = 100
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "SplunkConfig":
        """Create config from environment variables."""
        hec_url = os.environ.get("SPLUNK_HEC_URL", "")
        hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "")
        return cls(
            hec_url=hec_url,
            hec_token=hec_token,
            index=os.environ.get("SPLUNK_INDEX", "main"),
            source=os.environ.get("SPLUNK_SOURCE", "redops"),
            sourcetype=os.environ.get("SPLUNK_SOURCETYPE", "redops:scan"),
            verify_ssl=os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true",
        )


class SplunkHECExporter:
    """
    Exports data to Splunk via HTTP Event Collector.

    Supports batching events for efficiency and handles retries.
    """

    def __init__(self, config: SplunkConfig | None = None):
        """
        Initialize the exporter.

        Args:
            config: Splunk configuration (uses env vars if not provided)
        """
        self.config = config or SplunkConfig.from_env()
        self._pending_events: list[dict] = []

    def _build_event(
        self,
        data: dict[str, Any],
        timestamp: datetime | None = None,
        event_type: str = "scan",
    ) -> dict[str, Any]:
        """
        Build a Splunk HEC event.

        Args:
            data: Event data
            timestamp: Event timestamp
            event_type: Type of event (scan, finding, etc.)

        Returns:
            HEC-formatted event
        """
        ts = timestamp or datetime.now(timezone.utc)
        epoch_time = ts.timestamp()

        return {
            "time": epoch_time,
            "host": "redops",
            "source": self.config.source,
            "sourcetype": f"{self.config.sourcetype}:{event_type}",
            "index": self.config.index,
            "event": data,
        }

    def add_event(
        self,
        data: dict[str, Any],
        timestamp: datetime | None = None,
        event_type: str = "scan",
    ) -> None:
        """
        Add an event to the pending batch.

        Args:
            data: Event data
            timestamp: Event timestamp
            event_type: Type of event
        """
        event = self._build_event(data, timestamp, event_type)
        self._pending_events.append(event)

    def add_finding(self, finding: Finding, scan_id: str | None = None) -> None:
        """
        Add a finding to the pending batch.

        Args:
            finding: RedOPS finding
            scan_id: Optional scan identifier
        """
        data = {
            "scan_id": scan_id,
            "finding_type": "security_finding",
            "module": finding.module,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value if finding.severity else "unknown",
            "data": finding.data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.add_event(data, event_type="finding")

    def flush(self) -> dict[str, Any]:
        """
        Send all pending events to Splunk.

        Returns:
            Result with status and counts
        """
        if not self._pending_events:
            return {"success": True, "sent": 0, "message": "No events to send"}

        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        if not self.config.hec_url or not self.config.hec_token:
            return {"success": False, "error": "Splunk HEC not configured"}

        headers = {
            "Authorization": f"Splunk {self.config.hec_token}",
            "Content-Type": "application/json",
        }

        # Build batch payload (newline-delimited JSON)
        payload = "\n".join(json.dumps(e) for e in self._pending_events)
        total_events = len(self._pending_events)

        try:
            response = requests.post(
                self.config.hec_url,
                headers=headers,
                data=payload,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                self._pending_events = []
                return {
                    "success": True,
                    "sent": total_events,
                    "message": f"Sent {total_events} events to Splunk",
                }

            # Handle HEC errors
            try:
                error_data = response.json()
                error_text = error_data.get("text", "Unknown error")
            except (ValueError, KeyError):
                error_text = response.text[:200]

            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {error_text}",
                "attempted": total_events,
            }

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e),
                "attempted": total_events,
            }

    def export_context(
        self, ctx: Context, scan_id: str | None = None
    ) -> dict[str, Any]:
        """
        Export all context data to Splunk.

        Args:
            ctx: Pipeline context
            scan_id: Optional scan identifier

        Returns:
            Export result
        """
        scan_id = scan_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Export scan summary
        summary_event = {
            "scan_id": scan_id,
            "event_type": "scan_summary",
            "target": ctx.target,
            "pipeline_name": ctx.get("pipeline_name"),
            "pipeline_version": ctx.get("pipeline_version"),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "data_keys": list(ctx.data.keys()),
        }
        self.add_event(summary_event, event_type="summary")

        # Export findings
        for key, value in ctx.data.items():
            if key.startswith("finding_"):
                finding_data = {
                    "scan_id": scan_id,
                    "finding_key": key,
                    **value,
                }
                self.add_event(finding_data, event_type="finding")

        # Export key scan results
        export_keys = [
            "domain_profile",
            "dns_enumeration",
            "subdomains",
            "port_scan",
            "ssl_analysis",
            "whois_data",
            "greynoise_result",
            "abuseipdb_result",
            "urlhaus_result",
            "urlscan_result",
            "passivedns_result",
            "otx_indicator",
        ]

        for key in export_keys:
            if key in ctx.data:
                result_event = {
                    "scan_id": scan_id,
                    "result_type": key,
                    "data": ctx.data[key],
                }
                self.add_event(result_event, event_type="result")

        return self.flush()


def export_to_splunk(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Export scan results to Splunk HEC.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - hec_url: Splunk HEC URL (or SPLUNK_HEC_URL env var)
            - hec_token: HEC token (or SPLUNK_HEC_TOKEN env var)
            - index: Target index (default: main)
            - scan_id: Optional scan identifier

    Returns:
        Updated context with export result
    """
    params = params or {}

    config = SplunkConfig(
        hec_url=params.get("hec_url") or os.environ.get("SPLUNK_HEC_URL", ""),
        hec_token=params.get("hec_token") or os.environ.get("SPLUNK_HEC_TOKEN", ""),
        index=params.get("index", "main"),
        source=params.get("source", "redops"),
        sourcetype=params.get("sourcetype", "redops:scan"),
        verify_ssl=params.get("verify_ssl", True),
    )

    exporter = SplunkHECExporter(config)

    ctx.log("Exporting to Splunk HEC", level="INFO")

    result = exporter.export_context(ctx, scan_id=params.get("scan_id"))

    if result.get("success"):
        ctx.log(f"Splunk export complete: {result.get('sent', 0)} events", level="INFO")
    else:
        ctx.log(f"Splunk export failed: {result.get('error')}", level="WARNING")

    ctx.add("splunk_export_result", result)
    return ctx
