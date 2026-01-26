"""
Datadog integration.

Exports RedOPS findings and scan results to Datadog Logs and Events API.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import os
import json
from dataclasses import dataclass
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel

# Try to import requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Datadog API endpoints by region
DATADOG_ENDPOINTS = {
    "us1": "https://http-intake.logs.datadoghq.com",
    "us3": "https://http-intake.logs.us3.datadoghq.com",
    "us5": "https://http-intake.logs.us5.datadoghq.com",
    "eu1": "https://http-intake.logs.datadoghq.eu",
    "ap1": "https://http-intake.logs.ap1.datadoghq.com",
    "us1-fed": "https://http-intake.logs.ddog-gov.com",
}

DATADOG_EVENTS_ENDPOINTS = {
    "us1": "https://api.datadoghq.com/api/v1/events",
    "us3": "https://api.us3.datadoghq.com/api/v1/events",
    "us5": "https://api.us5.datadoghq.com/api/v1/events",
    "eu1": "https://api.datadoghq.eu/api/v1/events",
    "ap1": "https://api.ap1.datadoghq.com/api/v1/events",
    "us1-fed": "https://api.ddog-gov.com/api/v1/events",
}


@dataclass
class DatadogConfig:
    """Datadog configuration."""

    api_key: str
    site: str = "us1"
    service: str = "redops"
    source: str = "redops"
    tags: List[str] = None
    timeout: int = 30

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    @classmethod
    def from_env(cls) -> "DatadogConfig":
        """Create config from environment variables."""
        tags_str = os.environ.get("DD_TAGS", "")
        tags = [t.strip() for t in tags_str.split(",")] if tags_str else []
        return cls(
            api_key=os.environ.get("DD_API_KEY", ""),
            site=os.environ.get("DD_SITE", "us1"),
            service=os.environ.get("DD_SERVICE", "redops"),
            source=os.environ.get("DD_SOURCE", "redops"),
            tags=tags,
        )

    @property
    def logs_endpoint(self) -> str:
        """Get the logs intake endpoint for this site."""
        return DATADOG_ENDPOINTS.get(self.site, DATADOG_ENDPOINTS["us1"])

    @property
    def events_endpoint(self) -> str:
        """Get the events API endpoint for this site."""
        return DATADOG_EVENTS_ENDPOINTS.get(self.site, DATADOG_EVENTS_ENDPOINTS["us1"])


class DatadogExporter:
    """
    Exports data to Datadog Logs and Events.

    Supports batch log export and individual event creation.
    """

    def __init__(self, config: Optional[DatadogConfig] = None):
        """
        Initialize the exporter.

        Args:
            config: Datadog configuration (uses env vars if not provided)
        """
        self.config = config or DatadogConfig.from_env()
        self._pending_logs: List[Dict] = []

    def _build_log_entry(
        self,
        message: str,
        data: Dict[str, Any],
        level: str = "info",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Build a Datadog log entry.

        Args:
            message: Log message
            data: Additional data
            level: Log level (info, warning, error, etc.)
            tags: Additional tags

        Returns:
            Datadog log entry
        """
        all_tags = self.config.tags.copy()
        if tags:
            all_tags.extend(tags)

        return {
            "message": message,
            "ddsource": self.config.source,
            "ddtags": ",".join(all_tags),
            "service": self.config.service,
            "status": level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }

    def add_log(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        level: str = "info",
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Add a log entry to the pending batch.

        Args:
            message: Log message
            data: Additional data
            level: Log level
            tags: Additional tags
        """
        entry = self._build_log_entry(message, data or {}, level, tags)
        self._pending_logs.append(entry)

    def add_finding(self, finding: Finding, scan_id: Optional[str] = None) -> None:
        """
        Add a finding as a log entry.

        Args:
            finding: RedOPS finding
            scan_id: Optional scan identifier
        """
        # Map severity to Datadog log level
        level_map = {
            RiskLevel.CRITICAL: "error",
            RiskLevel.HIGH: "error",
            RiskLevel.MEDIUM: "warning",
            RiskLevel.LOW: "info",
            RiskLevel.INFO: "info",
        }
        level = level_map.get(finding.severity, "info")

        data = {
            "scan_id": scan_id,
            "finding_type": "security_finding",
            "module": finding.module,
            "title": finding.title,
            "severity": finding.severity.value if finding.severity else "unknown",
            "finding_data": finding.data,
        }

        tags = [f"severity:{finding.severity.value}" if finding.severity else "severity:unknown"]
        self.add_log(f"Security Finding: {finding.title}", data, level, tags)

    def flush_logs(self) -> Dict[str, Any]:
        """
        Send all pending logs to Datadog.

        Returns:
            Result with status and counts
        """
        if not self._pending_logs:
            return {"success": True, "sent": 0, "message": "No logs to send"}

        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        if not self.config.api_key:
            return {"success": False, "error": "Datadog API key not configured"}

        headers = {
            "DD-API-KEY": self.config.api_key,
            "Content-Type": "application/json",
        }

        total_logs = len(self._pending_logs)

        try:
            response = requests.post(
                f"{self.config.logs_endpoint}/api/v2/logs",
                headers=headers,
                json=self._pending_logs,
                timeout=self.config.timeout,
            )

            if response.status_code in (200, 202):
                self._pending_logs = []
                return {
                    "success": True,
                    "sent": total_logs,
                    "message": f"Sent {total_logs} logs to Datadog",
                }

            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "attempted": total_logs,
            }

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e),
                "attempted": total_logs,
            }

    def send_event(
        self,
        title: str,
        text: str,
        alert_type: str = "info",
        tags: Optional[List[str]] = None,
        aggregation_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send an event to Datadog Events API.

        Args:
            title: Event title
            text: Event text
            alert_type: Type (info, warning, error, success)
            tags: Additional tags
            aggregation_key: Key for aggregating related events

        Returns:
            Result with status
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        if not self.config.api_key:
            return {"success": False, "error": "Datadog API key not configured"}

        all_tags = self.config.tags.copy()
        if tags:
            all_tags.extend(tags)

        event = {
            "title": title,
            "text": text,
            "alert_type": alert_type,
            "tags": all_tags,
            "source_type_name": self.config.source,
        }
        if aggregation_key:
            event["aggregation_key"] = aggregation_key

        headers = {
            "DD-API-KEY": self.config.api_key,
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                self.config.events_endpoint,
                headers=headers,
                json=event,
                timeout=self.config.timeout,
            )

            if response.status_code in (200, 202):
                return {
                    "success": True,
                    "event_id": response.json().get("event", {}).get("id"),
                    "message": "Event sent to Datadog",
                }

            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
            }

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def export_context(self, ctx: Context, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Export all context data to Datadog.

        Args:
            ctx: Pipeline context
            scan_id: Optional scan identifier

        Returns:
            Export result
        """
        scan_id = scan_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Add scan summary log
        summary_data = {
            "scan_id": scan_id,
            "event_type": "scan_summary",
            "target": ctx.target,
            "pipeline_name": ctx.get("pipeline_name"),
            "pipeline_version": ctx.get("pipeline_version"),
            "data_keys": list(ctx.data.keys()),
        }
        self.add_log(
            f"Scan completed for {ctx.target}",
            summary_data,
            level="info",
            tags=[f"target:{ctx.target}", f"scan_id:{scan_id}"],
        )

        # Add findings as logs
        finding_count = 0
        high_severity_findings = []
        for key, value in ctx.data.items():
            if key.startswith("finding_"):
                finding_count += 1
                finding_data = {
                    "scan_id": scan_id,
                    "finding_key": key,
                    **value,
                }
                severity = value.get("severity", "unknown")
                level = "error" if severity in ("critical", "high") else "warning" if severity == "medium" else "info"
                self.add_log(
                    f"Finding: {value.get('title', 'Unknown')}",
                    finding_data,
                    level=level,
                    tags=[f"severity:{severity}", f"scan_id:{scan_id}"],
                )

                if severity in ("critical", "high"):
                    high_severity_findings.append(value.get("title", "Unknown"))

        # Add key results as logs
        export_keys = [
            ("domain_profile", "Domain profile collected"),
            ("dns_enumeration", "DNS enumeration complete"),
            ("subdomains", "Subdomain discovery complete"),
            ("port_scan", "Port scan complete"),
            ("ssl_analysis", "SSL analysis complete"),
            ("greynoise_result", "GreyNoise query complete"),
            ("abuseipdb_result", "AbuseIPDB query complete"),
            ("urlscan_result", "URLScan.io query complete"),
            ("passivedns_result", "Passive DNS query complete"),
            ("otx_indicator", "AlienVault OTX query complete"),
        ]

        for key, message in export_keys:
            if key in ctx.data:
                self.add_log(
                    message,
                    {"scan_id": scan_id, "result_type": key, "data": ctx.data[key]},
                    level="info",
                    tags=[f"result_type:{key}", f"scan_id:{scan_id}"],
                )

        # Flush logs
        result = self.flush_logs()

        # Send summary event if there are high severity findings
        if high_severity_findings:
            event_result = self.send_event(
                title=f"RedOPS Scan Alert: {finding_count} findings for {ctx.target}",
                text=f"High severity findings:\n" + "\n".join(f"- {f}" for f in high_severity_findings[:10]),
                alert_type="error",
                tags=[f"target:{ctx.target}", f"scan_id:{scan_id}"],
                aggregation_key=f"redops_scan_{ctx.target}",
            )
            result["event_result"] = event_result

        return result


def export_to_datadog(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Export scan results to Datadog.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - api_key: Datadog API key (or DD_API_KEY env var)
            - site: Datadog site (us1, us3, us5, eu1, ap1, us1-fed)
            - service: Service name (default: redops)
            - tags: Additional tags (comma-separated)
            - scan_id: Optional scan identifier

    Returns:
        Updated context with export result
    """
    params = params or {}

    tags_param = params.get("tags", "")
    tags = [t.strip() for t in tags_param.split(",")] if tags_param else []

    config = DatadogConfig(
        api_key=params.get("api_key") or os.environ.get("DD_API_KEY", ""),
        site=params.get("site") or os.environ.get("DD_SITE", "us1"),
        service=params.get("service") or os.environ.get("DD_SERVICE", "redops"),
        source=params.get("source") or os.environ.get("DD_SOURCE", "redops"),
        tags=tags,
    )

    exporter = DatadogExporter(config)

    ctx.log("Exporting to Datadog", level="INFO")

    result = exporter.export_context(ctx, scan_id=params.get("scan_id"))

    if result.get("success"):
        ctx.log(f"Datadog export complete: {result.get('sent', 0)} logs", level="INFO")
    else:
        ctx.log(f"Datadog export failed: {result.get('error')}", level="WARNING")

    ctx.add("datadog_export_result", result)
    return ctx
