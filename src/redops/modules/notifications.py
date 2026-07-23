"""
Notification Module for RedOPS.

Sends scan results and alerts to various channels:
- Slack
- Discord
- Email (SMTP)
- Webhooks (generic)
"""

import logging
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class NotificationConfig:
    """Configuration for notifications."""

    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    notify_emails: list[str] | None = None
    webhook_urls: list[str] | None = None

    @classmethod
    def from_env(cls) -> "NotificationConfig":
        """Load configuration from environment variables."""
        emails = os.getenv("NOTIFY_EMAILS", "")
        webhooks = os.getenv("WEBHOOK_URLS", "")

        return cls(
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL"),
            smtp_host=os.getenv("SMTP_HOST"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_user=os.getenv("SMTP_USER"),
            smtp_password=os.getenv("SMTP_PASSWORD"),
            smtp_from=os.getenv("SMTP_FROM"),
            notify_emails=[e.strip() for e in emails.split(",") if e.strip()],
            webhook_urls=[w.strip() for w in webhooks.split(",") if w.strip()],
        )


class NotificationService:
    """Service for sending notifications."""

    def __init__(self, config: NotificationConfig | None = None):
        """Initialize the notification service."""
        self.config = config or NotificationConfig.from_env()
        self._validate_dependencies()

    def _validate_dependencies(self):
        """Check if required dependencies are available."""
        if not HAS_REQUESTS:
            # Only warn if webhook URLs are configured
            if (
                self.config.slack_webhook_url
                or self.config.discord_webhook_url
                or self.config.webhook_urls
            ):
                raise ImportError(
                    "requests library required for webhook notifications. "
                    "Install with: pip install requests"
                )

    def notify_scan_complete(
        self,
        target: str,
        preset: str,
        findings_count: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
        report_path: str | None = None,
        extra_data: dict[str, Any] | None = None,
    ) -> dict[str, bool]:
        """
        Send notification that a scan has completed.

        Returns:
            Dict mapping channel names to success status
        """
        results = {}

        message = self._format_scan_message(
            target=target,
            preset=preset,
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
            report_path=report_path,
        )

        # Slack
        if self.config.slack_webhook_url:
            results["slack"] = self._send_slack(message, critical_count, high_count)

        # Discord
        if self.config.discord_webhook_url:
            results["discord"] = self._send_discord(message, critical_count, high_count)

        # Email
        if self.config.smtp_host and self.config.notify_emails:
            results["email"] = self._send_email(
                subject=f"RedOPS Scan Complete: {target}",
                body=message["text"],
            )

        # Generic webhooks
        if self.config.webhook_urls:
            webhook_data = {
                "event": "scan_complete",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "preset": preset,
                "findings_count": findings_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "report_path": report_path,
                **(extra_data or {}),
            }
            for i, url in enumerate(self.config.webhook_urls):
                results[f"webhook_{i}"] = self._send_webhook(url, webhook_data)

        return results

    def notify_alert(
        self,
        title: str,
        message: str,
        severity: str = "info",
        extra_data: dict[str, Any] | None = None,
    ) -> dict[str, bool]:
        """
        Send an alert notification.

        Args:
            title: Alert title
            message: Alert message
            severity: info, warning, error, critical
        """
        results = {}

        # Determine color based on severity
        colors = {
            "info": "#36a64f",
            "warning": "#ffcc00",
            "error": "#ff6600",
            "critical": "#ff0000",
        }
        color = colors.get(severity, "#36a64f")

        if self.config.slack_webhook_url:
            results["slack"] = self._send_slack_alert(title, message, color)

        if self.config.discord_webhook_url:
            results["discord"] = self._send_discord_alert(title, message, color)

        if self.config.smtp_host and self.config.notify_emails:
            results["email"] = self._send_email(
                subject=f"[RedOPS {severity.upper()}] {title}",
                body=message,
            )

        return results

    def _format_scan_message(
        self,
        target: str,
        preset: str,
        findings_count: int,
        critical_count: int,
        high_count: int,
        report_path: str | None,
    ) -> dict[str, Any]:
        """Format scan completion message."""
        status = "completed"
        if critical_count > 0:
            status = "completed with CRITICAL findings"
        elif high_count > 0:
            status = "completed with HIGH findings"

        text = f"""RedOPS Security Scan {status}

Target: {target}
Preset: {preset}
Total Findings: {findings_count}
Critical: {critical_count}
High: {high_count}
"""
        if report_path:
            text += f"Report: {report_path}\n"

        return {
            "title": f"RedOPS Scan {status.title()}",
            "text": text,
            "target": target,
            "preset": preset,
            "findings_count": findings_count,
            "critical_count": critical_count,
            "high_count": high_count,
        }

    def _send_slack(self, message: dict[str, Any], critical: int, high: int) -> bool:
        """Send notification to Slack."""
        if not HAS_REQUESTS:
            return False

        # Determine color
        if critical > 0:
            color = "#ff0000"
        elif high > 0:
            color = "#ff6600"
        else:
            color = "#36a64f"

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": message["title"],
                    "text": message["text"],
                    "fields": [
                        {"title": "Target", "value": message["target"], "short": True},
                        {"title": "Preset", "value": message["preset"], "short": True},
                        {
                            "title": "Findings",
                            "value": str(message["findings_count"]),
                            "short": True,
                        },
                        {
                            "title": "Critical",
                            "value": str(message["critical_count"]),
                            "short": True,
                        },
                    ],
                    "footer": "RedOPS Security Scanner",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

        try:
            response = requests.post(
                self.config.slack_webhook_url,
                json=payload,
                timeout=10,
            )
            return response.status_code == 200
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
            logger.warning("Failed to send Slack notification: %s", e)
            return False

    def _send_slack_alert(self, title: str, message: str, color: str) -> bool:
        """Send alert to Slack."""
        if not HAS_REQUESTS:
            return False

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": message,
                    "footer": "RedOPS Alert",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ]
        }

        try:
            response = requests.post(
                self.config.slack_webhook_url,
                json=payload,
                timeout=10,
            )
            return response.status_code == 200
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
            logger.warning("Failed to send Slack alert: %s", e)
            return False

    def _send_discord(self, message: dict[str, Any], critical: int, high: int) -> bool:
        """Send notification to Discord."""
        if not HAS_REQUESTS:
            return False

        # Determine color (Discord uses decimal)
        if critical > 0:
            color = 16711680  # Red
        elif high > 0:
            color = 16744448  # Orange
        else:
            color = 3066993  # Green

        payload = {
            "embeds": [
                {
                    "title": message["title"],
                    "description": message["text"],
                    "color": color,
                    "fields": [
                        {"name": "Target", "value": message["target"], "inline": True},
                        {"name": "Preset", "value": message["preset"], "inline": True},
                        {
                            "name": "Findings",
                            "value": str(message["findings_count"]),
                            "inline": True,
                        },
                    ],
                    "footer": {"text": "RedOPS Security Scanner"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ]
        }

        try:
            response = requests.post(
                self.config.discord_webhook_url,
                json=payload,
                timeout=10,
            )
            return response.status_code in (200, 204)
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
            logger.warning("Failed to send Discord notification: %s", e)
            return False

    def _send_discord_alert(self, title: str, message: str, color: str) -> bool:
        """Send alert to Discord."""
        if not HAS_REQUESTS:
            return False

        # Convert hex color to decimal
        color_int = int(color.lstrip("#"), 16)

        payload = {
            "embeds": [
                {
                    "title": title,
                    "description": message,
                    "color": color_int,
                    "footer": {"text": "RedOPS Alert"},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ]
        }

        try:
            response = requests.post(
                self.config.discord_webhook_url,
                json=payload,
                timeout=10,
            )
            return response.status_code in (200, 204)
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
            logger.warning("Failed to send Discord alert: %s", e)
            return False

    def _send_email(self, subject: str, body: str) -> bool:
        """Send email notification."""
        if not self.config.smtp_host or not self.config.notify_emails:
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.config.smtp_from or self.config.smtp_user
            msg["To"] = ", ".join(self.config.notify_emails)
            msg["Subject"] = subject

            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.starttls()
                if self.config.smtp_user and self.config.smtp_password:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.send_message(msg)

            return True
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError, smtplib.SMTPException) as e:
            logger.warning("Failed to send email notification: %s", e)
            return False

    def _send_webhook(self, url: str, data: dict[str, Any]) -> bool:
        """Send to generic webhook."""
        if not HAS_REQUESTS:
            return False

        try:
            response = requests.post(url, json=data, timeout=10)
            return response.status_code in (200, 201, 202, 204)
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
            logger.warning("Failed to send webhook to %s: %s", url, e)
            return False


# Module integration function
def notify_on_complete(ctx, params: dict[str, Any] | None = None):
    """Pipeline module to send notifications after scan."""
    params = params or {}

    try:
        service = NotificationService()

        # Extract findings info from context
        findings_count = len(ctx.data.get("findings", []))
        critical_count = sum(
            1 for f in ctx.data.get("findings", []) if f.get("severity") == "critical"
        )
        high_count = sum(
            1 for f in ctx.data.get("findings", []) if f.get("severity") == "high"
        )

        results = service.notify_scan_complete(
            target=ctx.target or "unknown",
            preset=params.get("preset", "unknown"),
            findings_count=findings_count,
            critical_count=critical_count,
            high_count=high_count,
            report_path=ctx.data.get("report_path"),
        )

        ctx.add("notification_results", results)
        ctx.log(f"Notifications sent: {results}", level="INFO")

    except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as e:
        ctx.log(f"Notification failed: {e}", level="WARNING")

    return ctx
