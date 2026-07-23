"""
Email notification backend for RedOPS.

Provides SMTP-based email notifications with template support.
"""

import logging
import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from string import Template
from typing import Any

from .webhooks import NotificationLevel, NotificationMessage, WebhookProvider

logger = logging.getLogger(__name__)


@dataclass
class EmailConfig:
    """SMTP email configuration."""

    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    use_ssl: bool = False
    timeout: int = 30

    from_address: str = "redops@localhost"
    from_name: str = "RedOPS Security"
    reply_to: str = ""

    # Defaults
    default_recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "EmailConfig":
        """Create config from environment variables."""
        return cls(
            smtp_host=os.environ.get("SMTP_HOST", "localhost"),
            smtp_port=int(os.environ.get("SMTP_PORT", "587")),
            smtp_user=os.environ.get("SMTP_USER", ""),
            smtp_password=os.environ.get("SMTP_PASSWORD", ""),
            use_tls=os.environ.get("SMTP_TLS", "true").lower() == "true",
            use_ssl=os.environ.get("SMTP_SSL", "false").lower() == "true",
            timeout=int(os.environ.get("SMTP_TIMEOUT", "30")),
            from_address=os.environ.get("EMAIL_FROM", "redops@localhost"),
            from_name=os.environ.get("EMAIL_FROM_NAME", "RedOPS Security"),
            reply_to=os.environ.get("EMAIL_REPLY_TO", ""),
            default_recipients=os.environ.get("EMAIL_RECIPIENTS", "").split(",")
            if os.environ.get("EMAIL_RECIPIENTS")
            else [],
        )


@dataclass
class EmailTemplate:
    """Email template with HTML and plain text versions."""

    name: str
    subject: str
    html_body: str
    text_body: str
    variables: list[str] = field(default_factory=list)

    def render(self, data: dict[str, Any]) -> tuple:
        """
        Render template with data.

        Returns:
            Tuple of (subject, html_body, text_body)
        """
        subject = Template(self.subject).safe_substitute(data)
        html = Template(self.html_body).safe_substitute(data)
        text = Template(self.text_body).safe_substitute(data)
        return subject, html, text


# Built-in email templates
SCAN_COMPLETE_TEMPLATE = EmailTemplate(
    name="scan_complete",
    subject="[RedOPS] Scan Complete: $target",
    html_body="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #1a1a2e; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f5f5f5; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background: white; border-radius: 8px; min-width: 80px; }
        .critical { color: #9c27b0; }
        .high { color: #f44336; }
        .medium { color: #ff9800; }
        .low { color: #2196f3; }
        .info { color: #4caf50; }
        .count { font-size: 24px; font-weight: bold; }
        .label { font-size: 12px; text-transform: uppercase; }
        .button { display: inline-block; padding: 12px 24px; background: #1a1a2e; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ RedOPS Security Scan</h1>
        </div>
        <div class="content">
            <h2>Scan Complete</h2>
            <p><strong>Target:</strong> $target</p>
            <p><strong>Completed:</strong> $timestamp</p>

            <div class="stats">
                <div class="stat-box">
                    <div class="count critical">$critical</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="count high">$high</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-box">
                    <div class="count medium">$medium</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-box">
                    <div class="count low">$low</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-box">
                    <div class="count info">$info</div>
                    <div class="label">Info</div>
                </div>
            </div>

            <p><strong>Total Findings:</strong> $total_findings</p>

            $details

            <p style="text-align: center; margin-top: 30px;">
                <a href="$report_url" class="button">View Full Report</a>
            </p>
        </div>
        <div class="footer">
            <p>This is an automated message from RedOPS Security Assessment Framework</p>
        </div>
    </div>
</body>
</html>
    """,
    text_body="""
RedOPS Security Scan Complete
=============================

Target: $target
Completed: $timestamp

Findings Summary:
- Critical: $critical
- High: $high
- Medium: $medium
- Low: $low
- Info: $info

Total Findings: $total_findings

$details

View Full Report: $report_url

---
This is an automated message from RedOPS Security Assessment Framework
    """,
    variables=[
        "target",
        "timestamp",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "total_findings",
        "details",
        "report_url",
    ],
)


CRITICAL_FINDING_TEMPLATE = EmailTemplate(
    name="critical_finding",
    subject="[CRITICAL] Security Alert: $title",
    html_body="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #9c27b0; color: white; padding: 20px; text-align: center; }
        .alert-box { background: #fce4ec; border-left: 4px solid #9c27b0; padding: 15px; margin: 20px 0; }
        .content { padding: 20px; background: #f5f5f5; }
        .field { margin: 10px 0; }
        .field-label { font-weight: bold; color: #666; }
        .button { display: inline-block; padding: 12px 24px; background: #9c27b0; color: white; text-decoration: none; border-radius: 4px; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 CRITICAL SECURITY ALERT</h1>
        </div>
        <div class="content">
            <div class="alert-box">
                <h2>$title</h2>
            </div>

            <div class="field">
                <span class="field-label">Target:</span> $target
            </div>
            <div class="field">
                <span class="field-label">Severity:</span> <strong style="color: #9c27b0;">CRITICAL</strong>
            </div>
            <div class="field">
                <span class="field-label">Detected:</span> $timestamp
            </div>

            <h3>Description</h3>
            <p>$description</p>

            <h3>Remediation</h3>
            <p>$remediation</p>

            <p style="text-align: center; margin-top: 30px;">
                <a href="$finding_url" class="button">View Finding Details</a>
            </p>
        </div>
        <div class="footer">
            <p>⚠️ This finding requires immediate attention</p>
        </div>
    </div>
</body>
</html>
    """,
    text_body="""
🚨 CRITICAL SECURITY ALERT
==========================

$title

Target: $target
Severity: CRITICAL
Detected: $timestamp

Description:
$description

Remediation:
$remediation

View Finding Details: $finding_url

---
⚠️ This finding requires immediate attention
    """,
    variables=[
        "title",
        "target",
        "timestamp",
        "description",
        "remediation",
        "finding_url",
    ],
)


DAILY_DIGEST_TEMPLATE = EmailTemplate(
    name="daily_digest",
    subject="[RedOPS] Daily Security Digest - $date",
    html_body="""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #1a1a2e; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f5f5f5; }
        .summary-box { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .metric { display: inline-block; text-align: center; padding: 10px 20px; }
        .metric-value { font-size: 28px; font-weight: bold; color: #1a1a2e; }
        .metric-label { font-size: 12px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #1a1a2e; color: white; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Daily Security Digest</h1>
            <p>$date</p>
        </div>
        <div class="content">
            <div class="summary-box">
                <div class="metric">
                    <div class="metric-value">$scans_completed</div>
                    <div class="metric-label">Scans Completed</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$new_findings</div>
                    <div class="metric-label">New Findings</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$resolved_findings</div>
                    <div class="metric-label">Resolved</div>
                </div>
            </div>

            <h3>Top Findings</h3>
            $findings_table

            <h3>Recent Scans</h3>
            $scans_table

        </div>
        <div class="footer">
            <p>RedOPS Security Assessment Framework - Daily Digest</p>
        </div>
    </div>
</body>
</html>
    """,
    text_body="""
Daily Security Digest - $date
=============================

Summary:
- Scans Completed: $scans_completed
- New Findings: $new_findings
- Resolved: $resolved_findings

Top Findings:
$findings_list

Recent Scans:
$scans_list

---
RedOPS Security Assessment Framework - Daily Digest
    """,
    variables=[
        "date",
        "scans_completed",
        "new_findings",
        "resolved_findings",
        "findings_table",
        "scans_table",
        "findings_list",
        "scans_list",
    ],
)


# Template registry
TEMPLATES: dict[str, EmailTemplate] = {
    "scan_complete": SCAN_COMPLETE_TEMPLATE,
    "critical_finding": CRITICAL_FINDING_TEMPLATE,
    "daily_digest": DAILY_DIGEST_TEMPLATE,
}


def render_email_template(
    template_name: str,
    data: dict[str, Any],
) -> tuple:
    """
    Render an email template.

    Args:
        template_name: Template name
        data: Template variables

    Returns:
        Tuple of (subject, html_body, text_body)
    """
    template = TEMPLATES.get(template_name)
    if not template:
        raise ValueError(f"Unknown template: {template_name}")
    return template.render(data)


class EmailBackend(WebhookProvider):
    """
    SMTP email notification backend.

    Sends emails via SMTP with support for:
    - HTML and plain text emails
    - Templates
    - Attachments
    - CC/BCC
    """

    LEVEL_SUBJECTS = {
        NotificationLevel.INFO: "ℹ️",
        NotificationLevel.WARNING: "⚠️",
        NotificationLevel.ERROR: "❌",
        NotificationLevel.CRITICAL: "🚨",
        NotificationLevel.SUCCESS: "✅",
    }

    def __init__(self, config: EmailConfig | None = None):
        """
        Initialize email backend.

        Args:
            config: Email configuration
        """
        self.config = config or EmailConfig.from_env()

    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message as email payload (not used directly)."""
        return message.to_dict()

    def send(self, message: NotificationMessage) -> bool:
        """Send notification as email."""
        recipients = self.config.default_recipients
        if not recipients:
            logger.warning("No email recipients configured")
            return False

        return self.send_email(
            to=recipients,
            subject=f"{self.LEVEL_SUBJECTS.get(message.level, '')} {message.title}",
            body=message.body,
            html_body=self._format_html(message),
        )

    def send_email(
        self,
        to: list[str],
        subject: str,
        body: str,
        html_body: str | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        reply_to: str | None = None,
    ) -> bool:
        """
        Send an email.

        Args:
            to: Recipient addresses
            subject: Email subject
            body: Plain text body
            html_body: HTML body (optional)
            cc: CC addresses
            bcc: BCC addresses
            attachments: List of attachment dicts with 'filename' and 'content'
            reply_to: Reply-to address

        Returns:
            True if sent successfully
        """
        try:
            # Create message
            if html_body:
                msg = MIMEMultipart("alternative")
                msg.attach(MIMEText(body, "plain"))
                msg.attach(MIMEText(html_body, "html"))
            else:
                msg = MIMEText(body, "plain")

            # Set headers
            msg["Subject"] = subject
            msg["From"] = f"{self.config.from_name} <{self.config.from_address}>"
            msg["To"] = ", ".join(to)

            if cc:
                msg["Cc"] = ", ".join(cc)
            if reply_to or self.config.reply_to:
                msg["Reply-To"] = reply_to or self.config.reply_to

            # Add attachments
            if attachments:
                # Convert to multipart if needed
                if not isinstance(msg, MIMEMultipart):
                    text_content = msg.get_payload()
                    msg = MIMEMultipart()
                    msg.attach(MIMEText(text_content, "plain"))

                for attachment in attachments:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment["content"])
                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f'attachment; filename="{attachment["filename"]}"',
                    )
                    msg.attach(part)

            # Build recipient list
            all_recipients = list(to)
            if cc:
                all_recipients.extend(cc)
            if bcc:
                all_recipients.extend(bcc)
            if self.config.bcc:
                all_recipients.extend(self.config.bcc)

            # Send
            self._send_smtp(msg, all_recipients)

            logger.info(f"Email sent to {len(all_recipients)} recipients: {subject}")
            return True

        except (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def _send_smtp(self, msg: MIMEText, recipients: list[str]) -> None:
        """Send message via SMTP."""
        if self.config.use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(
                self.config.smtp_host,
                self.config.smtp_port,
                context=context,
                timeout=self.config.timeout,
            ) as server:
                if self.config.smtp_user:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(
                    self.config.from_address,
                    recipients,
                    msg.as_string(),
                )
        else:
            with smtplib.SMTP(
                self.config.smtp_host,
                self.config.smtp_port,
                timeout=self.config.timeout,
            ) as server:
                if self.config.use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                if self.config.smtp_user:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(
                    self.config.from_address,
                    recipients,
                    msg.as_string(),
                )

    def _format_html(self, message: NotificationMessage) -> str:
        """Format message as HTML email."""
        level_colors = {
            NotificationLevel.INFO: "#2196F3",
            NotificationLevel.WARNING: "#FFC107",
            NotificationLevel.ERROR: "#F44336",
            NotificationLevel.CRITICAL: "#9C27B0",
            NotificationLevel.SUCCESS: "#4CAF50",
        }
        color = level_colors.get(message.level, "#808080")

        # Build fields HTML
        fields_html = ""
        if message.fields:
            fields_html = "<table style='width: 100%; border-collapse: collapse; margin: 15px 0;'>"
            for key, value in message.fields.items():
                fields_html += f"""
                <tr>
                    <td style='padding: 8px; border-bottom: 1px solid #eee; font-weight: bold; width: 30%;'>{key}</td>
                    <td style='padding: 8px; border-bottom: 1px solid #eee;'>{value}</td>
                </tr>
                """
            fields_html += "</table>"

        # Build button HTML
        button_html = ""
        if message.url:
            button_html = f"""
            <p style='text-align: center; margin-top: 20px;'>
                <a href='{message.url}' style='display: inline-block; padding: 12px 24px; background: {color}; color: white; text-decoration: none; border-radius: 4px;'>View Details</a>
            </p>
            """

        return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: {color}; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
        .content {{ padding: 20px; background: #f9f9f9; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px; }}
        .footer {{ text-align: center; padding: 15px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.LEVEL_SUBJECTS.get(message.level, "")} {message.title}</h1>
        </div>
        <div class="content">
            <p>{message.body}</p>
            {fields_html}
            {button_html}
        </div>
        <div class="footer">
            <p>Source: {message.source} | {message.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        </div>
    </div>
</body>
</html>
        """

    def send_template(
        self,
        template_name: str,
        to: list[str],
        data: dict[str, Any],
        **kwargs,
    ) -> bool:
        """
        Send email using a template.

        Args:
            template_name: Template name
            to: Recipient addresses
            data: Template data
            **kwargs: Additional send_email arguments

        Returns:
            True if sent successfully
        """
        try:
            subject, html_body, text_body = render_email_template(template_name, data)
            return self.send_email(
                to=to,
                subject=subject,
                body=text_body,
                html_body=html_body,
                **kwargs,
            )
        except ValueError as e:
            logger.error(f"Template error: {e}")
            return False

    def test_connection(self) -> bool:
        """Test SMTP connection."""
        try:
            if self.config.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.config.smtp_host,
                    self.config.smtp_port,
                    context=context,
                    timeout=self.config.timeout,
                ) as server:
                    if self.config.smtp_user:
                        server.login(self.config.smtp_user, self.config.smtp_password)
                    return True
            else:
                with smtplib.SMTP(
                    self.config.smtp_host,
                    self.config.smtp_port,
                    timeout=self.config.timeout,
                ) as server:
                    if self.config.use_tls:
                        server.starttls()
                    if self.config.smtp_user:
                        server.login(self.config.smtp_user, self.config.smtp_password)
                    return True
        except (ConnectionError, TimeoutError, OSError, RuntimeError, ValueError) as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False
