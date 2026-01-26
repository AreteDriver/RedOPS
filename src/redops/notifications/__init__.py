"""
Notifications module for RedOPS.

Supports Email, Slack, Teams, Discord, PagerDuty, and custom webhooks.
"""

from .webhooks import (
    WebhookProvider,
    NotificationMessage,
    NotificationLevel,
    SlackWebhook,
    TeamsWebhook,
    DiscordWebhook,
    GenericWebhook,
    PagerDutyWebhook,
)
from .manager import (
    NotificationConfig,
    NotificationManager,
    get_notification_manager,
    notify,
)
from .email import (
    EmailConfig,
    EmailBackend,
    EmailTemplate,
    render_email_template,
    TEMPLATES as EMAIL_TEMPLATES,
)

__all__ = [
    # Message types
    "NotificationMessage",
    "NotificationLevel",
    # Webhook Providers
    "WebhookProvider",
    "SlackWebhook",
    "TeamsWebhook",
    "DiscordWebhook",
    "GenericWebhook",
    "PagerDutyWebhook",
    # Email
    "EmailConfig",
    "EmailBackend",
    "EmailTemplate",
    "render_email_template",
    "EMAIL_TEMPLATES",
    # Manager
    "NotificationConfig",
    "NotificationManager",
    "get_notification_manager",
    "notify",
]
