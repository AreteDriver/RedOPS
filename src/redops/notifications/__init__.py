"""
Webhook notifications for RedOPS.

Supports Slack, Teams, Discord, PagerDuty, and custom webhooks.
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

__all__ = [
    # Message types
    "NotificationMessage",
    "NotificationLevel",
    # Providers
    "WebhookProvider",
    "SlackWebhook",
    "TeamsWebhook",
    "DiscordWebhook",
    "GenericWebhook",
    "PagerDutyWebhook",
    # Manager
    "NotificationConfig",
    "NotificationManager",
    "get_notification_manager",
    "notify",
]
