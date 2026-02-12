"""
Webhook notification providers for RedOPS.

Supports Slack, Microsoft Teams, Discord, and custom webhooks.
"""

from typing import Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from enum import Enum
import logging
import os

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = logging.getLogger(__name__)


class NotificationLevel(Enum):
    """Notification severity level."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SUCCESS = "success"


@dataclass
class NotificationMessage:
    """A notification message to send."""

    title: str
    body: str
    level: NotificationLevel = NotificationLevel.INFO
    fields: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "redops"
    url: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "body": self.body,
            "level": self.level.value,
            "fields": self.fields,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "url": self.url,
            "tags": self.tags,
        }


class WebhookProvider(ABC):
    """Base class for webhook providers."""

    @abstractmethod
    def send(self, message: NotificationMessage) -> bool:
        """Send a notification message."""
        pass

    @abstractmethod
    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message for the provider's API."""
        pass


class SlackWebhook(WebhookProvider):
    """
    Slack Incoming Webhook provider.

    Sends notifications to Slack channels via webhooks.
    """

    LEVEL_COLORS = {
        NotificationLevel.INFO: "#2196F3",
        NotificationLevel.WARNING: "#FFC107",
        NotificationLevel.ERROR: "#F44336",
        NotificationLevel.CRITICAL: "#9C27B0",
        NotificationLevel.SUCCESS: "#4CAF50",
    }

    LEVEL_EMOJI = {
        NotificationLevel.INFO: ":information_source:",
        NotificationLevel.WARNING: ":warning:",
        NotificationLevel.ERROR: ":x:",
        NotificationLevel.CRITICAL: ":rotating_light:",
        NotificationLevel.SUCCESS: ":white_check_mark:",
    }

    def __init__(
        self,
        webhook_url: str | None = None,
        channel: str | None = None,
        username: str = "RedOPS",
        icon_emoji: str = ":shield:",
    ):
        """
        Initialize Slack webhook.

        Args:
            webhook_url: Slack webhook URL
            channel: Override channel (optional)
            username: Bot username
            icon_emoji: Bot emoji icon
        """
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji

    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message as Slack Block Kit payload."""
        color = self.LEVEL_COLORS.get(message.level, "#808080")
        emoji = self.LEVEL_EMOJI.get(message.level, ":bell:")

        attachment = {
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {message.title}",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": message.body,
                    },
                },
            ],
        }

        # Add fields
        if message.fields:
            fields_block = {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{k}:*\n{v}"}
                    for k, v in list(message.fields.items())[:10]
                ],
            }
            attachment["blocks"].append(fields_block)

        # Add link button if URL provided
        if message.url:
            attachment["blocks"].append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "View Details"},
                            "url": message.url,
                        }
                    ],
                }
            )

        # Add timestamp footer
        attachment["blocks"].append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Source: {message.source} | {message.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    }
                ],
            }
        )

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [attachment],
        }

        if self.channel:
            payload["channel"] = self.channel

        return payload

    def send(self, message: NotificationMessage) -> bool:
        """Send notification to Slack."""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        if not HAS_HTTPX:
            logger.error("httpx not installed, cannot send Slack notification")
            return False

        payload = self.format_payload(message)

        try:
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                logger.info(f"Slack notification sent: {message.title}")
                return True
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False


class TeamsWebhook(WebhookProvider):
    """
    Microsoft Teams Incoming Webhook provider.

    Uses Adaptive Cards for rich formatting.
    """

    LEVEL_COLORS = {
        NotificationLevel.INFO: "accent",
        NotificationLevel.WARNING: "warning",
        NotificationLevel.ERROR: "attention",
        NotificationLevel.CRITICAL: "attention",
        NotificationLevel.SUCCESS: "good",
    }

    def __init__(self, webhook_url: str | None = None):
        """
        Initialize Teams webhook.

        Args:
            webhook_url: Teams webhook URL
        """
        self.webhook_url = webhook_url or os.environ.get("TEAMS_WEBHOOK_URL", "")

    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message as Teams Adaptive Card."""
        color = self.LEVEL_COLORS.get(message.level, "default")

        body = [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": message.title,
                "color": color,
            },
            {
                "type": "TextBlock",
                "text": message.body,
                "wrap": True,
            },
        ]

        # Add fields as fact set
        if message.fields:
            body.append(
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": k, "value": v}
                        for k, v in list(message.fields.items())[:10]
                    ],
                }
            )

        # Add timestamp
        body.append(
            {
                "type": "TextBlock",
                "text": f"Source: {message.source} | {message.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "size": "Small",
                "isSubtle": True,
            }
        )

        card = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "body": body,
        }

        # Add action button if URL provided
        if message.url:
            card["actions"] = [
                {
                    "type": "Action.OpenUrl",
                    "title": "View Details",
                    "url": message.url,
                }
            ]

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }

    def send(self, message: NotificationMessage) -> bool:
        """Send notification to Teams."""
        if not self.webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False

        if not HAS_HTTPX:
            logger.error("httpx not installed, cannot send Teams notification")
            return False

        payload = self.format_payload(message)

        try:
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                logger.info(f"Teams notification sent: {message.title}")
                return True
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False


class DiscordWebhook(WebhookProvider):
    """
    Discord Webhook provider.

    Uses embeds for rich formatting.
    """

    LEVEL_COLORS = {
        NotificationLevel.INFO: 3447003,  # Blue
        NotificationLevel.WARNING: 16776960,  # Yellow
        NotificationLevel.ERROR: 15158332,  # Red
        NotificationLevel.CRITICAL: 10181046,  # Purple
        NotificationLevel.SUCCESS: 3066993,  # Green
    }

    LEVEL_EMOJI = {
        NotificationLevel.INFO: "ℹ️",
        NotificationLevel.WARNING: "⚠️",
        NotificationLevel.ERROR: "❌",
        NotificationLevel.CRITICAL: "🚨",
        NotificationLevel.SUCCESS: "✅",
    }

    def __init__(
        self,
        webhook_url: str | None = None,
        username: str = "RedOPS",
        avatar_url: str | None = None,
    ):
        """
        Initialize Discord webhook.

        Args:
            webhook_url: Discord webhook URL
            username: Bot username
            avatar_url: Bot avatar URL
        """
        self.webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.username = username
        self.avatar_url = avatar_url

    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message as Discord embed."""
        color = self.LEVEL_COLORS.get(message.level, 8421504)
        emoji = self.LEVEL_EMOJI.get(message.level, "🔔")

        embed = {
            "title": f"{emoji} {message.title}",
            "description": message.body,
            "color": color,
            "timestamp": message.timestamp.isoformat(),
            "footer": {
                "text": f"Source: {message.source}",
            },
        }

        # Add fields
        if message.fields:
            embed["fields"] = [
                {"name": k, "value": v, "inline": True}
                for k, v in list(message.fields.items())[:25]
            ]

        # Add URL
        if message.url:
            embed["url"] = message.url

        payload = {
            "username": self.username,
            "embeds": [embed],
        }

        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url

        return payload

    def send(self, message: NotificationMessage) -> bool:
        """Send notification to Discord."""
        if not self.webhook_url:
            logger.warning("Discord webhook URL not configured")
            return False

        if not HAS_HTTPX:
            logger.error("httpx not installed, cannot send Discord notification")
            return False

        payload = self.format_payload(message)

        try:
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                logger.info(f"Discord notification sent: {message.title}")
                return True
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False


class GenericWebhook(WebhookProvider):
    """
    Generic webhook provider.

    Sends JSON payload to any HTTP endpoint.
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        method: str = "POST",
        headers: dict[str, str] | None = None,
        auth_token: str | None = None,
        auth_header: str = "Authorization",
    ):
        """
        Initialize generic webhook.

        Args:
            webhook_url: Target webhook URL
            method: HTTP method (POST, PUT)
            headers: Additional headers
            auth_token: Authentication token
            auth_header: Header name for auth token
        """
        self.webhook_url = webhook_url or os.environ.get("WEBHOOK_URL", "")
        self.method = method.upper()
        self.headers = headers or {}
        self.auth_token = auth_token or os.environ.get("WEBHOOK_AUTH_TOKEN")
        self.auth_header = auth_header

    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message as generic JSON."""
        return {
            "title": message.title,
            "body": message.body,
            "level": message.level.value,
            "fields": message.fields,
            "timestamp": message.timestamp.isoformat(),
            "source": message.source,
            "url": message.url,
            "tags": message.tags,
        }

    def send(self, message: NotificationMessage) -> bool:
        """Send notification to webhook."""
        if not self.webhook_url:
            logger.warning("Webhook URL not configured")
            return False

        if not HAS_HTTPX:
            logger.error("httpx not installed, cannot send webhook notification")
            return False

        payload = self.format_payload(message)
        headers = {"Content-Type": "application/json", **self.headers}

        if self.auth_token:
            headers[self.auth_header] = f"Bearer {self.auth_token}"

        try:
            with httpx.Client(timeout=30) as client:
                if self.method == "PUT":
                    response = client.put(
                        self.webhook_url, json=payload, headers=headers
                    )
                else:
                    response = client.post(
                        self.webhook_url, json=payload, headers=headers
                    )
                response.raise_for_status()
                logger.info(f"Webhook notification sent: {message.title}")
                return True
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")
            return False


class PagerDutyWebhook(WebhookProvider):
    """
    PagerDuty Events API v2 provider.

    Creates incidents/alerts via PagerDuty's Events API.
    """

    LEVEL_SEVERITY = {
        NotificationLevel.INFO: "info",
        NotificationLevel.WARNING: "warning",
        NotificationLevel.ERROR: "error",
        NotificationLevel.CRITICAL: "critical",
        NotificationLevel.SUCCESS: "info",
    }

    def __init__(
        self,
        routing_key: str | None = None,
        source: str = "redops",
    ):
        """
        Initialize PagerDuty webhook.

        Args:
            routing_key: PagerDuty integration key
            source: Source identifier
        """
        self.routing_key = routing_key or os.environ.get("PAGERDUTY_ROUTING_KEY", "")
        self.source = source
        self.events_url = "https://events.pagerduty.com/v2/enqueue"

    def format_payload(self, message: NotificationMessage) -> dict[str, Any]:
        """Format message as PagerDuty event."""
        severity = self.LEVEL_SEVERITY.get(message.level, "info")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": message.title,
                "source": self.source,
                "severity": severity,
                "timestamp": message.timestamp.isoformat(),
                "custom_details": {
                    "body": message.body,
                    **message.fields,
                },
            },
        }

        if message.url:
            payload["links"] = [{"href": message.url, "text": "View Details"}]

        return payload

    def send(self, message: NotificationMessage) -> bool:
        """Send notification to PagerDuty."""
        if not self.routing_key:
            logger.warning("PagerDuty routing key not configured")
            return False

        if not HAS_HTTPX:
            logger.error("httpx not installed, cannot send PagerDuty notification")
            return False

        payload = self.format_payload(message)

        try:
            with httpx.Client(timeout=30) as client:
                response = client.post(
                    self.events_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                logger.info(f"PagerDuty notification sent: {message.title}")
                return True
        except Exception as e:
            logger.error(f"Failed to send PagerDuty notification: {e}")
            return False
