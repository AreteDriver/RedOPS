"""Notification system module for RedOPS.

Provides multi-channel alerts (email, webhook, Slack), templates, and throttling.
"""

import hashlib
import json
import re
import smtplib
import threading
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Callable


class NotificationError(Exception):
    """Base exception for notification errors."""

    pass


class ChannelError(NotificationError):
    """Raised when a channel operation fails."""

    pass


class TemplateError(NotificationError):
    """Raised when template rendering fails."""

    pass


class ThrottleError(NotificationError):
    """Raised when notification is throttled."""

    pass


# =============================================================================
# Notification Types
# =============================================================================


class NotificationLevel(Enum):
    """Notification severity levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationStatus(Enum):
    """Status of a notification."""

    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    THROTTLED = "throttled"
    QUEUED = "queued"


@dataclass
class Notification:
    """A notification to be sent."""

    title: str
    message: str
    level: NotificationLevel = NotificationLevel.INFO
    channel: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = ""
    status: NotificationStatus = NotificationStatus.PENDING
    error: str | None = None
    sent_at: datetime | None = None
    retries: int = 0

    def __post_init__(self):
        if not self.id:
            self.id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate a unique ID for this notification."""
        content = f"{self.title}:{self.message}:{self.timestamp.isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "level": self.level.value,
            "channel": self.channel,
            "data": self.data,
            "tags": list(self.tags),
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "error": self.error,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "retries": self.retries,
        }


# =============================================================================
# Templates
# =============================================================================


class TemplateEngine:
    """Simple template engine for notifications."""

    VARIABLE_PATTERN = re.compile(r"\{\{\s*(\w+(?:\.\w+)*)\s*\}\}")

    def __init__(self):
        self._templates: dict[str, str] = {}
        self._filters: dict[str, Callable[[Any], str]] = {
            "upper": lambda x: str(x).upper(),
            "lower": lambda x: str(x).lower(),
            "title": lambda x: str(x).title(),
            "json": lambda x: json.dumps(x),
            "date": lambda x: (
                x.strftime("%Y-%m-%d") if hasattr(x, "strftime") else str(x)
            ),
            "datetime": lambda x: (
                x.strftime("%Y-%m-%d %H:%M:%S") if hasattr(x, "strftime") else str(x)
            ),
        }

    def register_template(self, name: str, template: str) -> None:
        """Register a named template."""
        self._templates[name] = template

    def get_template(self, name: str) -> str | None:
        """Get a registered template."""
        return self._templates.get(name)

    def register_filter(self, name: str, func: Callable[[Any], str]) -> None:
        """Register a custom filter."""
        self._filters[name] = func

    def render(self, template: str, context: dict[str, Any]) -> str:
        """Render a template with the given context."""

        def replace_var(match):
            var_path = match.group(1)
            parts = var_path.split(".")
            value = context

            try:
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part, "")
                    else:
                        value = getattr(value, part, "")
                return str(value) if value is not None else ""
            except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
                return ""

        return self.VARIABLE_PATTERN.sub(replace_var, template)

    def render_named(self, name: str, context: dict[str, Any]) -> str:
        """Render a named template."""
        template = self._templates.get(name)
        if not template:
            raise TemplateError(f"Template not found: {name}")
        return self.render(template, context)


# =============================================================================
# Throttling
# =============================================================================


@dataclass
class ThrottleRule:
    """A throttling rule."""

    key: str
    max_count: int
    window_seconds: int
    cooldown_seconds: int = 0


class ThrottleManager:
    """Manages notification throttling."""

    def __init__(self):
        self._counts: dict[str, list[datetime]] = {}
        self._cooldowns: dict[str, datetime] = {}
        self._rules: dict[str, ThrottleRule] = {}
        self._lock = threading.RLock()

    def add_rule(self, rule: ThrottleRule) -> None:
        """Add a throttling rule."""
        self._rules[rule.key] = rule

    def remove_rule(self, key: str) -> bool:
        """Remove a throttling rule."""
        if key in self._rules:
            del self._rules[key]
            return True
        return False

    def check(self, key: str) -> tuple[bool, str | None]:
        """Check if a notification should be throttled.

        Returns (allowed, reason).
        """
        with self._lock:
            rule = self._rules.get(key)
            if not rule:
                return True, None

            now = datetime.now()

            # Check cooldown
            if key in self._cooldowns:
                if now < self._cooldowns[key]:
                    remaining = (self._cooldowns[key] - now).seconds
                    return False, f"In cooldown for {remaining}s"
                else:
                    del self._cooldowns[key]

            # Clean old entries
            if key in self._counts:
                cutoff = now - timedelta(seconds=rule.window_seconds)
                self._counts[key] = [t for t in self._counts[key] if t > cutoff]

            # Check count
            count = len(self._counts.get(key, []))
            if count >= rule.max_count:
                # Enter cooldown
                if rule.cooldown_seconds > 0:
                    self._cooldowns[key] = now + timedelta(
                        seconds=rule.cooldown_seconds
                    )
                    return (
                        False,
                        f"Rate limit exceeded, in cooldown for {rule.cooldown_seconds}s",
                    )
                return False, f"Rate limit exceeded ({count}/{rule.max_count})"

            return True, None

    def record(self, key: str) -> None:
        """Record a notification for throttling."""
        with self._lock:
            if key not in self._counts:
                self._counts[key] = []
            self._counts[key].append(datetime.now())

    def reset(self, key: str) -> None:
        """Reset throttle state for a key."""
        with self._lock:
            self._counts.pop(key, None)
            self._cooldowns.pop(key, None)

    def get_stats(self, key: str) -> dict[str, Any]:
        """Get throttle statistics for a key."""
        with self._lock:
            rule = self._rules.get(key)
            if not rule:
                return {"key": key, "has_rule": False}

            count = len(self._counts.get(key, []))
            in_cooldown = key in self._cooldowns

            return {
                "key": key,
                "has_rule": True,
                "current_count": count,
                "max_count": rule.max_count,
                "window_seconds": rule.window_seconds,
                "in_cooldown": in_cooldown,
                "cooldown_until": self._cooldowns.get(key, None),
            }


# =============================================================================
# Notification Channels
# =============================================================================


class NotificationChannel(ABC):
    """Base class for notification channels."""

    name: str = "base"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.enabled = True

    @abstractmethod
    def send(self, notification: Notification) -> bool:
        """Send a notification. Returns True on success."""
        pass

    def validate_config(self) -> str | None:
        """Validate channel configuration. Returns error message or None."""
        return None


class EmailChannel(NotificationChannel):
    """Email notification channel."""

    name = "email"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.smtp_host = self.config.get("smtp_host", "localhost")
        self.smtp_port = self.config.get("smtp_port", 587)
        self.smtp_user = self.config.get("smtp_user", "")
        self.smtp_password = self.config.get("smtp_password", "")
        self.use_tls = self.config.get("use_tls", True)
        self.from_address = self.config.get("from_address", "")
        self.to_addresses = self.config.get("to_addresses", [])

    def validate_config(self) -> str | None:
        if not self.from_address:
            return "from_address is required"
        if not self.to_addresses:
            return "to_addresses is required"
        return None

    def send(self, notification: Notification) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = (
                f"[{notification.level.value.upper()}] {notification.title}"
            )
            msg["From"] = self.from_address
            msg["To"] = ", ".join(self.to_addresses)

            # Plain text version
            text_body = f"{notification.title}\n\n{notification.message}"
            if notification.data:
                text_body += f"\n\nData:\n{json.dumps(notification.data, indent=2)}"

            # HTML version
            html_body = f"""
            <html>
            <body>
            <h2>{notification.title}</h2>
            <p>{notification.message}</p>
            {f"<pre>{json.dumps(notification.data, indent=2)}</pre>" if notification.data else ""}
            <p><small>Level: {notification.level.value} | Time: {notification.timestamp}</small></p>
            </body>
            </html>
            """

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            return True

        except (OSError, ConnectionError, RuntimeError, ValueError) as e:
            notification.error = str(e)
            return False


class WebhookChannel(NotificationChannel):
    """Webhook notification channel."""

    name = "webhook"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.url = self.config.get("url", "")
        self.method = self.config.get("method", "POST")
        self.headers = self.config.get("headers", {})
        self.timeout = self.config.get("timeout", 30)

    def validate_config(self) -> str | None:
        if not self.url:
            return "url is required"
        return None

    def send(self, notification: Notification) -> bool:
        try:
            payload = {
                "title": notification.title,
                "message": notification.message,
                "level": notification.level.value,
                "timestamp": notification.timestamp.isoformat(),
                "data": notification.data,
                "tags": list(notification.tags),
            }

            headers = {"Content-Type": "application/json", **self.headers}

            data = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                self.url, data=data, headers=headers, method=self.method
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status < 400

        except (OSError, ConnectionError, RuntimeError, ValueError) as e:
            notification.error = str(e)
            return False


class SlackChannel(NotificationChannel):
    """Slack notification channel."""

    name = "slack"

    LEVEL_COLORS = {
        NotificationLevel.DEBUG: "#808080",
        NotificationLevel.INFO: "#0000FF",
        NotificationLevel.WARNING: "#FFA500",
        NotificationLevel.ERROR: "#FF0000",
        NotificationLevel.CRITICAL: "#8B0000",
    }

    LEVEL_EMOJIS = {
        NotificationLevel.DEBUG: ":bug:",
        NotificationLevel.INFO: ":information_source:",
        NotificationLevel.WARNING: ":warning:",
        NotificationLevel.ERROR: ":x:",
        NotificationLevel.CRITICAL: ":rotating_light:",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.webhook_url = self.config.get("webhook_url", "")
        self.channel = self.config.get("channel", "")
        self.username = self.config.get("username", "RedOPS")
        self.icon_emoji = self.config.get("icon_emoji", ":shield:")
        self.timeout = self.config.get("timeout", 30)

    def validate_config(self) -> str | None:
        if not self.webhook_url:
            return "webhook_url is required"
        return None

    def send(self, notification: Notification) -> bool:
        try:
            emoji = self.LEVEL_EMOJIS.get(notification.level, ":bell:")
            color = self.LEVEL_COLORS.get(notification.level, "#808080")

            attachment = {
                "color": color,
                "title": f"{emoji} {notification.title}",
                "text": notification.message,
                "footer": f"RedOPS | {notification.level.value.upper()}",
                "ts": int(notification.timestamp.timestamp()),
            }

            if notification.data:
                fields = []
                for key, value in notification.data.items():
                    fields.append(
                        {"title": key, "value": str(value)[:100], "short": True}
                    )
                attachment["fields"] = fields[:10]

            payload = {
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "attachments": [attachment],
            }

            if self.channel:
                payload["channel"] = self.channel

            data = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status == 200

        except (OSError, ConnectionError, RuntimeError, ValueError) as e:
            notification.error = str(e)
            return False


class ConsoleChannel(NotificationChannel):
    """Console output channel (for debugging/logging)."""

    name = "console"

    LEVEL_PREFIXES = {
        NotificationLevel.DEBUG: "[DEBUG]",
        NotificationLevel.INFO: "[INFO]",
        NotificationLevel.WARNING: "[WARN]",
        NotificationLevel.ERROR: "[ERROR]",
        NotificationLevel.CRITICAL: "[CRITICAL]",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.output_func = self.config.get("output_func", print)
        self.include_data = self.config.get("include_data", True)

    def send(self, notification: Notification) -> bool:
        try:
            prefix = self.LEVEL_PREFIXES.get(notification.level, "[NOTIF]")
            message = f"{prefix} {notification.title}: {notification.message}"

            if self.include_data and notification.data:
                message += f"\n  Data: {json.dumps(notification.data)}"

            self.output_func(message)
            return True

        except (OSError, ConnectionError, RuntimeError, ValueError) as e:
            notification.error = str(e)
            return False


class CallbackChannel(NotificationChannel):
    """Custom callback channel."""

    name = "callback"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.callback = self.config.get("callback")

    def validate_config(self) -> str | None:
        if not self.callback or not callable(self.callback):
            return "callback must be a callable"
        return None

    def send(self, notification: Notification) -> bool:
        try:
            result = self.callback(notification)
            return bool(result) if result is not None else True
        except (OSError, ConnectionError, RuntimeError, ValueError) as e:
            notification.error = str(e)
            return False


# =============================================================================
# Notification Manager
# =============================================================================


@dataclass
class NotificationResult:
    """Result of sending a notification."""

    notification_id: str
    success: bool
    channel: str
    error: str | None = None
    sent_at: datetime | None = None


class NotificationManager:
    """Central manager for notifications."""

    def __init__(self):
        self._channels: dict[str, NotificationChannel] = {}
        self._templates = TemplateEngine()
        self._throttle = ThrottleManager()
        self._history: list[Notification] = []
        self._max_history = 1000
        self._lock = threading.RLock()
        self._listeners: list[Callable[[Notification, NotificationResult], None]] = []
        self._default_channel: str | None = None

    @property
    def templates(self) -> TemplateEngine:
        """Get the template engine."""
        return self._templates

    @property
    def throttle(self) -> ThrottleManager:
        """Get the throttle manager."""
        return self._throttle

    def register_channel(self, channel: NotificationChannel) -> None:
        """Register a notification channel."""
        error = channel.validate_config()
        if error:
            raise ChannelError(f"Invalid channel config for {channel.name}: {error}")
        self._channels[channel.name] = channel

        if not self._default_channel:
            self._default_channel = channel.name

    def unregister_channel(self, name: str) -> bool:
        """Unregister a channel."""
        if name in self._channels:
            del self._channels[name]
            if self._default_channel == name:
                self._default_channel = next(iter(self._channels), None)
            return True
        return False

    def get_channel(self, name: str) -> NotificationChannel | None:
        """Get a channel by name."""
        return self._channels.get(name)

    def list_channels(self) -> list[str]:
        """List registered channel names."""
        return list(self._channels.keys())

    def set_default_channel(self, name: str) -> None:
        """Set the default channel."""
        if name not in self._channels:
            raise ChannelError(f"Channel not found: {name}")
        self._default_channel = name

    def add_listener(
        self, listener: Callable[[Notification, NotificationResult], None]
    ) -> None:
        """Add a notification listener."""
        self._listeners.append(listener)

    def notify(
        self,
        title: str,
        message: str,
        level: NotificationLevel = NotificationLevel.INFO,
        channel: str | None = None,
        data: dict[str, Any] | None = None,
        tags: set[str] | None = None,
        throttle_key: str | None = None,
    ) -> NotificationResult:
        """Send a notification."""
        notification = Notification(
            title=title,
            message=message,
            level=level,
            channel=channel or self._default_channel or "",
            data=data or {},
            tags=tags or set(),
        )
        return self.send(notification, throttle_key=throttle_key)

    def send(
        self, notification: Notification, throttle_key: str | None = None
    ) -> NotificationResult:
        """Send a notification object."""
        # Determine channel
        channel_name = notification.channel or self._default_channel
        if not channel_name:
            return NotificationResult(
                notification_id=notification.id,
                success=False,
                channel="",
                error="No channel specified and no default channel set",
            )

        channel = self._channels.get(channel_name)
        if not channel:
            return NotificationResult(
                notification_id=notification.id,
                success=False,
                channel=channel_name,
                error=f"Channel not found: {channel_name}",
            )

        if not channel.enabled:
            return NotificationResult(
                notification_id=notification.id,
                success=False,
                channel=channel_name,
                error="Channel is disabled",
            )

        # Check throttling
        if throttle_key:
            allowed, reason = self._throttle.check(throttle_key)
            if not allowed:
                notification.status = NotificationStatus.THROTTLED
                notification.error = reason
                self._record_notification(notification)
                return NotificationResult(
                    notification_id=notification.id,
                    success=False,
                    channel=channel_name,
                    error=reason,
                )

        # Send notification
        success = channel.send(notification)

        if success:
            notification.status = NotificationStatus.SENT
            notification.sent_at = datetime.now()
            if throttle_key:
                self._throttle.record(throttle_key)
        else:
            notification.status = NotificationStatus.FAILED

        self._record_notification(notification)

        result = NotificationResult(
            notification_id=notification.id,
            success=success,
            channel=channel_name,
            error=notification.error,
            sent_at=notification.sent_at,
        )

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(notification, result)
            except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
                pass

        return result

    def send_to_all(self, notification: Notification) -> dict[str, NotificationResult]:
        """Send notification to all enabled channels."""
        results = {}
        for name, channel in self._channels.items():
            if channel.enabled:
                notif_copy = Notification(
                    title=notification.title,
                    message=notification.message,
                    level=notification.level,
                    channel=name,
                    data=notification.data.copy(),
                    tags=notification.tags.copy(),
                )
                results[name] = self.send(notif_copy)
        return results

    def _record_notification(self, notification: Notification) -> None:
        """Record a notification in history."""
        with self._lock:
            self._history.append(notification)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history :]

    def get_history(
        self,
        limit: int = 100,
        level: NotificationLevel | None = None,
        channel: str | None = None,
        status: NotificationStatus | None = None,
    ) -> list[Notification]:
        """Get notification history with optional filters."""
        with self._lock:
            filtered = self._history

            if level:
                filtered = [n for n in filtered if n.level == level]
            if channel:
                filtered = [n for n in filtered if n.channel == channel]
            if status:
                filtered = [n for n in filtered if n.status == status]

            return filtered[-limit:]

    def get_statistics(self) -> dict[str, Any]:
        """Get notification statistics."""
        with self._lock:
            total = len(self._history)
            by_status = {}
            by_level = {}
            by_channel = {}

            for n in self._history:
                by_status[n.status.value] = by_status.get(n.status.value, 0) + 1
                by_level[n.level.value] = by_level.get(n.level.value, 0) + 1
                by_channel[n.channel] = by_channel.get(n.channel, 0) + 1

            return {
                "total": total,
                "by_status": by_status,
                "by_level": by_level,
                "by_channel": by_channel,
                "channels_registered": list(self._channels.keys()),
                "default_channel": self._default_channel,
            }


# =============================================================================
# Convenience Functions
# =============================================================================

_default_manager: NotificationManager | None = None


def get_notification_manager() -> NotificationManager:
    """Get the default notification manager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = NotificationManager()
    return _default_manager


def set_notification_manager(manager: NotificationManager) -> None:
    """Set the default notification manager."""
    global _default_manager
    _default_manager = manager


def notify(
    title: str,
    message: str,
    level: NotificationLevel = NotificationLevel.INFO,
    **kwargs,
) -> NotificationResult:
    """Send a notification using the default manager."""
    return get_notification_manager().notify(title, message, level, **kwargs)


def notify_info(title: str, message: str, **kwargs) -> NotificationResult:
    """Send an info notification."""
    return notify(title, message, NotificationLevel.INFO, **kwargs)


def notify_warning(title: str, message: str, **kwargs) -> NotificationResult:
    """Send a warning notification."""
    return notify(title, message, NotificationLevel.WARNING, **kwargs)


def notify_error(title: str, message: str, **kwargs) -> NotificationResult:
    """Send an error notification."""
    return notify(title, message, NotificationLevel.ERROR, **kwargs)


def notify_critical(title: str, message: str, **kwargs) -> NotificationResult:
    """Send a critical notification."""
    return notify(title, message, NotificationLevel.CRITICAL, **kwargs)
