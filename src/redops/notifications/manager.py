"""
Notification manager for RedOPS.

Orchestrates sending notifications to multiple providers.
"""

from typing import Any, Callable
from dataclasses import dataclass
import os
import logging
import threading
import queue

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

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Notification configuration."""

    enabled: bool = True
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    discord_webhook_url: str = ""
    pagerduty_routing_key: str = ""
    generic_webhook_url: str = ""
    min_level: NotificationLevel = NotificationLevel.INFO
    async_send: bool = True
    retry_count: int = 2
    retry_delay_seconds: int = 5

    @classmethod
    def from_env(cls) -> "NotificationConfig":
        """Create config from environment variables."""
        level_str = os.environ.get("NOTIFICATION_MIN_LEVEL", "info").lower()
        try:
            min_level = NotificationLevel(level_str)
        except ValueError:
            min_level = NotificationLevel.INFO

        return cls(
            enabled=os.environ.get("NOTIFICATIONS_ENABLED", "true").lower() == "true",
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
            teams_webhook_url=os.environ.get("TEAMS_WEBHOOK_URL", ""),
            discord_webhook_url=os.environ.get("DISCORD_WEBHOOK_URL", ""),
            pagerduty_routing_key=os.environ.get("PAGERDUTY_ROUTING_KEY", ""),
            generic_webhook_url=os.environ.get("WEBHOOK_URL", ""),
            min_level=min_level,
            async_send=os.environ.get("NOTIFICATION_ASYNC", "true").lower() == "true",
            retry_count=int(os.environ.get("NOTIFICATION_RETRY_COUNT", "2")),
            retry_delay_seconds=int(os.environ.get("NOTIFICATION_RETRY_DELAY", "5")),
        )


class NotificationManager:
    """
    Manages notification delivery to multiple providers.

    Supports:
    - Multiple simultaneous providers
    - Minimum severity filtering
    - Async delivery
    - Retry on failure
    - Custom notification formatters
    """

    def __init__(self, config: NotificationConfig | None = None):
        """
        Initialize notification manager.

        Args:
            config: Notification configuration
        """
        self.config = config or NotificationConfig.from_env()
        self._providers: dict[str, WebhookProvider] = {}
        self._queue: queue.Queue = queue.Queue()
        self._worker_thread: threading.Thread | None = None
        self._running = False
        self._formatters: list[
            Callable[[NotificationMessage], NotificationMessage]
        ] = []

        self._setup_providers()

        if self.config.async_send:
            self._start_worker()

    def _setup_providers(self) -> None:
        """Set up configured providers."""
        if self.config.slack_webhook_url:
            self._providers["slack"] = SlackWebhook(self.config.slack_webhook_url)

        if self.config.teams_webhook_url:
            self._providers["teams"] = TeamsWebhook(self.config.teams_webhook_url)

        if self.config.discord_webhook_url:
            self._providers["discord"] = DiscordWebhook(self.config.discord_webhook_url)

        if self.config.pagerduty_routing_key:
            self._providers["pagerduty"] = PagerDutyWebhook(
                self.config.pagerduty_routing_key
            )

        if self.config.generic_webhook_url:
            self._providers["generic"] = GenericWebhook(self.config.generic_webhook_url)

        logger.info(
            f"Notification providers configured: {list(self._providers.keys())}"
        )

    def _start_worker(self) -> None:
        """Start the async worker thread."""
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def _worker_loop(self) -> None:
        """Async worker loop."""
        while self._running:
            try:
                item = self._queue.get(timeout=1)
                if item is None:
                    break

                message, providers, retries = item
                self._send_to_providers(message, providers, retries)
                self._queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Notification worker error: {e}")

    def _send_to_providers(
        self,
        message: NotificationMessage,
        providers: list[str] | None,
        retries: int,
    ) -> dict[str, bool]:
        """Send message to specified providers."""
        results = {}
        target_providers = providers or list(self._providers.keys())

        for name in target_providers:
            provider = self._providers.get(name)
            if not provider:
                continue

            success = False
            for attempt in range(retries + 1):
                try:
                    success = provider.send(message)
                    if success:
                        break
                except Exception as e:
                    logger.error(f"Provider {name} attempt {attempt + 1} failed: {e}")

                if attempt < retries:
                    import time

                    time.sleep(self.config.retry_delay_seconds)

            results[name] = success

        return results

    def add_provider(self, name: str, provider: WebhookProvider) -> None:
        """
        Add a custom provider.

        Args:
            name: Provider name
            provider: Provider instance
        """
        self._providers[name] = provider
        logger.info(f"Added notification provider: {name}")

    def remove_provider(self, name: str) -> bool:
        """Remove a provider."""
        if name in self._providers:
            del self._providers[name]
            return True
        return False

    def add_formatter(
        self,
        formatter: Callable[[NotificationMessage], NotificationMessage],
    ) -> None:
        """
        Add a message formatter.

        Formatters are applied in order before sending.

        Args:
            formatter: Function that transforms messages
        """
        self._formatters.append(formatter)

    def _apply_formatters(self, message: NotificationMessage) -> NotificationMessage:
        """Apply all formatters to a message."""
        for formatter in self._formatters:
            try:
                message = formatter(message)
            except Exception as e:
                logger.error(f"Formatter error: {e}")
        return message

    def _should_send(self, level: NotificationLevel) -> bool:
        """Check if message should be sent based on level."""
        if not self.config.enabled:
            return False

        level_order = {
            NotificationLevel.INFO: 1,
            NotificationLevel.SUCCESS: 1,
            NotificationLevel.WARNING: 2,
            NotificationLevel.ERROR: 3,
            NotificationLevel.CRITICAL: 4,
        }

        msg_level = level_order.get(level, 0)
        min_level = level_order.get(self.config.min_level, 0)

        return msg_level >= min_level

    def send(
        self,
        message: NotificationMessage,
        providers: list[str] | None = None,
        sync: bool = False,
    ) -> bool:
        """
        Send a notification.

        Args:
            message: Message to send
            providers: Specific providers to use (None = all)
            sync: Force synchronous sending

        Returns:
            True if message was queued/sent successfully
        """
        if not self._should_send(message.level):
            logger.debug(f"Message filtered by level: {message.level.value}")
            return False

        if not self._providers:
            logger.warning("No notification providers configured")
            return False

        # Apply formatters
        message = self._apply_formatters(message)

        # Send
        if sync or not self.config.async_send:
            results = self._send_to_providers(
                message,
                providers,
                self.config.retry_count,
            )
            return any(results.values())
        else:
            self._queue.put((message, providers, self.config.retry_count))
            return True

    def send_simple(
        self,
        title: str,
        body: str,
        level: NotificationLevel = NotificationLevel.INFO,
        **kwargs,
    ) -> bool:
        """
        Send a simple notification.

        Args:
            title: Message title
            body: Message body
            level: Notification level
            **kwargs: Additional message fields

        Returns:
            True if message was sent/queued
        """
        message = NotificationMessage(
            title=title,
            body=body,
            level=level,
            fields=kwargs.get("fields", {}),
            url=kwargs.get("url"),
            tags=kwargs.get("tags", []),
        )
        return self.send(message)

    def notify_scan_complete(
        self,
        target: str,
        findings_count: int,
        severity_counts: dict[str, int],
        url: str | None = None,
    ) -> bool:
        """
        Send scan completion notification.

        Args:
            target: Scan target
            findings_count: Total findings
            severity_counts: Counts by severity
            url: Link to results

        Returns:
            True if sent
        """
        # Determine level based on findings
        if severity_counts.get("critical", 0) > 0:
            level = NotificationLevel.CRITICAL
        elif severity_counts.get("high", 0) > 0:
            level = NotificationLevel.ERROR
        elif severity_counts.get("medium", 0) > 0:
            level = NotificationLevel.WARNING
        elif findings_count > 0:
            level = NotificationLevel.INFO
        else:
            level = NotificationLevel.SUCCESS

        fields = {
            "Target": target,
            "Total Findings": str(findings_count),
            "Critical": str(severity_counts.get("critical", 0)),
            "High": str(severity_counts.get("high", 0)),
            "Medium": str(severity_counts.get("medium", 0)),
            "Low": str(severity_counts.get("low", 0)),
        }

        message = NotificationMessage(
            title="Scan Complete",
            body=f"Security scan completed for {target}",
            level=level,
            fields=fields,
            url=url,
            tags=["scan", "complete"],
        )

        return self.send(message)

    def notify_scan_error(
        self,
        target: str,
        error: str,
        pipeline: str | None = None,
    ) -> bool:
        """
        Send scan error notification.

        Args:
            target: Scan target
            error: Error message
            pipeline: Pipeline name

        Returns:
            True if sent
        """
        fields = {"Target": target}
        if pipeline:
            fields["Pipeline"] = pipeline

        message = NotificationMessage(
            title="Scan Failed",
            body=f"Error scanning {target}: {error}",
            level=NotificationLevel.ERROR,
            fields=fields,
            tags=["scan", "error"],
        )

        return self.send(message)

    def notify_critical_finding(
        self,
        target: str,
        finding_title: str,
        finding_details: str,
        url: str | None = None,
    ) -> bool:
        """
        Send critical finding alert.

        Args:
            target: Scan target
            finding_title: Finding title
            finding_details: Finding description
            url: Link to finding

        Returns:
            True if sent
        """
        message = NotificationMessage(
            title=f"Critical Finding: {finding_title}",
            body=finding_details,
            level=NotificationLevel.CRITICAL,
            fields={"Target": target},
            url=url,
            tags=["finding", "critical"],
        )

        return self.send(message)

    def stop(self) -> None:
        """Stop the notification manager."""
        self._running = False
        if self._worker_thread:
            self._queue.put(None)  # Signal shutdown
            self._worker_thread.join(timeout=5)

    def get_stats(self) -> dict[str, Any]:
        """Get notification statistics."""
        return {
            "enabled": self.config.enabled,
            "providers": list(self._providers.keys()),
            "queue_size": self._queue.qsize(),
            "async_enabled": self.config.async_send,
            "min_level": self.config.min_level.value,
        }


# Global notification manager
_notification_manager: NotificationManager | None = None


def get_notification_manager() -> NotificationManager:
    """Get the global notification manager."""
    global _notification_manager
    if _notification_manager is None:
        _notification_manager = NotificationManager()
    return _notification_manager


def notify(
    title: str,
    body: str,
    level: NotificationLevel = NotificationLevel.INFO,
    **kwargs,
) -> bool:
    """
    Send a notification using the global manager.

    Args:
        title: Message title
        body: Message body
        level: Notification level
        **kwargs: Additional fields

    Returns:
        True if sent/queued
    """
    manager = get_notification_manager()
    return manager.send_simple(title, body, level, **kwargs)
