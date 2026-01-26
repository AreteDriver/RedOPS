"""Tests for webhook notifications module."""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import json


class TestNotificationMessage:
    """Tests for NotificationMessage."""

    def test_message_creation(self):
        """Test basic message creation."""
        from redops.notifications import NotificationMessage, NotificationLevel

        msg = NotificationMessage(
            title="Test Alert",
            body="Something happened",
            level=NotificationLevel.WARNING,
        )

        assert msg.title == "Test Alert"
        assert msg.body == "Something happened"
        assert msg.level == NotificationLevel.WARNING
        assert msg.source == "redops"

    def test_message_with_fields(self):
        """Test message with additional fields."""
        from redops.notifications import NotificationMessage, NotificationLevel

        msg = NotificationMessage(
            title="Alert",
            body="Details",
            level=NotificationLevel.ERROR,
            fields={"Target": "example.com", "Count": "5"},
            url="https://example.com/report",
            tags=["security", "scan"],
        )

        assert msg.fields["Target"] == "example.com"
        assert msg.url == "https://example.com/report"
        assert "security" in msg.tags

    def test_message_to_dict(self):
        """Test message serialization."""
        from redops.notifications import NotificationMessage, NotificationLevel

        msg = NotificationMessage(
            title="Test",
            body="Body",
            level=NotificationLevel.INFO,
        )

        data = msg.to_dict()

        assert data["title"] == "Test"
        assert data["body"] == "Body"
        assert data["level"] == "info"
        assert "timestamp" in data


class TestSlackWebhook:
    """Tests for SlackWebhook."""

    def test_slack_creation(self):
        """Test Slack webhook creation."""
        from redops.notifications import SlackWebhook

        slack = SlackWebhook(
            webhook_url="https://hooks.slack.com/test",
            channel="#alerts",
        )

        assert slack.webhook_url == "https://hooks.slack.com/test"
        assert slack.channel == "#alerts"

    def test_slack_format_payload(self):
        """Test Slack payload formatting."""
        from redops.notifications import SlackWebhook, NotificationMessage, NotificationLevel

        slack = SlackWebhook(webhook_url="https://hooks.slack.com/test")

        msg = NotificationMessage(
            title="Security Alert",
            body="Critical finding detected",
            level=NotificationLevel.CRITICAL,
            fields={"Target": "example.com"},
            url="https://report.example.com",
        )

        payload = slack.format_payload(msg)

        assert "attachments" in payload
        assert payload["username"] == "RedOPS"
        assert len(payload["attachments"]) == 1

        attachment = payload["attachments"][0]
        assert "blocks" in attachment
        assert attachment["color"] == "#9C27B0"  # Critical = purple

    def test_slack_format_info_level(self):
        """Test Slack formatting for info level."""
        from redops.notifications import SlackWebhook, NotificationMessage, NotificationLevel

        slack = SlackWebhook(webhook_url="https://test.com")
        msg = NotificationMessage(title="Info", body="Test", level=NotificationLevel.INFO)

        payload = slack.format_payload(msg)

        assert payload["attachments"][0]["color"] == "#2196F3"  # Blue

    def test_slack_send_no_url(self):
        """Test Slack send fails without URL."""
        from redops.notifications import SlackWebhook, NotificationMessage

        slack = SlackWebhook(webhook_url="")
        msg = NotificationMessage(title="Test", body="Test")

        result = slack.send(msg)
        assert result is False

    @patch("httpx.Client")
    def test_slack_send_success(self, mock_client_cls):
        """Test successful Slack send."""
        from redops.notifications import SlackWebhook, NotificationMessage

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        slack = SlackWebhook(webhook_url="https://hooks.slack.com/test")
        msg = NotificationMessage(title="Test", body="Test")

        result = slack.send(msg)

        assert result is True
        mock_client.post.assert_called_once()


class TestTeamsWebhook:
    """Tests for TeamsWebhook."""

    def test_teams_creation(self):
        """Test Teams webhook creation."""
        from redops.notifications import TeamsWebhook

        teams = TeamsWebhook(webhook_url="https://teams.webhook.url")

        assert teams.webhook_url == "https://teams.webhook.url"

    def test_teams_format_payload(self):
        """Test Teams payload formatting."""
        from redops.notifications import TeamsWebhook, NotificationMessage, NotificationLevel

        teams = TeamsWebhook(webhook_url="https://teams.webhook.url")

        msg = NotificationMessage(
            title="Alert",
            body="Important message",
            level=NotificationLevel.WARNING,
            fields={"Key": "Value"},
        )

        payload = teams.format_payload(msg)

        assert payload["type"] == "message"
        assert "attachments" in payload
        assert payload["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

        card = payload["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard"
        assert len(card["body"]) >= 2

    def test_teams_format_with_url(self):
        """Test Teams formatting with action URL."""
        from redops.notifications import TeamsWebhook, NotificationMessage

        teams = TeamsWebhook(webhook_url="https://test.com")
        msg = NotificationMessage(
            title="Alert",
            body="Test",
            url="https://details.com",
        )

        payload = teams.format_payload(msg)
        card = payload["attachments"][0]["content"]

        assert "actions" in card
        assert card["actions"][0]["url"] == "https://details.com"


class TestDiscordWebhook:
    """Tests for DiscordWebhook."""

    def test_discord_creation(self):
        """Test Discord webhook creation."""
        from redops.notifications import DiscordWebhook

        discord = DiscordWebhook(
            webhook_url="https://discord.com/api/webhooks/test",
            username="TestBot",
        )

        assert discord.webhook_url == "https://discord.com/api/webhooks/test"
        assert discord.username == "TestBot"

    def test_discord_format_payload(self):
        """Test Discord payload formatting."""
        from redops.notifications import DiscordWebhook, NotificationMessage, NotificationLevel

        discord = DiscordWebhook(webhook_url="https://test.com")

        msg = NotificationMessage(
            title="Alert",
            body="Test message",
            level=NotificationLevel.ERROR,
            fields={"Field1": "Value1", "Field2": "Value2"},
        )

        payload = discord.format_payload(msg)

        assert payload["username"] == "RedOPS"
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1

        embed = payload["embeds"][0]
        assert "❌" in embed["title"]  # Error emoji
        assert embed["color"] == 15158332  # Red
        assert len(embed["fields"]) == 2

    def test_discord_format_success_level(self):
        """Test Discord formatting for success level."""
        from redops.notifications import DiscordWebhook, NotificationMessage, NotificationLevel

        discord = DiscordWebhook(webhook_url="https://test.com")
        msg = NotificationMessage(title="Success", body="Done", level=NotificationLevel.SUCCESS)

        payload = discord.format_payload(msg)

        assert payload["embeds"][0]["color"] == 3066993  # Green


class TestGenericWebhook:
    """Tests for GenericWebhook."""

    def test_generic_creation(self):
        """Test generic webhook creation."""
        from redops.notifications import GenericWebhook

        webhook = GenericWebhook(
            webhook_url="https://api.example.com/webhook",
            headers={"X-Custom": "value"},
            auth_token="secret123",
        )

        assert webhook.webhook_url == "https://api.example.com/webhook"
        assert webhook.headers["X-Custom"] == "value"
        assert webhook.auth_token == "secret123"

    def test_generic_format_payload(self):
        """Test generic payload formatting."""
        from redops.notifications import GenericWebhook, NotificationMessage, NotificationLevel

        webhook = GenericWebhook(webhook_url="https://test.com")

        msg = NotificationMessage(
            title="Test",
            body="Body text",
            level=NotificationLevel.WARNING,
            fields={"key": "value"},
            tags=["tag1"],
        )

        payload = webhook.format_payload(msg)

        assert payload["title"] == "Test"
        assert payload["body"] == "Body text"
        assert payload["level"] == "warning"
        assert payload["fields"]["key"] == "value"
        assert "tag1" in payload["tags"]

    @patch("httpx.Client")
    def test_generic_send_with_auth(self, mock_client_cls):
        """Test generic webhook with authentication."""
        from redops.notifications import GenericWebhook, NotificationMessage

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        webhook = GenericWebhook(
            webhook_url="https://api.example.com/webhook",
            auth_token="secret",
        )
        msg = NotificationMessage(title="Test", body="Test")

        result = webhook.send(msg)

        assert result is True
        call_args = mock_client.post.call_args
        assert "Authorization" in call_args.kwargs["headers"]


class TestPagerDutyWebhook:
    """Tests for PagerDutyWebhook."""

    def test_pagerduty_creation(self):
        """Test PagerDuty webhook creation."""
        from redops.notifications import PagerDutyWebhook

        pd = PagerDutyWebhook(routing_key="test-key")

        assert pd.routing_key == "test-key"
        assert "pagerduty.com" in pd.events_url

    def test_pagerduty_format_payload(self):
        """Test PagerDuty payload formatting."""
        from redops.notifications import PagerDutyWebhook, NotificationMessage, NotificationLevel

        pd = PagerDutyWebhook(routing_key="test-key")

        msg = NotificationMessage(
            title="Critical Alert",
            body="Server down",
            level=NotificationLevel.CRITICAL,
            fields={"Server": "prod-1"},
            url="https://status.example.com",
        )

        payload = pd.format_payload(msg)

        assert payload["routing_key"] == "test-key"
        assert payload["event_action"] == "trigger"
        assert payload["payload"]["severity"] == "critical"
        assert payload["payload"]["summary"] == "Critical Alert"
        assert "links" in payload


class TestNotificationConfig:
    """Tests for NotificationConfig."""

    def test_config_defaults(self):
        """Test default configuration."""
        from redops.notifications import NotificationConfig, NotificationLevel

        config = NotificationConfig()

        assert config.enabled is True
        assert config.min_level == NotificationLevel.INFO
        assert config.async_send is True
        assert config.retry_count == 2

    def test_config_from_env(self):
        """Test configuration from environment."""
        env = {
            "NOTIFICATIONS_ENABLED": "true",
            "SLACK_WEBHOOK_URL": "https://slack.test",
            "TEAMS_WEBHOOK_URL": "https://teams.test",
            "NOTIFICATION_MIN_LEVEL": "warning",
        }

        with patch.dict("os.environ", env):
            from redops.notifications import NotificationConfig, NotificationLevel
            config = NotificationConfig.from_env()

            assert config.enabled is True
            assert config.slack_webhook_url == "https://slack.test"
            assert config.teams_webhook_url == "https://teams.test"
            assert config.min_level == NotificationLevel.WARNING


class TestNotificationManager:
    """Tests for NotificationManager."""

    def test_manager_creation(self):
        """Test manager creation."""
        from redops.notifications import NotificationManager, NotificationConfig

        config = NotificationConfig(
            enabled=True,
            async_send=False,
        )
        manager = NotificationManager(config)

        assert manager is not None
        manager.stop()

    def test_manager_add_provider(self):
        """Test adding custom provider."""
        from redops.notifications import NotificationManager, NotificationConfig, SlackWebhook

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        slack = SlackWebhook(webhook_url="https://test.com")
        manager.add_provider("custom-slack", slack)

        assert "custom-slack" in manager._providers
        manager.stop()

    def test_manager_remove_provider(self):
        """Test removing provider."""
        from redops.notifications import NotificationManager, NotificationConfig, SlackWebhook

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        slack = SlackWebhook(webhook_url="https://test.com")
        manager.add_provider("custom", slack)

        result = manager.remove_provider("custom")
        assert result is True
        assert "custom" not in manager._providers
        manager.stop()

    def test_manager_level_filtering(self):
        """Test message filtering by level."""
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            NotificationLevel,
            NotificationMessage,
        )

        config = NotificationConfig(
            enabled=True,
            min_level=NotificationLevel.WARNING,
            async_send=False,
        )
        manager = NotificationManager(config)

        # Info should be filtered
        msg_info = NotificationMessage(title="Info", body="Test", level=NotificationLevel.INFO)
        assert manager._should_send(msg_info.level) is False

        # Warning should pass
        msg_warning = NotificationMessage(title="Warning", body="Test", level=NotificationLevel.WARNING)
        assert manager._should_send(msg_warning.level) is True

        # Error should pass
        msg_error = NotificationMessage(title="Error", body="Test", level=NotificationLevel.ERROR)
        assert manager._should_send(msg_error.level) is True

        manager.stop()

    def test_manager_disabled(self):
        """Test manager when disabled."""
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            NotificationLevel,
        )

        config = NotificationConfig(enabled=False, async_send=False)
        manager = NotificationManager(config)

        assert manager._should_send(NotificationLevel.CRITICAL) is False
        manager.stop()

    def test_manager_send_simple(self):
        """Test simple notification sending."""
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            NotificationLevel,
            SlackWebhook,
        )

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        # Add mock provider
        mock_provider = MagicMock()
        mock_provider.send.return_value = True
        manager._providers["mock"] = mock_provider

        result = manager.send_simple(
            title="Test",
            body="Body",
            level=NotificationLevel.WARNING,
        )

        assert result is True
        mock_provider.send.assert_called_once()
        manager.stop()

    def test_manager_notify_scan_complete(self):
        """Test scan completion notification."""
        from redops.notifications import NotificationManager, NotificationConfig

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        mock_provider = MagicMock()
        mock_provider.send.return_value = True
        manager._providers["mock"] = mock_provider

        result = manager.notify_scan_complete(
            target="example.com",
            findings_count=5,
            severity_counts={"critical": 1, "high": 2, "medium": 2},
            url="https://report.example.com",
        )

        assert result is True

        # Check message was constructed correctly
        call_args = mock_provider.send.call_args
        msg = call_args[0][0]
        assert msg.title == "Scan Complete"
        assert msg.fields["Target"] == "example.com"
        manager.stop()

    def test_manager_notify_scan_error(self):
        """Test scan error notification."""
        from redops.notifications import NotificationManager, NotificationConfig, NotificationLevel

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        mock_provider = MagicMock()
        mock_provider.send.return_value = True
        manager._providers["mock"] = mock_provider

        result = manager.notify_scan_error(
            target="example.com",
            error="Connection timeout",
            pipeline="recon",
        )

        assert result is True

        call_args = mock_provider.send.call_args
        msg = call_args[0][0]
        assert msg.level == NotificationLevel.ERROR
        assert "Connection timeout" in msg.body
        manager.stop()

    def test_manager_notify_critical_finding(self):
        """Test critical finding notification."""
        from redops.notifications import NotificationManager, NotificationConfig, NotificationLevel

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        mock_provider = MagicMock()
        mock_provider.send.return_value = True
        manager._providers["mock"] = mock_provider

        result = manager.notify_critical_finding(
            target="example.com",
            finding_title="SQL Injection",
            finding_details="Found SQL injection vulnerability",
        )

        assert result is True

        call_args = mock_provider.send.call_args
        msg = call_args[0][0]
        assert msg.level == NotificationLevel.CRITICAL
        assert "SQL Injection" in msg.title
        manager.stop()

    def test_manager_formatter(self):
        """Test message formatter."""
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            NotificationMessage,
        )

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        def add_prefix(msg: NotificationMessage) -> NotificationMessage:
            msg.title = f"[PROD] {msg.title}"
            return msg

        manager.add_formatter(add_prefix)

        mock_provider = MagicMock()
        mock_provider.send.return_value = True
        manager._providers["mock"] = mock_provider

        manager.send_simple(title="Alert", body="Test")

        call_args = mock_provider.send.call_args
        msg = call_args[0][0]
        assert msg.title.startswith("[PROD]")
        manager.stop()

    def test_manager_stats(self):
        """Test manager statistics."""
        from redops.notifications import NotificationManager, NotificationConfig

        config = NotificationConfig(
            enabled=True,
            slack_webhook_url="https://test.com",
            async_send=False,
        )
        manager = NotificationManager(config)

        stats = manager.get_stats()

        assert stats["enabled"] is True
        assert "slack" in stats["providers"]
        assert stats["async_enabled"] is False
        manager.stop()


class TestGlobalNotify:
    """Tests for global notify function."""

    def test_notify_function(self):
        """Test global notify function."""
        import redops.notifications.manager as manager_module
        manager_module._notification_manager = None

        from redops.notifications import notify, NotificationLevel, get_notification_manager

        # Get manager and add mock provider
        mgr = get_notification_manager()
        mgr.config.async_send = False

        mock_provider = MagicMock()
        mock_provider.send.return_value = True
        mgr._providers["mock"] = mock_provider

        result = notify(
            title="Test Alert",
            body="Test body",
            level=NotificationLevel.WARNING,
        )

        assert result is True
        mgr.stop()

    def test_get_notification_manager_singleton(self):
        """Test global manager is singleton."""
        import redops.notifications.manager as manager_module
        manager_module._notification_manager = None

        from redops.notifications import get_notification_manager

        mgr1 = get_notification_manager()
        mgr2 = get_notification_manager()

        assert mgr1 is mgr2
        mgr1.stop()


class TestNotificationModuleImports:
    """Test module imports."""

    def test_all_exports(self):
        """Test all expected exports."""
        from redops.notifications import (
            # Message types
            NotificationMessage,
            NotificationLevel,
            # Providers
            WebhookProvider,
            SlackWebhook,
            TeamsWebhook,
            DiscordWebhook,
            GenericWebhook,
            PagerDutyWebhook,
            # Manager
            NotificationConfig,
            NotificationManager,
            get_notification_manager,
            notify,
        )

        assert callable(get_notification_manager)
        assert callable(notify)
