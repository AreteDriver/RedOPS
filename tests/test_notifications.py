"""Tests for webhook notifications module."""

import pytest
from unittest.mock import patch, MagicMock


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
        from redops.notifications import (
            SlackWebhook,
            NotificationMessage,
            NotificationLevel,
        )

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
        from redops.notifications import (
            SlackWebhook,
            NotificationMessage,
            NotificationLevel,
        )

        slack = SlackWebhook(webhook_url="https://test.com")
        msg = NotificationMessage(
            title="Info", body="Test", level=NotificationLevel.INFO
        )

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
        from redops.notifications import (
            TeamsWebhook,
            NotificationMessage,
            NotificationLevel,
        )

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
        assert (
            payload["attachments"][0]["contentType"]
            == "application/vnd.microsoft.card.adaptive"
        )

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
        from redops.notifications import (
            DiscordWebhook,
            NotificationMessage,
            NotificationLevel,
        )

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
        from redops.notifications import (
            DiscordWebhook,
            NotificationMessage,
            NotificationLevel,
        )

        discord = DiscordWebhook(webhook_url="https://test.com")
        msg = NotificationMessage(
            title="Success", body="Done", level=NotificationLevel.SUCCESS
        )

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
        from redops.notifications import (
            GenericWebhook,
            NotificationMessage,
            NotificationLevel,
        )

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
        from redops.notifications import (
            PagerDutyWebhook,
            NotificationMessage,
            NotificationLevel,
        )

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
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            SlackWebhook,
        )

        config = NotificationConfig(enabled=True, async_send=False)
        manager = NotificationManager(config)

        slack = SlackWebhook(webhook_url="https://test.com")
        manager.add_provider("custom-slack", slack)

        assert "custom-slack" in manager._providers
        manager.stop()

    def test_manager_remove_provider(self):
        """Test removing provider."""
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            SlackWebhook,
        )

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
        msg_info = NotificationMessage(
            title="Info", body="Test", level=NotificationLevel.INFO
        )
        assert manager._should_send(msg_info.level) is False

        # Warning should pass
        msg_warning = NotificationMessage(
            title="Warning", body="Test", level=NotificationLevel.WARNING
        )
        assert manager._should_send(msg_warning.level) is True

        # Error should pass
        msg_error = NotificationMessage(
            title="Error", body="Test", level=NotificationLevel.ERROR
        )
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
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            NotificationLevel,
        )

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
        from redops.notifications import (
            NotificationManager,
            NotificationConfig,
            NotificationLevel,
        )

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

        from redops.notifications import (
            notify,
            NotificationLevel,
            get_notification_manager,
        )

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


class TestEmailConfig:
    """Tests for EmailConfig."""

    def test_default_config(self):
        """Test default email configuration."""
        from redops.notifications import EmailConfig

        config = EmailConfig()

        assert config.smtp_host == "localhost"
        assert config.smtp_port == 587
        assert config.use_tls is True
        assert config.use_ssl is False
        assert config.from_address == "redops@localhost"
        assert config.from_name == "RedOPS Security"

    def test_custom_config(self):
        """Test custom email configuration."""
        from redops.notifications import EmailConfig

        config = EmailConfig(
            smtp_host="mail.example.com",
            smtp_port=465,
            smtp_user="user@example.com",
            smtp_password="secret",
            use_tls=False,
            use_ssl=True,
            from_address="security@example.com",
            from_name="Security Team",
            default_recipients=["admin@example.com"],
        )

        assert config.smtp_host == "mail.example.com"
        assert config.smtp_port == 465
        assert config.use_ssl is True
        assert config.default_recipients == ["admin@example.com"]

    def test_config_from_env(self):
        """Test configuration from environment."""
        env = {
            "SMTP_HOST": "smtp.test.com",
            "SMTP_PORT": "465",
            "SMTP_USER": "testuser",
            "SMTP_PASSWORD": "testpass",
            "SMTP_TLS": "false",
            "SMTP_SSL": "true",
            "EMAIL_FROM": "test@example.com",
            "EMAIL_FROM_NAME": "Test Sender",
            "EMAIL_RECIPIENTS": "a@test.com,b@test.com",
        }

        with patch.dict("os.environ", env):
            from redops.notifications import EmailConfig

            config = EmailConfig.from_env()

            assert config.smtp_host == "smtp.test.com"
            assert config.smtp_port == 465
            assert config.smtp_user == "testuser"
            assert config.smtp_password == "testpass"
            assert config.use_tls is False
            assert config.use_ssl is True
            assert config.from_address == "test@example.com"
            assert config.default_recipients == ["a@test.com", "b@test.com"]


class TestEmailTemplate:
    """Tests for EmailTemplate."""

    def test_template_creation(self):
        """Test template creation."""
        from redops.notifications import EmailTemplate

        template = EmailTemplate(
            name="test",
            subject="Alert: $title",
            html_body="<h1>$title</h1><p>$body</p>",
            text_body="$title\n\n$body",
            variables=["title", "body"],
        )

        assert template.name == "test"
        assert "$title" in template.subject

    def test_template_render(self):
        """Test template rendering."""
        from redops.notifications import EmailTemplate

        template = EmailTemplate(
            name="test",
            subject="Alert: $title",
            html_body="<h1>$title</h1><p>$body</p>",
            text_body="$title\n\n$body",
        )

        subject, html, text = template.render(
            {
                "title": "Security Alert",
                "body": "A critical issue was found",
            }
        )

        assert subject == "Alert: Security Alert"
        assert "<h1>Security Alert</h1>" in html
        assert "Security Alert" in text
        assert "A critical issue was found" in text

    def test_template_render_missing_var(self):
        """Test template with missing variable keeps placeholder."""
        from redops.notifications import EmailTemplate

        template = EmailTemplate(
            name="test",
            subject="$title - $missing",
            html_body="<p>$body</p>",
            text_body="$body",
        )

        subject, html, text = template.render({"title": "Test", "body": "Content"})

        assert subject == "Test - $missing"  # safe_substitute keeps missing vars


class TestBuiltinTemplates:
    """Tests for built-in email templates."""

    def test_scan_complete_template(self):
        """Test scan complete template."""
        from redops.notifications import render_email_template

        data = {
            "target": "example.com",
            "timestamp": "2025-01-26 12:00:00",
            "critical": "1",
            "high": "2",
            "medium": "5",
            "low": "10",
            "info": "3",
            "total_findings": "21",
            "details": "See report for details",
            "report_url": "https://report.example.com/123",
        }

        subject, html, text = render_email_template("scan_complete", data)

        assert "example.com" in subject
        assert "example.com" in html
        assert "21" in text  # total findings
        assert "report.example.com" in html

    def test_critical_finding_template(self):
        """Test critical finding template."""
        from redops.notifications import render_email_template

        data = {
            "title": "SQL Injection",
            "target": "api.example.com",
            "timestamp": "2025-01-26 12:00:00",
            "description": "SQL injection in login endpoint",
            "remediation": "Use parameterized queries",
            "finding_url": "https://findings.example.com/456",
        }

        subject, html, text = render_email_template("critical_finding", data)

        assert "CRITICAL" in subject
        assert "SQL Injection" in subject
        assert "SQL injection in login endpoint" in html
        assert "parameterized queries" in text

    def test_daily_digest_template(self):
        """Test daily digest template."""
        from redops.notifications import render_email_template

        data = {
            "date": "2025-01-26",
            "scans_completed": "15",
            "new_findings": "42",
            "resolved_findings": "8",
            "findings_table": "<table><tr><td>Finding 1</td></tr></table>",
            "scans_table": "<table><tr><td>Scan 1</td></tr></table>",
            "findings_list": "- Finding 1\n- Finding 2",
            "scans_list": "- Scan 1\n- Scan 2",
        }

        subject, html, text = render_email_template("daily_digest", data)

        assert "2025-01-26" in subject
        assert "Daily" in subject
        assert "15" in html  # scans completed
        assert "42" in text  # new findings

    def test_unknown_template(self):
        """Test unknown template raises error."""
        from redops.notifications import render_email_template

        with pytest.raises(ValueError, match="Unknown template"):
            render_email_template("nonexistent", {})


class TestEmailBackend:
    """Tests for EmailBackend."""

    def test_backend_creation(self):
        """Test email backend creation."""
        from redops.notifications import EmailBackend, EmailConfig

        config = EmailConfig(
            smtp_host="mail.test.com",
            from_address="test@example.com",
        )
        backend = EmailBackend(config)

        assert backend.config.smtp_host == "mail.test.com"
        assert backend.config.from_address == "test@example.com"

    def test_backend_format_payload(self):
        """Test format_payload returns message dict."""
        from redops.notifications import EmailBackend, EmailConfig, NotificationMessage

        backend = EmailBackend(EmailConfig())
        msg = NotificationMessage(title="Test", body="Body")

        payload = backend.format_payload(msg)

        assert payload["title"] == "Test"
        assert payload["body"] == "Body"

    def test_backend_send_no_recipients(self):
        """Test send fails without recipients."""
        from redops.notifications import EmailBackend, EmailConfig, NotificationMessage

        config = EmailConfig(default_recipients=[])
        backend = EmailBackend(config)
        msg = NotificationMessage(title="Test", body="Body")

        result = backend.send(msg)

        assert result is False

    @patch("smtplib.SMTP")
    def test_backend_send_email_plain(self, mock_smtp_cls):
        """Test sending plain text email."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_cls.return_value = mock_smtp

        config = EmailConfig(
            smtp_host="localhost",
            use_tls=False,
            from_address="test@example.com",
        )
        backend = EmailBackend(config)

        result = backend.send_email(
            to=["recipient@example.com"],
            subject="Test Subject",
            body="Test body content",
        )

        assert result is True
        mock_smtp.sendmail.assert_called_once()

    @patch("smtplib.SMTP")
    def test_backend_send_email_html(self, mock_smtp_cls):
        """Test sending HTML email."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_cls.return_value = mock_smtp

        config = EmailConfig(smtp_host="localhost", use_tls=False)
        backend = EmailBackend(config)

        result = backend.send_email(
            to=["recipient@example.com"],
            subject="Test Subject",
            body="Plain text",
            html_body="<h1>HTML Content</h1>",
        )

        assert result is True
        mock_smtp.sendmail.assert_called_once()

    @patch("smtplib.SMTP")
    def test_backend_send_email_with_tls(self, mock_smtp_cls):
        """Test sending email with TLS."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_cls.return_value = mock_smtp

        config = EmailConfig(
            smtp_host="localhost",
            use_tls=True,
            smtp_user="user",
            smtp_password="pass",
        )
        backend = EmailBackend(config)

        result = backend.send_email(
            to=["recipient@example.com"],
            subject="Test",
            body="Body",
        )

        assert result is True
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user", "pass")

    @patch("smtplib.SMTP_SSL")
    def test_backend_send_email_with_ssl(self, mock_smtp_ssl_cls):
        """Test sending email with SSL."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_ssl_cls.return_value = mock_smtp

        config = EmailConfig(
            smtp_host="localhost",
            smtp_port=465,
            use_ssl=True,
        )
        backend = EmailBackend(config)

        result = backend.send_email(
            to=["recipient@example.com"],
            subject="Test",
            body="Body",
        )

        assert result is True
        mock_smtp_ssl_cls.assert_called_once()

    @patch("smtplib.SMTP")
    def test_backend_send_email_with_cc_bcc(self, mock_smtp_cls):
        """Test sending email with CC and BCC."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_cls.return_value = mock_smtp

        config = EmailConfig(smtp_host="localhost", use_tls=False)
        backend = EmailBackend(config)

        result = backend.send_email(
            to=["to@example.com"],
            subject="Test",
            body="Body",
            cc=["cc@example.com"],
            bcc=["bcc@example.com"],
        )

        assert result is True
        # Verify all recipients included
        call_args = mock_smtp.sendmail.call_args
        recipients = call_args[0][1]
        assert "to@example.com" in recipients
        assert "cc@example.com" in recipients
        assert "bcc@example.com" in recipients

    @patch("smtplib.SMTP")
    def test_backend_send_email_with_attachment(self, mock_smtp_cls):
        """Test sending email with attachment."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_cls.return_value = mock_smtp

        config = EmailConfig(smtp_host="localhost", use_tls=False)
        backend = EmailBackend(config)

        result = backend.send_email(
            to=["recipient@example.com"],
            subject="Test",
            body="Body",
            attachments=[
                {"filename": "report.pdf", "content": b"PDF content here"},
            ],
        )

        assert result is True
        mock_smtp.sendmail.assert_called_once()

    @patch("smtplib.SMTP")
    def test_backend_send_template(self, mock_smtp_cls):
        """Test sending template email."""
        from redops.notifications import EmailBackend, EmailConfig

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp_cls.return_value = mock_smtp

        config = EmailConfig(smtp_host="localhost", use_tls=False)
        backend = EmailBackend(config)

        data = {
            "target": "example.com",
            "timestamp": "2025-01-26",
            "critical": "0",
            "high": "1",
            "medium": "2",
            "low": "3",
            "info": "4",
            "total_findings": "10",
            "details": "",
            "report_url": "https://example.com/report",
        }

        result = backend.send_template(
            template_name="scan_complete",
            to=["recipient@example.com"],
            data=data,
        )

        assert result is True
        mock_smtp.sendmail.assert_called_once()

    def test_backend_send_template_unknown(self):
        """Test send_template with unknown template."""
        from redops.notifications import EmailBackend, EmailConfig

        config = EmailConfig()
        backend = EmailBackend(config)

        result = backend.send_template(
            template_name="nonexistent",
            to=["test@example.com"],
            data={},
        )

        assert result is False

    def test_backend_format_html(self):
        """Test HTML formatting of message."""
        from redops.notifications import (
            EmailBackend,
            EmailConfig,
            NotificationMessage,
            NotificationLevel,
        )

        backend = EmailBackend(EmailConfig())
        msg = NotificationMessage(
            title="Security Alert",
            body="A vulnerability was found",
            level=NotificationLevel.WARNING,
            fields={"Target": "example.com", "Severity": "High"},
            url="https://example.com/details",
        )

        html = backend._format_html(msg)

        assert "Security Alert" in html
        assert "A vulnerability was found" in html
        assert "example.com" in html
        assert "View Details" in html
        assert "https://example.com/details" in html


class TestEmailModuleIntegration:
    """Integration tests for email module."""

    def test_email_exports(self):
        """Test email module exports."""
        from redops.notifications import (
            render_email_template,
            EMAIL_TEMPLATES,
        )

        assert callable(render_email_template)
        assert "scan_complete" in EMAIL_TEMPLATES
        assert "critical_finding" in EMAIL_TEMPLATES
        assert "daily_digest" in EMAIL_TEMPLATES


class TestNotificationModuleImports:
    """Test module imports."""

    def test_all_exports(self):
        """Test all expected exports."""
        from redops.notifications import (
            # Message types
            render_email_template,
            get_notification_manager,
            notify,
        )

        assert callable(get_notification_manager)
        assert callable(notify)
        assert callable(render_email_template)
