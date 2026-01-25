"""Tests for the notifications module."""

import sys
import pytest
from unittest.mock import patch, MagicMock

# Create mock requests module before importing notifications
mock_requests = MagicMock()
mock_requests.post.return_value.status_code = 200


class TestNotificationConfig:
    """Tests for NotificationConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        from redops.modules.notifications import NotificationConfig
        config = NotificationConfig()
        assert config.slack_webhook_url is None
        assert config.discord_webhook_url is None
        assert config.smtp_port == 587
        assert config.notify_emails is None

    def test_from_env(self):
        """Test loading config from environment."""
        from redops.modules.notifications import NotificationConfig
        with patch.dict("os.environ", {
            "SLACK_WEBHOOK_URL": "https://slack.example.com/webhook",
            "DISCORD_WEBHOOK_URL": "https://discord.example.com/webhook",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "465",
            "NOTIFY_EMAILS": "user1@example.com,user2@example.com",
        }):
            config = NotificationConfig.from_env()
            assert config.slack_webhook_url == "https://slack.example.com/webhook"
            assert config.discord_webhook_url == "https://discord.example.com/webhook"
            assert config.smtp_host == "smtp.example.com"
            assert config.smtp_port == 465
            assert config.notify_emails == ["user1@example.com", "user2@example.com"]

    def test_from_env_empty(self):
        """Test loading config with no environment variables."""
        from redops.modules.notifications import NotificationConfig
        with patch.dict("os.environ", {}, clear=True):
            config = NotificationConfig.from_env()
            assert config.slack_webhook_url is None
            assert config.notify_emails == []


class TestNotificationService:
    """Tests for NotificationService."""

    def test_init_with_config_no_webhooks(self):
        """Test initialization with config without webhooks."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig(
            smtp_host="smtp.example.com",  # No webhook URLs
            notify_emails=["user@example.com"]
        )
        service = NotificationService(config)
        assert service.config.smtp_host == "smtp.example.com"

    def test_format_scan_message(self):
        """Test scan message formatting."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig()
        service = NotificationService(config)

        message = service._format_scan_message(
            target="example.com",
            preset="quick",
            findings_count=10,
            critical_count=2,
            high_count=3,
            report_path="/path/to/report.md",
        )

        assert message["target"] == "example.com"
        assert message["preset"] == "quick"
        assert message["findings_count"] == 10
        assert message["critical_count"] == 2
        assert "Critical" in message["title"] or "critical" in message["title"].lower()
        assert "example.com" in message["text"]

    def test_format_scan_message_no_critical(self):
        """Test scan message formatting without critical findings."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig()
        service = NotificationService(config)

        message = service._format_scan_message(
            target="example.com",
            preset="quick",
            findings_count=5,
            critical_count=0,
            high_count=2,
            report_path=None,
        )

        assert "high" in message["title"].lower()
        assert "critical" not in message["title"].lower()

    def test_format_scan_message_clean(self):
        """Test scan message formatting with no findings."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig()
        service = NotificationService(config)

        message = service._format_scan_message(
            target="example.com",
            preset="quick",
            findings_count=0,
            critical_count=0,
            high_count=0,
            report_path=None,
        )

        assert "Completed" in message["title"]
        assert "CRITICAL" not in message["title"]
        assert "HIGH" not in message["title"]

    def test_notify_scan_complete_no_config(self):
        """Test notification with no channels configured."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig()
        service = NotificationService(config)

        results = service.notify_scan_complete(
            target="example.com",
            preset="quick",
        )

        assert results == {}


class TestNotificationServiceWithRequests:
    """Tests for NotificationService that require requests library."""

    @pytest.fixture(autouse=True)
    def setup_requests_mock(self):
        """Setup mock requests module."""
        self.mock_requests = MagicMock()
        self.mock_requests.post.return_value.status_code = 200

        # Patch before module import
        with patch.dict(sys.modules, {'requests': self.mock_requests}):
            # Reload the module with requests available
            import redops.modules.notifications as notif_module
            self.original_has_requests = notif_module.HAS_REQUESTS
            notif_module.HAS_REQUESTS = True
            notif_module.requests = self.mock_requests
            self.notif_module = notif_module
            yield
            # Restore
            notif_module.HAS_REQUESTS = self.original_has_requests

    def test_init_with_webhook_config(self):
        """Test initialization with webhook config."""
        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://slack.example.com/webhook"
        )
        service = self.notif_module.NotificationService(config)
        assert service.config.slack_webhook_url == "https://slack.example.com/webhook"

    def test_send_slack(self):
        """Test Slack notification."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Test message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 0,
            "critical_count": 0,
        }

        result = service._send_slack(message, 0, 0)
        assert result is True
        self.mock_requests.post.assert_called_once()

    def test_send_discord(self):
        """Test Discord notification."""
        self.mock_requests.post.return_value.status_code = 204

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Test message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 0,
            "critical_count": 0,
        }

        result = service._send_discord(message, 0, 0)
        assert result is True
        self.mock_requests.post.assert_called_once()

    def test_send_webhook(self):
        """Test generic webhook."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            webhook_urls=["https://example.com/webhook"]
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_webhook(
            "https://example.com/webhook",
            {"event": "test"}
        )
        assert result is True

    def test_notify_scan_complete(self):
        """Test full scan complete notification."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test",
            discord_webhook_url="https://discord.com/api/webhooks/test",
        )
        service = self.notif_module.NotificationService(config)

        results = service.notify_scan_complete(
            target="example.com",
            preset="quick",
            findings_count=5,
            critical_count=1,
            high_count=2,
        )

        assert results["slack"] is True
        assert results["discord"] is True

    def test_notify_alert_slack(self):
        """Test alert notification to Slack."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        results = service.notify_alert(
            title="Test Alert",
            message="This is a test alert",
            severity="warning"
        )

        assert "slack" in results
        assert results["slack"] is True

    def test_notify_alert_discord(self):
        """Test alert notification to Discord."""
        self.mock_requests.post.return_value.status_code = 204

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        results = service.notify_alert(
            title="Critical Issue",
            message="Something went wrong",
            severity="critical"
        )

        assert "discord" in results
        assert results["discord"] is True

    def test_notify_alert_all_severities(self):
        """Test alert with all severity levels."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        for severity in ["info", "warning", "error", "critical"]:
            results = service.notify_alert(
                title=f"{severity.capitalize()} Alert",
                message=f"This is a {severity} alert",
                severity=severity
            )
            assert results["slack"] is True

    def test_send_slack_alert_success(self):
        """Test successful Slack alert."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_slack_alert(
            title="Alert Title",
            message="Alert message",
            color="#ff0000"
        )

        assert result is True
        self.mock_requests.post.assert_called()

        # Verify payload structure
        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert "attachments" in payload
        assert payload["attachments"][0]["title"] == "Alert Title"
        assert payload["attachments"][0]["color"] == "#ff0000"

    def test_send_slack_alert_failure(self):
        """Test Slack alert failure."""
        self.mock_requests.post.return_value.status_code = 500

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_slack_alert(
            title="Alert",
            message="Message",
            color="#36a64f"
        )

        assert result is False

    def test_send_slack_alert_exception(self):
        """Test Slack alert with exception."""
        self.mock_requests.post.side_effect = Exception("Connection error")

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_slack_alert(
            title="Alert",
            message="Message",
            color="#36a64f"
        )

        assert result is False

        # Reset side effect
        self.mock_requests.post.side_effect = None
        self.mock_requests.post.return_value.status_code = 200

    def test_send_discord_alert_success(self):
        """Test successful Discord alert."""
        self.mock_requests.post.return_value.status_code = 204

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_discord_alert(
            title="Alert Title",
            message="Alert message",
            color="#ff0000"
        )

        assert result is True
        self.mock_requests.post.assert_called()

        # Verify payload structure
        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert "embeds" in payload
        assert payload["embeds"][0]["title"] == "Alert Title"

    def test_send_discord_alert_color_conversion(self):
        """Test Discord alert converts hex color to int."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        service._send_discord_alert(
            title="Alert",
            message="Message",
            color="#ff6600"  # Orange
        )

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        # 0xff6600 = 16737792
        assert payload["embeds"][0]["color"] == 16737792

    def test_send_discord_alert_failure(self):
        """Test Discord alert failure."""
        self.mock_requests.post.return_value.status_code = 500

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_discord_alert(
            title="Alert",
            message="Message",
            color="#36a64f"
        )

        assert result is False

    def test_send_discord_alert_exception(self):
        """Test Discord alert with exception."""
        self.mock_requests.post.side_effect = Exception("Network error")

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        result = service._send_discord_alert(
            title="Alert",
            message="Message",
            color="#36a64f"
        )

        assert result is False

        # Reset
        self.mock_requests.post.side_effect = None
        self.mock_requests.post.return_value.status_code = 200

    def test_slack_critical_color(self):
        """Test critical findings use red color."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 5,
            "critical_count": 1,
        }

        service._send_slack(message, critical=1, high=0)

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["attachments"][0]["color"] == "#ff0000"

    def test_slack_high_color(self):
        """Test high findings use orange color."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 5,
            "critical_count": 0,
        }

        service._send_slack(message, critical=0, high=3)

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["attachments"][0]["color"] == "#ff6600"

    def test_slack_clean_color(self):
        """Test no critical/high use green color."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 0,
            "critical_count": 0,
        }

        service._send_slack(message, critical=0, high=0)

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["attachments"][0]["color"] == "#36a64f"

    def test_discord_critical_color(self):
        """Test critical findings use red color."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 5,
            "critical_count": 1,
        }

        service._send_discord(message, critical=1, high=0)

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["embeds"][0]["color"] == 16711680  # Red

    def test_discord_high_color(self):
        """Test high findings use orange color."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 5,
            "critical_count": 0,
        }

        service._send_discord(message, critical=0, high=3)

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["embeds"][0]["color"] == 16744448  # Orange

    def test_discord_clean_color(self):
        """Test no critical/high use green color."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = self.notif_module.NotificationService(config)

        message = {
            "title": "Test",
            "text": "Message",
            "target": "example.com",
            "preset": "quick",
            "findings_count": 0,
            "critical_count": 0,
        }

        service._send_discord(message, critical=0, high=0)

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["embeds"][0]["color"] == 3066993  # Green

    def test_webhook_accepts_201(self):
        """Test webhook accepts 201 Created."""
        self.mock_requests.post.return_value.status_code = 201

        config = self.notif_module.NotificationConfig()
        service = self.notif_module.NotificationService(config)

        result = service._send_webhook("https://example.com/hook", {"data": "test"})
        assert result is True

    def test_webhook_accepts_202(self):
        """Test webhook accepts 202 Accepted."""
        self.mock_requests.post.return_value.status_code = 202

        config = self.notif_module.NotificationConfig()
        service = self.notif_module.NotificationService(config)

        result = service._send_webhook("https://example.com/hook", {"data": "test"})
        assert result is True

    def test_webhook_accepts_204(self):
        """Test webhook accepts 204 No Content."""
        self.mock_requests.post.return_value.status_code = 204

        config = self.notif_module.NotificationConfig()
        service = self.notif_module.NotificationService(config)

        result = service._send_webhook("https://example.com/hook", {"data": "test"})
        assert result is True

    def test_webhook_rejects_400(self):
        """Test webhook rejects 400 Bad Request."""
        self.mock_requests.post.return_value.status_code = 400

        config = self.notif_module.NotificationConfig()
        service = self.notif_module.NotificationService(config)

        result = service._send_webhook("https://example.com/hook", {"data": "test"})
        assert result is False

    def test_multiple_webhooks(self):
        """Test notification to multiple webhooks."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            webhook_urls=[
                "https://example.com/hook1",
                "https://example.com/hook2",
                "https://example.com/hook3",
            ]
        )
        service = self.notif_module.NotificationService(config)

        results = service.notify_scan_complete(
            target="example.com",
            preset="quick"
        )

        assert results["webhook_0"] is True
        assert results["webhook_1"] is True
        assert results["webhook_2"] is True
        assert self.mock_requests.post.call_count >= 3

    def test_webhook_extra_data(self):
        """Test webhook includes extra_data."""
        self.mock_requests.post.return_value.status_code = 200

        config = self.notif_module.NotificationConfig(
            webhook_urls=["https://example.com/hook"]
        )
        service = self.notif_module.NotificationService(config)

        service.notify_scan_complete(
            target="example.com",
            preset="quick",
            extra_data={"custom_field": "custom_value"}
        )

        call_kwargs = self.mock_requests.post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["custom_field"] == "custom_value"


class TestNotifyOnComplete:
    """Tests for the pipeline integration function."""

    def test_notify_on_complete(self):
        """Test the pipeline module function."""
        from redops.modules.notifications import notify_on_complete
        # Create a mock context
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.data = {
            "findings": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
            ],
            "report_path": "/path/to/report.md",
        }

        # Call with no webhooks configured (should not fail)
        with patch.dict("os.environ", {}, clear=True):
            result = notify_on_complete(ctx, {"preset": "quick"})

        assert result is ctx
        ctx.add.assert_called()
        ctx.log.assert_called()

    def test_notify_on_complete_error_handling(self):
        """Test error handling in pipeline module."""
        from redops.modules.notifications import notify_on_complete
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.data = {}

        # Should not raise even with invalid config
        result = notify_on_complete(ctx, {})
        assert result is ctx


class TestSendEmail:
    """Tests for _send_email method."""

    def test_send_email_success(self):
        """Test successful email send."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        with patch("redops.modules.notifications.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

            config = NotificationConfig(
                smtp_host="smtp.example.com",
                smtp_port=587,
                smtp_user="user@example.com",
                smtp_password="password",
                smtp_from="noreply@example.com",
                notify_emails=["recipient@example.com"]
            )
            service = NotificationService(config)

            result = service._send_email(
                subject="Test Subject",
                body="Test body content"
            )

            assert result is True
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with("user@example.com", "password")
            mock_smtp.send_message.assert_called_once()

    def test_send_email_without_auth(self):
        """Test email send without authentication."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        with patch("redops.modules.notifications.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

            config = NotificationConfig(
                smtp_host="smtp.example.com",
                smtp_port=25,
                notify_emails=["recipient@example.com"]
            )
            service = NotificationService(config)

            result = service._send_email(
                subject="Test",
                body="Body"
            )

            assert result is True
            mock_smtp.login.assert_not_called()

    def test_send_email_no_smtp_host(self):
        """Test email fails without SMTP host."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig(
            notify_emails=["recipient@example.com"]
        )
        service = NotificationService(config)

        result = service._send_email(
            subject="Test",
            body="Body"
        )

        assert result is False

    def test_send_email_no_recipients(self):
        """Test email fails without recipients."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig(
            smtp_host="smtp.example.com"
        )
        service = NotificationService(config)

        result = service._send_email(
            subject="Test",
            body="Body"
        )

        assert result is False

    def test_send_email_exception(self):
        """Test email handles exceptions."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        with patch("redops.modules.notifications.smtplib.SMTP") as mock_smtp_class:
            mock_smtp_class.side_effect = Exception("Connection refused")

            config = NotificationConfig(
                smtp_host="smtp.example.com",
                smtp_port=587,
                notify_emails=["recipient@example.com"]
            )
            service = NotificationService(config)

            result = service._send_email(
                subject="Test",
                body="Body"
            )

            assert result is False

    def test_send_email_uses_smtp_from(self):
        """Test email uses smtp_from for From header."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        with patch("redops.modules.notifications.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

            config = NotificationConfig(
                smtp_host="smtp.example.com",
                smtp_from="custom@example.com",
                notify_emails=["recipient@example.com"]
            )
            service = NotificationService(config)

            service._send_email(subject="Test", body="Body")

            # Verify the message was sent
            mock_smtp.send_message.assert_called_once()


class TestNotifyAlertWithEmail:
    """Tests for notify_alert with email."""

    def test_alert_sends_email(self):
        """Test alert sends email notification."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        with patch("redops.modules.notifications.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_class.return_value.__exit__ = MagicMock(return_value=False)

            config = NotificationConfig(
                smtp_host="smtp.example.com",
                smtp_port=587,
                notify_emails=["admin@example.com"]
            )
            service = NotificationService(config)

            results = service.notify_alert(
                title="Security Alert",
                message="Critical vulnerability detected",
                severity="critical"
            )

            assert "email" in results
            assert results["email"] is True
            mock_smtp.send_message.assert_called_once()


class TestFromEnvEdgeCases:
    """Tests for NotificationConfig.from_env edge cases."""

    def test_from_env_with_whitespace_emails(self):
        """Test from_env handles whitespace in emails."""
        from redops.modules.notifications import NotificationConfig
        with patch.dict("os.environ", {
            "NOTIFY_EMAILS": "  user1@example.com  ,  user2@example.com  ",
        }):
            config = NotificationConfig.from_env()
            assert config.notify_emails == ["user1@example.com", "user2@example.com"]

    def test_from_env_with_empty_items(self):
        """Test from_env handles empty items in lists."""
        from redops.modules.notifications import NotificationConfig
        with patch.dict("os.environ", {
            "NOTIFY_EMAILS": "user@example.com,,another@example.com,",
            "WEBHOOK_URLS": "https://hook1.com,,https://hook2.com,"
        }):
            config = NotificationConfig.from_env()
            assert config.notify_emails == ["user@example.com", "another@example.com"]
            assert config.webhook_urls == ["https://hook1.com", "https://hook2.com"]

    def test_from_env_default_smtp_port(self):
        """Test from_env uses default SMTP port."""
        from redops.modules.notifications import NotificationConfig
        with patch.dict("os.environ", {}, clear=True):
            config = NotificationConfig.from_env()
            assert config.smtp_port == 587


class TestNotifyAlertNoConfig:
    """Test notify_alert with no config."""

    def test_notify_alert_no_config(self):
        """Test alert with no channels configured."""
        from redops.modules.notifications import NotificationConfig, NotificationService
        config = NotificationConfig()
        service = NotificationService(config)

        results = service.notify_alert(
            title="Alert",
            message="Message"
        )

        assert results == {}
