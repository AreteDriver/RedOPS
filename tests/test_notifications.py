"""Tests for the notifications module."""

import pytest
from unittest.mock import patch, MagicMock
from redops.modules.notifications import (
    NotificationConfig,
    NotificationService,
    notify_on_complete,
)


class TestNotificationConfig:
    """Tests for NotificationConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = NotificationConfig()
        assert config.slack_webhook_url is None
        assert config.discord_webhook_url is None
        assert config.smtp_port == 587
        assert config.notify_emails is None

    def test_from_env(self):
        """Test loading config from environment."""
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
        with patch.dict("os.environ", {}, clear=True):
            config = NotificationConfig.from_env()
            assert config.slack_webhook_url is None
            assert config.notify_emails == []


class TestNotificationService:
    """Tests for NotificationService."""

    def test_init_with_config(self):
        """Test initialization with explicit config."""
        config = NotificationConfig(
            slack_webhook_url="https://slack.example.com/webhook"
        )
        service = NotificationService(config)
        assert service.config.slack_webhook_url == "https://slack.example.com/webhook"

    def test_format_scan_message(self):
        """Test scan message formatting."""
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

    @patch("redops.modules.notifications.requests")
    def test_send_slack(self, mock_requests):
        """Test Slack notification."""
        mock_requests.post.return_value.status_code = 200

        config = NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test"
        )
        service = NotificationService(config)

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
        mock_requests.post.assert_called_once()

    @patch("redops.modules.notifications.requests")
    def test_send_discord(self, mock_requests):
        """Test Discord notification."""
        mock_requests.post.return_value.status_code = 204

        config = NotificationConfig(
            discord_webhook_url="https://discord.com/api/webhooks/test"
        )
        service = NotificationService(config)

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
        mock_requests.post.assert_called_once()

    @patch("redops.modules.notifications.requests")
    def test_send_webhook(self, mock_requests):
        """Test generic webhook."""
        mock_requests.post.return_value.status_code = 200

        config = NotificationConfig(
            webhook_urls=["https://example.com/webhook"]
        )
        service = NotificationService(config)

        result = service._send_webhook(
            "https://example.com/webhook",
            {"event": "test"}
        )
        assert result is True

    @patch("redops.modules.notifications.requests")
    def test_notify_scan_complete(self, mock_requests):
        """Test full scan complete notification."""
        mock_requests.post.return_value.status_code = 200

        config = NotificationConfig(
            slack_webhook_url="https://hooks.slack.com/test",
            discord_webhook_url="https://discord.com/api/webhooks/test",
        )
        service = NotificationService(config)

        results = service.notify_scan_complete(
            target="example.com",
            preset="quick",
            findings_count=5,
            critical_count=1,
            high_count=2,
        )

        assert results["slack"] is True
        assert results["discord"] is True

    def test_notify_scan_complete_no_config(self):
        """Test notification with no channels configured."""
        config = NotificationConfig()
        service = NotificationService(config)

        results = service.notify_scan_complete(
            target="example.com",
            preset="quick",
        )

        assert results == {}


class TestNotifyOnComplete:
    """Tests for the pipeline integration function."""

    def test_notify_on_complete(self):
        """Test the pipeline module function."""
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
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.data = {}

        # Should not raise even with invalid config
        result = notify_on_complete(ctx, {})
        assert result is ctx
