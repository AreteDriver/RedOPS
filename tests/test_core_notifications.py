"""Tests for core notifications module."""

import time
import pytest
from unittest.mock import MagicMock, patch

from redops.core.notifications import (
    # Exceptions
    ChannelError,
    TemplateError,
    NotificationLevel,
    NotificationStatus,
    Notification,
    # Templates
    TemplateEngine,
    # Throttling
    ThrottleRule,
    ThrottleManager,
    # Channels
    EmailChannel,
    WebhookChannel,
    SlackChannel,
    ConsoleChannel,
    CallbackChannel,
    # Manager
    NotificationManager,
    # Utilities
    get_notification_manager,
    set_notification_manager,
    notify_info,
    notify_warning,
    notify_error,
    notify_critical,
)


class TestNotification:
    """Tests for Notification class."""

    def test_basic_creation(self):
        """Test creating a basic notification."""
        n = Notification(title="Test", message="Test message")
        assert n.title == "Test"
        assert n.message == "Test message"
        assert n.level == NotificationLevel.INFO
        assert n.status == NotificationStatus.PENDING
        assert len(n.id) == 16

    def test_with_level(self):
        """Test notification with custom level."""
        n = Notification(
            title="Alert", message="Critical issue", level=NotificationLevel.CRITICAL
        )
        assert n.level == NotificationLevel.CRITICAL

    def test_with_data(self):
        """Test notification with extra data."""
        data = {"key": "value", "count": 42}
        n = Notification(title="Test", message="Test", data=data)
        assert n.data == data

    def test_to_dict(self):
        """Test converting notification to dictionary."""
        n = Notification(
            title="Test",
            message="Test message",
            level=NotificationLevel.WARNING,
            tags={"tag1", "tag2"},
        )
        d = n.to_dict()
        assert d["title"] == "Test"
        assert d["message"] == "Test message"
        assert d["level"] == "warning"
        assert set(d["tags"]) == {"tag1", "tag2"}

    def test_unique_ids(self):
        """Test that notifications get unique IDs."""
        n1 = Notification(title="Test", message="Test")
        time.sleep(0.01)
        n2 = Notification(title="Test", message="Test")
        assert n1.id != n2.id


class TestTemplateEngine:
    """Tests for TemplateEngine class."""

    def test_simple_render(self):
        """Test simple variable rendering."""
        engine = TemplateEngine()
        result = engine.render("Hello {{ name }}!", {"name": "World"})
        assert result == "Hello World!"

    def test_nested_render(self):
        """Test nested variable rendering."""
        engine = TemplateEngine()
        result = engine.render(
            "{{ user.name }} - {{ user.email }}",
            {"user": {"name": "John", "email": "john@example.com"}},
        )
        assert result == "John - john@example.com"

    def test_missing_variable(self):
        """Test missing variable returns empty string."""
        engine = TemplateEngine()
        result = engine.render("Hello {{ name }}!", {})
        assert result == "Hello !"

    def test_register_template(self):
        """Test registering a named template."""
        engine = TemplateEngine()
        engine.register_template("greeting", "Hello {{ name }}!")
        assert engine.get_template("greeting") == "Hello {{ name }}!"

    def test_render_named(self):
        """Test rendering a named template."""
        engine = TemplateEngine()
        engine.register_template("greeting", "Hello {{ name }}!")
        result = engine.render_named("greeting", {"name": "World"})
        assert result == "Hello World!"

    def test_render_named_not_found(self):
        """Test rendering non-existent template raises error."""
        engine = TemplateEngine()
        with pytest.raises(TemplateError, match="Template not found"):
            engine.render_named("missing", {})


class TestThrottleManager:
    """Tests for ThrottleManager class."""

    def test_no_rule_allows_all(self):
        """Test that without rules, all notifications are allowed."""
        throttle = ThrottleManager()
        allowed, reason = throttle.check("any_key")
        assert allowed is True
        assert reason is None

    def test_basic_throttling(self):
        """Test basic rate limiting."""
        throttle = ThrottleManager()
        throttle.add_rule(ThrottleRule(key="test", max_count=2, window_seconds=60))

        # First two should be allowed
        for _ in range(2):
            allowed, _ = throttle.check("test")
            assert allowed is True
            throttle.record("test")

        # Third should be blocked
        allowed, reason = throttle.check("test")
        assert allowed is False
        assert "rate limit" in reason.lower()

    def test_cooldown(self):
        """Test cooldown period."""
        throttle = ThrottleManager()
        throttle.add_rule(
            ThrottleRule(
                key="test",
                max_count=1,
                window_seconds=1,  # Short window so it expires with cooldown
                cooldown_seconds=1,
            )
        )

        # First allowed
        throttle.check("test")
        throttle.record("test")

        # Second blocked (in cooldown)
        allowed, reason = throttle.check("test")
        assert allowed is False
        assert "cooldown" in reason.lower()

        # Wait for both cooldown and window to expire
        time.sleep(1.1)

        # Now both cooldown and window have passed, so should be allowed
        allowed, _ = throttle.check("test")
        assert allowed is True

    def test_remove_rule(self):
        """Test removing a rule."""
        throttle = ThrottleManager()
        throttle.add_rule(ThrottleRule(key="test", max_count=1, window_seconds=60))

        assert throttle.remove_rule("test") is True
        assert throttle.remove_rule("test") is False

    def test_reset(self):
        """Test resetting throttle state."""
        throttle = ThrottleManager()
        throttle.add_rule(ThrottleRule(key="test", max_count=1, window_seconds=60))

        throttle.record("test")
        allowed, _ = throttle.check("test")
        assert allowed is False

        throttle.reset("test")
        allowed, _ = throttle.check("test")
        assert allowed is True

    def test_get_stats(self):
        """Test getting throttle statistics."""
        throttle = ThrottleManager()
        throttle.add_rule(ThrottleRule(key="test", max_count=5, window_seconds=60))
        throttle.record("test")
        throttle.record("test")

        stats = throttle.get_stats("test")
        assert stats["has_rule"] is True
        assert stats["current_count"] == 2
        assert stats["max_count"] == 5


class TestConsoleChannel:
    """Tests for ConsoleChannel."""

    def test_send_success(self):
        """Test sending to console."""
        channel = ConsoleChannel()
        n = Notification(title="Test", message="Test message")

        with patch("sys.stdout"):
            result = channel.send(n)
            assert result is True

    def test_level_prefix(self):
        """Test different levels have different prefixes."""
        channel = ConsoleChannel()
        for level in NotificationLevel:
            n = Notification(title="Test", message="Test", level=level)
            with patch("sys.stdout"):
                result = channel.send(n)
                assert result is True


class TestCallbackChannel:
    """Tests for CallbackChannel."""

    def test_callback_called(self):
        """Test callback is called with notification."""
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})

        n = Notification(title="Test", message="Test message")
        result = channel.send(n)

        assert result is True
        callback.assert_called_once_with(n)

    def test_callback_returns_false(self):
        """Test callback returning False fails the send."""
        callback = MagicMock(return_value=False)
        channel = CallbackChannel(config={"callback": callback})

        n = Notification(title="Test", message="Test")
        result = channel.send(n)

        assert result is False

    def test_callback_exception(self):
        """Test callback exception is caught."""
        callback = MagicMock(side_effect=Exception("Test error"))
        channel = CallbackChannel(config={"callback": callback})

        n = Notification(title="Test", message="Test")
        result = channel.send(n)

        assert result is False

    def test_validate_config(self):
        """Test config validation."""
        channel = CallbackChannel(config={})
        assert channel.validate_config() is not None

        channel = CallbackChannel(config={"callback": lambda n: True})
        assert channel.validate_config() is None


class TestWebhookChannel:
    """Tests for WebhookChannel."""

    def test_validate_config_missing_url(self):
        """Test validation fails without URL."""
        channel = WebhookChannel(config={})
        assert channel.validate_config() is not None
        assert "url" in channel.validate_config().lower()

    def test_validate_config_with_url(self):
        """Test validation passes with URL."""
        channel = WebhookChannel(config={"url": "https://example.com/webhook"})
        assert channel.validate_config() is None


class TestSlackChannel:
    """Tests for SlackChannel."""

    def test_validate_config_missing_webhook(self):
        """Test validation fails without webhook URL."""
        channel = SlackChannel(config={})
        assert channel.validate_config() is not None

    def test_validate_config_with_webhook(self):
        """Test validation passes with webhook URL."""
        channel = SlackChannel(config={"webhook_url": "https://hooks.slack.com/test"})
        assert channel.validate_config() is None


class TestEmailChannel:
    """Tests for EmailChannel."""

    def test_validate_config_missing_from(self):
        """Test validation fails without from address."""
        channel = EmailChannel(config={"to_addresses": ["test@example.com"]})
        error = channel.validate_config()
        assert error is not None
        assert "from" in error.lower()

    def test_validate_config_missing_to(self):
        """Test validation fails without to addresses."""
        channel = EmailChannel(config={"from_address": "sender@example.com"})
        error = channel.validate_config()
        assert error is not None
        assert "to" in error.lower()


class TestNotificationManager:
    """Tests for NotificationManager."""

    def test_register_channel(self):
        """Test registering a channel."""
        manager = NotificationManager()
        channel = CallbackChannel(config={"callback": lambda n: True})
        manager.register_channel(channel)
        assert "callback" in manager.list_channels()

    def test_register_invalid_channel(self):
        """Test registering channel with invalid config raises error."""
        manager = NotificationManager()
        channel = CallbackChannel(config={})  # Missing callback
        with pytest.raises(ChannelError):
            manager.register_channel(channel)

    def test_unregister_channel(self):
        """Test unregistering a channel."""
        manager = NotificationManager()
        channel = CallbackChannel(config={"callback": lambda n: True})
        manager.register_channel(channel)
        assert manager.unregister_channel("callback") is True
        assert "callback" not in manager.list_channels()

    def test_list_channels(self):
        """Test listing registered channels."""
        manager = NotificationManager()
        cb1 = CallbackChannel(config={"callback": lambda n: True})
        cb1.name = "c1"
        cb2 = CallbackChannel(config={"callback": lambda n: True})
        cb2.name = "c2"
        manager.register_channel(cb1)
        manager.register_channel(cb2)
        channels = manager.list_channels()
        assert "c1" in channels
        assert "c2" in channels

    def test_notify(self):
        """Test sending a notification."""
        manager = NotificationManager()
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})
        channel.name = "test"
        manager.register_channel(channel)

        result = manager.notify("Test", "Test message", channel="test")
        assert result.success is True
        callback.assert_called_once()

    def test_notify_no_channel(self):
        """Test notification fails with no matching channel."""
        manager = NotificationManager()
        result = manager.notify("Test", "Test message", channel="nonexistent")
        assert result.success is False

    def test_notify_with_throttling(self):
        """Test notification throttling."""
        manager = NotificationManager()
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})
        channel.name = "test"
        manager.register_channel(channel)

        manager.throttle.add_rule(
            ThrottleRule(key="test_throttle", max_count=1, window_seconds=60)
        )

        # First should succeed
        result1 = manager.notify(
            "Test", "Test", channel="test", throttle_key="test_throttle"
        )
        assert result1.success is True

        # Second should be throttled
        result2 = manager.notify(
            "Test", "Test", channel="test", throttle_key="test_throttle"
        )
        assert result2.success is False

    def test_send_to_all(self):
        """Test sending to all channels."""
        manager = NotificationManager()

        for i in range(3):
            callback = MagicMock(return_value=True)
            channel = CallbackChannel(config={"callback": callback})
            channel.name = f"channel_{i}"
            manager.register_channel(channel)

        notification = Notification(title="Test", message="Test message")
        results = manager.send_to_all(notification)
        assert len(results) == 3
        assert all(r.success for r in results.values())

    def test_listener(self):
        """Test notification listener."""
        manager = NotificationManager()
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})
        channel.name = "test"
        manager.register_channel(channel)

        events = []
        manager.add_listener(lambda n, r: events.append((n, r)))

        manager.notify("Test", "Test message", channel="test")
        assert len(events) == 1
        assert events[0][0].title == "Test"

    def test_history(self):
        """Test notification history."""
        manager = NotificationManager()
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})
        channel.name = "test"
        manager.register_channel(channel)

        manager.notify("Test 1", "Message", channel="test")
        manager.notify("Test 2", "Message", channel="test")

        history = manager.get_history()
        assert len(history) == 2
        assert history[0].title == "Test 1"
        assert history[1].title == "Test 2"

    def test_statistics(self):
        """Test notification statistics."""
        manager = NotificationManager()
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})
        channel.name = "test"
        manager.register_channel(channel)

        manager.notify("Test 1", "Message", channel="test")
        manager.notify("Test 2", "Message", channel="test")

        stats = manager.get_statistics()
        assert stats["total"] == 2
        assert stats["by_status"]["sent"] == 2


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_get_notification_manager(self):
        """Test getting global manager."""
        manager = get_notification_manager()
        assert isinstance(manager, NotificationManager)

    def test_set_notification_manager(self):
        """Test setting global manager."""
        original = get_notification_manager()
        new_manager = NotificationManager()
        set_notification_manager(new_manager)
        assert get_notification_manager() is new_manager
        set_notification_manager(original)  # Restore

    def test_notify_functions(self):
        """Test convenience notify functions."""
        manager = NotificationManager()
        callback = MagicMock(return_value=True)
        channel = CallbackChannel(config={"callback": callback})
        channel.name = "default"
        manager.register_channel(channel)
        set_notification_manager(manager)

        # Test each level function
        notify_info("Info title", "Info message", channel="default")
        notify_warning("Warning title", "Warning message", channel="default")
        notify_error("Error title", "Error message", channel="default")
        notify_critical("Critical title", "Critical message", channel="default")

        assert callback.call_count == 4


class TestIntegration:
    """Integration tests."""

    def test_full_workflow(self):
        """Test complete notification workflow."""
        manager = NotificationManager()

        # Register channels
        events = []

        def callback(n):
            return (events.append(n), True)[1]

        channel = CallbackChannel(config={"callback": callback})
        channel.name = "test"
        manager.register_channel(channel)

        # Add templates
        manager.templates.register_template(
            "alert", "[{{ level }}] {{ title }}: {{ message }}"
        )

        # Add throttling
        manager.throttle.add_rule(
            ThrottleRule(key="alert", max_count=5, window_seconds=60)
        )

        # Send notifications
        for i in range(3):
            result = manager.notify(
                f"Alert {i}",
                f"Message {i}",
                level=NotificationLevel.WARNING,
                channel="test",
                throttle_key="alert",
            )
            assert result.success is True

        # Check events
        assert len(events) == 3

        # Check history
        history = manager.get_history()
        assert len(history) == 3

        # Check stats
        stats = manager.get_statistics()
        assert stats["total"] == 3

    def test_channel_failure_handling(self):
        """Test handling of channel failures."""
        manager = NotificationManager()

        # Register failing channel
        fail_callback = MagicMock(return_value=False)
        fail_channel = CallbackChannel(config={"callback": fail_callback})
        fail_channel.name = "fail"
        manager.register_channel(fail_channel)

        result = manager.notify("Test", "Test", channel="fail")
        assert result.success is False

        # Check that it was recorded in history as failed
        history = manager.get_history()
        assert len(history) == 1
        assert history[0].status == NotificationStatus.FAILED
