"""Tests for the Alerting System module."""

import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


from redops.core.alerting import (
    Alert,
    AlertCondition,
    AlertManager,
    AlertRule,
    AlertSeverity,
    AlertState,
    CallbackChannel,
    ConditionOperator,
    EmailChannel,
    EscalationPolicy,
    LogChannel,
    SilenceRule,
    WebhookChannel,
    create_rule,
    threshold_rule,
)


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""

    def test_all_severities_exist(self):
        """Test all severities are defined."""
        assert AlertSeverity.INFO.value == "info"
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.CRITICAL.value == "critical"

    def test_priority(self):
        """Test severity priorities."""
        assert AlertSeverity.INFO.priority < AlertSeverity.LOW.priority
        assert AlertSeverity.LOW.priority < AlertSeverity.MEDIUM.priority
        assert AlertSeverity.MEDIUM.priority < AlertSeverity.HIGH.priority
        assert AlertSeverity.HIGH.priority < AlertSeverity.CRITICAL.priority

    def test_from_string(self):
        """Test conversion from string."""
        assert AlertSeverity.from_string("critical") == AlertSeverity.CRITICAL
        assert AlertSeverity.from_string("HIGH") == AlertSeverity.HIGH
        assert AlertSeverity.from_string("unknown") == AlertSeverity.MEDIUM


class TestAlertState:
    """Tests for AlertState enum."""

    def test_all_states_exist(self):
        """Test all states are defined."""
        assert AlertState.PENDING.value == "pending"
        assert AlertState.FIRING.value == "firing"
        assert AlertState.ACKNOWLEDGED.value == "acknowledged"
        assert AlertState.RESOLVED.value == "resolved"
        assert AlertState.SILENCED.value == "silenced"


class TestConditionOperator:
    """Tests for ConditionOperator enum."""

    def test_all_operators_exist(self):
        """Test all operators are defined."""
        assert ConditionOperator.EQUALS.value == "eq"
        assert ConditionOperator.GREATER_THAN.value == "gt"
        assert ConditionOperator.CONTAINS.value == "contains"
        assert ConditionOperator.MATCHES.value == "matches"


class TestAlertCondition:
    """Tests for AlertCondition."""

    def test_equals(self):
        """Test equals condition."""
        cond = AlertCondition("status", ConditionOperator.EQUALS, "error")
        assert cond.evaluate({"status": "error"})
        assert not cond.evaluate({"status": "ok"})

    def test_not_equals(self):
        """Test not equals condition."""
        cond = AlertCondition("status", ConditionOperator.NOT_EQUALS, "ok")
        assert cond.evaluate({"status": "error"})
        assert not cond.evaluate({"status": "ok"})

    def test_greater_than(self):
        """Test greater than condition."""
        cond = AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80)
        assert cond.evaluate({"cpu": 90})
        assert not cond.evaluate({"cpu": 70})

    def test_less_than(self):
        """Test less than condition."""
        cond = AlertCondition("memory", ConditionOperator.LESS_THAN, 100)
        assert cond.evaluate({"memory": 50})
        assert not cond.evaluate({"memory": 150})

    def test_contains(self):
        """Test contains condition."""
        cond = AlertCondition("message", ConditionOperator.CONTAINS, "error")
        assert cond.evaluate({"message": "critical error occurred"})
        assert not cond.evaluate({"message": "all ok"})

    def test_matches(self):
        """Test regex matches condition."""
        cond = AlertCondition("ip", ConditionOperator.MATCHES, r"^192\.168\.")
        assert cond.evaluate({"ip": "192.168.1.1"})
        assert not cond.evaluate({"ip": "10.0.0.1"})

    def test_in_operator(self):
        """Test in operator condition."""
        cond = AlertCondition("status", ConditionOperator.IN, ["error", "critical"])
        assert cond.evaluate({"status": "error"})
        assert not cond.evaluate({"status": "warning"})

    def test_nested_field(self):
        """Test nested field access."""
        cond = AlertCondition("host.cpu.usage", ConditionOperator.GREATER_THAN, 90)
        data = {"host": {"cpu": {"usage": 95}}}
        assert cond.evaluate(data)

    def test_missing_field(self):
        """Test condition with missing field."""
        cond = AlertCondition("missing", ConditionOperator.EQUALS, "value")
        assert not cond.evaluate({"other": "field"})


class TestAlert:
    """Tests for Alert."""

    def test_basic_alert(self):
        """Test basic alert creation."""
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test Alert",
            severity=AlertSeverity.HIGH,
        )
        assert alert.alert_id == "a1"
        assert alert.state == AlertState.PENDING
        assert alert.severity == AlertSeverity.HIGH

    def test_acknowledge(self):
        """Test alert acknowledgment."""
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
        )
        alert.acknowledge("user@example.com")

        assert alert.state == AlertState.ACKNOWLEDGED
        assert alert.acknowledged_by == "user@example.com"
        assert alert.acknowledged_at is not None

    def test_resolve(self):
        """Test alert resolution."""
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
        )
        alert.resolve("admin")

        assert alert.state == AlertState.RESOLVED
        assert alert.resolved_by == "admin"
        assert alert.resolved_at is not None

    def test_fire_again(self):
        """Test refiring alert."""
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
        )
        alert.resolve()
        alert.fire_again()

        assert alert.state == AlertState.FIRING
        assert alert.firing_count == 2

    def test_fingerprint(self):
        """Test fingerprint generation."""
        alert1 = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
            labels={"env": "prod"},
        )
        alert2 = Alert(
            alert_id="a2",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
            labels={"env": "prod"},
        )
        alert3 = Alert(
            alert_id="a3",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
            labels={"env": "dev"},
        )

        assert alert1.fingerprint == alert2.fingerprint
        assert alert1.fingerprint != alert3.fingerprint

    def test_duration(self):
        """Test duration calculation."""
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.MEDIUM,
            triggered_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        duration = alert.duration
        assert duration >= timedelta(hours=1)

    def test_to_dict(self):
        """Test serialization to dict."""
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
            message="Test message",
        )
        d = alert.to_dict()

        assert d["alert_id"] == "a1"
        assert d["severity"] == "high"
        assert d["message"] == "Test message"


class TestAlertRule:
    """Tests for AlertRule."""

    def test_basic_rule(self):
        """Test basic rule creation."""
        rule = AlertRule(
            rule_id="r1",
            name="High CPU",
            conditions=[
                AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80),
            ],
        )
        assert rule.rule_id == "r1"
        assert rule.enabled

    def test_evaluate_all(self):
        """Test evaluating with all conditions."""
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80),
                AlertCondition("memory", ConditionOperator.GREATER_THAN, 70),
            ],
            condition_logic="all",
        )

        assert rule.evaluate({"cpu": 90, "memory": 80})
        assert not rule.evaluate({"cpu": 90, "memory": 50})

    def test_evaluate_any(self):
        """Test evaluating with any condition."""
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80),
                AlertCondition("memory", ConditionOperator.GREATER_THAN, 70),
            ],
            condition_logic="any",
        )

        assert rule.evaluate({"cpu": 90, "memory": 50})
        assert rule.evaluate({"cpu": 50, "memory": 80})
        assert not rule.evaluate({"cpu": 50, "memory": 50})

    def test_disabled_rule(self):
        """Test disabled rule."""
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80),
            ],
            enabled=False,
        )
        assert not rule.evaluate({"cpu": 90})

    def test_create_alert(self):
        """Test creating alert from rule."""
        rule = AlertRule(
            rule_id="r1",
            name="High CPU",
            conditions=[],
            severity=AlertSeverity.HIGH,
            message_template="CPU is at {cpu}%",
        )
        alert = rule.create_alert({"cpu": 95})

        assert alert.rule_id == "r1"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.message == "CPU is at 95%"


class TestSilenceRule:
    """Tests for SilenceRule."""

    def test_active_silence(self):
        """Test active silence detection."""
        now = datetime.now(timezone.utc)
        silence = SilenceRule(
            silence_id="s1",
            matchers={"name": "Test"},
            starts_at=now - timedelta(hours=1),
            ends_at=now + timedelta(hours=1),
            created_by="admin",
        )
        assert silence.is_active

    def test_expired_silence(self):
        """Test expired silence."""
        now = datetime.now(timezone.utc)
        silence = SilenceRule(
            silence_id="s1",
            matchers={},
            starts_at=now - timedelta(hours=2),
            ends_at=now - timedelta(hours=1),
            created_by="admin",
        )
        assert not silence.is_active

    def test_matches_alert(self):
        """Test silence matching alert."""
        now = datetime.now(timezone.utc)
        silence = SilenceRule(
            silence_id="s1",
            matchers={"name": "Test Alert"},
            starts_at=now - timedelta(hours=1),
            ends_at=now + timedelta(hours=1),
            created_by="admin",
        )
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test Alert",
            severity=AlertSeverity.MEDIUM,
        )
        assert silence.matches(alert)

    def test_no_match_different_name(self):
        """Test silence not matching different alert."""
        now = datetime.now(timezone.utc)
        silence = SilenceRule(
            silence_id="s1",
            matchers={"name": "Other Alert"},
            starts_at=now - timedelta(hours=1),
            ends_at=now + timedelta(hours=1),
            created_by="admin",
        )
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test Alert",
            severity=AlertSeverity.MEDIUM,
        )
        assert not silence.matches(alert)


class TestLogChannel:
    """Tests for LogChannel."""

    def test_send_alert(self):
        """Test sending alert."""
        channel = LogChannel("log", "Log Channel")
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
        )

        result = channel.send(alert)
        assert result
        assert len(channel.alerts) == 1
        assert channel.alerts[0]["type"] == "alert"

    def test_send_resolved(self):
        """Test sending resolution."""
        channel = LogChannel("log", "Log Channel")
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
        )

        channel.send(alert)
        channel.send_resolved(alert)

        assert len(channel.alerts) == 2
        assert channel.alerts[1]["type"] == "resolved"

    def test_clear(self):
        """Test clearing alerts."""
        channel = LogChannel("log", "Log Channel")
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
        )
        channel.send(alert)
        channel.clear()

        assert len(channel.alerts) == 0


class TestCallbackChannel:
    """Tests for CallbackChannel."""

    def test_callback_called(self):
        """Test callback is called."""
        alerts_received = []

        def on_alert(alert):
            alerts_received.append(alert)
            return True

        channel = CallbackChannel("cb", "Callback", on_alert)
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
        )

        channel.send(alert)
        assert len(alerts_received) == 1

    def test_resolved_callback(self):
        """Test resolved callback."""
        resolved = []

        def on_resolved(alert):
            resolved.append(alert)
            return True

        channel = CallbackChannel("cb", "Callback", lambda a: True, on_resolved)
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
        )

        channel.send_resolved(alert)
        assert len(resolved) == 1


class TestEscalationPolicy:
    """Tests for EscalationPolicy."""

    def test_add_levels(self):
        """Test adding escalation levels."""
        policy = EscalationPolicy("p1", "Default")
        policy.add_level(timedelta(minutes=5), ["email"])
        policy.add_level(timedelta(minutes=15), ["email", "sms"])

        assert len(policy.levels) == 2
        assert policy.levels[0].level == 1
        assert policy.levels[1].level == 2

    def test_get_level_for_duration(self):
        """Test getting level for duration."""
        policy = EscalationPolicy("p1", "Default")
        policy.add_level(timedelta(minutes=5), ["email"])
        policy.add_level(timedelta(minutes=15), ["sms"])

        level = policy.get_level_for_duration(timedelta(minutes=10))
        assert level.level == 1

        level = policy.get_level_for_duration(timedelta(minutes=20))
        assert level.level == 2


class TestAlertManager:
    """Tests for AlertManager."""

    def test_add_rule(self):
        """Test adding rules."""
        manager = AlertManager()
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[],
        )
        manager.add_rule(rule)

        assert manager.get_rule("r1") == rule

    def test_remove_rule(self):
        """Test removing rules."""
        manager = AlertManager()
        rule = AlertRule(rule_id="r1", name="Test", conditions=[])
        manager.add_rule(rule)
        manager.remove_rule("r1")

        assert manager.get_rule("r1") is None

    def test_add_channel(self):
        """Test adding channels."""
        manager = AlertManager()
        channel = LogChannel("log", "Log")
        manager.add_channel(channel)

        assert manager.get_channel("log") == channel

    def test_evaluate_triggers_alert(self):
        """Test evaluation triggers alert."""
        manager = AlertManager()
        channel = LogChannel("log", "Log")
        manager.add_channel(channel)

        rule = AlertRule(
            rule_id="r1",
            name="High CPU",
            conditions=[
                AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80),
            ],
            severity=AlertSeverity.HIGH,
        )
        manager.add_rule(rule)

        alerts = manager.evaluate({"cpu": 90})

        assert len(alerts) == 1
        assert alerts[0].name == "High CPU"
        assert len(channel.alerts) == 1

    def test_evaluate_no_trigger(self):
        """Test evaluation doesn't trigger when condition not met."""
        manager = AlertManager()
        rule = AlertRule(
            rule_id="r1",
            name="High CPU",
            conditions=[
                AlertCondition("cpu", ConditionOperator.GREATER_THAN, 80),
            ],
        )
        manager.add_rule(rule)

        alerts = manager.evaluate({"cpu": 50})
        assert len(alerts) == 0

    def test_get_firing_alerts(self):
        """Test getting firing alerts."""
        manager = AlertManager()
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
        )
        manager.add_rule(rule)
        manager.evaluate({"value": True})

        firing = manager.get_firing_alerts()
        assert len(firing) == 1

    def test_acknowledge_alert(self):
        """Test acknowledging alert."""
        manager = AlertManager()
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
        )
        manager.add_rule(rule)
        alerts = manager.evaluate({"value": True})

        result = manager.acknowledge_alert(alerts[0].alert_id, "admin")
        assert result

        alert = manager.get_alert(alerts[0].alert_id)
        assert alert.state == AlertState.ACKNOWLEDGED

    def test_resolve_alert(self):
        """Test resolving alert."""
        manager = AlertManager()
        channel = LogChannel("log", "Log")
        manager.add_channel(channel)

        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
        )
        manager.add_rule(rule)
        alerts = manager.evaluate({"value": True})

        result = manager.resolve_alert(alerts[0].alert_id, "admin")
        assert result

        # Alert should be moved to history
        assert manager.get_alert(alerts[0].alert_id) is None
        history = manager.get_history()
        assert len(history) == 1

    def test_silence_rule(self):
        """Test silence rules."""
        manager = AlertManager()
        now = datetime.now(timezone.utc)

        silence = SilenceRule(
            silence_id="s1",
            matchers={"name": "Test"},
            starts_at=now - timedelta(hours=1),
            ends_at=now + timedelta(hours=1),
            created_by="admin",
        )
        manager.add_silence(silence)

        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
        )
        manager.add_rule(rule)

        alerts = manager.evaluate({"value": True})
        assert alerts[0].state == AlertState.SILENCED

    def test_deduplication(self):
        """Test alert deduplication."""
        manager = AlertManager()
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
        )
        manager.add_rule(rule)

        # First evaluation creates alert
        alerts1 = manager.evaluate({"value": True})
        assert len(alerts1) == 1

        # Second evaluation updates existing (no new alert)
        alerts2 = manager.evaluate({"value": True})
        assert len(alerts2) == 0

        # Check firing count increased
        alert = manager.get_alerts()[0]
        assert alert.firing_count == 2

    def test_get_stats(self):
        """Test getting statistics."""
        manager = AlertManager()
        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
            severity=AlertSeverity.HIGH,
        )
        manager.add_rule(rule)
        manager.evaluate({"value": True})

        stats = manager.get_stats()
        assert stats["total_rules"] == 1
        assert stats["firing"] == 1
        assert stats["by_severity"]["high"] == 1


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_rule(self):
        """Test create_rule function."""
        rule = create_rule(
            name="Test",
            conditions=[
                ("cpu", ">", 80),
                ("memory", ">=", 70),
            ],
            severity=AlertSeverity.HIGH,
        )

        assert rule.name == "Test"
        assert len(rule.conditions) == 2
        assert rule.severity == AlertSeverity.HIGH

    def test_threshold_rule(self):
        """Test threshold_rule function."""
        rule = threshold_rule(
            name="High CPU",
            field="cpu",
            threshold=80,
            severity=AlertSeverity.CRITICAL,
        )

        assert rule.name == "High CPU"
        assert rule.evaluate({"cpu": 90})
        assert not rule.evaluate({"cpu": 70})


class TestWebhookChannel:
    """Tests for WebhookChannel."""

    def test_channel_properties(self):
        """Test webhook channel properties."""
        channel = WebhookChannel(
            channel_id="wh1",
            name="Webhook",
            url="https://example.com/webhook",
        )
        assert channel.id == "wh1"
        assert channel.url == "https://example.com/webhook"

    @patch("urllib.request.urlopen")
    def test_send_success(self, mock_urlopen):
        """Test successful webhook send."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        channel = WebhookChannel("wh1", "Webhook", "https://example.com")
        alert = Alert(
            alert_id="a1",
            rule_id="r1",
            name="Test",
            severity=AlertSeverity.HIGH,
        )

        result = channel.send(alert)
        assert result


class TestEmailChannel:
    """Tests for EmailChannel."""

    def test_channel_properties(self):
        """Test email channel properties."""
        channel = EmailChannel(
            channel_id="email1",
            name="Email",
            recipients=["admin@example.com"],
        )
        assert channel.id == "email1"
        assert channel.enabled


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_evaluation(self):
        """Test concurrent alert evaluation."""
        manager = AlertManager()
        channel = LogChannel("log", "Log")
        manager.add_channel(channel)

        for i in range(10):
            rule = AlertRule(
                rule_id=f"r{i}",
                name=f"Rule {i}",
                conditions=[
                    AlertCondition("value", ConditionOperator.EQUALS, i),
                ],
            )
            manager.add_rule(rule)

        def evaluate_rule(value):
            manager.evaluate({"value": value})

        threads = [threading.Thread(target=evaluate_rule, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each rule should have triggered once
        assert len(manager.get_alerts()) == 10


class TestCooldown:
    """Tests for alert cooldown."""

    def test_cooldown_prevents_rapid_alerts(self):
        """Test that cooldown prevents rapid re-alerting."""
        manager = AlertManager()

        rule = AlertRule(
            rule_id="r1",
            name="Test",
            conditions=[
                AlertCondition("value", ConditionOperator.EQUALS, True),
            ],
            cooldown=timedelta(seconds=5),
        )
        manager.add_rule(rule)

        # First alert
        alerts1 = manager.evaluate({"value": True})
        assert len(alerts1) == 1

        # Resolve it
        manager.resolve_alert(alerts1[0].alert_id)

        # Try to alert again immediately - should be blocked by cooldown
        alerts2 = manager.evaluate({"value": True})
        assert len(alerts2) == 0
