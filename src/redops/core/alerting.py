"""
Alerting System Module for RedOPS.

Provides alert rules, thresholds, notification channels,
and escalation for security monitoring.
"""

import hashlib
import json
import re
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


class AlertSeverity(Enum):
    """Alert severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def priority(self) -> int:
        """Get numeric priority (higher = more severe)."""
        return {
            AlertSeverity.INFO: 1,
            AlertSeverity.LOW: 2,
            AlertSeverity.MEDIUM: 3,
            AlertSeverity.HIGH: 4,
            AlertSeverity.CRITICAL: 5,
        }[self]

    @classmethod
    def from_string(cls, value: str) -> "AlertSeverity":
        """Convert string to severity."""
        mapping = {s.value: s for s in cls}
        return mapping.get(value.lower(), cls.MEDIUM)


class AlertState(Enum):
    """Alert lifecycle states."""

    PENDING = "pending"
    FIRING = "firing"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SILENCED = "silenced"


class ConditionOperator(Enum):
    """Operators for alert conditions."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"
    IN = "in"
    NOT_IN = "not_in"


@dataclass
class AlertCondition:
    """A condition that triggers an alert."""

    field: str
    operator: ConditionOperator
    value: Any
    description: str = ""

    def evaluate(self, data: Dict[str, Any]) -> bool:
        """Evaluate condition against data."""
        actual = self._get_field_value(data, self.field)
        if actual is None:
            return False

        if self.operator == ConditionOperator.EQUALS:
            return actual == self.value
        elif self.operator == ConditionOperator.NOT_EQUALS:
            return actual != self.value
        elif self.operator == ConditionOperator.GREATER_THAN:
            return actual > self.value
        elif self.operator == ConditionOperator.GREATER_THAN_OR_EQUAL:
            return actual >= self.value
        elif self.operator == ConditionOperator.LESS_THAN:
            return actual < self.value
        elif self.operator == ConditionOperator.LESS_THAN_OR_EQUAL:
            return actual <= self.value
        elif self.operator == ConditionOperator.CONTAINS:
            return self.value in actual
        elif self.operator == ConditionOperator.NOT_CONTAINS:
            return self.value not in actual
        elif self.operator == ConditionOperator.MATCHES:
            return bool(re.match(self.value, str(actual)))
        elif self.operator == ConditionOperator.IN:
            return actual in self.value
        elif self.operator == ConditionOperator.NOT_IN:
            return actual not in self.value

        return False

    def _get_field_value(self, data: Dict[str, Any], field: str) -> Any:
        """Get nested field value from data."""
        parts = field.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
        return current


@dataclass
class Alert:
    """Represents an alert instance."""

    alert_id: str
    rule_id: str
    name: str
    severity: AlertSeverity
    state: AlertState = AlertState.PENDING
    message: str = ""
    source: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    triggered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    firing_count: int = 1
    last_fired_at: Optional[datetime] = None
    fingerprint: str = ""

    def __post_init__(self):
        """Generate fingerprint if not set."""
        if not self.fingerprint:
            self.fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication."""
        data = f"{self.rule_id}:{self.name}:{sorted(self.labels.items())}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def acknowledge(self, by: str) -> None:
        """Acknowledge the alert."""
        self.state = AlertState.ACKNOWLEDGED
        self.acknowledged_at = datetime.now(timezone.utc)
        self.acknowledged_by = by

    def resolve(self, by: Optional[str] = None) -> None:
        """Resolve the alert."""
        self.state = AlertState.RESOLVED
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by = by or "auto"

    def silence(self) -> None:
        """Silence the alert."""
        self.state = AlertState.SILENCED

    def fire_again(self) -> None:
        """Mark alert as firing again."""
        self.firing_count += 1
        self.last_fired_at = datetime.now(timezone.utc)
        if self.state in (AlertState.RESOLVED, AlertState.SILENCED):
            self.state = AlertState.FIRING

    @property
    def duration(self) -> Optional[timedelta]:
        """Get alert duration."""
        if self.resolved_at:
            return self.resolved_at - self.triggered_at
        return datetime.now(timezone.utc) - self.triggered_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "state": self.state.value,
            "message": self.message,
            "source": self.source,
            "labels": self.labels,
            "annotations": self.annotations,
            "triggered_at": self.triggered_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "firing_count": self.firing_count,
            "fingerprint": self.fingerprint,
        }


@dataclass
class AlertRule:
    """Defines conditions for triggering alerts."""

    rule_id: str
    name: str
    conditions: List[AlertCondition]
    severity: AlertSeverity = AlertSeverity.MEDIUM
    message_template: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    for_duration: Optional[timedelta] = None  # Must be true for this duration
    enabled: bool = True
    channels: List[str] = field(default_factory=list)  # Notification channel IDs
    cooldown: Optional[timedelta] = None  # Minimum time between alerts
    condition_logic: str = "all"  # "all" or "any"

    def evaluate(self, data: Dict[str, Any]) -> bool:
        """Evaluate all conditions."""
        if not self.enabled:
            return False

        if not self.conditions:
            return False

        if self.condition_logic == "all":
            return all(c.evaluate(data) for c in self.conditions)
        else:
            return any(c.evaluate(data) for c in self.conditions)

    def create_alert(self, data: Optional[Dict[str, Any]] = None) -> Alert:
        """Create an alert from this rule."""
        message = self.message_template
        if data:
            try:
                message = self.message_template.format(**data)
            except (KeyError, ValueError):
                pass

        return Alert(
            alert_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            state=AlertState.FIRING,
            message=message,
            labels=dict(self.labels),
            annotations=dict(self.annotations),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "enabled": self.enabled,
            "condition_logic": self.condition_logic,
            "conditions": [
                {
                    "field": c.field,
                    "operator": c.operator.value,
                    "value": c.value,
                }
                for c in self.conditions
            ],
            "channels": self.channels,
            "labels": self.labels,
        }


@dataclass
class SilenceRule:
    """Rule for silencing alerts."""

    silence_id: str
    matchers: Dict[str, str]  # Label matchers
    starts_at: datetime
    ends_at: datetime
    created_by: str
    comment: str = ""

    def matches(self, alert: Alert) -> bool:
        """Check if this silence matches an alert."""
        now = datetime.now(timezone.utc)
        if not (self.starts_at <= now <= self.ends_at):
            return False

        for key, value in self.matchers.items():
            if key == "name" and alert.name != value:
                return False
            elif key == "severity" and alert.severity.value != value:
                return False
            elif key == "rule_id" and alert.rule_id != value:
                return False
            elif key in alert.labels and alert.labels[key] != value:
                return False

        return True

    @property
    def is_active(self) -> bool:
        """Check if silence is currently active."""
        now = datetime.now(timezone.utc)
        return self.starts_at <= now <= self.ends_at


class NotificationChannel(ABC):
    """Base class for notification channels."""

    def __init__(self, channel_id: str, name: str):
        """Initialize channel."""
        self._id = channel_id
        self._name = name
        self._enabled = True

    @property
    def id(self) -> str:
        """Get channel ID."""
        return self._id

    @property
    def name(self) -> str:
        """Get channel name."""
        return self._name

    @property
    def enabled(self) -> bool:
        """Check if channel is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Set channel enabled state."""
        self._enabled = value

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send alert notification."""
        pass

    @abstractmethod
    def send_resolved(self, alert: Alert) -> bool:
        """Send resolution notification."""
        pass


class WebhookChannel(NotificationChannel):
    """Webhook notification channel."""

    def __init__(self,
                 channel_id: str,
                 name: str,
                 url: str,
                 headers: Optional[Dict[str, str]] = None,
                 method: str = "POST"):
        """Initialize webhook channel."""
        super().__init__(channel_id, name)
        self._url = url
        self._headers = headers or {}
        self._method = method
        self._last_response: Optional[Dict[str, Any]] = None

    @property
    def url(self) -> str:
        """Get webhook URL."""
        return self._url

    def send(self, alert: Alert) -> bool:
        """Send alert via webhook."""
        payload = {
            "type": "alert",
            "alert": alert.to_dict(),
        }
        return self._send_request(payload)

    def send_resolved(self, alert: Alert) -> bool:
        """Send resolution via webhook."""
        payload = {
            "type": "resolved",
            "alert": alert.to_dict(),
        }
        return self._send_request(payload)

    def _send_request(self, payload: Dict[str, Any]) -> bool:
        """Send HTTP request."""
        try:
            import urllib.request
            import urllib.error

            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", **self._headers}

            req = urllib.request.Request(
                self._url,
                data=data,
                headers=headers,
                method=self._method,
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                self._last_response = {
                    "status": response.status,
                    "body": response.read().decode("utf-8"),
                }
                return response.status < 400

        except Exception as e:
            self._last_response = {"error": str(e)}
            return False


class EmailChannel(NotificationChannel):
    """Email notification channel."""

    def __init__(self,
                 channel_id: str,
                 name: str,
                 recipients: List[str],
                 smtp_host: str = "localhost",
                 smtp_port: int = 25,
                 from_address: str = "alerts@redops.local",
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 use_tls: bool = False):
        """Initialize email channel."""
        super().__init__(channel_id, name)
        self._recipients = recipients
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._from_address = from_address
        self._username = username
        self._password = password
        self._use_tls = use_tls

    def send(self, alert: Alert) -> bool:
        """Send alert email."""
        subject = f"[{alert.severity.value.upper()}] Alert: {alert.name}"
        body = self._format_alert_body(alert, resolved=False)
        return self._send_email(subject, body)

    def send_resolved(self, alert: Alert) -> bool:
        """Send resolution email."""
        subject = f"[RESOLVED] Alert: {alert.name}"
        body = self._format_alert_body(alert, resolved=True)
        return self._send_email(subject, body)

    def _format_alert_body(self, alert: Alert, resolved: bool) -> str:
        """Format alert email body."""
        status = "RESOLVED" if resolved else "FIRING"
        lines = [
            f"Alert: {alert.name}",
            f"Status: {status}",
            f"Severity: {alert.severity.value}",
            f"Message: {alert.message}",
            f"Triggered: {alert.triggered_at.isoformat()}",
        ]
        if resolved and alert.resolved_at:
            lines.append(f"Resolved: {alert.resolved_at.isoformat()}")
        if alert.labels:
            lines.append(f"Labels: {alert.labels}")
        return "\n".join(lines)

    def _send_email(self, subject: str, body: str) -> bool:
        """Send email via SMTP."""
        try:
            import smtplib
            from email.mime.text import MIMEText

            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self._from_address
            msg["To"] = ", ".join(self._recipients)

            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                if self._use_tls:
                    server.starttls()
                if self._username and self._password:
                    server.login(self._username, self._password)
                server.sendmail(self._from_address, self._recipients, msg.as_string())

            return True
        except Exception:
            return False


class CallbackChannel(NotificationChannel):
    """Callback-based notification channel for custom handling."""

    def __init__(self,
                 channel_id: str,
                 name: str,
                 on_alert: Callable[[Alert], bool],
                 on_resolved: Optional[Callable[[Alert], bool]] = None):
        """Initialize callback channel."""
        super().__init__(channel_id, name)
        self._on_alert = on_alert
        self._on_resolved = on_resolved

    def send(self, alert: Alert) -> bool:
        """Send alert via callback."""
        return self._on_alert(alert)

    def send_resolved(self, alert: Alert) -> bool:
        """Send resolution via callback."""
        if self._on_resolved:
            return self._on_resolved(alert)
        return True


class LogChannel(NotificationChannel):
    """Log-based notification channel."""

    def __init__(self, channel_id: str, name: str):
        """Initialize log channel."""
        super().__init__(channel_id, name)
        self._alerts: List[Dict[str, Any]] = []

    @property
    def alerts(self) -> List[Dict[str, Any]]:
        """Get logged alerts."""
        return list(self._alerts)

    def send(self, alert: Alert) -> bool:
        """Log alert."""
        self._alerts.append({
            "type": "alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert": alert.to_dict(),
        })
        return True

    def send_resolved(self, alert: Alert) -> bool:
        """Log resolution."""
        self._alerts.append({
            "type": "resolved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert": alert.to_dict(),
        })
        return True

    def clear(self) -> None:
        """Clear logged alerts."""
        self._alerts.clear()


@dataclass
class EscalationLevel:
    """A level in an escalation policy."""

    level: int
    delay: timedelta
    channels: List[str]
    repeat_count: int = 1


class EscalationPolicy:
    """Policy for escalating unacknowledged alerts."""

    def __init__(self, policy_id: str, name: str):
        """Initialize escalation policy."""
        self._id = policy_id
        self._name = name
        self._levels: List[EscalationLevel] = []

    @property
    def id(self) -> str:
        """Get policy ID."""
        return self._id

    @property
    def name(self) -> str:
        """Get policy name."""
        return self._name

    @property
    def levels(self) -> List[EscalationLevel]:
        """Get escalation levels."""
        return self._levels

    def add_level(self,
                  delay: timedelta,
                  channels: List[str],
                  repeat_count: int = 1) -> "EscalationPolicy":
        """Add an escalation level."""
        level = EscalationLevel(
            level=len(self._levels) + 1,
            delay=delay,
            channels=channels,
            repeat_count=repeat_count,
        )
        self._levels.append(level)
        return self

    def get_level_for_duration(self, duration: timedelta) -> Optional[EscalationLevel]:
        """Get the escalation level for a given alert duration."""
        for level in reversed(self._levels):
            if duration >= level.delay:
                return level
        return None


class AlertManager:
    """Central manager for alerts."""

    def __init__(self):
        """Initialize alert manager."""
        self._rules: Dict[str, AlertRule] = {}
        self._alerts: Dict[str, Alert] = {}
        self._channels: Dict[str, NotificationChannel] = {}
        self._silences: Dict[str, SilenceRule] = {}
        self._policies: Dict[str, EscalationPolicy] = {}
        self._alert_history: List[Alert] = []
        self._lock = threading.Lock()
        self._last_evaluation: Dict[str, datetime] = {}
        self._pending_conditions: Dict[str, Tuple[datetime, Dict[str, Any]]] = {}

    # Rule management
    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        with self._lock:
            self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> None:
        """Remove an alert rule."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]

    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_rules(self) -> List[AlertRule]:
        """Get all rules."""
        return list(self._rules.values())

    # Channel management
    def add_channel(self, channel: NotificationChannel) -> None:
        """Add a notification channel."""
        with self._lock:
            self._channels[channel.id] = channel

    def remove_channel(self, channel_id: str) -> None:
        """Remove a notification channel."""
        with self._lock:
            if channel_id in self._channels:
                del self._channels[channel_id]

    def get_channel(self, channel_id: str) -> Optional[NotificationChannel]:
        """Get a channel by ID."""
        return self._channels.get(channel_id)

    # Silence management
    def add_silence(self, silence: SilenceRule) -> None:
        """Add a silence rule."""
        with self._lock:
            self._silences[silence.silence_id] = silence

    def remove_silence(self, silence_id: str) -> None:
        """Remove a silence rule."""
        with self._lock:
            if silence_id in self._silences:
                del self._silences[silence_id]

    def get_active_silences(self) -> List[SilenceRule]:
        """Get currently active silences."""
        return [s for s in self._silences.values() if s.is_active]

    # Escalation policy management
    def add_policy(self, policy: EscalationPolicy) -> None:
        """Add an escalation policy."""
        with self._lock:
            self._policies[policy.id] = policy

    def get_policy(self, policy_id: str) -> Optional[EscalationPolicy]:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    # Alert management
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        return self._alerts.get(alert_id)

    def get_alerts(self,
                   state: Optional[AlertState] = None,
                   severity: Optional[AlertSeverity] = None,
                   rule_id: Optional[str] = None) -> List[Alert]:
        """Get alerts with optional filters."""
        alerts = list(self._alerts.values())

        if state is not None:
            alerts = [a for a in alerts if a.state == state]
        if severity is not None:
            alerts = [a for a in alerts if a.severity == severity]
        if rule_id is not None:
            alerts = [a for a in alerts if a.rule_id == rule_id]

        return sorted(alerts, key=lambda a: a.triggered_at, reverse=True)

    def get_firing_alerts(self) -> List[Alert]:
        """Get all firing alerts."""
        return self.get_alerts(state=AlertState.FIRING)

    def acknowledge_alert(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert and alert.state == AlertState.FIRING:
                alert.acknowledge(by)
                return True
            return False

    def resolve_alert(self, alert_id: str, by: Optional[str] = None) -> bool:
        """Resolve an alert."""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert and alert.state in (AlertState.FIRING, AlertState.ACKNOWLEDGED):
                alert.resolve(by)
                self._send_resolved(alert)
                self._archive_alert(alert)
                return True
            return False

    def _archive_alert(self, alert: Alert) -> None:
        """Move alert to history."""
        self._alert_history.append(alert)
        if alert.alert_id in self._alerts:
            del self._alerts[alert.alert_id]

    # Evaluation
    def evaluate(self, data: Dict[str, Any], source: str = "") -> List[Alert]:
        """Evaluate all rules against data."""
        triggered = []

        with self._lock:
            for rule in self._rules.values():
                if not rule.enabled:
                    continue

                # Check cooldown
                if rule.cooldown:
                    last_eval = self._last_evaluation.get(rule.rule_id)
                    if last_eval:
                        if datetime.now(timezone.utc) - last_eval < rule.cooldown:
                            continue

                if rule.evaluate(data):
                    # Handle for_duration
                    if rule.for_duration:
                        if rule.rule_id not in self._pending_conditions:
                            self._pending_conditions[rule.rule_id] = (
                                datetime.now(timezone.utc),
                                data,
                            )
                            continue
                        else:
                            start_time, _ = self._pending_conditions[rule.rule_id]
                            if datetime.now(timezone.utc) - start_time < rule.for_duration:
                                continue
                            # Duration satisfied, clear pending
                            del self._pending_conditions[rule.rule_id]
                    else:
                        # Clear any pending if condition no longer needs duration
                        if rule.rule_id in self._pending_conditions:
                            del self._pending_conditions[rule.rule_id]

                    # Check for existing alert (deduplication)
                    existing = self._find_existing_alert(rule)
                    if existing:
                        existing.fire_again()
                    else:
                        alert = rule.create_alert(data)
                        alert.source = source

                        # Check silences
                        if self._is_silenced(alert):
                            alert.silence()
                        else:
                            self._send_alert(alert, rule)

                        self._alerts[alert.alert_id] = alert
                        triggered.append(alert)

                    self._last_evaluation[rule.rule_id] = datetime.now(timezone.utc)
                else:
                    # Condition not met, clear pending
                    if rule.rule_id in self._pending_conditions:
                        del self._pending_conditions[rule.rule_id]

        return triggered

    def _find_existing_alert(self, rule: AlertRule) -> Optional[Alert]:
        """Find existing firing alert for a rule."""
        for alert in self._alerts.values():
            if alert.rule_id == rule.rule_id and alert.state in (
                AlertState.FIRING,
                AlertState.ACKNOWLEDGED,
            ):
                return alert
        return None

    def _is_silenced(self, alert: Alert) -> bool:
        """Check if alert should be silenced."""
        for silence in self._silences.values():
            if silence.matches(alert):
                return True
        return False

    def _send_alert(self, alert: Alert, rule: AlertRule) -> None:
        """Send alert to channels."""
        channel_ids = rule.channels if rule.channels else list(self._channels.keys())

        for channel_id in channel_ids:
            channel = self._channels.get(channel_id)
            if channel and channel.enabled:
                try:
                    channel.send(alert)
                except Exception:
                    pass

    def _send_resolved(self, alert: Alert) -> None:
        """Send resolution to channels."""
        rule = self._rules.get(alert.rule_id)
        channel_ids = rule.channels if rule else list(self._channels.keys())

        for channel_id in channel_ids:
            channel = self._channels.get(channel_id)
            if channel and channel.enabled:
                try:
                    channel.send_resolved(alert)
                except Exception:
                    pass

    # History
    def get_history(self,
                    limit: int = 100,
                    since: Optional[datetime] = None) -> List[Alert]:
        """Get alert history."""
        history = self._alert_history
        if since:
            history = [a for a in history if a.triggered_at >= since]
        return sorted(history, key=lambda a: a.triggered_at, reverse=True)[:limit]

    def clear_history(self) -> None:
        """Clear alert history."""
        with self._lock:
            self._alert_history.clear()

    # Stats
    def get_stats(self) -> Dict[str, Any]:
        """Get alerting statistics."""
        alerts = list(self._alerts.values())
        return {
            "total_rules": len(self._rules),
            "enabled_rules": sum(1 for r in self._rules.values() if r.enabled),
            "total_channels": len(self._channels),
            "active_silences": len(self.get_active_silences()),
            "total_alerts": len(alerts),
            "firing": sum(1 for a in alerts if a.state == AlertState.FIRING),
            "acknowledged": sum(1 for a in alerts if a.state == AlertState.ACKNOWLEDGED),
            "silenced": sum(1 for a in alerts if a.state == AlertState.SILENCED),
            "by_severity": {
                s.value: sum(1 for a in alerts if a.severity == s)
                for s in AlertSeverity
            },
        }


# Convenience functions
def create_rule(
    name: str,
    conditions: List[Tuple[str, str, Any]],
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    message: str = "",
    **kwargs
) -> AlertRule:
    """Create an alert rule with simple condition syntax."""
    operator_map = {
        "==": ConditionOperator.EQUALS,
        "!=": ConditionOperator.NOT_EQUALS,
        ">": ConditionOperator.GREATER_THAN,
        ">=": ConditionOperator.GREATER_THAN_OR_EQUAL,
        "<": ConditionOperator.LESS_THAN,
        "<=": ConditionOperator.LESS_THAN_OR_EQUAL,
        "contains": ConditionOperator.CONTAINS,
        "matches": ConditionOperator.MATCHES,
        "in": ConditionOperator.IN,
    }

    parsed_conditions = []
    for field, op, value in conditions:
        operator = operator_map.get(op, ConditionOperator.EQUALS)
        parsed_conditions.append(AlertCondition(
            field=field,
            operator=operator,
            value=value,
        ))

    return AlertRule(
        rule_id=str(uuid.uuid4()),
        name=name,
        conditions=parsed_conditions,
        severity=severity,
        message_template=message,
        **kwargs,
    )


def threshold_rule(
    name: str,
    field: str,
    threshold: float,
    operator: str = ">",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    message: str = "",
    **kwargs
) -> AlertRule:
    """Create a simple threshold-based rule."""
    return create_rule(
        name=name,
        conditions=[(field, operator, threshold)],
        severity=severity,
        message=message or f"{field} {operator} {threshold}",
        **kwargs,
    )
