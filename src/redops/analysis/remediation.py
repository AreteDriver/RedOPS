"""
Remediation tracking and progress monitoring.

Tracks the lifecycle of findings from detection to remediation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class RemediationStatus(Enum):
    """Status of remediation efforts."""

    OPEN = "open"  # Not yet addressed
    IN_PROGRESS = "in_progress"  # Being worked on
    PENDING_VERIFICATION = "pending_verification"  # Fix applied, needs retest
    VERIFIED = "verified"  # Fix confirmed
    FALSE_POSITIVE = "false_positive"  # Not a real issue
    ACCEPTED_RISK = "accepted_risk"  # Risk accepted
    DEFERRED = "deferred"  # Postponed


class RemediationPriority(Enum):
    """Priority levels for remediation."""

    P1_CRITICAL = 1  # Fix immediately (< 24 hours)
    P2_HIGH = 2  # Fix within 7 days
    P3_MEDIUM = 3  # Fix within 30 days
    P4_LOW = 4  # Fix within 90 days
    P5_INFORMATIONAL = 5  # Best effort


# SLA definitions by severity
DEFAULT_SLAS = {
    "critical": timedelta(days=1),
    "high": timedelta(days=7),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
    "info": timedelta(days=180),
}


@dataclass
class RemediationRecord:
    """Record of a finding's remediation status."""

    finding_id: str
    finding_title: str
    severity: str
    status: RemediationStatus = RemediationStatus.OPEN
    priority: Optional[RemediationPriority] = None
    assignee: Optional[str] = None
    due_date: Optional[datetime] = None
    detected_at: datetime = field(default_factory=datetime.now)
    status_changed_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    notes: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Set defaults based on severity."""
        if self.priority is None:
            self.priority = self._severity_to_priority()
        if self.due_date is None:
            self.due_date = self._calculate_due_date()

    def _severity_to_priority(self) -> RemediationPriority:
        """Map severity to priority."""
        mapping = {
            "critical": RemediationPriority.P1_CRITICAL,
            "high": RemediationPriority.P2_HIGH,
            "medium": RemediationPriority.P3_MEDIUM,
            "low": RemediationPriority.P4_LOW,
            "info": RemediationPriority.P5_INFORMATIONAL,
        }
        return mapping.get(self.severity.lower(), RemediationPriority.P3_MEDIUM)

    def _calculate_due_date(self) -> datetime:
        """Calculate due date based on severity SLA."""
        sla = DEFAULT_SLAS.get(self.severity.lower(), timedelta(days=30))
        return self.detected_at + sla

    @property
    def is_overdue(self) -> bool:
        """Check if remediation is overdue."""
        if self.status in (
            RemediationStatus.VERIFIED,
            RemediationStatus.FALSE_POSITIVE,
            RemediationStatus.ACCEPTED_RISK,
        ):
            return False
        return datetime.now() > self.due_date if self.due_date else False

    @property
    def days_open(self) -> int:
        """Days since finding was detected."""
        end_date = self.resolved_at or datetime.now()
        return (end_date - self.detected_at).days

    @property
    def days_until_due(self) -> Optional[int]:
        """Days until due date (negative if overdue)."""
        if not self.due_date:
            return None
        return (self.due_date - datetime.now()).days

    @property
    def mttr(self) -> Optional[float]:
        """Mean time to remediate in days (if resolved)."""
        if self.resolved_at:
            return (self.resolved_at - self.detected_at).total_seconds() / 86400
        return None

    def add_note(self, text: str, author: Optional[str] = None) -> None:
        """Add a note to the remediation record."""
        self.notes.append(
            {
                "text": text,
                "author": author,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def update_status(
        self, new_status: RemediationStatus, note: Optional[str] = None
    ) -> None:
        """Update remediation status."""
        old_status = self.status
        self.status = new_status
        self.status_changed_at = datetime.now()

        if new_status in (
            RemediationStatus.VERIFIED,
            RemediationStatus.FALSE_POSITIVE,
            RemediationStatus.ACCEPTED_RISK,
        ):
            self.resolved_at = datetime.now()

        if note:
            self.add_note(f"Status changed: {old_status.value} -> {new_status.value}. {note}")

        logger.info(f"Finding {self.finding_id} status: {old_status.value} -> {new_status.value}")


@dataclass
class RemediationMetrics:
    """Aggregated remediation metrics."""

    total_findings: int = 0
    open_findings: int = 0
    in_progress: int = 0
    verified: int = 0
    false_positives: int = 0
    accepted_risk: int = 0
    overdue: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_priority: Dict[str, int] = field(default_factory=dict)
    avg_mttr_days: Optional[float] = None
    remediation_rate: float = 0.0
    sla_compliance_rate: float = 0.0


class RemediationTracker:
    """Track and manage remediation progress across findings.

    Provides metrics, SLA tracking, and remediation workflow management.
    """

    def __init__(
        self,
        slas: Optional[Dict[str, timedelta]] = None,
        auto_assign: bool = False,
        assignment_rules: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize tracker.

        Args:
            slas: Custom SLA definitions by severity
            auto_assign: Automatically assign findings
            assignment_rules: Rules for auto-assignment (severity -> assignee)
        """
        self.slas = slas or DEFAULT_SLAS.copy()
        self.auto_assign = auto_assign
        self.assignment_rules = assignment_rules or {}
        self.records: Dict[str, RemediationRecord] = {}

    def track_finding(
        self,
        finding_id: str,
        finding_title: str,
        severity: str,
        detected_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RemediationRecord:
        """
        Start tracking a finding.

        Args:
            finding_id: Unique finding identifier
            finding_title: Title/description of finding
            severity: Severity level
            detected_at: When finding was detected
            metadata: Additional metadata

        Returns:
            RemediationRecord for the finding
        """
        if finding_id in self.records:
            logger.warning(f"Finding {finding_id} already tracked, updating")

        record = RemediationRecord(
            finding_id=finding_id,
            finding_title=finding_title,
            severity=severity,
            detected_at=detected_at or datetime.now(),
            metadata=metadata or {},
        )

        # Calculate custom due date
        sla = self.slas.get(severity.lower(), timedelta(days=30))
        record.due_date = record.detected_at + sla

        # Auto-assign if enabled
        if self.auto_assign and severity.lower() in self.assignment_rules:
            record.assignee = self.assignment_rules[severity.lower()]

        self.records[finding_id] = record
        logger.info(f"Now tracking finding {finding_id} ({severity})")

        return record

    def track_findings_from_scan(
        self, scan_data: Dict[str, Any]
    ) -> List[RemediationRecord]:
        """
        Track all findings from a scan.

        Args:
            scan_data: Scan result dictionary

        Returns:
            List of created RemediationRecords
        """
        records = []
        scan_time = self._parse_date(scan_data.get("started_at"))

        for finding in scan_data.get("findings", []):
            record = self.track_finding(
                finding_id=str(finding.get("id", "")),
                finding_title=finding.get("title", ""),
                severity=finding.get("severity", "medium"),
                detected_at=scan_time,
                metadata={
                    "scan_id": scan_data.get("scan_id"),
                    "target": scan_data.get("target"),
                    "module": finding.get("module"),
                    "category": finding.get("category"),
                },
            )
            records.append(record)

        return records

    def update_from_comparison(
        self,
        comparison_result: Any,  # ComparisonResult
    ) -> Dict[str, List[str]]:
        """
        Update tracking based on scan comparison.

        Args:
            comparison_result: Result from ScanComparator

        Returns:
            Dictionary of finding IDs by action taken
        """
        actions = {
            "marked_resolved": [],
            "new_tracked": [],
            "reactivated": [],
        }

        # Mark resolved findings
        for diff in comparison_result.resolved_findings:
            finding_id = diff.finding.id
            if finding_id in self.records:
                self.records[finding_id].update_status(
                    RemediationStatus.PENDING_VERIFICATION,
                    "Finding not present in latest scan",
                )
                actions["marked_resolved"].append(finding_id)

        # Track new findings
        for diff in comparison_result.new_findings:
            record = self.track_finding(
                finding_id=diff.finding.id,
                finding_title=diff.finding.title,
                severity=diff.finding.severity,
                metadata={"category": diff.finding.category, "module": diff.finding.module},
            )
            actions["new_tracked"].append(record.finding_id)

        # Handle regressions
        for diff in comparison_result.regression_findings:
            finding_id = diff.finding.id
            if finding_id in self.records:
                self.records[finding_id].update_status(
                    RemediationStatus.OPEN,
                    "Finding reappeared in latest scan (regression)",
                )
                actions["reactivated"].append(finding_id)
            else:
                record = self.track_finding(
                    finding_id=diff.finding.id,
                    finding_title=diff.finding.title,
                    severity=diff.finding.severity,
                )
                record.add_note("This is a regression - finding was previously resolved")
                actions["new_tracked"].append(record.finding_id)

        return actions

    def get_record(self, finding_id: str) -> Optional[RemediationRecord]:
        """Get a specific remediation record."""
        return self.records.get(finding_id)

    def get_records_by_status(
        self, status: RemediationStatus
    ) -> List[RemediationRecord]:
        """Get all records with a specific status."""
        return [r for r in self.records.values() if r.status == status]

    def get_overdue_records(self) -> List[RemediationRecord]:
        """Get all overdue records."""
        return [r for r in self.records.values() if r.is_overdue]

    def get_records_by_assignee(self, assignee: str) -> List[RemediationRecord]:
        """Get all records assigned to a person."""
        return [r for r in self.records.values() if r.assignee == assignee]

    def get_metrics(self) -> RemediationMetrics:
        """Calculate aggregated remediation metrics."""
        metrics = RemediationMetrics()
        metrics.total_findings = len(self.records)

        mttr_values = []
        sla_met = 0

        for record in self.records.values():
            # Count by status
            if record.status == RemediationStatus.OPEN:
                metrics.open_findings += 1
            elif record.status == RemediationStatus.IN_PROGRESS:
                metrics.in_progress += 1
            elif record.status == RemediationStatus.VERIFIED:
                metrics.verified += 1
            elif record.status == RemediationStatus.FALSE_POSITIVE:
                metrics.false_positives += 1
            elif record.status == RemediationStatus.ACCEPTED_RISK:
                metrics.accepted_risk += 1

            # Count overdue
            if record.is_overdue:
                metrics.overdue += 1

            # Count by severity
            severity = record.severity.lower()
            metrics.by_severity[severity] = metrics.by_severity.get(severity, 0) + 1

            # Count by priority
            if record.priority:
                priority = record.priority.name
                metrics.by_priority[priority] = metrics.by_priority.get(priority, 0) + 1

            # MTTR for resolved
            if record.mttr is not None:
                mttr_values.append(record.mttr)

                # Check if SLA was met
                if record.resolved_at and record.due_date:
                    if record.resolved_at <= record.due_date:
                        sla_met += 1

        # Calculate averages
        if mttr_values:
            metrics.avg_mttr_days = sum(mttr_values) / len(mttr_values)

        resolved = metrics.verified + metrics.false_positives
        if metrics.total_findings > 0:
            metrics.remediation_rate = (resolved / metrics.total_findings) * 100

        if resolved > 0:
            metrics.sla_compliance_rate = (sla_met / resolved) * 100

        return metrics

    def generate_report(self) -> str:
        """Generate a text report of remediation status."""
        metrics = self.get_metrics()

        lines = [
            "Remediation Status Report",
            "=" * 50,
            "",
            "Overview:",
            f"  Total findings tracked: {metrics.total_findings}",
            f"  Open:                   {metrics.open_findings}",
            f"  In Progress:            {metrics.in_progress}",
            f"  Verified/Resolved:      {metrics.verified}",
            f"  False Positives:        {metrics.false_positives}",
            f"  Accepted Risk:          {metrics.accepted_risk}",
            f"  Overdue:                {metrics.overdue}",
            "",
            "Metrics:",
            f"  Remediation Rate:       {metrics.remediation_rate:.1f}%",
            f"  SLA Compliance:         {metrics.sla_compliance_rate:.1f}%",
        ]

        if metrics.avg_mttr_days is not None:
            lines.append(f"  Average MTTR:           {metrics.avg_mttr_days:.1f} days")

        # By severity
        lines.extend(["", "By Severity:"])
        for severity, count in sorted(metrics.by_severity.items()):
            lines.append(f"  {severity.title()}: {count}")

        # Overdue details
        overdue = self.get_overdue_records()
        if overdue:
            lines.extend(["", f"Overdue Items ({len(overdue)}):"])
            for record in sorted(overdue, key=lambda r: r.due_date or datetime.max)[:10]:
                days = abs(record.days_until_due or 0)
                lines.append(
                    f"  [{record.severity.upper()}] {record.finding_title[:40]} "
                    f"- {days} days overdue"
                )

        return "\n".join(lines)

    def _parse_date(self, date_value: Any) -> datetime:
        """Parse date from various formats."""
        if isinstance(date_value, datetime):
            return date_value
        if isinstance(date_value, str):
            try:
                return datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now()
