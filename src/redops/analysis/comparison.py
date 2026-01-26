"""
Scan comparison and diff functionality.

Compares findings between scans to identify new, resolved, and unchanged issues.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import hashlib
import logging

logger = logging.getLogger(__name__)


class DiffType(Enum):
    """Type of finding difference."""

    NEW = "new"  # Finding appeared in new scan
    RESOLVED = "resolved"  # Finding no longer present
    UNCHANGED = "unchanged"  # Finding exists in both
    MODIFIED = "modified"  # Finding exists but changed
    REGRESSION = "regression"  # Previously resolved, now reappeared


@dataclass
class FindingData:
    """Normalized finding data for comparison."""

    id: str
    title: str
    severity: str
    description: str
    module: str = ""
    category: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    status: str = "open"
    fingerprint: str = ""

    def __post_init__(self):
        """Generate fingerprint if not provided."""
        if not self.fingerprint:
            self.fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """Generate a fingerprint for deduplication.

        The fingerprint is based on stable attributes that identify
        the same vulnerability across scans.
        """
        # Create fingerprint from stable attributes
        components = [
            self.title.lower().strip(),
            self.severity.lower(),
            self.module.lower() if self.module else "",
            self.category.lower() if self.category else "",
        ]

        # Add key evidence items if present
        if self.evidence:
            for key in sorted(self.evidence.keys()):
                if key in ("url", "endpoint", "parameter", "path", "port"):
                    components.append(str(self.evidence[key]).lower())

        # Add CVEs for precise matching
        if self.cve_ids:
            components.extend(sorted(self.cve_ids))

        fingerprint_str = "|".join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


@dataclass
class FindingDiff:
    """Represents a difference between findings."""

    diff_type: DiffType
    finding: FindingData
    previous_finding: Optional[FindingData] = None
    changes: Dict[str, Tuple[Any, Any]] = field(default_factory=dict)

    @property
    def is_improvement(self) -> bool:
        """Check if this diff represents an improvement."""
        if self.diff_type == DiffType.RESOLVED:
            return True
        if self.diff_type == DiffType.MODIFIED and self.previous_finding:
            # Severity decreased
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            old_sev = severity_order.get(self.previous_finding.severity.lower(), 0)
            new_sev = severity_order.get(self.finding.severity.lower(), 0)
            return new_sev < old_sev
        return False

    @property
    def is_regression(self) -> bool:
        """Check if this diff represents a regression."""
        if self.diff_type in (DiffType.NEW, DiffType.REGRESSION):
            return True
        if self.diff_type == DiffType.MODIFIED and self.previous_finding:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            old_sev = severity_order.get(self.previous_finding.severity.lower(), 0)
            new_sev = severity_order.get(self.finding.severity.lower(), 0)
            return new_sev > old_sev
        return False


@dataclass
class ComparisonResult:
    """Result of comparing two scans."""

    baseline_scan_id: str
    current_scan_id: str
    baseline_date: datetime
    current_date: datetime
    target: str
    new_findings: List[FindingDiff] = field(default_factory=list)
    resolved_findings: List[FindingDiff] = field(default_factory=list)
    unchanged_findings: List[FindingDiff] = field(default_factory=list)
    modified_findings: List[FindingDiff] = field(default_factory=list)
    regression_findings: List[FindingDiff] = field(default_factory=list)

    @property
    def total_baseline(self) -> int:
        """Total findings in baseline scan."""
        return (
            len(self.resolved_findings)
            + len(self.unchanged_findings)
            + len(self.modified_findings)
        )

    @property
    def total_current(self) -> int:
        """Total findings in current scan."""
        return (
            len(self.new_findings)
            + len(self.unchanged_findings)
            + len(self.modified_findings)
            + len(self.regression_findings)
        )

    @property
    def remediation_rate(self) -> float:
        """Calculate remediation rate as percentage."""
        if self.total_baseline == 0:
            return 100.0
        resolved = len(self.resolved_findings)
        return (resolved / self.total_baseline) * 100

    @property
    def new_finding_rate(self) -> float:
        """Calculate rate of new findings."""
        if self.total_current == 0:
            return 0.0
        new = len(self.new_findings) + len(self.regression_findings)
        return (new / self.total_current) * 100

    def severity_summary(self, diff_type: Optional[DiffType] = None) -> Dict[str, int]:
        """Get severity counts for a diff type or all."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        if diff_type is None:
            findings = (
                self.new_findings
                + self.resolved_findings
                + self.unchanged_findings
                + self.modified_findings
                + self.regression_findings
            )
        elif diff_type == DiffType.NEW:
            findings = self.new_findings
        elif diff_type == DiffType.RESOLVED:
            findings = self.resolved_findings
        elif diff_type == DiffType.UNCHANGED:
            findings = self.unchanged_findings
        elif diff_type == DiffType.MODIFIED:
            findings = self.modified_findings
        elif diff_type == DiffType.REGRESSION:
            findings = self.regression_findings
        else:
            findings = []

        for diff in findings:
            severity = diff.finding.severity.lower()
            if severity in counts:
                counts[severity] += 1

        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "baseline_date": self.baseline_date.isoformat(),
            "current_date": self.current_date.isoformat(),
            "target": self.target,
            "summary": {
                "baseline_total": self.total_baseline,
                "current_total": self.total_current,
                "new": len(self.new_findings),
                "resolved": len(self.resolved_findings),
                "unchanged": len(self.unchanged_findings),
                "modified": len(self.modified_findings),
                "regressions": len(self.regression_findings),
                "remediation_rate": round(self.remediation_rate, 2),
                "new_finding_rate": round(self.new_finding_rate, 2),
            },
            "severity_new": self.severity_summary(DiffType.NEW),
            "severity_resolved": self.severity_summary(DiffType.RESOLVED),
        }


class ScanComparator:
    """Compare findings between two scans.

    Identifies new, resolved, and modified findings to track
    remediation progress over time.
    """

    def __init__(
        self,
        match_threshold: float = 0.8,
        use_fingerprint: bool = True,
        track_regressions: bool = True,
        historical_scans: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Initialize comparator.

        Args:
            match_threshold: Similarity threshold for fuzzy matching
            use_fingerprint: Use fingerprint-based matching
            track_regressions: Track findings that reappear
            historical_scans: Previous scan data for regression detection
        """
        self.match_threshold = match_threshold
        self.use_fingerprint = use_fingerprint
        self.track_regressions = track_regressions
        self.historical_fingerprints: Set[str] = set()

        if historical_scans and track_regressions:
            self._load_historical_fingerprints(historical_scans)

    def _load_historical_fingerprints(self, scans: List[Dict[str, Any]]) -> None:
        """Load fingerprints from historical scans."""
        for scan in scans:
            for finding in scan.get("findings", []):
                fp = self._extract_fingerprint(finding)
                if fp:
                    self.historical_fingerprints.add(fp)

    def _extract_fingerprint(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract or generate fingerprint from finding dict."""
        if "fingerprint" in finding:
            return finding["fingerprint"]

        # Generate fingerprint
        finding_data = FindingData(
            id=finding.get("id", ""),
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            description=finding.get("description", ""),
            module=finding.get("module", ""),
            category=finding.get("category", ""),
            evidence=finding.get("evidence", {}),
            cve_ids=finding.get("cve_ids", []),
        )
        return finding_data.fingerprint

    def compare(
        self,
        baseline: Dict[str, Any],
        current: Dict[str, Any],
    ) -> ComparisonResult:
        """
        Compare two scan results.

        Args:
            baseline: Previous/baseline scan data
            current: Current scan data

        Returns:
            ComparisonResult with categorized findings
        """
        # Convert to FindingData
        baseline_findings = self._normalize_findings(baseline.get("findings", []))
        current_findings = self._normalize_findings(current.get("findings", []))

        # Build fingerprint maps
        baseline_by_fp = {f.fingerprint: f for f in baseline_findings}
        current_by_fp = {f.fingerprint: f for f in current_findings}

        result = ComparisonResult(
            baseline_scan_id=baseline.get("scan_id", "unknown"),
            current_scan_id=current.get("scan_id", "unknown"),
            baseline_date=self._parse_date(baseline.get("started_at")),
            current_date=self._parse_date(current.get("started_at")),
            target=current.get("target", baseline.get("target", "")),
        )

        # Track processed fingerprints
        processed_baseline: Set[str] = set()
        processed_current: Set[str] = set()

        # Match findings by fingerprint
        if self.use_fingerprint:
            for fp, current_finding in current_by_fp.items():
                if fp in baseline_by_fp:
                    # Finding exists in both
                    baseline_finding = baseline_by_fp[fp]
                    processed_baseline.add(fp)
                    processed_current.add(fp)

                    changes = self._detect_changes(baseline_finding, current_finding)
                    if changes:
                        diff = FindingDiff(
                            diff_type=DiffType.MODIFIED,
                            finding=current_finding,
                            previous_finding=baseline_finding,
                            changes=changes,
                        )
                        result.modified_findings.append(diff)
                    else:
                        diff = FindingDiff(
                            diff_type=DiffType.UNCHANGED,
                            finding=current_finding,
                            previous_finding=baseline_finding,
                        )
                        result.unchanged_findings.append(diff)
                else:
                    # New finding
                    processed_current.add(fp)

                    # Check if it's a regression
                    if self.track_regressions and fp in self.historical_fingerprints:
                        diff = FindingDiff(
                            diff_type=DiffType.REGRESSION,
                            finding=current_finding,
                        )
                        result.regression_findings.append(diff)
                    else:
                        diff = FindingDiff(
                            diff_type=DiffType.NEW,
                            finding=current_finding,
                        )
                        result.new_findings.append(diff)

            # Find resolved findings
            for fp, baseline_finding in baseline_by_fp.items():
                if fp not in processed_baseline:
                    diff = FindingDiff(
                        diff_type=DiffType.RESOLVED,
                        finding=baseline_finding,
                    )
                    result.resolved_findings.append(diff)

        logger.info(
            f"Comparison complete: {len(result.new_findings)} new, "
            f"{len(result.resolved_findings)} resolved, "
            f"{len(result.unchanged_findings)} unchanged, "
            f"{len(result.modified_findings)} modified, "
            f"{len(result.regression_findings)} regressions"
        )

        return result

    def _normalize_findings(self, findings: List[Dict[str, Any]]) -> List[FindingData]:
        """Normalize findings to FindingData objects."""
        normalized = []
        for f in findings:
            finding = FindingData(
                id=str(f.get("id", "")),
                title=f.get("title", ""),
                severity=f.get("severity", "unknown"),
                description=f.get("description", ""),
                module=f.get("module", ""),
                category=f.get("category", ""),
                evidence=f.get("evidence", {}),
                cvss_score=f.get("cvss_score"),
                cve_ids=f.get("cve_ids", []),
                status=f.get("status", "open"),
                fingerprint=f.get("fingerprint", ""),
            )
            normalized.append(finding)
        return normalized

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

    def _detect_changes(
        self, baseline: FindingData, current: FindingData
    ) -> Dict[str, Tuple[Any, Any]]:
        """Detect changes between two findings."""
        changes = {}

        if baseline.severity != current.severity:
            changes["severity"] = (baseline.severity, current.severity)

        if baseline.status != current.status:
            changes["status"] = (baseline.status, current.status)

        if baseline.cvss_score != current.cvss_score:
            changes["cvss_score"] = (baseline.cvss_score, current.cvss_score)

        if baseline.description != current.description:
            changes["description"] = ("changed", "changed")

        if set(baseline.cve_ids) != set(current.cve_ids):
            changes["cve_ids"] = (baseline.cve_ids, current.cve_ids)

        return changes

    def generate_summary(self, result: ComparisonResult) -> str:
        """Generate a text summary of comparison results."""
        lines = [
            f"Scan Comparison Summary",
            f"=" * 50,
            f"Target: {result.target}",
            f"Baseline: {result.baseline_scan_id} ({result.baseline_date.strftime('%Y-%m-%d')})",
            f"Current:  {result.current_scan_id} ({result.current_date.strftime('%Y-%m-%d')})",
            "",
            f"Findings Overview:",
            f"  Baseline total: {result.total_baseline}",
            f"  Current total:  {result.total_current}",
            "",
            f"Changes:",
            f"  New findings:      {len(result.new_findings):3d}",
            f"  Resolved:          {len(result.resolved_findings):3d}",
            f"  Unchanged:         {len(result.unchanged_findings):3d}",
            f"  Modified:          {len(result.modified_findings):3d}",
            f"  Regressions:       {len(result.regression_findings):3d}",
            "",
            f"Metrics:",
            f"  Remediation rate:  {result.remediation_rate:.1f}%",
            f"  New finding rate:  {result.new_finding_rate:.1f}%",
        ]

        # Severity breakdown for new findings
        if result.new_findings:
            new_severity = result.severity_summary(DiffType.NEW)
            lines.extend(
                [
                    "",
                    "New Findings by Severity:",
                    f"  Critical: {new_severity['critical']}",
                    f"  High:     {new_severity['high']}",
                    f"  Medium:   {new_severity['medium']}",
                    f"  Low:      {new_severity['low']}",
                    f"  Info:     {new_severity['info']}",
                ]
            )

        return "\n".join(lines)
