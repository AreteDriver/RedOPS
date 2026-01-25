"""
Scan History - SQLite-based persistence for scan results.

Stores scan history, findings, and metadata for later retrieval and analysis.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from contextlib import contextmanager


@dataclass
class ScanRecord:
    """A stored scan record."""

    id: Optional[int] = None
    target: str = ""
    preset: str = "quick"
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    modules_run: List[str] = field(default_factory=list)
    findings_count: int = 0
    risk_score: Optional[float] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "target": self.target,
            "preset": self.preset,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "modules_run": self.modules_run,
            "findings_count": self.findings_count,
            "risk_score": self.risk_score,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass
class FindingRecord:
    """A stored finding record."""

    id: Optional[int] = None
    scan_id: int = 0
    module: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    title: str = ""
    description: str = ""
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


class ScanHistoryDB:
    """SQLite-based scan history storage."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        preset TEXT DEFAULT 'quick',
        status TEXT DEFAULT 'pending',
        started_at TEXT,
        completed_at TEXT,
        duration_seconds REAL DEFAULT 0,
        modules_run TEXT,
        findings_count INTEGER DEFAULT 0,
        risk_score REAL,
        error TEXT,
        metadata TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        module TEXT NOT NULL,
        severity TEXT DEFAULT 'info',
        title TEXT NOT NULL,
        description TEXT,
        evidence TEXT,
        remediation TEXT,
        metadata TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scan_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        key TEXT NOT NULL,
        value TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        UNIQUE(scan_id, key)
    );

    CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
    CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
    CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_scan_data_scan ON scan_data(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_data_key ON scan_data(key);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize scan history database.

        Args:
            db_path: Path to SQLite database file.
                     Defaults to ~/.config/redops/history.db
        """
        if db_path is None:
            db_dir = Path.home() / ".config" / "redops"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "history.db")

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript(self.SCHEMA)

    @contextmanager
    def _get_connection(self):
        """Get database connection with context management."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # Scan operations

    def create_scan(self, target: str, preset: str = "quick", metadata: Dict[str, Any] = None) -> int:
        """
        Create a new scan record.

        Args:
            target: Scan target
            preset: Scan preset name
            metadata: Optional metadata

        Returns:
            Scan ID
        """
        started_at = datetime.now().isoformat()
        metadata_json = json.dumps(metadata or {})

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (target, preset, status, started_at, metadata)
                VALUES (?, ?, 'running', ?, ?)
                """,
                (target, preset, started_at, metadata_json),
            )
            return cursor.lastrowid

    def update_scan(
        self,
        scan_id: int,
        status: str = None,
        modules_run: List[str] = None,
        findings_count: int = None,
        risk_score: float = None,
        error: str = None,
        duration_seconds: float = None,
    ):
        """
        Update a scan record.

        Args:
            scan_id: Scan ID to update
            status: New status
            modules_run: List of modules that ran
            findings_count: Total findings count
            risk_score: Risk score
            error: Error message if failed
            duration_seconds: Scan duration
        """
        updates = []
        params = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)
            if status in ("completed", "failed"):
                updates.append("completed_at = ?")
                params.append(datetime.now().isoformat())

        if modules_run is not None:
            updates.append("modules_run = ?")
            params.append(json.dumps(modules_run))

        if findings_count is not None:
            updates.append("findings_count = ?")
            params.append(findings_count)

        if risk_score is not None:
            updates.append("risk_score = ?")
            params.append(risk_score)

        if error is not None:
            updates.append("error = ?")
            params.append(error)

        if duration_seconds is not None:
            updates.append("duration_seconds = ?")
            params.append(duration_seconds)

        if not updates:
            return

        params.append(scan_id)
        query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"

        with self._get_connection() as conn:
            conn.execute(query, params)

    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        """
        Get a scan by ID.

        Args:
            scan_id: Scan ID

        Returns:
            ScanRecord or None
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()

        if not row:
            return None

        return self._row_to_scan(row)

    def list_scans(
        self,
        target: str = None,
        status: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ScanRecord]:
        """
        List scans with optional filtering.

        Args:
            target: Filter by target (substring match)
            status: Filter by status
            limit: Maximum results
            offset: Result offset

        Returns:
            List of ScanRecord
        """
        conditions = []
        params = []

        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")

        if status:
            conditions.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            SELECT * FROM scans
            {where}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_scan(row) for row in rows]

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and all associated data.

        Args:
            scan_id: Scan ID

        Returns:
            True if deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0

    def _row_to_scan(self, row: sqlite3.Row) -> ScanRecord:
        """Convert database row to ScanRecord."""
        return ScanRecord(
            id=row["id"],
            target=row["target"],
            preset=row["preset"],
            status=row["status"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            duration_seconds=row["duration_seconds"] or 0,
            modules_run=json.loads(row["modules_run"]) if row["modules_run"] else [],
            findings_count=row["findings_count"] or 0,
            risk_score=row["risk_score"],
            error=row["error"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    # Finding operations

    def add_finding(
        self,
        scan_id: int,
        module: str,
        severity: str,
        title: str,
        description: str = "",
        evidence: str = None,
        remediation: str = None,
        metadata: Dict[str, Any] = None,
    ) -> int:
        """
        Add a finding to a scan.

        Args:
            scan_id: Scan ID
            module: Module that generated the finding
            severity: Severity level
            title: Finding title
            description: Finding description
            evidence: Supporting evidence
            remediation: Remediation guidance
            metadata: Additional metadata

        Returns:
            Finding ID
        """
        metadata_json = json.dumps(metadata or {})

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings
                (scan_id, module, severity, title, description, evidence, remediation, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, module, severity, title, description, evidence, remediation, metadata_json),
            )
            return cursor.lastrowid

    def get_findings(
        self,
        scan_id: int,
        severity: str = None,
        module: str = None,
    ) -> List[FindingRecord]:
        """
        Get findings for a scan.

        Args:
            scan_id: Scan ID
            severity: Filter by severity
            module: Filter by module

        Returns:
            List of FindingRecord
        """
        conditions = ["scan_id = ?"]
        params = [scan_id]

        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        if module:
            conditions.append("module = ?")
            params.append(module)

        query = f"""
            SELECT * FROM findings
            WHERE {' AND '.join(conditions)}
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                created_at DESC
        """

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_finding(row) for row in rows]

    def _row_to_finding(self, row: sqlite3.Row) -> FindingRecord:
        """Convert database row to FindingRecord."""
        return FindingRecord(
            id=row["id"],
            scan_id=row["scan_id"],
            module=row["module"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            evidence=row["evidence"],
            remediation=row["remediation"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
        )

    # Scan data operations (for storing context data)

    def store_scan_data(self, scan_id: int, key: str, value: Any):
        """
        Store arbitrary scan data.

        Args:
            scan_id: Scan ID
            key: Data key
            value: Data value (will be JSON serialized)
        """
        value_json = json.dumps(value, default=str)

        with self._get_connection() as conn:
            # Upsert - replace if exists
            conn.execute(
                """
                INSERT INTO scan_data (scan_id, key, value)
                VALUES (?, ?, ?)
                ON CONFLICT(scan_id, key) DO UPDATE SET value = excluded.value
                """,
                (scan_id, key, value_json),
            )

    def get_scan_data(self, scan_id: int, key: str = None) -> Dict[str, Any]:
        """
        Get scan data.

        Args:
            scan_id: Scan ID
            key: Optional specific key (returns all if None)

        Returns:
            Dictionary of scan data
        """
        with self._get_connection() as conn:
            if key:
                row = conn.execute(
                    "SELECT value FROM scan_data WHERE scan_id = ? AND key = ?",
                    (scan_id, key),
                ).fetchone()
                if row:
                    return {key: json.loads(row["value"])}
                return {}
            else:
                rows = conn.execute(
                    "SELECT key, value FROM scan_data WHERE scan_id = ?",
                    (scan_id,),
                ).fetchall()
                return {row["key"]: json.loads(row["value"]) for row in rows}

    # Statistics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get history statistics.

        Returns:
            Statistics dictionary
        """
        with self._get_connection() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            completed_scans = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE status = 'completed'"
            ).fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

            severity_counts = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
            ):
                severity_counts[row["severity"]] = row["count"]

            recent_targets = [
                row["target"]
                for row in conn.execute(
                    "SELECT DISTINCT target FROM scans ORDER BY created_at DESC LIMIT 10"
                )
            ]

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": total_scans - completed_scans,
            "total_findings": total_findings,
            "findings_by_severity": severity_counts,
            "recent_targets": recent_targets,
        }

    def cleanup_old(self, days: int = 30) -> int:
        """
        Remove scans older than specified days.

        Args:
            days: Age threshold in days

        Returns:
            Number of deleted scans
        """
        threshold = datetime.now().isoformat()[:10]  # Current date

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM scans
                WHERE date(created_at) < date(?, '-' || ? || ' days')
                """,
                (threshold, days),
            )
            return cursor.rowcount


# Convenience function for getting global instance
_default_db: Optional[ScanHistoryDB] = None


def get_history_db(db_path: str = None) -> ScanHistoryDB:
    """Get the default history database instance."""
    global _default_db
    if _default_db is None or db_path is not None:
        _default_db = ScanHistoryDB(db_path)
    return _default_db
