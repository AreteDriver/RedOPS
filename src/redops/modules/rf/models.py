"""
SQLite models and schema for RF operations.

Lightweight dataclass models backed by a dedicated RF SQLite
database at ~/operator/operator.db.  No ORM — raw SQL via the
stdlib sqlite3 module.
"""

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / "operator" / "operator.db"

# ---------------------------------------------------------------------------
# Enums as string literals (kept simple, no Enum class needed)
# ---------------------------------------------------------------------------

SESSION_STATUSES = (
    "created",
    "active",
    "finalizing",
    "closed",
    "archived",
)

INTERFACE_MODES = ("managed", "monitor")

CAPTURE_TYPES = (
    "handshake",
    "pmkid",
    "pcap",
    "deauth_log",
)

FINDING_TYPES = (
    "vuln",
    "intel",
    "anomaly",
    "note",
)

TOOL_RUN_STATUSES = ("running", "done", "error")

# ---------------------------------------------------------------------------
# Dataclass models
# ---------------------------------------------------------------------------


@dataclass
class RFSession:
    """A top-level RF engagement session."""

    id: int | None = None
    name: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ended_at: str | None = None
    status: str = "created"
    notes: str = ""
    base_path: str = ""


@dataclass
class WirelessInterface:
    """A wireless NIC enrolled in a session."""

    id: int | None = None
    name: str = ""
    mac_real: str = ""
    mac_spoofed: str | None = None
    mode: str = "managed"
    channel: int | None = None
    chipset: str = ""
    session_id: int | None = None


@dataclass
class Target:
    """A wireless access point or network of interest."""

    id: int | None = None
    session_id: int | None = None
    bssid: str = ""
    essid: str = ""
    channel: int | None = None
    encryption: str = ""
    signal_dbm: int | None = None
    wps_enabled: bool = False
    vendor: str = ""
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    client_count: int = 0
    tags: list[str] = field(default_factory=list)
    ai_notes: str = ""
    status: str = ""
    priority: int = 0


@dataclass
class Client:
    """A wireless client station associated with a target."""

    id: int | None = None
    mac: str = ""
    target_id: int | None = None
    signal: int | None = None
    probes: list[str] = field(default_factory=list)
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data_frames: int = 0


@dataclass
class Capture:
    """A packet capture or credential artifact."""

    id: int | None = None
    target_id: int | None = None
    session_id: int | None = None
    capture_type: str = ""
    file_path: str = ""
    file_hash: str = ""
    tool: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    size_bytes: int = 0
    notes: str = ""
    converted: bool = False


@dataclass
class RFFinding:
    """An intelligence or vulnerability finding."""

    id: int | None = None
    target_id: int | None = None
    session_id: int | None = None
    finding_type: str = ""
    severity: str = ""
    title: str = ""
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    ai_analysis: str = ""
    source_tool: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    verified: bool = False


@dataclass
class ToolRun:
    """A tracked invocation of an external tool."""

    id: int | None = None
    session_id: int | None = None
    tool: str = ""
    command: str = ""
    pid: int | None = None
    status: str = "running"
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ended_at: str | None = None
    exit_code: int | None = None
    log_path: str = ""


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS rf_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    started_at  TEXT    NOT NULL,
    ended_at    TEXT,
    status      TEXT    NOT NULL DEFAULT 'created',
    notes       TEXT    NOT NULL DEFAULT '',
    base_path   TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS wireless_interfaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    mac_real    TEXT    NOT NULL,
    mac_spoofed TEXT,
    mode        TEXT    NOT NULL DEFAULT 'managed',
    channel     INTEGER,
    chipset     TEXT    NOT NULL DEFAULT '',
    session_id  INTEGER REFERENCES rf_sessions(id)
);

CREATE TABLE IF NOT EXISTS targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER REFERENCES rf_sessions(id),
    bssid         TEXT    NOT NULL,
    essid         TEXT    NOT NULL DEFAULT '',
    channel       INTEGER,
    encryption    TEXT    NOT NULL DEFAULT '',
    signal_dbm    INTEGER,
    wps_enabled   INTEGER NOT NULL DEFAULT 0,
    vendor        TEXT    NOT NULL DEFAULT '',
    first_seen    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    client_count  INTEGER NOT NULL DEFAULT 0,
    tags          TEXT    NOT NULL DEFAULT '[]',
    ai_notes      TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT '',
    priority      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac         TEXT    NOT NULL,
    target_id   INTEGER REFERENCES targets(id),
    signal      INTEGER,
    probes      TEXT    NOT NULL DEFAULT '[]',
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    data_frames INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS captures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER REFERENCES targets(id),
    session_id    INTEGER REFERENCES rf_sessions(id),
    capture_type  TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    file_hash     TEXT    NOT NULL DEFAULT '',
    tool          TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL DEFAULT 0,
    notes         TEXT    NOT NULL DEFAULT '',
    converted     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rf_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER REFERENCES targets(id),
    session_id    INTEGER REFERENCES rf_sessions(id),
    finding_type  TEXT    NOT NULL,
    severity      TEXT    NOT NULL DEFAULT '',
    title         TEXT    NOT NULL DEFAULT '',
    detail        TEXT    NOT NULL DEFAULT '',
    evidence      TEXT    NOT NULL DEFAULT '{}',
    ai_analysis   TEXT    NOT NULL DEFAULT '',
    source_tool   TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES rf_sessions(id),
    tool        TEXT    NOT NULL,
    command     TEXT    NOT NULL DEFAULT '',
    pid         INTEGER,
    status      TEXT    NOT NULL DEFAULT 'running',
    started_at  TEXT    NOT NULL,
    ended_at    TEXT,
    exit_code   INTEGER,
    log_path    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_targets_session
    ON targets(session_id);
CREATE INDEX IF NOT EXISTS idx_targets_bssid
    ON targets(bssid);
CREATE INDEX IF NOT EXISTS idx_clients_target
    ON clients(target_id);
CREATE INDEX IF NOT EXISTS idx_captures_session
    ON captures(session_id);
CREATE INDEX IF NOT EXISTS idx_captures_target
    ON captures(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_session
    ON rf_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_target
    ON rf_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_session
    ON tool_runs(session_id);
"""


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def init_db(db_path: Path | None = None) -> sqlite3.Connection:
    """Create all RF tables and return an open connection.

    Args:
        db_path: Path to the SQLite database file.
            Defaults to ~/operator/operator.db.

    Returns:
        An open ``sqlite3.Connection`` with WAL mode and
        foreign keys enabled.
    """
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Initializing RF database at %s", path)

    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA_SQL)
    conn.commit()
    logger.info("RF database ready (%d tables)", 7)
    return conn


# ---------------------------------------------------------------------------
# Row ↔ dataclass helpers
# ---------------------------------------------------------------------------


def _json_dumps(obj: Any) -> str:
    """Serialize a Python object to a JSON string."""
    return json.dumps(obj, default=str)


def _json_loads(raw: str | None) -> Any:
    """Deserialize a JSON string, returning an empty
    container on failure."""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def insert_session(
    conn: sqlite3.Connection,
    session: RFSession,
) -> int:
    """Insert a new RF session and return its id.

    Args:
        conn: Open database connection.
        session: The session to persist.

    Returns:
        The auto-generated row id.
    """
    cur = conn.execute(
        "INSERT INTO rf_sessions "
        "(name, started_at, ended_at, status, notes, base_path) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            session.name,
            session.started_at,
            session.ended_at,
            session.status,
            session.notes,
            session.base_path,
        ),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def insert_target(
    conn: sqlite3.Connection,
    target: Target,
) -> int:
    """Insert a target and return its id.

    Args:
        conn: Open database connection.
        target: The target to persist.

    Returns:
        The auto-generated row id.
    """
    cur = conn.execute(
        "INSERT INTO targets "
        "(session_id, bssid, essid, channel, encryption, "
        "signal_dbm, wps_enabled, vendor, first_seen, "
        "last_seen, client_count, tags, ai_notes, status, "
        "priority) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            target.session_id,
            target.bssid,
            target.essid,
            target.channel,
            target.encryption,
            target.signal_dbm,
            int(target.wps_enabled),
            target.vendor,
            target.first_seen,
            target.last_seen,
            target.client_count,
            _json_dumps(target.tags),
            target.ai_notes,
            target.status,
            target.priority,
        ),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def insert_client(
    conn: sqlite3.Connection,
    client: Client,
) -> int:
    """Insert a client and return its id.

    Args:
        conn: Open database connection.
        client: The client to persist.

    Returns:
        The auto-generated row id.
    """
    cur = conn.execute(
        "INSERT INTO clients "
        "(mac, target_id, signal, probes, first_seen, "
        "last_seen, data_frames) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            client.mac,
            client.target_id,
            client.signal,
            _json_dumps(client.probes),
            client.first_seen,
            client.last_seen,
            client.data_frames,
        ),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def insert_capture(
    conn: sqlite3.Connection,
    capture: Capture,
) -> int:
    """Insert a capture record and return its id.

    Args:
        conn: Open database connection.
        capture: The capture to persist.

    Returns:
        The auto-generated row id.
    """
    cur = conn.execute(
        "INSERT INTO captures "
        "(target_id, session_id, capture_type, file_path, "
        "file_hash, tool, created_at, size_bytes, notes, "
        "converted) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            capture.target_id,
            capture.session_id,
            capture.capture_type,
            capture.file_path,
            capture.file_hash,
            capture.tool,
            capture.created_at,
            capture.size_bytes,
            capture.notes,
            int(capture.converted),
        ),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def insert_finding(
    conn: sqlite3.Connection,
    finding: RFFinding,
) -> int:
    """Insert an RF finding and return its id.

    Args:
        conn: Open database connection.
        finding: The finding to persist.

    Returns:
        The auto-generated row id.
    """
    cur = conn.execute(
        "INSERT INTO rf_findings "
        "(target_id, session_id, finding_type, severity, "
        "title, detail, evidence, ai_analysis, source_tool, "
        "created_at, verified) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            finding.target_id,
            finding.session_id,
            finding.finding_type,
            finding.severity,
            finding.title,
            finding.detail,
            _json_dumps(finding.evidence),
            finding.ai_analysis,
            finding.source_tool,
            finding.created_at,
            int(finding.verified),
        ),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def insert_tool_run(
    conn: sqlite3.Connection,
    tool_run: ToolRun,
) -> int:
    """Insert a tool run record and return its id.

    Args:
        conn: Open database connection.
        tool_run: The tool run to persist.

    Returns:
        The auto-generated row id.
    """
    cur = conn.execute(
        "INSERT INTO tool_runs "
        "(session_id, tool, command, pid, status, "
        "started_at, ended_at, exit_code, log_path) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (
            tool_run.session_id,
            tool_run.tool,
            tool_run.command,
            tool_run.pid,
            tool_run.status,
            tool_run.started_at,
            tool_run.ended_at,
            tool_run.exit_code,
            tool_run.log_path,
        ),
    )
    conn.commit()
    return cur.lastrowid  # type: ignore[return-value]


def get_session(
    conn: sqlite3.Connection,
    session_id: int,
) -> RFSession | None:
    """Fetch a single session by id.

    Args:
        conn: Open database connection.
        session_id: The session row id.

    Returns:
        An ``RFSession`` or ``None`` if not found.
    """
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM rf_sessions WHERE id = ?",
        (session_id,),
    ).fetchone()
    if row is None:
        return None
    return RFSession(
        id=row["id"],
        name=row["name"],
        started_at=row["started_at"],
        ended_at=row["ended_at"],
        status=row["status"],
        notes=row["notes"],
        base_path=row["base_path"],
    )


def get_targets_for_session(
    conn: sqlite3.Connection,
    session_id: int,
) -> list[Target]:
    """Fetch all targets belonging to a session.

    Args:
        conn: Open database connection.
        session_id: The parent session id.

    Returns:
        List of ``Target`` instances.
    """
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM targets WHERE session_id = ? "
        "ORDER BY priority DESC, last_seen DESC",
        (session_id,),
    ).fetchall()
    results: list[Target] = []
    for row in rows:
        results.append(
            Target(
                id=row["id"],
                session_id=row["session_id"],
                bssid=row["bssid"],
                essid=row["essid"],
                channel=row["channel"],
                encryption=row["encryption"],
                signal_dbm=row["signal_dbm"],
                wps_enabled=bool(row["wps_enabled"]),
                vendor=row["vendor"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                client_count=row["client_count"],
                tags=_json_loads(row["tags"]),
                ai_notes=row["ai_notes"],
                status=row["status"],
                priority=row["priority"],
            )
        )
    return results


def update_tool_run_status(
    conn: sqlite3.Connection,
    tool_run_id: int,
    status: str,
    exit_code: int | None = None,
    ended_at: str | None = None,
) -> None:
    """Update a tool run's completion status.

    Args:
        conn: Open database connection.
        tool_run_id: The tool run row id.
        status: New status value.
        exit_code: Process exit code if finished.
        ended_at: ISO timestamp of completion.
    """
    if ended_at is None:
        ended_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE tool_runs SET status=?, exit_code=?, ended_at=? WHERE id=?",
        (status, exit_code, ended_at, tool_run_id),
    )
    conn.commit()
