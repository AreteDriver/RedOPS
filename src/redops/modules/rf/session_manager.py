"""RF operator session manager with evidence chain tracking.

Manages RF operation sessions including directory structure creation,
SQLite-backed metadata storage, capture file hashing, and session
lifecycle management (CREATED -> ACTIVE -> FINALIZING -> CLOSED -> ARCHIVED).
"""

import hashlib
import json
import logging
import sqlite3
import tarfile
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

_DB_NAME = "sessions.db"
_HASH_CHUNK_SIZE = 8192  # 8KB chunks for file hashing


class SessionStatus(str, Enum):
    """Session lifecycle states."""

    CREATED = "created"
    ACTIVE = "active"
    FINALIZING = "finalizing"
    CLOSED = "closed"
    ARCHIVED = "archived"


@dataclass
class Capture:
    """Record of a captured evidence file.

    Attributes:
        capture_id: Unique identifier for this capture.
        session_id: Parent session identifier.
        target_id: Identifier of the target (e.g., BSSID).
        capture_type: Type of capture (e.g., 'pmkid', 'handshake', 'pcap').
        file_path: Absolute path to the capture file.
        tool: Tool that produced this capture.
        sha256: SHA-256 hash of the capture file.
        timestamp: When the capture was recorded.
    """

    capture_id: str
    session_id: str
    target_id: str
    capture_type: str
    file_path: str
    tool: str
    sha256: str
    timestamp: str


@dataclass
class RFSession:
    """RF operator session metadata.

    Attributes:
        session_id: Unique session identifier.
        name: Human-readable session name.
        status: Current lifecycle status.
        notes: Operator notes for this session.
        session_dir: Path to the session directory.
        created_at: ISO-format creation timestamp.
        started_at: ISO-format start timestamp, if started.
        ended_at: ISO-format end timestamp, if ended.
        captures: List of capture records in this session.
    """

    session_id: str
    name: str
    status: SessionStatus
    notes: str
    session_dir: str
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    captures: list[Capture] = field(default_factory=list)


def _compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file using chunked reads.

    Args:
        file_path: Path to the file to hash.

    Returns:
        Hex-encoded SHA-256 digest string.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _now_iso() -> str:
    """Return current UTC time as ISO-format string."""
    return datetime.now(timezone.utc).isoformat()


class SessionManager:
    """Manages RF operator sessions and evidence chain.

    Creates and tracks operator sessions with directory structures,
    SQLite metadata, and SHA-256 hashed evidence files.

    Attributes:
        base_dir: Root directory for all session data.
        db_path: Path to the SQLite database.
    """

    _SESSION_SUBDIRS = ("pcap", "hashes", "logs", "reports", "evidence")

    def __init__(
        self,
        base_dir: Path = Path.home() / "operator",
    ) -> None:
        """Initialize the session manager.

        Creates the base directory structure and initializes
        the SQLite database if they do not already exist.

        Args:
            base_dir: Root directory for operator data.
                Defaults to ~/operator.
        """
        self.base_dir = Path(base_dir)
        self.db_path = self.base_dir / _DB_NAME

        self.base_dir.mkdir(parents=True, exist_ok=True)
        (self.base_dir / "sessions").mkdir(exist_ok=True)

        self._init_db()
        logger.info("SessionManager initialized at %s", self.base_dir)

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    notes TEXT DEFAULT '',
                    session_dir TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    ended_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS captures (
                    capture_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    capture_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id)
                        REFERENCES sessions(session_id)
                )
            """)
            conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a database connection with row factory.

        Returns:
            SQLite connection with Row factory enabled.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def create_session(
        self,
        name: str,
        notes: str = "",
    ) -> RFSession:
        """Create a new RF operator session.

        Creates the session directory structure, writes initial
        session.json metadata, and inserts a record into SQLite.

        Args:
            name: Human-readable session name. Used as the
                directory name (sanitized).
            notes: Optional operator notes.

        Returns:
            The newly created RFSession.

        Raises:
            ValueError: If name is empty.
            FileExistsError: If session directory already exists.
        """
        if not name or not name.strip():
            raise ValueError("Session name must not be empty")

        session_id = str(uuid.uuid4())
        safe_name = name.strip().replace(" ", "_").replace("/", "_")
        session_dir = self.base_dir / "sessions" / safe_name

        if session_dir.exists():
            raise FileExistsError(f"Session directory already exists: {session_dir}")

        # Create directory structure
        session_dir.mkdir(parents=True)
        for subdir in self._SESSION_SUBDIRS:
            (session_dir / subdir).mkdir()

        now = _now_iso()

        session = RFSession(
            session_id=session_id,
            name=name.strip(),
            status=SessionStatus.CREATED,
            notes=notes,
            session_dir=str(session_dir),
            created_at=now,
        )

        # Write session.json
        self._write_session_json(session)

        # Insert into SQLite
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO sessions
                    (session_id, name, status, notes,
                     session_dir, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.name,
                    session.status.value,
                    session.notes,
                    session.session_dir,
                    session.created_at,
                ),
            )
            conn.commit()

        logger.info(
            "Created session '%s' (%s) at %s",
            name,
            session_id,
            session_dir,
        )
        return session

    def start_session(self, session_id: str) -> None:
        """Set a session status to active.

        Args:
            session_id: The session to start.

        Raises:
            ValueError: If session not found or not in CREATED state.
        """
        session = self.get_session(session_id)
        if session.status != SessionStatus.CREATED:
            raise ValueError(
                f"Cannot start session in '{session.status.value}' "
                f"state (must be '{SessionStatus.CREATED.value}')"
            )

        now = _now_iso()
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET status = ?, started_at = ?
                WHERE session_id = ?
                """,
                (SessionStatus.ACTIVE.value, now, session_id),
            )
            conn.commit()

        session.status = SessionStatus.ACTIVE
        session.started_at = now
        self._write_session_json(session)

        logger.info("Started session %s", session_id)

    def end_session(self, session_id: str) -> None:
        """Finalize and close a session.

        Transitions through FINALIZING state, computes SHA-256
        hashes for all evidence files, writes final session.json,
        and sets status to CLOSED.

        Args:
            session_id: The session to end.

        Raises:
            ValueError: If session not found or not in ACTIVE state.
        """
        session = self.get_session(session_id)
        if session.status != SessionStatus.ACTIVE:
            raise ValueError(
                f"Cannot end session in '{session.status.value}' "
                f"state (must be '{SessionStatus.ACTIVE.value}')"
            )

        # Transition to FINALIZING
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE sessions SET status = ? WHERE session_id = ?",
                (SessionStatus.FINALIZING.value, session_id),
            )
            conn.commit()

        session_dir = Path(session.session_dir)

        # Compute hashes for all evidence files
        evidence_hashes: dict[str, str] = {}
        evidence_dirs = [
            session_dir / d for d in self._SESSION_SUBDIRS if (session_dir / d).exists()
        ]
        for evidence_dir in evidence_dirs:
            for file_path in evidence_dir.rglob("*"):
                if file_path.is_file():
                    file_hash = _compute_sha256(file_path)
                    rel_path = str(file_path.relative_to(session_dir))
                    evidence_hashes[rel_path] = file_hash

        # Write hash manifest
        hashes_file = session_dir / "hashes" / "manifest.json"
        hashes_file.write_text(
            json.dumps(evidence_hashes, indent=2),
            encoding="utf-8",
        )

        # Finalize session
        now = _now_iso()
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE sessions
                SET status = ?, ended_at = ?
                WHERE session_id = ?
                """,
                (SessionStatus.CLOSED.value, now, session_id),
            )
            conn.commit()

        session.status = SessionStatus.CLOSED
        session.ended_at = now
        self._write_session_json(session)

        logger.info(
            "Ended session %s — %d evidence files hashed",
            session_id,
            len(evidence_hashes),
        )

    def get_session(self, session_id: str) -> RFSession:
        """Retrieve a session by ID.

        Args:
            session_id: The session identifier.

        Returns:
            The matching RFSession with captures populated.

        Raises:
            ValueError: If no session with the given ID exists.
        """
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()

            if row is None:
                raise ValueError(f"Session not found: {session_id}")

            captures = self._get_captures(conn, session_id)

        return RFSession(
            session_id=row["session_id"],
            name=row["name"],
            status=SessionStatus(row["status"]),
            notes=row["notes"],
            session_dir=row["session_dir"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            captures=captures,
        )

    def list_sessions(self) -> list[RFSession]:
        """List all sessions.

        Returns:
            List of all RFSession records, ordered by creation
            time descending.
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC"
            ).fetchall()

            sessions: list[RFSession] = []
            for row in rows:
                captures = self._get_captures(conn, row["session_id"])
                sessions.append(
                    RFSession(
                        session_id=row["session_id"],
                        name=row["name"],
                        status=SessionStatus(row["status"]),
                        notes=row["notes"],
                        session_dir=row["session_dir"],
                        created_at=row["created_at"],
                        started_at=row["started_at"],
                        ended_at=row["ended_at"],
                        captures=captures,
                    )
                )

        return sessions

    def add_capture(
        self,
        session_id: str,
        target_id: str,
        capture_type: str,
        file_path: Path,
        tool: str,
    ) -> Capture:
        """Record a capture file in the session evidence chain.

        Computes the SHA-256 hash of the file and stores the
        capture record in SQLite.

        Args:
            session_id: Parent session identifier.
            target_id: Target identifier (e.g., BSSID, ESSID).
            capture_type: Type of capture ('pmkid', 'handshake',
                'pcap', 'deauth', etc.).
            file_path: Path to the capture file.
            tool: Name of the tool that produced the capture.

        Returns:
            The newly created Capture record.

        Raises:
            ValueError: If session not found or not active.
            FileNotFoundError: If the capture file does not exist.
        """
        session = self.get_session(session_id)
        if session.status != SessionStatus.ACTIVE:
            raise ValueError(
                f"Cannot add captures to session in '{session.status.value}' state"
            )

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Capture file not found: {file_path}")

        capture_id = str(uuid.uuid4())
        sha256 = _compute_sha256(file_path)
        now = _now_iso()

        capture = Capture(
            capture_id=capture_id,
            session_id=session_id,
            target_id=target_id,
            capture_type=capture_type,
            file_path=str(file_path),
            tool=tool,
            sha256=sha256,
            timestamp=now,
        )

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO captures
                    (capture_id, session_id, target_id,
                     capture_type, file_path, tool,
                     sha256, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    capture.capture_id,
                    capture.session_id,
                    capture.target_id,
                    capture.capture_type,
                    capture.file_path,
                    capture.tool,
                    capture.sha256,
                    capture.timestamp,
                ),
            )
            conn.commit()

        logger.info(
            "Added %s capture from %s for target %s (SHA256: %.16s...)",
            capture_type,
            tool,
            target_id,
            sha256,
        )

        return capture

    def archive_session(self, session_id: str) -> Path:
        """Archive a closed session as a tar.gz file.

        Compresses the session directory into a tar.gz archive
        in the base sessions directory, then sets the session
        status to ARCHIVED.

        Args:
            session_id: The session to archive.

        Returns:
            Path to the created archive file.

        Raises:
            ValueError: If session not found or not in CLOSED state.
        """
        session = self.get_session(session_id)
        if session.status != SessionStatus.CLOSED:
            raise ValueError(
                f"Cannot archive session in "
                f"'{session.status.value}' state "
                f"(must be '{SessionStatus.CLOSED.value}')"
            )

        session_dir = Path(session.session_dir)
        archive_name = f"{session_dir.name}.tar.gz"
        archive_path = self.base_dir / "sessions" / archive_name

        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(session_dir, arcname=session_dir.name)

        with self._get_conn() as conn:
            conn.execute(
                "UPDATE sessions SET status = ? WHERE session_id = ?",
                (SessionStatus.ARCHIVED.value, session_id),
            )
            conn.commit()

        logger.info(
            "Archived session %s to %s",
            session_id,
            archive_path,
        )

        return archive_path

    def _get_captures(
        self,
        conn: sqlite3.Connection,
        session_id: str,
    ) -> list[Capture]:
        """Retrieve all captures for a session.

        Args:
            conn: Active database connection.
            session_id: Session to query captures for.

        Returns:
            List of Capture records ordered by timestamp.
        """
        rows = conn.execute(
            """
            SELECT * FROM captures
            WHERE session_id = ?
            ORDER BY timestamp ASC
            """,
            (session_id,),
        ).fetchall()

        return [
            Capture(
                capture_id=row["capture_id"],
                session_id=row["session_id"],
                target_id=row["target_id"],
                capture_type=row["capture_type"],
                file_path=row["file_path"],
                tool=row["tool"],
                sha256=row["sha256"],
                timestamp=row["timestamp"],
            )
            for row in rows
        ]

    def _write_session_json(self, session: RFSession) -> None:
        """Write session metadata to session.json.

        Args:
            session: The session to serialize.
        """
        session_dir = Path(session.session_dir)
        session_file = session_dir / "session.json"

        data = {
            "session_id": session.session_id,
            "name": session.name,
            "status": session.status.value,
            "notes": session.notes,
            "created_at": session.created_at,
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "captures": [asdict(c) for c in session.captures],
        }

        session_file.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )
