"""Tests for the RF SQLite persistence layer (modules/rf/models.py).

Exercises the dataclasses, schema init, and every row<->dataclass helper
against a throwaway on-disk SQLite database. The RF DB layer ships with the
rf/ subsystem; these tests cover it directly (no hardware/tools involved).
"""

import json

import pytest

from redops.modules.rf import models
from redops.modules.rf.models import (
    Capture,
    Client,
    RFFinding,
    RFSession,
    Target,
    ToolRun,
    WirelessInterface,
    get_session,
    get_targets_for_session,
    init_db,
    insert_capture,
    insert_client,
    insert_finding,
    insert_session,
    insert_target,
    insert_tool_run,
    update_tool_run_status,
)


@pytest.fixture
def conn(tmp_path):
    """An initialized RF database on a temp path."""
    c = init_db(tmp_path / "rf.db")
    yield c
    c.close()


class TestSchema:
    def test_init_db_creates_tables(self, conn):
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        expected = {
            "rf_sessions",
            "wireless_interfaces",
            "targets",
            "clients",
            "captures",
            "rf_findings",
            "tool_runs",
        }
        assert expected.issubset(names)

    def test_foreign_keys_enabled(self, conn):
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def test_init_db_default_path(self, tmp_path, monkeypatch):
        """No path → falls back to DEFAULT_DB_PATH (redirected to tmp)."""
        monkeypatch.setattr(models, "DEFAULT_DB_PATH", tmp_path / "d" / "op.db")
        c = init_db()
        try:
            assert (tmp_path / "d" / "op.db").exists()
        finally:
            c.close()


class TestDataclassDefaults:
    def test_session_defaults(self):
        s = RFSession()
        assert s.id is None
        assert s.status == "created"
        assert s.started_at  # default_factory populated an ISO timestamp

    def test_target_defaults(self):
        t = Target()
        assert t.wps_enabled is False
        assert t.tags == []
        assert t.priority == 0

    def test_interface_and_client_defaults(self):
        assert WirelessInterface().mode == "managed"
        assert Client().probes == []


class TestRoundTrips:
    def test_session_round_trip(self, conn):
        sid = insert_session(conn, RFSession(name="engagement-1", notes="n"))
        assert isinstance(sid, int)
        fetched = get_session(conn, sid)
        assert fetched is not None
        assert fetched.name == "engagement-1"
        assert fetched.notes == "n"

    def test_get_session_missing_returns_none(self, conn):
        assert get_session(conn, 9999) is None

    def test_target_round_trip_preserves_tags_and_wps(self, conn):
        sid = insert_session(conn, RFSession(name="s"))
        insert_target(
            conn,
            Target(
                session_id=sid,
                bssid="AA:BB:CC:DD:EE:FF",
                essid="corp-wifi",
                wps_enabled=True,
                tags=["high-value", "wpa2"],
                priority=5,
            ),
        )
        insert_target(conn, Target(session_id=sid, bssid="11:22:33:44:55:66"))
        targets = get_targets_for_session(conn, sid)
        assert len(targets) == 2
        # Ordered by priority DESC → the priority-5 target comes first.
        top = targets[0]
        assert top.wps_enabled is True
        assert top.tags == ["high-value", "wpa2"]

    def test_client_capture_finding_toolrun_insert(self, conn):
        sid = insert_session(conn, RFSession(name="s"))
        tid = insert_target(conn, Target(session_id=sid, bssid="AA:AA:AA:AA:AA:AA"))
        assert insert_client(
            conn, Client(mac="DE:AD:BE:EF:00:01", target_id=tid, probes=["home"])
        )
        assert insert_capture(
            conn,
            Capture(
                target_id=tid,
                session_id=sid,
                capture_type="handshake",
                file_path="/tmp/h.pcap",
                converted=True,
            ),
        )
        assert insert_finding(
            conn,
            RFFinding(
                target_id=tid,
                session_id=sid,
                finding_type="vuln",
                severity="high",
                title="WPS enabled",
                evidence={"pin_attempts": 3},
                verified=True,
            ),
        )
        assert insert_tool_run(
            conn,
            ToolRun(session_id=sid, tool="airodump-ng", command="airodump-ng wlan1"),
        )

    def test_finding_evidence_json_persisted(self, conn):
        sid = insert_session(conn, RFSession(name="s"))
        insert_finding(
            conn,
            RFFinding(session_id=sid, finding_type="intel", evidence={"k": "v"}),
        )
        raw = conn.execute("SELECT evidence FROM rf_findings").fetchone()[0]
        assert json.loads(raw) == {"k": "v"}


class TestToolRunUpdate:
    def test_update_status_sets_exit_code_and_end(self, conn):
        sid = insert_session(conn, RFSession(name="s"))
        rid = insert_tool_run(conn, ToolRun(session_id=sid, tool="reaver"))
        update_tool_run_status(conn, rid, "done", exit_code=0)
        row = conn.execute(
            "SELECT status, exit_code, ended_at FROM tool_runs WHERE id=?", (rid,)
        ).fetchone()
        assert row[0] == "done"
        assert row[1] == 0
        assert row[2]  # ended_at auto-filled when not provided

    def test_update_status_explicit_ended_at(self, conn):
        sid = insert_session(conn, RFSession(name="s"))
        rid = insert_tool_run(conn, ToolRun(session_id=sid, tool="reaver"))
        update_tool_run_status(
            conn, rid, "error", exit_code=1, ended_at="2026-01-01T00:00:00+00:00"
        )
        row = conn.execute(
            "SELECT status, ended_at FROM tool_runs WHERE id=?", (rid,)
        ).fetchone()
        assert row[0] == "error"
        assert row[1] == "2026-01-01T00:00:00+00:00"


class TestJsonHelpers:
    def test_json_dumps_round_trips_normal_objects(self):
        assert json.loads(models._json_dumps({"k": "v"})) == {"k": "v"}
        assert json.loads(models._json_dumps([1, 2])) == [1, 2]

    def test_json_dumps_default_str_for_non_serializable(self):
        from datetime import datetime, timezone

        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # default=str path: datetime is not natively JSON-serializable.
        assert models._json_dumps(dt) == json.dumps(str(dt))

    def test_json_loads_empty_returns_dict(self):
        assert models._json_loads(None) == {}
        assert models._json_loads("") == {}

    def test_json_loads_bad_json_returns_dict(self):
        assert models._json_loads("{not valid") == {}

    def test_json_loads_valid(self):
        assert models._json_loads('["a", "b"]') == ["a", "b"]
