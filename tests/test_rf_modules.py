"""Tests for the RF operations module.

Covers parsers, models, session lifecycle, event bus, and AI client.
Subprocess-dependent modules (interface_manager, tool_manager) are tested
where parsing logic can be exercised in isolation.
"""

import asyncio
import json
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# ── Parsers ──
from redops.modules.rf.parsers.airodump import (
    _clean_field,
    _parse_ap_row,
    _parse_client_row,
    _parse_int,
    parse_airodump_csv,
)
from redops.modules.rf.parsers.hcxdumptool import (
    check_for_captures,
    parse_hcx_status,
)
from redops.modules.rf.parsers.horst import parse_horst_line
from redops.modules.rf.parsers.reaver import parse_reaver_line
from redops.modules.rf.parsers.tshark import (
    build_tshark_stats_command,
    parse_tshark_json,
)

# ── Models & Session Manager ──
from redops.modules.rf.models import (
    Capture,
    Client,
    RFSession,
    RFFinding,
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
from redops.modules.rf.session_manager import (
    Capture as SMCapture,
    RFSession as SMRFSession,
    SessionManager,
    SessionStatus,
    _compute_sha256,
    _now_iso,
)

# ── Event Bus ──
from redops.modules.rf.event_bus import (
    EVENT_AP_DISCOVERED,
    EVENT_TOOL_STARTED,
    Event,
    EventBus,
)

# ── AI Client ──
from redops.modules.rf.ai_client import (
    AIClient,
    AIClientError,
    _load_ollama_host,
    _load_openrouter_config,
)

# ── Tool Manager ──
from redops.modules.rf.tool_manager import (
    IngestionStrategy,
    ResourceClass,
    ToolManager,
    ToolSpec,
    register_defaults,
)


# ═══════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def tmp_db():
    """Yield a temporary SQLite database path and clean up after."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = Path(f.name)
    yield path
    path.unlink(missing_ok=True)


@pytest.fixture
def db_conn(tmp_db):
    """Open an initialized RF database connection."""
    conn = init_db(tmp_db)
    yield conn
    conn.close()


# ═══════════════════════════════════════════════════════════
# Airodump Parser
# ═══════════════════════════════════════════════════════════

class TestAirodumpParser:
    """Tests for airodump-ng CSV parser."""

    def test_clean_field(self):
        assert _clean_field("  test  ") == "test"
        assert _clean_field("") == ""
        assert _clean_field(None) == ""

    def test_parse_int(self):
        assert _parse_int("42") == 42
        assert _parse_int("  7  ") == 7
        assert _parse_int("bad") == 0
        assert _parse_int("bad", -1) == -1
        assert _parse_int(None) == 0

    def test_parse_ap_row_valid(self):
        row = [
            "00:11:22:33:44:55", "2024-01-01", "2024-01-02",
            "6", "54", "WPA2", "CCMP", "PSK", "-42",
            "100", "50", "", "6", "TestAP", "",
        ]
        result = _parse_ap_row(row)
        assert result is not None
        assert result["bssid"] == "00:11:22:33:44:55"
        assert result["essid"] == "TestAP"
        assert result["channel"] == 6
        assert result["signal"] == -42

    def test_parse_ap_row_short(self):
        assert _parse_ap_row(["00:11:22:33:44:55"]) is None

    def test_parse_ap_row_invalid_bssid(self):
        row = ["short", "", "", "6"] + [""] * 10
        assert _parse_ap_row(row) is None

    def test_parse_client_row_valid(self):
        row = [
            "AA:BB:CC:DD:EE:FF", "2024-01-01", "2024-01-02",
            "-60", "10", "00:11:22:33:44:55", "TestAP,OtherAP",
        ]
        result = _parse_client_row(row)
        assert result is not None
        assert result["mac"] == "AA:BB:CC:DD:EE:FF"
        assert result["signal"] == -60
        assert result["probes"] == ["TestAP", "OtherAP"]

    def test_parse_airodump_csv_full(self, tmp_path):
        csv = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, 2024-01-01, 2024-01-02, 6, 54, WPA2, "
            "CCMP, PSK, -42, 100, 0, 0.0.0.0, 6, TestAP, \n\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            "AA:BB:CC:DD:EE:FF, 2024-01-01, 2024-01-02, -60, 10, "
            "00:11:22:33:44:55, TestAP\n"
        )
        f = tmp_path / "test.csv"
        f.write_text(csv)
        aps, clients = parse_airodump_csv(str(f))
        assert len(aps) == 1
        assert aps[0]["essid"] == "TestAP"
        assert len(clients) == 1
        assert clients[0]["mac"] == "AA:BB:CC:DD:EE:FF"

    def test_parse_airodump_csv_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_airodump_csv(str(tmp_path / "nonexistent.csv"))


# ═══════════════════════════════════════════════════════════
# Hcxdumptool Parser
# ═══════════════════════════════════════════════════════════

class TestHcxdumptoolParser:
    """Tests for hcxdumptool status parser."""

    def test_parse_hcx_status_empty(self):
        assert parse_hcx_status("") is None
        assert parse_hcx_status("   ") is None

    def test_parse_hcx_status_packets(self):
        result = parse_hcx_status("[60] packets: 1500")
        assert result["timestamp"] == 60
        assert result["packets"] == 1500

    def test_parse_hcx_status_bssid_essid(self):
        result = parse_hcx_status("BSSID: 00:11:22:33:44:55 ESSID: TestAP")
        assert result["bssid"] == "00:11:22:33:44:55"
        assert result["essid"] == "TestAP"

    def test_parse_hcx_status_client(self):
        result = parse_hcx_status("CLIENT: aa:bb:cc:dd:ee:ff")
        assert result["client"] == "AA:BB:CC:DD:EE:FF"

    def test_parse_hcx_status_pmkid(self):
        result = parse_hcx_status("PMKID captured")
        assert result["pmkid_detected"] is True
        assert result["eapol_detected"] is False

    def test_parse_hcx_status_eapol(self):
        result = parse_hcx_status("EAPOL frame received")
        assert result["pmkid_detected"] is False
        assert result["eapol_detected"] is True

    def test_check_for_captures_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            check_for_captures(tmp_path / "nonexistent.pcapng")

    def test_check_for_captures_success(self, tmp_path):
        pcap = tmp_path / "test.pcapng"
        pcap.write_text("dummy")
        with patch("redops.modules.rf.parsers.hcxdumptool.subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                stdout="PMKID: 2\nEAPOL: 3\nbest handshake: 1",
                stderr="",
                returncode=0,
            )
            result = check_for_captures(pcap)
        assert result["pmkids"] == 2
        assert result["handshakes"] == 3
        assert result["best_handshakes"] == 1

    def test_check_for_captures_tool_not_found(self, tmp_path):
        pcap = tmp_path / "test.pcapng"
        pcap.write_text("dummy")
        with patch("redops.modules.rf.parsers.hcxdumptool.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("hcxpcapngtool")
            result = check_for_captures(pcap)
        assert "not found" in result["error"]

    def test_check_for_captures_timeout(self, tmp_path):
        pcap = tmp_path / "test.pcapng"
        pcap.write_text("dummy")
        with patch("redops.modules.rf.parsers.hcxdumptool.subprocess.run") as mock_run:
            import subprocess as sp
            mock_run.side_effect = sp.TimeoutExpired("hcxpcapngtool", 60)
            result = check_for_captures(pcap)
        assert "timed out" in result["error"]


# ═══════════════════════════════════════════════════════════
# Horst Parser
# ═══════════════════════════════════════════════════════════

class TestHorstParser:
    """Tests for horst output parser."""

    def test_parse_horst_line_standard(self):
        line = "1234.5  -45  6  BEACON  00:11:22:33:44:55"
        result = parse_horst_line(line)
        assert result["mac"] == "00:11:22:33:44:55"
        assert result["signal"] == -45
        assert result["channel"] == 6
        assert result["type"] == "BEACON"

    def test_parse_horst_line_bracket(self):
        line = "[6]  -50dBm  DATA  AA:BB:CC:DD:EE:FF  extra info"
        result = parse_horst_line(line)
        assert result["mac"] == "AA:BB:CC:DD:EE:FF"
        assert result["signal"] == -50
        assert result["channel"] == 6
        assert result["type"] == "DATA"
        assert result["extra"] == "extra info"

    def test_parse_horst_line_empty(self):
        assert parse_horst_line("") is None
        assert parse_horst_line("   ") is None

    def test_parse_horst_line_header_skipped(self):
        assert parse_horst_line("# comment") is None
        assert parse_horst_line("---") is None

    def test_parse_horst_line_no_match(self):
        assert parse_horst_line("not a valid line") is None


# ═══════════════════════════════════════════════════════════
# Reaver Parser
# ═══════════════════════════════════════════════════════════

class TestReaverParser:
    """Tests for reaver output parser."""

    def test_parse_reaver_line_empty(self):
        assert parse_reaver_line("") is None

    def test_wps_pin_found(self):
        result = parse_reaver_line("WPS PIN: '12345678'")
        assert result["type"] == "success"
        assert result["wps_pin"] == "12345678"

    def test_wpa_psk_found(self):
        result = parse_reaver_line("WPA PSK: 'secretpassword'")
        assert result["type"] == "success"
        assert result["wpa_psk"] == "secretpassword"

    def test_pin_attempt(self):
        result = parse_reaver_line("Trying pin 1234")
        assert result["type"] == "attempt"
        assert result["pin"] == "1234"

    def test_pin_attempt_with_progress(self):
        result = parse_reaver_line("Trying pin 1234 (12.5% complete)")
        assert result["type"] == "attempt"
        assert result["pin"] == "1234"
        assert result["progress"] == 12.5

    def test_progress_standalone(self):
        result = parse_reaver_line("45.0% complete")
        assert result["type"] == "progress"
        assert result["progress"] == 45.0

    def test_association(self):
        result = parse_reaver_line("Associated with AA:BB (ESSID: TestNet)")
        assert result["type"] == "association"
        assert result["bssid"] == "AA:BB"
        assert result["essid"] == "TestNet"

    def test_locked_warning(self):
        result = parse_reaver_line("WARNING: WPS locked")
        assert result["type"] == "warning"
        assert result["warning"] == "locked"

    def test_rate_limited_warning(self):
        result = parse_reaver_line("WARNING: rate limiting detected")
        assert result["type"] == "warning"
        assert result["warning"] == "rate_limited"

    def test_timeout_warning(self):
        result = parse_reaver_line("WARNING: timeout occurred")
        assert result["type"] == "warning"
        assert result["warning"] == "timeout"

    def test_failure(self):
        result = parse_reaver_line("WPS transaction failed")
        assert result["type"] == "failure"

    def test_no_match(self):
        assert parse_reaver_line("random log line") is None


# ═══════════════════════════════════════════════════════════
# Tshark Parser
# ═══════════════════════════════════════════════════════════

class TestTsharkParser:
    """Tests for tshark JSON parser and command builder."""

    def test_build_command_basic(self):
        cmd = build_tshark_stats_command("wlan0mon", 30)
        assert cmd[0] == "tshark"
        assert "wlan0mon" in cmd
        assert "duration:30" in cmd

    def test_build_command_empty_interface_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_tshark_stats_command("", 30)

    def test_build_command_zero_duration_raises(self):
        with pytest.raises(ValueError, match="positive"):
            build_tshark_stats_command("wlan0", 0)

    def test_build_command_negative_duration_raises(self):
        with pytest.raises(ValueError, match="positive"):
            build_tshark_stats_command("wlan0", -1)

    def test_parse_tshark_json_empty(self):
        assert parse_tshark_json("") is None
        assert parse_tshark_json("   ") is None

    def test_parse_tshark_json_invalid(self):
        assert parse_tshark_json("not json") is None

    def test_parse_tshark_json_index_line_skipped(self):
        line = '{"index": {}}'
        assert parse_tshark_json(line) is None

    def test_parse_tshark_json_no_layers_skipped(self):
        line = '{"timestamp": 123}'
        assert parse_tshark_json(line) is None

    def test_parse_tshark_json_full(self):
        line = json.dumps({
            "timestamp": "1234567890",
            "layers": {
                "frame": {
                    "frame_frame_len": ["1500"],
                    "frame_frame_protocols": ["eth:ip:tcp"],
                },
                "eth": {
                    "eth_eth_src": ["00:11:22:33:44:55"],
                    "eth_eth_dst": ["AA:BB:CC:DD:EE:FF"],
                },
                "ip": {
                    "ip_ip_src": ["192.168.1.1"],
                    "ip_ip_dst": ["192.168.1.2"],
                },
            },
        })
        result = parse_tshark_json(line)
        assert result["timestamp"] == "1234567890"
        assert result["length"] == 1500
        assert result["protocol"] == "eth:ip:tcp"
        assert result["src_mac"] == "00:11:22:33:44:55"
        assert result["dst_mac"] == "AA:BB:CC:DD:EE:FF"
        assert result["src_ip"] == "192.168.1.1"
        assert result["dst_ip"] == "192.168.1.2"

    def test_parse_tshark_json_no_ip(self):
        line = json.dumps({
            "layers": {
                "frame": {"frame_frame_len": "64"},
                "eth": {
                    "eth_eth_src": "00:11:22:33:44:55",
                },
            },
        })
        result = parse_tshark_json(line)
        assert result["length"] == 64
        assert result["src_mac"] == "00:11:22:33:44:55"
        assert result.get("src_ip") is None

    def test_get_pcap_summary_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            from redops.modules.rf.parsers.tshark import get_pcap_summary
            get_pcap_summary(tmp_path / "nonexistent.pcap")

    def test_get_pcap_summary_success(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_text("dummy")
        from redops.modules.rf.parsers.tshark import get_pcap_summary
        with patch("redops.modules.rf.parsers.tshark.subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                stdout=json.dumps({
                    "layers": {
                        "frame": {
                            "frame_frame_len": ["100"],
                            "frame_frame_protocols": ["eth:ip:tcp"],
                        },
                        "eth": {
                            "eth_eth_src": ["00:11:22:33:44:55"],
                            "eth_eth_dst": ["AA:BB:CC:DD:EE:FF"],
                        },
                        "ip": {
                            "ip_ip_src": ["10.0.0.1"],
                            "ip_ip_dst": ["10.0.0.2"],
                        },
                    },
                }),
                stderr="",
                returncode=0,
            )
            result = get_pcap_summary(pcap, max_packets=1)
        assert result["packet_count"] == 1
        assert "tcp" in result["protocols"]


# ═══════════════════════════════════════════════════════════
# RF Models (DB layer)
# ═══════════════════════════════════════════════════════════

class TestRFModels:
    """Tests for RF SQLite-backed models."""

    def test_init_db_creates_tables(self, db_conn):
        tables = db_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {t[0] for t in tables}
        assert "rf_sessions" in names
        assert "targets" in names
        assert "clients" in names
        assert "captures" in names
        assert "rf_findings" in names
        assert "tool_runs" in names

    def test_insert_and_get_session(self, db_conn):
        session = RFSession(name="Test Session")
        sid = insert_session(db_conn, session)
        assert isinstance(sid, int)
        fetched = get_session(db_conn, sid)
        assert fetched is not None
        assert fetched.name == "Test Session"
        assert fetched.status == "created"

    def test_insert_target(self, db_conn):
        session = RFSession(name="S")
        sid = insert_session(db_conn, session)
        target = Target(
            session_id=sid,
            bssid="00:11:22:33:44:55",
            essid="TestAP",
            tags=["wps", "high-signal"],
        )
        tid = insert_target(db_conn, target)
        assert isinstance(tid, int)
        targets = get_targets_for_session(db_conn, sid)
        assert len(targets) == 1
        assert targets[0].bssid == "00:11:22:33:44:55"
        assert targets[0].tags == ["wps", "high-signal"]

    def test_insert_client(self, db_conn):
        client = Client(mac="AA:BB:CC:DD:EE:FF", probes=["Net1", "Net2"])
        cid = insert_client(db_conn, client)
        assert isinstance(cid, int)

    def test_insert_capture(self, db_conn):
        session = RFSession(name="S")
        sid = insert_session(db_conn, session)
        cap = Capture(
            target_id=None,
            session_id=sid,
            capture_type="handshake",
            file_path="/tmp/cap.pcap",
        )
        cap_id = insert_capture(db_conn, cap)
        assert isinstance(cap_id, int)

    def test_insert_finding(self, db_conn):
        session = RFSession(name="S")
        sid = insert_session(db_conn, session)
        finding = RFFinding(
            target_id=None,
            session_id=sid,
            finding_type="vuln",
            severity="high",
            evidence={"key": "value"},
        )
        fid = insert_finding(db_conn, finding)
        assert isinstance(fid, int)

    def test_insert_tool_run(self, db_conn):
        session = RFSession(name="S")
        sid = insert_session(db_conn, session)
        tr = ToolRun(session_id=sid, tool="airodump-ng", command="airodump-ng wlan0")
        trid = insert_tool_run(db_conn, tr)
        assert isinstance(trid, int)

    def test_update_tool_run_status(self, db_conn):
        session = RFSession(name="S")
        sid = insert_session(db_conn, session)
        tr = ToolRun(session_id=sid, tool="test")
        trid = insert_tool_run(db_conn, tr)
        update_tool_run_status(db_conn, trid, "done", 0)
        row = db_conn.execute(
            "SELECT status, exit_code FROM tool_runs WHERE id=?", (trid,)
        ).fetchone()
        assert row[0] == "done"
        assert row[1] == 0

    def test_get_session_missing(self, db_conn):
        assert get_session(db_conn, 9999) is None


# ═══════════════════════════════════════════════════════════
# Session Manager
# ═══════════════════════════════════════════════════════════

class TestSessionManager:
    """Tests for RF SessionManager lifecycle."""

    def test_create_session(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("Lab Test")
        assert session.name == "Lab Test"
        assert session.status == SessionStatus.CREATED
        assert Path(session.session_dir).exists()
        # Check subdirs created
        for sub in sm._SESSION_SUBDIRS:
            assert (Path(session.session_dir) / sub).exists()

    def test_create_session_empty_name_raises(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        with pytest.raises(ValueError, match="empty"):
            sm.create_session("")

    def test_create_session_duplicate_raises(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        sm.create_session("Duplicate")
        with pytest.raises(FileExistsError):
            sm.create_session("Duplicate")

    def test_start_session(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("S")
        sm.start_session(session.session_id)
        fetched = sm.get_session(session.session_id)
        assert fetched.status == SessionStatus.ACTIVE
        assert fetched.started_at is not None

    def test_start_not_created_raises(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("S")
        sm.start_session(session.session_id)
        with pytest.raises(ValueError, match="created"):
            sm.start_session(session.session_id)

    def test_end_session(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("S")
        sm.start_session(session.session_id)
        sm.end_session(session.session_id)
        fetched = sm.get_session(session.session_id)
        assert fetched.status == SessionStatus.CLOSED
        assert fetched.ended_at is not None

    def test_add_capture(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("S")
        sm.start_session(session.session_id)
        cap_file = tmp_path / "test.pcap"
        cap_file.write_text("pcap data")
        capture = sm.add_capture(
            session.session_id,
            target_id="00:11:22:33:44:55",
            capture_type="pcap",
            file_path=cap_file,
            tool="airodump-ng",
        )
        assert capture.capture_type == "pcap"
        assert capture.sha256 is not None
        assert len(capture.sha256) == 64

    def test_add_capture_inactive_raises(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("S")
        cap_file = tmp_path / "test.pcap"
        cap_file.write_text("data")
        with pytest.raises(ValueError, match="created"):
            sm.add_capture(
                session.session_id,
                target_id="t",
                capture_type="pcap",
                file_path=cap_file,
                tool="t",
            )

    def test_list_sessions(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        sm.create_session("A")
        sm.create_session("B")
        sessions = sm.list_sessions()
        assert len(sessions) == 2

    def test_archive_session(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("ArchiveMe")
        sm.start_session(session.session_id)
        sm.end_session(session.session_id)
        archive = sm.archive_session(session.session_id)
        assert archive.exists()
        assert archive.suffix == ".gz"

    def test_archive_not_closed_raises(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("S")
        with pytest.raises(ValueError, match="closed"):
            sm.archive_session(session.session_id)

    def test_compute_sha256(self, tmp_path):
        f = tmp_path / "hash.txt"
        f.write_text("hello")
        h = _compute_sha256(f)
        assert len(h) == 64
        # Verify with stdlib
        import hashlib
        expected = hashlib.sha256(b"hello").hexdigest()
        assert h == expected

    def test_now_iso(self):
        s = _now_iso()
        assert "T" in s
        assert "+" in s


# ═══════════════════════════════════════════════════════════
# Event Bus
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def event_bus():
    return EventBus(history_size=10)


class TestEventBus:
    """Tests for the RF asyncio event bus."""

    @pytest.mark.asyncio
    async def test_subscribe_and_emit(self, event_bus):
        events = []

        def handler(evt):
            events.append(evt)

        sub_id = event_bus.subscribe(EVENT_AP_DISCOVERED, handler)
        evt = await event_bus.emit(EVENT_AP_DISCOVERED, {"bssid": "00:11:22:33:44:55"})
        assert len(events) == 1
        assert events[0].data["bssid"] == "00:11:22:33:44:55"
        assert event_bus.unsubscribe(sub_id) is True

    @pytest.mark.asyncio
    async def test_async_subscriber(self, event_bus):
        events = []

        async def handler(evt):
            events.append(evt)

        event_bus.subscribe(EVENT_AP_DISCOVERED, handler)
        await event_bus.emit(EVENT_AP_DISCOVERED, {"x": 1})
        assert len(events) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe_unknown(self, event_bus):
        assert event_bus.unsubscribe("not-real") is False

    @pytest.mark.asyncio
    async def test_emit_no_subscribers(self, event_bus):
        evt = await event_bus.emit(EVENT_TOOL_STARTED, {})
        assert evt.event_type == EVENT_TOOL_STARTED

    @pytest.mark.asyncio
    async def test_history_tracks_events(self, event_bus):
        await event_bus.emit(EVENT_AP_DISCOVERED, {"a": 1})
        await event_bus.emit(EVENT_AP_DISCOVERED, {"b": 2})
        recent = event_bus.recent_events
        assert len(recent) == 2

    @pytest.mark.asyncio
    async def test_recent_events_by_type(self, event_bus):
        await event_bus.emit(EVENT_AP_DISCOVERED, {})
        await event_bus.emit(EVENT_TOOL_STARTED, {})
        aps = event_bus.recent_events_by_type(EVENT_AP_DISCOVERED)
        assert len(aps) == 1

    @pytest.mark.asyncio
    async def test_history_respects_size(self):
        bus = EventBus(history_size=3)
        for i in range(5):
            await bus.emit(EVENT_AP_DISCOVERED, {"i": i})
        assert len(bus.recent_events) == 3

    @pytest.mark.asyncio
    async def test_subscriber_count(self, event_bus):
        assert event_bus.subscriber_count == 0
        event_bus.subscribe(EVENT_AP_DISCOVERED, lambda e: None)
        assert event_bus.subscriber_count == 1
        sid = event_bus.subscribe(EVENT_AP_DISCOVERED, lambda e: None)
        assert event_bus.subscriber_count == 2
        event_bus.unsubscribe(sid)
        assert event_bus.subscriber_count == 1

    @pytest.mark.asyncio
    async def test_emit_sync(self, event_bus):
        events = []

        def handler(evt):
            events.append(evt)

        event_bus.subscribe(EVENT_AP_DISCOVERED, handler)
        evt = event_bus.emit_sync(EVENT_AP_DISCOVERED, {"sync": True})
        assert len(events) == 1
        assert events[0].data["sync"] is True

    @pytest.mark.asyncio
    async def test_emit_sync_skips_async(self, event_bus):
        async def async_handler(evt):
            pass

        event_bus.subscribe(EVENT_AP_DISCOVERED, async_handler)
        # Should not raise; async subscriber skipped with warning
        evt = event_bus.emit_sync(EVENT_AP_DISCOVERED, {})
        assert evt.event_type == EVENT_AP_DISCOVERED

    @pytest.mark.asyncio
    async def test_create_queue(self, event_bus):
        qid = event_bus.create_queue(EVENT_AP_DISCOVERED)
        queue = event_bus.get_queue(qid)
        assert queue is not None
        await event_bus.emit(EVENT_AP_DISCOVERED, {"x": 1})
        evt = queue.get_nowait()
        assert evt.data["x"] == 1
        assert event_bus.remove_queue(qid) is True
        assert event_bus.remove_queue("bad") is False

    @pytest.mark.asyncio
    async def test_queue_filtering(self, event_bus):
        qid = event_bus.create_queue(EVENT_AP_DISCOVERED)
        queue = event_bus.get_queue(qid)
        await event_bus.emit(EVENT_TOOL_STARTED, {})
        await event_bus.emit(EVENT_AP_DISCOVERED, {"y": 2})
        # Only AP event should land
        assert queue.qsize() == 1
        evt = queue.get_nowait()
        assert evt.data["y"] == 2

    @pytest.mark.asyncio
    async def test_clear_history(self, event_bus):
        await event_bus.emit(EVENT_AP_DISCOVERED, {})
        event_bus.clear_history()
        assert len(event_bus.recent_events) == 0

    @pytest.mark.asyncio
    async def test_subscriber_error_isolated(self, event_bus):
        def bad_handler(evt):
            raise RuntimeError("boom")

        good_events = []

        def good_handler(evt):
            good_events.append(evt)

        event_bus.subscribe(EVENT_AP_DISCOVERED, bad_handler)
        event_bus.subscribe(EVENT_AP_DISCOVERED, good_handler)
        await event_bus.emit(EVENT_AP_DISCOVERED, {})
        assert len(good_events) == 1


# ═══════════════════════════════════════════════════════════
# AI Client
# ═══════════════════════════════════════════════════════════

class TestAIClientConfig:
    """Tests for AIClient configuration loading."""

    def test_load_ollama_host_default(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch.object(Path, "exists", return_value=False):
                host = _load_ollama_host()
                assert host == "http://localhost:11434"

    def test_load_ollama_host_from_env(self):
        with patch.dict("os.environ", {"OLLAMA_HOST": "http://remote:11434"}):
            host = _load_ollama_host()
            assert host == "http://remote:11434"

    def test_load_ollama_host_from_file(self, tmp_path):
        env_file = tmp_path / "ollama-remote.env"
        env_file.write_text('OLLAMA_HOST="http://file:11434"\n')
        with patch.dict("os.environ", {}, clear=True):
            with patch("redops.modules.rf.ai_client._ENV_FILE", env_file):
                host = _load_ollama_host()
                assert host == "http://file:11434"

    def test_load_openrouter_config(self):
        with patch.dict(
            "os.environ",
            {"OPENROUTER_BASE_URL": "http://or.com", "OPENROUTER_API_KEY": "key123"},
        ):
            base, key = _load_openrouter_config()
            assert base == "http://or.com"
            assert key == "key123"


class TestAIClientParsing:
    """Tests for AIClient JSON parsing helper."""

    def test_parse_json_response_plain(self):
        raw = '{"recommendations": [{"bssid": "00:11:22:33:44:55"}]}'
        result = AIClient._parse_json_response(raw)
        assert result["recommendations"][0]["bssid"] == "00:11:22:33:44:55"

    def test_parse_json_response_markdown_fences(self):
        raw = "```json\n{\"key\": \"value\"}\n```"
        result = AIClient._parse_json_response(raw)
        assert result["key"] == "value"

    def test_parse_json_response_non_dict(self):
        raw = "[1, 2, 3]"
        result = AIClient._parse_json_response(raw)
        assert result == {"data": [1, 2, 3]}

    def test_parse_json_response_invalid(self):
        raw = "not json"
        result = AIClient._parse_json_response(raw)
        assert result["raw_response"] == "not json"


# ═══════════════════════════════════════════════════════════
# Tool Manager
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def tool_manager():
    from redops.core.event_bus import EventBus as CoreEventBus
    bus = CoreEventBus()
    return ToolManager(event_bus=bus, session_path=Path("/tmp"))


class TestToolManager:
    """Tests for ToolManager registry and command building."""

    def test_register_tool(self, tool_manager):
        spec = ToolSpec(
            name="test-tool",
            binary_path="/usr/bin/test",
            requires_monitor=True,
            requires_root=True,
        )
        tool_manager.register_tool(spec)
        assert "test-tool" in tool_manager._registry

    def test_register_defaults(self, tool_manager):
        register_defaults(tool_manager)
        assert "airodump-ng" in tool_manager._registry
        assert "tshark" in tool_manager._registry
        assert "reaver" in tool_manager._registry

    def test_build_command_basic(self, tool_manager):
        spec = ToolSpec(name="test", binary_path="test", requires_root=False)
        cmd = tool_manager._build_command(spec, "wlan0", ["-v"])
        assert cmd == ["test", "-v", "wlan0"]

    def test_build_command_with_root(self, tool_manager):
        spec = ToolSpec(name="test", binary_path="test", requires_root=True)
        cmd = tool_manager._build_command(spec, "wlan0", [])
        assert cmd[0] == "sudo"
        assert "test" in cmd

    def test_build_command_interface_override(self, tool_manager):
        spec = ToolSpec(name="test", binary_path="test")
        cmd = tool_manager._build_command(spec, "wlan0", ["-i", "wlan1"])
        # When -i is in args, interface should NOT be appended
        assert "wlan1" in cmd
        assert "wlan0" not in cmd

    def test_interface_lock_acquire_and_release(self, tool_manager):
        spec = ToolSpec(name="t1", binary_path="t1")
        tool_manager._acquire_interface("wlan0", "id1", spec)
        assert tool_manager.interface_lock["wlan0"] == "id1"
        tool_manager._release_interface("wlan0", "id1")
        assert "wlan0" not in tool_manager.interface_lock

    def test_interface_lock_prevents_double_acquire(self, tool_manager):
        spec = ToolSpec(name="t1", binary_path="t1")
        tool_manager._acquire_interface("wlan0", "id1", spec)
        with pytest.raises(RuntimeError, match="locked"):
            tool_manager._acquire_interface("wlan0", "id2", spec)
        tool_manager._release_interface("wlan0", "id1")

    def test_inject_tool_exclusivity(self, tool_manager):
        inject_spec = ToolSpec(
            name="reaver",
            binary_path="reaver",
            resource_class=ResourceClass.RF_INJECT,
        )
        tool_manager._acquire_interface("wlan0", "id1", inject_spec)
        # Populate _running so the exclusivity check can inspect the spec
        mock_proc = Mock()
        mock_proc.spec = inject_spec
        tool_manager._running["id1"] = mock_proc
        with pytest.raises(RuntimeError, match="inject"):
            tool_manager._acquire_interface("wlan1", "id2", inject_spec)
        tool_manager._release_interface("wlan0", "id1")
        tool_manager._running.pop("id1", None)

    def test_release_interface_wrong_holder_warns(self, tool_manager, monkeypatch):
        from unittest.mock import MagicMock
        import redops.modules.rf.tool_manager as tm_mod
        tool_manager.interface_lock["wlan0"] = "id1"
        warn_mock = MagicMock()
        monkeypatch.setattr(tm_mod.logger, "warning", warn_mock)
        tool_manager._release_interface("wlan0", "id2")
        assert warn_mock.called
        assert "not by" in warn_mock.call_args[0][0]

    def test_get_running_empty(self, tool_manager):
        assert tool_manager.get_running() == []

    def test_tool_spec_defaults(self):
        spec = ToolSpec(name="simple", binary_path="/bin/simple")
        assert spec.requires_monitor is False
        assert spec.ingestion_strategy == IngestionStrategy.STREAM


# ═══════════════════════════════════════════════════════════
# Integration: EventBus + ToolManager
# ═══════════════════════════════════════════════════════════

class TestRFIntegration:
    """Integration tests across RF subsystems."""

    @pytest.mark.asyncio
    async def test_event_bus_tool_lifecycle(self):
        bus = EventBus()
        events = []

        def collect(evt):
            events.append(evt.event_type)

        bus.subscribe(EVENT_TOOL_STARTED, collect)
        bus.subscribe("tool_stopped", collect)

        await bus.emit(EVENT_TOOL_STARTED, {"tool": "airodump-ng"})
        await bus.emit("tool_stopped", {"tool": "airodump-ng"})

        assert len(events) == 2
        assert events[0] == EVENT_TOOL_STARTED

    def test_session_manager_with_captures(self, tmp_path):
        sm = SessionManager(base_dir=tmp_path)
        session = sm.create_session("Integration")
        sm.start_session(session.session_id)

        # Create a fake capture
        cap_dir = Path(session.session_dir) / "evidence"
        cap_file = cap_dir / "test.pcap"
        cap_file.write_text("pcap data")

        capture = sm.add_capture(
            session.session_id,
            target_id="00:11:22:33:44:55",
            capture_type="pcap",
            file_path=cap_file,
            tool="airodump-ng",
        )

        sm.end_session(session.session_id)
        archived = sm.archive_session(session.session_id)

        assert archived.exists()
        assert capture.sha256 is not None

        # Verify session.json was written
        session_json = Path(session.session_dir) / "session.json"
        assert session_json.exists()
        data = json.loads(session_json.read_text())
        assert data["status"] == "closed"
