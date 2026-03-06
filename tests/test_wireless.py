"""Tests for active wireless modules — monitor, scan, evil_twin, deauth."""

from unittest.mock import MagicMock, patch

from redops.core.context import Context
from redops.modules.active.wireless.monitor import (
    disable_monitor_mode,
    enable_monitor_mode,
    get_wireless_interfaces,
)
from redops.modules.active.wireless.scan import (
    _parse_airodump_csv,
    scan_access_points,
)


# ── monitor.py ──────────────────────────────────────────────────────


class TestGetWirelessInterfaces:
    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_returns_interface_names(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="wlan0     IEEE 802.11  ESSID:off\neth0      no wireless\nwlan1     IEEE 802.11  ESSID:off\n"
        )
        result = get_wireless_interfaces()
        assert result == ["wlan0", "wlan1"]

    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_returns_empty_when_no_wireless(self, mock_run):
        mock_run.return_value = MagicMock(stdout="eth0      no wireless\n")
        result = get_wireless_interfaces()
        assert result == []


class TestEnableMonitorMode:
    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Mode:Monitor", returncode=0)
        ctx = Context(target="home-lab")
        result = enable_monitor_mode(ctx, {"interface": "wlan1"})
        assert result.get("monitor_ready") is True
        assert result.get("monitor_interface") == "wlan1mon"

    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_failure(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Mode:Managed", returncode=1)
        ctx = Context(target="home-lab")
        result = enable_monitor_mode(ctx, {"interface": "wlan1"})
        assert result.get("monitor_ready") is False

    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_default_interface(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Mode:Monitor", returncode=0)
        ctx = Context(target="home-lab")
        result = enable_monitor_mode(ctx)
        assert result.get("monitor_interface") == "wlan1mon"


class TestDisableMonitorMode:
    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_restores_managed_mode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        ctx = Context(target="home-lab")
        ctx.add("monitor_interface", "wlan1mon")
        result = disable_monitor_mode(ctx)
        assert result.get("monitor_ready") is False

    @patch("redops.modules.active.wireless.monitor.subprocess.run")
    def test_uses_context_interface(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        ctx = Context(target="home-lab")
        ctx.add("monitor_interface", "wlan2mon")
        disable_monitor_mode(ctx)
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("wlan2mon" in c for c in calls)


# ── scan.py ─────────────────────────────────────────────────────────


SAMPLE_AIRODUMP_CSV = "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, beacons, IV, LAN IP, ID-length, ESSID, Key\r\nAA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:01:00,  6, 54, WPA2, CCMP, PSK, -40, 100, 0, 0.0.0.0, 10, TestNetwork, \r\n11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 11, 54, OPN, , , -60, 50, 0, 0.0.0.0, 8, OpenNet, \r\n\r\nStation MAC, First time seen, Last time seen, Power, packets, BSSID, Probed ESSIDs\r\nAA:11:BB:22:CC:33, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -30, 100, AA:BB:CC:DD:EE:FF, TestNetwork\r\n"


class TestParseAirodumpCsv:
    def test_parses_aps_and_clients(self, tmp_path):
        csv_file = tmp_path / "scan-01.csv"
        csv_file.write_text(SAMPLE_AIRODUMP_CSV)
        aps, clients = _parse_airodump_csv(str(csv_file))
        assert len(aps) == 2
        assert aps[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert aps[0]["essid"] == "TestNetwork"
        assert aps[0]["channel"] == "6"
        assert aps[0]["encryption"] == "WPA2"
        assert aps[1]["essid"] == "OpenNet"
        assert len(clients) == 1
        assert clients[0]["mac"] == "AA:11:BB:22:CC:33"
        assert clients[0]["associated_bssid"] == "AA:BB:CC:DD:EE:FF"

    def test_missing_file_returns_empty(self):
        aps, clients = _parse_airodump_csv("/nonexistent/file.csv")
        assert aps == []
        assert clients == []

    def test_empty_file_returns_empty(self, tmp_path):
        csv_file = tmp_path / "empty.csv"
        csv_file.write_text("")
        aps, clients = _parse_airodump_csv(str(csv_file))
        assert aps == []
        assert clients == []


class TestScanAccessPoints:
    @patch("redops.modules.active.wireless.scan.time.sleep")
    @patch("redops.modules.active.wireless.scan.subprocess.Popen")
    def test_stores_results_in_context(self, mock_popen, mock_sleep, tmp_path):
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc

        ctx = Context(target="home-lab")
        ctx.add("monitor_interface", "wlan1mon")

        with patch(
            "redops.modules.active.wireless.scan.tempfile.TemporaryDirectory"
        ) as mock_tmpdir:
            mock_tmpdir.return_value.__enter__ = MagicMock(return_value=str(tmp_path))
            mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)

            csv_file = tmp_path / "scan-01.csv"
            csv_file.write_text(SAMPLE_AIRODUMP_CSV)

            result = scan_access_points(ctx, {"duration": 1})

        assert result.get("scan_complete") is True
        assert len(result.get("access_points", [])) == 2
        assert len(result.get("clients", [])) == 1


# ── evil_twin.py ────────────────────────────────────────────────────


class TestEvilTwin:
    @patch("redops.modules.active.wireless.evil_twin.subprocess.Popen")
    @patch("redops.modules.active.wireless.evil_twin.subprocess.run")
    @patch("redops.modules.active.wireless.evil_twin.time.sleep")
    def test_start_evil_twin_success(self, mock_sleep, mock_run, mock_popen):
        from redops.modules.active.wireless.evil_twin import start_evil_twin

        mock_run.return_value = MagicMock(returncode=0)
        mock_popen.return_value = MagicMock()

        ctx = Context(target="home-lab")
        ctx.add(
            "access_points",
            [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "essid": "TestNetwork",
                    "channel": "6",
                    "signal": "-40",
                    "encryption": "WPA2",
                }
            ],
        )

        result = start_evil_twin(ctx, {"ap_interface": "wlan0"})
        assert result.get("evil_twin_active") is True
        assert result.get("evil_twin_essid") == "TestNetwork"
        assert result.get("evil_twin_channel") == "6"
        assert result.get("ap_subnet") == "192.168.99.0/24"

    def test_start_evil_twin_no_aps(self):
        from redops.modules.active.wireless.evil_twin import start_evil_twin

        ctx = Context(target="home-lab")
        result = start_evil_twin(ctx)
        assert result.get("evil_twin_active") is False

    @patch("redops.modules.active.wireless.evil_twin.subprocess.run")
    def test_stop_evil_twin(self, mock_run):
        from redops.modules.active.wireless.evil_twin import stop_evil_twin

        mock_run.return_value = MagicMock(returncode=0)
        mock_proc = MagicMock()

        ctx = Context(target="home-lab")
        ctx.add("hostapd_proc", mock_proc)
        ctx.add("dnsmasq_proc", mock_proc)

        result = stop_evil_twin(ctx)
        assert result.get("evil_twin_active") is False
        assert mock_proc.terminate.call_count == 2


class TestSelectTarget:
    def test_selects_by_bssid(self):
        from redops.modules.active.wireless.evil_twin import _select_target

        aps = [
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "essid": "Net1",
                "channel": "6",
                "signal": "-80",
            },
            {
                "bssid": "11:22:33:44:55:66",
                "essid": "Net2",
                "channel": "11",
                "signal": "-40",
            },
        ]
        result = _select_target(aps, "11:22:33:44:55:66")
        assert result["essid"] == "Net2"

    def test_selects_highest_signal(self):
        from redops.modules.active.wireless.evil_twin import _select_target

        aps = [
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "essid": "Weak",
                "channel": "6",
                "signal": "-80",
            },
            {
                "bssid": "11:22:33:44:55:66",
                "essid": "Strong",
                "channel": "11",
                "signal": "-30",
            },
        ]
        result = _select_target(aps, None)
        assert result["essid"] == "Strong"


# ── deauth.py ───────────────────────────────────────────────────────


class TestDeauthFlood:
    def test_no_scapy_logs_error(self):
        from redops.modules.active.wireless import deauth

        original = deauth.HAS_SCAPY
        try:
            deauth.HAS_SCAPY = False
            ctx = Context(target="home-lab")
            result = deauth.deauth_flood(ctx)
            assert result.get("deauth_active") is False
            error_logs = result.get_logs(level="ERROR")
            assert any("Scapy" in log["message"] for log in error_logs)
        finally:
            deauth.HAS_SCAPY = original

    def test_no_target_bssid_logs_error(self):
        from redops.modules.active.wireless import deauth

        original = deauth.HAS_SCAPY
        try:
            deauth.HAS_SCAPY = True
            ctx = Context(target="home-lab")
            result = deauth.deauth_flood(ctx)
            error_logs = result.get_logs(level="ERROR")
            assert any("BSSID" in log["message"] for log in error_logs)
        finally:
            deauth.HAS_SCAPY = original
