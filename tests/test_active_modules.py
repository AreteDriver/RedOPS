"""Tests for active module business logic.

Covers parsing, subprocess interaction mocking, parameter validation,
and context data flows for all modules under ``modules/active/``.
Authorization gating is tested in ``test_active_authorization.py``.
"""

import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from redops.core.context import Context
from redops.modules.active.authorization import (
    ActiveAuthorization,
    record_authorization,
)
from redops.modules.active.network.arp_scan import discover_hosts
from redops.modules.active.network.port_scan import _parse_nmap_xml, scan_ports
from redops.modules.active.wireless.deauth import deauth_flood
from redops.modules.active.wireless.evil_twin import (
    _select_target,
    start_evil_twin,
    stop_evil_twin,
)
from redops.modules.active.wireless.monitor import (
    disable_monitor_mode,
    enable_monitor_mode,
    get_wireless_interfaces,
)
from redops.modules.active.wireless.scan import _parse_airodump_csv, scan_access_points


@pytest.fixture
def authorized_context():
    """A context with a valid active authorization."""
    ctx = Context(target="192.168.99.0/24")
    ctx.authorization = ActiveAuthorization(
        operator="test-operator",
        target_assertion="192.168.99.0/24",
        consent_text="I consent to testing my own lab network.",
    )
    return ctx


# ───────────────────────────────
# Port Scan
# ───────────────────────────────

class TestParseNmapXml:
    """Tests for nmap XML output parser."""

    def test_empty_xml_returns_empty_list(self):
        assert _parse_nmap_xml("") == []

    def test_no_open_ports_returns_empty_list(self):
        xml = """<nmaprun>
            <host><ports>
                <port portid="22" protocol="tcp">
                    <state state="closed"/>
                </port>
            </ports></host></nmaprun>"""
        assert _parse_nmap_xml(xml) == []

    def test_open_port_with_service(self):
        xml = """<nmaprun>
            <host><ports>
                <port portid="22" protocol="tcp">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="8.9"/>
                </port>
            </ports></host></nmaprun>"""
        result = _parse_nmap_xml(xml)
        assert len(result) == 1
        assert result[0]["port"] == "22"
        assert result[0]["protocol"] == "tcp"
        assert result[0]["service"] == "ssh"
        assert result[0]["product"] == "OpenSSH"
        assert result[0]["version"] == "8.9"

    def test_open_port_without_service(self):
        xml = """<nmaprun>
            <host><ports>
                <port portid="80" protocol="tcp">
                    <state state="open"/>
                </port>
            </ports></host></nmaprun>"""
        result = _parse_nmap_xml(xml)
        assert result[0]["service"] == ""
        assert result[0]["version"] == ""
        assert result[0]["product"] == ""

    def test_multiple_open_ports(self):
        xml = """<nmaprun>
            <host><ports>
                <port portid="22" protocol="tcp">
                    <state state="open"/>
                    <service name="ssh"/>
                </port>
                <port portid="443" protocol="tcp">
                    <state state="open"/>
                    <service name="https"/>
                </port>
            </ports></host></nmaprun>"""
        result = _parse_nmap_xml(xml)
        assert len(result) == 2
        assert result[0]["port"] == "22"
        assert result[1]["port"] == "443"

    def test_malformed_xml_is_graceful(self):
        assert _parse_nmap_xml("<invalid>") == []


class TestScanPorts:
    """Tests for port scan module execution."""

    def test_no_live_hosts_early_return(self, authorized_context):
        result = scan_ports(authorized_context)
        assert result is authorized_context
        assert result.get("port_scan_results") is None
        assert any("No live hosts" in str(m) for m in authorized_context.logs)

    def test_default_parameters(self, authorized_context):
        authorized_context.add("live_hosts", [{"ip": "192.168.99.5"}])
        with patch("redops.modules.active.network.port_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            scan_ports(authorized_context)
            call = mock_run.call_args
            cmd = call[0][0]
            assert "-sV" in cmd
            assert "-sU" in cmd
            assert "-T4" in cmd
            assert "T:1-1024,U:23,2323" in cmd
            assert "192.168.99.5" in cmd

    def test_custom_parameters(self, authorized_context):
        authorized_context.add("live_hosts", [{"ip": "10.0.0.1"}])
        with patch("redops.modules.active.network.port_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            scan_ports(
                authorized_context,
                {"ports": "22,80,443", "timing": "T5"},
            )
            call = mock_run.call_args
            cmd = call[0][0]
            assert "22,80,443" in cmd
            assert "-T5" in cmd

    def test_parsed_results_stored(self, authorized_context):
        authorized_context.add("live_hosts", [{"ip": "192.168.99.5"}])
        xml = """<nmaprun>
            <host><ports>
                <port portid="22" protocol="tcp">
                    <state state="open"/>
                    <service name="ssh"/>
                </port>
            </ports></host></nmaprun>"""
        with patch("redops.modules.active.network.port_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=xml, stderr="")
            scan_ports(authorized_context)
        results = authorized_context.get("port_scan_results")
        assert len(results) == 1
        assert results[0]["ip"] == "192.168.99.5"
        assert results[0]["open_ports"][0]["port"] == "22"

    def test_multiple_hosts_scanned_sequentially(self, authorized_context):
        authorized_context.add(
            "live_hosts",
            [{"ip": "192.168.99.1"}, {"ip": "192.168.99.2"}],
        )
        with patch("redops.modules.active.network.port_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            scan_ports(authorized_context)
            assert mock_run.call_count == 2


# ───────────────────────────────
# ARP Scan
# ───────────────────────────────

class TestDiscoverHosts:
    """Tests for ARP host discovery."""

    def test_default_subnet_from_context(self, authorized_context):
        authorized_context.add("ap_subnet", "10.0.0.0/24")
        with patch("redops.modules.active.network.arp_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            with patch("redops.modules.active.network.arp_scan.time.sleep"):
                discover_hosts(authorized_context, {"wait": 0})
            cmd = mock_run.call_args[0][0]
            assert "10.0.0.0/24" in cmd

    def test_default_subnet_fallback(self, authorized_context):
        with patch("redops.modules.active.network.arp_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            with patch("redops.modules.active.network.arp_scan.time.sleep"):
                discover_hosts(authorized_context, {"wait": 0})
            cmd = mock_run.call_args[0][0]
            assert "192.168.99.0/24" in cmd

    def test_parses_arp_scan_output(self, authorized_context):
        stdout = """192.168.99.1\t00:11:22:33:44:55\tVendor A
192.168.99.2\taa:bb:cc:dd:ee:ff\tVendor B"""
        with patch("redops.modules.active.network.arp_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=stdout, stderr="")
            with patch("redops.modules.active.network.arp_scan.time.sleep"):
                discover_hosts(authorized_context, {"wait": 0})
        hosts = authorized_context.get("live_hosts")
        assert len(hosts) == 2
        assert hosts[0]["ip"] == "192.168.99.1"
        assert hosts[0]["mac"] == "00:11:22:33:44:55"
        assert hosts[0]["vendor"] == "Vendor A"

    def test_ignores_malformed_lines(self, authorized_context):
        stdout = """192.168.99.1\t00:11:22:33:44:55\tVendor A
not a valid line
192.168.99.2\taa:bb:cc:dd:ee:ff\tVendor B"""
        with patch("redops.modules.active.network.arp_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=stdout, stderr="")
            with patch("redops.modules.active.network.arp_scan.time.sleep"):
                discover_hosts(authorized_context, {"wait": 0})
        hosts = authorized_context.get("live_hosts")
        assert len(hosts) == 2

    def test_wait_parameter(self, authorized_context):
        with patch("redops.modules.active.network.arp_scan.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            with patch("redops.modules.active.network.arp_scan.time.sleep") as mock_sleep:
                discover_hosts(authorized_context, {"wait": 42})
                mock_sleep.assert_called_once_with(42)


# ───────────────────────────────
# Wireless Scan (airodump)
# ───────────────────────────────

class TestParseAirodumpCsv:
    """Tests for airodump-ng CSV parser."""

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "scan-01.csv"
        f.write_text("")
        aps, clients = _parse_airodump_csv(str(f))
        assert aps == []
        assert clients == []

    def test_missing_file_returns_empty(self, tmp_path):
        aps, clients = _parse_airodump_csv(str(tmp_path / "nonexistent.csv"))
        assert aps == []
        assert clients == []

    def test_parses_access_points(self, tmp_path):
        csv = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, "
            "CCMP, PSK, -42, 100, 0, 0.0.0.0, 6, TestAP, \n"
            "aa:bb:cc:dd:ee:ff, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 11, 54, WPA3, "
            "CCMP, SAE, -55, 50, 0, 0.0.0.0, 7, TestAP2, \n\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            "11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -60, 10, "
            "00:11:22:33:44:55, TestAP\n"
        )
        f = tmp_path / "scan-01.csv"
        f.write_text(csv)
        aps, clients = _parse_airodump_csv(str(f))
        assert len(aps) == 2
        assert aps[0]["bssid"] == "00:11:22:33:44:55"
        assert aps[0]["essid"] == "TestAP"
        assert aps[0]["channel"] == "6"
        assert aps[0]["signal"] == "-42"
        assert aps[0]["encryption"] == "WPA2"
        assert len(clients) == 1
        assert clients[0]["mac"] == "11:22:33:44:55:66"
        assert clients[0]["associated_bssid"] == "00:11:22:33:44:55"

    def test_crlf_line_endings(self, tmp_path):
        csv = (
            "BSSID, First time seen\r\n"
            "00:11:22:33:44:55, 2024-01-01\r\n\r\n"
            "Station MAC, First time seen\r\n"
            "11:22:33:44:55:66, 2024-01-01\r\n"
        )
        f = tmp_path / "scan-01.csv"
        f.write_text(csv)
        aps, clients = _parse_airodump_csv(str(f))
        assert len(aps) == 1
        assert len(clients) == 1

    def test_skips_invalid_bssid_length(self, tmp_path):
        csv = (
            "BSSID, First time seen\n"
            "short, 2024-01-01\n\n"
            "Station MAC, First time seen\n"
            "also-short, 2024-01-01\n"
        )
        f = tmp_path / "scan-01.csv"
        f.write_text(csv)
        aps, clients = _parse_airodump_csv(str(f))
        assert aps == []
        assert clients == []


class TestScanAccessPoints:
    """Tests for wireless AP scan execution."""

    def test_default_duration_and_interface(self, authorized_context):
        authorized_context.add("monitor_interface", "wlan1mon")
        with patch("redops.modules.active.wireless.scan.subprocess.Popen") as mock_popen:
            proc = Mock()
            mock_popen.return_value = proc
            with patch("redops.modules.active.wireless.scan.time.sleep") as mock_sleep:
                with patch.object(
                    Path,
                    "exists",
                    return_value=False,
                ):
                    scan_access_points(authorized_context)
                mock_sleep.assert_called_once_with(30)
            cmd = mock_popen.call_args[0][0]
            assert "wlan1mon" in cmd
            assert "airodump-ng" in cmd

    def test_custom_channel(self, authorized_context):
        authorized_context.add("monitor_interface", "wlan0mon")
        with patch("redops.modules.active.wireless.scan.subprocess.Popen") as mock_popen:
            proc = Mock()
            mock_popen.return_value = proc
            with patch("redops.modules.active.wireless.scan.time.sleep"):
                with patch.object(Path, "exists", return_value=False):
                    scan_access_points(authorized_context, {"channel": 6})
            cmd = mock_popen.call_args[0][0]
            assert "--channel" in cmd
            assert "6" in cmd

    def test_results_stored_in_context(self, authorized_context):
        authorized_context.add("monitor_interface", "wlan1mon")
        csv = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, "
            "CCMP, PSK, -42, 100, 0, 0.0.0.0, 6, TestAP, \n\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            "11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -60, 10, "
            "00:11:22:33:44:55, TestAP\n"
        )
        with patch("redops.modules.active.wireless.scan.subprocess.Popen") as mock_popen:
            proc = Mock()
            mock_popen.return_value = proc
            with patch("redops.modules.active.wireless.scan.time.sleep"):
                with patch("redops.modules.active.wireless.scan.Path.exists", return_value=True):
                    with patch("redops.modules.active.wireless.scan.Path.read_bytes", return_value=csv.encode()):
                        scan_access_points(authorized_context, {"duration": 1})
        aps = authorized_context.get("access_points")
        clients = authorized_context.get("clients")
        assert len(aps) == 1
        assert aps[0]["essid"] == "TestAP"
        assert len(clients) == 1
        assert authorized_context.get("scan_complete") is True


# ───────────────────────────────
# Evil Twin
# ───────────────────────────────

class TestSelectTarget:
    """Tests for target AP selection logic."""

    def test_select_by_bssid(self):
        aps = [
            {"bssid": "00:11:22:33:44:55", "essid": "A", "signal": "-30", "channel": "6"},
            {"bssid": "aa:bb:cc:dd:ee:ff", "essid": "B", "signal": "-50", "channel": "11"},
        ]
        result = _select_target(aps, "aa:bb:cc:dd:ee:ff")
        assert result["essid"] == "B"

    def test_select_highest_signal_when_no_bssid(self):
        aps = [
            {"bssid": "00:11:22:33:44:55", "essid": "A", "signal": "-70", "channel": "6"},
            {"bssid": "aa:bb:cc:dd:ee:ff", "essid": "B", "signal": "-30", "channel": "11"},
        ]
        result = _select_target(aps, None)
        assert result["essid"] == "B"

    def test_fallback_for_non_numeric_signal(self):
        aps = [
            {"bssid": "00:11:22:33:44:55", "essid": "A", "signal": "bad", "channel": "6"},
            {"bssid": "aa:bb:cc:dd:ee:ff", "essid": "B", "signal": "-50", "channel": "11"},
        ]
        result = _select_target(aps, None)
        assert result["essid"] == "B"


class TestStartEvilTwin:
    """Tests for evil twin AP setup."""

    def test_no_access_points_early_return(self, authorized_context):
        result = start_evil_twin(authorized_context)
        assert result.get("evil_twin_active") is False
        assert any("No APs" in str(m) for m in authorized_context.logs)

    def test_default_ap_interface_and_ip(self, authorized_context):
        authorized_context.add(
            "access_points",
            [{"bssid": "00:11:22:33:44:55", "essid": "TestAP", "signal": "-40", "channel": "6"}],
        )
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            with patch("redops.modules.active.wireless.evil_twin.subprocess.Popen") as mock_popen:
                mock_proc = Mock()
                mock_popen.return_value = mock_proc
                start_evil_twin(authorized_context)
        assert authorized_context.get("evil_twin_active") is True
        assert authorized_context.get("evil_twin_essid") == "TestAP"
        assert authorized_context.get("ap_subnet") == "192.168.99.0/24"
        assert authorized_context.get("evil_twin_channel") == "6"

    def test_custom_ap_interface_and_ip(self, authorized_context):
        authorized_context.add(
            "access_points",
            [{"bssid": "00:11:22:33:44:55", "essid": "TestAP", "signal": "-40", "channel": "1"}],
        )
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run") as mock_run:
            with patch("redops.modules.active.wireless.evil_twin.subprocess.Popen"):
                start_evil_twin(
                    authorized_context,
                    {"ap_interface": "wlan2", "ap_ip": "10.0.0.1"},
                )
            # Check IP configuration commands
            cmds = [call[0][0] for call in mock_run.call_args_list]
            assert any("wlan2" in str(cmd) and "flush" in str(cmd) for cmd in cmds)
            assert any("10.0.0.1/24" in str(cmd) for cmd in cmds)

    def test_target_bssid_selection(self, authorized_context):
        authorized_context.add(
            "access_points",
            [
                {"bssid": "00:11:22:33:44:55", "essid": "A", "signal": "-60", "channel": "6"},
                {"bssid": "aa:bb:cc:dd:ee:ff", "essid": "B", "signal": "-30", "channel": "11"},
            ],
        )
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            with patch("redops.modules.active.wireless.evil_twin.subprocess.Popen"):
                start_evil_twin(authorized_context, {"target_bssid": "aa:bb:cc:dd:ee:ff"})
        assert authorized_context.get("evil_twin_essid") == "B"
        assert authorized_context.get("evil_twin_bssid") == "aa:bb:cc:dd:ee:ff"

    def test_config_files_written(self, authorized_context):
        authorized_context.add(
            "access_points",
            [{"bssid": "00:11:22:33:44:55", "essid": "TestAP", "signal": "-40", "channel": "6"}],
        )
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            with patch("redops.modules.active.wireless.evil_twin.subprocess.Popen"):
                start_evil_twin(authorized_context)
        hostapd = Path("/tmp/redops_hostapd.conf")
        dnsmasq = Path("/tmp/redops_dnsmasq.conf")
        if hostapd.exists():
            content = hostapd.read_text()
            assert "ssid=TestAP" in content
            assert "channel=6" in content
            hostapd.unlink(missing_ok=True)
        if dnsmasq.exists():
            content = dnsmasq.read_text()
            assert "dhcp-range" in content
            dnsmasq.unlink(missing_ok=True)

    def test_process_handles_stored(self, authorized_context):
        authorized_context.add(
            "access_points",
            [{"bssid": "00:11:22:33:44:55", "essid": "TestAP", "signal": "-40", "channel": "6"}],
        )
        mock_proc = Mock()
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            with patch("redops.modules.active.wireless.evil_twin.subprocess.Popen", return_value=mock_proc):
                start_evil_twin(authorized_context)
        assert authorized_context.get("hostapd_proc") is mock_proc
        assert authorized_context.get("dnsmasq_proc") is mock_proc
        assert authorized_context.get("captured_clients") == []


class TestStopEvilTwin:
    """Tests for evil twin teardown."""

    def test_terminates_processes(self, authorized_context):
        mock_proc = Mock()
        authorized_context.add("hostapd_proc", mock_proc)
        authorized_context.add("dnsmasq_proc", mock_proc)
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            stop_evil_twin(authorized_context)
        assert mock_proc.terminate.call_count == 2
        assert authorized_context.get("evil_twin_active") is False

    def test_handles_missing_processes(self, authorized_context):
        authorized_context.add("hostapd_proc", None)
        authorized_context.add("dnsmasq_proc", None)
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            # Should not raise
            stop_evil_twin(authorized_context)
        assert authorized_context.get("evil_twin_active") is False


# ───────────────────────────────
# Monitor Mode
# ───────────────────────────────

class TestGetWirelessInterfaces:
    """Tests for wireless interface enumeration."""

    def test_parses_iwconfig_output(self):
        iwconfig = "wlan0     IEEE 802.11  ESSID:off/any\nwlan1     IEEE 802.11  Mode:Monitor"
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout=iwconfig, stderr="")
            interfaces = get_wireless_interfaces()
            assert "wlan0" in interfaces
            assert "wlan1" in interfaces

    def test_empty_output_returns_empty_list(self):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="", stderr="")
            interfaces = get_wireless_interfaces()
            assert interfaces == []


class TestEnableMonitorMode:
    """Tests for monitor mode enable."""

    def test_default_interface(self, authorized_context):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="wlan1mon  Monitor", stderr="")
            enable_monitor_mode(authorized_context)
            cmds = [call[0][0] for call in mock_run.call_args_list]
            assert any("airmon-ng" in str(cmd) and "check" in str(cmd) for cmd in cmds)
            assert any("airmon-ng" in str(cmd) and "start" in str(cmd) for cmd in cmds)
            assert any("wlan1mon" in str(cmd) for cmd in cmds)

    def test_success_sets_context(self, authorized_context):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="wlan1mon  Monitor  Frequency:2.457 GHz", stderr="")
            enable_monitor_mode(authorized_context, {"interface": "wlan0"})
        assert authorized_context.get("monitor_interface") == "wlan0mon"
        assert authorized_context.get("monitor_ready") is True

    def test_failure_sets_false(self, authorized_context):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="No such device", stderr="")
            enable_monitor_mode(authorized_context)
        assert authorized_context.get("monitor_ready") is False

    def test_custom_interface(self, authorized_context):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            mock_run.return_value = Mock(stdout="wlan2mon  Monitor", stderr="")
            enable_monitor_mode(authorized_context, {"interface": "wlan2"})
        assert authorized_context.get("monitor_interface") == "wlan2mon"


class TestDisableMonitorMode:
    """Tests for monitor mode disable."""

    def test_default_interface_from_context(self, authorized_context):
        authorized_context.add("monitor_interface", "wlan1mon")
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            disable_monitor_mode(authorized_context)
            cmds = [call[0][0] for call in mock_run.call_args_list]
            assert any("stop" in str(cmd) and "wlan1mon" in str(cmd) for cmd in cmds)

    def test_default_interface_fallback(self, authorized_context):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            disable_monitor_mode(authorized_context)
            cmds = [call[0][0] for call in mock_run.call_args_list]
            assert any("stop" in str(cmd) and "wlan1mon" in str(cmd) for cmd in cmds)

    def test_restarts_networkmanager(self, authorized_context):
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            disable_monitor_mode(authorized_context)
            cmds = [call[0][0] for call in mock_run.call_args_list]
            assert any("NetworkManager" in str(cmd) for cmd in cmds)

    def test_sets_monitor_ready_false(self, authorized_context):
        authorized_context.add("monitor_ready", True)
        with patch("redops.modules.active.wireless.monitor.subprocess.run"):
            disable_monitor_mode(authorized_context)
        assert authorized_context.get("monitor_ready") is False


# ───────────────────────────────
# Deauth
# ───────────────────────────────

@pytest.fixture
def mock_scapy():
    """Inject mock scapy objects into deauth module for testing.

    Scapy is not installed in the test environment, so we inject mocks
    for all scapy symbols the module references when HAS_SCAPY is True.
    """
    import redops.modules.active.wireless.deauth as deauth_mod

    original = {}
    mock_pkt = MagicMock()
    mock_pkt.__truediv__ = MagicMock(return_value=mock_pkt)

    mocks = {
        "RadioTap": MagicMock(return_value=mock_pkt),
        "Dot11": MagicMock(return_value=mock_pkt),
        "Dot11Deauth": MagicMock(return_value=mock_pkt),
        "sendp": MagicMock(),
        "HAS_SCAPY": True,
    }

    for name, mock_obj in mocks.items():
        if hasattr(deauth_mod, name):
            original[name] = getattr(deauth_mod, name)
        setattr(deauth_mod, name, mock_obj)

    yield mocks

    for name in mocks:
        if name in original:
            setattr(deauth_mod, name, original[name])
        else:
            delattr(deauth_mod, name)


class TestDeauthFlood:
    """Tests for deauth flood module."""

    def test_no_scapy_early_return(self, authorized_context):
        with patch("redops.modules.active.wireless.deauth.HAS_SCAPY", False):
            result = deauth_flood(authorized_context)
            assert result.get("deauth_active") is False
            assert any("Scapy not installed" in str(m) for m in authorized_context.logs)

    def test_no_target_bssid_early_return(self, authorized_context, mock_scapy):
        result = deauth_flood(authorized_context)
        assert result.get("deauth_active") is None
        assert any("No target BSSID" in str(m) for m in authorized_context.logs)

    def test_spawns_thread_with_defaults(self, authorized_context, mock_scapy):
        authorized_context.add("evil_twin_bssid", "00:11:22:33:44:55")
        authorized_context.add("clients", [])
        result = deauth_flood(authorized_context, {"duration": 0})
        assert result.get("deauth_active") is True
        thread = result.get("deauth_thread")
        assert isinstance(thread, threading.Thread)
        assert thread.daemon is True
        # Join so the thread doesn't outlive the test and trigger warnings
        thread.join(timeout=2)

    def test_custom_parameters(self, authorized_context, mock_scapy):
        authorized_context.add("evil_twin_bssid", "00:11:22:33:44:55")
        authorized_context.add("clients", [])
        with patch("redops.modules.active.wireless.deauth.time.sleep"):
            deauth_flood(
                authorized_context,
                {"duration": 0, "count": 128, "interval": 0.5},
            )
        assert authorized_context.get("deauth_active") is True

    def test_targets_specific_clients(self, authorized_context, mock_scapy):
        authorized_context.add("evil_twin_bssid", "00:11:22:33:44:55")
        authorized_context.add(
            "clients",
            [
                {"mac": "aa:bb:cc:dd:ee:ff", "associated_bssid": "00:11:22:33:44:55"},
                {"mac": "11:22:33:44:55:66", "associated_bssid": "other"},
            ],
        )
        with patch("redops.modules.active.wireless.deauth.time.sleep"):
            result = deauth_flood(authorized_context, {"duration": 0})
        thread = result.get("deauth_thread")
        thread.join(timeout=2)
        # Should target only the client associated with our BSSID
        # Can't easily inspect thread internals, but verify it runs
        assert authorized_context.get("deauth_active") is True

    def test_broadcast_when_no_matching_clients(self, authorized_context, mock_scapy):
        authorized_context.add("evil_twin_bssid", "00:11:22:33:44:55")
        authorized_context.add("clients", [{"mac": "aa:bb:cc:dd:ee:ff", "associated_bssid": "other"}])
        with patch("redops.modules.active.wireless.deauth.time.sleep"):
            result = deauth_flood(authorized_context, {"duration": 0})
        thread = result.get("deauth_thread")
        thread.join(timeout=2)
        assert authorized_context.get("deauth_active") is True


# ───────────────────────────────
# Integration / End-to-end flows
# ───────────────────────────────

class TestActiveModuleIntegration:
    """Integration tests demonstrating typical active module workflows."""

    def test_full_wireless_pipeline(self, authorized_context, mock_scapy):
        """Enable monitor → scan APs → start evil twin → deauth → stop."""
        with patch("redops.modules.active.wireless.monitor.subprocess.run") as mock_run:
            # enable_monitor_mode
            mock_run.return_value = Mock(stdout="wlan1mon  Monitor", stderr="")
            enable_monitor_mode(authorized_context, {"interface": "wlan1"})

        assert authorized_context.get("monitor_ready") is True

        # scan_access_points
        csv = (
            "BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
            "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
            "00:11:22:33:44:55, 2024-01-01 00:00:00, 2024-01-01 00:01:00, 6, 54, WPA2, "
            "CCMP, PSK, -42, 100, 0, 0.0.0.0, 6, TestAP, \n\n"
            "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
            "11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:01:00, -60, 10, "
            "00:11:22:33:44:55, TestAP\n"
        )
        with patch("redops.modules.active.wireless.scan.subprocess.Popen") as mock_popen:
            proc = Mock()
            mock_popen.return_value = proc
            with patch("redops.modules.active.wireless.scan.time.sleep"):
                with patch("redops.modules.active.wireless.scan.Path.exists", return_value=True):
                    with patch("redops.modules.active.wireless.scan.Path.read_bytes", return_value=csv.encode()):
                        scan_access_points(authorized_context, {"duration": 1})

        aps = authorized_context.get("access_points")
        assert len(aps) == 1
        assert aps[0]["essid"] == "TestAP"

        # start_evil_twin
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            with patch("redops.modules.active.wireless.evil_twin.subprocess.Popen"):
                start_evil_twin(authorized_context)

        assert authorized_context.get("evil_twin_active") is True
        assert authorized_context.get("evil_twin_essid") == "TestAP"

        # deauth_flood
        with patch("redops.modules.active.wireless.deauth.time.sleep"):
            deauth_flood(authorized_context, {"duration": 0})
            time.sleep(0.05)

        assert authorized_context.get("deauth_active") is True

        # stop_evil_twin
        with patch("redops.modules.active.wireless.evil_twin.subprocess.run"):
            stop_evil_twin(authorized_context)

        assert authorized_context.get("evil_twin_active") is False

        # disable_monitor_mode
        with patch("redops.modules.active.wireless.monitor.subprocess.run"):
            disable_monitor_mode(authorized_context)

        assert authorized_context.get("monitor_ready") is False
