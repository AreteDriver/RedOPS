"""Tests for active network modules — arp_scan, port_scan."""

from unittest.mock import MagicMock, patch

from redops.core.context import Context
from redops.modules.active.network.arp_scan import discover_hosts
from redops.modules.active.network.port_scan import _parse_nmap_xml, scan_ports


# ── arp_scan.py ─────────────────────────────────────────────────────


class TestDiscoverHosts:
    @patch("redops.modules.active.network.arp_scan.time.sleep")
    @patch("redops.modules.active.network.arp_scan.subprocess.run")
    def test_discovers_hosts(self, mock_run, mock_sleep):
        mock_run.return_value = MagicMock(
            stdout=(
                "Interface: wlan0, datalink: EN10MB\n"
                "192.168.99.50\t00:11:22:33:44:55\tSamsung Electronics\n"
                "192.168.99.51\tab:cd:ef:01:23:45\tApple Inc\n"
            ),
            returncode=0,
        )

        ctx = Context(target="home-lab")
        ctx.add("ap_subnet", "192.168.99.0/24")
        result = discover_hosts(ctx, {"wait": 0})

        hosts = result.get("live_hosts", [])
        assert len(hosts) == 2
        assert hosts[0]["ip"] == "192.168.99.50"
        assert hosts[0]["mac"] == "00:11:22:33:44:55"
        assert hosts[0]["vendor"] == "Samsung Electronics"
        assert hosts[1]["ip"] == "192.168.99.51"

    @patch("redops.modules.active.network.arp_scan.time.sleep")
    @patch("redops.modules.active.network.arp_scan.subprocess.run")
    def test_no_hosts_found(self, mock_run, mock_sleep):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        ctx = Context(target="home-lab")
        result = discover_hosts(ctx, {"wait": 0})
        assert result.get("live_hosts") == []

    @patch("redops.modules.active.network.arp_scan.time.sleep")
    @patch("redops.modules.active.network.arp_scan.subprocess.run")
    def test_uses_context_subnet(self, mock_run, mock_sleep):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        ctx = Context(target="home-lab")
        ctx.add("ap_subnet", "10.0.0.0/24")
        discover_hosts(ctx, {"wait": 0})
        call_args = mock_run.call_args[0][0]
        assert "10.0.0.0/24" in call_args


# ── port_scan.py ────────────────────────────────────────────────────


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnetd" product="GNU inetutils" version="2.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestParseNmapXml:
    def test_parses_open_ports(self):
        ports = _parse_nmap_xml(SAMPLE_NMAP_XML)
        assert len(ports) == 2
        assert ports[0]["port"] == "22"
        assert ports[0]["service"] == "ssh"
        assert ports[0]["product"] == "OpenSSH"
        assert ports[1]["port"] == "23"
        assert ports[1]["service"] == "telnetd"

    def test_ignores_closed_ports(self):
        ports = _parse_nmap_xml(SAMPLE_NMAP_XML)
        port_ids = [p["port"] for p in ports]
        assert "80" not in port_ids

    def test_handles_invalid_xml(self):
        ports = _parse_nmap_xml("not xml at all")
        assert ports == []

    def test_handles_empty_string(self):
        ports = _parse_nmap_xml("")
        assert ports == []


class TestScanPorts:
    @patch("redops.modules.active.network.port_scan.subprocess.run")
    def test_scans_all_hosts(self, mock_run):
        mock_run.return_value = MagicMock(stdout=SAMPLE_NMAP_XML, returncode=0)
        ctx = Context(target="home-lab")
        ctx.add(
            "live_hosts",
            [
                {"ip": "192.168.99.50", "mac": "00:11:22:33:44:55", "vendor": "Test"},
                {"ip": "192.168.99.51", "mac": "ab:cd:ef:01:23:45", "vendor": "Test"},
            ],
        )

        result = scan_ports(ctx)
        scan_results = result.get("port_scan_results", [])
        assert len(scan_results) == 2
        assert scan_results[0]["ip"] == "192.168.99.50"
        assert len(scan_results[0]["open_ports"]) == 2

    def test_no_hosts_logs_error(self):
        ctx = Context(target="home-lab")
        result = scan_ports(ctx)
        error_logs = result.get_logs(level="ERROR")
        assert any("No live hosts" in log["message"] for log in error_logs)
