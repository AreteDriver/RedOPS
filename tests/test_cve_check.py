"""Tests for CVE cross-reference module."""

from redops.core.context import Context
from redops.modules.active.exploit.cve_check import check_cves


class TestCheckCves:
    def test_finds_telnetd_cve(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "port_scan_results",
            [
                {
                    "ip": "192.168.99.50",
                    "open_ports": [
                        {
                            "port": "23",
                            "protocol": "tcp",
                            "service": "telnetd",
                            "version": "2.4",
                            "product": "GNU inetutils",
                        },
                    ],
                },
            ],
        )

        result = check_cves(ctx)
        findings = result.get("cve_findings", [])
        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2026-24061"
        assert findings[0]["cvss"] == 9.8
        assert findings[0]["ip"] == "192.168.99.50"

    def test_high_value_targets(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "port_scan_results",
            [
                {
                    "ip": "192.168.99.50",
                    "open_ports": [
                        {
                            "port": "23",
                            "protocol": "tcp",
                            "service": "telnetd",
                            "version": "2.4",
                            "product": "",
                        },
                    ],
                },
            ],
        )

        result = check_cves(ctx)
        hvt = result.get("high_value_targets", [])
        assert len(hvt) == 1
        assert hvt[0]["cvss"] >= 9.0

    def test_no_matches(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "port_scan_results",
            [
                {
                    "ip": "192.168.99.50",
                    "open_ports": [
                        {
                            "port": "22",
                            "protocol": "tcp",
                            "service": "ssh",
                            "version": "8.9p1",
                            "product": "OpenSSH",
                        },
                    ],
                },
            ],
        )

        result = check_cves(ctx)
        assert result.get("cve_findings") == []
        assert result.get("high_value_targets") == []

    def test_empty_scan_results(self):
        ctx = Context(target="home-lab")
        result = check_cves(ctx)
        assert result.get("cve_findings") == []
        assert result.get("high_value_targets") == []

    def test_matches_on_product_field(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "port_scan_results",
            [
                {
                    "ip": "192.168.99.50",
                    "open_ports": [
                        {
                            "port": "23",
                            "protocol": "tcp",
                            "service": "telnet",
                            "version": "2.4",
                            "product": "telnetd daemon",
                        },
                    ],
                },
            ],
        )

        result = check_cves(ctx)
        assert len(result.get("cve_findings", [])) == 1
