"""Tests for AI agent, planner, and tool registry."""

from unittest.mock import patch

from redops.core.context import Context
from redops.modules.ai.agent import _parse_agent_response, run_agent
from redops.modules.ai.planner import build_attack_surface_summary
from redops.modules.ai.tools import TOOL_REGISTRY, get_tool_descriptions


# ── tools.py ────────────────────────────────────────────────────────


class TestToolRegistry:
    def test_all_tools_have_fn(self):
        for name, info in TOOL_REGISTRY.items():
            assert callable(info["fn"]), f"{name} fn is not callable"

    def test_all_tools_have_description(self):
        for name, info in TOOL_REGISTRY.items():
            assert info["description"], f"{name} missing description"

    def test_get_tool_descriptions_returns_string(self):
        result = get_tool_descriptions()
        assert isinstance(result, str)
        assert "scan_access_points" in result
        assert "check_cves" in result

    def test_registry_has_expected_tools(self):
        expected = {
            "scan_access_points",
            "start_evil_twin",
            "deauth_flood",
            "discover_hosts",
            "scan_ports",
            "check_cves",
        }
        assert set(TOOL_REGISTRY.keys()) == expected


# ── planner.py ──────────────────────────────────────────────────────


class TestBuildAttackSurfaceSummary:
    def test_empty_context(self):
        ctx = Context(target="home-lab")
        result = build_attack_surface_summary(ctx)
        assert "CURRENT ATTACK SURFACE" in result
        assert "END ATTACK SURFACE" in result

    def test_includes_access_points(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "access_points",
            [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "essid": "TestNet",
                    "channel": "6",
                    "encryption": "WPA2",
                    "signal": "-40",
                },
            ],
        )
        result = build_attack_surface_summary(ctx)
        assert "ACCESS POINTS" in result
        assert "TestNet" in result

    def test_includes_cve_findings(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "cve_findings",
            [
                {
                    "id": "CVE-2026-24061",
                    "cvss": 9.8,
                    "ip": "192.168.99.50",
                    "port": "23",
                    "description": "telnetd auth bypass",
                },
            ],
        )
        result = build_attack_surface_summary(ctx)
        assert "CVE FINDINGS" in result
        assert "CVE-2026-24061" in result

    def test_includes_high_value_targets(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "high_value_targets",
            [
                {
                    "id": "CVE-2026-24061",
                    "cvss": 9.8,
                    "ip": "192.168.99.50",
                    "port": "23",
                },
            ],
        )
        result = build_attack_surface_summary(ctx)
        assert "HIGH VALUE TARGETS" in result
        assert "***" in result

    def test_caps_items_per_section(self):
        ctx = Context(target="home-lab")
        ctx.add(
            "access_points",
            [
                {
                    "bssid": f"AA:BB:CC:DD:EE:{i:02X}",
                    "essid": f"Net{i}",
                    "channel": "6",
                    "encryption": "WPA2",
                    "signal": "-40",
                }
                for i in range(20)
            ],
        )
        result = build_attack_surface_summary(ctx)
        assert "20 found" in result
        # Only 10 entries shown
        assert result.count("AA:BB:CC:DD:EE:") == 10


# ── agent.py ────────────────────────────────────────────────────────


class TestParseAgentResponse:
    def test_valid_json(self):
        result = _parse_agent_response(
            '{"thought": "test", "action": "scan_access_points", "params": {}}'
        )
        assert result["action"] == "scan_access_points"

    def test_json_with_prose(self):
        result = _parse_agent_response(
            'Here is my response: {"thought": "test", "action": "COMPLETE", "summary": "done"}'
        )
        assert result["action"] == "COMPLETE"

    def test_invalid_json(self):
        result = _parse_agent_response("this is not json at all")
        assert result is None

    def test_empty_string(self):
        result = _parse_agent_response("")
        assert result is None


class TestRunAgent:
    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_completes(self, mock_ollama):
        mock_ollama.return_value = (
            '{"thought": "No APs to scan", "action": "COMPLETE", '
            '"summary": "Chain complete"}'
        )

        ctx = Context(target="home-lab")
        result = run_agent(ctx, {"max_iterations": 3})

        assert result.get("agent_complete") is True
        assert result.get("agent_summary") == "Chain complete"
        assert len(result.get("agent_log", [])) == 1

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_calls_tool(self, mock_ollama):
        mock_ollama.side_effect = [
            '{"thought": "Need to check CVEs", "action": "check_cves", "params": {}}',
            '{"thought": "Done", "action": "COMPLETE", "summary": "CVEs checked"}',
        ]

        ctx = Context(target="home-lab")
        ctx.add("port_scan_results", [])
        result = run_agent(ctx, {"max_iterations": 5})

        assert result.get("agent_complete") is True
        assert len(result.get("agent_log", [])) == 2

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_max_iterations(self, mock_ollama):
        mock_ollama.return_value = (
            '{"thought": "scanning", "action": "check_cves", "params": {}}'
        )

        ctx = Context(target="home-lab")
        ctx.add("port_scan_results", [])
        result = run_agent(ctx, {"max_iterations": 2})

        assert result.get("agent_complete") is False
        assert result.get("agent_summary") == "Max iterations reached."
        assert len(result.get("agent_log", [])) == 2

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_handles_empty_response(self, mock_ollama):
        mock_ollama.return_value = ""

        ctx = Context(target="home-lab")
        result = run_agent(ctx, {"max_iterations": 3})

        assert result.get("agent_complete") is False
        error_logs = result.get_logs(level="ERROR")
        assert any("empty response" in log["message"] for log in error_logs)

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_handles_unparseable_response(self, mock_ollama):
        mock_ollama.return_value = "gobbledygook"

        ctx = Context(target="home-lab")
        result = run_agent(ctx, {"max_iterations": 3})

        assert result.get("agent_complete") is False

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_handles_unknown_tool(self, mock_ollama):
        mock_ollama.side_effect = [
            '{"thought": "test", "action": "nonexistent_tool", "params": {}}',
            '{"thought": "done", "action": "COMPLETE", "summary": "done"}',
        ]

        ctx = Context(target="home-lab")
        result = run_agent(ctx, {"max_iterations": 5})

        warning_logs = result.get_logs(level="WARNING")
        assert any("Unknown tool" in log["message"] for log in warning_logs)

    def test_agent_no_requests(self):
        from redops.modules.ai import agent

        original = agent.HAS_REQUESTS
        try:
            agent.HAS_REQUESTS = False
            ctx = Context(target="home-lab")
            result = agent.run_agent(ctx)
            assert result.get("agent_complete") is False
        finally:
            agent.HAS_REQUESTS = original
