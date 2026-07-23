"""Tests for AI agent, planner, and tool registry."""

from unittest.mock import patch, MagicMock

from redops.core.context import Context
from redops.modules.active.authorization import record_authorization
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
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
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
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
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
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        ctx.add("port_scan_results", [])
        result = run_agent(ctx, {"max_iterations": 2})

        assert result.get("agent_complete") is False
        assert result.get("agent_summary") == "Max iterations reached."
        assert len(result.get("agent_log", [])) == 2

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_handles_empty_response(self, mock_ollama):
        mock_ollama.return_value = ""

        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        result = run_agent(ctx, {"max_iterations": 3})

        assert result.get("agent_complete") is False
        error_logs = result.get_logs(level="ERROR")
        assert any("empty response" in log["message"] for log in error_logs)

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_handles_unparseable_response(self, mock_ollama):
        mock_ollama.return_value = "gobbledygook"

        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        result = run_agent(ctx, {"max_iterations": 3})

        assert result.get("agent_complete") is False

    @patch("redops.modules.ai.agent._call_ollama")
    def test_agent_handles_unknown_tool(self, mock_ollama):
        mock_ollama.side_effect = [
            '{"thought": "test", "action": "nonexistent_tool", "params": {}}',
            '{"thought": "done", "action": "COMPLETE", "summary": "done"}',
        ]

        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        result = run_agent(ctx, {"max_iterations": 5})

        warning_logs = result.get_logs(level="WARNING")
        assert any("Unknown tool" in log["message"] for log in warning_logs)

    def test_agent_no_requests(self):
        from redops.modules.ai import agent

        original = agent.HAS_REQUESTS
        try:
            agent.HAS_REQUESTS = False
            ctx = Context(target="home-lab")
            record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
            result = agent.run_agent(ctx)
            assert result.get("agent_complete") is False
        finally:
            agent.HAS_REQUESTS = original


# ── qwen-uncensored preset ──────────────────────────────────────────


class TestQwenUncensoredPreset:
    """Smoke tests for the Qwen-uncensored AI preset wired into the ReAct agent."""

    def test_preset_registered(self):
        from redops.modules.ai.presets import AI_PRESETS, get_preset

        assert "qwen-uncensored" in AI_PRESETS
        preset = get_preset("qwen-uncensored")
        assert preset["provider"] == "ollama"
        assert preset["model"].startswith("huihui_ai/qwen")
        assert 0.0 <= preset["temperature"] <= 1.0
        assert preset["max_tokens"] > 0
        assert preset["options"]["num_ctx"] >= 8192

    def test_preset_unknown_raises(self):
        from redops.modules.ai.presets import get_preset
        import pytest

        with pytest.raises(KeyError):
            get_preset("does-not-exist")

    def test_all_qwen_presets_present(self):
        from redops.modules.ai.presets import AI_PRESETS

        expected = {
            "qwen-uncensored",
            "qwen-uncensored-small",
            "qwen-uncensored-large",
            "qwen3-uncensored",
            "qwen3.6-aggressive",
        }
        assert expected.issubset(set(AI_PRESETS))

    def test_installed_hauhaucs_preset(self):
        """The qwen3.6-aggressive preset points at the locally-pulled HauhauCS model."""
        from redops.modules.ai.presets import get_preset

        preset = get_preset("qwen3.6-aggressive")
        assert preset["provider"] == "ollama"
        assert preset["model"].startswith("hf.co/HauhauCS/")
        assert 0.0 <= preset["temperature"] <= 1.0
        assert preset["max_tokens"] > 0
        assert preset["options"]["num_ctx"] >= 8192

    @patch("redops.modules.ai.agent.requests")
    def test_agent_uses_preset_model_and_temperature(self, mock_requests):
        """Preset model + temperature + options should reach the Ollama payload."""
        from redops.modules.ai.presets import get_preset

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": (
                '{"thought": "no surface", "action": "COMPLETE", "summary": "done"}'
            )
        }
        mock_response.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_response
        mock_requests.RequestException = Exception

        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        result = run_agent(ctx, {"preset": "qwen-uncensored", "max_iterations": 1})

        assert result.get("agent_complete") is True
        assert mock_requests.post.called
        _, kwargs = mock_requests.post.call_args
        payload = kwargs["json"]
        preset = get_preset("qwen-uncensored")
        assert payload["model"] == preset["model"]
        assert payload["format"] == "json"
        assert payload["options"]["temperature"] == preset["temperature"]
        assert payload["options"]["num_ctx"] == preset["options"]["num_ctx"]

    @patch("redops.modules.ai.agent.requests")
    def test_explicit_params_override_preset(self, mock_requests):
        """An explicit model/temperature should win over the preset's values."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": ('{"thought": "x", "action": "COMPLETE", "summary": "x"}')
        }
        mock_response.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_response
        mock_requests.RequestException = Exception

        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        run_agent(
            ctx,
            {
                "preset": "qwen-uncensored",
                "model": "llama3.1:8b",
                "temperature": 0.9,
                "max_iterations": 1,
            },
        )

        _, kwargs = mock_requests.post.call_args
        payload = kwargs["json"]
        assert payload["model"] == "llama3.1:8b"
        assert payload["options"]["temperature"] == 0.9

    def test_unknown_preset_logs_error(self):
        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        result = run_agent(ctx, {"preset": "bogus-preset"})
        assert result.get("agent_complete") is False
        error_logs = result.get_logs(level="ERROR")
        assert any("bogus-preset" in log["message"] for log in error_logs)

    @patch("redops.modules.ai.agent.requests")
    def test_react_loop_completes_with_preset(self, mock_requests):
        """End-to-end: preset drives a 2-step ReAct loop to COMPLETE."""
        mock_response_1 = MagicMock()
        mock_response_1.json.return_value = {
            "response": (
                '{"thought": "scan CVEs", "action": "check_cves", "params": {}}'
            )
        }
        mock_response_2 = MagicMock()
        mock_response_2.json.return_value = {
            "response": (
                '{"thought": "chain done", "action": "COMPLETE", '
                '"summary": "CVEs assessed"}'
            )
        }
        for r in (mock_response_1, mock_response_2):
            r.raise_for_status = MagicMock()
        mock_requests.post.side_effect = [mock_response_1, mock_response_2]
        mock_requests.RequestException = Exception

        ctx = Context(target="home-lab")
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")
        ctx.add("port_scan_results", [])
        result = run_agent(ctx, {"preset": "qwen-uncensored", "max_iterations": 5})

        assert result.get("agent_complete") is True
        assert result.get("agent_summary") == "CVEs assessed"
        assert len(result.get("agent_log", [])) == 2
        assert mock_requests.post.call_count == 2
