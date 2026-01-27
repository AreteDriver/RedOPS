"""Tests for the extended MCP tools module."""

import pytest
from unittest.mock import patch
from redops.mcp.tools import (
    EXTENDED_TOOLS,
    MCP_PROMPTS,
    execute_extended_tool,
    get_prompt_content,
)


class TestExtendedTools:
    """Tests for extended tool definitions."""

    def test_tool_definitions_present(self):
        """Test that all expected tools are defined."""
        expected_tools = [
            "redops_check_ip",
            "redops_check_url",
            "redops_cert_transparency",
            "redops_asn_lookup",
            "redops_enumerate_subdomains",
            "redops_export_sarif",
            "redops_export_junit",
            "redops_dashboard_summary",
        ]

        for tool_name in expected_tools:
            assert tool_name in EXTENDED_TOOLS

    def test_tool_has_schema(self):
        """Test that all tools have input schemas."""
        for tool_name, tool_def in EXTENDED_TOOLS.items():
            assert "inputSchema" in tool_def, f"{tool_name} missing inputSchema"
            assert "properties" in tool_def["inputSchema"], (
                f"{tool_name} missing properties"
            )

    def test_tool_has_description(self):
        """Test that all tools have descriptions."""
        for tool_name, tool_def in EXTENDED_TOOLS.items():
            assert "description" in tool_def
            assert len(tool_def["description"]) > 10


class TestExecuteExtendedTool:
    """Tests for execute_extended_tool function."""

    async def test_unknown_tool(self):
        """Test handling of unknown tool."""
        with pytest.raises(ValueError, match="Unknown tool"):
            await execute_extended_tool("unknown_tool", {})

    @patch("redops.mcp.tools._tool_check_ip")
    async def test_routes_to_check_ip(self, mock_tool):
        """Test routing to check_ip tool."""
        mock_tool.return_value = {"result": "ok"}

        await execute_extended_tool("redops_check_ip", {"ip": "8.8.8.8"})

        mock_tool.assert_called_once_with({"ip": "8.8.8.8"})

    @patch("redops.mcp.tools._tool_check_url")
    async def test_routes_to_check_url(self, mock_tool):
        """Test routing to check_url tool."""
        mock_tool.return_value = {"result": "ok"}

        await execute_extended_tool("redops_check_url", {"url": "http://example.com"})

        mock_tool.assert_called_once()

    @patch("redops.mcp.tools._tool_cert_transparency")
    async def test_routes_to_cert_transparency(self, mock_tool):
        """Test routing to cert_transparency tool."""
        mock_tool.return_value = {"result": "ok"}

        await execute_extended_tool(
            "redops_cert_transparency", {"domain": "example.com"}
        )

        mock_tool.assert_called_once()

    @patch("redops.mcp.tools._tool_asn_lookup")
    async def test_routes_to_asn_lookup(self, mock_tool):
        """Test routing to asn_lookup tool."""
        mock_tool.return_value = {"result": "ok"}

        await execute_extended_tool("redops_asn_lookup", {"target": "8.8.8.8"})

        mock_tool.assert_called_once()

    @patch("redops.mcp.tools._tool_enumerate_subdomains")
    async def test_routes_to_enumerate_subdomains(self, mock_tool):
        """Test routing to enumerate_subdomains tool."""
        mock_tool.return_value = {"result": "ok"}

        await execute_extended_tool(
            "redops_enumerate_subdomains", {"domain": "example.com"}
        )

        mock_tool.assert_called_once()

    @patch("redops.mcp.tools._tool_dashboard_summary")
    async def test_routes_to_dashboard_summary(self, mock_tool):
        """Test routing to dashboard_summary tool."""
        mock_tool.return_value = {"result": "ok"}

        await execute_extended_tool("redops_dashboard_summary", {"scan_data": {}})

        mock_tool.assert_called_once()


class TestToolCheckIp:
    """Tests for _tool_check_ip function."""

    async def test_missing_ip(self):
        """Test error when IP is missing."""
        from redops.mcp.tools import _tool_check_ip

        with pytest.raises(ValueError, match="IP address is required"):
            await _tool_check_ip({})

    @patch("redops.modules.threat_intel.greynoise.query_greynoise")
    @patch("redops.modules.threat_intel.abuseipdb.check_ip_reputation")
    async def test_queries_sources(self, mock_abuseipdb, mock_greynoise):
        """Test that both sources are queried."""
        from redops.mcp.tools import _tool_check_ip

        # Mock the module functions to return the context
        def mock_gn(ctx):
            ctx.add("greynoise_result", {"noise": False})
            return ctx

        def mock_ab(ctx):
            ctx.add("abuseipdb_result", {"abuseConfidenceScore": 0})
            return ctx

        mock_greynoise.side_effect = mock_gn
        mock_abuseipdb.side_effect = mock_ab

        result = await _tool_check_ip({"ip": "8.8.8.8"})

        assert result["ip"] == "8.8.8.8"
        assert "sources" in result


class TestToolCheckUrl:
    """Tests for _tool_check_url function."""

    async def test_missing_url(self):
        """Test error when URL is missing."""
        from redops.mcp.tools import _tool_check_url

        with pytest.raises(ValueError, match="URL is required"):
            await _tool_check_url({})

    @patch("redops.modules.threat_intel.urlhaus.check_url")
    async def test_checks_url(self, mock_check):
        """Test that URL is checked."""
        from redops.mcp.tools import _tool_check_url

        def mock_fn(ctx):
            ctx.add("urlhaus_result", {"query_status": "no_results"})
            return ctx

        mock_check.side_effect = mock_fn

        result = await _tool_check_url({"url": "http://example.com"})

        assert result["url"] == "http://example.com"


class TestToolCertTransparency:
    """Tests for _tool_cert_transparency function."""

    async def test_missing_domain(self):
        """Test error when domain is missing."""
        from redops.mcp.tools import _tool_cert_transparency

        with pytest.raises(ValueError, match="Domain is required"):
            await _tool_cert_transparency({})

    @patch("redops.modules.recon.cert_transparency.search_ct_logs")
    async def test_searches_ct_logs(self, mock_search):
        """Test that CT logs are searched."""
        from redops.mcp.tools import _tool_cert_transparency

        def mock_fn(ctx, params=None):
            ctx.add("ct_results", {})
            ctx.add("ct_subdomains", ["www.example.com"])
            return ctx

        mock_search.side_effect = mock_fn

        result = await _tool_cert_transparency({"domain": "example.com"})

        assert result["domain"] == "example.com"
        assert "subdomains" in result


class TestToolAsnLookup:
    """Tests for _tool_asn_lookup function."""

    async def test_missing_target(self):
        """Test error when target is missing."""
        from redops.mcp.tools import _tool_asn_lookup

        with pytest.raises(ValueError, match="Target is required"):
            await _tool_asn_lookup({})

    @patch("redops.modules.recon.asn_lookup.lookup_asn")
    async def test_looks_up_asn(self, mock_lookup):
        """Test that ASN is looked up."""
        from redops.mcp.tools import _tool_asn_lookup

        def mock_fn(ctx, params=None):
            ctx.add("asn_lookup", {"asn": 15169})
            return ctx

        mock_lookup.side_effect = mock_fn

        result = await _tool_asn_lookup({"target": "8.8.8.8"})

        assert result["target"] == "8.8.8.8"
        assert "asn_lookup" in result


class TestToolEnumerateSubdomains:
    """Tests for _tool_enumerate_subdomains function."""

    async def test_missing_domain(self):
        """Test error when domain is missing."""
        from redops.mcp.tools import _tool_enumerate_subdomains

        with pytest.raises(ValueError, match="Domain is required"):
            await _tool_enumerate_subdomains({})

    @patch("redops.modules.recon.subdomain_enum.enumerate_subdomains")
    async def test_enumerates_subdomains(self, mock_enum):
        """Test that subdomains are enumerated."""
        from redops.mcp.tools import _tool_enumerate_subdomains

        def mock_fn(ctx, params=None):
            ctx.add("subdomains", ["www.example.com", "api.example.com"])
            ctx.add("subdomain_enum_results", {})
            return ctx

        mock_enum.side_effect = mock_fn

        result = await _tool_enumerate_subdomains({"domain": "example.com"})

        assert result["domain"] == "example.com"
        assert "subdomains" in result


class TestToolDashboardSummary:
    """Tests for _tool_dashboard_summary function."""

    @patch("redops.web.dashboard_widgets.generate_dashboard_data")
    async def test_generates_dashboard(self, mock_gen):
        """Test that dashboard data is generated."""
        from redops.mcp.tools import _tool_dashboard_summary

        mock_gen.return_value = {"risk_summary": {}}

        result = await _tool_dashboard_summary({"scan_data": {"data": {}}})

        mock_gen.assert_called_once()
        assert "risk_summary" in result


class TestMcpPrompts:
    """Tests for MCP prompts."""

    def test_prompts_defined(self):
        """Test that prompts are defined."""
        expected_prompts = [
            "security-assessment",
            "vulnerability-report",
            "threat-analysis",
        ]

        prompt_names = [p["name"] for p in MCP_PROMPTS]
        for expected in expected_prompts:
            assert expected in prompt_names

    def test_prompts_have_arguments(self):
        """Test that prompts have arguments defined."""
        for prompt in MCP_PROMPTS:
            assert "arguments" in prompt
            assert len(prompt["arguments"]) > 0


class TestGetPromptContent:
    """Tests for get_prompt_content function."""

    def test_security_assessment_prompt(self):
        """Test security assessment prompt content."""
        content = get_prompt_content("security-assessment", {"target": "example.com"})

        assert "example.com" in content
        assert "security assessment" in content.lower()

    def test_vulnerability_report_prompt(self):
        """Test vulnerability report prompt content."""
        content = get_prompt_content(
            "vulnerability-report", {"findings": '{"test": true}'}
        )

        assert '{"test": true}' in content
        assert "vulnerability report" in content.lower()

    def test_threat_analysis_prompt(self):
        """Test threat analysis prompt content."""
        content = get_prompt_content("threat-analysis", {"indicator": "1.2.3.4"})

        assert "1.2.3.4" in content
        assert "threat" in content.lower()

    def test_unknown_prompt(self):
        """Test handling of unknown prompt."""
        content = get_prompt_content("unknown-prompt", {})

        assert "Unknown prompt" in content
