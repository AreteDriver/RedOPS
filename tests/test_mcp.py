"""Tests for RedOPS MCP Server."""

import asyncio
import pytest
from unittest.mock import patch

from redops.mcp.server import MCPServer, create_server


def run_async(coro):
    """Helper to run async code in tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestMCPServer:
    """Test MCP server functionality."""

    @pytest.fixture
    def server(self):
        """Create a server instance."""
        return create_server()

    def test_create_server(self):
        """Test server creation."""
        server = create_server()
        assert isinstance(server, MCPServer)
        assert not server.initialized

    def test_tools_registered(self, server):
        """Test that tools are registered."""
        assert "redops_scan" in server.tools
        assert "redops_explain" in server.tools
        assert "redops_analyze" in server.tools
        assert "redops_suggest" in server.tools
        assert "redops_summarize" in server.tools

    def test_tool_schema(self, server):
        """Test tool schema structure."""
        scan_tool = server.tools["redops_scan"]
        assert "name" in scan_tool
        assert "description" in scan_tool
        assert "inputSchema" in scan_tool
        assert scan_tool["inputSchema"]["type"] == "object"
        assert "target" in scan_tool["inputSchema"]["properties"]

    def test_handle_initialize(self, server):
        """Test initialize request."""
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        }
        response = run_async(server.handle_message(message))
        assert response["id"] == 1
        assert "result" in response
        assert "protocolVersion" in response["result"]
        assert "capabilities" in response["result"]
        assert "serverInfo" in response["result"]

    def test_handle_tools_list(self, server):
        """Test tools/list request."""
        message = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        response = run_async(server.handle_message(message))
        assert response["id"] == 2
        assert "result" in response
        assert "tools" in response["result"]
        assert len(response["result"]["tools"]) == 5

    def test_handle_notification(self, server):
        """Test notification (no id) handling."""
        message = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        response = run_async(server.handle_message(message))
        assert response is None
        assert server.initialized

    def test_handle_unknown_method(self, server):
        """Test unknown method error."""
        message = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "unknown/method",
            "params": {},
        }
        response = run_async(server.handle_message(message))
        assert response["id"] == 3
        assert "error" in response
        assert response["error"]["code"] == -32601

    def test_tool_call_scan(self, server):
        """Test scan tool execution."""
        message = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "redops_scan",
                "arguments": {"target": "example.com"},
            },
        }
        response = run_async(server.handle_message(message))
        assert response["id"] == 4
        assert "result" in response
        assert "content" in response["result"]
        # Verify scan data is returned
        text = response["result"]["content"][0]["text"]
        assert "example.com" in text or "target" in text

    def test_tool_call_explain_no_ai(self, server):
        """Test explain tool when AI is not configured."""
        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            message = {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "redops_explain",
                    "arguments": {"query": "What is XSS?"},
                },
            }
            response = run_async(server.handle_message(message))
            assert response["id"] == 5
            assert "result" in response
            assert "content" in response["result"]
            # Should have graceful error message
            text = response["result"]["content"][0]["text"]
            assert "not available" in text or "API key" in text

    def test_tool_call_unknown_tool(self, server):
        """Test unknown tool error."""
        message = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "unknown_tool",
                "arguments": {},
            },
        }
        response = run_async(server.handle_message(message))
        assert response["id"] == 6
        assert "error" in response
        assert response["error"]["code"] == -32602

    def test_tool_call_missing_required_arg(self, server):
        """Test missing required argument."""
        message = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "redops_scan",
                "arguments": {},  # Missing target
            },
        }
        response = run_async(server.handle_message(message))
        assert response["id"] == 7
        assert "result" in response
        # Should indicate error
        assert (
            response["result"].get("isError")
            or "Error" in response["result"]["content"][0]["text"]
        )
