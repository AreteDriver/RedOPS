"""Tests for MCP Server module."""

import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock


class TestMCPServerInit:
    """Tests for MCPServer initialization."""

    def test_server_init(self):
        """Test server initialization."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        assert server.initialized is False
        assert "redops_scan" in server.tools
        assert "redops_explain" in server.tools
        assert "redops_analyze" in server.tools
        assert "redops_suggest" in server.tools
        assert "redops_summarize" in server.tools

    def test_register_tools(self):
        """Test tools are registered correctly."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        tools = server.tools

        # Check scan tool
        assert tools["redops_scan"]["name"] == "redops_scan"
        assert "inputSchema" in tools["redops_scan"]
        assert "target" in tools["redops_scan"]["inputSchema"]["properties"]

        # Check explain tool
        assert tools["redops_explain"]["name"] == "redops_explain"
        assert "query" in tools["redops_explain"]["inputSchema"]["properties"]


class TestHandleMessage:
    """Tests for handle_message method."""

    async def test_handle_notification_initialized(self):
        """Test handling initialized notification."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        message = {"method": "notifications/initialized"}

        result = await server.handle_message(message)

        assert result is None
        assert server.initialized is True

    async def test_handle_notification_no_response(self):
        """Test notifications return None."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        message = {"method": "some/notification"}  # No id

        result = await server.handle_message(message)

        assert result is None

    async def test_handle_initialize_request(self):
        """Test handling initialize request."""
        from redops.mcp.server import MCPServer, MCP_PROTOCOL_VERSION
        from redops.main import __version__

        server = MCPServer()
        message = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

        result = await server.handle_message(message)

        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1
        assert result["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
        assert result["result"]["serverInfo"]["name"] == "redops"
        assert result["result"]["serverInfo"]["version"] == __version__

    async def test_handle_tools_list_request(self):
        """Test handling tools/list request."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        message = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}

        result = await server.handle_message(message)

        assert result["id"] == 2
        assert "tools" in result["result"]
        assert len(result["result"]["tools"]) == 5

    async def test_handle_unknown_method(self):
        """Test handling unknown method returns error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        message = {"jsonrpc": "2.0", "id": 3, "method": "unknown/method"}

        result = await server.handle_message(message)

        assert result["id"] == 3
        assert "error" in result
        assert result["error"]["code"] == -32601
        assert "Method not found" in result["error"]["message"]

    async def test_handle_message_exception(self):
        """Test handling exception in message processing."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        # Patch _handle_initialize to raise an exception
        server._handle_initialize = MagicMock(side_effect=RuntimeError("Test error"))

        message = {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {}}

        result = await server.handle_message(message)

        assert result["id"] == 4
        assert "error" in result
        assert result["error"]["code"] == -32603
        assert "Test error" in result["error"]["message"]


class TestToolsCall:
    """Tests for tools/call handling."""

    async def test_tools_call_unknown_tool(self):
        """Test calling unknown tool returns error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        message = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "unknown_tool", "arguments": {}},
        }

        result = await server.handle_message(message)

        assert "error" in result
        assert result["error"]["code"] == -32602
        assert "Unknown tool" in result["error"]["message"]

    async def test_tools_call_success_string_result(self):
        """Test successful tool call with string result."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        server._execute_tool = AsyncMock(return_value="Test explanation")

        message = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "redops_explain",
                "arguments": {"query": "What is XSS?"},
            },
        }

        result = await server.handle_message(message)

        assert result["id"] == 6
        assert "result" in result
        assert result["result"]["content"][0]["type"] == "text"
        assert result["result"]["content"][0]["text"] == "Test explanation"

    async def test_tools_call_success_dict_result(self):
        """Test successful tool call with dict result."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        server._execute_tool = AsyncMock(return_value={"key": "value"})

        message = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "redops_scan", "arguments": {"target": "example.com"}},
        }

        result = await server.handle_message(message)

        assert result["id"] == 7
        assert "result" in result
        # Dict result should be JSON serialized
        assert '"key"' in result["result"]["content"][0]["text"]

    async def test_tools_call_execution_error(self):
        """Test tool call that raises an exception."""
        from redops.mcp.server import MCPServer

        server = MCPServer()
        server._execute_tool = AsyncMock(side_effect=ValueError("Execution failed"))

        message = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "redops_scan", "arguments": {"target": "example.com"}},
        }

        result = await server.handle_message(message)

        assert result["id"] == 8
        assert "result" in result
        assert result["result"]["isError"] is True
        assert "Error executing" in result["result"]["content"][0]["text"]


class TestExecuteTool:
    """Tests for _execute_tool method."""

    async def test_execute_tool_scan(self):
        """Test executing scan tool."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_ctx = MagicMock()
        mock_ctx.data = {"domain": "example.com"}
        mock_ctx.logs = []

        with patch("redops.core.context.Context", return_value=mock_ctx):
            with patch(
                "redops.modules.recon.domains.profile_domain", return_value=mock_ctx
            ):
                with patch(
                    "redops.modules.recon.tech_stack.fingerprint", return_value=mock_ctx
                ):
                    result = await server._execute_tool(
                        "redops_scan", {"target": "example.com"}
                    )

        assert result["target"] == "example.com"
        assert result["preset"] == "quick"
        assert "data" in result

    async def test_execute_tool_explain(self):
        """Test executing explain tool."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "XSS is a vulnerability..."

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = await server._execute_tool(
                "redops_explain", {"query": "What is XSS?"}
            )

        assert result == "XSS is a vulnerability..."

    async def test_execute_tool_analyze(self):
        """Test executing analyze tool."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Analysis results..."

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = await server._execute_tool(
                "redops_analyze", {"scan_data": {"target": "example.com"}}
            )

        assert result == "Analysis results..."

    async def test_execute_tool_suggest(self):
        """Test executing suggest tool."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_assistant = MagicMock()
        mock_assistant.suggest_remediations.return_value = "Suggestions..."

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = await server._execute_tool(
                "redops_suggest", {"scan_data": {"findings": []}}
            )

        assert result == "Suggestions..."

    async def test_execute_tool_summarize(self):
        """Test executing summarize tool."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "Executive summary..."

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = await server._execute_tool(
                "redops_summarize", {"scan_data": {"target": "example.com"}}
            )

        assert result == "Executive summary..."

    async def test_execute_tool_unknown(self):
        """Test executing unknown tool raises error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with pytest.raises(ValueError, match="Unknown tool"):
            await server._execute_tool("unknown_tool", {})


class TestToolScan:
    """Tests for _tool_scan method."""

    async def test_tool_scan_missing_target(self):
        """Test scan without target raises error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with pytest.raises(ValueError, match="Target is required"):
            await server._tool_scan({})

    async def test_tool_scan_with_preset(self):
        """Test scan with specific preset."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_ctx = MagicMock()
        mock_ctx.data = {}
        mock_ctx.logs = []

        with patch("redops.core.context.Context", return_value=mock_ctx):
            with patch(
                "redops.modules.recon.domains.profile_domain", return_value=mock_ctx
            ):
                with patch(
                    "redops.modules.recon.tech_stack.fingerprint", return_value=mock_ctx
                ):
                    result = await server._tool_scan(
                        {"target": "example.com", "preset": "full"}
                    )

        assert result["preset"] == "full"

    async def test_tool_scan_module_failure(self):
        """Test scan handles module failure gracefully."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        mock_ctx = MagicMock()
        mock_ctx.data = {}
        mock_ctx.logs = []

        def failing_module(ctx):
            raise RuntimeError("Module failed")

        with patch("redops.core.context.Context", return_value=mock_ctx):
            with patch(
                "redops.modules.recon.domains.profile_domain",
                side_effect=failing_module,
            ):
                with patch(
                    "redops.modules.recon.tech_stack.fingerprint", return_value=mock_ctx
                ):
                    result = await server._tool_scan({"target": "example.com"})

        # Should complete despite module failure
        assert result["target"] == "example.com"
        mock_ctx.log.assert_called()


class TestToolExplain:
    """Tests for _tool_explain method."""

    async def test_tool_explain_missing_query(self):
        """Test explain without query raises error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with pytest.raises(ValueError, match="Query is required"):
            await server._tool_explain({})

    async def test_tool_explain_ai_not_available(self):
        """Test explain when AI is not available."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = await server._tool_explain({"query": "What is XSS?"})

        assert "not available" in result
        assert "API key" in result


class TestToolAnalyze:
    """Tests for _tool_analyze method."""

    async def test_tool_analyze_missing_scan_data(self):
        """Test analyze without scan_data raises error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with pytest.raises(ValueError, match="scan_data is required"):
            await server._tool_analyze({})

    async def test_tool_analyze_ai_not_available(self):
        """Test analyze when AI is not available."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ImportError("No module"),
        ):
            result = await server._tool_analyze(
                {"scan_data": {"target": "example.com"}}
            )

        assert "not available" in result


class TestToolSuggest:
    """Tests for _tool_suggest method."""

    async def test_tool_suggest_missing_scan_data(self):
        """Test suggest without scan_data raises error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with pytest.raises(ValueError, match="scan_data is required"):
            await server._tool_suggest({})

    async def test_tool_suggest_ai_not_available(self):
        """Test suggest when AI is not available."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = await server._tool_suggest(
                {"scan_data": {"target": "example.com"}}
            )

        assert "not available" in result


class TestToolSummarize:
    """Tests for _tool_summarize method."""

    async def test_tool_summarize_missing_scan_data(self):
        """Test summarize without scan_data raises error."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with pytest.raises(ValueError, match="scan_data is required"):
            await server._tool_summarize({})

    async def test_tool_summarize_ai_not_available(self):
        """Test summarize when AI is not available."""
        from redops.mcp.server import MCPServer

        server = MCPServer()

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = await server._tool_summarize(
                {"scan_data": {"target": "example.com"}}
            )

        assert "not available" in result


class TestErrorResponse:
    """Tests for _error_response method."""

    def test_error_response_format(self):
        """Test error response format."""
        from redops.mcp.server import MCPServer, JSONRPC_VERSION

        server = MCPServer()
        result = server._error_response(123, -32600, "Invalid request")

        assert result["jsonrpc"] == JSONRPC_VERSION
        assert result["id"] == 123
        assert result["error"]["code"] == -32600
        assert result["error"]["message"] == "Invalid request"


class TestCreateServer:
    """Tests for create_server function."""

    def test_create_server(self):
        """Test create_server returns MCPServer instance."""
        from redops.mcp.server import create_server, MCPServer

        server = create_server()

        assert isinstance(server, MCPServer)
        assert server.initialized is False


class TestMain:
    """Tests for main function."""

    def test_main_keyboard_interrupt(self):
        """Test main handles keyboard interrupt gracefully."""
        from redops.mcp.server import main

        def mock_asyncio_run_interrupt(coro):
            coro.close()
            raise KeyboardInterrupt

        with patch(
            "redops.mcp.server.asyncio.run", side_effect=mock_asyncio_run_interrupt
        ):
            # Should not raise
            main()

    def test_main_calls_run_server(self):
        """Test main calls run_server."""

        # Mock asyncio.run to actually close the coroutine to avoid warnings
        def mock_asyncio_run(coro):
            coro.close()

        with patch(
            "redops.mcp.server.asyncio.run", side_effect=mock_asyncio_run
        ) as mock_run:
            from redops.mcp.server import main

            main()

        mock_run.assert_called_once()


class TestRunServer:
    """Tests for run_server function."""

    async def test_run_server_empty_input(self):
        """Test run_server handles empty input."""
        from redops.mcp.server import run_server

        # Create mock reader that returns empty line (EOF)
        mock_reader = AsyncMock()
        mock_reader.readline.return_value = b""

        mock_protocol = MagicMock()

        with patch("asyncio.StreamReader", return_value=mock_reader):
            with patch("asyncio.StreamReaderProtocol", return_value=mock_protocol):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.connect_read_pipe = AsyncMock()
                    mock_loop.return_value.connect_write_pipe = AsyncMock(
                        return_value=(MagicMock(), MagicMock())
                    )
                    with patch("asyncio.StreamWriter"):
                        # This should exit when reader returns empty
                        await run_server()

    async def test_run_server_invalid_json(self):
        """Test run_server handles invalid JSON."""
        from redops.mcp.server import run_server

        # Create mock reader that returns invalid JSON then EOF
        mock_reader = AsyncMock()
        mock_reader.readline.side_effect = [b"not valid json\n", b""]

        mock_protocol = MagicMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.StreamReader", return_value=mock_reader):
            with patch("asyncio.StreamReaderProtocol", return_value=mock_protocol):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.connect_read_pipe = AsyncMock()
                    mock_loop.return_value.connect_write_pipe = AsyncMock(
                        return_value=(MagicMock(), MagicMock())
                    )
                    with patch("asyncio.StreamWriter", return_value=mock_writer):
                        await run_server()

        # Should not have written any response for invalid JSON
        mock_writer.write.assert_not_called()

    async def test_run_server_valid_message(self):
        """Test run_server processes valid message."""
        from redops.mcp.server import run_server

        # Create mock reader that returns valid JSON then EOF
        valid_message = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        mock_reader = AsyncMock()
        mock_reader.readline.side_effect = [valid_message.encode() + b"\n", b""]

        mock_protocol = MagicMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.StreamReader", return_value=mock_reader):
            with patch("asyncio.StreamReaderProtocol", return_value=mock_protocol):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.connect_read_pipe = AsyncMock()
                    mock_loop.return_value.connect_write_pipe = AsyncMock(
                        return_value=(MagicMock(), MagicMock())
                    )
                    with patch("asyncio.StreamWriter", return_value=mock_writer):
                        await run_server()

        # Should have written a response
        mock_writer.write.assert_called()

    async def test_run_server_notification_no_response(self):
        """Test run_server doesn't respond to notifications."""
        from redops.mcp.server import run_server

        # Notification (no id)
        notification = json.dumps({"method": "notifications/initialized"})
        mock_reader = AsyncMock()
        mock_reader.readline.side_effect = [notification.encode() + b"\n", b""]

        mock_protocol = MagicMock()
        mock_writer = MagicMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.StreamReader", return_value=mock_reader):
            with patch("asyncio.StreamReaderProtocol", return_value=mock_protocol):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.connect_read_pipe = AsyncMock()
                    mock_loop.return_value.connect_write_pipe = AsyncMock(
                        return_value=(MagicMock(), MagicMock())
                    )
                    with patch("asyncio.StreamWriter", return_value=mock_writer):
                        await run_server()

        # Should not have written response for notification
        mock_writer.write.assert_not_called()

    async def test_run_server_exception_handling(self, capsys):
        """Test run_server handles exceptions."""
        from redops.mcp.server import run_server

        mock_reader = AsyncMock()
        mock_reader.readline.side_effect = ConnectionError("Connection error")

        mock_protocol = MagicMock()

        with patch("asyncio.StreamReader", return_value=mock_reader):
            with patch("asyncio.StreamReaderProtocol", return_value=mock_protocol):
                with patch("asyncio.get_event_loop") as mock_loop:
                    mock_loop.return_value.connect_read_pipe = AsyncMock()
                    mock_loop.return_value.connect_write_pipe = AsyncMock(
                        return_value=(MagicMock(), MagicMock())
                    )
                    with patch("asyncio.StreamWriter"):
                        await run_server()

        captured = capsys.readouterr()
        assert "Error" in captured.err
