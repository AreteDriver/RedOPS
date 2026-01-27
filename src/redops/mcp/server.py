"""
RedOPS MCP Server - Model Context Protocol server for Claude Code integration.

This server exposes RedOPS functionality as MCP tools that can be used
by Claude Code and other MCP-compatible clients.

Usage:
    redops-mcp  # Start the MCP server (stdio transport)

Configuration in Claude Code:
    Add to ~/.claude.json:
    {
        "mcpServers": {
            "redops": {
                "command": "redops-mcp"
            }
        }
    }
"""

import asyncio
import json
import sys
from typing import Any

from redops.main import __version__


# MCP Protocol constants
JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2024-11-05"


class MCPServer:
    """MCP Server implementation for RedOPS."""

    def __init__(self):
        self.tools = self._register_tools()
        self.initialized = False

    def _register_tools(self) -> dict[str, dict]:
        """Register available tools."""
        return {
            "redops_scan": {
                "name": "redops_scan",
                "description": "Run a security reconnaissance scan on a target domain. Returns domain profile, technology stack, and basic exposure information.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target domain to scan (e.g., example.com)",
                        },
                        "preset": {
                            "type": "string",
                            "description": "Scan preset: quick (default), recon, full",
                            "enum": ["quick", "recon", "full"],
                            "default": "quick",
                        },
                    },
                    "required": ["target"],
                },
            },
            "redops_explain": {
                "name": "redops_explain",
                "description": "Get an AI-powered explanation of a security concept, vulnerability, or finding. Useful for understanding CVEs, attack techniques, and security best practices.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The security concept or question to explain",
                        },
                    },
                    "required": ["query"],
                },
            },
            "redops_analyze": {
                "name": "redops_analyze",
                "description": "Analyze security scan results using AI. Provides risk assessment, prioritized findings, and actionable insights.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_data": {
                            "type": "object",
                            "description": "Scan results data to analyze (from redops_scan)",
                        },
                    },
                    "required": ["scan_data"],
                },
            },
            "redops_suggest": {
                "name": "redops_suggest",
                "description": "Get AI-powered remediation suggestions for security findings. Returns prioritized fix recommendations with effort estimates.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_data": {
                            "type": "object",
                            "description": "Scan results data to generate suggestions for",
                        },
                    },
                    "required": ["scan_data"],
                },
            },
            "redops_summarize": {
                "name": "redops_summarize",
                "description": "Generate an executive summary of security scan results. Suitable for non-technical stakeholders.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scan_data": {
                            "type": "object",
                            "description": "Scan results data to summarize",
                        },
                    },
                    "required": ["scan_data"],
                },
            },
        }

    async def handle_message(self, message: dict) -> dict | None:
        """Handle an incoming JSON-RPC message."""
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params", {})

        # Handle notifications (no id)
        if msg_id is None:
            if method == "notifications/initialized":
                self.initialized = True
            return None

        # Handle requests
        try:
            if method == "initialize":
                return self._handle_initialize(msg_id, params)
            elif method == "tools/list":
                return self._handle_tools_list(msg_id)
            elif method == "tools/call":
                return await self._handle_tools_call(msg_id, params)
            else:
                return self._error_response(
                    msg_id, -32601, f"Method not found: {method}"
                )
        except Exception as e:
            return self._error_response(msg_id, -32603, str(e))

    def _handle_initialize(self, msg_id: int, params: dict) -> dict:
        """Handle initialize request."""
        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": msg_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": "redops",
                    "version": __version__,
                },
            },
        }

    def _handle_tools_list(self, msg_id: int) -> dict:
        """Handle tools/list request."""
        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": msg_id,
            "result": {
                "tools": list(self.tools.values()),
            },
        }

    async def _handle_tools_call(self, msg_id: int, params: dict) -> dict:
        """Handle tools/call request."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in self.tools:
            return self._error_response(msg_id, -32602, f"Unknown tool: {tool_name}")

        try:
            result = await self._execute_tool(tool_name, arguments)
            return {
                "jsonrpc": JSONRPC_VERSION,
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result
                            if isinstance(result, str)
                            else json.dumps(result, indent=2),
                        }
                    ],
                },
            }
        except Exception as e:
            return {
                "jsonrpc": JSONRPC_VERSION,
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error executing {tool_name}: {e}",
                        }
                    ],
                    "isError": True,
                },
            }

    async def _execute_tool(self, tool_name: str, arguments: dict) -> Any:
        """Execute a tool and return the result."""
        if tool_name == "redops_scan":
            return await self._tool_scan(arguments)
        elif tool_name == "redops_explain":
            return await self._tool_explain(arguments)
        elif tool_name == "redops_analyze":
            return await self._tool_analyze(arguments)
        elif tool_name == "redops_suggest":
            return await self._tool_suggest(arguments)
        elif tool_name == "redops_summarize":
            return await self._tool_summarize(arguments)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    async def _tool_scan(self, arguments: dict) -> dict:
        """Execute a scan."""
        target = arguments.get("target")
        preset = arguments.get("preset", "quick")

        if not target:
            raise ValueError("Target is required")

        # Run scan modules
        from redops.core.context import Context
        from redops.modules.recon.domains import profile_domain
        from redops.modules.recon.tech_stack import fingerprint

        ctx = Context(target=target)

        # Run modules based on preset
        modules = []
        if preset in ["quick", "recon", "full"]:
            modules.append(("profile_domain", profile_domain))
            modules.append(("fingerprint", fingerprint))

        for name, module_fn in modules:
            try:
                ctx = module_fn(ctx)
            except Exception as e:
                ctx.log(f"Module {name} failed: {e}", level="ERROR")

        return {
            "target": target,
            "preset": preset,
            "data": ctx.data,
            "logs": ctx.logs[-10:],  # Last 10 log entries
        }

    async def _tool_explain(self, arguments: dict) -> str:
        """Get AI explanation."""
        query = arguments.get("query")
        if not query:
            raise ValueError("Query is required")

        try:
            from redops.modules.ai_assistant import AIAssistant

            assistant = AIAssistant()
            return assistant.explain(query)
        except (ImportError, ValueError) as e:
            return f"AI explanation not available: {e}. Configure an API key with 'redops apikey set -p <provider>'."

    async def _tool_analyze(self, arguments: dict) -> str:
        """Analyze scan results."""
        scan_data = arguments.get("scan_data")
        if not scan_data:
            raise ValueError("scan_data is required")

        try:
            from redops.modules.ai_assistant import AIAssistant

            assistant = AIAssistant()
            return assistant.analyze_findings(scan_data)
        except (ImportError, ValueError) as e:
            return f"AI analysis not available: {e}"

    async def _tool_suggest(self, arguments: dict) -> str:
        """Get remediation suggestions."""
        scan_data = arguments.get("scan_data")
        if not scan_data:
            raise ValueError("scan_data is required")

        try:
            from redops.modules.ai_assistant import AIAssistant

            assistant = AIAssistant()
            return assistant.suggest_remediations(scan_data)
        except (ImportError, ValueError) as e:
            return f"AI suggestions not available: {e}"

    async def _tool_summarize(self, arguments: dict) -> str:
        """Generate executive summary."""
        scan_data = arguments.get("scan_data")
        if not scan_data:
            raise ValueError("scan_data is required")

        try:
            from redops.modules.ai_assistant import AIAssistant

            assistant = AIAssistant()
            return assistant.summarize(scan_data)
        except (ImportError, ValueError) as e:
            return f"AI summary not available: {e}"

    def _error_response(self, msg_id: int, code: int, message: str) -> dict:
        """Create an error response."""
        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": msg_id,
            "error": {
                "code": code,
                "message": message,
            },
        }


def create_server() -> MCPServer:
    """Create an MCP server instance."""
    return MCPServer()


async def run_server():
    """Run the MCP server on stdio."""
    server = create_server()

    # Read from stdin, write to stdout
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    (
        writer_transport,
        writer_protocol,
    ) = await asyncio.get_event_loop().connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    writer = asyncio.StreamWriter(
        writer_transport, writer_protocol, reader, asyncio.get_event_loop()
    )

    while True:
        try:
            # Read line (JSON-RPC message)
            line = await reader.readline()
            if not line:
                break

            # Parse message
            try:
                message = json.loads(line.decode())
            except json.JSONDecodeError:
                continue

            # Handle message
            response = await server.handle_message(message)

            # Send response if not a notification
            if response:
                writer.write((json.dumps(response) + "\n").encode())
                await writer.drain()

        except Exception as e:
            # Log errors to stderr (not stdout which is for protocol)
            print(f"Error: {e}", file=sys.stderr)
            break


def main():
    """Main entry point for MCP server."""
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
