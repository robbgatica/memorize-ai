#!/usr/bin/env python3
"""
Example MCP client for using Memory Forensics MCP Server with Ollama/Llama

This script demonstrates how to:
1. Connect to the MCP server via stdio
2. Send prompts to Ollama (running Llama or other models)
3. Handle tool calls from the LLM
4. Execute tools via MCP and return results

Prerequisites:
- Ollama installed: curl -fsSL https://ollama.com/install.sh | sh
- A model pulled: ollama pull llama3.1:70b
- MCP server working: python server.py should run without errors

Usage:
    python examples/ollama_client.py

Environment variables:
    OLLAMA_MODEL: Model to use (default: llama3.1:70b)
    MCP_SERVER_PATH: Path to server.py (default: ../server.py)
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    print("Error: httpx not installed. Install with: pip install httpx")
    sys.exit(1)


class OllamaMCPClient:
    """MCP client that uses Ollama as the LLM backend"""

    def __init__(
        self,
        server_path: Path,
        ollama_model: str = "llama3.1:70b",
        ollama_url: str = "http://localhost:11434"
    ):
        self.server_path = server_path
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        self.mcp_process = None
        self.tools = []
        self.conversation_history = []

    async def start_mcp_server(self):
        """Start the MCP server as a subprocess"""
        print(f"Starting MCP server: {self.server_path}")

        # Get the venv python path
        venv_python = self.server_path.parent / "venv" / "bin" / "python"
        if not venv_python.exists():
            venv_python = "python3"

        self.mcp_process = await asyncio.create_subprocess_exec(
            str(venv_python),
            str(self.server_path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Wait for initialization
        await asyncio.sleep(2)

        # Send initialize request
        await self._send_mcp_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "ollama-mcp-client",
                    "version": "0.1.0"
                }
            }
        })

        # Get available tools
        tools_response = await self._send_mcp_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })

        if tools_response and "result" in tools_response:
            self.tools = tools_response["result"].get("tools", [])
            print(f"Loaded {len(self.tools)} tools from MCP server")

    async def _send_mcp_request(self, request: Dict) -> Optional[Dict]:
        """Send a JSON-RPC request to MCP server"""
        if not self.mcp_process or not self.mcp_process.stdin:
            return None

        try:
            request_str = json.dumps(request) + "\n"
            self.mcp_process.stdin.write(request_str.encode())
            await self.mcp_process.stdin.drain()

            # Read response
            response_line = await self.mcp_process.stdout.readline()
            if response_line:
                return json.loads(response_line.decode())
        except Exception as e:
            print(f"MCP request error: {e}")
        return None

    async def call_tool(self, tool_name: str, arguments: Dict) -> str:
        """Call an MCP tool and return the result"""
        response = await self._send_mcp_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        })

        if response and "result" in response:
            content = response["result"].get("content", [])
            if content and len(content) > 0:
                return content[0].get("text", "No result")
        return "Tool execution failed"

    def _format_tools_for_ollama(self) -> str:
        """Format tools as a description for Ollama"""
        if not self.tools:
            return "No tools available."

        tools_desc = "You have access to the following memory forensics tools:\n\n"
        for tool in self.tools:
            tools_desc += f"**{tool['name']}**\n"
            tools_desc += f"  Description: {tool.get('description', 'No description')}\n"

            # Add parameters
            schema = tool.get('inputSchema', {})
            props = schema.get('properties', {})
            required = schema.get('required', [])

            if props:
                tools_desc += "  Parameters:\n"
                for param_name, param_info in props.items():
                    req_marker = " (required)" if param_name in required else ""
                    param_desc = param_info.get('description', 'No description')
                    tools_desc += f"    - {param_name}{req_marker}: {param_desc}\n"

            tools_desc += "\n"

        tools_desc += "\nTo use a tool, respond with JSON in this format:\n"
        tools_desc += '{"tool": "tool_name", "arguments": {"param1": "value1"}}\n\n'
        tools_desc += "After using tools, provide your analysis in plain text.\n"

        return tools_desc

    async def chat(self, user_message: str) -> str:
        """Send a message to Ollama and handle tool calls"""

        # Add system prompt with tools
        if not self.conversation_history:
            system_prompt = f"""You are a memory forensics expert assistant. {self._format_tools_for_ollama()}

When a user asks you to analyze memory dumps, use the available tools to gather information, then provide a detailed analysis.

IMPORTANT:
1. First, use tools to gather data
2. Then, provide your analysis based on the tool results
3. Respond with JSON when calling tools, plain text for analysis"""

            self.conversation_history.append({
                "role": "system",
                "content": system_prompt
            })

        # Add user message
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        # Call Ollama
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.ollama_model,
                    "messages": self.conversation_history,
                    "stream": False,
                    "options": {
                        "num_ctx": 32768  # Increase context window for tool descriptions
                    }
                }
            )

            if response.status_code != 200:
                return f"Ollama error: {response.status_code} - {response.text}"

            result = response.json()
            assistant_message = result.get("message", {}).get("content", "")

            # Check if response is a tool call
            if assistant_message.strip().startswith("{"):
                try:
                    tool_call = json.loads(assistant_message.strip())
                    if "tool" in tool_call and "arguments" in tool_call:
                        # Execute tool
                        tool_name = tool_call["tool"]
                        tool_args = tool_call["arguments"]

                        print(f"\n[Calling tool: {tool_name}]")
                        tool_result = await self.call_tool(tool_name, tool_args)

                        # Add tool result to history
                        self.conversation_history.append({
                            "role": "assistant",
                            "content": assistant_message
                        })
                        self.conversation_history.append({
                            "role": "user",
                            "content": f"Tool result:\n{tool_result}\n\nNow provide your analysis."
                        })

                        # Get analysis
                        return await self.chat("")

                except json.JSONDecodeError:
                    pass  # Not a tool call, treat as regular response

            # Add assistant response to history
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })

            return assistant_message

    async def close(self):
        """Shutdown MCP server"""
        if self.mcp_process:
            self.mcp_process.terminate()
            await self.mcp_process.wait()


async def main():
    """Interactive chat loop"""
    # Configuration
    server_path = Path(os.getenv(
        "MCP_SERVER_PATH",
        Path(__file__).parent.parent / "server.py"
    ))
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3.1:70b")

    if not server_path.exists():
        print(f"Error: MCP server not found at {server_path}")
        sys.exit(1)

    print("Memory Forensics MCP Client with Ollama")
    print("=" * 50)
    print(f"Model: {ollama_model}")
    print(f"Server: {server_path}")
    print("=" * 50)

    # Check if Ollama is running
    try:
        async with httpx.AsyncClient() as client:
            await client.get("http://localhost:11434/api/tags")
    except Exception:
        print("\nError: Ollama not running. Start with: ollama serve")
        sys.exit(1)

    # Start client
    client = OllamaMCPClient(server_path, ollama_model)
    await client.start_mcp_server()

    print("\nReady! Type your questions (or 'quit' to exit)\n")

    # Interactive loop
    while True:
        try:
            user_input = input("You: ").strip()

            if user_input.lower() in ["quit", "exit", "q"]:
                break

            if not user_input:
                continue

            print("\nAssistant: ", end="", flush=True)
            response = await client.chat(user_input)
            print(response)
            print()

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {e}")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
