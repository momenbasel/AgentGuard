"""AgentGuard MCP Server - expose scanning as Model Context Protocol tools.

Run with: agentguard mcp
Or:       python -m agentguard.mcp_server

This provides AgentGuard capabilities to any MCP-compatible AI client.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def serve():
    """Run the MCP server over stdio."""
    # MCP stdio transport: read JSON-RPC from stdin, write to stdout
    server = AgentGuardMCPServer()
    server.run()


class AgentGuardMCPServer:
    """Minimal MCP server implementation over stdio."""

    TOOLS = [
        {
            "name": "agentguard_scan",
            "description": (
                "Scan a shell command for supply chain security risks. "
                "Checks for typosquatting, known malicious packages, suspicious registry metadata, "
                "dangerous patterns (curl|sh), and optionally VirusTotal detections. "
                "Use this BEFORE executing any package install, git clone, or download command."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to scan (e.g., 'npm install lodash')",
                    },
                    "strict": {
                        "type": "boolean",
                        "description": "Use strict mode (lower risk threshold)",
                        "default": False,
                    },
                    "virustotal": {
                        "type": "boolean",
                        "description": "Enable VirusTotal scanning (requires VT_API_KEY env)",
                        "default": False,
                    },
                },
                "required": ["command"],
            },
        },
        {
            "name": "agentguard_check_package",
            "description": (
                "Check a specific package name for typosquatting and blocklist matches "
                "without a full command. Quick lookup for package safety."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Package name (e.g., 'lodash', '@angular/core')",
                    },
                    "manager": {
                        "type": "string",
                        "description": "Package manager",
                        "enum": ["npm", "pip", "go", "cargo", "gem"],
                        "default": "npm",
                    },
                },
                "required": ["name"],
            },
        },
        {
            "name": "agentguard_config",
            "description": "View or modify AgentGuard configuration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["show", "allow", "block"],
                        "description": "Config action",
                    },
                    "package": {
                        "type": "string",
                        "description": "Package name for allow/block actions",
                    },
                },
                "required": ["action"],
            },
        },
    ]

    def run(self):
        """Main loop - read JSON-RPC messages from stdin."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            response = self._handle(msg)
            if response:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

    def _handle(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "initialize":
            return self._respond(msg_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "agentguard",
                    "version": "0.1.0",
                },
            })

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return self._respond(msg_id, {"tools": self.TOOLS})

        if method == "tools/call":
            return self._handle_tool_call(msg_id, msg.get("params", {}))

        if method == "ping":
            return self._respond(msg_id, {})

        return self._error(msg_id, -32601, f"Method not found: {method}")

    def _handle_tool_call(self, msg_id: Any, params: dict) -> dict:
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        try:
            if tool_name == "agentguard_scan":
                result = self._tool_scan(args)
            elif tool_name == "agentguard_check_package":
                result = self._tool_check_package(args)
            elif tool_name == "agentguard_config":
                result = self._tool_config(args)
            else:
                return self._error(msg_id, -32602, f"Unknown tool: {tool_name}")

            return self._respond(msg_id, {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
            })
        except Exception as e:
            return self._respond(msg_id, {
                "content": [{"type": "text", "text": f"Error: {e}"}],
                "isError": True,
            })

    def _tool_scan(self, args: dict) -> dict:
        from agentguard.config import Config
        from agentguard.scanner import scan_command

        config = Config.load()
        if args.get("strict"):
            config.mode = "strict"
        if args.get("virustotal"):
            config.check_virustotal = True

        result = scan_command(args["command"], config)
        return {
            "verdict": "BLOCK" if result.has_blockers() else "WARN" if result.has_warnings() else "ALLOW",
            "max_severity": result.max_severity,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "package": f.package,
                    "message": f.message,
                }
                for f in result.findings
            ],
            "packages_checked": result.packages_checked,
        }

    def _tool_check_package(self, args: dict) -> dict:
        from agentguard.parsers import PackageRef
        from agentguard.checks.typosquat import TyposquatChecker
        from agentguard.checks.blocklist import BlocklistChecker

        pkg = PackageRef(manager=args.get("manager", "npm"), name=args["name"])

        bl = BlocklistChecker()
        bl_result = bl.check(pkg)
        if bl_result.is_blocked:
            return {"safe": False, "reason": bl_result.message}

        ts = TyposquatChecker()
        ts_result = ts.check(pkg)
        if ts_result.is_suspect:
            return {"safe": False, "reason": ts_result.message}

        return {"safe": True, "message": f"'{args['name']}' passed blocklist and typosquat checks"}

    def _tool_config(self, args: dict) -> dict:
        from agentguard.config import Config
        from dataclasses import asdict

        config = Config.load()
        action = args["action"]

        if action == "show":
            return asdict(config)
        elif action == "allow" and args.get("package"):
            config.allowlist.append(args["package"])
            config.save()
            return {"status": "ok", "message": f"Added '{args['package']}' to allowlist"}
        elif action == "block" and args.get("package"):
            config.blocklist_extra.append(args["package"])
            config.save()
            return {"status": "ok", "message": f"Added '{args['package']}' to blocklist"}
        return {"error": "Invalid action or missing package"}

    def _respond(self, msg_id: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _error(self, msg_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


if __name__ == "__main__":
    serve()
