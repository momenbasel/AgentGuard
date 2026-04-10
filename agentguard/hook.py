"""Claude Code hook handler - reads tool input from stdin, runs checks."""

from __future__ import annotations

import json
import sys

from agentguard.config import Config
from agentguard.scanner import scan_command


SEVERITY_EXIT_CODES = {
    "CRITICAL": 2,
    "HIGH": 2,
    "MEDIUM": 0,  # warn but allow
    "LOW": 0,
    "INFO": 0,
    "NONE": 0,
}


def hook_main(strict: bool = False) -> None:
    """Entry point for Claude Code PreToolUse hook.

    Reads JSON from stdin with shape:
      { "tool_name": "Bash", "tool_input": { "command": "..." } }

    Exits 0 to allow, 2 to block.
    Findings are printed to stderr (shown to the model).
    """
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        input_data = json.loads(raw)
    except (json.JSONDecodeError, KeyboardInterrupt):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only inspect Bash commands
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    config = Config.load()
    if strict:
        config.mode = "strict"

    result = scan_command(command, config)

    if not result.findings:
        # Clean - output brief OK to stderr for transparency
        print("AgentGuard: OK", file=sys.stderr)
        sys.exit(0)

    # Print findings to stderr
    print(f"AgentGuard: {len(result.findings)} finding(s)", file=sys.stderr)
    print(result.format(verbose=config.verbose), file=sys.stderr)

    if result.has_blockers():
        print(
            "\nAgentGuard BLOCKED this command. "
            "Add packages to allowlist in ~/.agentguard/config.json to override.",
            file=sys.stderr,
        )
        sys.exit(2)

    # Warnings - allow but inform
    sys.exit(0)
