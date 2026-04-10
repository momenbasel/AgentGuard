"""AgentGuard as a Claude Code skill.

This module provides the skill entry point that Claude Code invokes
when the user triggers /agentguard or when the PreToolUse hook fires.
"""

from __future__ import annotations

import json
import sys

from agentguard.config import Config
from agentguard.scanner import scan_command


SKILL_PROMPT = """You are AgentGuard, an AI supply chain security scanner.
When invoked, analyze the provided command or package list for:
1. Known malicious packages (blocklist)
2. Typosquatting of popular packages (Levenshtein distance + homoglyphs)
3. Suspicious registry metadata (new packages, low downloads, no repo)
4. Dangerous command patterns (curl|sh, sudo install, custom registries)
5. VirusTotal detections (if VT_API_KEY is set)
6. Repository verification (GitHub stars, age, forks)

Report findings by severity: CRITICAL > HIGH > MEDIUM > LOW > INFO.
Block CRITICAL and HIGH. Warn on MEDIUM. Allow LOW and INFO.
"""


def skill_main():
    """Entry point when invoked as a Claude Code skill.

    Usage: agentguard skill "npm install some-package"
    Or pipe: echo '{"command": "npm install foo"}' | agentguard skill --stdin
    """
    import argparse

    parser = argparse.ArgumentParser(prog="agentguard skill")
    parser.add_argument("command", nargs="*", help="Command to analyze")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument("--vt", action="store_true", help="Enable VirusTotal scanning")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(sys.argv[2:] if len(sys.argv) > 2 else [])

    config = Config.load()
    if args.strict:
        config.mode = "strict"
    if args.vt:
        config.check_virustotal = True

    if args.stdin:
        raw = sys.stdin.read().strip()
        try:
            data = json.loads(raw)
            command = data.get("command", raw)
        except json.JSONDecodeError:
            command = raw
    elif args.command:
        command = " ".join(args.command)
    else:
        print("Usage: agentguard skill <command>")
        print("       echo '<cmd>' | agentguard skill --stdin")
        sys.exit(1)

    result = scan_command(command, config)

    # Output structured result for the AI to interpret
    output = {
        "agentguard_version": "0.1.0",
        "command": command,
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
        "stats": {
            "packages_checked": result.packages_checked,
            "actions_parsed": result.actions_parsed,
        },
    }

    print(json.dumps(output, indent=2))
    sys.exit(2 if result.has_blockers() else 0)
