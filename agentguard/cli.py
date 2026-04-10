"""AgentGuard CLI - scan commands, manage config, install hooks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentguard import __version__
from agentguard.config import Config
from agentguard.hook import hook_main
from agentguard.scanner import scan_command


def main():
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AI Agent Supply Chain Security - protect against malicious packages installed by AI agents",
    )
    parser.add_argument("-V", "--version", action="version", version=f"agentguard {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan a shell command for risks")
    scan_parser.add_argument("cmd", nargs="+", help="Command to scan")
    scan_parser.add_argument("-v", "--verbose", action="store_true")
    scan_parser.add_argument("--json", action="store_true", dest="json_output", help="JSON output")
    scan_parser.add_argument("--strict", action="store_true", help="Use strict mode")

    # hook
    hook_parser = subparsers.add_parser("hook", help="Run as Claude Code hook (reads stdin)")
    hook_parser.add_argument("--strict", action="store_true")

    # install
    install_parser = subparsers.add_parser("install", help="Install Claude Code hooks")
    install_parser.add_argument("--global", action="store_true", dest="global_install",
                                help="Install globally (~/.claude/settings.json)")
    install_parser.add_argument("--strict", action="store_true",
                                help="Install in strict mode (block HIGH + CRITICAL)")

    # config
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_sub.add_parser("show", help="Show current config")
    config_sub.add_parser("init", help="Create default config file")
    allow_parser = config_sub.add_parser("allow", help="Add package to allowlist")
    allow_parser.add_argument("package", help="Package name to allow")
    block_parser = config_sub.add_parser("block", help="Add package to blocklist")
    block_parser.add_argument("package", help="Package name to block")

    # uninstall
    subparsers.add_parser("uninstall", help="Remove Claude Code hooks")

    # update
    subparsers.add_parser("update", help="Update blocklist from live security feeds (OSV.dev)")

    # mcp
    subparsers.add_parser("mcp", help="Run as MCP server (stdio transport)")

    # skill
    skill_parser = subparsers.add_parser("skill", help="Run as Claude Code skill")
    skill_parser.add_argument("cmd", nargs="*", help="Command to analyze")
    skill_parser.add_argument("--stdin", action="store_true")
    skill_parser.add_argument("--vt", action="store_true", help="Enable VirusTotal")
    skill_parser.add_argument("--strict", action="store_true")

    args = parser.parse_args()

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "hook":
        hook_main(strict=args.strict)
    elif args.command == "install":
        _cmd_install(args)
    elif args.command == "uninstall":
        _cmd_uninstall()
    elif args.command == "config":
        _cmd_config(args)
    elif args.command == "update":
        _cmd_update()
    elif args.command == "mcp":
        from agentguard.mcp_server import serve
        serve()
    elif args.command == "skill":
        from agentguard.skill import skill_main
        skill_main()
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_scan(args):
    """Scan a command string."""
    command = " ".join(args.cmd)
    config = Config.load()
    config.verbose = args.verbose
    if args.strict:
        config.mode = "strict"

    result = scan_command(command, config)

    if args.json_output:
        output = {
            "command": result.command,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "package": f.package,
                    "message": f.message,
                    "details": f.details,
                }
                for f in result.findings
            ],
            "summary": {
                "total": len(result.findings),
                "max_severity": result.max_severity,
                "blocked": result.has_blockers(),
                "packages_checked": result.packages_checked,
            },
        }
        print(json.dumps(output, indent=2))
    else:
        if not result.findings:
            print("OK: No issues found")
        else:
            print(result.format(verbose=args.verbose))
            if result.has_blockers():
                print(f"\nWould BLOCK this command ({result.max_severity})")

    sys.exit(2 if result.has_blockers() else 0)


def _cmd_install(args):
    """Install AgentGuard as a Claude Code hook."""
    if args.global_install:
        settings_path = Path.home() / ".claude" / "settings.json"
    else:
        settings_path = Path.cwd() / ".claude" / "settings.json"

    settings_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing settings
    settings = {}
    if settings_path.exists():
        with open(settings_path) as f:
            settings = json.load(f)

    # Build hook command
    hook_cmd = "agentguard hook"
    if args.strict:
        hook_cmd += " --strict"

    # Add the hook
    hooks = settings.setdefault("hooks", {})
    pre_tool = hooks.setdefault("PreToolUse", [])

    # Check if already installed
    for entry in pre_tool:
        if isinstance(entry, dict):
            for h in entry.get("hooks", []):
                if "agentguard" in h.get("command", ""):
                    print(f"AgentGuard hook already installed in {settings_path}")
                    return

    hook_entry = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": hook_cmd,
            }
        ],
    }
    pre_tool.append(hook_entry)

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)

    scope = "globally" if args.global_install else f"in {settings_path}"
    mode = "strict" if args.strict else "normal"
    print(f"AgentGuard hook installed {scope} (mode: {mode})")
    print(f"Config: {settings_path}")


def _cmd_uninstall():
    """Remove AgentGuard hooks from Claude Code settings."""
    removed = False
    for settings_path in [
        Path.home() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.json",
    ]:
        if not settings_path.exists():
            continue

        with open(settings_path) as f:
            settings = json.load(f)

        hooks = settings.get("hooks", {})
        pre_tool = hooks.get("PreToolUse", [])

        new_pre_tool = []
        for entry in pre_tool:
            if isinstance(entry, dict):
                new_hooks = [
                    h for h in entry.get("hooks", [])
                    if "agentguard" not in h.get("command", "")
                ]
                if new_hooks:
                    entry["hooks"] = new_hooks
                    new_pre_tool.append(entry)
                else:
                    removed = True
            else:
                new_pre_tool.append(entry)

        if removed:
            hooks["PreToolUse"] = new_pre_tool
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
            print(f"AgentGuard hook removed from {settings_path}")

    if not removed:
        print("No AgentGuard hooks found to remove")


def _cmd_update():
    """Update blocklist from live security feeds."""
    from agentguard.checks.feed import FeedChecker

    blocklist_path = Path(__file__).parent / "data" / "blocklist.json"
    feed = FeedChecker()
    count = feed.update_blocklist(blocklist_path)
    print(f"Blocklist updated: {count} new entries added")


def _cmd_config(args):
    """Manage AgentGuard configuration."""
    if args.config_command == "show":
        config = Config.load()
        from dataclasses import asdict
        print(json.dumps(asdict(config), indent=2))

    elif args.config_command == "init":
        config = Config()
        config.save()
        print(f"Config created at {Config.DEFAULT_CONFIG_PATH if hasattr(Config, 'DEFAULT_CONFIG_PATH') else '~/.agentguard/config.json'}")

    elif args.config_command == "allow":
        config = Config.load()
        if args.package not in config.allowlist:
            config.allowlist.append(args.package)
            config.save()
            print(f"Added '{args.package}' to allowlist")
        else:
            print(f"'{args.package}' already in allowlist")

    elif args.config_command == "block":
        config = Config.load()
        if args.package not in config.blocklist_extra:
            config.blocklist_extra.append(args.package)
            config.save()
            print(f"Added '{args.package}' to blocklist")
        else:
            print(f"'{args.package}' already in blocklist")

    else:
        print("Usage: agentguard config {show|init|allow|block}")


if __name__ == "__main__":
    main()
