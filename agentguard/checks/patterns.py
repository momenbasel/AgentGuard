"""Suspicious command pattern detection."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PatternResult:
    is_suspect: bool = False
    severity: str = "INFO"  # INFO, MEDIUM, HIGH, CRITICAL
    pattern_name: str = ""
    message: str = ""


SUSPICIOUS_PATTERNS = [
    {
        "name": "piped_execution",
        "pattern": r"curl\s+.*\|\s*(sudo\s+)?(ba)?sh",
        "severity": "CRITICAL",
        "message": "Remote script piped directly to shell - cannot verify content before execution",
    },
    {
        "name": "piped_execution_wget",
        "pattern": r"wget\s+.*\|\s*(sudo\s+)?(ba)?sh",
        "severity": "CRITICAL",
        "message": "Remote script piped directly to shell via wget",
    },
    {
        "name": "piped_python",
        "pattern": r"curl\s+.*\|\s*(sudo\s+)?python3?",
        "severity": "CRITICAL",
        "message": "Remote script piped to Python interpreter",
    },
    {
        "name": "eval_remote",
        "pattern": r"eval\s+\"\$\(curl",
        "severity": "CRITICAL",
        "message": "eval of remote content - extremely dangerous",
    },
    {
        "name": "hidden_npm_script",
        "pattern": r"npm\s+(run|exec)\s+\S*install\S*",
        "severity": "HIGH",
        "message": "npm run script with 'install' in name - could be disguised postinstall",
    },
    {
        "name": "global_install",
        "pattern": r"(npm|pnpm|yarn)\s+(i|install)\s+-g\s+",
        "severity": "MEDIUM",
        "message": "Global package install - will affect system-wide",
    },
    {
        "name": "sudo_install",
        "pattern": r"sudo\s+(npm|pip|pip3|gem)\s+install",
        "severity": "HIGH",
        "message": "Package install with sudo - packages run with root privileges",
    },
    {
        "name": "npm_override_registry",
        "pattern": r"(npm|pnpm|yarn)\s+.*--registry\s+(?!https://registry\.npmjs\.org)",
        "severity": "HIGH",
        "message": "Non-default npm registry - packages may not be from npmjs.org",
    },
    {
        "name": "pip_override_index",
        "pattern": r"pip3?\s+install\s+.*--index-url\s+(?!https://pypi\.org)",
        "severity": "HIGH",
        "message": "Non-default PyPI index - packages may not be from pypi.org",
    },
    {
        "name": "pip_extra_index",
        "pattern": r"pip3?\s+install\s+.*--extra-index-url",
        "severity": "MEDIUM",
        "message": "Extra PyPI index URL - dependency confusion risk",
    },
    {
        "name": "install_from_url",
        "pattern": r"pip3?\s+install\s+https?://",
        "severity": "HIGH",
        "message": "pip install from direct URL - bypasses PyPI safety checks",
    },
    {
        "name": "npm_ignore_scripts",
        "pattern": r"npm\s+.*--ignore-scripts\s*$",
        "severity": "INFO",
        "message": "npm --ignore-scripts is actually safer (disables postinstall)",
    },
    {
        "name": "cargo_no_verify",
        "pattern": r"cargo\s+install\s+.*--no-verify",
        "severity": "MEDIUM",
        "message": "cargo install with --no-verify skips build verification",
    },
    {
        "name": "gem_no_ri",
        "pattern": r"gem\s+install\s+.*--no-document",
        "severity": "INFO",
        "message": "gem install detected",
    },
    {
        "name": "go_insecure",
        "pattern": r"GONOSUMCHECK=\S+\s+go\s+(get|install)",
        "severity": "HIGH",
        "message": "Go install with checksum verification disabled",
    },
    {
        "name": "chmod_exec_download",
        "pattern": r"(curl|wget)\s+.*&&\s*chmod\s+\+x",
        "severity": "HIGH",
        "message": "Download and make executable - review the downloaded file first",
    },
    {
        "name": "base64_decode_exec",
        "pattern": r"base64\s+(-d|--decode).*\|\s*(ba)?sh",
        "severity": "CRITICAL",
        "message": "base64 decoded content piped to shell - obfuscated execution",
    },
    {
        "name": "skill_install",
        "pattern": r"npx\s+skills?\s+install",
        "severity": "MEDIUM",
        "message": "AI skill installation - verify the skill source and permissions",
    },
]


class PatternChecker:
    def __init__(self):
        self.patterns = SUSPICIOUS_PATTERNS

    def check(self, command: str) -> list[PatternResult]:
        """Check a command against all suspicious patterns."""
        results = []
        for p in self.patterns:
            if re.search(p["pattern"], command, re.IGNORECASE):
                results.append(PatternResult(
                    is_suspect=True,
                    severity=p["severity"],
                    pattern_name=p["name"],
                    message=p["message"],
                ))
        return results
