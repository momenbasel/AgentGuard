"""Known malicious package blocklist."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agentguard.parsers import PackageRef

DATA_DIR = Path(__file__).parent.parent / "data"


@dataclass
class BlocklistResult:
    is_blocked: bool = False
    reason: Optional[str] = None
    reference: Optional[str] = None
    message: str = ""


class BlocklistChecker:
    def __init__(self, extra_blocked: Optional[list[str]] = None):
        self._blocklist: Optional[dict] = None
        self.extra_blocked = set(extra_blocked or [])

    @property
    def blocklist(self) -> dict:
        if self._blocklist is None:
            path = DATA_DIR / "blocklist.json"
            if path.exists():
                with open(path) as f:
                    self._blocklist = json.load(f)
            else:
                self._blocklist = {}
        return self._blocklist

    def check(self, pkg: PackageRef) -> BlocklistResult:
        """Check if a package is on the blocklist."""
        name = pkg.full_name.lower()

        # Check extra blocklist
        if name in self.extra_blocked:
            return BlocklistResult(
                is_blocked=True,
                reason="User-configured blocklist",
                message=f"Package '{pkg.full_name}' is on your custom blocklist",
            )

        # Check by manager
        manager_key = _normalize_manager(pkg.manager)
        manager_list = self.blocklist.get(manager_key, {})

        if name in manager_list:
            entry = manager_list[name]
            return BlocklistResult(
                is_blocked=True,
                reason=entry.get("reason", "Known malicious package"),
                reference=entry.get("reference"),
                message=f"BLOCKED: '{pkg.full_name}' - {entry.get('reason', 'known malicious')}",
            )

        # Check wildcard patterns (e.g., all packages from a known-bad scope)
        patterns = self.blocklist.get("patterns", {}).get(manager_key, [])
        for pattern in patterns:
            import fnmatch
            if fnmatch.fnmatch(name, pattern.get("pattern", "")):
                return BlocklistResult(
                    is_blocked=True,
                    reason=pattern.get("reason", "Matches malicious pattern"),
                    message=f"BLOCKED: '{pkg.full_name}' matches pattern - {pattern.get('reason', '')}",
                )

        return BlocklistResult(is_blocked=False)


def _normalize_manager(manager: str) -> str:
    """Normalize manager name for blocklist lookup."""
    npm_family = {"npm", "pnpm", "yarn", "bun", "npx"}
    pip_family = {"pip", "pip3", "uv"}

    if manager in npm_family:
        return "npm"
    if manager in pip_family:
        return "pypi"
    if manager == "composer":
        return "composer"
    return manager
