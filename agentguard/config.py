"""AgentGuard configuration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG_PATH = Path.home() / ".agentguard" / "config.json"

RISK_THRESHOLDS = {
    "strict": 30,
    "normal": 60,
    "permissive": 80,
}


@dataclass
class Config:
    mode: str = "normal"  # strict, normal, permissive
    block_piped_exec: bool = True
    check_typosquat: bool = True
    check_registry: bool = True
    check_blocklist: bool = True
    check_repo: bool = True
    check_patterns: bool = True
    check_virustotal: bool = False  # requires VT_API_KEY env var
    typosquat_threshold: int = 2  # max edit distance
    min_package_age_days: int = 7
    min_downloads: int = 100
    allowlist: list[str] = field(default_factory=list)
    blocklist_extra: list[str] = field(default_factory=list)
    registry_timeout: int = 5
    verbose: bool = False

    @property
    def risk_threshold(self) -> int:
        return RISK_THRESHOLDS.get(self.mode, 60)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        path = path or DEFAULT_CONFIG_PATH
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()

    def save(self, path: Optional[Path] = None) -> None:
        path = path or DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        from dataclasses import asdict
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)
