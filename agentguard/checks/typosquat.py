"""Typosquatting detection using edit distance and common attack patterns."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agentguard.parsers import PackageRef


DATA_DIR = Path(__file__).parent.parent / "data"

# Homoglyph map for visual confusion attacks
HOMOGLYPHS = {
    "l": ["1", "I", "|"],
    "I": ["l", "1", "|"],
    "1": ["l", "I", "|"],
    "0": ["O", "o"],
    "O": ["0", "o"],
    "o": ["0", "O"],
    "rn": ["m"],
    "m": ["rn"],
    "vv": ["w"],
    "w": ["vv"],
    "cl": ["d"],
    "d": ["cl"],
}


@dataclass
class TyposquatResult:
    is_suspect: bool
    target_package: Optional[str] = None
    distance: int = 0
    attack_type: Optional[str] = None  # swap, insert, delete, homoglyph, scope
    confidence: float = 0.0
    message: str = ""


class TyposquatChecker:
    def __init__(self, threshold: int = 2):
        self.threshold = threshold
        self._popular_npm: Optional[set[str]] = None
        self._popular_pypi: Optional[set[str]] = None

    def _load_popular(self, manager: str) -> set[str]:
        """Load popular package names for a given manager."""
        filename = f"popular_{manager}.txt"
        filepath = DATA_DIR / filename
        if not filepath.exists():
            return set()
        with open(filepath) as f:
            return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}

    @property
    def popular_npm(self) -> set[str]:
        if self._popular_npm is None:
            self._popular_npm = self._load_popular("npm")
        return self._popular_npm

    @property
    def popular_pypi(self) -> set[str]:
        if self._popular_pypi is None:
            self._popular_pypi = self._load_popular("pypi")
        return self._popular_pypi

    def _get_popular_for(self, manager: str) -> set[str]:
        """Get the correct popular set for a package manager."""
        if manager in ("npm", "pnpm", "yarn", "bun", "npx"):
            return self.popular_npm
        if manager in ("pip", "pip3", "uv"):
            return self.popular_pypi
        return self.popular_npm | self.popular_pypi

    def check(self, pkg: PackageRef) -> TyposquatResult:
        """Check a package for typosquatting similarity to popular packages."""
        name = pkg.full_name.lower()
        popular = self._get_popular_for(pkg.manager)

        # Exact match = legitimate
        if name in popular:
            return TyposquatResult(is_suspect=False)

        # Check edit distance against each popular package
        best_match = None
        best_distance = self.threshold + 1

        for pop in popular:
            dist = _levenshtein(name, pop)
            if 0 < dist <= self.threshold and dist < best_distance:
                best_distance = dist
                best_match = pop

        if best_match:
            attack_type = _classify_attack(name, best_match)
            confidence = 1.0 - (best_distance / (len(best_match) + 1))
            return TyposquatResult(
                is_suspect=True,
                target_package=best_match,
                distance=best_distance,
                attack_type=attack_type,
                confidence=confidence,
                message=f"'{pkg.full_name}' looks like typosquat of '{best_match}' "
                        f"(distance={best_distance}, type={attack_type})",
            )

        # Check homoglyph attacks
        homoglyph_match = _check_homoglyphs(name, popular)
        if homoglyph_match:
            return TyposquatResult(
                is_suspect=True,
                target_package=homoglyph_match,
                distance=0,
                attack_type="homoglyph",
                confidence=0.9,
                message=f"'{pkg.full_name}' uses visual confusion with '{homoglyph_match}'",
            )

        # Check scope confusion (@angular/core vs @angullar/core)
        if pkg.scope:
            scope_match = _check_scope_confusion(pkg, popular)
            if scope_match:
                return scope_match

        return TyposquatResult(is_suspect=False)


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def _classify_attack(suspect: str, target: str) -> str:
    """Classify the type of typosquatting attack."""
    if len(suspect) > len(target):
        return "insertion"
    if len(suspect) < len(target):
        return "deletion"

    # Check for transposition
    diffs = [(i, s, t) for i, (s, t) in enumerate(zip(suspect, target)) if s != t]
    if len(diffs) == 2:
        i1, s1, t1 = diffs[0]
        i2, s2, t2 = diffs[1]
        if s1 == t2 and s2 == t1 and abs(i1 - i2) == 1:
            return "transposition"

    return "substitution"


def _check_homoglyphs(name: str, popular: set[str]) -> Optional[str]:
    """Check for homoglyph-based attacks."""
    for char, replacements in HOMOGLYPHS.items():
        if char in name:
            for repl in replacements:
                candidate = name.replace(char, repl)
                if candidate in popular:
                    return candidate
    return None


def _check_scope_confusion(pkg: PackageRef, popular: set[str]) -> Optional[TyposquatResult]:
    """Check for npm scope confusion attacks."""
    if not pkg.scope:
        return None

    scope_name = pkg.scope.lstrip("@").lower()
    pkg_name = pkg.name.lower()

    # Check if the unscoped version is popular
    if pkg_name in popular:
        return TyposquatResult(
            is_suspect=True,
            target_package=pkg_name,
            distance=0,
            attack_type="scope_confusion",
            confidence=0.7,
            message=f"'{pkg.full_name}' adds a scope to popular package '{pkg_name}' - possible scope confusion",
        )

    # Check if the scope itself is a typosquat of known orgs
    known_scopes = {"angular", "babel", "types", "vue", "react", "aws-sdk",
                    "google-cloud", "azure", "anthropic", "openai", "vercel"}
    for ks in known_scopes:
        if 0 < _levenshtein(scope_name, ks) <= 1:
            return TyposquatResult(
                is_suspect=True,
                target_package=f"@{ks}/{pkg_name}",
                distance=_levenshtein(scope_name, ks),
                attack_type="scope_typosquat",
                confidence=0.85,
                message=f"Scope '@{scope_name}' is similar to known org '@{ks}'",
            )

    return None
