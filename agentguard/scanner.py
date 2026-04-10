"""Main scanning orchestrator - coordinates all checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from agentguard.config import Config
from agentguard.parsers import parse_command, CommandAction, PackageRef
from agentguard.checks.typosquat import TyposquatChecker
from agentguard.checks.registry import RegistryChecker
from agentguard.checks.blocklist import BlocklistChecker
from agentguard.checks.repo import RepoChecker
from agentguard.checks.patterns import PatternChecker
from agentguard.checks.virustotal import VirusTotalChecker
from agentguard.checks.feed import FeedChecker


@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # typosquat, blocklist, registry, repo, pattern
    package: Optional[str] = None
    message: str = ""
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        pkg = f" [{self.package}]" if self.package else ""
        return f"[{self.severity}] {self.category}{pkg}: {self.message}"


@dataclass
class ScanResult:
    command: str
    findings: list[Finding] = field(default_factory=list)
    actions_parsed: int = 0
    packages_checked: int = 0

    def has_blockers(self) -> bool:
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    def has_warnings(self) -> bool:
        return any(f.severity in ("MEDIUM", "LOW") for f in self.findings)

    @property
    def max_severity(self) -> str:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if not self.findings:
            return "NONE"
        return min(self.findings, key=lambda f: order.get(f.severity, 5)).severity

    def format(self, verbose: bool = False) -> str:
        if not self.findings:
            return "OK: No issues found"

        lines = []
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

        for f in sorted_findings:
            lines.append(str(f))
            if verbose and f.details:
                for k, v in f.details.items():
                    lines.append(f"  {k}: {v}")

        return "\n".join(lines)


def scan_command(command: str, config: Optional[Config] = None) -> ScanResult:
    """Scan a shell command for supply chain risks."""
    config = config or Config.load()
    result = ScanResult(command=command)

    # Parse the command
    actions = parse_command(command)
    result.actions_parsed = len(actions)

    # Initialize checkers
    typosquat = TyposquatChecker(threshold=config.typosquat_threshold) if config.check_typosquat else None
    registry = RegistryChecker(config) if config.check_registry else None
    blocklist = BlocklistChecker(extra_blocked=config.blocklist_extra) if config.check_blocklist else None
    repo = RepoChecker(config) if config.check_repo else None
    patterns = PatternChecker() if config.check_patterns else None
    vt = VirusTotalChecker(config) if getattr(config, "check_virustotal", False) else None
    feed = FeedChecker() if getattr(config, "check_feed", True) else None

    # Run pattern checks on the full command
    if patterns:
        pattern_results = patterns.check(command)
        for pr in pattern_results:
            if pr.is_suspect:
                result.findings.append(Finding(
                    severity=pr.severity,
                    category="pattern",
                    message=pr.message,
                    details={"pattern": pr.pattern_name},
                ))

    # Process each action
    for action in actions:
        # Check packages
        for pkg in action.packages:
            result.packages_checked += 1

            # Skip allowlisted packages
            if pkg.full_name.lower() in {a.lower() for a in config.allowlist}:
                continue

            # Blocklist check
            if blocklist:
                bl_result = blocklist.check(pkg)
                if bl_result.is_blocked:
                    result.findings.append(Finding(
                        severity="CRITICAL",
                        category="blocklist",
                        package=pkg.full_name,
                        message=bl_result.message,
                        details={"reason": bl_result.reason, "reference": bl_result.reference},
                    ))
                    continue  # No need for further checks

            # Live feed check (OSV.dev)
            if feed:
                feed_result = feed.check_package(pkg.full_name, pkg.manager, pkg.version)
                if feed_result:
                    result.findings.append(Finding(
                        severity=feed_result.severity,
                        category="feed",
                        package=pkg.full_name,
                        message=f"OSV advisory: {feed_result.reason}",
                        details={"reference": feed_result.reference},
                    ))

            # Typosquatting check
            if typosquat:
                ts_result = typosquat.check(pkg)
                if ts_result.is_suspect:
                    severity = "HIGH" if ts_result.confidence > 0.8 else "MEDIUM"
                    result.findings.append(Finding(
                        severity=severity,
                        category="typosquat",
                        package=pkg.full_name,
                        message=ts_result.message,
                        details={
                            "target": ts_result.target_package,
                            "distance": ts_result.distance,
                            "attack_type": ts_result.attack_type,
                            "confidence": ts_result.confidence,
                        },
                    ))

            # VirusTotal check
            if vt and vt.enabled:
                vt_result = None
                if pkg.manager in ("npm", "pnpm", "yarn", "bun", "npx"):
                    vt_result = vt.scan_npm_package(pkg.full_name, pkg.version)
                elif pkg.manager in ("pip", "pip3", "uv"):
                    vt_result = vt.scan_pypi_package(pkg.name, pkg.version)

                if vt_result and vt_result.is_malicious:
                    result.findings.append(Finding(
                        severity="CRITICAL",
                        category="virustotal",
                        package=pkg.full_name,
                        message=vt_result.message,
                        details={
                            "detections": vt_result.detection_rate,
                            "engines": vt_result.detection_names[:5],
                            "permalink": vt_result.permalink,
                        },
                    ))
                elif vt_result and vt_result.is_suspect:
                    result.findings.append(Finding(
                        severity="HIGH",
                        category="virustotal",
                        package=pkg.full_name,
                        message=vt_result.message,
                        details={"detections": vt_result.detection_rate},
                    ))

            # Registry check
            if registry:
                reg_result = registry.check(pkg)
                if reg_result.error:
                    if config.verbose:
                        result.findings.append(Finding(
                            severity="INFO",
                            category="registry",
                            package=pkg.full_name,
                            message=f"Registry check failed: {reg_result.error}",
                        ))
                elif not reg_result.exists:
                    result.findings.append(Finding(
                        severity="HIGH",
                        category="registry",
                        package=pkg.full_name,
                        message=reg_result.message,
                    ))
                elif reg_result.is_suspect:
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        category="registry",
                        package=pkg.full_name,
                        message=reg_result.message,
                        details={
                            "age_days": reg_result.age_days,
                            "weekly_downloads": reg_result.weekly_downloads,
                            "has_repo": reg_result.has_repo,
                        },
                    ))

        # VirusTotal URL scan for downloads
        if vt and vt.enabled and action.urls and action.action in ("download", "piped_exec", "clone"):
            for url in action.urls:
                vt_url_result = vt.scan_url(url)
                if vt_url_result.is_malicious:
                    result.findings.append(Finding(
                        severity="CRITICAL",
                        category="virustotal",
                        message=f"URL flagged by VirusTotal: {vt_url_result.message}",
                        details={"url": url, "detections": vt_url_result.detection_rate},
                    ))
                elif vt_url_result.is_suspect:
                    result.findings.append(Finding(
                        severity="HIGH",
                        category="virustotal",
                        message=f"URL suspicious on VirusTotal: {vt_url_result.message}",
                        details={"url": url, "detections": vt_url_result.detection_rate},
                    ))

        # Check URLs (for clone/download actions)
        if repo and action.urls:
            for url in action.urls:
                repo_result = repo.check_url(url)
                if repo_result.error:
                    if config.verbose:
                        result.findings.append(Finding(
                            severity="INFO",
                            category="repo",
                            message=f"Repo check failed: {repo_result.error}",
                            details={"url": url},
                        ))
                elif not repo_result.exists:
                    result.findings.append(Finding(
                        severity="HIGH",
                        category="repo",
                        message=repo_result.message,
                        details={"url": url},
                    ))
                elif repo_result.is_suspect:
                    result.findings.append(Finding(
                        severity="MEDIUM",
                        category="repo",
                        message=repo_result.message,
                        details={
                            "url": url,
                            "stars": repo_result.stars,
                            "is_fork": repo_result.is_fork,
                        },
                    ))

    return result
