"""Repository verification checks."""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

from agentguard.config import Config


@dataclass
class RepoResult:
    is_suspect: bool = False
    exists: bool = True
    stars: Optional[int] = None
    is_fork: bool = False
    is_archived: bool = False
    owner_type: Optional[str] = None
    message: str = ""
    error: Optional[str] = None


class RepoChecker:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    def check_url(self, url: str) -> RepoResult:
        """Check a git URL for suspicious characteristics."""
        # Extract GitHub owner/repo
        github_match = re.match(
            r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/.\s]+?)(?:\.git)?/?$",
            url,
        )
        if github_match:
            owner, repo = github_match.groups()
            return self._check_github(owner, repo)

        # Non-GitHub URLs - flag as informational
        if re.match(r"https?://", url):
            return RepoResult(
                is_suspect=False,
                message=f"Non-GitHub repo URL, manual verification recommended: {url}",
            )

        return RepoResult()

    def _check_github(self, owner: str, repo: str) -> RepoResult:
        """Check GitHub repository metadata."""
        url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {"Accept": "application/vnd.github.v3+json"}

        # Use GITHUB_TOKEN if available
        import os
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.config.registry_timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return RepoResult(
                    exists=False,
                    is_suspect=True,
                    message=f"GitHub repo '{owner}/{repo}' does not exist",
                )
            return RepoResult(error=f"GitHub API error: {e.code}")
        except Exception as e:
            return RepoResult(error=f"GitHub API unreachable: {e}")

        result = RepoResult()
        issues = []

        result.stars = data.get("stargazers_count", 0)
        result.is_fork = data.get("fork", False)
        result.is_archived = data.get("archived", False)
        result.owner_type = data.get("owner", {}).get("type", "Unknown")

        if result.is_archived:
            issues.append("repository is archived")

        if result.is_fork:
            parent = data.get("parent", {}).get("full_name", "unknown")
            issues.append(f"repository is a fork of {parent}")

        if result.stars is not None and result.stars < 5:
            issues.append(f"very low star count ({result.stars})")

        # Check if repo was recently created
        created_at = data.get("created_at")
        if created_at:
            from datetime import datetime, timezone
            try:
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days < 30:
                    issues.append(f"repo created only {age_days} days ago")
            except (ValueError, TypeError):
                pass

        if issues:
            result.is_suspect = True
            result.message = f"GitHub '{owner}/{repo}': {', '.join(issues)}"

        return result

    def verify_clone_target(self, url: str, expected_owner: Optional[str] = None) -> RepoResult:
        """Verify a git clone target is legitimate and not a lookalike."""
        result = self.check_url(url)

        if expected_owner and not result.error:
            github_match = re.match(
                r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/",
                url,
            )
            if github_match:
                actual_owner = github_match.group(1).lower()
                if actual_owner != expected_owner.lower():
                    result.is_suspect = True
                    result.message = (
                        f"Expected owner '{expected_owner}' but got '{actual_owner}'. "
                        f"{result.message}"
                    )

        return result
