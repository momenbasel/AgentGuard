"""Registry metadata checks - age, downloads, maintainers."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from agentguard.config import Config
from agentguard.parsers import PackageRef


@dataclass
class RegistryResult:
    exists: bool = True
    is_suspect: bool = False
    age_days: Optional[int] = None
    weekly_downloads: Optional[int] = None
    maintainer_count: Optional[int] = None
    has_repo: bool = True
    message: str = ""
    error: Optional[str] = None


class RegistryChecker:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()

    def check(self, pkg: PackageRef) -> RegistryResult:
        """Check package registry metadata."""
        if pkg.manager in ("npm", "pnpm", "yarn", "bun", "npx"):
            return self._check_npm(pkg)
        if pkg.manager in ("pip", "pip3", "uv"):
            return self._check_pypi(pkg)
        if pkg.manager == "composer":
            return self._check_packagist(pkg)
        return RegistryResult(message="Registry check not supported for this manager")

    def _check_npm(self, pkg: PackageRef) -> RegistryResult:
        """Check npm registry for package metadata."""
        name = pkg.full_name
        url = f"https://registry.npmjs.org/{name}"

        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.config.registry_timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return RegistryResult(
                    exists=False,
                    is_suspect=True,
                    message=f"Package '{name}' not found on npm registry",
                )
            return RegistryResult(error=f"npm registry error: {e.code}")
        except Exception as e:
            return RegistryResult(error=f"npm registry unreachable: {e}")

        result = RegistryResult()
        issues = []

        # Check age
        time_info = data.get("time", {})
        created = time_info.get("created")
        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - created_dt).days
                result.age_days = age
                if age < self.config.min_package_age_days:
                    result.is_suspect = True
                    issues.append(f"package is only {age} days old")
            except (ValueError, TypeError):
                pass

        # Check maintainers
        maintainers = data.get("maintainers", [])
        result.maintainer_count = len(maintainers)
        if len(maintainers) == 0:
            result.is_suspect = True
            issues.append("no maintainers listed")

        # Check repository
        latest = data.get("versions", {})
        latest_version = data.get("dist-tags", {}).get("latest", "")
        version_data = latest.get(latest_version, {})
        repo = version_data.get("repository") or data.get("repository")
        if not repo:
            result.has_repo = False
            issues.append("no repository URL")

        if issues:
            result.message = f"npm '{name}': {', '.join(issues)}"

        return result

    def _check_pypi(self, pkg: PackageRef) -> RegistryResult:
        """Check PyPI for package metadata."""
        url = f"https://pypi.org/pypi/{pkg.name}/json"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.config.registry_timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return RegistryResult(
                    exists=False,
                    is_suspect=True,
                    message=f"Package '{pkg.name}' not found on PyPI",
                )
            return RegistryResult(error=f"PyPI error: {e.code}")
        except Exception as e:
            return RegistryResult(error=f"PyPI unreachable: {e}")

        result = RegistryResult()
        issues = []
        info = data.get("info", {})

        # Check project URLs for repo
        urls = info.get("project_urls") or {}
        if not urls:
            result.has_repo = False
            issues.append("no project URLs")

        # Check upload time of earliest release
        releases = data.get("releases", {})
        earliest_upload = None
        for version, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        if earliest_upload is None or dt < earliest_upload:
                            earliest_upload = dt
                    except (ValueError, TypeError):
                        pass

        if earliest_upload:
            age = (datetime.now(timezone.utc) - earliest_upload).days
            result.age_days = age
            if age < self.config.min_package_age_days:
                result.is_suspect = True
                issues.append(f"first upload only {age} days ago")

        # Check author
        author = info.get("author") or info.get("author_email")
        if not author:
            issues.append("no author information")

        if issues:
            result.message = f"PyPI '{pkg.name}': {', '.join(issues)}"

        return result

    def _check_packagist(self, pkg: PackageRef) -> RegistryResult:
        """Check Packagist (PHP/Composer) for package metadata."""
        name = pkg.name  # format: vendor/package
        if "/" not in name:
            return RegistryResult(message=f"Composer package '{name}' missing vendor prefix")

        url = f"https://repo.packagist.org/p2/{name}.json"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.config.registry_timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return RegistryResult(
                    exists=False,
                    is_suspect=True,
                    message=f"Composer package '{name}' not found on Packagist",
                )
            return RegistryResult(error=f"Packagist error: {e.code}")
        except Exception as e:
            return RegistryResult(error=f"Packagist unreachable: {e}")

        result = RegistryResult()
        issues = []

        # Packagist p2 API returns packages.{name} array
        packages = data.get("packages", {}).get(name, [])
        if not packages:
            result.exists = False
            result.is_suspect = True
            return RegistryResult(
                exists=False, is_suspect=True,
                message=f"Composer package '{name}' has no versions",
            )

        # Check latest version metadata
        latest = packages[0] if packages else {}

        # Check source/dist
        source = latest.get("source", {})
        if not source.get("url"):
            result.has_repo = False
            issues.append("no source repository")

        # Check time
        release_time = latest.get("time")
        if release_time:
            try:
                dt = datetime.fromisoformat(release_time.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - dt).days
                result.age_days = age
                if age < self.config.min_package_age_days:
                    result.is_suspect = True
                    issues.append(f"latest release only {age} days old")
            except (ValueError, TypeError):
                pass

        if issues:
            result.message = f"Packagist '{name}': {', '.join(issues)}"

        return result
