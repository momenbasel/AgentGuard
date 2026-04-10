"""VirusTotal integration for URL and file hash scanning."""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
import hashlib
import time
from dataclasses import dataclass
from typing import Optional

from agentguard.config import Config


VT_API_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    is_malicious: bool = False
    is_suspect: bool = False
    detections: int = 0
    total_engines: int = 0
    detection_names: list[str] = None
    permalink: Optional[str] = None
    message: str = ""
    error: Optional[str] = None

    def __post_init__(self):
        if self.detection_names is None:
            self.detection_names = []

    @property
    def detection_rate(self) -> str:
        if self.total_engines == 0:
            return "N/A"
        return f"{self.detections}/{self.total_engines}"


class VirusTotalChecker:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.api_key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _request(self, endpoint: str, method: str = "GET", data: bytes = None) -> Optional[dict]:
        """Make a VT API request."""
        if not self.api_key:
            return None

        url = f"{VT_API_BASE}/{endpoint}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            req = urllib.request.Request(url, headers=headers, method=method, data=data)
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                return {"error": "VT rate limit exceeded - try again later"}
            return {"error": f"VT API error: {e.code}"}
        except Exception as e:
            return {"error": f"VT API unreachable: {e}"}

    def scan_url(self, url: str) -> VTResult:
        """Scan a URL against VirusTotal."""
        if not self.enabled:
            return VTResult(error="VT_API_KEY not set - skipping VirusTotal check")

        # URL ID is base64url of the URL
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        data = self._request(f"urls/{url_id}")
        if data is None:
            # URL not yet scanned - submit it
            submit_data = urllib.parse.urlencode({"url": url}).encode()
            submit_resp = self._request("urls", method="POST", data=submit_data)
            if submit_resp and "error" not in submit_resp:
                # Wait briefly and re-check
                time.sleep(2)
                data = self._request(f"urls/{url_id}")

        if data is None:
            return VTResult(message="URL not found in VirusTotal database")

        if "error" in data:
            return VTResult(error=data["error"])

        return self._parse_analysis(data, url)

    def scan_hash(self, file_hash: str) -> VTResult:
        """Look up a file hash on VirusTotal."""
        if not self.enabled:
            return VTResult(error="VT_API_KEY not set - skipping VirusTotal check")

        data = self._request(f"files/{file_hash}")
        if data is None:
            return VTResult(message=f"Hash {file_hash} not found in VirusTotal")

        if "error" in data:
            return VTResult(error=data["error"])

        return self._parse_analysis(data, file_hash)

    def scan_npm_package(self, name: str, version: Optional[str] = None) -> VTResult:
        """Scan an npm package tarball via its registry URL."""
        if not self.enabled:
            return VTResult(error="VT_API_KEY not set")

        # Get tarball URL from npm registry
        try:
            url = f"https://registry.npmjs.org/{name}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except Exception:
            return VTResult(error=f"Could not fetch npm metadata for {name}")

        # Get latest version tarball
        ver = version or data.get("dist-tags", {}).get("latest")
        if not ver:
            return VTResult(error="Could not determine package version")

        tarball = data.get("versions", {}).get(ver, {}).get("dist", {}).get("tarball")
        shasum = data.get("versions", {}).get(ver, {}).get("dist", {}).get("shasum")

        if shasum:
            # Check hash first (faster, no download)
            result = self.scan_hash(shasum)
            if result.detections > 0 or result.is_malicious:
                return result

        if tarball:
            return self.scan_url(tarball)

        return VTResult(message=f"No tarball found for {name}@{ver}")

    def scan_pypi_package(self, name: str, version: Optional[str] = None) -> VTResult:
        """Scan a PyPI package via its distribution hash."""
        if not self.enabled:
            return VTResult(error="VT_API_KEY not set")

        try:
            url = f"https://pypi.org/pypi/{name}/json"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except Exception:
            return VTResult(error=f"Could not fetch PyPI metadata for {name}")

        ver = version or data.get("info", {}).get("version")
        urls = data.get("urls", [])
        if not ver:
            releases = data.get("releases", {})
            if releases:
                ver = sorted(releases.keys())[-1]
                urls = releases.get(ver, [])

        # Check hashes of distribution files
        for dist in urls:
            digests = dist.get("digests", {})
            sha256 = digests.get("sha256")
            if sha256:
                result = self.scan_hash(sha256)
                if result.detections > 0 or result.is_malicious:
                    return result

        return VTResult(message=f"No detections for {name}@{ver}")

    def _parse_analysis(self, data: dict, identifier: str) -> VTResult:
        """Parse VT analysis response into VTResult."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        detection_names = []
        results = attrs.get("last_analysis_results", {})
        for engine, detail in results.items():
            if detail.get("category") in ("malicious", "suspicious"):
                detection_names.append(f"{engine}: {detail.get('result', 'detected')}")

        is_malicious = malicious > 3
        is_suspect = malicious > 0 or suspicious > 2

        permalink = f"https://www.virustotal.com/gui/url/{identifier}" if "/" in str(identifier) else None

        message = ""
        if is_malicious:
            message = f"MALICIOUS: {malicious}/{total} engines flagged this ({', '.join(detection_names[:3])})"
        elif is_suspect:
            message = f"Suspicious: {malicious + suspicious}/{total} detections"
        else:
            message = f"Clean: 0/{total} detections"

        return VTResult(
            is_malicious=is_malicious,
            is_suspect=is_suspect,
            detections=malicious + suspicious,
            total_engines=total,
            detection_names=detection_names,
            permalink=permalink,
            message=message,
        )
