"""Command parsers - extract package operations from shell commands."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PackageRef:
    manager: str
    name: str
    version: Optional[str] = None
    source: Optional[str] = None
    scope: Optional[str] = None  # @org for npm scoped packages

    @property
    def full_name(self) -> str:
        if self.scope:
            return f"{self.scope}/{self.name}"
        return self.name


@dataclass
class CommandAction:
    action: str  # install, clone, execute, download, piped_exec
    packages: list[PackageRef] = field(default_factory=list)
    raw_command: str = ""
    is_piped_exec: bool = False
    urls: list[str] = field(default_factory=list)


def parse_command(command: str) -> list[CommandAction]:
    """Parse a shell command and extract package/download operations."""
    actions: list[CommandAction] = []

    # Check piped execution first (curl|sh, wget|bash, etc.)
    if _is_piped_execution(command):
        urls = _extract_urls(command)
        actions.append(CommandAction(
            action="piped_exec",
            raw_command=command,
            is_piped_exec=True,
            urls=urls,
        ))

    # Split on pipes and command chains
    segments = re.split(r'\s*(?:&&|;|\|\|)\s*', command)

    for segment in segments:
        segment = segment.strip()
        # Handle pipes within segment - take the first part
        pipe_parts = segment.split("|")
        segment = pipe_parts[0].strip()
        if not segment:
            continue

        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()

        if not tokens:
            continue

        action = _parse_tokens(tokens, segment)
        if action:
            actions.append(action)

    return actions


def _is_piped_execution(command: str) -> bool:
    """Detect download-pipe-execute patterns."""
    patterns = [
        r"curl\s+.*\|\s*(ba)?sh",
        r"curl\s+.*\|\s*python3?",
        r"curl\s+.*\|\s*node",
        r"curl\s+.*\|\s*ruby",
        r"curl\s+.*\|\s*perl",
        r"curl\s+.*\|\s*sudo\s+(ba)?sh",
        r"wget\s+.*\|\s*(ba)?sh",
        r"wget\s+.*-O\s*-\s*\|\s*(ba)?sh",
    ]
    for p in patterns:
        if re.search(p, command, re.IGNORECASE):
            return True
    return False


def _extract_urls(command: str) -> list[str]:
    """Extract URLs from a command string."""
    url_pattern = r'https?://[^\s"\'>)]+'
    return re.findall(url_pattern, command)


def _parse_tokens(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse a single command segment into an action."""
    cmd = tokens[0].split("/")[-1]  # handle /usr/bin/npm etc.

    # npm / pnpm / yarn / bun
    if cmd in ("npm", "pnpm", "yarn", "bun"):
        return _parse_npm_family(tokens, raw)

    # npx / pnpx / bunx
    if cmd in ("npx", "pnpx", "bunx"):
        return _parse_npx(tokens, raw)

    # pip / pip3 / uv
    if cmd in ("pip", "pip3", "uv"):
        return _parse_pip(tokens, raw)

    # go
    if cmd == "go":
        return _parse_go(tokens, raw)

    # cargo
    if cmd == "cargo":
        return _parse_cargo(tokens, raw)

    # gem
    if cmd == "gem":
        return _parse_gem(tokens, raw)

    # git clone
    if cmd == "git" and len(tokens) > 1 and tokens[1] == "clone":
        return _parse_git_clone(tokens, raw)

    # curl / wget (standalone downloads)
    if cmd in ("curl", "wget"):
        return _parse_download(tokens, raw)

    # brew
    if cmd == "brew" and len(tokens) > 1 and tokens[1] == "install":
        return _parse_brew(tokens, raw)

    # composer (PHP/Laravel)
    if cmd == "composer":
        return _parse_composer(tokens, raw)

    # Skills install
    if cmd == "npx" or (len(tokens) > 1 and "skills" in tokens):
        return _parse_skills_install(tokens, raw)

    return None


def _parse_npm_family(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse npm/pnpm/yarn/bun install commands."""
    manager = tokens[0].split("/")[-1]
    install_cmds = {"install", "i", "add", "ci"}

    if len(tokens) < 2:
        return None

    subcmd = tokens[1]
    if subcmd not in install_cmds:
        return None

    packages = []
    skip_next = False
    for i, tok in enumerate(tokens[2:], start=2):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("-g", "--global", "-D", "--save-dev", "-E", "--save-exact",
                       "--save", "-S", "-P", "--save-peer", "--save-optional", "-O"):
                continue
            # Flags with values
            if tok in ("--registry", "--cache", "--prefix"):
                skip_next = True
            continue
        pkg = _parse_npm_package_spec(tok, manager)
        if pkg:
            packages.append(pkg)

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_npm_package_spec(spec: str, manager: str) -> Optional[PackageRef]:
    """Parse an npm package specifier like @scope/name@version."""
    if spec.startswith("./") or spec.startswith("/") or spec.startswith("file:"):
        return None  # local path

    scope = None
    name = spec
    version = None

    if name.startswith("@"):
        # Scoped: @scope/name@version
        parts = name.split("/", 1)
        if len(parts) == 2:
            scope = parts[0]
            name = parts[1]

    # Split version
    if "@" in name and not name.startswith("@"):
        name, version = name.rsplit("@", 1)
    elif "@" in name:
        parts = name.split("@")
        if len(parts) > 1:
            name = parts[0]
            version = parts[1] if parts[1] else None

    if not name:
        return None

    return PackageRef(manager=manager, name=name, version=version, scope=scope)


def _parse_npx(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse npx/pnpx/bunx commands."""
    packages = []
    skip_next = False
    for i, tok in enumerate(tokens[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("-p", "--package"):
                skip_next = True
                if i + 1 < len(tokens):
                    pkg = _parse_npm_package_spec(tokens[i + 1], "npx")
                    if pkg:
                        packages.append(pkg)
            continue
        if tok.startswith("./") or tok.startswith("/"):
            continue
        # First non-flag argument is the package to execute
        pkg = _parse_npm_package_spec(tok, "npx")
        if pkg:
            packages.append(pkg)
        break  # Only the first arg is the package

    if packages:
        return CommandAction(action="execute", packages=packages, raw_command=raw)
    return None


def _parse_pip(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse pip/pip3/uv pip install commands."""
    # Handle 'uv pip install'
    start_idx = 1
    if tokens[0].endswith("uv"):
        if len(tokens) < 3 or tokens[1] != "pip":
            return None
        start_idx = 2

    if len(tokens) <= start_idx or tokens[start_idx] != "install":
        return None

    packages = []
    skip_next = False
    for i, tok in enumerate(tokens[start_idx + 1:], start=start_idx + 1):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                       "-f", "--find-links", "-i", "--index-url", "--extra-index-url",
                       "--target", "-t"):
                skip_next = True
            continue
        if tok.startswith("./") or tok.startswith("/") or tok.startswith("git+"):
            continue

        name = tok
        version = None
        for op in ("==", ">=", "<=", "!=", "~=", ">", "<"):
            if op in name:
                name, version = name.split(op, 1)
                break
        # Strip extras like package[extra1,extra2]
        if "[" in name:
            name = name.split("[")[0]

        if name:
            packages.append(PackageRef(manager="pip", name=name, version=version))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_go(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse go get/install commands."""
    if len(tokens) < 3 or tokens[1] not in ("get", "install"):
        return None

    packages = []
    for tok in tokens[2:]:
        if tok.startswith("-"):
            continue
        name = tok
        version = None
        if "@" in name:
            name, version = name.rsplit("@", 1)
        if name:
            packages.append(PackageRef(manager="go", name=name, version=version))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_cargo(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse cargo add/install commands."""
    if len(tokens) < 3 or tokens[1] not in ("add", "install"):
        return None

    packages = []
    skip_next = False
    for i, tok in enumerate(tokens[2:], start=2):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("--version", "--git", "--branch", "--tag", "--rev", "--path"):
                skip_next = True
            continue
        packages.append(PackageRef(manager="cargo", name=tok))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_gem(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse gem install commands."""
    if len(tokens) < 3 or tokens[1] != "install":
        return None

    packages = []
    skip_next = False
    for i, tok in enumerate(tokens[2:], start=2):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("-v", "--version"):
                skip_next = True
            continue
        packages.append(PackageRef(manager="gem", name=tok))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_git_clone(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse git clone commands."""
    urls = []
    skip_next = False
    for i, tok in enumerate(tokens[2:], start=2):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("-b", "--branch", "--depth"):
                skip_next = True
            continue
        urls.append(tok)
        break  # Only the first non-flag arg is the URL

    if urls:
        return CommandAction(action="clone", raw_command=raw, urls=urls)
    return None


def _parse_download(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse curl/wget download commands."""
    urls = _extract_urls(raw)
    if urls:
        return CommandAction(action="download", raw_command=raw, urls=urls)
    return None


def _parse_brew(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse brew install commands."""
    packages = []
    for tok in tokens[2:]:
        if tok.startswith("-"):
            continue
        packages.append(PackageRef(manager="brew", name=tok))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_composer(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse composer require/install commands (PHP/Laravel)."""
    if len(tokens) < 2:
        return None

    subcmd = tokens[1]
    if subcmd not in ("require", "install", "update", "global"):
        return None

    # Handle 'composer global require'
    start_idx = 2
    if subcmd == "global" and len(tokens) > 2 and tokens[2] == "require":
        start_idx = 3

    if subcmd == "install":
        # composer install (from lock file) - no specific packages
        return None

    packages = []
    skip_next = False
    for i, tok in enumerate(tokens[start_idx:], start=start_idx):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            if tok in ("--dev", "-W", "--with-all-dependencies"):
                continue
            skip_next = True
            continue
        # Composer packages: vendor/package[:version]
        name = tok
        version = None
        if ":" in name:
            name, version = name.split(":", 1)
        packages.append(PackageRef(manager="composer", name=name, version=version))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None


def _parse_skills_install(tokens: list[str], raw: str) -> Optional[CommandAction]:
    """Parse Claude Code skill install commands."""
    # Pattern: npx skills install <org>/<repo> --skill <name>
    # or: npx @anthropic/skills install <spec>
    if "skills" not in tokens and "@anthropic/skills" not in " ".join(tokens):
        return None

    try:
        install_idx = tokens.index("install")
    except ValueError:
        return None

    packages = []
    for tok in tokens[install_idx + 1:]:
        if tok.startswith("-"):
            continue
        packages.append(PackageRef(manager="skill", name=tok, source="skills-registry"))

    if packages:
        return CommandAction(action="install", packages=packages, raw_command=raw)
    return None
