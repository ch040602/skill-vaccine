from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .parser import discover_skill_dirs, parse_skill
from .scanner import scan_path


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SKILL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class InstallError(ValueError):
    pass


@dataclass(frozen=True)
class InstallReport:
    installed: bool
    blocked: bool
    skill_name: str
    source: str
    destination: str
    mode: str
    reason: str
    scan: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "installed": self.installed,
            "blocked": self.blocked,
            "skill_name": self.skill_name,
            "source": self.source,
            "destination": self.destination,
            "mode": self.mode,
            "reason": self.reason,
            "scan": self.scan,
        }


def default_codex_skills_dir() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser() / "skills"
    return Path.home() / ".codex" / "skills"


def install_skill(
    source: Path,
    *,
    skills_dir: Path | None = None,
    fail_on: str = "high",
) -> InstallReport:
    source = source.expanduser()
    skill_dirs = discover_skill_dirs(source)
    if len(skill_dirs) != 1:
        raise InstallError(f"install requires exactly one Agent Skill package; found {len(skill_dirs)}")

    package = parse_skill(skill_dirs[0])
    skill_name = str(package.frontmatter.get("name", "")).strip()
    if not skill_name:
        raise InstallError("SKILL.md frontmatter must include a name before installation")
    if not SKILL_NAME_PATTERN.fullmatch(skill_name):
        raise InstallError("SKILL.md name may contain only letters, numbers, dot, underscore, and hyphen")

    scan = scan_path(source)
    target_root = (skills_dir or default_codex_skills_dir()).expanduser()
    destination = target_root / skill_name
    scan_payload = scan.to_dict()
    if _should_fail(scan.max_severity, fail_on):
        return InstallReport(
            installed=False,
            blocked=True,
            skill_name=skill_name,
            source=str(package.root),
            destination=str(destination),
            mode="copy",
            reason=f"scan max severity {scan.max_severity} meets install threshold {fail_on}",
            scan=scan_payload,
        )
    if destination.exists():
        raise InstallError(f"destination already exists: {destination}")

    target_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        package.root,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    return InstallReport(
        installed=True,
        blocked=False,
        skill_name=skill_name,
        source=str(package.root),
        destination=str(destination),
        mode="copy",
        reason="scan passed install threshold",
        scan=scan_payload,
    )


def _should_fail(max_severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[max_severity] >= SEVERITY_ORDER[threshold]
