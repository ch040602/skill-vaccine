from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import SkillPackage


def discover_skill_dirs(root: Path) -> list[Path]:
    root = root.resolve()
    if root.is_file() and root.name == "SKILL.md":
        return [root.parent]
    if (root / "SKILL.md").exists():
        return [root]
    return sorted(path.parent for path in root.rglob("SKILL.md"))


def parse_skill(skill_dir: Path) -> SkillPackage:
    skill_md = skill_dir / "SKILL.md"
    raw = skill_md.read_text(encoding="utf-8", errors="replace")
    frontmatter, body, errors = parse_frontmatter(raw)
    files = tuple(path for path in sorted(skill_dir.rglob("*")) if path.is_file())
    return SkillPackage(
        root=skill_dir,
        skill_md=skill_md,
        frontmatter=frontmatter,
        body=body,
        frontmatter_errors=tuple(errors),
        files=files,
    )


def parse_frontmatter(raw: str) -> tuple[dict[str, Any], str, list[tuple[int, str]]]:
    lines = raw.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, raw, [(1, "SKILL.md does not start with YAML frontmatter delimiter.")]

    end_index = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_index = index
            break

    if end_index is None:
        return {}, raw, [(1, "YAML frontmatter is not closed.")]

    metadata, errors = _parse_simple_yaml(lines[1:end_index])
    body = "\n".join(lines[end_index + 1 :])
    return metadata, body, errors


def _parse_simple_yaml(lines: list[str]) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    data: dict[str, Any] = {}
    errors: list[tuple[int, str]] = []
    current_key: str | None = None
    block_key: str | None = None
    block_indent: int | None = None
    block_lines: list[str] = []

    def flush_block() -> None:
        nonlocal block_key, block_indent, block_lines
        if block_key is not None:
            data[block_key] = " ".join(line.strip() for line in block_lines if line.strip())
        block_key = None
        block_indent = None
        block_lines = []

    for offset, raw_line in enumerate(lines, start=2):
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if block_key is not None:
            if indent >= (block_indent or 0) and line.startswith(" "):
                block_lines.append(line)
                continue
            flush_block()

        if line.startswith("  - ") and current_key:
            data.setdefault(current_key, []).append(line[4:].strip().strip("\"'"))
            continue
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            current_key = key.strip()
            stripped = value.strip()
            if not stripped:
                data[current_key] = []
            elif stripped in {">", "|", ">-", "|-"}:
                block_key = current_key
                block_indent = 2
                block_lines = []
            elif stripped.startswith("[") and stripped.endswith("]"):
                data[current_key] = [
                    item.strip().strip("\"'")
                    for item in stripped[1:-1].split(",")
                    if item.strip()
                ]
            else:
                data[current_key] = stripped.strip("\"'")
            continue
        errors.append((offset, f"Unsupported frontmatter line: {line.strip()}"))

    flush_block()
    return data, errors
