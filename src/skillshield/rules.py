from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, SkillPackage
from .rule_catalog import regex_text_patterns


TEXT_PATTERNS: tuple[tuple[str, str, str, str, str, str | None], ...] = regex_text_patterns()

SCANNED_SUFFIXES = {".py", ".ps1", ".sh", ".js", ".ts", ".bat", ".cmd", ".md", ".mdx", ".markdown"}
FORMAT_CONTROL_TRANSLATION = {codepoint: None for codepoint in (0x200B, 0x200C, 0x200D, 0xFEFF)}


def analyze_skill(package: SkillPackage) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    capabilities: set[str] = set()
    script_capabilities: set[str] = set()

    findings.extend(_check_frontmatter(package))
    for path in package.files:
        if _should_scan_file(path):
            text = path.read_text(encoding="utf-8", errors="replace")
            file_findings, file_capabilities = _scan_text(path, text, package.root)
            findings.extend(file_findings)
            capabilities.update(file_capabilities)
            if path != package.skill_md:
                script_capabilities.update(file_capabilities)

    findings.extend(_check_cross_file_consistency(package, script_capabilities))
    findings.extend(_check_permission_declarations(package, capabilities))
    return findings, capabilities


def _check_frontmatter(package: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    rel = _rel(package.skill_md, package.root)
    for line, message in package.frontmatter_errors:
        findings.append(
            Finding(
                rule_id="SS102",
                severity="medium",
                title="Invalid frontmatter syntax",
                message=message,
                path=rel,
                line=line,
                capability="skill.conformance",
            )
        )
    for key in ("name", "description"):
        if not package.frontmatter.get(key):
            findings.append(
                Finding(
                    rule_id="SS100",
                    severity="medium",
                    title="Missing required frontmatter",
                    message=f"SKILL.md is missing required frontmatter field '{key}'.",
                    path=rel,
                    line=1,
                    capability="skill.conformance",
                )
            )
    description = str(package.frontmatter.get("description", ""))
    if description and len(description.split()) < 6:
        findings.append(
            Finding(
                rule_id="SS101",
                severity="low",
                title="Low-specificity description",
                message="Description is too short for reliable routing and registry governance.",
                path=rel,
                line=1,
                evidence=description,
                capability="skill.conformance",
            )
        )
    return findings


def _scan_text(path: Path, text: str, root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    capabilities: set[str] = set()
    normalized_text = _normalize_for_matching(text)
    for rule_id, severity, title, pattern, capability, lifecycle_stage in TEXT_PATTERNS:
        regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        for match in regex.finditer(normalized_text):
            line = normalized_text.count("\n", 0, match.start()) + 1
            evidence = " ".join(match.group(0).split())[:180]
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    message=f"{title} matched in {_rel(path, root)}.",
                    path=_rel(path, root),
                    line=line,
                    evidence=evidence,
                    capability=capability,
                    lifecycle_stage=lifecycle_stage,
                    confidence=0.9 if severity in {"critical", "high"} else 0.75,
                )
            )
            capabilities.add(capability)
    return findings, capabilities


def _normalize_for_matching(text: str) -> str:
    return text.translate(FORMAT_CONTROL_TRANSLATION)


def _check_permission_declarations(package: SkillPackage, capabilities: set[str]) -> list[Finding]:
    declared = _declared_permissions(package)
    if not capabilities:
        return []
    if not declared:
        return [
            Finding(
                rule_id="SS200",
                severity="medium",
                title="Missing permission manifest",
                message="Risky capabilities were inferred but no permissions/capabilities field was declared.",
                path=_rel(package.skill_md, package.root),
                line=1,
                evidence=", ".join(sorted(capabilities)),
                capability="permission.manifest",
            )
        ]
    undeclared = sorted(capability for capability in capabilities if capability not in declared)
    if not undeclared:
        return []
    return [
        Finding(
            rule_id="SS201",
            severity="high",
            title="Inferred capability not declared",
            message="Skill behavior implies capabilities that are absent from the declared permission manifest.",
            path=_rel(package.skill_md, package.root),
            line=1,
            evidence=", ".join(undeclared),
            capability="permission.manifest",
        )
    ]


def _check_cross_file_consistency(package: SkillPackage, script_capabilities: set[str]) -> list[Finding]:
    if not script_capabilities:
        return []
    declared_text = _declared_behavior_text(package)
    hidden = sorted(
        capability
        for capability in script_capabilities
        if capability in DESCRIBABLE_CAPABILITY_TERMS and not _capability_is_described(capability, declared_text)
    )
    return [
        Finding(
            rule_id="SS202",
            severity="high",
            title="Script capability not described",
            message="A referenced script uses a capability that is not described in SKILL.md.",
            path=_rel(package.skill_md, package.root),
            line=1,
            evidence=capability,
            capability=capability,
            confidence=0.8,
            source="cross-file",
        )
        for capability in hidden
    ]


DESCRIBABLE_CAPABILITY_TERMS: dict[str, tuple[str, ...]] = {
    "env.read": ("env", "environment", "token", "secret", "credential", "api key", "key"),
    "network.read": ("network", "web", "http", "https", "api", "endpoint", "request", "fetch"),
    "network.write": ("network", "web", "http", "https", "api", "endpoint", "request", "post", "send", "sync", "synchronize"),
    "shell.execute": ("shell", "command", "terminal", "process", "execute"),
    "code.execute": ("dynamic code", "execute code", "eval", "script execution"),
    "filesystem.read": ("file", "filesystem", "read", "local"),
    "filesystem.write": ("file", "filesystem", "write", "modify", "delete", "local"),
    "package.install": ("package", "install", "dependency"),
}


def _declared_behavior_text(package: SkillPackage) -> str:
    values = [
        str(package.frontmatter.get("name", "")),
        str(package.frontmatter.get("description", "")),
        package.body,
    ]
    return "\n".join(values).lower()


def _capability_is_described(capability: str, text: str) -> bool:
    return any(term in text for term in DESCRIBABLE_CAPABILITY_TERMS[capability])


def _declared_permissions(package: SkillPackage) -> set[str]:
    values: set[str] = set()
    for key in ("permissions", "capabilities"):
        raw = package.frontmatter.get(key)
        if isinstance(raw, list):
            values.update(str(item) for item in raw)
        elif isinstance(raw, str):
            values.update(item.strip() for item in raw.split(",") if item.strip())
    return values


def _should_scan_file(path: Path) -> bool:
    return path.name == "SKILL.md" or path.suffix.lower() in SCANNED_SUFFIXES


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
