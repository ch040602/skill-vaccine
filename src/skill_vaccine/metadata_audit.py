from __future__ import annotations

import re

from .models import Finding, SkillPackage


REQUIRED_METADATA_FIELDS = ("source_url", "license", "version", "maintainer", "updated_at")


def audit_metadata(package: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_missing_metadata_findings(package))
    findings.extend(_invalid_metadata_findings(package))
    findings.extend(_readme_mismatch_findings(package))
    return findings


def _missing_metadata_findings(package: SkillPackage) -> list[Finding]:
    missing = [field for field in REQUIRED_METADATA_FIELDS if not package.frontmatter.get(field)]
    if not missing:
        return []
    return [
        Finding(
            rule_id="SS150",
            severity="medium",
            title="Missing registry metadata",
            message="Skill metadata is missing fields needed for registry trust review.",
            path="SKILL.md",
            line=1,
            evidence=", ".join(missing),
            capability="registry.metadata",
            source="metadata",
            confidence=0.85,
        )
    ]


def _invalid_metadata_findings(package: SkillPackage) -> list[Finding]:
    findings: list[Finding] = []
    source_url = str(package.frontmatter.get("source_url", ""))
    if source_url and not re.match(r"^https://[^/]+/.+", source_url):
        findings.append(
            Finding(
                rule_id="SS151",
                severity="medium",
                title="Invalid source URL",
                message="Registry source_url should be an HTTPS repository or project URL.",
                path="SKILL.md",
                line=1,
                evidence=source_url,
                capability="registry.metadata",
                source="metadata",
                confidence=0.85,
            )
        )
    version = str(package.frontmatter.get("version", ""))
    if version and not re.match(r"^\d+\.\d+\.\d+([.-][A-Za-z0-9]+)?$", version):
        findings.append(
            Finding(
                rule_id="SS152",
                severity="low",
                title="Non-semver version",
                message="Registry version should use a semver-like value.",
                path="SKILL.md",
                line=1,
                evidence=version,
                capability="registry.metadata",
                source="metadata",
                confidence=0.7,
            )
        )
    return findings


def _readme_mismatch_findings(package: SkillPackage) -> list[Finding]:
    readme = package.root / "README.md"
    if not readme.exists():
        return []
    readme_text = readme.read_text(encoding="utf-8", errors="replace")
    heading = _first_heading(readme_text)
    skill_name = str(package.frontmatter.get("name", ""))
    if not heading or not skill_name:
        return []
    if _tokens_overlap(skill_name, heading):
        return []
    return [
        Finding(
            rule_id="SS153",
            severity="medium",
            title="README metadata mismatch",
            message="README heading appears to describe a different package than SKILL.md.",
            path="README.md",
            line=1,
            evidence=f"SKILL.md name '{skill_name}' vs README heading '{heading}'",
            capability="registry.metadata",
            source="metadata",
            confidence=0.8,
        )
    ]


def _first_heading(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
    return None


def _tokens_overlap(left: str, right: str) -> bool:
    left_tokens = _tokens(left)
    right_tokens = _tokens(right)
    return bool(left_tokens & right_tokens)


def _tokens(text: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", text.lower()) if len(token) > 2}
