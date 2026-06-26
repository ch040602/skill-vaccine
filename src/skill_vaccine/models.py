from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


Severity = str
Verdict = str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    path: str
    line: int | None = None
    evidence: str | None = None
    capability: str | None = None
    lifecycle_stage: str | None = None
    confidence: float = 1.0
    source: str = "static"
    suppressed: bool = False
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "capability": self.capability,
            "lifecycle_stage": self.lifecycle_stage,
            "confidence": self.confidence,
            "source": self.source,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
        }
        return {key: value for key, value in data.items() if value is not None}


@dataclass(frozen=True)
class SkillPackage:
    root: Path
    skill_md: Path
    frontmatter: dict[str, Any]
    body: str
    frontmatter_errors: tuple[tuple[int, str], ...] = field(default_factory=tuple)
    files: tuple[Path, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SemanticCoverage:
    path: str
    total_bytes: int
    reviewed_bytes: int
    unreviewed_bytes: int
    chunk_count: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "path": self.path,
            "total_bytes": self.total_bytes,
            "reviewed_bytes": self.reviewed_bytes,
            "unreviewed_bytes": self.unreviewed_bytes,
            "chunk_count": self.chunk_count,
        }


@dataclass(frozen=True)
class ScanResult:
    root: str
    skill_count: int
    findings: tuple[Finding, ...]
    inferred_capabilities: tuple[str, ...]
    host_profile: str | None = None
    semantic_coverage: tuple[SemanticCoverage, ...] = field(default_factory=tuple)

    @property
    def max_severity(self) -> Severity:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        active_findings = [finding for finding in self.findings if not finding.suppressed]
        if not active_findings:
            return "info"
        return max((finding.severity for finding in active_findings), key=lambda item: order[item])

    @property
    def verdict(self) -> Verdict:
        active_findings = [finding for finding in self.findings if not finding.suppressed]
        if not active_findings:
            return "approved"
        if any(finding.severity == "critical" for finding in active_findings):
            return "rejected"
        return "conditional"

    @property
    def required_trust_tier(self) -> str:
        from .trust import required_trust_tier

        return required_trust_tier(self)

    @property
    def host_profile_policy(self) -> dict[str, Any] | None:
        from .host_policy import host_profile_policy

        policy = host_profile_policy(self.host_profile)
        return policy.to_dict() if policy else None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "root": self.root,
            "skill_count": self.skill_count,
            "max_severity": self.max_severity,
            "verdict": self.verdict,
            "required_trust_tier": self.required_trust_tier,
            "host_profile": self.host_profile,
            "host_profile_policy": self.host_profile_policy,
            "semantic_coverage": [coverage.to_dict() for coverage in self.semantic_coverage] or None,
            "inferred_capabilities": list(self.inferred_capabilities),
            "findings": [finding.to_dict() for finding in self.findings],
        }
        return {key: value for key, value in data.items() if value is not None}
