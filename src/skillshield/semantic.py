from __future__ import annotations

from .models import Finding, ScanResult, SemanticCoverage, SkillPackage


LAYER2_TASK_IDS = (
    "intent_alignment",
    "permission_justification",
    "covert_behavior",
    "cross_file_consistency",
)

HIGH_RISK_SEVERITIES = {"high", "critical"}
SEMANTIC_REVIEW_RULE_IDS = {"SS150", "SS151", "SS153", "SS200", "SS201"}
SEMANTIC_REVIEW_BYTES = 10_000


def layer2_schema() -> dict:
    return {
        "schema_version": 1,
        "name": "skillshield-layer2-semantic-decomposition",
        "description": "Provider-neutral structured outputs for optional Layer 2 semantic review.",
        "tasks": [
            _task_schema(
                "intent_alignment",
                "Check whether the skill's stated purpose matches its instructions and scripts.",
                [
                    "declared_purpose",
                    "observed_behavior",
                    "alignment_status",
                    "risk_score",
                    "rating",
                    "evidence",
                    "reason_codes",
                ],
            ),
            _task_schema(
                "permission_justification",
                "Check whether inferred capabilities are necessary and proportionate for the declared purpose.",
                [
                    "declared_permissions",
                    "inferred_capabilities",
                    "unjustified_capabilities",
                    "risk_score",
                    "rating",
                    "evidence",
                    "reason_codes",
                ],
            ),
            _task_schema(
                "covert_behavior",
                "Check for hidden, deceptive, obfuscated, or delayed behavior that is not disclosed to the user.",
                [
                    "covert_behaviors",
                    "user_visibility",
                    "trigger_conditions",
                    "risk_score",
                    "rating",
                    "evidence",
                    "reason_codes",
                ],
            ),
            _task_schema(
                "cross_file_consistency",
                "Check whether SKILL.md, referenced files, scripts, and metadata are mutually consistent.",
                [
                    "inconsistent_files",
                    "missing_references",
                    "hidden_capabilities",
                    "risk_score",
                    "rating",
                    "evidence",
                    "reason_codes",
                ],
            ),
        ],
        "routing": {
            "escalate_when": [
                "any static finding has high or critical severity",
                "permission manifest is missing while risky capabilities are inferred",
                "SKILL.md contains agent-context or selection manipulation signals",
                "scripts contain network, environment, shell, or dynamic code execution signals",
            ],
            "no_provider_side_effects": True,
        },
    }


def semantic_review_findings(result: ScanResult) -> tuple[Finding, ...]:
    high_risk_findings = [
        finding
        for finding in result.findings
        if finding.severity in HIGH_RISK_SEVERITIES or finding.rule_id in SEMANTIC_REVIEW_RULE_IDS
    ]
    if not high_risk_findings:
        return ()

    rule_ids = sorted({finding.rule_id for finding in high_risk_findings})
    task_ids = ", ".join(LAYER2_TASK_IDS)
    return (
        Finding(
            rule_id="SS300",
            severity="medium",
            title="Needs Layer 2 semantic review",
            message=(
                "Static findings indicate this skill should be reviewed with structured Layer 2 "
                "semantic decomposition before trust or publication decisions."
            ),
            path="SKILL.md",
            line=1,
            evidence=f"tasks={task_ids}; static_findings={', '.join(rule_ids)}",
            capability="agent.context",
            confidence=0.8,
            source="semantic-routing",
        ),
    )


def semantic_coverage_for_package(package: SkillPackage, reviewed_bytes: int = SEMANTIC_REVIEW_BYTES) -> SemanticCoverage:
    raw = package.skill_md.read_text(encoding="utf-8", errors="replace")
    total_bytes = len(raw.encode("utf-8"))
    reviewed = min(total_bytes, reviewed_bytes)
    unreviewed = max(total_bytes - reviewed, 0)
    chunk_count = max(1, (total_bytes + reviewed_bytes - 1) // reviewed_bytes)
    return SemanticCoverage(
        path=_rel(package.skill_md, package.root),
        total_bytes=total_bytes,
        reviewed_bytes=reviewed,
        unreviewed_bytes=unreviewed,
        chunk_count=chunk_count,
    )


def semantic_coverage_findings(
    package: SkillPackage,
    findings: list[Finding],
    coverage: SemanticCoverage,
) -> tuple[Finding, ...]:
    if coverage.unreviewed_bytes <= 0:
        return ()

    raw = package.skill_md.read_text(encoding="utf-8", errors="replace")
    late_findings = [
        finding
        for finding in findings
        if finding.path == coverage.path
        and finding.severity in HIGH_RISK_SEVERITIES
        and _line_start_byte(raw, finding.line or 1) >= coverage.reviewed_bytes
    ]
    if not late_findings:
        return ()

    rule_ids = ", ".join(sorted({finding.rule_id for finding in late_findings}))
    return (
        Finding(
            rule_id="SS301",
            severity="medium",
            title="Semantic review coverage gap",
            message=(
                "High-risk SKILL.md evidence appears after the default semantic review byte window. "
                "Review the unreviewed tail or increase semantic review coverage before trust decisions."
            ),
            path=coverage.path,
            line=min(finding.line or 1 for finding in late_findings),
            evidence=(
                f"reviewed_bytes={coverage.reviewed_bytes}; "
                f"unreviewed_bytes={coverage.unreviewed_bytes}; late_rules={rule_ids}"
            ),
            capability="agent.context",
            confidence=0.85,
            source="semantic-coverage",
        ),
    )


def _task_schema(task_id: str, description: str, required: list[str]) -> dict:
    return {
        "id": task_id,
        "description": description,
        "output_schema": {
            "type": "object",
            "required": required,
            "properties": {
                "risk_score": {"type": "number", "minimum": 0, "maximum": 1},
                "rating": {"type": "string", "enum": ["safe", "suspicious", "high_risk", "malicious", "unknown"]},
                "evidence": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["path", "quote_or_summary", "reason"],
                        "properties": {
                            "path": {"type": "string"},
                            "line": {"type": ["integer", "null"]},
                            "quote_or_summary": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                    },
                },
                "reason_codes": {"type": "array", "items": {"type": "string"}},
            },
        },
    }


def _line_start_byte(raw: str, target_line: int) -> int:
    offset = 0
    for line_number, line in enumerate(raw.splitlines(keepends=True), start=1):
        if line_number >= target_line:
            return offset
        offset += len(line.encode("utf-8"))
    return len(raw.encode("utf-8"))


def _rel(path, root) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
