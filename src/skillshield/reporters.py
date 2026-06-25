from __future__ import annotations

import json

from .models import Finding, ScanResult


def render_text(result: ScanResult) -> str:
    total_unreviewed = sum(coverage.unreviewed_bytes for coverage in result.semantic_coverage)
    lines = [
        f"SkillShield scan: {result.root}",
        f"Skills: {result.skill_count}",
        f"Max severity: {result.max_severity}",
        f"Verdict: {result.verdict}",
        f"Required trust tier: {result.required_trust_tier}",
        f"Inferred capabilities: {', '.join(result.inferred_capabilities) or 'none'}",
    ]
    if result.host_profile:
        lines.append(f"Host profile: {result.host_profile}")
    if result.semantic_coverage:
        lines.append(f"Semantic coverage: {len(result.semantic_coverage)} file(s), unreviewed bytes: {total_unreviewed}")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for finding in result.findings:
        location = finding.path
        if finding.line:
            location += f":{finding.line}"
        stage = f" stage={finding.lifecycle_stage}" if finding.lifecycle_stage else ""
        lines.append(f"[{finding.severity.upper()}] {finding.rule_id} {finding.title}{stage} ({location})")
        lines.append(f"  {finding.message}")
        if finding.evidence:
            lines.append(f"  evidence: {finding.evidence}")
        if finding.suppressed:
            lines.append(f"  suppressed: {finding.suppression_reason}")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def render_sarif(result: ScanResult) -> str:
    rules = {
        finding.rule_id: {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.message},
        }
        for finding in result.findings
    }
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillShield",
                        "informationUri": "https://github.com/skillshield/skillshield",
                        "rules": list(rules.values()),
                    }
                },
                "properties": {
                    "max_severity": result.max_severity,
                    "verdict": result.verdict,
                    "required_trust_tier": result.required_trust_tier,
                    "host_profile": result.host_profile,
                    "host_profile_policy": result.host_profile_policy,
                    "semantic_coverage": [coverage.to_dict() for coverage in result.semantic_coverage],
                },
                "results": [_sarif_result(finding) for finding in result.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _sarif_result(finding: Finding) -> dict:
    region = {"startLine": finding.line or 1}
    properties = {
        "severity": finding.severity,
        "capability": finding.capability,
        "lifecycle_stage": finding.lifecycle_stage,
        "confidence": finding.confidence,
        "evidence": finding.evidence,
        "suppressed": finding.suppressed,
        "suppression_reason": finding.suppression_reason,
    }
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": region,
                }
            }
        ],
        "properties": {key: value for key, value in properties.items() if value is not None},
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
