from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .models import Finding, ScanResult
from .scanner import scan_path
from .semantic import LAYER2_TASK_IDS


class SemanticProvider(Protocol):
    name: str

    def review(self, scan_result: ScanResult) -> list[dict]:
        """Return provider-specific Layer 2 task results without mutating scan state."""


class FakeSemanticProvider:
    name = "fake"

    def review(self, scan_result: ScanResult) -> list[dict]:
        risky_findings = [
            finding for finding in scan_result.findings if finding.severity in {"high", "critical"}
        ]
        has_critical = any(finding.severity == "critical" for finding in risky_findings)
        rating = "malicious" if has_critical else "suspicious" if risky_findings else "safe"
        risk_score = 0.9 if has_critical else 0.6 if risky_findings else 0.0
        evidence = [_evidence(finding) for finding in risky_findings[:5]]
        return [
            _task_result(
                "intent_alignment",
                rating,
                risk_score,
                evidence,
                {
                    "declared_purpose": "derived from SKILL.md metadata",
                    "observed_behavior": "derived from static findings",
                    "alignment_status": "unknown" if risky_findings else "aligned",
                },
            ),
            _task_result(
                "permission_justification",
                rating,
                risk_score,
                evidence,
                {
                    "declared_permissions": [],
                    "inferred_capabilities": list(scan_result.inferred_capabilities),
                    "unjustified_capabilities": list(scan_result.inferred_capabilities) if risky_findings else [],
                },
            ),
            _task_result(
                "covert_behavior",
                rating,
                risk_score,
                evidence,
                {
                    "covert_behaviors": [finding.rule_id for finding in risky_findings],
                    "user_visibility": "unknown" if risky_findings else "visible",
                    "trigger_conditions": [],
                },
            ),
            _task_result(
                "cross_file_consistency",
                rating,
                risk_score,
                evidence,
                {
                    "inconsistent_files": [],
                    "missing_references": [],
                    "hidden_capabilities": list(scan_result.inferred_capabilities) if risky_findings else [],
                },
            ),
        ]


def run_semantic_review(root: Path, provider: SemanticProvider) -> dict:
    scan_result = scan_path(root, include_semantic_review=True)
    return {
        "schema_version": 1,
        "provider": provider.name,
        "root": str(root),
        "scan_max_severity": scan_result.max_severity,
        "task_results": provider.review(scan_result),
        "network_enabled": False,
    }


def _task_result(
    task_id: str,
    rating: str,
    risk_score: float,
    evidence: list[dict],
    extra_fields: dict,
) -> dict:
    if task_id not in LAYER2_TASK_IDS:
        raise ValueError(f"unknown Layer 2 task id: {task_id}")
    result = {
        "task_id": task_id,
        "risk_score": risk_score,
        "rating": rating,
        "evidence": evidence,
        "reason_codes": _reason_codes(rating),
    }
    result.update(extra_fields)
    return result


def _reason_codes(rating: str) -> list[str]:
    if rating == "malicious":
        return ["critical_static_finding"]
    if rating == "suspicious":
        return ["high_risk_static_finding"]
    return []


def _evidence(finding: Finding) -> dict:
    return {
        "path": finding.path,
        "line": finding.line,
        "quote_or_summary": finding.evidence or finding.message,
        "reason": f"{finding.rule_id}: {finding.title}",
    }

