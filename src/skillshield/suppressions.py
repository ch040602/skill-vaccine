from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from .config import load_config_data
from .models import Finding


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    path: str
    reason: str


@dataclass(frozen=True)
class SuppressionPolicy:
    suppressions: tuple[Suppression, ...]
    allow_critical_suppressions: bool = False


def load_suppression_policy(path: Path | None) -> SuppressionPolicy | None:
    if path is None:
        return None
    raw = load_config_data(path)
    suppressions = []
    for item in raw.get("suppressions", []):
        rule_id = str(item.get("rule_id", "")).strip()
        finding_path = str(item.get("path", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if rule_id and finding_path and reason:
            suppressions.append(Suppression(rule_id=rule_id, path=finding_path, reason=reason))
    return SuppressionPolicy(
        suppressions=tuple(suppressions),
        allow_critical_suppressions=bool(raw.get("allow_critical_suppressions", False)),
    )


def apply_suppressions(findings: tuple[Finding, ...], policy: SuppressionPolicy | None) -> tuple[Finding, ...]:
    if policy is None:
        return findings
    return tuple(_apply_suppression(finding, policy) for finding in findings)


def _apply_suppression(finding: Finding, policy: SuppressionPolicy) -> Finding:
    for suppression in policy.suppressions:
        if _matches(finding, suppression):
            if finding.severity == "critical" and not policy.allow_critical_suppressions:
                return finding
            return replace(
                finding,
                suppressed=True,
                suppression_reason=suppression.reason,
            )
    return finding


def _matches(finding: Finding, suppression: Suppression) -> bool:
    return finding.rule_id == suppression.rule_id and finding.path == suppression.path
