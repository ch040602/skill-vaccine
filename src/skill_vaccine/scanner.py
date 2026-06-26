from __future__ import annotations

from pathlib import Path

from .metadata_audit import audit_metadata
from .models import ScanResult
from .parser import discover_skill_dirs, parse_skill
from .rules import analyze_skill
from .semantic import semantic_coverage_findings, semantic_coverage_for_package, semantic_review_findings
from .suppressions import apply_suppressions, load_suppression_policy


def scan_path(
    root: Path,
    include_semantic_review: bool = False,
    include_metadata_audit: bool = False,
    suppression_config: Path | None = None,
    enabled_rules: set[str] | None = None,
    host_profile: str | None = None,
) -> ScanResult:
    skill_dirs = discover_skill_dirs(root)
    all_findings = []
    semantic_coverages = []
    capabilities: set[str] = set()
    for skill_dir in skill_dirs:
        package = parse_skill(skill_dir)
        findings, inferred = analyze_skill(package)
        if include_metadata_audit:
            findings.extend(audit_metadata(package))
        if include_semantic_review:
            coverage = semantic_coverage_for_package(package)
            semantic_coverages.append(coverage)
            findings.extend(semantic_coverage_findings(package, findings, coverage))
        all_findings.extend(findings)
        capabilities.update(inferred)
    result = ScanResult(
        root=str(root),
        skill_count=len(skill_dirs),
        findings=tuple(all_findings),
        inferred_capabilities=tuple(sorted(capabilities)),
        host_profile=host_profile,
        semantic_coverage=tuple(semantic_coverages),
    )
    if include_semantic_review:
        result = ScanResult(
            root=result.root,
            skill_count=result.skill_count,
            findings=result.findings + semantic_review_findings(result),
            inferred_capabilities=result.inferred_capabilities,
            host_profile=result.host_profile,
            semantic_coverage=result.semantic_coverage,
        )
    if enabled_rules is not None:
        result = ScanResult(
            root=result.root,
            skill_count=result.skill_count,
            findings=tuple(finding for finding in result.findings if finding.rule_id in enabled_rules),
            inferred_capabilities=result.inferred_capabilities,
            host_profile=result.host_profile,
            semantic_coverage=result.semantic_coverage,
        )
    policy = load_suppression_policy(suppression_config)
    if policy is not None:
        result = ScanResult(
            root=result.root,
            skill_count=result.skill_count,
            findings=apply_suppressions(result.findings, policy),
            inferred_capabilities=result.inferred_capabilities,
            host_profile=result.host_profile,
            semantic_coverage=result.semantic_coverage,
        )
    return result
