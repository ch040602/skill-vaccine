from __future__ import annotations

from typing import Any

from .models import ScanResult
from .taxonomy import CAPABILITIES


def suggest_manifest(result: ScanResult) -> dict[str, Any]:
    permissions: dict[str, dict[str, Any]] = {}
    for finding in result.findings:
        capability_id = finding.capability
        if capability_id is None or capability_id not in CAPABILITIES:
            continue
        if capability_id in {"permission.manifest", "skill.conformance"}:
            continue
        capability = CAPABILITIES[capability_id]
        entry = permissions.setdefault(
            capability_id,
            {
                "capability": capability.id,
                "effect": capability.default_effect,
                "group": capability.group,
                "protected_object": capability.protected_object,
                "description": capability.description,
                "evidence": [],
            },
        )
        entry["evidence"].append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "path": finding.path,
                "line": finding.line,
                "evidence": finding.evidence,
            }
        )

    return {
        "schema_version": 1,
        "root": result.root,
        "permissions": list(permissions.values()),
        "notes": [
            "Review every suggested permission before adding it to a skill manifest.",
            "Use deny-by-default at runtime; this file is a static suggestion, not an authorization grant.",
        ],
    }

