from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .taxonomy import CAPABILITIES

if TYPE_CHECKING:
    from .models import ScanResult


@dataclass(frozen=True)
class TrustProfile:
    id: str
    description: str
    allowed_capabilities: tuple[str, ...]
    required_confirmations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "allowed_capabilities": list(self.allowed_capabilities),
            "required_confirmations": list(self.required_confirmations),
        }


UNVETTED_CAPABILITIES = (
    "skill.conformance",
    "registry.metadata",
)

LOCAL_ONLY_CAPABILITIES = tuple(sorted({
    *UNVETTED_CAPABILITIES,
    "filesystem.read",
    "filesystem.write",
    "source.read",
    "source.write",
}))

REVIEWED_CAPABILITIES = tuple(sorted({
    *LOCAL_ONLY_CAPABILITIES,
    "agent.selection",
    "browser.operate",
    "code.execute",
    "env.read",
    "network.read",
    "network.write",
    "package.install",
    "permission.manifest",
    "shell.execute",
}))

TRUSTED_CAPABILITIES = tuple(sorted(CAPABILITIES))


TRUST_PROFILES = (
    TrustProfile(
        id="unvetted",
        description="No side-effecting, external, execution, or context-control capabilities.",
        allowed_capabilities=UNVETTED_CAPABILITIES,
        required_confirmations=(
            "SKILL.md was parsed successfully.",
            "No active finding above low severity is present.",
            "No inferred capability outside governance metadata is present.",
        ),
    ),
    TrustProfile(
        id="local-only",
        description="May read or modify local files or source after path and scope confirmation.",
        allowed_capabilities=LOCAL_ONLY_CAPABILITIES,
        required_confirmations=(
            "User-selected local path or repository scope is explicit.",
            "Write/delete behavior is reviewed before execution.",
            "No network, environment, package, shell, or agent-context capability is present.",
        ),
    ),
    TrustProfile(
        id="reviewed",
        description="Human-reviewed capability use for external I/O, execution, packages, or routing influence.",
        allowed_capabilities=REVIEWED_CAPABILITIES,
        required_confirmations=(
            "Permission manifest or equivalent capability review exists.",
            "Human reviewer accepted external I/O, execution, package, or selection behavior.",
            "Runtime confirmations are required for side effects and sensitive reads.",
        ),
    ),
    TrustProfile(
        id="trusted",
        description="Highest tier for context-control, secret access, critical findings, or unsupported capabilities.",
        allowed_capabilities=TRUSTED_CAPABILITIES,
        required_confirmations=(
            "Named owner or trusted provenance is established.",
            "Execution is isolated or otherwise controlled by host policy.",
            "Context-control and secret access require explicit approval.",
            "Rejected scan verdicts remain blocked unless a separate override policy exists.",
        ),
    ),
)


def trust_profiles() -> tuple[TrustProfile, ...]:
    return TRUST_PROFILES


def trust_profile_schema() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "name": "skillshield-trust-tier-profiles",
        "profiles": [profile.to_dict() for profile in TRUST_PROFILES],
        "tier_order": [profile.id for profile in TRUST_PROFILES],
        "notes": [
            "required_trust_tier is advisory admission metadata; verdict still decides approved, conditional, or rejected.",
            "Hosts may enforce stricter policies than these built-in defaults.",
        ],
    }


def required_trust_tier(result: ScanResult) -> str:
    active_capabilities = _active_capabilities(result)
    if result.verdict == "rejected":
        return "trusted"
    if {"agent.context", "secrets.read"} & active_capabilities:
        return "trusted"
    if result.max_severity == "high":
        return "reviewed"
    if active_capabilities <= set(UNVETTED_CAPABILITIES) and result.max_severity in {"info", "low"}:
        return "unvetted"
    if active_capabilities <= set(LOCAL_ONLY_CAPABILITIES):
        return "local-only"
    if active_capabilities <= set(REVIEWED_CAPABILITIES):
        return "reviewed"
    return "trusted"


def _active_capabilities(result: ScanResult) -> set[str]:
    capabilities = set(result.inferred_capabilities)
    capabilities.update(
        finding.capability
        for finding in result.findings
        if finding.capability and not finding.suppressed
    )
    return capabilities
