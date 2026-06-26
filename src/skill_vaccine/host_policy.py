from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HostProfilePolicy:
    id: str
    description: str
    default_fail_on: str
    semantic_plan: bool
    metadata_audit: bool
    max_allowed_required_trust_tier: str
    verdict_policy: str
    non_goal: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "default_fail_on": self.default_fail_on,
            "semantic_plan": self.semantic_plan,
            "metadata_audit": self.metadata_audit,
            "max_allowed_required_trust_tier": self.max_allowed_required_trust_tier,
            "verdict_policy": self.verdict_policy,
            "non_goal": self.non_goal,
        }


HOST_PROFILE_POLICIES = {
    "local": HostProfilePolicy(
        id="local",
        description="Developer workstation scans with low friction and no extra review routing by default.",
        default_fail_on="critical",
        semantic_plan=False,
        metadata_audit=False,
        max_allowed_required_trust_tier="local-only",
        verdict_policy="Rejected skills fail; conditional skills are shown for local review.",
        non_goal="Does not grant filesystem or execution permission at runtime.",
    ),
    "ci": HostProfilePolicy(
        id="ci",
        description="Continuous integration scans that fail on high-risk findings while keeping runtime-free checks.",
        default_fail_on="high",
        semantic_plan=False,
        metadata_audit=False,
        max_allowed_required_trust_tier="reviewed",
        verdict_policy="Rejected or high-risk conditional skills fail the job.",
        non_goal="Does not replace code review, SARIF triage, or host sandboxing.",
    ),
    "registry": HostProfilePolicy(
        id="registry",
        description="Registry intake scans with provenance metadata and semantic-routing evidence enabled.",
        default_fail_on="medium",
        semantic_plan=True,
        metadata_audit=True,
        max_allowed_required_trust_tier="reviewed",
        verdict_policy="Rejected skills fail; conditional skills require registry review before admission.",
        non_goal="Does not publish or approve a skill automatically.",
    ),
    "marketplace-review": HostProfilePolicy(
        id="marketplace-review",
        description="Strict marketplace review scans that surface every active finding for reviewer disposition.",
        default_fail_on="low",
        semantic_plan=True,
        metadata_audit=True,
        max_allowed_required_trust_tier="trusted",
        verdict_policy="Any active finding requires explicit reviewer disposition; rejected remains blocked.",
        non_goal="Does not allow trust tier output to override rejected verdicts.",
    ),
}


def host_profile_policy(profile_id: str | None) -> HostProfilePolicy | None:
    if profile_id is None:
        return None
    try:
        return HOST_PROFILE_POLICIES[profile_id]
    except KeyError as exc:
        supported = ", ".join(sorted(HOST_PROFILE_POLICIES))
        raise ValueError(f"unsupported host_profile {profile_id!r}; expected one of: {supported}") from exc


def host_profile_policy_schema() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "name": "skill-vaccine-host-profile-policies",
        "profiles": [policy.to_dict() for policy in HOST_PROFILE_POLICIES.values()],
        "precedence": [
            "Explicit CLI flags",
            "Config file values",
            "Host profile defaults",
            "Built-in scanner defaults",
        ],
        "notes": [
            "Host profiles select scan defaults and review semantics; they do not hide findings.",
            "required_trust_tier and verdict remain separate outputs.",
        ],
    }

