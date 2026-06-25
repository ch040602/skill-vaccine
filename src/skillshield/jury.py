from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .semantic_review import FakeSemanticProvider, run_semantic_review


class JuryProvider(Protocol):
    name: str

    def review(self, semantic_review: dict) -> dict:
        """Return a jury verdict over a completed Layer 2 semantic review."""


class FakeJuryProvider:
    name = "fake"

    def review(self, semantic_review: dict) -> dict:
        task_results = semantic_review.get("task_results", [])
        critical_hold = _has_critical_static_hold(task_results)
        juror_votes = [
            _vote("juror_static", task_results, strict=True),
            _vote("juror_semantic", task_results, strict=False),
            _vote("juror_policy", task_results, strict=True),
        ]
        verdicts = {vote["verdict"] for vote in juror_votes}
        disagreement = len(verdicts) > 1
        final_verdict = _final_verdict(juror_votes, critical_hold)
        return {
            "schema_version": 1,
            "provider": self.name,
            "root": semantic_review.get("root"),
            "juror_votes": juror_votes,
            "disagreement": disagreement,
            "debate_rounds": _debate_rounds(juror_votes) if disagreement else [],
            "final_verdict": final_verdict,
            "critical_static_hold": critical_hold,
            "downgrade_allowed": not critical_hold,
        }


def jury_schema() -> dict:
    return {
        "schema_version": 1,
        "name": "skillshield-layer3-jury-protocol",
        "request_schema": {
            "type": "object",
            "required": ["semantic_review", "juror_profiles"],
            "properties": {
                "semantic_review": {"type": "object"},
                "juror_profiles": {"type": "array", "items": {"type": "string"}},
                "allow_downgrade": {"type": "boolean"},
            },
        },
        "response_schema": {
            "type": "object",
            "required": [
                "juror_votes",
                "disagreement",
                "debate_rounds",
                "final_verdict",
                "critical_static_hold",
            ],
            "properties": {
                "juror_votes": {"type": "array"},
                "disagreement": {"type": "boolean"},
                "debate_rounds": {"type": "array"},
                "final_verdict": {
                    "type": "string",
                    "enum": ["safe", "conditional", "malicious", "hold_for_human_review"],
                },
                "critical_static_hold": {"type": "boolean"},
            },
        },
        "safety_rules": [
            "A jury cannot downgrade critical static findings without explicit human review evidence.",
            "Disagreement must be preserved in the response, not hidden by averaging.",
            "The jury interface does not execute skill code or call providers by default.",
        ],
    }


def run_jury_review(semantic_review: dict, provider: JuryProvider) -> dict:
    return provider.review(semantic_review)


def run_fake_jury_for_path(root: Path) -> dict:
    semantic_review = run_semantic_review(root, FakeSemanticProvider())
    return run_jury_review(semantic_review, FakeJuryProvider())


def _vote(juror_id: str, task_results: list[dict], strict: bool) -> dict:
    worst_score = max((float(task.get("risk_score", 0)) for task in task_results), default=0.0)
    has_malicious = any(task.get("rating") == "malicious" for task in task_results)
    if has_malicious and strict:
        verdict = "malicious"
    elif worst_score >= 0.7:
        verdict = "hold_for_human_review"
    elif worst_score >= 0.4:
        verdict = "conditional"
    else:
        verdict = "safe"
    return {
        "juror_id": juror_id,
        "verdict": verdict,
        "confidence": 0.85 if verdict in {"malicious", "safe"} else 0.65,
        "reason": f"max semantic risk score={worst_score}",
    }


def _has_critical_static_hold(task_results: list[dict]) -> bool:
    return any("critical_static_finding" in task.get("reason_codes", []) for task in task_results)


def _final_verdict(juror_votes: list[dict], critical_hold: bool) -> str:
    verdicts = [vote["verdict"] for vote in juror_votes]
    if critical_hold and "malicious" in verdicts:
        return "malicious"
    if critical_hold:
        return "hold_for_human_review"
    if "malicious" in verdicts:
        return "hold_for_human_review"
    if "hold_for_human_review" in verdicts:
        return "hold_for_human_review"
    if "conditional" in verdicts:
        return "conditional"
    return "safe"


def _debate_rounds(juror_votes: list[dict]) -> list[dict]:
    return [
        {
            "round": 1,
            "summary": "Jurors disagreed; preserve the split verdict and require follow-up review.",
            "votes": juror_votes,
        }
    ]

