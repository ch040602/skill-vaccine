from __future__ import annotations

from typing import Any


BASE_REQUIRED_FIELDS = ("event_id", "timestamp", "skill_id", "session_id")


def telemetry_schema() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "name": "skillshield-local-usage-adherence-events",
        "description": (
            "Local artifact schema for evaluating whether an agent selected, read, and followed "
            "a skill. SkillShield does not collect these events automatically."
        ),
        "automatic_collection": False,
        "local_artifact_only": True,
        "event_types": [
            _event_type(
                "skill.selected",
                "A skill was selected or routed for a task.",
                required=BASE_REQUIRED_FIELDS + ("task_id", "selection_reason"),
            ),
            _event_type(
                "skill_md.read",
                "The agent read the skill's SKILL.md instructions.",
                required=BASE_REQUIRED_FIELDS + ("path", "bytes_read"),
            ),
            _event_type(
                "first_read.performed",
                "The agent performed the skill's required first-read or setup step.",
                required=BASE_REQUIRED_FIELDS + ("step_id", "path"),
            ),
            _event_type(
                "workflow.step.followed",
                "The agent followed a documented workflow step.",
                required=BASE_REQUIRED_FIELDS + ("step_id", "evidence"),
            ),
            _event_type(
                "workflow.step.skipped",
                "The agent skipped a documented workflow step.",
                required=BASE_REQUIRED_FIELDS + ("step_id", "reason"),
            ),
            _event_type(
                "workflow.step.contradicted",
                "The agent behavior contradicted a documented workflow step.",
                required=BASE_REQUIRED_FIELDS + ("step_id", "reason"),
            ),
        ],
        "privacy": {
            "default_storage": "local file chosen by evaluator",
            "network_transmission": "none",
            "sensitive_fields": ["task_summary", "evidence"],
        },
    }


def _event_type(event_id: str, description: str, required: tuple[str, ...]) -> dict[str, Any]:
    return {
        "id": event_id,
        "description": description,
        "required": list(required),
        "properties": {
            "event_id": {"type": "string", "description": "Stable unique event identifier."},
            "timestamp": {"type": "string", "format": "date-time"},
            "skill_id": {"type": "string"},
            "session_id": {"type": "string"},
            "task_id": {"type": "string"},
            "task_summary": {"type": "string"},
            "selection_reason": {"type": "string"},
            "path": {"type": "string"},
            "bytes_read": {"type": "integer", "minimum": 0},
            "step_id": {"type": "string"},
            "evidence": {"type": "string"},
            "reason": {"type": "string"},
        },
    }
