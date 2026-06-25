from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib.resources import files
from typing import Any


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    severity: str
    capability: str
    source_paper: str
    rationale: str
    extractor_kind: str
    pattern: str | None = None
    lifecycle_stage: str | None = None


def load_rule_definitions() -> tuple[RuleDefinition, ...]:
    raw = tomllib.loads(files("skillshield.data").joinpath("rules.toml").read_text(encoding="utf-8"))
    return tuple(_rule_definition(item) for item in raw.get("rules", []))


def regex_text_patterns() -> tuple[tuple[str, str, str, str, str, str | None], ...]:
    return tuple(
        (
            rule.rule_id,
            rule.severity,
            rule.title,
            rule.pattern or "",
            rule.capability,
            rule.lifecycle_stage,
        )
        for rule in load_rule_definitions()
        if rule.extractor_kind == "regex"
    )


def _rule_definition(item: dict[str, Any]) -> RuleDefinition:
    return RuleDefinition(
        rule_id=str(item["id"]),
        title=str(item["title"]),
        severity=str(item["severity"]),
        capability=str(item["capability"]),
        source_paper=str(item["source_paper"]),
        rationale=str(item["rationale"]),
        extractor_kind=str(item["extractor_kind"]),
        pattern=str(item["pattern"]) if item.get("pattern") is not None else None,
        lifecycle_stage=str(item["lifecycle_stage"]) if item.get("lifecycle_stage") is not None else None,
    )
