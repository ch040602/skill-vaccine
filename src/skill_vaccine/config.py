from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .host_policy import host_profile_policy


@dataclass(frozen=True)
class ScanConfig:
    fail_on: str | None = None
    semantic_plan: bool | None = None
    metadata_audit: bool | None = None
    host_profile: str | None = None
    enabled_rules: tuple[str, ...] | None = None


@dataclass(frozen=True)
class EffectiveScanOptions:
    fail_on: str
    semantic_plan: bool
    metadata_audit: bool
    host_profile: str | None


def load_config_data(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".toml":
        return tomllib.loads(text)
    return json.loads(text)


def load_scan_config(path: Path | None) -> ScanConfig:
    raw = load_config_data(path)
    enabled_rules = raw.get("enabled_rules") or raw.get("enabled-rules")
    return ScanConfig(
        fail_on=_optional_str(raw.get("fail_on") or raw.get("fail-on")),
        semantic_plan=_optional_bool(raw, "semantic_plan", "semantic-plan"),
        metadata_audit=_optional_bool(raw, "metadata_audit", "metadata-audit"),
        host_profile=_optional_str(raw.get("host_profile") or raw.get("host-profile")),
        enabled_rules=_enabled_rules(enabled_rules),
    )


def resolve_scan_options(
    config: ScanConfig,
    cli_fail_on: str | None = None,
    cli_semantic_plan: bool | None = None,
    cli_metadata_audit: bool | None = None,
) -> EffectiveScanOptions:
    policy = host_profile_policy(config.host_profile)
    return EffectiveScanOptions(
        fail_on=cli_fail_on or config.fail_on or (policy.default_fail_on if policy else "critical"),
        semantic_plan=_first_bool(cli_semantic_plan, config.semantic_plan, policy.semantic_plan if policy else None, False),
        metadata_audit=_first_bool(
            cli_metadata_audit,
            config.metadata_audit,
            policy.metadata_audit if policy else None,
            False,
        ),
        host_profile=config.host_profile,
    )


def _enabled_rules(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    rules = tuple(str(item).strip() for item in value if str(item).strip())
    return rules or None


def _optional_bool(raw: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        if key in raw:
            return bool(raw[key])
    return None


def _first_bool(*values: bool | None) -> bool:
    for value in values:
        if value is not None:
            return value
    return False


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
