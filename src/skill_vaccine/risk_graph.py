from __future__ import annotations

from pathlib import Path
from typing import Any

from .parser import discover_skill_dirs
from .scanner import scan_path


DATA_SOURCE_CAPABILITIES = {"env.read", "filesystem.read", "secrets.read", "source.read"}
EXFILTRATION_SINK_CAPABILITIES = {"network.write"}
COMMAND_EXECUTION_CAPABILITIES = {"shell.execute", "code.execute"}
PROMPT_INJECTION_RULES = {"SS001", "SS003", "SS013"}


def build_risk_graph(root: Path) -> dict[str, Any]:
    skill_dirs = discover_skill_dirs(root)
    root_path = root.resolve()
    nodes = [_build_node(root_path, skill_dir) for skill_dir in skill_dirs]
    edges = _build_edges(nodes)
    return {
        "root": str(root),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def _build_node(root: Path, skill_dir: Path) -> dict[str, Any]:
    result = scan_path(skill_dir)
    capabilities = set(result.inferred_capabilities)
    rule_ids = {finding.rule_id for finding in result.findings}
    tags = _node_tags(capabilities, rule_ids)
    return {
        "id": _node_id(root, skill_dir),
        "path": _node_path(root, skill_dir),
        "skill_count": result.skill_count,
        "max_severity": result.max_severity,
        "capabilities": sorted(capabilities),
        "rule_ids": sorted(rule_ids),
        "tags": sorted(tags),
        "finding_count": len(result.findings),
    }


def _node_tags(capabilities: set[str], rule_ids: set[str]) -> set[str]:
    tags: set[str] = set()
    if capabilities & DATA_SOURCE_CAPABILITIES:
        tags.add("data_source")
    if capabilities & EXFILTRATION_SINK_CAPABILITIES:
        tags.add("exfiltration_sink")
    if capabilities & COMMAND_EXECUTION_CAPABILITIES:
        tags.add("command_execution_sink")
        tags.add("command_injection_sink")
    if rule_ids & PROMPT_INJECTION_RULES:
        tags.add("prompt_injection_source")
    return tags


def _build_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for source in nodes:
        for target in nodes:
            if source["id"] == target["id"]:
                continue
            source_tags = set(source["tags"])
            target_tags = set(target["tags"])
            if "data_source" in source_tags and "exfiltration_sink" in target_tags:
                edges.append(_edge(source, target, "data_exfiltration", "high"))
            if "prompt_injection_source" in source_tags and "command_injection_sink" in target_tags:
                edges.append(_edge(source, target, "prompt_to_command_injection", "critical"))
    return edges


def _edge(source: dict[str, Any], target: dict[str, Any], risk_type: str, severity: str) -> dict[str, Any]:
    return {
        "source": source["id"],
        "target": target["id"],
        "risk_type": risk_type,
        "severity": severity,
        "evidence": {
            "source_tags": source["tags"],
            "target_tags": target["tags"],
            "source_capabilities": source["capabilities"],
            "target_capabilities": target["capabilities"],
        },
    }


def _node_id(root: Path, skill_dir: Path) -> str:
    rel = _node_path(root, skill_dir)
    return rel.replace("/", "__")


def _node_path(root: Path, skill_dir: Path) -> str:
    try:
        return skill_dir.resolve().relative_to(root).as_posix()
    except ValueError:
        return skill_dir.as_posix()
