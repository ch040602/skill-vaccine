from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    id: str
    group: str
    protected_object: str
    description: str
    default_effect: str = "confirm"


CAPABILITIES: dict[str, Capability] = {
    "filesystem.read": Capability("filesystem.read", "storage", "FILE", "Read local files."),
    "filesystem.write": Capability("filesystem.write", "storage", "FILE", "Create, modify, or delete local files."),
    "source.read": Capability("source.read", "code_repository", "SOURCE_CODE", "Read source repository content."),
    "source.write": Capability("source.write", "code_repository", "SOURCE_CODE", "Modify source repository content."),
    "env.read": Capability("env.read", "secrets", "ENV_VAR", "Read environment variables or secret-like runtime values."),
    "secrets.read": Capability("secrets.read", "secrets", "SECRETS", "Read credentials, tokens, or secret stores.", "deny"),
    "network.read": Capability("network.read", "network", "WEB", "Fetch remote content."),
    "network.write": Capability("network.write", "network", "EXTERNAL_API", "Send data to a remote endpoint."),
    "shell.execute": Capability("shell.execute", "execution", "PROCESS", "Run shell commands or external binaries."),
    "code.execute": Capability("code.execute", "execution", "REPL_SESSION", "Dynamically execute code."),
    "package.install": Capability("package.install", "system", "PACKAGE", "Install or modify packages."),
    "browser.operate": Capability("browser.operate", "agent_ecosystem", "TOOL", "Control a browser or browser automation tool."),
    "agent.context": Capability("agent.context", "agent_ecosystem", "CONTEXT", "Influence agent instructions or context.", "deny"),
    "agent.selection": Capability("agent.selection", "agent_ecosystem", "POLICY", "Influence skill discovery, routing, or selection."),
    "permission.manifest": Capability("permission.manifest", "governance", "POLICY", "Declare or validate skill permission policy."),
    "skill.conformance": Capability("skill.conformance", "governance", "POLICY", "Validate Agent Skill package structure."),
    "registry.metadata": Capability("registry.metadata", "governance", "POLICY", "Validate registry package metadata and provenance."),
}


def is_known_capability(capability_id: str | None) -> bool:
    return capability_id is None or capability_id in CAPABILITIES


def unknown_capabilities(capability_ids: set[str]) -> set[str]:
    return {capability_id for capability_id in capability_ids if capability_id not in CAPABILITIES}
