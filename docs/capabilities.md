# Capability Taxonomy

SkillShield treats an Agent Skill as a permission-bearing artifact. Findings carry a stable `capability` ID that can later feed manifest generation, deny-by-default runtime policy, CI gating, and marketplace trust decisions.

## Default Policy

The scanner does not execute skills. For policy interpretation, use deny-by-default:

- `deny`: unsafe unless explicitly reviewed and isolated.
- `confirm`: requires user or workspace policy approval before runtime execution.
- `allow`: safe only for narrow read-only actions inside a trusted profile.

The MVP reports inferred capabilities but does not enforce runtime permissions.

## Capability IDs

| ID | Group | Protected object | Default | Meaning |
|---|---|---|---|---|
| `filesystem.read` | storage | `FILE` | confirm | Read local files. |
| `filesystem.write` | storage | `FILE` | confirm | Create, modify, or delete local files. |
| `source.read` | code_repository | `SOURCE_CODE` | confirm | Read source repository content. |
| `source.write` | code_repository | `SOURCE_CODE` | confirm | Modify source repository content. |
| `env.read` | secrets | `ENV_VAR` | confirm | Read environment variables or secret-like runtime values. |
| `secrets.read` | secrets | `SECRETS` | deny | Read credentials, tokens, or secret stores. |
| `network.read` | network | `WEB` | confirm | Fetch remote content. |
| `network.write` | network | `EXTERNAL_API` | confirm | Send data to a remote endpoint. |
| `shell.execute` | execution | `PROCESS` | confirm | Run shell commands or external binaries. |
| `code.execute` | execution | `REPL_SESSION` | confirm | Dynamically execute code. |
| `package.install` | system | `PACKAGE` | confirm | Install or modify packages. |
| `browser.operate` | agent_ecosystem | `TOOL` | confirm | Control a browser or browser automation tool. |
| `agent.context` | agent_ecosystem | `CONTEXT` | deny | Influence agent instructions or context. |
| `agent.selection` | agent_ecosystem | `POLICY` | confirm | Influence skill discovery, routing, or selection. |
| `permission.manifest` | governance | `POLICY` | confirm | Declare or validate skill permission policy. |
| `skill.conformance` | governance | `POLICY` | confirm | Validate Agent Skill package structure. |
| `registry.metadata` | governance | `POLICY` | confirm | Validate registry package metadata and provenance. |
