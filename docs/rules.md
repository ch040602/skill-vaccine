# Rule Reference

This document explains why each implemented Skill Vaccine rule exists, what kind of evidence it uses, and how to fix or review a finding.

Rule metadata is packaged in `skill_vaccine/data/rules.toml` and loaded with `importlib.resources`. Regex-backed static rules use the catalog's `pattern` field as their evidence extractor; structural, metadata, permission, cross-file, semantic-routing, and semantic-coverage rules use explicit scanner code but still carry cataloged severity, capability, source, and rationale metadata.

## Static certainty vs semantic suspicion

Static rules identify textual or structural evidence in `SKILL.md`, helper Markdown documents, and scripts. Skill Vaccine does not execute skill scripts during scanning. Before regex matching, common zero-width format-control characters are normalized away so terms such as prompt-injection verbs or API-key references cannot be trivially split to evade checks. A static match is not always proof of exploitability, but it is enough to require review when the matched behavior touches agent context, secrets, network egress, shell execution, package governance, or registry metadata. Use Layer 2 semantic review for ambiguous intent, and use suppression config only when a finding has been reviewed with a reason.

## Security and Behavior Rules

### `SS001` Prompt-injection directive

Source inspiration: SkillSieve and SKILL.md semantic-attack papers treat agent-context manipulation as a primary malicious-skill class.

Fix guidance: Remove instructions that ask the agent to ignore, override, bypass, disregard, or supersede system/developer/user instructions. If the skill needs priority rules, phrase them as task-local constraints.

### `SS002` Secret exfiltration language

Source inspiration: SkillSieve, SkillGuard, and SkillProbe all treat secret access plus network egress as a severe risk.

Fix guidance: Remove language that sends secrets, credentials, tokens, passwords, or API keys. Declare only necessary capabilities and avoid transmitting secret values.

### `SS003` Hidden behavior instruction

Source inspiration: SkillSieve covert behavior checks and SKILL.md governance-evasion attacks.

Fix guidance: Remove "silently", "covertly", "hide this", or user-invisible instructions unless the behavior is harmless and explicitly disclosed.

### `SS004` Overbroad activation trigger

Source inspiration: Under the Hood of SKILL.md selection manipulation.

Fix guidance: Narrow activation to specific tasks and inputs. Avoid always-on wording such as "every request" or "before doing anything".

### `SS005` Persuasive selection framing

Source inspiration: SKILL.md description-only selection bias experiments.

Fix guidance: Replace claims such as "best", "official", "verified", or "preferred" with factual scope and limitations.

### `SS006` Dangerous shell deletion

Source inspiration: SkillSieve static layer dangerous command detection and SkillGuard protected-object enforcement.

Fix guidance: Remove destructive recursive deletion commands or isolate them behind explicit user confirmation and narrow paths.

### `SS007` Dynamic code execution

Source inspiration: SkillSieve static code-risk analysis.

Fix guidance: Avoid `eval`, `exec`, `Invoke-Expression`, and similar dynamic execution. Use structured parsers or fixed command dispatch.

### `SS008` Credential environment access

Source inspiration: SkillGuard capability inference for protected environment variables.

Fix guidance: Avoid reading environment variables unless required. Declare `env.read` and explain which variables are needed.

### `SS009` Network egress

Source inspiration: SkillGuard network capability governance and SkillProbe exfiltration sink modeling.

Fix guidance: Declare network capability, disclose endpoint purpose, and avoid sending user data or secrets to external services.

### `SS010` Reverse shell pattern

Source inspiration: SkillSieve malicious script signatures.

Fix guidance: Remove reverse shell constructs. They are not appropriate in an Agent Skill package.

### `SS011` Obfuscation primitive

Source inspiration: SkillSieve obfuscation and covert behavior analysis.

Fix guidance: Avoid base64 or encoded payloads unless there is a clear benign reason. Prefer plain, inspectable scripts.

### `SS012` Discovery keyword stuffing

Source inspiration: SKILL.md discovery manipulation attacks against retrieval and ranking.

Fix guidance: Remove keyword-stuffing fields and describe the skill's actual purpose in natural language.

### `SS013` Governance reviewer jailbreak

Source inspiration: SKILL.md governance evasion and reviewer-manipulation attacks.

Fix guidance: Remove instructions directed at reviewers, judges, scanners, or governance systems.

### `SS014` Checklist-hidden risky behavior

Source inspiration: SKILL.md checklist-hiding and semantic governance evasion.

Fix guidance: Keep definition-of-done/checklist text procedural only. Do not hide operational instructions or data movement there.

### `SS015` Process execution

Source inspiration: SkillGuard runtime process capability governance and SkillSieve static script-risk checks.

Fix guidance: Avoid launching subprocesses from skills unless explicitly required. Declare `shell.execute`, narrow allowed commands, and require user approval for shell execution.

### `SS016` Local file read

Source inspiration: SkillGuard capability inference and SkillSieve script-level evidence extraction.

Fix guidance: Declare `filesystem.read` when a script reads local files. Restrict read paths and avoid reading secrets or broad project roots.

### `SS017` Local file write or delete

Source inspiration: SkillGuard protected-object policy for local storage and static script-risk checks.

Fix guidance: Declare `filesystem.write` when a script creates, modifies, or deletes local files. Prefer narrow paths and avoid destructive deletion.

### `SS018` Package installation

Source inspiration: SkillGuard package/system capability governance and supply-chain risk checks.

Fix guidance: Declare `package.install` when a skill installs packages or modules. Prefer pinned dependencies and document why installation is necessary.

## Conformance Rules

### `SS100` Missing required frontmatter

Source inspiration: Skilldex spec-grounded package conformance diagnostics.

Fix guidance: Add required `name` and `description` frontmatter fields.

### `SS101` Low-specificity description

Source inspiration: Skilldex registry-quality checks and Google Agentic RAG corpus-description sensitivity.

Fix guidance: Expand the description so routing, discovery, and review systems can distinguish the skill's scope.

### `SS102` Invalid frontmatter syntax

Source inspiration: Skilldex compiler-style line diagnostics.

Fix guidance: Fix malformed YAML-like frontmatter. Close delimiters and avoid unsupported indentation.

## Registry Metadata Rules

### `SS150` Missing registry metadata

Source inspiration: Skilldex registry metadata and SkillProbe marketplace admission review.

Fix guidance: Add `source_url`, `license`, `version`, `maintainer`, and `updated_at` when preparing a skill for registry publication.

### `SS151` Invalid source URL

Source inspiration: registry provenance and source-linked trust badge requirements.

Fix guidance: Use an HTTPS project or repository URL for `source_url`.

### `SS152` Non-semver version

Source inspiration: package-manager release metadata conventions.

Fix guidance: Use a semver-like version such as `1.2.3`.

### `SS153` README metadata mismatch

Source inspiration: Skilldex package metadata consistency and SkillProbe semantic-behavioral alignment.

Fix guidance: Align README heading and package description with the `SKILL.md` name and purpose.

## Permission and Consistency Rules

### `SS200` Missing permission manifest

Source inspiration: SkillGuard manifest requirement and deny-by-default policy.

Fix guidance: Add `permissions` or `capabilities` frontmatter matching inferred behavior, or remove risky behavior.

### `SS201` Inferred capability not declared

Source inspiration: SkillGuard capability inference and manifest gap detection.

Fix guidance: Declare the missing capability, narrow the implementation, or remove the behavior.

### `SS202` Script capability not described

Source inspiration: SkillSieve cross-file consistency and SkillProbe semantic-behavioral alignment.

Fix guidance: Disclose script behavior in `SKILL.md`, especially env, network, shell, file, or dynamic execution behavior.

## Semantic Routing Rules

### `SS300` Needs Layer 2 semantic review

Source inspiration: SkillSieve Layer 2 structured semantic decomposition.

Fix guidance: Run or request structured semantic review for intent alignment, permission justification, covert behavior, and cross-file consistency. This rule is a routing signal, not a final malicious verdict.

### `SS301` Semantic review coverage gap

Source inspiration: SKILL.md governance-evasion risks where malicious instructions appear after reviewer or model context truncation.

Fix guidance: Review the unreviewed `SKILL.md` tail, increase semantic review coverage, split long instructions into auditable files, or remove late risky instructions before approval.

