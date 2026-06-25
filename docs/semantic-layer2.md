# Layer 2 Semantic Decomposition

SkillShield's Layer 2 is a provider-neutral review contract. The current implementation does not call an LLM or any network service. It only defines structured tasks and lets `scan --semantic-plan` add a routing finding when static evidence should be reviewed more deeply.

## CLI

```powershell
python -m skillshield semantic schema
python -m skillshield scan path\to\skill --semantic-plan --format json
python -m skillshield semantic review path\to\skill --provider fake
```

`--semantic-plan` may add `SS300 Needs Layer 2 semantic review` when static findings include high or critical severity findings, missing permission manifests with risky capabilities, agent-context manipulation, or risky script behavior.

`semantic review --provider fake` runs a deterministic local provider used for tests and integration development. It does not call a model, use the network, or execute skill code.

## Coverage Metadata

When `scan --semantic-plan` is enabled, JSON output includes `semantic_coverage` entries for each scanned `SKILL.md` file:

```json
{
  "path": "SKILL.md",
  "total_bytes": 12500,
  "reviewed_bytes": 10000,
  "unreviewed_bytes": 2500,
  "chunk_count": 2
}
```

The default provider-free review window is 10,000 bytes. Static scanning still reads the full file, but coverage metadata makes semantic-review truncation visible to CI and registry workflows.

`SS301` is emitted when high-risk `SKILL.md` evidence appears after the default reviewed byte window. Treat this as a review-blocking coverage warning: inspect the unreviewed tail or increase semantic review coverage before approving the skill.

## Tasks

### `intent_alignment`

Prompt contract:

```text
Compare the skill's declared name, description, and SKILL.md purpose with its observed instructions and scripts.
Return only structured JSON. Do not execute code. Use only supplied evidence.
```

Required output fields:

- `declared_purpose`
- `observed_behavior`
- `alignment_status`
- `risk_score`
- `rating`
- `evidence`
- `reason_codes`

### `permission_justification`

Prompt contract:

```text
Decide whether inferred capabilities are necessary and proportionate for the declared purpose.
Return unjustified capabilities with evidence. Do not grant permissions.
```

Required output fields:

- `declared_permissions`
- `inferred_capabilities`
- `unjustified_capabilities`
- `risk_score`
- `rating`
- `evidence`
- `reason_codes`

### `covert_behavior`

Prompt contract:

```text
Look for hidden, deceptive, obfuscated, delayed, or user-invisible behavior.
Treat claims without evidence as unknown rather than safe.
```

Required output fields:

- `covert_behaviors`
- `user_visibility`
- `trigger_conditions`
- `risk_score`
- `rating`
- `evidence`
- `reason_codes`

### `cross_file_consistency`

Prompt contract:

```text
Check whether SKILL.md, scripts, referenced files, and metadata are mutually consistent.
Flag hidden capabilities, missing references, and behavior found only outside SKILL.md.
```

Required output fields:

- `inconsistent_files`
- `missing_references`
- `hidden_capabilities`
- `risk_score`
- `rating`
- `evidence`
- `reason_codes`

## Safety Rules

- Layer 2 review must never execute skill scripts.
- Provider adapters must be opt-in and must not be called by `scan` unless explicitly enabled in a later TODO.
- The only implemented provider is `fake`; it is local and deterministic.
- Every high-risk or malicious rating must cite evidence with path and line when available.
- A semantic reviewer cannot downgrade critical static findings by itself. Downgrades require a later jury or explicit human review workflow.
- Missing evidence must produce `unknown`, not `safe`.
- The prompt must not include credentials, unrelated user data, or unneeded file contents.

## Rating Scale

| Rating | Meaning |
|---|---|
| `safe` | Evidence supports benign, proportionate behavior. |
| `suspicious` | Evidence indicates possible risk or incomplete disclosure. |
| `high_risk` | Evidence shows dangerous capability or severe policy mismatch. |
| `malicious` | Evidence shows harmful intent, exfiltration, deceptive execution, or prompt injection. |
| `unknown` | Evidence is insufficient or contradictory. |
