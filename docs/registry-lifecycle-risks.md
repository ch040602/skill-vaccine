# Registry Lifecycle Risks

SkillShield reports `lifecycle_stage` on findings that target how an agent skill is discovered, selected, or governed before runtime execution.

## Stages

| Stage | Meaning | Current static rules |
|---|---|---|
| `discovery` | Metadata or SKILL.md text attempts to bias registry search, retrieval, or ranking. | `SS012` |
| `selection` | The skill tries to over-activate itself or persuade the agent to choose it. | `SS004`, `SS005` |
| `governance` | The skill tries to manipulate reviewers, scanners, policy checks, or hidden evaluation checklists. | `SS001`, `SS002`, `SS003`, `SS013`, `SS014` |

## Implemented Detectors

### `SS012` Discovery keyword stuffing

Flags `Search keywords:`, `Ranking keywords:`, or `Retrieval keywords:` style metadata inside scanned skill text. This is a registry-facing signal because these fields can bias search and retrieval even when the declared user-facing purpose appears ordinary.

### `SS004` and `SS005` Selection manipulation

Flags overbroad triggers and persuasive selection framing such as always-on activation or claims that a skill is the best, official, verified, or preferred option.

### `SS013` Governance reviewer jailbreak

Flags instructions aimed at reviewers, judges, scanners, or governance layers that ask them to mark the skill safe, benign, approved, or to ignore risky wording.

### `SS014` Checklist-hidden risky behavior

Flags risky behavior placed near completion checklists, Definition of Done sections, or similar review-oriented structures. This catches SKILL.md-only attacks that hide unsafe behavior in places a reviewer or automated evaluator may treat as procedural text.

## Output Contract

JSON output includes `lifecycle_stage` on each applicable finding:

```json
{
  "rule_id": "SS013",
  "capability": "agent.context",
  "lifecycle_stage": "governance"
}
```

SARIF output stores the same value under `result.properties.lifecycle_stage`.

## Limits

These are static pattern detectors. They identify suspicious lifecycle manipulation signals but do not prove runtime exploitability. Use Layer 2 semantic review and Layer 3 jury review for ambiguous or high-impact cases.
