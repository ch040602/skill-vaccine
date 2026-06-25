# Local Usage and Adherence Events

SkillShield defines a local artifact schema for evaluating whether a skill was actually selected, read, and followed during an agent run.

No telemetry is collected automatically. The schema is for evaluator-owned local files, deterministic test harnesses, or explicit review artifacts.

```powershell
python -m skillshield telemetry schema
```

## Event Types

| Event | Meaning |
|---|---|
| `skill.selected` | A skill was routed or selected for a task. |
| `skill_md.read` | The agent read the skill's `SKILL.md`. |
| `first_read.performed` | The required first-read or setup step was completed. |
| `workflow.step.followed` | A documented workflow step was followed. |
| `workflow.step.skipped` | A documented workflow step was skipped. |
| `workflow.step.contradicted` | Agent behavior contradicted a documented workflow step. |

Each event includes local identifiers such as `event_id`, `timestamp`, `skill_id`, and `session_id`. Workflow events also include `step_id` plus local evidence or a reason.

## Non-Goals

- SkillShield does not transmit events.
- SkillShield does not monitor users or agents in the background.
- The scanner output does not include telemetry.
- Event artifacts can contain sensitive task summaries or evidence, so evaluators should store them locally and redact them before sharing.
