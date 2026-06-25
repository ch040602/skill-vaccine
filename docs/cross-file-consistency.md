# Cross-File Consistency

SkillShield checks whether capabilities found in referenced scripts are disclosed by `SKILL.md`.

The current implementation is static and conservative:

- It scans `SKILL.md` and script-like files without executing them.
- It infers script capabilities from existing static rules such as `env.read`, `network.write`, `shell.execute`, and `code.execute`.
- It compares those capabilities against the declared name, description, and body text in `SKILL.md`.
- It emits `SS202 Script capability not described` when script behavior is not disclosed in the skill text.

## Example

If `scripts/format.py` reads `os.environ` and posts data with `requests.post`, but `SKILL.md` only says the skill formats markdown notes, SkillShield reports:

```json
{
  "rule_id": "SS202",
  "source": "cross-file",
  "capability": "network.write",
  "evidence": "network.write"
}
```

If `SKILL.md` explicitly states that the skill uses an environment token and calls a configured API endpoint, `SS202` is not reported for those capabilities. The underlying static capability findings can still appear, because disclosure and safety are separate questions.

## Limits

This check is not semantic proof. It uses a small capability-term map and intentionally prefers explainable false positives over silent hidden behavior. Ambiguous findings should be routed to Layer 2 semantic review.
