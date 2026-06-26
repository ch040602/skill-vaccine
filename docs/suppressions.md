# Suppressions

Skill Vaccine supports config-based suppressions for expected false positives:

```powershell
skill-vaccine scan path\to\skill --config skill-vaccine.json --format json
```

Example config:

```json
{
  "suppressions": [
    {
      "rule_id": "SS004",
      "path": "SKILL.md",
      "reason": "Documented fixture intentionally exercises overbroad activation."
    }
  ]
}
```

## Behavior

- Suppressed findings remain in text, JSON, and SARIF output.
- JSON findings include `suppressed: true` and `suppression_reason`.
- SARIF stores the same fields under `result.properties`.
- `max_severity` and `--fail-on` ignore suppressed findings.
- Suppressions require a non-empty `reason`.

## Critical Findings

Critical findings are not suppressed unless the config explicitly opts in:

```json
{
  "allow_critical_suppressions": true,
  "suppressions": [
    {
      "rule_id": "SS001",
      "path": "SKILL.md",
      "reason": "Reviewed and accepted for this isolated test fixture."
    }
  ]
}
```

Use critical suppressions sparingly. They should be reviewed as policy exceptions, not as ordinary lint ignores.

