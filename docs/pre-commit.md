# Pre-Commit Hook

Skill Vaccine ships a pre-commit hook manifest:

```yaml
repos:
  - repo: https://github.com/ch040602/skill-vaccine
    rev: v0.1.0
    hooks:
      - id: skill-vaccine-review
```

For local development against this checkout:

```yaml
repos:
  - repo: local
    hooks:
      - id: skill-vaccine-review
        name: Skill Vaccine
        entry: skill-vaccine scan .
        language: python
        pass_filenames: false
        args: [--fail-on, high]
```

## Thresholds

The hook defaults to `args: [--fail-on, critical]`. Override the threshold in repository config with `args: [--fail-on, high]`, `medium`, or `low` when a stricter local policy is needed.

The hook scans the repository root rather than individual changed files because Agent Skill risks can span `SKILL.md`, scripts, and package metadata.

