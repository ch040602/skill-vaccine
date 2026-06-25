# Scan Config

SkillShield accepts JSON or TOML config files through `--config`.

```powershell
python -m skillshield scan path\to\skill --config skillshield.json --format json
python -m skillshield scan path\to\skill --config skillshield.toml --format json
```

Command-line flags take precedence over config values. If neither is present, `--fail-on` defaults to `critical`.

Supported fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `fail_on` | string | Exit with code `1` when the active maximum severity is at or above `low`, `medium`, `high`, or `critical`. |
| `semantic_plan` | boolean | Enables provider-free Layer 2 semantic review routing findings. |
| `metadata_audit` | boolean | Enables registry/package metadata audit findings. |
| `host_profile` | string | Applies built-in scan defaults for `local`, `ci`, `registry`, or `marketplace-review`, and adds profile metadata to JSON/SARIF output. |
| `enabled_rules` | string array | Emits only the listed rule IDs after scan and semantic routing. |
| `suppressions` | object array | Suppresses matched findings when `rule_id`, `path`, and `reason` match. |
| `allow_critical_suppressions` | boolean | Allows suppression of `critical` findings when explicitly set. |

JSON example:

```json
{
  "fail_on": "high",
  "semantic_plan": true,
  "metadata_audit": true,
  "host_profile": "ci",
  "enabled_rules": ["SS004", "SS005", "SS150", "SS300"],
  "suppressions": [
    {
      "rule_id": "SS004",
      "path": "SKILL.md",
      "reason": "The skill is intentionally selectable for the internal test registry."
    }
  ]
}
```

TOML example:

```toml
fail_on = "high"
semantic_plan = true
metadata_audit = true
host_profile = "ci"
enabled_rules = ["SS004", "SS005", "SS150", "SS300"]

[[suppressions]]
rule_id = "SS004"
path = "SKILL.md"
reason = "The skill is intentionally selectable for the internal test registry."
```

Suppression entries remain auditable in JSON and SARIF output. Critical findings are not suppressed unless `allow_critical_suppressions` is true.

## Host Profile Defaults

Host profile defaults apply only when a value is not supplied by a CLI flag or config field.

| Profile | Default `fail_on` | `semantic_plan` | `metadata_audit` |
| --- | --- | --- | --- |
| `local` | `critical` | `false` | `false` |
| `ci` | `high` | `false` | `false` |
| `registry` | `medium` | `true` | `true` |
| `marketplace-review` | `low` | `true` | `true` |

See [host profile policies](host-profiles.md) for the review semantics behind these defaults.
