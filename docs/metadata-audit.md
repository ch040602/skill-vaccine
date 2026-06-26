# Registry Metadata Audit

Skill Vaccine can add opt-in registry/package metadata findings:

```powershell
skill-vaccine scan path\to\skill --metadata-audit --format json
```

The audit is opt-in because early local skills often do not have publication metadata, while registry and marketplace review usually require it.

## Checked Fields

`SKILL.md` frontmatter should include:

- `source_url`
- `license`
- `version`
- `maintainer`
- `updated_at`

The audit also checks that `source_url` is an HTTPS URL, `version` is semver-like, and the first README heading does not obviously describe a different package than `SKILL.md`.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `SS150` | medium | Required registry metadata is missing. |
| `SS151` | medium | `source_url` is not an HTTPS project URL. |
| `SS152` | low | `version` is not semver-like. |
| `SS153` | medium | README heading appears to describe a different package than `SKILL.md`. |

## Trust Badges

These badges are documentation labels for registry policy. They are not cryptographic proof.

| Badge | Minimum criteria |
|---|---|
| `metadata-complete` | Required fields are present and pass static checks. |
| `source-linked` | `source_url` points to an HTTPS repository or project URL. |
| `maintainer-declared` | `maintainer` is present. |
| `fresh-metadata` | `updated_at` is present. Future TODOs should add age and expiry checks. |
| `readme-aligned` | README heading appears aligned with `SKILL.md` name. |

## Limits

Metadata can be falsified. Treat metadata audit as a registry review signal, not proof of identity, code provenance, or maintainer control.

