# Host Profile Policies

Host profiles select scan defaults for the environment running SkillShield. They make
`required_trust_tier` and `verdict` actionable without hiding findings or granting runtime
permission.

Print the built-in profile schema:

```powershell
python -m skillshield trust host-profiles
```

## Precedence

Policy values are resolved in this order:

1. Explicit CLI flags.
2. Config file values.
3. Host profile defaults.
4. Built-in scanner defaults.

For example, `host_profile: registry` defaults to `fail_on: medium`, `semantic_plan: true`, and
`metadata_audit: true`. Passing `--fail-on critical` keeps the registry host profile metadata but
uses the explicit CLI threshold.

## Built-In Profiles

| Profile | Default `fail_on` | `semantic_plan` | `metadata_audit` | Trust tier expectation |
| --- | --- | --- | --- | --- |
| `local` | `critical` | `false` | `false` | local review should normally stay at or below `local-only` |
| `ci` | `high` | `false` | `false` | CI should normally stay at or below `reviewed` |
| `registry` | `medium` | `true` | `true` | registry intake should normally stay at or below `reviewed` |
| `marketplace-review` | `low` | `true` | `true` | marketplace review can inspect `trusted` tier cases but must not auto-approve them |

## Semantics

- `verdict: rejected` remains blocked unless a later explicit policy override is implemented.
- `verdict: conditional` means active findings need review, suppression, or remediation.
- `required_trust_tier` describes the minimum trust boundary suggested by active findings and
  inferred capabilities.
- `host_profile_policy` appears in JSON and SARIF output when `host_profile` is configured.

## Non-Goals

- Host profiles do not execute skills.
- Host profiles do not suppress findings.
- Host profiles do not grant filesystem, network, shell, browser, or model permissions.
- Host profiles do not let trust tier output downgrade a rejected verdict.
