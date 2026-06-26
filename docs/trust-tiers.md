# Trust Tier Profiles

Skill Vaccine reports `required_trust_tier` as admission metadata derived from active findings,
inferred capabilities, and the scan `verdict`.

`required_trust_tier` does not override `verdict`. A skill with `verdict: rejected` remains blocked by
default even when the required tier is `trusted`; the tier says only that the skill needs the highest
operator trust boundary before any separate override policy could consider it.

Print the built-in profiles:

```powershell
skill-vaccine trust profiles
```

## Profiles

### `unvetted`

Use for clean or low-severity skills that only touch governance metadata such as package conformance
or registry metadata checks.

Allowed capabilities:

- `skill.conformance`
- `registry.metadata`

Required confirmations:

- `SKILL.md` parsed successfully.
- No active finding above low severity is present.
- No inferred capability outside governance metadata is present.

### `local-only`

Use for skills limited to local files or source repository access.

Allowed capabilities:

- `filesystem.read`
- `filesystem.write`
- `source.read`
- `source.write`
- `skill.conformance`
- `registry.metadata`

Required confirmations:

- User-selected local path or repository scope is explicit.
- Write/delete behavior is reviewed before execution.
- No network, environment, package, shell, or agent-context capability is present.

### `reviewed`

Use for human-reviewed skills that need external I/O, runtime execution, package operations, browser
automation, or skill-selection influence.

Allowed examples:

- `env.read`
- `network.read`
- `network.write`
- `shell.execute`
- `code.execute`
- `package.install`
- `browser.operate`
- `agent.selection`
- `permission.manifest`

Required confirmations:

- Permission manifest or equivalent capability review exists.
- Human reviewer accepted external I/O, execution, package, or selection behavior.
- Runtime confirmations are required for side effects and sensitive reads.

### `trusted`

Use for the highest-risk boundary: context-control, secret access, unsupported capabilities, or active
critical findings.

Allowed examples:

- `agent.context`
- `secrets.read`
- Any capability known to Skill Vaccine.

Required confirmations:

- Named owner or trusted provenance is established.
- Execution is isolated or otherwise controlled by host policy.
- Context-control and secret access require explicit approval.
- Rejected scan verdicts remain blocked unless a separate override policy exists.

## Scanner Output

Text output includes:

```text
Required trust tier: reviewed
```

JSON output includes:

```json
{
  "required_trust_tier": "reviewed"
}
```

SARIF output includes `runs[0].properties.required_trust_tier`.

Host profiles turn this metadata into environment-specific scan defaults. See
[host profile policies](host-profiles.md).

