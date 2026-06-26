# Layer 3 Jury Protocol

Layer 3 is a provider-neutral jury interface for high-risk or disputed Layer 2 results. The current implementation includes only a deterministic local fake jury. It does not call a model, use the network, or execute skill code.

## CLI

```powershell
python -m skill_vaccine jury schema
python -m skill_vaccine jury review path\to\skill --provider fake
```

## Response Contract

The jury response preserves disagreement instead of averaging it away.

Required fields:

- `juror_votes`
- `disagreement`
- `debate_rounds`
- `final_verdict`
- `critical_static_hold`

Allowed final verdicts:

- `safe`
- `conditional`
- `malicious`
- `hold_for_human_review`

## Safety Rules

- A jury cannot downgrade critical static findings without explicit human review evidence.
- Split verdicts preserve `debate_rounds` metadata.
- The fake jury is only an interface test, not a security classifier.
- Real jury providers must be opt-in and isolated from scanner core.
- The jury interface must not execute skill scripts.
