# Benchmark Fixtures

Skill Vaccine includes an MVP benchmark manifest at `tests/fixtures/benchmark/labels.json`.

Run it with:

```powershell
skill-vaccine eval tests\fixtures\benchmark\labels.json
```

## Label Schema

Each case records:

- `id`: stable case ID.
- `path`: fixture path relative to the label file.
- `label`: `benign` or a risky label such as `malicious`.
- `attack_class`: research-grounded category.
- `source_paper`: paper or research line that motivated the fixture.
- `expected_rule_ids`: rules that should fire for the case.

## Current Classes

| Attack class | Example fixture | Source line | Expected rules |
|---|---|---|---|
| `benign` | `benign_skill` | Skilldex / OpenSkillEval | none |
| `prompt_injection_and_exfiltration` | `malicious_skill` | SkillSieve / SkillGuard | `SS001`, `SS002` |
| `obfuscation` | `obfuscated_skill` | SkillSieve | `SS011` |
| `overbroad_selection` | `overbroad_skill` | Under the Hood of SKILL.md | `SS004`, `SS005` |
| `permission_mismatch` | `permission_mismatch_skill` | SkillGuard / SkillProbe | `SS201` |

## Metrics

The evaluator reports:

- precision
- recall
- F1
- F2
- false positive rate
- suspicious rate
- escalation rate
- confusion counts
- static finding and severity counts
- rule coverage for expected rule IDs

The benchmark is intentionally small. It proves the evaluation contract and prevents obvious regressions; it is not yet a statistically meaningful scanner-quality claim.

Current MVP fixture metrics:

| Metric | Value |
|---|---:|
| precision | 1.0 |
| recall | 1.0 |
| F1 | 1.0 |
| F2 | 1.0 |
| FPR | 0.0 |
| suspicious rate | 0.8 |
| escalation rate | 0.6 |
| rule coverage | 1.0 |

