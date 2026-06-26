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

The benchmark currently contains 14 cases: 2 benign controls and 12 risky cases.

| Group | Count | Attack classes |
|---|---:|---|
| Benign controls | 2 | `benign`, `benign_script` |
| Prompt and instruction attacks | 4 | `prompt_injection_and_exfiltration`, `referenced_markdown_instruction_smuggling`, `paraphrased_prompt_injection`, `governance_evasion` |
| Secret and data movement | 1 | `paraphrased_secret_exfiltration` |
| Obfuscation | 2 | `zero_width_obfuscation`, `encoded_payload_obfuscation` |
| Selection and discovery manipulation | 2 | `overbroad_selection`, `discovery_manipulation` |
| Permission and script capability risks | 3 | `permission_mismatch`, `script_capability_chain`, `platform_shell_risks` |

| Attack class | Example fixture | Source line | Expected rules |
|---|---|---|---|
| `benign` | `benign_skill` | Skilldex / OpenSkillEval | none |
| `benign_script` | `benign_script_skill` | Skilldex / OpenSkillEval | none |
| `prompt_injection_and_exfiltration` | `malicious_skill` | SkillSieve / SkillGuard | `SS001`, `SS002` |
| `referenced_markdown_instruction_smuggling` | `referenced_markdown_attack_skill` | SkillSieve / Under the Hood of SKILL.md | `SS001`, `SS002` |
| `paraphrased_secret_exfiltration` | `paraphrased_exfiltration_skill` | SkillSieve / SkillGuard | `SS002` |
| `paraphrased_prompt_injection` | `paraphrased_prompt_injection_skill` | Under the Hood of SKILL.md | `SS001` |
| `zero_width_obfuscation` | `zero_width_obfuscation_skill` | SkillSieve | `SS001`, `SS002` |
| `encoded_payload_obfuscation` | `obfuscated_skill` | SkillSieve | `SS011` |
| `overbroad_selection` | `overbroad_skill` | Under the Hood of SKILL.md | `SS004`, `SS005` |
| `permission_mismatch` | `permission_mismatch_skill` | SkillGuard / SkillProbe | `SS201` |
| `script_capability_chain` | `deep_script_skill` | SkillSieve / SkillGuard | `SS009`, `SS015`, `SS016`, `SS017`, `SS018`, `SS202` |
| `platform_shell_risks` | `platform_shell_risks` | SkillSieve | `SS006`, `SS007`, `SS010`, `SS015` |
| `discovery_manipulation` | `discovery_manipulation_skill` | Under the Hood of SKILL.md | `SS012` |
| `governance_evasion` | `governance_evasion_skill` | Under the Hood of SKILL.md | `SS013`, `SS014` |

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

Current fixture metrics from `skill-vaccine eval tests\fixtures\benchmark\labels.json`:

| Metric | Value |
|---|---:|
| cases | 14 |
| benign controls | 2 |
| risky cases | 12 |
| precision | 1.0 |
| recall | 1.0 |
| F1 | 1.0 |
| F2 | 1.0 |
| FPR | 0.0 |
| suspicious rate | 0.8571 |
| escalation rate | 0.7143 |
| rule coverage | 1.0 |

Confusion counts:

| Count | Value |
|---|---:|
| true positives | 12 |
| false positives | 0 |
| true negatives | 2 |
| false negatives | 0 |

Static finding totals:

| Count | Value |
|---|---:|
| total findings | 70 |
| medium findings | 16 |
| high findings | 36 |
| critical findings | 18 |
| covered expected cases | 12 / 12 |

