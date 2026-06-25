# Cross-Skill Risk Graph

SkillShield can build a provider-free JSON graph across multiple skill packages:

```powershell
python -m skillshield graph path\to\skills
```

The graph reuses static scan evidence. It does not execute skill code and does not call a model.

## Nodes

Each node represents one discovered skill package and includes:

- `id`: stable relative skill ID.
- `path`: relative skill path.
- `capabilities`: inferred capability IDs.
- `rule_ids`: matched rule IDs.
- `tags`: source/sink tags used for edge construction.
- `max_severity` and `finding_count`.

## Tags

| Tag | Meaning |
|---|---|
| `data_source` | Skill can read sensitive data such as environment variables, source, filesystem, or secrets. |
| `exfiltration_sink` | Skill can send data to an external endpoint. |
| `prompt_injection_source` | Skill contains agent-context manipulation or reviewer/governance injection evidence. |
| `command_injection_sink` | Skill can execute shell or dynamic code and may amplify prompt injection. |
| `command_execution_sink` | Alias for command execution capability, retained for readability. |

## Edges

| Risk type | Source tag | Target tag | Severity |
|---|---|---|---|
| `data_exfiltration` | `data_source` | `exfiltration_sink` | high |
| `prompt_to_command_injection` | `prompt_injection_source` | `command_injection_sink` | critical |

## Limits

Edges are compositional risk hypotheses, not proof that two skills will be selected in the same agent session. They are meant for registry governance, CI review, and Layer 2 semantic follow-up.
