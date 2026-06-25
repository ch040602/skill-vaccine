# SkillShield

![SkillShield teaser: security scanner reviewing Agent Skill packages](docs/assets/skillshield-teaser.png)

SkillShield's core scanner is **not** an Agent Skill and it is **not** an LLM wrapper.

It is a dependency-free Python CLI/package that scans Agent Skill packages. SkillShield checks
`SKILL.md`, referenced files, metadata, capability claims, and cross-skill combinations before an
agent, CI job, registry, or marketplace review process trusts a skill.

The repository also includes an optional `skills/skillshield-review` Agent Skill adapter for Codex
and Claude Code. That adapter does not replace the CLI; it asks the agent LLM to review a safe
SkillShield packet when semantic judgment is needed.

## Contents

- [Why](#why)
- [What This Is](#what-this-is)
- [Install](#install)
- [Quick Start](#quick-start)
- [Outputs](#outputs)
- [LLM-Assisted Review](#llm-assisted-review)
- [Policy Profiles](#policy-profiles)
- [Integrations](#integrations)
- [Documentation](#documentation)
- [Research Basis](#research-basis)
- [Development](#development)

## Why

Agent skills can hide risk in natural-language instructions, permission claims, helper scripts, and
registry metadata. SkillShield provides a local static review layer with optional semantic-routing
contracts, admission verdicts, trust tier metadata, SARIF output, and benchmark fixtures.

Current checks cover:

- prompt injection, secret exfiltration, hidden behavior, and governance evasion
- overbroad discovery/selection language in `SKILL.md`
- risky script behavior across Python, shell, PowerShell, batch, and JavaScript fixtures
- missing or mismatched permission/capability declarations
- registry metadata provenance gaps
- cross-file hidden capabilities and cross-skill risk graph links
- semantic review coverage gaps and provider-neutral Layer 2/Layer 3 contracts

## What This Is

SkillShield is primarily a scanner for skills. The installable Skill adapter is optional and lives
under `skills/skillshield-review`.

| Question | Answer |
| --- | --- |
| Is the core scanner a Codex/Agent Skill? | No. The Python package is a normal CLI/library. |
| Is there an optional Codex/Claude Code Skill? | Yes. `skills/skillshield-review` wraps the CLI output for agent-assisted review. |
| Does the scanner call an LLM by default? | No. The default scanner is static, local, and dependency-free. |
| What are the semantic and jury commands? | Provider-neutral schemas, deterministic fake-provider test harnesses, and safe LLM review packets. |
| What does it scan? | Agent Skill folders, including `SKILL.md`, helper scripts, metadata, config, and related packages. |
| Who is it for? | Developers, CI pipelines, registries, and marketplace reviewers evaluating third-party or generated skills. |

The Layer 2 semantic review and Layer 3 jury pieces define the review contract. The default
implementation still uses local fake providers for interface testing and does not send data to any
external model API. Use `skillshield llm prompt` or the `skillshield-review` Skill when you want a
Codex or Claude Code session to perform the semantic review over a bounded evidence packet.

## Install

From npm:

```powershell
npm install -g @cchsh/skill-shield
skillshield --help
```

From a checkout:

```powershell
python -m pip install -e .
```

Or run directly from the source tree:

```powershell
$env:PYTHONPATH = "src"
python -m skillshield scan tests\fixtures\benign_skill
```

## Quick Start

Scan a skill:

```powershell
skillshield scan path\to\skill --format text
skillshield scan path\to\skill --format json
skillshield scan path\to\skill --format sarif --fail-on high
```

Use a JSON or TOML config:

```powershell
skillshield scan path\to\skill --config skillshield.json --format json
skillshield scan path\to\skill --config skillshield.toml --format json
```

Inspect related contracts and reports:

```powershell
skillshield manifest suggest path\to\skill
skillshield semantic schema
skillshield semantic review path\to\skill --provider fake
skillshield jury schema
skillshield jury review path\to\skill --provider fake
skillshield llm schema
skillshield llm prompt path\to\skill --target codex --format markdown
skillshield llm validate llm-response.json
skillshield graph path\to\skills
skillshield eval tests\fixtures\benchmark\labels.json
skillshield telemetry schema
skillshield trust profiles
skillshield trust host-profiles
```

## Outputs

Every scan reports:

- `max_severity`: highest active finding severity
- `verdict`: `approved`, `conditional`, or `rejected`
- `required_trust_tier`: `unvetted`, `local-only`, `reviewed`, or `trusted`
- `inferred_capabilities`: capability IDs derived from findings and declarations
- `findings`: rule IDs, evidence, capability IDs, lifecycle stage, and suppression metadata

JSON and SARIF are intended for CI, registry intake, and review automation. Text output is for local
triage.

## LLM-Assisted Review

SkillShield now has two explicit operating modes.

| Mode | Use it when | What runs | LLM behavior |
| --- | --- | --- | --- |
| CLI-only mode | You need deterministic local scans, CI gates, SARIF, benchmarks, or registry intake. | `skillshield scan`, `semantic review --provider fake`, `jury review --provider fake`. | No LLM call. No network. No reviewed skill code execution. |
| Skill-assisted LLM review | You want Codex or Claude Code to judge intent, permission justification, covert behavior, or cross-file consistency using static evidence. | `skills/skillshield-review` runs `skillshield llm prompt ...` and the agent reviews the packet. | The agent LLM reviews the packet in-session. SkillShield still does not call a model API itself. |

Generate a review packet directly:

```powershell
skillshield llm schema
skillshield llm prompt path\to\skill --target codex --format markdown
skillshield llm prompt path\to\skill --target claude-code --format json
skillshield llm validate llm-response.json
```

`skillshield llm schema` prints the JSON contract for both the prompt packet and the expected LLM
response. `skillshield llm prompt` embeds the same `response_schema` in every JSON packet and prints
it in Markdown output so Codex or Claude Code can return machine-checkable review results.
`skillshield llm validate` checks a saved LLM response artifact against that contract and exits
non-zero when required fields, enum values, score ranges, or array fields are invalid.

Use the installable Skill adapter from this repo:

```text
skills/skillshield-review
```

The adapter is intentionally small: it tells Codex or Claude Code to collect SkillShield evidence,
avoid executing reviewed skill code, preserve critical static findings, and return structured JSON
with semantic task results. This is the path that matches the papers' layered pattern: fast static
screening first, LLM semantic review only when judgment is needed.

## Policy Profiles

Trust tiers describe the minimum operator boundary needed for a skill. Host profiles choose scan
defaults for a specific environment.

Built-in host profiles:

| Profile | Default threshold | Extra checks | Use case |
| --- | --- | --- | --- |
| `local` | `critical` | none | developer workstation triage |
| `ci` | `high` | none | pull request and build gating |
| `registry` | `medium` | semantic routing, metadata audit | registry intake |
| `marketplace-review` | `low` | semantic routing, metadata audit | strict marketplace review |

Explicit CLI flags override config values; config values override host profile defaults.

## Integrations

GitHub Actions:

```yaml
- uses: ./
  with:
    path: .
    fail-on: critical
    sarif-file: skillshield.sarif
```

pre-commit:

```yaml
repos:
  - repo: local
    hooks:
      - id: skillshield
        name: SkillShield
        entry: skillshield scan .
        language: python
        pass_filenames: false
        args: [--fail-on, high]
```

## Documentation

- [Rules](docs/rules.md)
- [Capabilities](docs/capabilities.md)
- [Config](docs/config.md)
- [Host profiles](docs/host-profiles.md)
- [Trust tiers](docs/trust-tiers.md)
- [Verdicts](docs/verdicts.md)
- [Suppressions](docs/suppressions.md)
- [Registry lifecycle risks](docs/registry-lifecycle-risks.md)
- [Cross-file consistency](docs/cross-file-consistency.md)
- [Risk graph](docs/risk-graph.md)
- [Metadata audit](docs/metadata-audit.md)
- [Semantic Layer 2](docs/semantic-layer2.md)
- [Jury Layer 3](docs/jury-layer3.md)
- [Telemetry schema](docs/telemetry.md)
- [Benchmark](docs/benchmark.md)
- [GitHub Action](docs/github-action.md)
- [pre-commit](docs/pre-commit.md)
- [Release](docs/release.md)

## Research Basis

SkillShield is grounded in the local research synthesis at
[research/skillshield_research_synthesis.md](research/skillshield_research_synthesis.md). Korean
paper summaries are indexed in [research/paper_summaries/index.md](research/paper_summaries/index.md).

The implementation maps ideas from SkillSieve, SkillGuard, SkillProbe, Skilldex, OpenSkillEval,
SkillsBench, EvoSkills, SKILL.md semantic-attack work, and broader agent-skill landscape papers into
static rules, semantic-routing contracts, jury protocol scaffolding, evaluation fixtures, and
admission-policy metadata.

## Development

Run tests:

```powershell
python -m pytest
python -m compileall -q src tests
```

Build distribution artifacts:

```powershell
python -m pip wheel . --no-deps --no-build-isolation -w .codex\review-driven-development\artifacts\wheel-smoke
npm pack --dry-run
```

Current benchmark smoke metrics on the bundled fixture set:

- precision: `1.0`
- recall: `1.0`
- F1: `1.0`
- F2: `1.0`
- FPR: `0.0`
- suspicious rate: `0.8`
- escalation rate: `0.6`

These are contract-smoke metrics for the MVP fixture suite, not broad scanner-quality claims.
