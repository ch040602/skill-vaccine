# Contributing

Skill Vaccine is a local CLI and Agent Skill adapter for scan-gated Agent Skill review. Contributions
must preserve the core safety boundary: scan and review candidate skill files without executing the
reviewed skill code.

## Development Setup

Install from the checkout:

```powershell
python -m pip install -e .
node bin\skill-vaccine.js --help
```

The Python package is `skill_vaccine`. The CLI name is `skill-vaccine`. The npm package identity is
`@cchsh/skill-vaccine`.

## Validation Checklist

Run the relevant focused tests first, then run the full local gate before submitting changes:

```powershell
python -m pytest
python -m compileall -q src tests
node bin\skill-vaccine.js --help
npm pack --dry-run
python C:\Users\hcslab_523\.codex\skills\.system\skill-creator\scripts\quick_validate.py skills\skill-vaccine-review
```

For changes that only touch documentation, run at least the focused documentation tests and any
packaging checks affected by the changed files.

## Scanner Rules

When adding or changing scanner behavior:

- Add or update tests before implementation.
- Update `src/skill_vaccine/data/rules.toml` for rule metadata, source inspiration, rationale, and
  extraction type.
- Update `docs/rules.md` and any affected capability, verdict, trust, or host-profile docs.
- Keep static scanning non-executing. Do not execute reviewed skill code, helper scripts, package
  installers, shell snippets, or setup hooks from a candidate skill.

Rules should prefer precise evidence and conservative severity. If a pattern is suspicious but not
deterministic, route it through semantic review instead of presenting it as certain malicious
behavior.

## Benchmark Updates

The benchmark fixture set is a contract smoke suite, not a broad quality claim. When adding attack
classes or changing expected detections:

- Add the skill fixture under `tests\fixtures`.
- Update `tests\fixtures\benchmark\labels.json` with `attack_class`, `source_paper`, and
  `expected_rule_ids`.
- Run `skill-vaccine eval tests\fixtures\benchmark\labels.json`.
- Update `docs/benchmark.md`, README benchmark metrics, and tests that pin expected metrics.

Benchmark cases should include benign controls as well as realistic adversarial examples such as
instruction smuggling, paraphrased exfiltration, obfuscation, permission mismatch, script capability
chains, and governance evasion.

## Agent Skill Adapter

The installable adapter lives in `skills\skill-vaccine-review`. Changes there must keep the
frontmatter valid and should be verified with:

```powershell
python C:\Users\hcslab_523\.codex\skills\.system\skill-creator\scripts\quick_validate.py skills\skill-vaccine-review
```

The adapter should call the CLI to generate safe review packets and use `skill-vaccine install` for
installation. It should not manually copy, link, execute, or run install scripts from a candidate
skill.

## npm Package Management

The npm package is currently managed as `@cchsh/skill-vaccine` with a public scoped publish
configuration. Before publishing or changing package metadata:

```powershell
npm whoami
npm pack --dry-run
```

Do not publish without maintainer authentication, an intentional version decision, and a clean pack
inspection.

## Pull Requests

Keep changes focused and include tests for behavior changes. Update README and docs when changing
user-facing commands, package identity, benchmark claims, install behavior, or safety boundaries.

Leave unrelated local files alone. In this checkout, untracked assets such as `promo\` may exist and
should not be modified unless the task explicitly asks for them.
