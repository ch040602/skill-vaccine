# Release

Skill Vaccine is packaged as a dependency-free Python CLI from `pyproject.toml`.

Local release smoke test:

```powershell
python -m pip install build twine
python -m pytest
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist\skill-vaccine-0.1.0-py3-none-any.whl
skill-vaccine scan tests\fixtures\benign_skill --format json
```

The GitHub release workflow runs on `v*` tags and manual dispatch. It tests the project, builds wheel and source distribution artifacts, checks metadata with Twine, and uploads `dist/*.whl` plus `dist/*.tar.gz` for release review.

`MANIFEST.in` includes README, action/pre-commit integration files, docs, research summaries, and fixture data in source distributions. Runtime wheel contents keep the internal `skill_vaccine` package and expose the `skill-vaccine` console entry point.

## npm

The npm package name is `@cchsh/skill-vaccine`, with the `skill-vaccine` binary mapped to
`bin/skill-vaccine.js`. `package.json` sets `publishConfig.access` to `public` for scoped package
publication.

As of the 2026-06-26 registry check, `npm view @cchsh/skill-vaccine` returned `404 Not Found`, so
the package is prepared locally but not published yet. `npm whoami` returned `E401` on this
workstation, so publish requires npm authentication first.

Release checks:

```powershell
npm login
npm whoami
npm pack --dry-run
npm publish --access public
npm view @cchsh/skill-vaccine name version repository.url homepage --json
```


