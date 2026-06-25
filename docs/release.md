# Release

SkillShield is packaged as a dependency-free Python CLI from `pyproject.toml`.

Local release smoke test:

```powershell
python -m pip install build twine
python -m pytest
python -m build
python -m twine check dist/*
python -m pip install --force-reinstall dist\skillshield-0.1.0-py3-none-any.whl
skillshield scan tests\fixtures\benign_skill --format json
```

The GitHub release workflow runs on `v*` tags and manual dispatch. It tests the project, builds wheel and source distribution artifacts, checks metadata with Twine, and uploads `dist/*.whl` plus `dist/*.tar.gz` for release review.

`MANIFEST.in` includes README, action/pre-commit integration files, docs, research summaries, and fixture data in source distributions. Runtime wheel contents remain the `skillshield` package and console entry point.
