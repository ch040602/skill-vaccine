# GitHub Action

SkillShield includes a composite action that installs the local package and writes SARIF output:

```yaml
- uses: ./
  with:
    path: .
    fail-on: critical
    sarif-file: skillshield.sarif
```

Upload the generated SARIF in the workflow:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: skillshield.sarif
```

The repository workflow at `.github/workflows/skillshield.yml` shows a complete pull request and main-branch example.

## Notes

- The action runs `skillshield scan --format sarif`.
- `fail-on` controls the scanner exit threshold.
- SARIF upload is kept in the workflow so repository permissions are explicit through `security-events: write`.
