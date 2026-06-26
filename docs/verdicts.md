# Verdicts

Skill Vaccine reports a `verdict` separately from `max_severity`.

| Verdict | Meaning |
| --- | --- |
| `approved` | No active findings remain after suppression policy is applied. |
| `conditional` | Active low, medium, or high findings require review or remediation before trust decisions. |
| `rejected` | At least one active critical finding is present. |

Suppressed findings remain visible in JSON and SARIF, but they do not affect `max_severity` or `verdict`.

The verdict is an admission-policy summary, not a runtime authorization grant. Manifest generation and host enforcement should still use the finding evidence and capability IDs.

