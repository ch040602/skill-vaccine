# Skilldex 요약 (arXiv:2604.16911)

## 메타데이터

- 주제: Agent Skill package manager, registry, conformance diagnostics.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2604.16911.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2604.16911.txt`

## 핵심 요약

Skilldex는 skill ecosystem에 package manager와 registry가 필요하며, Anthropic-style skill spec에 대한 compiler-style conformance scoring과 line-level diagnostics가 중요하다고 주장한다. Skillset abstraction으로 여러 skill bundle을 관리하는 방향도 제안한다.

## 방법

- SKILL.md format과 metadata를 spec-grounded 방식으로 검사한다.
- conformance score와 line-level diagnostic을 생성한다.
- registry와 CLI, MCP server를 통해 skill package discovery/install workflow를 제공한다.

## 실험과 지표

논문은 package registry UX, conformance diagnostics, skillset abstraction의 실용성을 중심으로 평가한다. security scanner 자체보다 package quality와 registry 운영을 위한 정형 metadata/diagnostic이 핵심이다.

## 한계

- conformance는 safety를 보장하지 않는다.
- registry metadata가 악의적으로 조작될 수 있다.
- line-level diagnostics가 semantic risk를 모두 포착하지는 못한다.

## SkillShield 반영

- `SS100`, `SS101`, `SS102` conformance diagnostics.
- `--metadata-audit`, `SS150`-`SS153`.
- SARIF/JSON output으로 registry와 CI가 소비 가능한 diagnostic 제공.
- 후속 TODO: rule rationale docs, package/release automation.
