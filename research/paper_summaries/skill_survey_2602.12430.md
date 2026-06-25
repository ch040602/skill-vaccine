# Agent Skills Survey 요약 (arXiv:2602.12430)

## 메타데이터

- 주제: Agent Skill architecture, acquisition, deployment, security taxonomy.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2602.12430.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2602.12430.txt`

## 핵심 요약

이 survey는 agent skill을 instruction, code, resource로 구성된 portable procedural infrastructure로 정리한다. progressive disclosure, SKILL.md specification, MCP와의 관계, skill acquisition, deployment, governance/security taxonomy를 폭넓게 다룬다.

## 방법

- agent skill architecture와 lifecycle을 taxonomy로 정리한다.
- skill acquisition, synthesis, deployment, evaluation 흐름을 분류한다.
- security와 governance를 skill trust/lifecycle 관점에서 제시한다.

## 실험과 지표

Survey 성격상 단일 실험보다 문헌 구조화와 taxonomy가 중심이다. community-contributed skill의 vulnerability와 capability-based permission model 필요성을 논의하며, skill ecosystem 개선 방향을 정리한다.

## 한계

- survey는 자체 detector나 benchmark를 직접 제공하지 않는다.
- 빠르게 변하는 ecosystem에서는 taxonomy가 곧 outdated될 수 있다.
- 구현 가능한 policy로 바꾸려면 scanner, manifest, registry workflow가 별도로 필요하다.

## SkillShield 반영

- SkillShield의 scope를 security-only가 아니라 conformance, permission, metadata, evaluation까지 확장했다.
- `docs/capabilities.md`, metadata audit, lifecycle risk docs가 survey의 governance 관점을 구현한다.
- 후속 TODO: trust tier policy profiles, generated-skill publication gate.
