# SkillSieve 요약 (arXiv:2604.06550)

## 메타데이터

- 주제: 악성 Agent Skill 탐지를 위한 계층형 scanner.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2604.06550.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2604.06550.txt`

## 핵심 요약

SkillSieve는 모든 skill을 비싼 LLM 판단으로 보내지 않고, 정적 triage, 구조화된 semantic decomposition, LLM jury를 순차 적용하는 비용 민감형 보안 pipeline을 제안한다. 핵심은 recall을 유지하면서 대부분의 평범한 skill을 Layer 1에서 끝내고, 의심 사례만 Layer 2/3로 올리는 것이다.

## 방법

- Layer 1: regex, AST, metadata, heuristic scoring으로 prompt injection, 위험한 코드, 비정상 metadata를 정적으로 검사한다.
- Layer 2: 의심 skill을 intent alignment, permission justification, covert behavior, cross-file consistency 같은 하위 semantic task로 분해한다.
- Layer 3: high-risk/borderline 사례를 여러 LLM juror에게 보내고 disagreement/debate metadata를 남긴다.

## 실험과 지표

논문은 Layer 1이 약 86% 물량을 zero API cost로 필터링하고, 평균 수십 ms 수준의 정적 처리 비용을 보고한다. 전체 pipeline은 높은 precision/recall/F1과 낮은 per-skill 비용을 목표로 하며, XGBoost fast-path가 LLM 호출을 줄이는 대신 소폭의 F1 감소를 만든다고 설명한다.

## 한계

- Layer 2/3는 LLM 품질과 prompt design에 영향을 받는다.
- 정적 Layer 1은 semantic rewriting이나 문맥 의존 위장을 놓칠 수 있다.
- benchmark와 threat model이 실제 registry 전체를 완전히 대표한다고 보기는 어렵다.

## Skill Vaccine 반영

- `scan`의 Layer 1 정적 rule 체계.
- `semantic schema`, `semantic review --provider fake`.
- `jury schema`, `jury review --provider fake`.
- `SS300` provider-free semantic routing finding.
- 후속 TODO: 실제 provider adapter, chunk coverage, broader benchmark.

