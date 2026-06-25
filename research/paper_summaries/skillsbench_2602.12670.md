# SkillsBench 요약 (arXiv:2602.12670)

## 메타데이터

- 주제: skill이 task performance를 실제로 높이는지 측정하는 paired benchmark.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2602.12670.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2602.12670.txt`

## 핵심 요약

SkillsBench는 no-skill 조건과 curated-skill 조건을 matched comparison으로 비교해야 skill efficacy를 제대로 측정할 수 있다고 주장한다. 현재 inventory는 8개 domain의 87개 task와 deterministic verifier를 포함한다.

## 방법

- 각 task를 no-skill baseline과 skill-augmented condition으로 비교한다.
- deterministic verifier로 pass/fail을 측정한다.
- model-harness configuration별 skill lift를 계산한다.

## 실험과 지표

논문은 87개 task와 18개 model-harness configuration에서 curated skill이 평균 pass rate를 33.9%에서 50.5%로 올렸다고 보고한다. 이는 +16.6 percentage point, 25.5% normalized gain에 해당한다.

## 한계

- curated skill 효과가 모든 task/모델에서 동일하지 않다.
- verifier가 다루기 어려운 open-ended task에는 한계가 있다.
- security scanner와 performance benchmark는 다른 목적의 평가다.

## SkillShield 반영

- eval command는 scanner quality regression을 측정하지만, task performance 주장은 하지 않는다.
- benchmark docs에서 MVP benchmark가 통계적 품질 주장이 아님을 명시했다.
- 후속 TODO: larger benchmark, packaged benchmark, deterministic verifier 연동.
