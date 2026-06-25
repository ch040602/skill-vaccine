# OpenSkillEval 요약 (arXiv:2605.23657)

## 메타데이터

- 주제: open skill quality와 skill-augmented agent system 평가.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2605.23657.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2605.23657.txt`

## 핵심 요약

OpenSkillEval은 skill이 존재한다고 해서 agent가 실제로 skill을 읽고, 따르고, task 성능을 높인다는 보장이 없다고 지적한다. 정적 benchmark 대신 evolving source에서 realistic task instance를 생성하고, skill usage와 cost-performance tradeoff를 함께 본다.

## 방법

- open-source skill을 수집하고 task instance를 자동 생성한다.
- skill-augmented agent system과 skill 자체의 품질을 함께 평가한다.
- skill availability, selection, adherence, downstream task success를 분리해 본다.

## 실험과 지표

논문은 generated task instance와 30개 open-source skill을 사용해 state-of-the-art model/framework를 평가한다. 결과는 인기 있는 public skill도 no-skill baseline을 항상 이기지 못하며, skill benefit이 model/framework/task에 따라 달라진다는 점을 보여준다.

## 한계

- task generation 품질과 verifier 설계가 평가 결과를 좌우한다.
- popularity와 quality 사이의 관계를 단순화하면 안 된다.
- offline scanner는 actual skill adherence를 직접 측정할 수 없다.

## SkillShield 반영

- `skillshield eval <labels.json>`.
- benchmark labels에 `source_paper`, `attack_class`, `expected_rule_ids`.
- 후속 TODO: telemetry schema, hard negatives, packaged benchmark data.
