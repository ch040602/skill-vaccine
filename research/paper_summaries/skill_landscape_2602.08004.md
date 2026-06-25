# Agent Skill Landscape 요약 (arXiv:2602.08004)

## 메타데이터

- 주제: Agent Skill ecosystem 성장, category concentration, adoption imbalance.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2602.08004.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2602.08004.txt`

## 핵심 요약

이 논문은 agent skill ecosystem이 빠르고 bursty하게 성장하며, category별 공급/수요 imbalance와 ecosystem homogeneity가 존재한다고 분석한다. tooling 관점에서는 registry, conformance, trust, discoverability 문제가 빠르게 중요해진다는 근거가 된다.

## 방법

- public skill dataset의 first_seen, category, adoption signal을 분석한다.
- publication growth와 category distribution을 추적한다.
- supply-demand imbalance와 homogeneity를 관찰한다.

## 실험과 지표

논문은 marketplace skill 수가 빠르게 증가하며 일 단위 성장률과 bursty publication pattern을 보인다고 설명한다. category concentration과 adoption imbalance는 broad developer tooling의 필요성을 뒷받침한다.

## 한계

- marketplace snapshot은 계속 변하므로 수치가 시간에 민감하다.
- adoption signal은 quality/security의 직접 proxy가 아니다.
- 공개 dataset이 private enterprise skill 사용을 대표하지 않을 수 있다.

## SkillShield 반영

- GitHub Action, pre-commit, SARIF, registry metadata audit으로 adoption friction을 줄였다.
- benchmark/eval과 rule docs로 trust를 보강한다.
- 후속 TODO: package/release automation, trust tier policy profiles.
