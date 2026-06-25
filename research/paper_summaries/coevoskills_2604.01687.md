# CoEvoSkills 요약 (arXiv:2604.01687)

## 메타데이터

- 주제: self-evolving multi-file Agent Skill generation.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2604.01687.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2604.01687.txt`

## 핵심 요약

CoEvoSkills는 skill이 단일 함수형 tool보다 복잡한 multi-file artifact라는 점에 주목한다. Skill Generator와 Skill Verifier를 결합해, ground-truth test content에 직접 접근하지 않고도 skill package를 반복 개선하는 framework를 제안한다.

## 방법

- Skill Generator가 SKILL.md, script, resource를 포함한 skill package를 생성/수정한다.
- Skill Verifier가 task feedback과 실패 evidence를 제공한다.
- co-evolution loop가 generator와 verifier를 함께 개선한다.

## 실험과 지표

논문은 SkillsBench에서 여러 baseline과 비교해 CoEvoSkills가 높은 pass rate를 달성한다고 보고한다. 핵심 지표는 generated skill이 downstream task completion을 얼마나 개선하는지이다.

## 한계

- 생성된 skill은 publication 전에 별도 보안/permission 검증이 필요하다.
- verifier feedback이 약하면 generator가 benchmark-specific shortcut을 학습할 수 있다.
- multi-file skill은 hidden script capability와 provenance 추적이 어려워진다.

## SkillShield 반영

- generated-skill publication gate TODO.
- cross-file consistency `SS202`.
- metadata/provenance audit.
- benchmark/eval command는 generated skill 검증 loop의 일부로 사용할 수 있다.
