# Under the Hood of SKILL.md 요약 (arXiv:2605.11418)

## 메타데이터

- 주제: SKILL.md-only semantic supply-chain attack.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2605.11418.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2605.11418.txt`

## 핵심 요약

이 논문은 SKILL.md가 단순 문서가 아니라 discovery, selection, governance에 영향을 주는 operational text라고 본다. 실행 코드 변경 없이 description, trigger text, checklist 문구만 바꿔 registry ranking, model selection, reviewer governance를 조작할 수 있음을 보인다.

## 방법

- Discovery: embedding/retrieval ranking에 영향을 주는 keyword/trigger 문구를 삽입한다.
- Selection: description-only framing으로 agent가 adversarial variant를 고르게 만든다.
- Governance: semantic rewriting, reviewer instruction, checklist hiding으로 심사/검출을 우회한다.

## 실험과 지표

논문은 discovery trigger가 높은 pairwise win rate와 Top-10 placement를 만들고, selection variant가 평균 77.6% paired trials에서 선택되는 현상을 보고한다. governance 실험은 코드 변경 없이 심사 단계가 semantic text에 취약해지는 사례를 보여준다.

## 한계

- 특정 registry embedding model과 agent selection policy에 따라 수치가 달라질 수 있다.
- 공격 성공은 user query 분포와 candidate set에 민감하다.
- 방어는 static keyword rule만으로 충분하지 않고 semantic review가 필요하다.

## Skill Vaccine 반영

- `lifecycle_stage`: discovery, selection, governance.
- `SS012` discovery keyword stuffing.
- `SS004`, `SS005` selection manipulation.
- `SS013`, `SS014` governance manipulation.
- `docs/registry-lifecycle-risks.md`.

