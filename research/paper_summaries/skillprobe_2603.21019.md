# SkillProbe 요약 (arXiv:2603.21019)

## 메타데이터

- 주제: skill marketplace 보안 감사와 cross-skill combinatorial risk.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2603.21019.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2603.21019.txt`

## 핵심 요약

SkillProbe는 개별 skill이 안전해 보여도 여러 skill이 같은 agent session에서 조합될 때 data exfiltration, indirect prompt injection, command injection 같은 위험 link가 생긴다고 본다. marketplace admission filtering, semantic-behavioral alignment, combinatorial risk simulation을 함께 다룬다.

## 방법

- admission 단계에서 명백한 악성/정책 위반 skill을 걸러낸다.
- semantic 목적과 실제 behavior alignment를 비교한다.
- skill 간 source/sink label graph를 만들어 combinatorial risk를 추적한다.

## 실험과 지표

논문은 ClawHub의 2,500개 real-world skill과 8개 mainstream LLM series를 사용한 대규모 audit을 보고한다. 전통적인 atomic-level auditing이 놓치는 cross-skill attack을 찾는 것이 핵심 평가 축이다.

## 한계

- graph edge는 가능성이지 실제 co-selection의 증거는 아니다.
- marketplace popularity나 usage count는 보안 proxy로 충분하지 않다.
- 실제 agent orchestration policy와 session memory 구조에 따라 위험이 달라진다.

## SkillShield 반영

- `skillshield graph <path>`.
- `data_source`, `exfiltration_sink`, `prompt_injection_source`, `command_injection_sink` tag.
- `data_exfiltration`, `prompt_to_command_injection` edge.
- `SS202` cross-file consistency finding.
