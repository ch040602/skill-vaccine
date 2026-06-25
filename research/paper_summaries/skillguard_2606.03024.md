# SkillGuard 요약 (arXiv:2606.03024)

## 메타데이터

- 주제: Agent Skill을 permission-bearing artifact로 다루는 permission framework.
- PDF: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2606.03024.pdf`
- TXT: `C:/Users/hcslab_523/Documents/paper-summary-agent/downloaded/arxiv.org_pdf_2606.03024.txt`

## 핵심 요약

SkillGuard는 skill을 단순 텍스트 instruction이 아니라 host resource에 접근할 수 있는 executable artifact로 본다. 따라서 manifest, runtime access control, user-mediated authorization, deny-by-default, capability inference가 필요하다고 주장한다.

## 방법

- skill manifest로 capability surface를 선언한다.
- host-specific tool invocation을 protected object taxonomy에 매핑한다.
- runtime pipeline에서 workspace defaults, manifest, user approval을 합성해 deny-by-default 정책을 적용한다.
- 정적/동적 evidence로 automated manifest generation을 수행한다.

## 실험과 지표

논문은 permission taxonomy가 관측 protected object의 99.76%를 cover하고, automated manifest generation이 91.0% F1에 도달한다고 보고한다. adversarial evaluation에서는 unsafe action을 줄이는 효과를 강조한다.

## 한계

- host별 tool semantics가 다르면 taxonomy와 enforcement adapter가 필요하다.
- manifest 선언 자체가 악의적으로 축소될 수 있으므로 inference와 audit이 필요하다.
- runtime enforcement가 없는 환경에서는 scanner output만으로 접근 차단을 보장하지 못한다.

## SkillShield 반영

- `capability` field와 `docs/capabilities.md`.
- `SS200` missing permission manifest.
- `SS201` inferred capability not declared.
- `manifest suggest`.
- suppression과 metadata audit도 permission governance와 분리해 audit trail로 유지한다.
