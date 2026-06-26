# Skill Vaccine Research Synthesis

Date generated: 2026-06-25
Language: Korean
Mode: agentic-rag portable mode + paper-summary-agent role synthesis

## Agentic RAG Retrieval Audit

Detailed Google Agentic RAG compliance audit:

- `research/google_agentic_rag_compliance_audit.md`
- `research/google_agentic_rag_trace.json`

### Corpus catalog

| Corpus ID | Description | Source |
|---|---|---|
| `skillsieve` | Malicious AI agent skill detection via hierarchical static, semantic, and jury triage. | arXiv:2604.06550 |
| `skillguard` | Permission manifest and runtime governance framework for agent skills. | arXiv:2606.03024 |
| `skillprobe` | Marketplace security auditing, semantic-behavioral alignment, and cross-skill risk simulation. | arXiv:2603.21019 |
| `skillmd-semantic-attack` | SKILL.md-only semantic supply-chain attacks against discovery, selection, and governance. | arXiv:2605.11418 |
| `skilldex` | Package manager, registry, and conformance diagnostics for agent skill packages. | arXiv:2604.16911 |
| `openskill-eval` | Dynamic evaluation of open skill quality and skill-augmented agent systems. | arXiv:2605.23657 |
| `evoskills` | Self-evolving multi-file skill generation using co-evolutionary verification. | arXiv:2604.01687 |
| `skillsbench` | Benchmark for measuring whether skills improve task outcomes. | arXiv:2602.12670 |
| `skill-landscape` | Data-driven analysis of Claude/GPT/Gemini skill ecosystem supply and adoption. | arXiv:2602.08004 |
| `skill-survey` | Survey/taxonomy of agent skills as procedural infrastructure. | arXiv:2602.12430 |

### Required facts

1. 어떤 보안 위험을 scanner가 잡아야 하는가.
2. 어떤 permission/capability 모델을 제공해야 하는가.
3. 어떤 conformance/registry/evaluation 기능이 GitHub-friendly 제품성을 만드는가.
4. 어떤 부분은 정적 scanner만으로 충분하지 않으며 후속 TODO로 남겨야 하는가.

### Sufficiency decision

Status: `sufficient` for MVP architecture and TODO generation.

Missing for future iterations:

- 논문별 전체 figure/table 한국어 해설은 개별 paper summary 파일로 확장해야 한다.
- SkillSieve/SkillGuard의 공개 artifact나 dataset schema는 아직 repo에 vendoring하지 않았다.
- LLM Layer 2/Jury Layer 3는 provider-neutral schema만 먼저 설계하고 구현은 후속 TODO로 둔다.

## Paper Summary-Agent Role Synthesis

개별 한국어 요약은 `research/paper_summaries/index.md`에 정리했다.

### 1. SkillSieve -> Layered scanner architecture

핵심 아이디어는 모든 skill을 비싼 LLM 판단으로 보내지 않고, 저비용 정적 triage에서 대부분을 걸러낸 뒤 의심 건만 structured semantic decomposition과 jury로 올리는 것이다. 논문 텍스트에서 Layer 1은 regex, AST, metadata를 사용하고 약 86%를 zero API cost로 필터링한다고 설명한다. Layer 2는 intent alignment, permission justification, covert behavior, cross-file consistency 같은 병렬 하위 판단을 사용한다. Layer 3는 여러 LLM jury로 borderline/high-risk 케이스를 검증한다.

Skill Vaccine 반영:

- `Layer 1`은 dependency-free Python 정적 scanner로 구현한다.
- 정적 규칙은 prompt injection, secret exfiltration, hidden/covert instructions, dangerous shell, dynamic execution, env/network access, obfuscation을 잡는다.
- Layer 2/3는 현재 TODO로 남기되, output schema가 나중에 붙기 쉬운 finding 구조를 먼저 만든다.

### 2. Under the Hood of SKILL.md -> SKILL.md 자체를 공격면으로 취급

이 논문은 SKILL.md가 단순 문서가 아니라 discovery, selection, governance 단계에 영향을 주는 operational text라고 본다. 검색 결과에 따르면 discovery 조작은 Top-10 placement, selection 조작은 description-only framing, governance evasion은 semantic rewriting/checklist hiding 같은 SKILL.md-only 변경으로 가능하다.

Skill Vaccine 반영:

- `description`의 과장, overbroad activation, persuasive selection framing을 별도 rule로 둔다.
- 본문에 숨은 "do not tell", "silently", "ignore previous/system" 류의 agent-facing instruction을 code risk와 별도로 잡는다.
- 향후 registry mode에서는 embedding stuffing/trigger length/anomalous keyword density를 검사한다.

### 3. SkillGuard -> Permission manifest and deny-by-default model

SkillGuard는 skill을 permission-bearing executable artifact로 본다. 주요 요소는 manifest, runtime access control, user-mediated authorization, deny-by-default, capability inference, behavior monitoring이다. 논문은 protected object taxonomy coverage와 automated manifest generation F1을 보고한다.

Skill Vaccine 반영:

- 정적 scanner가 inferred capability를 산출한다.
- `permissions` 또는 `capabilities` frontmatter가 없으면 `SS200`, inferred capability가 선언과 맞지 않으면 `SS201`로 보고한다.
- 향후 `skill-vaccine manifest suggest`가 inferred capability를 manifest 초안으로 만든다.

### 4. SkillProbe -> Marketplace admission and cross-skill risk

SkillProbe는 admission filtering, semantic-behavioral alignment, combinatorial risk simulation을 나눈다. 단일 skill만 보면 안전해도 여러 skill 조합에서 data exfiltration, indirect prompt injection, command injection risk link가 생길 수 있다는 점이 중요하다.

Skill Vaccine 반영:

- MVP는 single skill finding을 만든다.
- 후속 TODO는 `skill-vaccine graph scan <skill_dir>`로 output risk tag와 input sensitivity tag를 연결한다.
- SARIF는 단일 repo CI에 적합하고, 별도 JSON graph는 marketplace audit에 적합하다.

### 5. Skilldex/OpenSkillEval/SkillsBench/EvoSkills -> 제품성

Skilldex는 line-level conformance diagnostics와 package/registry UX가 중요함을 보여준다. OpenSkillEval과 SkillsBench는 인기 있는 skill이 반드시 성능을 높이지 않으며, task-grounded evaluation과 deterministic verifier가 필요하다는 점을 보여준다. EvoSkills는 skill authoring 자체가 비용이 크고 verifier loop가 필요하다는 점을 강조한다.

Skill Vaccine 반영:

- scanner는 security만 보지 않고 conformance와 evaluation hooks도 다룬다.
- fixture 기반 tests, SARIF, GitHub Action, pre-commit, benchmark harness를 TODO에 포함한다.
- finding은 사람이 바로 고칠 수 있도록 rule id, path, line, evidence, capability를 포함한다.

## Product Requirements

1. Local-first CLI: no network by default.
2. No dependency MVP: Windows/macOS/Linux에서 설치 friction을 낮춘다.
3. Structured outputs: text, JSON, SARIF.
4. Progressive analysis: static first, optional LLM second, optional jury third.
5. Permission inference: behavior에서 capability를 추론하고 manifest gap을 보고한다.
6. Registry readiness: package conformance와 selection/governance manipulation을 검사한다.
7. CI friendliness: `--fail-on` threshold와 SARIF upload를 지원한다.
8. Research traceability: 모든 major rule은 source paper와 rationale을 docs에 연결한다.

## Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| Regex-only scanner가 semantic attack을 놓침 | high | Layer 2 structured decomposition TODO |
| 정적 scanner false positive | medium | severity/confidence/evidence와 allowlist TODO |
| permission inference가 framework별 tool semantics를 모름 | high | host adapter TODO |
| 악성 fixture가 dual-use payload를 과도하게 자세히 담음 | medium | fixture는 최소 표현만 사용 |
| LLM provider 종속 | medium | schema-first adapter design |

