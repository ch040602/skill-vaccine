# Google Agentic RAG Compliance Audit

Date generated: 2026-06-25
RDD TODO: `RDD-T-00000031`
Scope: Verify whether Skill Vaccine's research workflow applied Google's Agentic RAG pattern completely enough for traceable development decisions.

## Sources

Primary sources checked:

- Google Research Blog, "Unlocking dependable responses with Gemini Enterprise Agent Platform's Agentic RAG", published 2026-06-05.
- Google Cloud Documentation, "RAG Engine Cross Corpus Retrieval".

Key source facts used:

- Google's framework goes beyond standard RAG by decomposing enterprise queries and searching iteratively until context is sufficient.
- The multi-agent roles include Orchestrator, Planner Agent, Query Rewriter, Search Fanout/RAG Agent, Sufficient Context Agent or Reasoning Agent, and Synthesis/LLM Generator.
- Cross-corpus routing depends on corpus `description`; Google Cloud docs explicitly warn that high-quality descriptions are crucial and not editable after corpus creation.
- The planner should route specific parts of a query to relevant corpora rather than naively searching all corpora.
- The Sufficient Context component decides whether retrieved contexts are enough; if not, it generates feedback for another retrieval loop.
- Google reports cross-corpus evaluation on FramesQA with 824 queries and 2,676 PDFs, 90.1% cross-corpus accuracy, and latency within about 3% of single-corpus mode.

## Compliance Verdict

Overall status: **partial but now remediated for documentation traceability**.

The previous Skill Vaccine work applied the spirit of Agentic RAG: it built a corpus catalog, searched multiple research corpora, used role-scoped paper analysis, judged the result sufficient for MVP requirements, and created TODOs for missing work.

However, it did **not** fully preserve the Google-style audit trail. The missing pieces were not primarily implementation bugs; they were traceability gaps:

1. No durable retrieval plan object mapped each required fact to candidate corpora.
2. No durable query rewrite/fanout log recorded original question -> plan item -> subquery -> source.
3. No durable snippet IDs tied research claims to specific paper/source evidence.
4. The sufficiency check existed only as prose, not as a structured assessment.
5. The iteration loop was summarized, but not recorded as iteration state with missing facts and feedback queries.
6. The final synthesis did not explicitly cite snippet IDs for each material claim.

This audit adds those missing artifacts in `research/google_agentic_rag_trace.json` and records follow-up TODOs for keeping this standard in later research updates.

## Google Pattern Checklist

| Google Agentic RAG element | Current Skill Vaccine state before this audit | Update made now | Status |
|---|---|---|---|
| Orchestrator / Router | Main agent coordinated paper discovery, summarization, and RDD development, but no explicit trace artifact. | Added durable trace with `orchestrator` metadata and decision state. | remediated |
| Corpus catalog with descriptions | Present in `skill-vaccine-research-synthesis.md`. | Repeated in structured trace with routing-purpose descriptions. | complete |
| Planner maps facts to corpora | Required facts were listed, but not mapped to candidate corpora. | Added `retrieval_plan.required_facts` and `routes`. | remediated |
| Query rewriting and fanout | Web/PDF searches were performed, but not durably logged by plan item. | Added `query_rewrites.subqueries` with target corpora and reasons. | remediated |
| Retrieve snippets with provenance | PDF/text sources were fetched, but synthesis cited papers broadly instead of snippet IDs. | Added `retrieved_snippets` with IDs, source URLs, local paths, and supported facts. | remediated |
| Draft from snippets only | The synthesis was source-grounded, but no draft object existed. | Added `draft_answer` in the trace. | remediated |
| Sufficient Context check | Prose status existed. | Added structured `context_assessment` with covered facts, missing facts, unsupported claims, and confidence. | remediated |
| Iterate on insufficiency | The process did a second pass via role agents and more TODOs, but not as explicit retrieval iteration. | Added `iterations` with feedback/missing facts and stop condition. | partially remediated |
| Final grounded answer with citations | Product requirements were grounded in papers, but not claim-to-snippet. | Added `grounded_answer.citations` mapping claims to snippet IDs. | remediated |
| Avoid naive all-corpus retrieval | Initial discovery was broad, then narrowed by role. | Trace now records broad discovery as iteration 0 and routed evidence extraction as iteration 1. Future runs must route first when corpus descriptions are known. | partial |

## Main Finding

The biggest deviation from Google's method was not insufficient research coverage. It was **insufficient provenance structure**. Google's pattern is valuable because it makes the answer auditable: which corpora were selected, which missing facts triggered follow-up retrieval, and which snippets support final claims.

Skill Vaccine now has the right development direction, but future research updates should not stop at a prose synthesis. They should produce a machine-readable trace before accepting downstream TODOs.

## Accepted RDD Findings

### RDD-F-0000000004

Severity: high

Claim: The previous Agentic RAG application lacked a durable query lineage and snippet-citation artifact.

Risk: Future contributors cannot distinguish source-supported TODOs from inferred TODOs.

Decision: accept.

Action: Add `research/google_agentic_rag_trace.json` and append TODOs requiring trace generation for future research updates.

### RDD-F-0000000005

Severity: medium

Claim: Initial broad web search resembled naive all-corpus retrieval before corpus descriptions were stabilized.

Risk: This can weaken routing discipline and make retrieval cost/noise scale poorly.

Decision: accept with context.

Reason: Broad discovery was acceptable for unknown corpus discovery, but once corpus candidates existed, later evidence extraction should have been route-first.

Action: Record future TODO to add a repeatable Agentic RAG research-run template.

## Required Future Standard

Any future Skill Vaccine research update should save:

1. `corpus_catalog`: id, description, source URL, local artifact path.
2. `retrieval_plan`: required facts, priority, candidate corpora, stop conditions.
3. `query_rewrites`: subqueries with fact ID and target corpora.
4. `retrieved_snippets`: snippet IDs, source, local path, lines/pages when available, supported facts.
5. `context_assessment`: sufficient/insufficient/unanswerable status, missing facts, unsupported claims, confidence.
6. `iterations`: feedback queries and stop decisions.
7. `grounded_answer`: material claims mapped to snippet IDs.

## Sources

- Google Research Blog: https://research.google/blog/unlocking-dependable-responses-with-gemini-enterprise-agent-platforms-agentic-rag/
- Google Cloud Cross Corpus Retrieval docs: https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/rag-engine/cross-corpus-retrieval

