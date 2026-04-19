# ThreatClaw — Benchmark Results

> Phase 6 of v1.1.0-beta grounding layer. Last updated: 2026-04-19.

## Purpose

ThreatClaw publishes a deterministic benchmark of its grounding layer —
the code that validates LLM output and reconciles verdicts against
deterministic signals. The benchmark is **not** a test of the underlying
LLM; it is a test of our guardrails.

- **Deterministic**: every input is a recorded fixture. Every run produces
  the same output.
- **Fast**: <100ms for the full corpus; runs in `cargo test` by default.
- **Public**: the corpus lives in `eval/fixtures/` and anyone can audit
  which scenarios we claim our guardrails handle.

## How to reproduce

```bash
git clone https://github.com/threatclaw/threatclaw
cd threatclaw
# Fast regression run (deterministic, no external deps)
cargo test --test grounding_benchmark

# Emit the JSON report
cargo test --test grounding_benchmark benchmark_emit_report -- --ignored --nocapture
```

The report is written to `eval/latest-benchmark-report.json`.

## Current results (v1.1.0-beta)

| Metric | Value |
|--------|-------|
| Scenarios | 6 |
| Passed | 6 |
| Failed | 0 |
| Rule-match accuracy | **100%** |
| Reconciliation agreement rate | **100%** |

### Rule coverage

| Rule | Scenarios | Description |
|------|-----------|-------------|
| `rule_a_confirmed_but_weak` | 1 | LLM confirms, signals weak → downgrade |
| `rule_b_false_positive_but_strong` | 1 | LLM dismisses, signals strong → escalate |
| `rule_c_inconclusive_but_kev` | 1 | LLM uncertain, CISA KEV hit → upgrade |
| `rule_d_validation_errors` | 1 | LLM confirmed with malformed MITRE/CVE |
| `rule_e_fabricated_citations` | 1 | LLM cites nonexistent alert/finding |
| `none` (passthrough) | 1 | All signals agree, verdict kept |

### Mode coverage

| Mode | Scenarios |
|------|-----------|
| `strict` | 6 |
| `lenient` | 0 |
| `off` | 0 |

Future fixtures should expand coverage to `lenient` (should observe but
not modify) and `off` (should short-circuit entirely).

### What this measures

- ✅ That the rule cascade's priority ordering (D > E > A > B > C) holds.
- ✅ That each rule triggers on the conditions documented in
  `internal/architecture-avril.md`.
- ✅ That passthrough works (no rule trigger when not warranted).

### What this does NOT measure

- ❌ LLM hallucination rate on real inputs. That requires a live benchmark
  against Ollama + Foundation-Sec-8B, out of scope for the deterministic
  runner.
- ❌ End-to-end latency of the ReAct loop. Phase 5 tracing provides
  per-call latency; aggregate p50/p95 is a downstream log-aggregator
  concern.

## Adding a scenario

1. Drop a JSON file in `eval/fixtures/` matching `eval/benchmark_schema.json`.
2. Run `cargo test --test grounding_benchmark`.
3. If it passes, commit. If it fails, either the fixture's `expected`
   block is wrong or the grounding layer behavior does not match your
   intuition — debug accordingly.

## NIS2 / ISO 42001 relevance

This benchmark is the **public evidence** that ThreatClaw's
anti-hallucination guardrails behave as documented. Auditors asking
"prove that you downgrade verdicts based on fabricated citations" can
be pointed at `rule-e-fabricated-citations.json` + the runner's
deterministic output.

The versioned report (`v1.0.0-phase6`) makes year-over-year comparison
straightforward: copy `eval/latest-benchmark-report.json` into your
audit bundle and archive it.
