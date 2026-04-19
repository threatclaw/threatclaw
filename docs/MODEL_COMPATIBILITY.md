# ThreatClaw — LLM Model Compatibility

> Updated 2026-04-19 for v1.0.6-beta.

## Summary

ThreatClaw's **grounding layer** (phase 1 of the v1.0.6 release) uses
Ollama's `format: <JSON Schema>` feature to constrain LLM outputs at
inference time via an FSM-based sampler. This requires the model to
have the right vocabulary metadata in its GGUF file and the underlying
llama.cpp grammar compiler to accept the schema.

We discovered during integration testing that **llama.cpp's
JSON-Schema → GBNF compiler has real limits** (see upstream issues
[ollama#12422](https://github.com/ollama/ollama/issues/12422),
[llama.cpp#19010](https://github.com/ggml-org/llama.cpp/issues/19010)).
Our schemas were simplified accordingly. Phase 2 Rust validators
compensate for what the schema no longer enforces.

## Tested OK with schema FSM

All four tested models successfully produced schema-compliant JSON
with the v1.0.6 simplified schemas:

| Model | RAM (Q8_0/Q4_K_M) | Role | Status |
|-------|-------------------|------|--------|
| `qwen3:14b` | ~10 GB | L1 triage / fallback L2 | ✅ |
| `qwen2.5:7b-instruct` | ~5 GB | L1 triage | ✅ |
| `mistral-small:24b` | ~14 GB | L0 conversational / L2 | ✅ |
| `hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF` | ~9 GB | **L2 forensic (recommended)** | ✅ |

## Schema shape requirements

### What llama.cpp handles reliably

- `enum` (e.g. severity, verdict type, evidence type) — **robust**
- `type` (number / string / array / object) — **robust**
- `required` field lists — **robust**
- `minimum` / `maximum` on numbers — **robust**
- `minLength` on strings — **robust** (low repetition count in GBNF)

### What llama.cpp chokes on (deliberately not used)

- `pattern` regex (e.g. `^T\d{4}$` for MITRE IDs) — crashes or rejects
  the model (**SIGSEGV** on mistral-small:24b, "failed to load
  vocabulary" on qwen3). Use Rust-side validation instead.
- `maxLength` > 500 on strings — triggers "number of repetitions
  exceeds sane defaults". We removed maxLength entirely; the tracing
  layer and database type constraints provide the upper bound.
- Nested `$ref` schemas — not tested, not recommended.
- `oneOf` / `anyOf` with complex alternatives — reports mixed.

## Troubleshooting

### Error: `"failed to load model vocabulary required for format"`

The GGUF file lacks the vocabulary metadata needed for grammar compilation.
Workaround: pull a different quant of the same model (e.g. Q4_K_M instead of
Q8_0), or fall back to `format: "json"` legacy mode (still valid on v1.0.6).

### Error: `"model runner has unexpectedly stopped"` / SIGSEGV

llama.cpp crashed while compiling the schema. In v1.0.6 this should not
happen with the shipped schemas (we removed the triggering patterns).
If you see it anyway, it likely means a custom skill passed its own
schema with regex patterns. Open an issue with the schema snippet.

### Error: `"number of repetitions exceeds sane defaults"`

Schema contains a string constraint with `maxLength` larger than
llama.cpp's grammar repetition limit. Remove the `maxLength` or reduce
below ~500. The v1.0.6 shipped schemas do not trigger this.

## Recommended production stack (as of 2026-04-19)

- **L0 conversational**: `mistral-small:24b` (24 GB RAM, Q4_K_M) — good
  tool-calling and structured outputs
- **L1 triage**: `qwen3:8b` — fast, permanent-resident in RAM
- **L2 forensic**: `Foundation-Sec-8B-Reasoning` (Q8_0 or Q4_K_M) —
  cyber-tuned reasoning with full schema FSM support

## Legacy `format: "json"` fallback

If a model does not support schema FSM at all, ThreatClaw
automatically falls back to the legacy `format: "json"` mode (plain
JSON hint without FSM). In this mode, the phase-2 Rust validators and
phase-3 reconciler are your only guardrails against LLM drift. The
operational guarantees remain strong in aggregate but the FSM
"mathematical" guarantee is lost for that specific model.
