# ThreatClaw — Observability

> Phase 5 of v1.1.0-beta grounding layer. Updated 2026-04-19.

## TL;DR

ThreatClaw emits **structured tracing events** at every LLM call, reconciler
decision and evidence-citation check. Event fields follow the OpenTelemetry
GenAI semantic conventions where applicable (`gen_ai_system`,
`gen_ai_request_model`, ...) plus ThreatClaw-specific fields
(`threatclaw_*`).

No OTel dependency is compiled into the binary — the tracing subscriber uses
a plain layer that any aggregator (Langfuse, Phoenix, Grafana, Loki,
Datadog...) can ingest by either:

1. Scraping the JSON log stream, or
2. Attaching a `tracing-opentelemetry` layer via a thin wrapper binary.

**Field naming note** — the `tracing` macro requires valid Rust identifiers
for field keys, so we use underscores rather than OTel's conventional dots.
`gen_ai_system` maps to `gen_ai.system` in a one-line Langfuse ingestion
rule or an OTel processor.

## Fields per event type

### `threatclaw.llm_call`

| Field | Type | Description |
|-------|------|-------------|
| `gen_ai_system` | string | `"ollama"` / `"anthropic"` / `"mistral"` |
| `gen_ai_request_model` | string | Model name (e.g. `"qwen3:8b"`) |
| `threatclaw_llm_level` | string | `"L1"` / `"L2"` / `"L0"` |
| `threatclaw_prompt_hash` | string | 16-hex SHA-256 prefix of the **anonymised** prompt |
| `threatclaw_prompt_len` | usize | Prompt length in bytes |
| `threatclaw_response_len` | usize | Response length in bytes |
| `threatclaw_latency_ms` | u128 | End-to-end latency in milliseconds |
| `threatclaw_schema_used` | bool | Whether a JSON Schema constrained the output |

### `threatclaw.reconciler`

| Field | Type | Description |
|-------|------|-------------|
| `threatclaw_incident_id` | i32 | Incident row id (or `-1` if unknown) |
| `threatclaw_validation_mode` | string | `"off"` / `"lenient"` / `"strict"` |
| `threatclaw_reconciler_applied` | bool | Whether the verdict was actually modified |
| `threatclaw_verdict_original` | string | LLM original verdict |
| `threatclaw_verdict_reconciled` | string | Reconciled verdict (same as original if no rule matched) |
| `threatclaw_reconciler_rule_code` | string | `"rule_a_confirmed_but_weak"` / etc. / `"none"` |
| `threatclaw_validation_error_count` | usize | Phase 2 validation errors |
| `threatclaw_citation_fabricated_count` | usize | Phase 4 fabricated citations |

### `threatclaw.citations`

| Field | Type | Description |
|-------|------|-------------|
| `threatclaw_incident_id` | i32 | Incident row id (or `-1`) |
| `threatclaw_citation_verified_count` | usize | Citations whose evidence_id was found in the dossier |
| `threatclaw_citation_unverifiable_count` | usize | Log / GraphNode types (not tracked in dossier) |
| `threatclaw_citation_fabricated_count` | usize | Citations with missing evidence_id in the dossier |

## Enabling verbose output

Set `RUST_LOG` to your preferred filter (defaults to
`threatclaw=info,tower_http=warn`) and start ThreatClaw normally. Examples:

```
# See all telemetry events
RUST_LOG=threatclaw=info ./threatclaw

# Only the reconciler events
RUST_LOG=threatclaw.reconciler=info ./threatclaw

# Only fabricated-citation incidents
RUST_LOG=threatclaw.citations=warn ./threatclaw
```

## Attaching Langfuse

Langfuse (https://langfuse.com) exposes an OTLP-compatible endpoint. Steps
to send ThreatClaw traces to a Langfuse instance:

1. Self-host Langfuse via its official docker-compose recipe
   (https://langfuse.com/self-hosting/docker-compose). Requires ClickHouse
   and ~2 GB RAM overhead.

2. Build a thin wrapper binary (not shipped by default) that initialises a
   `tracing-opentelemetry` layer alongside the existing ThreatClaw
   subscriber, with `OTEL_EXPORTER_OTLP_ENDPOINT` pointing at the Langfuse
   OTLP endpoint and `OTEL_EXPORTER_OTLP_HEADERS` carrying the Langfuse
   public/secret keys.

3. Traces will appear in the Langfuse UI with `gen_ai_*` and `threatclaw_*`
   attributes as first-class filters.

Integration-level sample code is kept out of this repo on purpose (the
OpenTelemetry Rust ecosystem churns through breaking changes every few
months). Refer to the current `tracing-opentelemetry` and
`opentelemetry-langfuse` docs.

## Attaching Phoenix / Grafana Tempo / Datadog

Same pattern as Langfuse — any OTLP-compatible backend works once the
tracing subscriber has a `tracing-opentelemetry` layer. Alternatively,
JSON-scrape via Loki / Elasticsearch / Splunk works without any code
change.

## Minimal Promtail snippet (Loki ingestion)

```yaml
scrape_configs:
  - job_name: threatclaw
    static_configs:
      - targets: [localhost]
        labels:
          job: threatclaw
          __path__: /var/log/threatclaw/*.log
    pipeline_stages:
      - json:
          expressions:
            level: fields.level
            target: fields.target
            prompt_hash: fields.threatclaw_prompt_hash
            rule_code: fields.threatclaw_reconciler_rule_code
      - labels:
          level:
          target:
```

## NIS2 / ISO 42001 audit use cases

The structured events are designed to support the auditability clauses of
NIS2 Art. 21 §2(e) and ISO/IEC 42001 A.6.2.6 (evidence index). Sample
queries an auditor might run against the log store:

- **Verdict trail for a given incident** —
  `threatclaw_incident_id = 42 AND target IN ("threatclaw.reconciler", "threatclaw.citations")`
- **All reconciliation downgrades over the last 30 days** —
  `target = "threatclaw.reconciler" AND threatclaw_reconciler_applied = true`
- **LLM p95 latency per model** —
  group by `gen_ai_request_model`, aggregate `threatclaw_latency_ms` p95
- **Fabricated-citation rate** —
  sum `threatclaw_citation_fabricated_count` / sum `threatclaw_citation_verified_count`

## Field naming: OTel convention mapping

When shipping to a backend that expects OTel-native dotted attributes
(`gen_ai.system` rather than `gen_ai_system`), apply an ingestion rule or
OTel processor. Example in a Grafana Alloy config:

```river
otelcol.processor.attributes "threatclaw_rename" {
  action {
    key = "gen_ai.system"
    from_attribute = "gen_ai_system"
    action = "insert"
  }
  // ... repeat for each renamed field
}
```

Langfuse has similar ingestion mapping in its configuration UI.
