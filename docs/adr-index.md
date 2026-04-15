# Architecture Decision Records — Index

ThreatClaw tracks architectural decisions as **ADRs** (Architecture Decision
Records) numbered `ADR-XXX`. This index lists the decisions referenced in the
public codebase so readers encountering a `See ADR-XXX` comment understand
what it refers to.

The detailed ADR contents are currently maintained internally while the
project stabilizes. Summaries or full publication may happen later.

---

## Core runtime

| ID | Title |
|---|---|
| ADR-001 | Bloom filter for IoC matching — constant-time lookup, low memory |
| ADR-002 | Isolation Forest for per-asset behavioral anomaly detection |
| ADR-003 | DBSCAN for behavioral peer-group clustering |
| ADR-004 | Random Forest + LSTM dual-backend for DGA domain detection |
| ADR-005 | Beacon detection via coefficient of variation (RITA-style) |
| ADR-006 | Constant-time comparison for secret/token validation |
| ADR-007 | BLAKE3 hashing for WASM integrity verification |
| ADR-008 | Argon2id for master password derivation |
| ADR-009 | Agent Soul hash compiled into binary (tamper detection) |
| ADR-010 | Kill switch — hard stop on self-integrity failure |

## LLM pipeline & agent loop

| ID | Title |
|---|---|
| ADR-011 | 5-level LLM architecture (L0 Ops → L1 Triage → L2 Forensic → L3 Cloud) |
| ADR-012 | Rules-based intelligence engine with LLM escalation |
| ADR-024 | 3-stage detection pipeline (ingest → correlate → verdict) |
| ADR-025 | Automatic detection of reasoning-capable models |
| ADR-026 | ReAct cycle with 5 safety pillars (soul, whitelist, HMAC memory, kill switch, XML wrapper) |
| ADR-028 | Cloud intent parser for natural-language commands |
| ADR-029 | Natural-language command interpretation pipeline |
| ADR-030 | Intelligence Engine per-cycle caches + investigation dedup |
| ADR-031 | IP classification unified function (`is_non_routable`) |
| ADR-032 | Cyber scheduler for default security routines |
| ADR-041 | Dynamic intelligence engine cycle (30s attack / 5min calm) |

## Sandbox & WASM

| ID | Title |
|---|---|
| ADR-013 | Fresh WASM instance per invocation (no state leak) |
| ADR-014 | Capability-based permissions, deny by default |
| ADR-023 | Community skills are read-only (no remediation permitted) |
| ADR-034 | Tool calling — native Ollama + JSON mode dual support |
| ADR-035 | Tool output sanitization (strip ANSI, redact secrets) |
| ADR-036 | Credential vault crypto (AES-256-GCM + HKDF) |
| ADR-037 | WASM credential injection at host boundary (never in sandbox) |
| ADR-038 | Docker ephemeral executor for scanner containers |

## Sigma & threat content

| ID | Title |
|---|---|
| ADR-018 | Composite priority score (CVSS × CISA KEV × EPSS) |
| ADR-020 | Native Sigma rule engine (no external Python sigmac) |

## Data & networking

| ID | Title |
|---|---|
| ADR-015 | Docker network isolation — 4 dedicated networks |
| ADR-016 | Sidecar llama-server for local LLM inference |
| ADR-017 | Apache AGE for graph intelligence (STIX 2.1) |
| ADR-019 | Naabu over rustscan for network discovery |
| ADR-021 | Reversible anonymization for cloud LLM escalation |
| ADR-022 | Zero-trust agent model — signed messages end-to-end |

## Security hardening

| ID | Title |
|---|---|
| ADR-027 | Notification routing matrix (channel × severity × verdict) |
| ADR-033 | HITL (Human-in-the-Loop) approval pipeline |
| ADR-039 | PostgreSQL TLS `require` mode by default |
| ADR-040 | API keys passed in headers, never as URL params |
| ADR-042 | Docker socket proxy (filtered API surface) |
| ADR-043 | Incidents layer above alerts and findings |
| ADR-044 | HITL security hardening — CSPRNG nonce, anti-replay, LDAP escape |

---

*Last updated: 2026-04-15.  If you are reading a `See ADR-XXX` comment in
the code and the ID is not listed here, please open an issue — the reference
may be stale.*
