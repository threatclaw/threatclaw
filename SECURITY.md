# Security Policy

## Reporting Vulnerabilities

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Preferred:** Use the **"Report a vulnerability"** button in the [Security tab](https://github.com/threatclaw/threatclaw/security/advisories) of this repository (GitHub Private Vulnerability Reporting).

**Alternative:** Send an email to **security@cyberconsulting.fr**

We will acknowledge within 48 hours and provide a fix timeline within 7 days.

## Audit Priority Files

The following files handle security-critical operations and are priority for audit:

| File | Function | Risk |
|------|----------|------|
| `src/agent/executor.rs` | Local command execution | Command injection |
| `src/agent/executor_ssh.rs` | Remote SSH execution (V2) | MITM, credential leak |
| `src/agent/soul.rs` | Agent identity integrity | Goal hijack |
| `src/secrets/crypto.rs` | AES-256-GCM encryption | Credential exposure |
| `src/secrets/master_password.rs` | Argon2id key derivation | Brute force |
| `src/agent/react_runner.rs` | LLM orchestration | Prompt injection |
| `src/agent/remediation_whitelist.rs` | Command whitelist | Bypass |
| `src/agent/tool_output_wrapper.rs` | Output sanitization | Indirect injection |
| `src/agent/kill_switch.rs` | Emergency stop | Bypass |
| `src/agent/hitl_nonce.rs` | Anti-replay HITL | Replay attack |

## Security Architecture

ThreatClaw implements a **Zero Trust Agent** architecture:

- **5 Piliers intouchables** : Soul immuable, Whitelist commandes, XML wrapper, Mémoire HMAC, Kill switch
- **OWASP ASI Top 10 2026** : 9/9 applicable risks mitigated
- **Credential vault** : AES-256-GCM + HKDF-SHA256 + Argon2id master password
- **WASM sandbox** : Skills cannot access filesystem, network, or secrets directly

See `docs/THREATCLAW_V2_ARCHITECTURE.md` for the complete security model.

## Known CVE Status

Last audit: 2026-03-21 (`cargo audit`)

| Status | Count | Details |
|--------|-------|---------|
| **Patched** | 10 | aws-lc-sys (2), rustls-webpki 0.103, wasmtime (4), serde_yml, tokio-tar, libsql default removed |
| **In binary** | 0 | No known CVE in the compiled binary (default features) |
| **Critical** | 0 | — |

Actions taken:
- `aws-lc-sys` 0.38.0 → 0.39.0: RUSTSEC-2026-0048 (HIGH 7.4), RUSTSEC-2026-0044
- `rustls-webpki` 0.103.9 → 0.103.10: RUSTSEC-2026-0049
- `wasmtime` 28.0.1 → 36.0.6: RUSTSEC-2025-0046, 2025-0118, 2026-0020, 2026-0021
- `serde_yml` → replaced by `serde_yaml_ng`: RUSTSEC-2025-0068
- `testcontainers-modules` removed (unused): eliminates `tokio-tar` RUSTSEC-2025-0111
- `libsql` removed from default features: `rustls-webpki` 0.102.8 no longer compiled
- `bedrock` already opt-in: `rustls-webpki` 0.101.7 only compiled if explicitly enabled

Note: `cargo audit` may report false positives from `Cargo.lock` for optional dependencies
(`libsql`, `bedrock`) that are not compiled into the default binary. Use `cargo tree` to verify.

## Planned Audit

A third-party security audit is planned before the official v1.0.0 release.
The audit will cover the files listed above plus the Docker composition and
network security model.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.2.x (beta) | Security fixes |
| < 2.2 | No support |
