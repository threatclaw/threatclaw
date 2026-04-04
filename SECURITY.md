# Security Policy

## Reporting Vulnerabilities

**DO NOT** open a public GitHub issue for security vulnerabilities.

**Preferred:** Use the **"Report a vulnerability"** button in the [Security tab](https://github.com/threatclaw/threatclaw/security/advisories) of this repository (GitHub Private Vulnerability Reporting).

**Alternative:** Send an email to **security@cyberconsulting.fr**

We will acknowledge within 48 hours and provide a fix timeline within 7 days.

## Security Architecture

ThreatClaw implements a **Zero Trust Agent** architecture with defense-in-depth:

- Immutable agent identity (compile-time verified)
- Command allowlisting with strict validation
- WASM sandboxed skill execution (deny-by-default capabilities)
- Encrypted credential vault
- Multi-trigger kill switch
- OWASP ASI Top 10 2026 mitigations

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
