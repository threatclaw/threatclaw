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
- ClawVault — encrypted credential storage at rest
- Multi-trigger kill switch
- OWASP ASI Top 10 2026 mitigations

### ClawShield — Remediation Security (HITL)

All remediation actions (ClawStrike) require Human-in-the-Loop approval. ClawShield provides 5 independent protection layers:

1. **Immutable rules** — Compile-time verified constraints that cannot be modified at runtime
2. **Boot-locked configuration** — Protected infrastructure list read at startup and locked in memory
3. **Compiled validation** — Action allowlisting, target validation, input escaping, rate limiting
4. **Cryptographic nonces** — Anti-replay and anti-parameter-swap protection
5. **Approver verification** — Identity-based authorization (numeric IDs, not spoofable usernames)

### Infrastructure Security

- PostgreSQL TLS enforced (sslmode=require)
- Docker secrets for credential management
- Docker socket proxy (filtered API access)
- 5 isolated Docker networks
- Inter-service authentication via bearer tokens
- Webhook HMAC authentication with constant-time comparison

## CVE Status

We maintain `cargo audit` compliance on all releases:

- **Zero known CVEs** in the compiled binary (default features)
- **Zero critical** advisories outstanding
- Dependencies patched proactively against RUSTSEC advisories

Use `cargo audit` on your own build for current status.

## Planned Audit

A third-party security audit is planned before the official v1.0.0 release.
The audit will cover the files listed above plus the Docker composition and
network security model.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.2.x (beta) | Security fixes |
| < 2.2 | No support |
