# Security Policy

## Reporting Vulnerabilities

**DO NOT** open a public GitHub issue for security vulnerabilities.

Please report security issues to: **security@cyberconsulting.fr**

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

## Planned Audit

A third-party security audit is planned before the official v1.0.0 release.
The audit will cover the files listed above plus the Docker composition and
network security model.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x (beta) | Security fixes |
| 0.1.x | No support |
