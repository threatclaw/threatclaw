# Security Policy

ThreatClaw is a cybersecurity product used by organizations to protect
their infrastructure. We take vulnerability reports very seriously and
commit to a responsible, coordinated disclosure process.

---

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

### Preferred — GitHub Private Vulnerability Reporting

Click the **"Report a vulnerability"** button in the
[Security tab](https://github.com/threatclaw/threatclaw/security/advisories)
of this repository. This gives us a private, auditable channel and
lets us invite you to the fix validation.

### Alternative — Email

Send your report to **security@cyberconsulting.fr**.

For sensitive details, encrypt your email with our PGP key (fingerprint
published at https://threatclaw.io/.well-known/security.txt when
available). If the key is not yet published at the time of your report,
send a short heads-up email first and we will share the current key out
of band.

---

## Response SLA

| Step | Target |
|---|---|
| Acknowledgement of receipt | **≤ 48 hours** (business days, Europe/Paris) |
| Triage + severity assessment | **≤ 7 days** |
| Patch release for **critical** vulnerabilities | **≤ 14 days** |
| Patch release for **high** vulnerabilities | **≤ 30 days** |
| Patch release for **medium / low** | **next minor release** |
| Public advisory + CVE (where appropriate) | **coordinated with reporter** |

If we miss a milestone, we will email you with the reason and an updated
timeline. In no case will we silently drop a report.

---

## Scope

### In scope

- The ThreatClaw core agent (Rust) — `src/**`
- The ThreatClaw dashboard (Next.js) — `dashboard/**`
- The ML engine (Python) — `ml-engine/**`
- Database migrations — `migrations/**`
- Docker composition and network topology — `docker/**`
- Official installation scripts — `installer/**`
- Official Typst report templates — `templates/**`
- WASM skill runtime and sandbox
- Official skills published in `skills/` (excluding `_future/`)

### Out of scope

- **Third-party skills** (community-trust level) — please report to
  the skill's own maintainer. The WASM sandbox is in scope; any
  sandbox escape via a community skill is a ThreatClaw vulnerability.
- Vulnerabilities in upstream dependencies **that are not reachable
  via our default configuration** (please report to the upstream
  project; we will patch upon release)
- Social-engineering or phishing against CyberConsulting.fr staff
- Denial of service achievable only through legitimate heavy load
  without a protocol flaw
- Self-XSS or attacks requiring the victim to disable browser security
- `threatclaw.io` website (marketing property — separate scope)

---

## Safe Harbor for Security Researchers

When conducting **good-faith security research** that adheres to this
policy, CyberConsulting.fr will:

1. Not pursue or support any legal action against you
2. Work with you to understand and resolve the issue quickly
3. Publicly credit you in our advisory (unless you prefer anonymity)

Good-faith research requires that you:

- Only test against **your own installation** or an instance you have
  explicit authorization to test
- Not access, modify, or exfiltrate data belonging to other users
- Not disrupt production systems or degrade their availability
- Give us reasonable time to remediate before any public disclosure
- Comply with all applicable laws in your jurisdiction

We cannot grant immunity from third-party claims or criminal law, but
we will not initiate legal action ourselves.

---

## Security Architecture (for context)

ThreatClaw follows a **Zero Trust Agent** design with defense-in-depth:

- **Immutable agent identity** — Soul manifest compile-time verified
- **Command allowlisting** — strict validation before any remediation
- **WASM sandboxed skill execution** — deny-by-default capabilities
- **ClawVault** — encrypted credential storage at rest
- **Multi-trigger kill switch**
- **OWASP ASI Top 10 (2026)** mitigations tracked per release

### ClawShield — Remediation Security (HITL)

All remediation actions require Human-in-the-Loop approval. Five
independent protection layers:

1. **Immutable rules** — compile-time verified constraints
2. **Boot-locked configuration** — protected infrastructure list
3. **Compiled validation** — action allowlist, target validation,
   input escaping, rate limiting
4. **Cryptographic nonces** — anti-replay and anti-parameter-swap
5. **Approver verification** — identity-based authorization
   (numeric IDs, not spoofable usernames)

### Infrastructure

- PostgreSQL TLS enforced (`sslmode=require`)
- Docker secrets for credential management
- Docker socket proxy (filtered API access)
- 5 isolated Docker networks
- Inter-service authentication via bearer tokens
- Webhook HMAC authentication with constant-time comparison

---

## CVE / Dependency Hygiene

We maintain `cargo audit` compliance on all releases:

- **Zero known CVEs** in the compiled binary with default features
- **Zero critical** advisories outstanding
- Dependencies patched proactively against RUSTSEC advisories
- `npm audit` run on every dashboard release

Run `cargo audit` and `npm audit --prefix dashboard` on your own build
for current status.

---

## Third-party Audit

A third-party security audit is planned before the official `v2.0.0`
release (stable non-beta). The audit scope will include the core agent,
Docker composition, network topology, and WASM sandbox. Results will be
published here.

---

## Supported Versions

| Version | Status | Security fixes |
|---------|--------|----------------|
| `1.0.x-beta` (current) | Active | ✅ |
| `< 1.0.0-beta` | Pre-public dev history | ❌ |

We generally backport security fixes to the two most recent minor
versions once `1.0.0` is stable.

---

*If in doubt, err on the side of reporting. We would rather process one
non-issue than miss a real one.*
