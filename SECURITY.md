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

### Alternative — Email (PGP-encrypted)

Send your report to **security@threatclaw.io**.

For sensitive details, **encrypt your email with our PGP key**:

- **Fingerprint** — `6A72 8106 4019 33B5 F772  9C64 9A23 EDB9 3FA6 F355`
- **Download** — https://threatclaw.io/.well-known/pgp-key.asc
- **Keyservers** — `keys.openpgp.org` and `keyserver.ubuntu.com`

```bash
# Import our key before sending your encrypted report
curl -sSL https://threatclaw.io/.well-known/pgp-key.asc | gpg --import
# or:
gpg --keyserver hkps://keys.openpgp.org --recv-keys 6A728106401933B5F7729C649A23EDB93FA6F355
```

Machine-readable policy at
[https://threatclaw.io/.well-known/security.txt](https://threatclaw.io/.well-known/security.txt)
(signed with the same key, RFC 9116).

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

- **Immutable agent identity** — tamper detection on the agent binary itself
- **Strict allowlist** before any remediation action reaches the network
- **Sandboxed skill execution** — deny-by-default capabilities, no host filesystem
- **ClawVault** — encrypted credential storage at rest
- **Kill switch** — automatic hard stop on integrity failure
- **OWASP ASI Top 10 (2026)** mitigations tracked per release

### ClawShield — Remediation Security (HITL)

All remediation actions are Human-in-the-Loop. ClawShield is a multi-layer
guard that sits between the agent's reasoning and any change made to a
client's infrastructure: rule-level constraints, target validation,
anti-replay protection, and identity-based approver verification.

Implementation details (which primitives, how many layers, exact ordering)
are not published here on purpose. They are documented internally and are
covered by the responsible-disclosure scope below — please report any
suspected bypass.

### Infrastructure

- Encrypted database connections by default
- Container secrets management (no plain-text credentials on disk)
- Filtered Docker API surface (no raw socket exposure)
- Network isolation between agent, dashboard, ML, database and ingest tiers
- Inter-service authentication on every call
- Webhook authentication with constant-time validation

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
