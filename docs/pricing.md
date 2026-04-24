# Pricing

ThreatClaw is open-core. **The engine and almost every skill are free
forever** under the AGPL v3 license. A small number of **premium skills
that perform automated remediation** ship under a commercial license
starting with v1.1 (expected mid-2026).

This page is the canonical, up-to-date pricing reference. If you spot a
discrepancy with blog posts or marketing material, **this page wins**.

---

## What is free forever (AGPL v3)

| | |
|---|---|
| **Core engine** | Agent, scheduler, intelligence engine, anonymizer, 5-level local LLM stack, graph (AGE + pgvector), web dashboard |
| **All ingest skills** | SIEM (Wazuh, Graylog, Elastic, Splunk-compatible), endpoint (osquery, Sysmon, Velociraptor), network (pfSense, OPNsense, Fortinet, Mikrotik, Unifi, Cloudflare, Pi-hole), identity (Active Directory, Authentik, Keycloak, M365 / Entra ID), backup (Proxmox, Veeam), DevSecOps (Checkov, Semgrep, Grype, Trivy, ZAP), ticketing (DFIR-IRIS, TheHive, Shuffle) |
| **All threat intelligence feeds** | CERT-FR, CISA KEV, EPSS, NVD, MITRE ATT&CK, PhishTank, Spamhaus, OpenPhish, GreyNoise (free tier), ... |
| **All detection content** | Sigma rulesets, correlation engine, behavioral scoring, ML anomaly detection |
| **All NIS2 / compliance reporting** | Standard report templates, evidence trail, auditability |
| **Velociraptor DFIR — Phases A + B** | Hunt ingestion + 4 read-only VQL tools exposed to the L2 forensic LLM |

"Free forever" means: no time bomb, no feature degradation, no
forced upgrade to a paid tier for code that is free today. See
[FAQ § commitment](#commitment) below.

---

## What requires a paid license (premium)

Starting **v1.1** (mid-2026), a small number of skills that **perform
automated actions on protected infrastructure** are distributed as
premium, commercial-licensed binaries through `hub.threatclaw.io`:

| Skill | Action capability | Release target |
|---|---|---|
| `skill-velociraptor-actions` | Endpoint quarantine via Velociraptor `Windows.Remediation.*` artifacts, with HITL approval flow | v1.1 |
| `skill-opnsense-actions` | Block IP, kill states, quarantine MAC, toggle rule — with savepoint + 60-second auto-revert safety net | v1.1 |
| `skill-ad-remediation` | Disable account, force password reset, remove from group (HITL) | v1.2 |
| `skill-fortinet-actions` | Block / URL category / ban IP on FortiOS with approval flow | v1.2 |
| `skill-stormshield-actions` | Equivalent on Stormshield SNS (FR national champion partner) | v1.2 |
| `skill-sophos-xgs-actions` | Equivalent on Sophos XGS | v1.3 |

The **read-only / inventory / detection** part of every listed product
stays free. What becomes paid is specifically the code that **acts** on
your infrastructure: it carries the most engineering cost, the most
operational risk, and the most direct business value.

---

## License types

| Type | Scope | Price |
|---|---|---|
| **Individual** | One premium skill, one deployment site | **€79 / year / skill** |
| **Action Pack** | All current and future premium skills, one deployment site | **€590 / year / site** |
| **MSP** | All premium skills, unlimited client deployments by the MSP | **€1 990 / year / MSP** |
| **Enterprise** | Custom scope (SLA, source escrow, dedicated support, air-gapped with hardware tokens) | quote on request |

Pricing is **annual, paid in advance**, VAT excluded (French
VAT applies for EU consumers where required).

### License properties

- **Offline verification** — Ed25519 signature check, no permanent
  internet connection required to use a premium skill
- **90-day grace period** — if the license platform is unreachable, the
  skills continue to function for 90 days past expiry so a payment
  hiccup or air-gapped site never silently bricks production
- **Site pinning (optional)** — Individual and Action Pack licenses can
  be pinned to a specific install fingerprint; MSP licenses are
  unrestricted by design
- **No telemetry bound to licensing** — the license check is local, no
  phone-home is required for a signed, non-revoked cert

---

## Early adopter program

All ThreatClaw installations performed during the **v1.0.x beta period**
(before v1.1 GA) are eligible for a **50 % lifetime discount** on all
premium licenses. The discount applies to every renewal as long as the
licensee remains in good standing.

**Concretely** :
- Action Pack: **€295 / year for life** instead of €590
- MSP License: **€995 / year for life** instead of €1 990
- Individual skill: **€39.50 / year for life** instead of €79

To claim: email `contact@cyberconsulting.fr` with your ThreatClaw
installation hash (shown in Dashboard → Settings → About) before v1.1
GA. We will issue a lifetime discount code valid for all future license
purchases from that install.

---

## What your license gets you

- **Binary updates** — new releases of the premium skills you've
  licensed, for the entire subscription period
- **Security patches** — distributed within 72 hours of a confirmed
  vulnerability
- **Detection content updates** — new Sigma rules, new MITRE ATT&CK
  mappings specific to the skill's domain
- **Community support** via GitHub Discussions and the public Discord
  (free for everyone) — **Premium Support** (SLA, ticketing, phone) is
  available as an Enterprise add-on

---

## What does NOT change

- **The core stays AGPL v3 forever.** Ever. This is the
  non-negotiable commitment ThreatClaw was founded on.
- **No feature downgrade.** Nothing that is free today will move behind
  a paywall. The paid surface only grows by adding net-new skills.
- **No mandatory SaaS.** ThreatClaw remains 100 % self-hostable. We
  don't operate a "cloud version" you're forced to migrate to.
- **No hidden telemetry.** The only telemetry is opt-in heartbeat used
  to count active installs and identify early adopters.

<a id="commitment"></a>

### Our commitment in writing

If any skill currently free in this document ever moves to premium in a
future ThreatClaw release:

1. It will be announced at least **6 months in advance**
2. Existing installations will be **grandfathered to the free tier
   forever**
3. The forks maintained by the community at that point **will remain
   legally free under AGPL v3** — we cannot and will not retroactively
   relicense published OSS code

This is our version of the ["Postgres covenant"](https://wiki.postgresql.org/wiki/Sustaining_Membership_FAQ).
We lose our community the moment we renege on it, and we know it.

---

## FAQ

**Can I keep using an old version indefinitely?**
Yes. AGPL v3 lets you run any past release forever. The core never phones
home. The caveat: you will not receive security patches for skills you
have not paid for, and the ecosystem (sigma rules, MITRE data) evolves.

**MSP / MSSP: can I resell to my customers?**
Yes, with the MSP License (€1 990 / year). Unlimited customer
deployments. We do **not** charge per-endpoint, per-tenant, or per-GB on
this tier.

**Air-gapped deployments (healthcare, defense, energy)?**
Supported. Offline verification + 90-day grace period covers 95 % of
air-gapped deployments. For deployments with stricter isolation
(hardware tokens, courier-delivered licenses), contact us for an
Enterprise quote.

**Academic / non-profit use?**
Premium skills are free for accredited academic institutions,
registered 501(c)(3) / French loi-1901 associations, and recognized
public-interest cybersecurity projects. Email us with documentation of
your status.

**GDPR / data residency?**
ThreatClaw is on-premise by design. Your data never leaves your
infrastructure unless you explicitly enable cloud LLM fallback (which is
opt-in, anonymized per 17 configurable PII categories, and fully
auditable).

**Who sees my license purchase data?**
CyberConsulting.fr + Stripe (payment processor, EU-located). No third
parties. Purchase data is not shared, sold, or used for marketing
beyond direct ThreatClaw communications (which you can opt out of).

---

## Contact

- Commercial licensing: `contact@cyberconsulting.fr`
- Technical community: [GitHub Discussions](https://github.com/CyberConsulting-fr/threatclaw/discussions)
- General: [threatclaw.io](https://threatclaw.io)
- Security issues: `security@cyberconsulting.fr` (PGP key on the website)
