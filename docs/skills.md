# Skills

ThreatClaw skills are sandboxed modules that extend the agent's capabilities. Each skill is invoked through a controlled boundary — no direct filesystem access, limited memory, declared network capabilities. See [SKILL_DEVELOPMENT_GUIDE.md](SKILL_DEVELOPMENT_GUIDE.md) for the full sandbox model.

## Skills shipped with ThreatClaw

| Skill | Purpose |
|-------|---------|
| `skill-appsec` | Code, dependency and Docker image scanning. Aggregates findings in the database. |
| `skill-cloud-posture` | AWS / Azure / GCP posture audit. 300+ CIS / NIS2 / ISO 27001 checks, agentless, read-only credentials. |
| `skill-darkweb` | Credential-leak monitoring for emails and domains. |
| `skill-email-audit` | DMARC / SPF / DKIM verification for client domains. Alerts on spoofing exposure. |
| `skill-phishing` | LLM-generated phishing templates, GoPhish orchestration, NIS2 Art.21 §2g reporting. |
| `skill-report-gen` | Executive (COMEX) and technical PDF reports in French. NIS2 / ISO 27001 templates. |
| `skill-secrets` | Detects credentials exposed in Git repositories (full history). Classifies and scores criticality. |
| `skill-secrets-audit` | Companion auditor for `skill-secrets` results. |
| `skill-shadow-ai-monitor` | Detects unauthorized AI usage (Shadow AI). Correlates SIEM alerts + graph + policy. EU AI Act / NIS2 / ISO 42001 evidence. |
| `skill-soc-monitor` | Ingests log alerts, triages with the local LLM, filters false positives, correlates across sources. |
| `skill-strelka-scanner` | Deep file analysis via Strelka — 79 scanners (ClamAV, YARA, capa, PE/ELF, archives, macros, OCR, QR codes, steganography). |
| `skill-vuln-scan` | Network and image vulnerability scanning. CVSS + EPSS scoring, real-criticality prioritization. |

The dashboard exposes the up-to-date skill catalog at **Settings → Skills**, including which ones are enabled, what they require (API keys, credentials), and their last-run status.

## Connectors

Connectors are skills that pull from — or push to — an external system
already present in the customer environment. They are what makes the
inventory rich and what lets the platform act when the operator
approves a remediation. Each connector is configured once under
**Skills → its tile**; the data starts flowing on the next cycle.

| Category | Connectors |
|----------|------------|
| Endpoint / EDR | `osquery`, `velociraptor`, `wazuh` |
| Firewall / network | `pfsense`, `fortinet`, `mikrotik`, `unifi`, `freebox` (the OPNsense skill ships as an external skill, not bundled) |
| Discovery | `nmap-discovery`, `dhcp-parser` |
| SIEM / log sources | `elastic-siem`, `graylog`, `microsoft-sentinel`, `zeek`, `suricata`, `crowdsec` |
| Identity & directory | `active-directory`, `authentik`, `keycloak`, `microsoft-graph` |
| Inventory & CMDB | `glpi` |
| DNS / filtering | `pihole` |
| Virtualisation & backup | `proxmox`, `proxmox-backup`, `veeam` |
| Edge / CDN | `cloudflare` |
| Incident response & ticketing | `dfir-iris`, `thehive`, `defectdojo` |
| Automation / SOAR | `shuffle` |
| Monitoring | `uptimerobot` |

The dashboard exposes the catalog at **Settings → Skills** with the
current configuration state, last-run timestamp, and per-connector
health. New connectors land in the catalog automatically as soon as
their skill manifest is added to the registry.

## Notification channels

Independent from the connector list, ten messaging channels are
available to deliver alerts and HITL prompts: Slack, Telegram, Discord,
WhatsApp, Signal, Email (SMTP), Mattermost, Ntfy, Gotify and Olvid.
Each channel is configured under **Setup → Channels**; see
[`configuration.md`](configuration.md#channels) for the per-channel
setup steps.

## Building your own

The supported path is the **community skill** model: a Python module running in an isolated container, communicating with the agent over a Unix socket. Read [SKILL_DEVELOPMENT_GUIDE.md](SKILL_DEVELOPMENT_GUIDE.md) for the structure, manifest, and security constraints.

Community skills are **read-only by design** — they observe and report findings; they cannot trigger remediation actions. Remediation lives in first-party connectors gated by ClawShield HITL.
