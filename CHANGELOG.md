# Changelog

All notable changes to ThreatClaw are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/)

Versioning: [Semantic Versioning](https://semver.org/) starting with `v1.0.0-beta`.
Earlier `v0.x` entries below cover pre-public internal development and are kept for transparency.

## [1.0.45-beta] — 2026-06-17

### Added
- Asset inventory merge mode: tick-box selection, conflict flagging on cross-source mismatch, and a "keep separate" action for legitimate look-alike pairs.
- Four CACAO dispatchers (SSH brute force, SSH root login, sudo failure, sensitive auth file modified) and four Windows-syslog rules covering Sysmon process create, encoded PowerShell, downloader cradle and reflective loader.
- Endpoint agent installer runs a pre-flight check against the gateway before touching the host: a clearly-rejected token or an unreachable URL aborts with an actionable message instead of leaving a half-configured agent.

### Changed
- Verdict reconciler gains Rule I (downgrade `confirmed` when the investigation ran zero skill calls) and Rule J (downgrade `confirmed` when no LLM citation could be verified).
- Asset-alias resolution extended to `find_open_incident_for_asset*` and `query_logs` so dedup and the L1 log-search skill match across id / name / hostname.
- Intelligence-engine cycle interval is now a `tc_config_ie_cycle_secs` setting (60–1800 s, default 300).

### Fixed
- Sigma alerts now carry `log_id`, restoring the alert → raw log drill-down.
- Junk hostnames (kernel, dockerd, container ids, …) no longer reach the finding insert path or the ML scoring loop.
- Snoozed-then-woken incidents stuck on `pending` are finalised to `inconclusive` instead of staying in the active queue indefinitely.
- Asset-score formula soft-caps the alert term at 60 so the correlation bonuses (kill chain, known exploit, active attack) still have room to push above the noise floor.
- Auto-stub sigma rules created by the legacy alert insert path now ship as `enabled=false` and stay out of the dashboard rule list.
- Future-clamp sigma engine warning is rate-limited to once every 5 minutes.

### Operations
- One-shot schema cleanup on upgrade drops accumulated stale rows (ML scores, findings, auto-stub rules) and is a no-op on a clean stack.

## [1.0.44-beta] — 2026-06-17

### Fixed
- The intelligence engine could ship a "Behavioral anomalies" CRITICAL verdict on a dossier that carried zero linked alerts. The asset-alerts lookup compared the alert hostname only against the asset id; auto-enrolled assets whose id carries a prefix (e.g. `syslog-observed-X`) while the alerts keyed on the bare hostname returned an empty list, and the analyst LLM judged on no evidence. The lookup now resolves the input through every asset alias (id, name, hostname, lower/upper variants, IP addresses). A new reconciler rule also downgrades any "confirmed" verdict to "inconclusive MEDIUM" when the dossier carries zero sigma alerts and the machine-learning anomaly score is below 0.5.
- The investigation loop never executed any deterministic enrichment before the analyst LLM. The prompt advertised the available skills as optional, and a CPU-served local model systematically returned a verdict on the first iteration without ever requesting a skill. The loop now runs a small pre-flight skill set before the first LLM call (asset_context on the primary asset, and a reputation lookup on every distinct source IP carried by the dossier, capped at five). The results land in the prompt before iteration one.
- Three more asset-keyed lookups carried the same alias mismatch — the corroboration counter that drives the graph dispatcher's `recent_count_5m` / `recent_count_1h` variables and the sigma medium-rule promotion path, the firewall-events lookup behind the perimeter-blocked graph, and the attack-path counter consumed by the verdict reconciler. Each now resolves through the asset alias set, so auto-enrolled assets recover the deterministic signals the graphs and the reconciler need.
- Two Linux SSH rules silently stopped firing on modern installs after OpenSSH 9 split the daemon into a master `sshd` listener and a per-connection `sshd-session` child. The rules pinned `program.ident: sshd` strictly and matched nothing. `lnx-auth-001` and `lnx-auth-002` now accept both idents. `lnx-auth-001` also drops the lone `preauth` token from its failure signals — `[preauth]` is a phase marker OpenSSH attaches to routine messages including the `Postponed publickey for ...` line emitted on every successful key login — and keeps only the explicit refusal trailers. `lnx-auth-002` similarly drops the bare substring `for root from`, which fired on routine `Postponed publickey for root from ...` and `Accepted publickey for root from ...` messages.
- The user-crontab persistence rule (`lnx-persist-001`) did not detect `crontab -e` on Debian or Ubuntu hosts. Its case-sensitive program list pinned `crond`, `cron`, `CROND` but not `CRON` — the all-caps form Debian-family cron daemons log under. The list now accepts `CRON` too; the strict `") REPLACE ("` message anchor is unchanged.
- Every auto-enrolment path now passes through a single chokepoint that classifies the incoming evidence by MAC, then hostname, then IP address before deciding whether to merge into an existing asset or create a new one. The three sources that previously built their own asset record and called `upsert_asset` directly — the osquery webhook, the syslog observe-and-enrol pass, and the threat graph's unknown-internal-device branch — converge on a single asset record per machine even when the first sync arrives a few hundred milliseconds before the second.
- The agent installer's rsyslog warning surfaced `https:514` instead of the operator's actual ThreatClaw host because the variable expansion chopped the URL at the first colon. The host is now extracted with the same sed pipeline the rsyslog-installed branch uses. The installer also no longer prints a misleading `Installing osquery X.Y.Z` line: the script does not pin the package version, so the log now reads `Installing osquery (latest from pkg.osquery.io, X.Y.Z or newer)`.

### Operations
- No new schema migration in v1.0.44. The asset chokepoint converges on the existing record set without rewriting it. The rule rewrites take effect on the next sigma cycle once the core image is replaced; rules that were operator-disabled stay disabled and must be re-enabled explicitly on the inventory page.

## [1.0.43-beta] — 2026-06-17

### Fixed
- A Windows host that runs the osquery agent could land twice on the inventory page on the very first sync, surfacing as two rows with the same hostname but different ids (e.g. `osquery-observed-W10-1` plus `w10-1`). Two enrolment paths race on the first sync: the observe-and-enrol pass writes directly to the assets table, and the asset-resolution pipeline that runs a few hundred milliseconds later was consulting only the graph store, missed the row, and minted a fresh id via `generate_asset_id`. The asset-resolution pipeline now consults the PostgreSQL assets table first and reuses the existing id; only the legacy graph lookup remains as a fallback for datasets that have a graph node without a matching PostgreSQL row. A one-shot rewrite on upgrade also merges existing duplicates: only pairs where at least one row carries the `observed` tag are touched, the oldest row in each group becomes canonical, every cross-table reference is redirected onto it, and field-level facts from the alias are smart-merged into the canonical row before it is removed.

## [1.0.42-beta] — 2026-06-16

### Fixed
- The four operator-decision endpoints introduced in v1.0.38-beta (Resolve, False Positive, Accept Risk, Snooze) plus the admin Delete returned "not authenticated" on every click. The dashboard proxy attaches its own Bearer token to authenticate itself to the gateway but was not forwarding the user's session cookie, so the handler that resolves the cookie against the dashboard auth table found nothing and rejected the request. The proxy now forwards the cookie on every non-agent route; agent ingress paths still authenticate by webhook token only and remain cookie-free.
- The intelligence cycle no longer recreates an incident every five minutes when a recurring signal hits a pattern the operator has already triaged out. Previously the dedup query only matched open and investigating incidents; a resolved or snoozed incident on the same asset+pattern within the 4h window was invisible to the dedup, so a flapping rule could mint a fresh incident every cycle. The cycle now performs a rate-limit lookup against resolved and snoozed incidents in the same window, and skips creation when one is present.
- Seven Linux detection rules whose previous body used bare contains tokens (matching anywhere in the log body) have been rewritten with the strict program-and-signal pattern that v1.0.37 introduced for the first four. Each rule ships a regression fixture asserting the canonical attack shape and the canonical noise shape it must not match, so the test runner catches a future drift back to the bare-token form:
    - `lnx-persist-001` (Cron Job Added) — was matching every routine cron session message; now requires crond + the parenthesised "(USER) REPLACE (FILE)" trailer.
    - `lnx-auth-001` (SSH Password Brute Force) — was matching every routine SSH session message; now requires sshd + an explicit failure trailer.
    - `lnx-auth-002` (SSH Root Login Attempt) — was matching every routine SSH session message; now requires sshd + a root-targeting trailer.
    - `lnx-fim-001` (Sensitive Auth File Modified) — was matching every read of /etc/passwd or /etc/shadow; now scoped to the account-management binaries that legitimately write these files.
    - `lnx-acct-001` (Local User Created) — was matching man pages and package install logs mentioning the binary name; now scoped to ident=useradd / adduser / groupadd.
    - `lnx-auth-004` (Sudo — Not in Sudoers) — was matching any program that quoted the phrase; now scoped to ident=sudo with the explicit refusal trailer.
    - `lnx-exec-001` (Remote Payload Piped To Shell) — was matching every log line mentioning curl or wget; now requires the download token AND a shell-pipe token together, each anchored on whitespace.
- Three host-firewall and policy rules (`lnx-evasion-001`, `lnx-evasion-002`, `lnx-evasion-003`) gained a prose filter so a config note or tutorial that quotes the destructive command does not fire the rule. The command tokens themselves are now anchored on leading whitespace.
- The dashboard `/incidents` list defaulted to status='open' confirmed incidents only (correct for the operator queue). A "Show resolved" toggle now exposes the resolved confirmed rows on demand so the analyst can review recent triage without leaving the page.

### Operations
- On upgrade the migration sweep is a no-op for V81–V84 because they already ran in v1.0.41. The rule rewrites take effect at the next sigma cycle once the core image is replaced; rules that were operator-disabled during the v1.0.41 hardening window stay disabled and must be re-enabled explicitly on the inventory page if the operator wants the new shape live.

## [1.0.41-beta] — 2026-06-16

### Fixed
- Linux endpoints reported by both fluent-bit syslog forwarding and the osquery agent could land twice in the inventory when one path emitted the FQDN (for example `web-01.internal`) and the other the short hostname (`web-01`). The asset lookup now matches across both shapes, preferring exact-hostname match first and falling back to the short-hostname segment, so the two enrolment paths converge on a single asset row. A one-shot rewrite on upgrade also merges the existing duplicate rows: only auto-enrolled assets (carrying the `observed` tag) are touched, the oldest row in each group becomes canonical, and every cross-table reference (findings, incidents, graph executions, ml scores, scan queue, sentinel entities, merge aliases) is redirected onto it before the redundant row is removed. Operator-curated assets are left untouched.

## [1.0.40-beta] — 2026-06-16

### Fixed
- External endpoint agents (osquery on Windows and Linux) could not reach the gateway over the public address. The dashboard proxy fronting the core API required a dashboard session cookie before forwarding any request, including the four agent ingress paths that already authenticate themselves with a per-source webhook token. Every external agent sync failed with HTTP 401 even when the operator had correctly configured the webhook token. The proxy now skips the session check for the agent ingress paths and forwards the agent's webhook token to the core, which validates it constant-time against the per-source value in settings. Internal collectors that already reached the core over the docker network were unaffected.
- The forensic enrichment layer no longer narrates around alerts the engine itself has disowned. When an incident referenced a sigma alert that had since been reclassified as false positive or migrated by the cleanup pass on upgrade, the deep-narrative model was still pulling that alert into its evidence list and producing a kill-chain narrative around an attack that never happened. The enrichment now filters reclassified alerts out before the prompt is built; the narrative reflects only the alerts the engine still stands behind.
- The incident list page filtered against the legacy closed state and silently broke when the canonical closed state was renamed in v1.0.38-beta. Historical resolved-confirmed incidents started leaking back into the live operator queue. The filter now pins on the open state, and resolved / archived / closed rows surface only on the archives page.
- The per-incident detail page was still rendering the legacy three-button strip (Mark FP / Archive / Ignore Pattern). The new operator decision menu introduced in v1.0.38-beta is now wired on the detail page in an inline layout so each action (Resolve / False Positive / Accept Risk / Snooze + admin-only Delete) is a full-width button stacked vertically. Relaunch Investigation and Ignore Pattern remain as secondary actions below.

### Changed
- The one-shot cleanup that reclassifies the historical alerts and incidents produced by the pre-v1.0.37 detection engine now records the disposition as "migrated" instead of "false positive". Some of those rows correspond to legitimate evaluation activity that the previous rule mis-titled — calling them false positives mislabels real events. The new disposition carries the honest semantic: superseded by a rewritten rule, re-evaluated by the new rule on the next sigma cycle, and a fresh incident raised if the underlying activity is real. A safety-net rewrite also re-labels rows that already received the previous disposition on operators upgrading from v1.0.37-beta or v1.0.38-beta.
- The dashboard archives view recognises the new migrated verdict, surfaces a filter chip for it, and renders it in a neutral colour so the row does not present as either a positive or a negative finding. The critical-incident pill in the top bar now also treats resolved and archived incidents as closed instead of counting them as open, fixing a regression introduced when the canonical closed state was renamed in v1.0.38-beta.

## [1.0.38-beta] — 2026-06-15

### Changed
- The operator decision menu on an incident is rewritten around four explicit actions plus an admin-only Delete. The previous three buttons (Archive, False Positive, Ignore) were near-synonyms that all came down to "hide it from my view", and the downstream tuning loop drew the wrong conclusion every time. The new menu separates the intentions cleanly: **Resolve** ("I handled this — real incident, now closed"), **False Positive** ("the detection was wrong" — with an optional follow-up that creates a sigma exception scoped to the asset, the target user, or the source IP), **Accept Risk** ("real, but the business chose to accept it"), and **Snooze** ("remind me in N hours"). The admin-only **Delete** entry hard-deletes a row with an audit-log entry — useful for test data or accidental incidents, not part of the normal triage flow. Each pick opens a small modal, no decision is taken in a single click except Resolve.
- The intelligence cycle wakes up snoozed incidents automatically. When a snooze deadline passes, the incident returns to the active queue with a note explaining the wake-up — no operator action required.

### Operations
- Existing historical incidents that were closed with `status='closed'` are now stored as `status='resolved'`. The two terms had been used interchangeably and the dashboard filter now uses a single canonical state.

## [1.0.37-beta] — 2026-06-15

### Fixed
- Incident titles for sigma-driven detections no longer append the static CVE exposure count of the asset. The previous title shape (`Golden Ticket on srv-01 — 5 exploitable KEV CVE(s)`) suggested to the operator that the attack had leveraged those CVEs, when in practice the CVE exposure was an unrelated static-scan finding on the same host. Titles now stick to the actual detection pattern; CVE exposure remains visible in the dossier summary and finding list.
- The 5-minute incident deduplication window is now pattern-aware. Previously the cycle merged every new detection on the same host into the first open incident, even when the new detection described a completely different attack. After this change, a new attack pattern on a host that already has an open incident creates its own incident with the right title and timeline. The earlier behaviour silently absorbed a post-compromise privilege escalation into the morning's brute-force incident on the same host, and only the dashboard's hidden pattern field reflected the change.
- The detection engine now produces a separate alert when the same rule fires on a different target. The previous implementation deduplicated only on rule and host for the full one-hour suppression window, so a Golden Ticket against `alice` followed by another against `bobby` collapsed into the first alert and the second one was never surfaced. The dedup key now folds in target user, source / destination address and a hash of the matched fields, so semantically distinct events surface independently while repeat hits of the exact same payload still dedupe naturally.
- The detection cycle now caps any persisted log timestamp at wall-clock at the database boundary. Some syslog producers ship a timestamp adjusted to a local timezone that the ingestion path then re-tags as UTC, so each row landed an hour or two ahead of wall-clock. The cycle's forward cursor uses that timestamp to advance — a single future row froze every subsequent read between then and the bogus timestamp. The clamp catches every producer regardless of the path used and notes the upstream timezone bug for separate investigation.
- The per-tag fair-share quota on the cycle's read path no longer caps coverage at scale. With the previous quota, a syslog spike of ~10 000 events per 5-minute cycle saturated the per-tag share and left the tail of the backlog — the part that carried the actual attack signal — unevaluated for hours while the cycle chewed through the spike's front. The batch size and per-tag share were both raised so a single source can take most of the batch when needed while still reserving capacity for the others, and the cycle now drains a six-times-larger spike per tick.
- The deep narrative validator no longer rejects a response whose MITRE technique entries are listed by bare ID when the attested entries are stored with the full label. Both sides are normalized to the technique ID before comparison so `T1110.001` matches `T1110.001 Password Brute Force` without a rejection.
- Three customer-facing truncation paths (incident investigator description, Telegram report send-out, Telegram chat reply) are codepoint-bounded so a multi-byte UTF-8 character at the cut boundary cannot panic the 5-minute cycle. The earlier byte-slice cut crashed the cycle on the first finding whose description ended on an accent — every subsequent cycle silently refused to fire until the process was restarted.

### Changed
- Four detection rules were rewritten so they detect their intended attack instead of pattern-matching unrelated content: Account Promoted To Root, Sudo Authentication Failure, Remote Desktop Lateral Movement, and Golden Ticket — RC4 TGT. Each ships with regression test fixtures that assert both the canonical attack and the canonical false-positive shape it must not match.

## [1.0.36-beta] — 2026-06-15

### Fixed
- The detection engine no longer falls back to scanning the entire serialized event whenever a rule references a field that is not present at the explicit path. A rule looking for a substring inside a command line now matches only against the command-line field; if the event does not carry a command line, the rule does not fire. Previous builds silently scanned every value in the JSON body when the explicit field was missing, which let a rule targeting `commandline` match on a port number stored in a completely unrelated field elsewhere in the event. The behaviour was the root cause of a recurring false-positive incident pattern, where a critical-severity alert was raised on benign authentication failures because a substring that legitimately appears inside the standard authentication trailer was being treated as a hit on a different field's content. The whole-event fallback is preserved only for the symbolic body aliases legacy syslog rules use as a stand-in for the raw log line, so existing rules that genuinely meant "anywhere in the log body" continue to work.
- The intelligence cycle no longer rebuilds incidents around alerts the analyst has already triaged out as false positive or resolved. The 5-minute cycle previously re-picked closed alerts from history and replayed them through the deterministic incident graph, producing a fresh incident under the same pattern key with the closed alert references back in the alert list. The query that feeds each cycle now excludes alerts in the false-positive and resolved states. Triaged-out alerts stay in the table for audit; they are just not eligible to re-trigger an incident.
- The detection engine now reads new logs through a forward-paged cursor instead of always taking the most recent N rows. At very high ingestion rates the fixed-window read silently overlooked the logs that arrived between two ticks because each cycle restarted from "the most recent N" again. The cursor resumes from the last log processed on the previous cycle and advances strictly forward, so the per-cycle batch size only governs throughput per tick, not coverage. A safety floor caps how far the cursor can drag the read after an outage so a stale cursor cannot trigger a multi-hour rescan; the per-tag fair-share quota that protects against a single high-volume source eating the whole batch is preserved.
- The "Account Promoted To Root", "Sudo Authentication Failure", "Remote Desktop Lateral Movement" and "Golden Ticket — Kerberos TGT" rules are rewritten against the actual event shape they intended to detect. The previous selections were too coarse and produced critical-severity false positives on benign authentication and process activity. Each rule now ships with regression test cases modeled on the canonical false-positive shape, so any future change that would re-introduce the noise is caught in continuous integration.

### Added
- The detection engine now honours the full Sigma 2.0 value modifier set. Rules can use regular expressions, case-sensitive matching, network range comparisons, field-presence checks, numeric comparators, Windows command-line dash-variant expansion, Base64 / Base64-offset / UTF-16 value encoding, and cross-field references. Each of these was previously silently dropped at rule compile time or rejected upstream by the converter; the converter has been updated to let these rules pass through. The operator-facing Sigma rules guide lists every modifier with semantics and an example.
- The upstream SigmaHQ rule converter at `tools/sigma_convert.py` now accepts the value modifiers listed above instead of rejecting them as unsupported. The CLI banner reflects the new scope and the import report is interpretable across older imports because the previous rejection reasons are still documented in the converter notes.

### Changed
- The nginx body cap raised from 10 MB to 20 MB so full data-centre and VDI host snapshots reach the osquery endpoint without being cut at the edge. The corresponding internal comment that still referenced the 10 MB cap is brought in line.

### Operations
- The rate limiter for incoming agent telemetry now buckets per-host instead of per-source-type, with a per-source-type backstop to prevent fleet-wide bursts. Without this change the upstream cap was shared across the entire fleet, which at scale silently dropped the bulk of the telemetry. Independent rate-limit tests cover the per-host bucket, the backstop and an anti-spoofing path that prevents an attacker-controlled hostname from minting unlimited buckets.
- The 5-minute intelligence cycle now runs in its own task with a heartbeat. A panic inside the cycle surfaces as a recoverable error and the ticker keeps running on the next interval instead of silently wedging the agent. The lateral-movement detection that previously only emitted a log line now creates a real finding the dashboard can surface and triage like every other finding.
- The ML scoring loop now batches its database writes in a single round-trip per cycle instead of opening one connection per scored asset. At fleet scale this removes a 10,000-connection burst from the database every cycle.
- Session tokens are now sampled from the operating-system cryptographic source instead of the standard random API. The dashboard cross-route handler now requires authentication and rejects requests targeting non-public addresses, closing a server-side-request-forgery path. The SSH executor pins host fingerprints on first connection so a man-in-the-middle on the management network is detected, and the graph note identifier is validated before use to close a malformed-input path.
- The installer now pins its container image references by digest and verifies the installer script checksum against the published value before running it, so an attacker who compromises the distribution endpoint cannot substitute a malicious binary without the operator noticing.

## [1.0.35-beta] — 2026-06-15

### Added
- Confirmation modal before rotating the agent webhook token on **Setup > Endpoints**. The single-click "Regenerate" path previously invalidated every previously-installed endpoint agent the moment it was clicked, and a customer hit this case on a casual visit to the page to look up the current token. The modal now spells out that the rotation invalidates every machine already installed with the previous token, that the operator must push the new token onto each machine or reinstall the agent, and that the token is durable across ThreatClaw updates so rotation is only necessary on suspected compromise. The first-install "Generate" path stays one-click since there is nothing to invalidate yet.

### Changed
- Incident card titles, IE timeline step labels, and the asset coverage panel now render in English by default for fresh installs. The L1 ReAct prompts also default to English so the AI narrative on a fresh deployment is consistent end-to-end without further configuration. French installs that explicitly persisted the dashboard language setting keep their behaviour; only the default for fresh installs changes.
- Installer warning when listing the bundled investigation graphs from upstream rewritten to make clear that the install will use the graphs already bundled inside the core container when the upstream listing fails — the original wording suggested a broken install when in fact nothing was wrong.

### Docs
- New "Webhook token lifecycle" section in the operator handbook explains that the token is durable across updates and restarts, and only changes on an explicit click. Also lists the recovery path — copy the new token from the dashboard, edit the per-agent token file or reinstall the agent with the install one-liner — so an operator can self-recover after an accidental rotation.

## [1.0.34-beta] — 2026-06-15

### Fixed
- The production container image now ships the on-disk Sigma rule catalog. Previous v1.0.32 and v1.0.33 builds were packaged with the rules directory missing from the runtime layer, so the engine only compiled whatever was already persisted in the database from a prior install — a fresh install therefore loaded a 74-rule legacy catalog instead of the 1095-rule pack that has shipped since v1.0.32. After updating, the engine count climbs to the full 1095 rules on the next boot.
- The container start-up no longer prints a noisy permission warning when the shared volume between the core and dashboard is read-only on first creation. The script now probes writability up front and silently falls back to the configured auth token already provided through the environment file — the dashboard supports the fallback path, so nothing functional changes.

### Added
- The deep AI analysis section of an incident now responds in a configurable language so the narrative reads in the operator's working language without changing the underlying engine's reasoning quality. Default is English. Configure it from the dashboard configuration page, or by setting the report language variable in the environment file. The structural part of the analysis stays English because the local AI engine is most reliably grounded in English; only the customer-visible narrative honors the configured language. The dashboard UI language remains independent (set in **Config > General > Language**).
- New `docs/operator-handbook.md`, `docs/sigma-rules.md`, `docs/hitl-workflow.md` and `docs/hunt.md`. The handbook is the page to bookmark once an install is up — it covers the three-layer detection model (engine log vs incidents vs Attack Timeline), the 5-minute Intelligence Engine cadence, and a tour of every dashboard panel. The Sigma guide walks through the 1095-rule catalog, the promotion ladder (`monitor` / `detect` / `block`), exceptions, the field map per ingestion source, and the upstream SigmaHQ importer at `tools/sigma_convert.py`. The HITL guide covers the proposed-action panel, the cross-channel approval surfaces, the safety guard, and the pre-flight checklist before turning on Responder mode. The Hunt guide documents the log lake page with three worked examples and the REST equivalent.

### Changed
- The L2 forensic prompt was rewritten in English (the prompt itself is never customer-visible). Every previously-hardcoded French string in `forensic_enricher.rs` — timeline step labels, action descriptions, the deterministic fallback narrative — is now English canonical so the dashboard reads consistently end-to-end without depending on the LLM language. The remaining server-emitted French strings in `intelligence_engine.rs` step labels and the API handler error responses are scheduled for the next release.

## [1.0.33-beta] — 2026-06-15

### Fixed
- Windows endpoints running the osquery agent now appear in the dashboard inventory on first sync. The osquery webhook handler previously only updated the internal agent registration table and the software inventory when an asset row already existed; it never created the asset itself. Linux happened to work because the rsyslog forwarder shipped by the same installer pushes syslog events through a separate path that auto-enrolls new hostnames as observed assets. Windows has no syslog companion, so the asset was never created and the agent remained invisible despite syncing every five minutes. The webhook now mirrors the syslog enrolment shape and emits an asset row on the first sync, with an OS hint carried through to the dashboard so the right icon and inventory filter apply. Existing agents are picked up retroactively — no agent reinstall is required.
- The local AI forensic model download is now retried up to three times with backoff when the underlying base pull from Hugging Face fails, the model inventory is refreshed between the pull and the alias-create steps so the create step sees the freshly pulled base, and every failure now logs the HTTP status code and the response body returned by Ollama instead of being silenced. The previous behaviour silently moved on when the long Q8_0 download was interrupted by a transient network error, the subsequent alias create then 404'd against a missing base, the `threatclaw-forensic` alias never registered, and every L2 forensic enrichment retried indefinitely against the missing model — producing the sustained CPU and memory load reported on a fresh install whose hf.co connection timed out during the initial pull.

## [1.0.32-beta] — 2026-06-15

### Added
- A SigmaHQ-to-ThreatClaw rule converter (`tools/sigma_convert.py`) ingests upstream Sigma rule files and emits ThreatClaw-shaped detection YAML aligned to the local ingestion model. The converter remaps the upstream `logsource` to the receiving log channel, rewrites field names per source (Sysmon nested paths, PowerShell script-block fields, flat syslog, firewall top-level keys), and rejects rules that depend on engine features ThreatClaw does not implement yet (regex, CIDR, base64 offsets, cross-field references, count aggregations, parenthesized condition groupings). On the upstream catalog of 3133 rules, 2857 (91.2 %) convert cleanly.
- Bulk import of 984 upstream Sigma rules, filtered to severity `critical` or `high`, across four packs: Windows process creation (563), Windows PowerShell script-block (62), Sysmon multi-channel covering registry / file / network connection / image load / DNS / named pipe / remote thread / driver load (326), and Linux syslog covering sshd / cron / FIM / nft (33). Imports land in the `monitor` disposition by default so they surface as informational signal without auto-creating findings until each rule is reviewed.
- Sigma detection language: the native engine now understands the SigmaHQ quantifiers `1 of <pattern>` and `all of <pattern>`, including `1 of them` / `all of them` and prefix / suffix glob patterns over selection names. The engine also recognizes the `|all` chain modifier on field keys, so `CommandLine|contains|all: [...]` requires every value to be present rather than any. These two additions unlock roughly seven hundred upstream rules that previously compiled but would never have matched.

### Changed
- The native Sigma scan now applies a per-tag quota when reading the recent log batch. Previously a flat `ORDER BY time DESC LIMIT N` was issued, and on any deployment where one channel dominates by volume (syslog at one hundred thousand events per day on a typical install) the entire batch was taken from that channel and every other source was invisible to the matcher. The new query uses a window function with `PARTITION BY tag` so each ingestion channel keeps a fair slice; high-volume sources can no longer starve low-volume ones.
- Seventy first-party Sigma rules were realigned so their `logsource` filter matches an actually-active ingestion tag. Authoring used the upstream SigmaHQ category names (`process`, `process_creation`, `alert`, `firewall`, `ps_script`) which never matched the receiving tag taxonomy and silently dropped every event before the matcher was even consulted. Affected rule families: PowerShell obfuscation, Sysmon detection pack, Windows authentication, advanced threat actor TTPs, OPNsense / Fortinet firewall, Proxmox audit.

### Fixed
- The Sigma matcher's logsource filter is no longer bypassed by rules whose category contained common substrings of the log tag. The realigned categories (`osquery`, `syslog`, `opnsense`, `fortinet`, `proxmox`, `zeek`) match the substring contract the engine actually enforces.

## [1.0.31-beta] — 2026-06-14

### Added
- A Hunt panel dedicated page in the dashboard exposes the full log lake for free-text investigation. Filters cover hostname, source tag, time range (15 min to 30 d, plus a custom window) and a substring search across the JSON payload. Results paginate with a stable cursor on `(time, id)` and report how many TimescaleDB chunks the query scanned so the operator can tell when a range is too wide.
- The hostname filter is a combobox seeded from the inventory, so the operator picks from the assets actually being monitored, with the option to type a free-text value for hosts not yet enrolled.
- Saved hunt queries: a named preset is one click away from a populated filter set, and recalled later from the sidebar chips.
- A Hunt panel button on the incident detail page opens the log lake pre-filtered to the asset hostname and a ±10 min window around the attack events, so a pivot from "what did the AI surface" to "what was actually in the logs" is a single click instead of three.

### Changed
- Logs API: `GET /api/tc/logs/search` is the canonical entry point for the Hunt panel and any external SIEM pivot tool. Filters are exposed verbatim and pagination is keyset-based.

### Fixed
- The asset detail page no longer freezes on hosts with large software inventories. The deduplication on the software array compared whole JSON objects byte-for-byte, but osquery re-sends every package with metadata that varies between scans (install path, last_seen, source token), so duplicates were never collapsed and a single Debian host had accumulated 165k entries for roughly 461 real packages — a 19.5 MB payload that breached the dashboard fetch timeout. Software is now deduplicated on `(name, version)`. On the worst observed host the payload drops from 19.5 MB to 128 KB.
- A single CVE that affects several sub-packages of the same product family — Visual C++ Redistributable shipped as five runtime variants is the canonical case — is now reported once per asset instead of once per matching sub-package. The previous behavior repeated the same CVE several times in the asset findings list and inflated the visible "critical" count for what is in reality a single patch to apply.

### Removed
- The Phase G readiness page is no longer linked from the Investigation menu. It was a migration counter for the Phase G HITL refoundation and serves no operational purpose now that the refoundation has shipped. The page itself remains on disk and can be re-linked later if a similar rollout is run again.

### Dependencies
- Apply safe patch bumps across the workspace: `tokio` 1.52.1 → 1.52.3, `rustls` 0.23.39 → 0.23.40, `cron` 0.13 → 0.16, `criterion` 0.5 → 0.8 (dev). Dashboard: `cytoscape` 3.33.1 → 3.33.3, `postcss` 8.4.33 → 8.5.14, `@types/node` 25.5.0 → 25.7.0 (dev).

## [1.0.30-beta] — 2026-06-13

### Added
- A deterministic baseline per detection rule now guarantees that every incident card carries the canonical MITRE technique and at least one concrete remediation action, even when the local AI enrichment cannot complete in time. The deeper LLM analysis still wins when it produces a complete answer; the baseline only fills fields that would otherwise be empty.
- Windows endpoint detections now route to dedicated investigation workflows: brute force, account management, audit log tampering, offensive tool execution, and credential dumping. Each workflow runs an enrichment path appropriate to the platform instead of falling back to a generic SSH-themed investigation that primed the AI with the wrong context.

### Changed
- Incident titles are derived strictly from the actual rule identifier and platform context. A Windows brute force will never again be labelled as an SSH brute force just because the alert text contains the word "brute".
- The AI analysis is rejected when it cites entities (CVE identifiers, public IPs, port scans) that are absent from the incident dossier. The fabricated narrative is replaced with a deterministic note pointing the analyst to the underlying alerts and findings.
- The Windows agent deduplicates the same brute-force burst across consecutive sync cycles, so a single attack run produces a single alert and a single incident card instead of a duplicated chain.
- The investigation cooldown now records failed runs as well as successful ones, which stops the runaway re-investigation loop observed when the local AI tier consistently times out.
- The incident dossier passed to the AI enrichment now lists the actual alert and finding titles with source IPs and target users, instead of only a count summary. Without explicit grounding the AI was prone to fill the gap with plausible-sounding attack stories.

## [1.0.29-beta] — 2026-06-12

### Added
- The Windows agent now detects credential brute force, account creation and deletion, privileged group membership changes, audit log clearing, and offensive PowerShell patterns. PowerShell detection requires Script Block Logging to be enabled on the endpoint; the agent guides surface the registry one-liner that turns it on.
- The Windows agent installer now bundles Sysmon with the SwiftOnSecurity baseline. The agent picks up the Sysmon channel automatically and surfaces direct alerts on LSASS access and on known offensive tool patterns (credential extraction, AD reconnaissance, living-off-the-land binaries).
- The Linux agent installer now also drops an rsyslog forwarder and auditd rules in the same run. One command sets up the agent, the log forwarder, and file integrity monitoring on credential files and the SSH daemon configuration. Without an explicit forwarding template, journald-sourced messages drop the hostname and the SOC console attributes them to the process name instead of the real host; the bundled rsyslog config uses a template that anchors the hostname explicitly.
- A server-driven agent manifest endpoint lets new osquery queries roll out from the server. Endpoints fetch the manifest each cycle and pick up new detection sources without a fleet redeploy.
- The installer scripts are now self-served by the core at `/api/tc/agent/install.sh` and `/api/tc/agent/install.ps1`. The `curl | bash` one-liner works against any deployed instance without depending on the public installer CDN.

### Changed
- Dashboard Config > Sources de logs guides are aligned with the new agent path. The agent install commands are surfaced first, the rsyslog template that avoids the hostname attribution bug is documented inline, and the connector sources (Wazuh, Pi-hole, Active Directory, Microsoft Sentinel) are clearly pointed to the Skills panel rather than mixed with the syslog push sources.

## [1.0.28-beta] — 2026-06-11

### Added
- Syslog source hostnames are now auto-enrolled as assets the first time they appear in a recent log batch, source `syslog`, category `endpoint`. Without this hook a customer forwarding raw syslog from thousands of hosts saw zero asset rows even though the SOC console clearly showed live traffic; triage and the dashboard inventory were unusable for the syslog-only deployment path. A heuristic filter drops common syslog program names (kernel, systemd, dockerd, containerd, rsyslogd, sshd, cron, etc.) and Docker container ids that would otherwise leak into the asset table when the syslog header omits the hostname field.
- The agent installer now declares `python3` as an install dependency on Debian and RHEL. Minimal images and containers do not ship it by default and the sync script crashed silently on the very first run without it.

### Changed
- Syslog source attribution is now correctly preserved across the ingestion path. The previous behavior surfaced the log collector identifier instead of the originating host, which made every monitored device appear under the same name in the SOC console, alerts, findings and the asset inventory. The fix is mirrored in the container entrypoint so a restart no longer overrides the database-side update.
- The fluent-bit TCP syslog listener now uses the RFC3164 parser instead of strict RFC5424. Stock rsyslog, syslog-ng and journald emit RFC3164 by default; clients shipping via TCP with the default format were silently dropped before the parser switch.
- Sigma matchers that fall through to scanning the full log body now record the substring that actually matched, not the placeholder marker `(found in log body)`. Downstream remediation code that extracts source ips and usernames from `matched_fields` now keeps a usable handle on the offending token.
- The agent sync script assembles the osquery payload via temp files rather than environment variables and command-line arguments. Hosts with thousands of installed packages previously hit ARG_MAX and broke the sync after the inventory grew past a few hundred entries.
- The installer auto-installs the Docker Compose plugin when it is missing on the host, avoiding a manual prerequisite step on minimal server images.
- The dashboard SOC console, configuration pages, asset pages, incident timeline, intelligence and findings views, skills and scans pages, network, license, alerts, users, archives and setup wizard are now fully translated to English through the i18n system. Previously remaining French strings have been migrated to the same translation table.

## [1.0.27-beta] — 2026-06-11

### Added
- Microsoft Sentinel connector skill (`skill-microsoft-sentinel`) ingesting Sentinel incidents, related alerts, entities, and analytic rule context at one-minute cadence. Defender alerts already ingested via the Microsoft 365 connector are automatically deduplicated. Sentinel-extracted entities (Account, Host) hydrate the canonical asset record via the existing resolver. Optional comment write back to Sentinel after L2 forensic produces a verdict (requires the Sentinel Responder role; graceful fallback to read-only when only Reader is granted).
- Shared Microsoft OAuth layer (`microsoft_auth`) extracted from the Microsoft 365 connector. Both skills now share token cache, certificate-based client assertion (PS256), and HTTP retry policy across different scopes (Graph and Azure Resource Manager).

### Changed
- The Microsoft 365 connector is refactored to consume the shared OAuth layer. No behavior change.

## [1.0.26-beta] — 2026-06-02

### Added
- Asset detail page in the dashboard at `/assets/[assetId]` rendering the canonical asset record (name, hostname, normalized IPs) alongside a per-skill coverage grid (IDS, EDR, vulnerability scanner, IAM, etc.). Each gap surfaces an operator-facing action hint that adapts to which skills are actually connected, so a missing capability is presented as a concrete next step instead of a blank cell.
- API endpoint `GET /api/assets/{id}/full` and the `compute_asset_coverage` helper that exposes the hydrated asset view consumed by the new page: per-skill coverage state (covered / partial / gap / not_configured), short human-readable detail, last-seen timestamp where relevant, and the recommended action when the state is below covered.
- Asset enrolment skill (`skill_asset_enrolment`) which automatically enrols a freshly observed host into the asset inventory when the dedicated skill is configured, cutting the manual onboarding step previously required for new endpoints.
- Asset hydration on incidents: incident endpoints now expose the linked asset's name, hostname and IP list alongside the canonical id, and the attack timeline carries that asset context next to every event so the operator no longer has to look up raw identifiers.

### Changed
- IP addresses stored on assets are now normalized at write time: port stripping, IPv4-in-IPv6 collapsing, lowercasing, and dedup. The same host known by different representations no longer surfaces as multiple assets, and asset resolution and forensic enrichment rely on the normalized form.
- Container entrypoint applies the new migration on startup; existing rows are rewritten in place so the dedup effect is visible immediately after the upgrade.

## [1.0.25-beta] — 2026-05-06

### Added
- Canonical schema for human-in-the-loop response actions exposed on incidents (`kind`, `cmd_id`, `description`, `params`, `rationale`, `requires_hitl`, `skill_id`, `origin`). The dashboard, the forensic analyst service and the playbook workers now share the same shape — incidents persisted by older code paths are coerced into the canonical shape on read.
- Multi-action HITL panel: when an incident with an external source IP is confirmed, the operator now sees a panel of proposed actions adapted to the connected skills (firewall block, EDR isolation / process kill / artifact collection, IAM disable user / reset password / Kerberos rotation). When the relevant skill is not connected, the action is downgraded to a manual recommendation so the operator still has guidance instead of an empty list.
- Per-action HITL approval: the operator can now approve or reject one specific action of the panel without committing the whole incident, while keeping the global "Approve all" shortcut.
- Live IP reputation lookups: the incident dossier now actually queries the configured threat-intel sources at incident creation time (community community-tier services, with optional API keys read from skill configuration), with response time and result status logged.
- Investigation timeline: every agent action on an incident — skill call, model call, playbook step, deterministic action derivation, incident open, remediation, operator note — is captured as an append-only audit trail. The dashboard renders it as a collapsible accordion below the attack timeline so the operator can audit what the agent actually did, when, and with what payload.
- Asset hydration on the API edge: incident endpoints expose `asset_name`, `asset_hostname` and `asset_ips` alongside the canonical asset id so the dashboard can render "debian (10.77.0.136)" everywhere instead of the raw identifier.
- Predictive vulnerability findings are now filtered out of an incident driven by a live detection rule. Static CVE inventories belong on the asset's posture page, not in the chronology of an SSH brute force. The vulnerability section on the incident page now reads "Vulnerabilities tied to this attack" and links to the asset page when no CVE is directly tied to the observed attack.

### Changed
- `docker-compose.yml` memory limits revised: core service raised to 2 GB (was 512 MB, hitting cgroup OOM under steady load) and database service raised to 1 GB. Core healthcheck loosened (interval 30s, timeout 15s, retries 20, start_period 120s) so the deeper analysis cycle does not race the liveness probe under CPU contention.
- Daemon main loop now survives the closing of all conversational channels: background investigation tasks (intelligence engine, forensic analyst, detection engine, schedulers) keep running and the process waits for an explicit shutdown signal instead of exiting silently.
- Incident dossier carries a buffer of pending investigation steps, drained into the timeline both at incident creation and on incident dedup so no skill call is lost.

### Fixed
- Triple-shape mismatch on `proposed_actions`: the dashboard, the forensic analyst writer and the playbook worker writer were producing three incompatible shapes, leaving the operator with an empty HITL section even when a real block-IP proposal had been persisted. All writers now emit the canonical bundle, and a forward-compatible parser coerces any legacy row on read.
- Forensic analyst service now records a structured timeline entry on success, on validator rejection, and on timeout (with the deterministic block-IP fallback that was already shipping). The operator sees exactly which path the incident took.

## [1.0.24-beta] — 2026-05-05

### Added
- IDS alert normalizer layer with a vendor-agnostic schema (severity, category, signature, flowbits, direction). The first adapter ships for the bundled IDS sensor; adding a new vendor is one file plus one registry line, with the false-positive policy shared across vendors.
- False-positive filter for IDS alerts that drops perimeter informational events tied to legitimate update / policy traffic before they create incidents (Windows Defender signature updates, Adobe / Google / Mozilla / Dropbox auto-updaters, dotted-quad executable downloads from CDN). On a typical small-business fleet this removes around 1 500 false-positive incidents per day.
- Cross-skill incident enrichment: each incident dossier is now pre-enriched with CVE details, IP reputation lookups, threat-intel matches and correlated firewall lines from every connected firewall skill, in parallel, before any LLM step.
- Attack timeline panel on the incident page renders the structured enrichment (color-coded IP reputation, CVSS / EPSS / KEV badges on CVEs, threat-intel matches, factual firewall lines).
- Deterministic remediation suggestion: every confirmed incident with an external source IP attested by at least one detection rule now surfaces an `opnsense_block_ip` proposal in the human-in-the-loop queue, even when the forensic analyst service is busy or times out.
- Outbound-direction awareness on generic IDS alerts: when telemetry indicates an internal asset reaching out (update CDN, dotted-quad host, packed executable download), the incident title is rephrased as “Suspicious outbound traffic from X to Y (review)” instead of presenting the remote endpoint as an attacker.

### Changed
- Forensic analyst pipeline serialises model calls through a global single-permit semaphore so multiple incidents queued at the same time no longer starve the deeper analysis stage. Conversational L0 bot stays out of the queue and remains responsive.
- Forensic analyst timeout reduced from 20 minutes to 5 minutes; on timeout, the deterministic block-IP fallback persists a remediation proposal so the operator always has an actionable next step.
- Forensic prompt hides static software-vulnerability findings when at least one live detection rule is present in the incident, so the narrative stays anchored on the observed attack rather than on contextual patch state.
- Incident title prioritisation now favours the live detection rule over static vulnerability findings (a brute-force burst is described as a brute-force burst, not as a CVE list on the same host).

### Fixed
- Forensic enrichment no longer skipped when the eligibility gate is computed from the persisted record: we now use the actual count of attested detection IDs and finding IDs instead of a stale aggregate column that was always zero.
- Detection-rule lookup by ID was silently returning zero rows because of an integer-width mismatch on the primary key. Identifier handling normalised across the database trait, the SQL adapter, and all call sites; structured forensic context is now reliably hydrated.
- Asset resolution for detection rules now joins on the asset’s recorded IP addresses (with port stripping), so an asset known by canonical name can still be linked to detection events keyed on its IP. This unblocked alert correlation, source-IP visibility in titles, and the deterministic block-IP proposal.
- Hallucination guardrails extended with new sentinels (generic threat-actor placeholders, exfiltration / ransomware terms, well-known APT names) so unverifiable narrative claims trigger a rejection and a deterministic summary instead of being persisted.

## [1.0.23-beta] — 2026-05-04

### Added
- Endpoint inventory: hardened agent installer for Debian 13 (apt-key removed in trixie) and for Windows hosts with multi-NIC layouts. The agent now filters virtual / Docker / WSL interfaces so a single host no longer surfaces as multiple assets.
- ml-engine ships a reproducible Docker image: training corpora and DGA models are rebuilt from public sources (Tranco + synthetic) at image build time, with a SHA256 provenance sidecar. No customer or telemetry data ever enters the image.
- Attack-prediction page now exposes two tabs: a static CVE-chain analyzer that works as soon as inventory + CVE + one critical asset exist, and the existing graph-walker for analyst drill-down.
- CVE auto-correlation list extended with Windows server stack, Microsoft desktop apps, virtualization platforms and common security/monitoring tools so Windows inventories trigger NVD lookups too.
- New "Endpoint Agents", "CVE & Attack Prediction" and "Inventory Gate" sections in the README, plus dedicated `docs/inventory-gate.md` and `docs/attack-prediction.md` reference pages.
- Getting-started walks through agent install on Linux and Windows and how to declare a critical asset.
- API reference lists endpoint-agent webhook routes, bulk archive operations and both attack-prediction endpoints.

### Changed
- Asset resolution merges discoveries that share a hostname even when their MACs differ (Docker bridges, virtual NICs). Prevents phantom assets on every osquery sync.
- IDS findings route to the destination internal asset, with a fallback to the source IP when both ends are external. The firewall hostname is no longer used as the asset for traffic it merely observed.
- Generic operator labels across the UI and back-office prompts where the audience may be a CISO, DSI, MSP analyst or internal IT lead.

### Fixed
- Network page IDS card no longer scrolls horizontally when an IDS snippet is wide.
- ml-engine image declares its source repository label so the GitHub Container Registry can attach a fresh container package to this repo on first push.

## [1.0.22-beta] — 2026-05-04

Major signal-to-noise rework. The console now stays quiet on a healthy
infrastructure and only escalates events that touch monitored assets.

### Changed
- **Inventory gate**: incidents are escalated only when the asset matches a declared entry (`assets` table or `internal_networks` CIDR), with RFC1918 as a universal fallback. External IPs are kept as forensic findings but never spawn incidents.
- **ML clustering and anomaly detection** now build their behavioural baseline from monitored assets only. Cluster membership is no longer polluted by Internet scanners.
- IDS findings route to the destination asset when private; outbound flags from a private host still surface that host as the asset.

### Fixed
- L1 prompt no longer copies a hardcoded SSH brute-force example into unrelated incident titles.

### Note
- 1.0.21-beta is deprecated — its perimeter-mitigated bulk-archive query was inert. Skip directly to 1.0.22-beta.

## [1.0.21-beta] — 2026-05-04

### Changed
- Perimeter-mitigated rule now also recognises firewall events that arrive as findings (direct-API connectors), not only rows in the legacy firewall events table.

### Added
- `POST /api/tc/incidents/bulk-archive-perimeter-mitigated` with `?dry_run=true` preview. Backfills the rule across existing open incidents.
- Dashboard maintenance: two-step button to preview then archive perimeter-mitigated incidents from the console.

## [1.0.20-beta] — 2026-05-03

### Added
- Attack timeline on the incident report — alerts and findings shown in chronological order.
- `POST /api/tc/incidents/bulk-archive-stale` — archive open+pending incidents older than 24h.
- Perimeter-mitigated rule — drop dossiers whose evidence is fully blocked at the firewall.

### Changed
- Incident report page is the single triage destination — no more inline expansion.

### Fixed
- CI: install missing protobuf dev headers so the proto build stage succeeds in GitHub Actions.
- Align version strings across the Cargo manifest, README badge and installer script.

## [1.0.19-beta] — 2026-05-03

Investigation graphs now ship inside the release image and are downloaded automatically
by the installer, so a clean install via one-liner or release download is fully operational.

### Fixed
- **Investigation graphs missing from release image** — the 51 CACAO investigation graphs
  are now bundled in the `ghcr.io/threatclaw/core` image and used automatically when the
  host `graphs/sigma/` bind-mount is empty.
- **Investigation graphs not downloaded by installer** — `install.sh` now downloads the
  full graph library on first install and on `--update`, so the bind-mount is populated
  immediately without manual steps.

## [1.0.18-beta] — 2026-05-02

Fix clean-install reliability: investigation graphs and AI models now work out of the box
without cloning the repository.

### Fixed
- **CACAO graphs not loading on release installs** — investigation graphs bundled in the
  Docker image are now used automatically when the host `graphs/sigma/` directory is empty
  (bind-mount fallback via entrypoint). Previously, any install that did not include a full
  git clone had zero graphs and fell back entirely to ReAct.
- **AI models not created on fresh installs** — the triage and forensic analysis models
  are now created automatically on first boot. Fresh installs no longer produce errors on
  every investigation and loop on pending incidents.
- **Forensic section stuck in spinner** — `forensic_enriched_at` was missing from the
  `get_incident` SQL query; the dashboard incident page now renders the L2 forensic
  narrative correctly once enrichment completes.

### Added
- **Anti-hallucination gate** in forensic enricher — incidents with fewer than 2 alerts
  and no evidence citations skip the LLM call and store an explicit "insufficient data"
  message instead of risking fabricated MITRE techniques.
- **Forensic L2 section in incident report** — dedicated panel shows the async narrative,
  MITRE ATT&CK tags, and evidence citations; a spinner indicates enrichment in progress.
- **HITL actions panel** in incident report — proposed remediation actions with
  approve/reject controls, shown only when actionable commands are present.
- **Auto-load related incidents** — correlation panel loads automatically on page open.

### Changed
- **Graph-first mode is now the default** — the investigation engine delegates to
  deterministic graphs when a matching rule exists; unmatched dossiers still fall back
  to the reasoning engine. Can be overridden in `.env`.

## [1.0.17-beta] — 2026-05-02

Two-speed AI pipeline, 13 new investigation graphs, and investigation workspace.

### Added
- **Two-speed AI pipeline** — triage runs synchronously on a cyber-specialized model
  (`threatclaw-primary`); forensic enrichment runs asynchronously after confirmation,
  one incident at a time, without blocking the detection pipeline.
- **Async forensic enricher** — background scheduler produces a detailed RSSI-readable
  narrative with MITRE mapping and evidence citations. Idempotent: a crash mid-analysis
  is recovered cleanly on the next cycle.
- **13 CACAO investigation graphs** — deterministic verdict paths for lab rule IDs
  not previously covered; wired into the full pipeline alongside the LLM path.
- **Investigation workspace** — `/incidents/:id/investigate` page with an interactive
  agent workspace, IP enrichment, and L1 analysis runner.
- **Incident full-detail API** — `GET /incidents/:id/full`, `POST /investigate`,
  `GET /incidents/:id/related`, `POST /incidents/:id/report`.
- **Continuous monitoring** — post-graph L1 trigger with 15-minute re-evaluation window.

### Changed
- **Verdict summaries** — ML internals (anomaly scores, cluster IDs) removed from
  RSSI-facing text; summaries now read as plain-language security analysis.
- **Investigation page** — redesigned incidents table and investigation workspace.

### Fixed
- Reinvestigate endpoint now correctly parses the LLM JSON response instead of
  converting it to display text before parsing (systematic silent failure).
- Reconciler: alert ID column type mismatch corrected, preventing dropped alerts on high-volume rules.
- Reconciler: ML anomaly score, Sigma alerts, and lateral paths properly wired
  into the verdict context.
- Nginx header buffer size corrected, fixing intermittent navigation failures.

---

## [1.0.16-beta] — 2026-04-29

Asset accounting tightened. Operators can now merge duplicate rows
and retire an asset from billing and monitoring with a single toggle.

### Added
- **Manual merge** — select two or more rows in `/assets`, click *Fusionner*; aliases
  redirect to the canonical asset for 30 days (undoable).
- **Single exclusion toggle** — one switch removes an asset from both the billable count
  and the detection pipeline, with a typed reason and an automatic 90-day expiry.
- **Proxmox VM enrichment** — connector now fetches MAC and primary IP per VM, fixing
  duplicate inventory when the same machine is also seen by the firewall or DHCP.

### Changed
- **Billable count** — assets are billable when they show recurring presence (declared
  inventory or three distinct days of activity in the last 30), not because a finding
  fired. Quiet legitimate hosts no longer drop off the bill mid-month.

---

## [1.0.15-beta] — 2026-04-29

Phase G ships. ThreatClaw now decides on known attack patterns through deterministic
investigation playbooks, and falls back to AI reasoning only on the ambiguous branches.
Pricing pivots to an asset-tiered model with HITL included on every tier.

### Added
- **Investigation playbooks (CACAO v2 standard)** — deterministic decisions on common attack scenarios (SSH/RDP brute force, honeypot touches, file-integrity, AD events, EDR responses, firewall events, shadow AI), with a traceable, reproducible path under 100 ms.
- **Predictive Threat Map** — top attack paths populated, including lateral paths inferred from logon events.
- **LLM-assisted graph authoring** — the operator can draft a CACAO v2 playbook from a Sigma rule, with parse + compile validation before save.
- **Manual asset criticality** — operator can override an asset's criticality from the dashboard.
- **Phase G readiness gauge** — live ratio of incidents covered by a proposed HITL action.

### Changed
- **Pricing model** — HITL actions are free on every tier. The paid lever is the cap on monitored assets per tier, see [threatclaw.io/pricing](https://threatclaw.io/pricing). Functionality is identical across tiers.
- **L2 timeouts** downgrade verdicts to `Inconclusive` instead of poisoning incidents with `Error`.
- Threat-map empty state explains the actual cause instead of a generic message.

---

## [1.0.14-beta] — 2026-04-27

Pipeline refoundation: alerts, findings and incidents are wired the way a real SOC expects.
FortiGate becomes a first-class SIEM source. The L2 verdict is grounded against the asset
graph. The operator sees an "act now" zone with prominent HITL buttons on every incident.

### Added
- **FortiGate full ingestion** — full SOC posture in one cycle, no syslog forwarding required. Sigma starter pack ships for FortiGate auth and config events.
- **OPNsense full-API ingestion** — eight log scopes via REST. Sigma rules ship for OPNsense auth, IDS, and DNS-resolver events.
- **Sigma rule promotion** — corroborated signals become findings; lone medium/low alerts stay as alerts. Stops the noise.
- **Asset normalization in Sigma matches** — raw hostnames are resolved to the canonical asset before insert.
- **Human incident titles** — readable summaries based on the top finding instead of cryptic dossier identifiers.
- **Adaptive LLM prompt** — the prompt now lists only the skills actually configured and enabled, so the model doesn't hallucinate sources that aren't installed.
- **Impossible-travel detection** in the identity graph.
- **Firewall and FortiGate baseline drift findings** — catches rule wipes, rogue APs, deauth attacks.
- **`/network` page** — single pane of glass for connected firewalls, blocked sources, identity anomalies, IDS alerts, admin events.
- **Action-first incident detail UI** — large HITL buttons surfaced at the top.

### Changed
- HITL license enforced uniformly on every destructive route, including channel callbacks.
- New connectors: FortiGate webfilter URL block, OPNsense MAC quarantine.
- LLM timeout calibrated for CPU-only inference.

### Fixed
- Sigma rules with array `contains` modifier now fire correctly.
- OPNsense audit-log ingestion path corrected.
- Docker build dependencies fixed.

---

## [1.0.13-beta] — 2026-04-26

OPNsense promoted to a real SIEM source. Three new detectors cover network and endpoint.
Introduces the original HITL license model (subsequently superseded by the asset-tiered
pricing announced in v1.0.15).

### Added
- **HITL license model** — every destructive action gated behind a license check. License page rebuilt; HTTP 402 returned when missing.
- **Endpoint remediation trio (Velociraptor)** — quarantine endpoint, kill process, isolate host. Ships a custom Velociraptor artifact in-tree.
- **OPNsense as a SIEM source** — multiple REST endpoints consumed, rolling firewall events table.
- **Aggregate firewall detector** — port-scan and brute-force aggregation with severity escalation when source is internal.
- **Sigma firewall starter pack** — backdoor port hits, RDP/SMB inbound, UDP amplification, cryptomining proxy ports.
- **Dedicated `/scans` page** — four tabs, nine scan types, real scheduler.
- **Skill catalogue redesign** — single grouped feed per category, "Installed" badge, HITL panel with separate privileged credential fields.

### Fixed
- OPNsense firewall events were silently dropped at insert.

---

## [1.0.12-beta] — 2026-04-25

Velociraptor connector hardened end-to-end. Wazuh agent telemetry wired into the user
behaviour graph. Dashboard navigation unified across every page.

### Added
- **`/users` page** — list and detail of every observed identity, with asset cross-reference, login history, escalation edges, UBA anomalies, honeypot hits.
- **Wazuh → identity graph bridge** — Windows logon events emit identity edges so the user page surfaces real activity.

### Changed
- **skill-velociraptor** rewritten on native gRPC + mTLS (the previous REST path was a dead end).
- **Dashboard navigation unified** — single sidebar across all sectioned pages. Reports gain dedicated routes per category.
- **AD connector** — service-account detection (svc-/srv- prefix or trailing `$`) and French admin-group recognition.

### Fixed
- Asset sources accumulate properly across all resolution paths.
- Identity graph events stop overwriting authoritative `is_admin` and `is_service_account` flags.
- osquery webhook payload size raised so a domain-controller snapshot is no longer rejected.

---

## [1.0.11-beta] — 2026-04-24

Two new connectors for the two vectors that dominate SMB incidents: compromised endpoints
and compromised cloud-identity tenants.

### Added
- **skill-velociraptor** — hunt-result ingestion into the asset graph, plus four read-only tools exposed to the L2 forensic assistant. mTLS, cursor-based sync.
- **skill-microsoft-graph** — full M365 / Entra ID tenant ingestion via OAuth app-only. Pulls sign-ins, audits, users, devices, Conditional Access, Defender alerts, Identity Protection. Detects mail auto-forward rules, illicit OAuth consent, impossible travel, MFA fatigue, Global Admin assignment.
- **Feature probe matrix** on the M365 skill — reports which detections are available on the tenant's licence tier.
- **Identity graph bridging** for cloud sign-ins.

### Changed
- Connector sync gains cursor persistence on both new skills, so restarts never replay.

---

## [1.0.10-beta] — 2026-04-22

Wazuh connector hardened for real customer traffic.

### Added
- Wazuh noise filter — Docker veth and auditd promisc events silenced by default.
- Cursor-based pagination — no event loss when the source fires faster than a sync cycle.
- Attack-scenario harness with CI workflow.

### Fixed
- Log and Sigma alert ingestion no longer fails silently on edge-case payloads.
- Wazuh agent re-enrollment no longer creates duplicate assets.

### Changed
- Local LLM default capacity reduced to fit a typical SMB host without swap thrash.

---

## [1.0.9-beta] — 2026-04-22

Conversational chat lands in the dashboard, grounded LLM by default, and a
Linux/Wazuh Sigma starter pack so fresh installs catch things in the first hour.
Dashboard redesigned as a full SOC console.

### Added
- **Dashboard chat** — same conversational assistant as Slack/Telegram, with thread history and tool-call citations.
- **Grounding strict by default** — every LLM answer is cited against a database source or refused.
- **Sigma starter pack** — MITRE-tagged rules covering SSH brute force, privilege escalation, credential theft, audit tampering.
- **Home KPI strip** — open incidents, severity distribution, top-risk asset, alert volume.

### Changed
- Dashboard redesigned as a SOC operator console — dense, sober, red reserved for urgency.
- ML engine state shows "learning · N/14 d" during bootstrap instead of "offline".
- Per-section save buttons, restart wizard moved out of the global footer.

### Fixed
- Graph layer no longer mistakes hostnames for IP addresses.
- ML engine state read from health endpoint.
- Version badge drift blocked at CI.

### Infrastructure
- Staging pipeline: every push to `main` builds, deploys, and rolls back the database if anything fails.
- Release workflow time roughly halved.

---

## [1.0.8-beta] — 2026-04-21

Five features that consolidate ThreatClaw into a SOC-in-a-box of production-grade quality:
auto blast-radius on sensitive incidents, a normalized typed asset graph, suppression rules
with TTL and audit, time-to-alert telemetry on KEV exposure, and a monthly CISO PDF report.

### Added
- **Auto blast radius** — score 0-100, top assets impacted, manual recompute. Triggers on lateral-risk MITRE categories at high severity or above.
- **Normalized typed asset graph** — replaces ad-hoc joins. AD, Azure AD, AWS, Cloudflare, Proxmox, network and data edges, all weighted for shortest-path queries.
- **Suppression rules v1** — TTL-bounded, audit-trailed, hot-reload-safe. Wizard surfaces a 14-day dry-run before save and warns when confirmed incidents would have been suppressed.
- **CISA KEV time-to-alert telemetry** — measures the gap between a CVE being added to KEV and the first asset match locally.
- **Monthly CISO PDF report** — KPIs, MTTR, blast-radius distribution, top-three risks of the month.

### Community & Governance
- **CLA v1.1** — patent grant + retaliation, French moral-rights compatible, governing law clause.
- **CLA Assistant bot** active on every PR.
- **Code of Conduct** — Contributor Covenant 3.0 with sections specific to weaponised disclosure, credential leakage, offensive-security showcasing.
- **Security policy refresh** — supported versions, scope, safe-harbor clause, SLAs, PGP workflow.
- **Domain alignment** — product addresses migrated to `@threatclaw.io`.

---

## [1.0.7-beta] — 2026-04-20

Shadow AI detection, an AI governance dashboard, and four AI compliance report templates.
Detects unauthorized usage of commercial LLM APIs and self-hosted LLM runtimes from
network traffic — no TLS decryption, no endpoint agent.

### Added
- **Shadow AI detection** — passive detection of commercial LLM APIs and self-hosted LLM runtimes, by network fingerprint. Findings carry `category=AI_USAGE_POLICY` with provider, endpoint and policy decision metadata.
- **AI governance dashboard** (`/governance`) — Shadow AI live, AI System Inventory, four-framework compliance posture (NIS2 / ISO 27001 / ISO 42001 / NIST AI RMF), evidence and audit trail.
- **Native compliance evaluators** — NIS2 Article 21 §2(a-j), ISO 27001:2022 Annex A, ISO 42001:2023 Annex A, NIST AI RMF 1.0 (2025 revision).
- **Four AI governance report templates** — EU AI Act, ISO 42001 assessment, NIST AI RMF, AI governance whitepaper. Targets the 2026-08-02 EU AI Act high-risk obligations.
- **Real audit trail export** — append-only audit table, hash-chained, with verifiable journal hash.

### Changed
- Exports page redesigned around four usage-oriented sections with contextual parameters per export, visible legal badges, regional filtering.

---

## [1.0.6-beta] — 2026-04-19

A full anti-hallucination layer for the LLM verdict pipeline lands as opt-in
infrastructure. Off by default; existing installations are unaffected until an operator
flips the switch.

### Added
- **Grounding layer** — multi-stage validation between LLM output and final verdict, modes `off / lenient / strict`. Off by default.
- **Evidence citations** — verdicts must cite concrete alert and finding identifiers from the dossier.
- **Public benchmark** — deterministic regression run, reproducible from `cargo test`.

### Changed
- Schema-constrained ingestion adopted across all LLM call sites.

### Fixed
- LLM JSON repair path no longer over-eagerly accepts bare strings or nulls.
- Parser deduplication: shared between investigation and reconciler.

---

## [1.0.5-beta] — 2026-04-17

### Security
- Dashboard, zero CVE — Next.js bumped (5 high-severity advisories patched). `npm audit` clean.
- Rust default build, zero active CVE — `cargo audit` clean.
- Transitive advisories under optional features documented with rationale.

### Changed
- React 18 → 19 (enables newer Server Components features).
- Node.js 20 → 22 on Docker images (Node 20 EOL April 2026).
- Turbopack now default for dashboard builds.
- Docker base images bumped and aligned.

### Fixed
- LAN syslog ingestion — collector network reconfigured so external syslog sources can reach it while database access remains internal.

---

## [1.0.4-beta] — 2026-04-17

### Added
- **systemd service** — auto-start on reboot.
- **FHS-standard symlink** — `/etc/threatclaw` for sysadmin discoverability.
- **Log persistence** — `/var/log/threatclaw/` with logrotate (14-day retention, daily, compressed).

### Changed
- Installer success message now shows `systemctl` commands and log paths.
- Uninstall cleans up systemd unit, logrotate config, symlink, and log directory.

---

## [1.0.3-beta] — 2026-04-17

### Added
- **Demo isolation** — every simulation tagged, scoped to a unique session, auto-cleanup after one hour.
- **Cleanup API** — purge demo data on demand.
- **Visible `[DEMO]` banner** on simulation notifications across every channel.

### Fixed
- Simulation scenarios no longer pollute production graph, ML baseline, findings, or compliance reports.

---

## [1.0.2-beta] — 2026-04-16

### Added
- **ThreatClaw Agent — Windows** — PowerShell installer, telemetry collection (read-only), scheduled-task sync.
- **One-liner Windows install** via `irm | iex`.
- **Agent tab in dashboard Config** — token generation, Linux / Windows install snippets, registered-agents table with last-sync status.

### Changed
- Home page agent block replaced with a compact link to Config → Agent.
- Agent description clarifies it collects telemetry only — it does not act on endpoints.

---

## [1.0.1-beta] — 2026-04-16

Post-launch quality release. Security, stability, hygiene.

### Security
- **Dependabot sweep** across the binary and the dashboard.
- Upstream WASM-dependency provenance documented.

### Fixed
- Test suite — recovered failing lib tests on environment-mutex cascades.
- Installer — core readiness timeout adjusted for slower cold-start hosts.
- Dashboard internationalization parity restored on visible pages.

### Added
- Single source-of-truth version-propagation script.
- Repo-wide drift check (versions, internationalization, dashboard endpoints, migration fields, skill catalog, Dockerfile coverage).

---

## [1.0.0-beta] — 2026-04-14

First public beta of ThreatClaw — autonomous cybersecurity agent for SMBs.
Self-hosted, AI-powered, sandboxed skills.

### Highlights
- **Multi-level local LLM stack** — conversational, triage, forensic, instruct, with optional anonymized cloud escalation.
- **Conversational tool calling** — bot answers operator questions against the local database.
- **Intelligence Engine** — dynamic correlation cycle, verdict-based notifications, incident deduplication, kill-chain reconstruction.
- **Incident management** — structured forensic parsing (IOCs, MITRE, proposed actions), notes, re-investigate, fallback actions.
- **Network detection** — DNS tunneling, TLS-fingerprint analysis, beaconing detection, ransomware heuristics, threat-feed correlation.
- **ML engine** — anomaly detection, DGA detection, behavioral clustering.
- **Graph Intelligence** — typed asset graph with priority-ranked resolution, STIX 2.1 export, kill-chain reconstruction.
- **Multi-channel HITL** — Telegram, Slack, Discord, Signal, WhatsApp, Mattermost, Ntfy, web. Bidirectional conversational bot.
- **Remediation engine** — HITL-approved actions (firewall block, account disable, ticket creation), boot-locked protected infrastructure, anti-replay protection, rate limits.
- **Backups** — daily automatic backups with retention, manual trigger, external path.
- **Notification anti-spam** — configurable cooldowns, quiet hours, daily digest, escalation bypass.
- **Skill catalogue** — connectors, enrichments and tools across firewall / SIEM / EDR / DFIR / ticketing / scanning / cloud.
- **Dashboard** — bilingual (FR/EN) console with real-time KPIs.
- **Compliance reports** — NIS2, ISO 27001, NIST.
- **Asset intelligence** — auto-discovery, fingerprinting, software inventory, automatic CVE correlation.
- **Offline mode** — full / degraded / offline / air-gap, with bundle delivery for air-gapped sites.
- **Docker plug-and-play** — one-liner installer, auto model pull, auto-generated TLS certificates.
- **Anonymizer** — international PII categories with custom rules, applied before any cloud LLM escalation.
- **Hardening** — TLS 1.2/1.3 only, HSTS preload, CSP, container isolation, signed sandboxed skill runtime.

### Note on version numbering
Pre-`v1.0.0` entries reflect the internal development history before the first public
release. They are retained for transparency but should be read as preview iterations.

---

## [0.x-beta] — March 2026

Pre-public development releases. Two snapshots are kept for transparency:

- **0.2.0-beta** (2026-03-29) — conversational layer, skill marketplace foundation, ephemeral skill containers, Wazuh import, finding deduplication, multilingual exports, dark glass dashboard, native multi-platform installers, ML engine, graph intelligence, ReAct reasoning loop, encrypted credential vault, anti-replay HITL.
- **0.2.0.1-beta** (2026-03-30) — security hardening pass: nginx reverse proxy, TLS 1.2/1.3 only, HSTS / CSP / Permissions-Policy, container isolation, image pinning, session-cookie hardening, brute-force throttling, weak-password rejection at boot.
- **0.1.0** (2026-03-18) — initial fork and rebranding, first prototype skills, Docker composition, installer.
