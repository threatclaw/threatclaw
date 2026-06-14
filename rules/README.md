# ThreatClaw detection rules

Source-of-truth Sigma rules in YAML, synced into the `sigma_rules`
table at every boot of `threatclaw-core`. Aligned with the SigmaHQ rule
convention (https://github.com/SigmaHQ/sigma-specification).

## Format

Each rule lives in `rules/<logsource>/<rule-id>.yaml`. Required fields
per the SigmaHQ convention:

```yaml
title: Brute force on Windows account
id: win-auth-brute-001
status: experimental   # experimental | test | stable | deprecated
description: |
  Five failed logons (event 4625) for the same target user within
  10 minutes from one source IP.
references:
  - https://attack.mitre.org/techniques/T1110/001/
author: ThreatClaw
date: 2026-06-14
tags:
  - attack.credential_access
  - attack.t1110.001
logsource:
  category: alert        # at least one of category / product / service
  product: windows
  service: security
detection:
  selection:
    event_id: '4625'
  condition: selection
falsepositives:
  - Internal vulnerability scans hitting the same account.
level: high              # informational | low | medium | high | critical
```

## Sync semantics

At core boot, `src/agent/sigma_file_loader.rs` walks `rules/**/*.yaml`
(excluding `*.test.yaml`), parses each file, and upserts into the DB.
On collision with a rule shipped by a migration (same `id`), the file
wins. The disposition / tier / enabled flags set through the dashboard
are preserved across syncs — only the YAML-derived fields (title,
description, detection, tags, level, status, references, author,
falsepositives) get overwritten.

## Test fixtures

Each rule should ship with a sibling `<rule-id>.test.yaml` listing
positive and negative event fixtures. The Rust test runner under
`tests/sigma_rules.rs` asserts that every positive event triggers the
rule and that no negative event does. Rules without a test fixture
emit a warning at `cargo test`; from phase C+1 onward this becomes an
error.
