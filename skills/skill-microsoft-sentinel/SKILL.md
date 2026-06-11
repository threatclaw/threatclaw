---
name: skill-microsoft-sentinel
version: 1.0.0
description: Microsoft Sentinel connector. Ingests Sentinel incidents, alerts, entities, and analytic rule context into ThreatClaw.
permissions:
  - https:management.azure.com:443
  - https:login.microsoftonline.com:443
requires_approval: false
data_classification: internal
nis2_articles:
  - "Art.21 §2b - Gestion des incidents"
  - "Art.21 §2g - Detection et reponse aux incidents"
activation:
  keywords:
    - microsoft sentinel
    - sentinel incidents
    - azure sentinel
    - sentinel connector
    - sentinel alerts
  patterns:
    - "(?i)microsoft.*sentinel"
    - "(?i)azure.*sentinel"
    - "(?i)sentinel.*incident"
---

# skill-microsoft-sentinel

Pulls Microsoft Sentinel incidents into the ThreatClaw incident pipeline.
Each Sentinel incident becomes a ThreatClaw incident with full L1 triage
and L2 forensic coverage. Defender alerts already ingested via
skill-microsoft-graph are deduplicated, so a customer with both skills
active sees one incident per real threat, not two.

## What it does

- Polls the Sentinel REST API every minute for new or modified incidents
- For each incident: pulls related alerts (with `providerAlertId` for
  dedup), extracted entities (Account, Host, IP, etc.), and analytic rule
  context when the incident is Sentinel-native
- Hydrates ThreatClaw assets from Sentinel entities via the canonical
  asset resolver
- Mirrors Sentinel status changes back into ThreatClaw incidents
  (last-writer-wins)
- Optionally posts the ThreatClaw L2 forensic verdict as a comment back
  to the Sentinel incident (requires `Microsoft Sentinel Responder`
  role; graceful fallback to read-only when only Reader is granted)

## What it does not do

- Does not modify Sentinel incident status. Comment-only by design.
- Does not run KQL queries (deferred to a future Hunt Tool)
- Does not support multiple workspaces per tenant (deferred to v2)

## Azure prerequisites

Customer-side setup, one-time:

1. Create an App Registration in Microsoft Entra (or reuse the one
   already configured for skill-microsoft-graph)
2. Add a client secret OR upload a certificate for client assertion
3. On the Sentinel workspace
   (Microsoft.OperationalInsights/workspaces/<your-ws>), assign the App
   the Azure RBAC role `Microsoft Sentinel Reader` at minimum
4. Optional: to enable comment write, assign `Microsoft Sentinel
   Responder` instead of Reader

## Configuration

The dashboard config UI for this skill asks for:

- Tenant ID (auto-filled if skill-microsoft-graph is already configured)
- Application (client) ID (auto-filled)
- Auth method and credential (auto-filled, encrypted at rest)
- Subscription ID, Resource group, Workspace name, Workspace ID
- Toggle: enable comment write (default off, requires Responder role)

## Configuration storage keys (skill_configs)

| Key | Type | Notes |
|---|---|---|
| `tenant_id` | UUID string | shared with skill-microsoft-graph |
| `client_id` | UUID string | shared with skill-microsoft-graph |
| `auth_method` | "certificate" or "secret" | shared |
| `credential` | encrypted string | shared, PEM for cert, secret value for secret |
| `subscription_id` | UUID string | Sentinel-specific |
| `resource_group` | string | Sentinel-specific |
| `workspace_name` | string | Sentinel-specific |
| `workspace_id` | UUID string | Sentinel-specific |
| `enable_comment_write` | "true" or "false" | default false |
| `last_incident_modified` | RFC3339 timestamp | written by the connector itself, the cursor |
| `last_auth_error` | JSON string | written by the connector on AAD errors |
| `comment_write_disabled_reason` | string | written when auto-fallback to Reader-only |

## Observability

Successful sync cycle logs an `INFO` line tagged `sentinel_sync` with the
SyncResult counters (incidents_pulled, incidents_new, alerts_pulled,
entities_pulled, comments_posted, dedup_skipped, errors). Auth failures
debounce to one retry per hour after three consecutive failures.

## Validation

After configuring the skill, trigger a Sentinel incident (or wait for an
existing rule to fire). Within 2 minutes, the incident appears in the
ThreatClaw incidents table with `external_source = 'sentinel'`.
