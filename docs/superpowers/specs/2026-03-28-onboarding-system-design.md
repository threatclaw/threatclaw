# ThreatClaw — Onboarding System Design

**Date:** 2026-03-28
**Status:** Approved

## Overview

In-app onboarding system with 3 experience levels, a progress checklist banner, and contextual guided tours using Driver.js.

## 1. Experience Levels

Proposed after SetupWizard completion (first login). Stored in `settings` key `onboarding_level`.

| Level | Behavior |
|---|---|
| **Discovery** | Auto tours on first page visit + checklist + tooltips |
| **Standard** | Checklist + empty states, tours via manual click |
| **Expert** | Nothing — just empty states |

Changeable in Config > General.

## 2. Checklist Banner

Minimalist progress bar at the top of the Status page, below TopNav:

- Thin progress line + "5/8 — Getting Started Guide"
- Each step clickable → navigates to the right page + launches tour
- `×` button → confirmation modal → persisted `onboarding_dismissed`
- Auto-hides when 8/8 complete

## 3. The 8 Steps

| # | Step | Navigation | Auto-detection |
|---|---|---|---|
| 1 | Create admin account | — | Logged in = true |
| 2 | Fill company profile | Config > Company | `company_name` non-empty |
| 3 | Configure AI | Config > ThreatClaw AI | Health `llm` non null |
| 4 | Connect a channel | Config > Channels | 1+ channel enabled + token |
| 5 | Declare internal networks | Config > Company | 1+ network in `/api/tc/networks` |
| 6 | Configure a scan | Skills > Catalog → nmap | 1+ skill with config field set |
| 7 | Connect log source | Config > Log Sources | `logs.today > 0` |
| 8 | Run first scan | Skills > nmap → Run | 1+ asset or finding in DB |

## 4. Driver.js Tours

- 2-4 bubbles per page max
- Auto-triggered in Discovery mode (first visit), manual in Standard
- Tour completion tracked in settings `tours_completed: ["status", "skills", ...]`
- Dark theme CSS matching ThreatClaw design

### Tour: Skills (step 6 — nmap flow)
1. Catalog tab → highlight nmap card → "Install this network scanner"
2. After install → Installed tab → highlight gear icon → "Configure your target"
3. Config popup → highlight target field → "Enter your network (e.g. 192.168.1.0/24)"

## 5. API Endpoint

`GET /api/tc/onboarding/status` returns:
```json
{
  "level": "discovery",
  "dismissed": false,
  "steps": [
    { "id": "admin", "done": true },
    { "id": "company", "done": false }
  ],
  "tours_completed": ["status"],
  "completed": 3,
  "total": 8
}
```

Aggregates checks from existing APIs. No new database table.

## 6. Technical Stack

- **Driver.js** (~5kB, MIT, zero dependencies)
- Hook `useOnboarding()` — loads status, exposes actions
- Component `OnboardingBanner` — progress bar
- Component `OnboardingTour` — Driver.js wrapper per page
- All strings in `i18n.ts` — ~50 new FR/EN keys

## 7. Dismiss & Reactivate

- `×` on banner → confirmation modal → `onboarding_dismissed: true` in DB
- Reactivable in Config > General (toggle "Show getting started guide")

## 8. i18n

All 8 step titles, descriptions, all Driver.js bubble text, level names, confirmation modal — everything in `i18n.ts` with FR/EN.
