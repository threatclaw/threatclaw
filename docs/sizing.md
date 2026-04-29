# Sizing Guide

How to dimension the server that will run ThreatClaw at your client site or on your own infrastructure.

This guide is built from real measurements taken on two reference machines spanning a wide hardware era gap (a recent AMD laptop and an older Intel server). The numbers below are conservative — your mileage will vary by workload, by the active LLM mode, and by how aggressively you tune the agent.

---

## TL;DR — Quick recommendations

| Use case | Min CPU | Min RAM | Recommended LLM mode |
|---|---|---|---|
| Discovery / POC | 4 modern cores, AVX2 | 16 GB | Cloud L0 + L1 local |
| SMB 5-50 endpoints | 6-8 modern cores | 24 GB | Cloud L0 + L1/L2 local |
| SMB NIS2 full-local | 8 cores Zen3+ / 12th gen+ | 32 GB | L0 light + L1 + L2 on demand |
| SMB comfort | 8-16 cores Zen3+ / Raptor Lake | 48 GB | L0 mid + L1 + L2 + L2.5 |
| Enterprise / MSP | 16+ cores Zen4+ / EPYC | 64+ GB | L0 premium full stack |

**Rule of thumb**: post-2020 CPU with AVX2 is mandatory, DDR4-3200 or better. Below this threshold, only the cloud-L0 mode produces an acceptable conversational experience.

---

## 1. What the ThreatClaw stack consumes outside the LLM

The agent itself is light. Idle baseline (no model loaded) is dominated by the inference runtime and the database.

| Component | Idle RAM | Loaded RAM | CPU |
|---|---|---|---|
| Core agent | 174 MB | 400-600 MB | 1-2 threads |
| Dashboard | 55 MB | 100-200 MB | < 1 thread |
| Database (with graph + vector + time-series extensions) | 215 MB | 500 MB - 1 GB | 1-2 threads |
| ML engine | 130 MB | 400-800 MB during nightly retrain | 1-2 threads |
| Log shipper | 25 MB | 50-100 MB | < 1 thread |
| Reverse proxy | 12 MB | 30 MB | < 1 thread |
| LLM runtime daemon (idle) | 500 MB | + the loaded model | depends on model |
| Container overhead | ~500 MB | ~500 MB | - |
| **Total without LLM** | **~1.6 GB** | **~3 GB** | **4-6 threads** |

An 8 GB host without local LLM could in principle run the entire ThreatClaw stack. The real consumer is the inference runtime and whichever models it loads.

---

## 2. RAM consumption by LLM tier

Memory budget per ThreatClaw LLM tier, with a ~8 K context window:

| Tier | Role | RAM (loaded, light) | RAM (loaded, comfortable) |
|---|---|---|---|
| **L0 light** | conversational chatbot, low-RAM mode | ~3 GB | ~3.5 GB |
| **L0 mid** | conversational chatbot, comfort mode | ~10 GB | ~12 GB |
| **L0 premium** | conversational chatbot, premium mode | ~14 GB | ~15.5 GB |
| **L1** | first-line triage, always resident | ~6 GB | ~6.5 GB |
| **L2** | forensic reasoning, on-demand | ~8.5 GB | ~9.5 GB |
| **L2.5** | playbooks and report generation, on-demand | ~5 GB | ~5.5 GB |
| **L3** | cloud escalation, anonymized | n/a (remote) | n/a (remote) |

L1 stays loaded; L2 and L2.5 are loaded only when an investigation or a report needs them. The four L0 modes are mutually exclusive — pick one.

---

## 3. Inference speed by CPU

Reference test: a short SOC summarization prompt in French, generation rate measured in tokens per second.

| Tier | Modern AMD laptop (8c/16t, 2023) | Mid-2010s Intel server (4c/8t, 2015) |
|---|---|---|
| L0 light | 16-17 tok/s | ~6 tok/s |
| L0 mid | 18 tok/s | ~7 tok/s |
| L0 premium | 4 tok/s | ~2 tok/s |

The 2.5× factor between an old Xeon and a recent Zen 4 is the difference between "usable chatbot" (15+ tok/s, the analyst waits ~3 s) and "frustrating chatbot" (6 tok/s, the analyst waits 15-30 s and stops using it).

**For the conversational experience, target 12 tok/s in generation, minimum.** Below that, switch to cloud L0.

---

## 4. The four deployment profiles

### Profile 1 — Cloud L0 — small offices, tight budget, POC

Smallest viable setup. The conversational L0 runs on a hosted API; sensitive data is anonymized before any cloud call. Forensic analysis stays local.

| | Minimum | Recommended |
|---|---|---|
| CPU | 4 modern cores, AVX2 mandatory | 6 modern cores |
| RAM | **16 GB** | **24 GB** |
| Disk | 100 GB SSD | 200 GB SSD |
| Local models | L1 only (~6 GB) | L1 + L2 on demand (~15 GB peak) |
| Cloud LLM cost | ~5-15 €/month | ~15-30 €/month |
| Analyst experience | Instant chatbot (cloud), local forensics OK | Everything fast |

**Hardware fit**: small VPS plans, NAS-class servers, refurbished single-socket boxes.

---

### Profile 2 — Light full-local — for SMBs under strict NIS2

Everything on-prem, nothing leaves the network. For sovereignty constraints, OIVs, or clients who want to control the entire LLM chain.

| | Minimum | Recommended |
|---|---|---|
| CPU | **8 modern cores**, AVX2 (Zen3+, Alder Lake+ minimum) | 8-12 cores Zen4 or Raptor Lake |
| RAM | **32 GB** | **32 GB** comfortable |
| Disk | 200 GB NVMe SSD | 500 GB NVMe SSD |
| Local models | L0 light + L1 permanent + L2 on demand | + L2.5 |
| Peak RAM | 3 + 6 + 9 = **18 GB models** + 3 GB base = 21 GB | Same |
| Analyst experience | L0 fast (10-15 tok/s), L2 forensics in ~30 s | Same |

**Hardware fit**: small rack servers (Dell PowerEdge R-series, HPE ProLiant ML/DL), Intel NUC 12/13 Pro, mid-range Synology, mini-PC built around a Ryzen 7.

**Avoid**: Xeons older than 2018. A 2016-era E5-2680 v4 caps around 4 tok/s on a 24B model — not viable for conversational use. The only acceptable Xeons are Gold 6xxx 3rd-gen or newer.

---

### Profile 3 — Comfort full-local — SMB sweet spot

The best comfort/cost ratio for an SMB that wants everything local and fluid.

| | Recommended |
|---|---|
| CPU | **Ryzen 9 5900X / 7900 / 9900** or Intel i7-13700 / 14700 (8-16 cores Zen3+/Alder Lake+) |
| RAM | **48 GB** |
| Disk | 500 GB NVMe (OS + models) + 2 TB HDD for log retention |
| Local models | L0 mid + L1 + L2 + L2.5 on demand |
| Peak RAM | 10 + 6 + 9 = 25 GB + 4 GB base = **~29 GB** |
| Analyst experience | L0 conversational 15-20 tok/s, forensics 10 tok/s, fluid throughout |

**Hardware fit**: rack 1U/2U, custom-built Ryzen 9 dedicated server, workstation reused as a server.

---

### Profile 4 — Enterprise / MSP — RSSI consultancies and large SMBs

For shared-CISO consultancies that manage several clients, MSPs, or SMBs of 200+ endpoints with high log volume.

| | Recommended |
|---|---|
| CPU | **Ryzen 9 9950X** or **EPYC 9354** (16-32 cores Zen4/Zen5) |
| RAM | **64-128 GB** |
| Disk | 1 TB NVMe (OS + ML models) + 4 TB SSD (database) |
| Optional GPU | Mid-range NVIDIA 16 GB (×10 speed-up on L0/L1) |
| Local models | L0 premium + L1 + L2 + L2.5 + side-by-side model evaluation |
| Peak RAM | 14 + 6 + 9 + 5 = 34 GB models + 8 GB buffer = **~42 GB** |
| Analyst experience | Fast across the board even without GPU; with GPU, unbeatable |

**Hardware fit**: rack-mount Dell PowerEdge or Supermicro, Threadripper Pro workstations, GPU-equipped cloud instances.

---

## 5. What actually matters in the CPU

For local LLM inference, the priority order is counter-intuitive:

| Priority | Criterion | Why |
|---|---|---|
| **Critical** | AVX2 instructions | Without AVX2, inference is 5-10× slower. Hard requirement. |
| **Critical** | CPU year (2020+) | Per-cycle performance progressed ~80% in 8 years. A modern 8-core beats a 2016 16-core. |
| **Important** | Memory bandwidth | Inference is memory-bound, not compute-bound. DDR5 > DDR4-3200 > DDR4-2400. |
| **Important** | Physical cores (8-12) | Above 12 cores, single-user gains are marginal. |
| **Useful** | AVX-512 | +15-25% on CPUs that support it. |
| **Bonus** | More than 16 cores | Only useful for batch / multi-user workloads. |

### The old-Xeon trap

A 500 € used dual-Xeon E5-2680 v4 server (28 cores total, 128 GB RAM) **looks** ideal on paper. In reality its IPC is so low it barely matches a 2020 Ryzen 5 5600 for inference. For a client looking for "just a cheap server", this kind of machine is tempting but the user experience will be poor.

**Pre-purchase test**: run a representative L0 generation locally and check tok/s. Below 10 tok/s on a comfortable L0, change machine or switch to cloud-L0 mode.

---

## 6. RAM recommendations

Inference is **extremely sensitive to memory bandwidth**, more than to compute. A loaded model reads its full weight from RAM at every generated token. Therefore:

- DDR4-3200 minimum, DDR4-2666 acceptable, DDR4-2133 to avoid
- DDR5 typically buys 30-50% extra tok/s vs equivalent DDR4
- ECC recommended in production but not mandatory
- Don't under-populate channels (dual-channel minimum, quad-channel on EPYC / Xeon Scalable)

**Rule**: between 32 GB DDR4-3200 and 64 GB DDR4-2133, take the **32 GB DDR4-3200**. Speed beats capacity for our quantized models, all of which fit under 32 GB.

---

## 7. Disk — why NVMe SSD

Disk only matters in three scenarios:

1. **Initial model load** (first request after boot). NVMe loads a 10 GB model in ~5 s, SATA SSD in ~30 s, HDD in ~3 min.
2. **First-boot model download** (15-20 GB download then write).
3. **Database storage** for logs and alerts. A typical SMB stores 50-200 MB raw logs per day.

**Recommendation**: NVMe SSD for OS + models. HDD acceptable for the database log partition if budget is tight, but SSD is preferable.

---

## 8. Cloud and rented servers

| Provider | Plan example | CPU | RAM | Profile fit |
|---|---|---|---|---|
| Hetzner | CX32 | 4 vCPU Intel | 16 GB | Profile 1 (Cloud L0) |
| Hetzner | CX42 | 8 vCPU | 32 GB | Profile 2 |
| Hetzner | CCX33 (dedicated) | 8 vCPU AMD EPYC | 32 GB | Profile 2-3 |
| OVH | Advance-1 | Ryzen 5 Pro 3600 | 32 GB | Profile 2 |
| OVH | Rise-LE-1 | Ryzen 7 | 64 GB | Profile 3 |
| Scaleway | DEV1-L | 4 vCPU | 8 GB | POC only |
| Scaleway | PRO2-M | 8 vCPU | 32 GB | Profile 2 |

Shared-vCPU VPS instances are typically **disappointing** for inference (jitter, throttling). Prefer dedicated instances or bare metal as soon as you go past POC.

---

## 9. Air-gap and strict NIS2

For clients who cannot send **any** data to the cloud (OIV, defense, regulated healthcare, public administration):

- Profile 2 full-local is mandatory
- Server budget: 2000-4000 € for a Ryzen-based dedicated server or a NUC 13 Pro with 32 GB
- Use the offline bundle workflow (downloaded once a month on an internet-connected machine, transferred via USB)
- Cloud L3 escalation is disabled; everything stays on local L1/L2/L2.5

The conversational experience will be **less fluid** than cloud L0 (you cannot exceed ~15 tok/s on a modern Ryzen 9), but forensics remain strong on local L2.

---

## 10. RAM — quick formula

```
RAM = 3 GB (base stack)
    + RAM of permanent L0 (or 0 if cloud L0)
    + RAM of permanent L1 (~6 GB)
    + max(RAM L2, RAM L2.5) — only one loaded at a time
    + 2 GB kernel + cache buffer
```

Concrete examples:
- Profile 1 (cloud L0): 3 + 0 + 6 + 9 + 2 = **20 GB** → spec for 24 GB
- Profile 2 (L0 light): 3 + 3 + 6 + 9 + 2 = **23 GB** → spec for 32 GB
- Profile 3 (L0 mid): 3 + 10 + 6 + 9 + 2 = **30 GB** → spec for 48 GB
- Profile 4 (L0 premium): 3 + 14 + 6 + 9 + 2 = **34 GB** → spec for 64 GB

The 2 GB buffer is conservative. Active connectors (SIEM, network, ML retrain) can grow it. Always plan margin.

---

## 11. Running on under-spec'd hardware

If the client already has a machine that fits no profile (e.g. old Xeon, 16 GB, SATA SSD), here is the order of compromises to propose:

1. **Switch to cloud L0** in `Settings → AI`. The chatbot becomes instant regardless of CPU.
2. **Use the L0 light variant** instead of the regular L1 (3 GB instead of 6 GB, ~3× faster).
3. **Disable L2.5** in config. Saves 5 GB RAM. Playbooks fall back to L2 or are skipped.
4. **Disable the ML engine** in `docker-compose.yml`. Saves 400-800 MB. Sigma + Intelligence Engine still work; only ML scoring stops.
5. **Lower the Intelligence Engine cadence** from 5 min to 15 min in the settings. Cuts average CPU load.
6. **Last resort**: route L1 to cloud as well. ThreatClaw becomes a "thin client" and the host only runs the base stack.

A pure thin-client setup (everything in cloud) holds in **~4 GB used**. Monthly cloud cost stays under 30 € in 95% of SMB cases.

---

## 12. Pre-sales checklist

Five questions to score the right profile in 30 seconds:

1. **What CPU and what year is the target server?** → eliminates Profiles 2-4 if pre-2018.
2. **How much RAM is available or budgeted?** → maps directly to a profile.
3. **Are there sovereignty constraints (strict NIS2, OIV, healthcare)?** → forces Profile 2 minimum, blocks cloud L0.
4. **How many endpoints to monitor?** → drives the log volume, hence the disk.
5. **Will the analyst use the chatbot multiple times a day?** → if yes, you need a fast chatbot (cloud L0 or Profile 3+).

---

## Reference machines

The numbers above were measured on:

- **DEV** — modern AMD laptop (8 cores / 16 threads, Zen 4, AVX-512), 30 GB DDR5-4800, NVMe SSD. Representative of a good Profile 3 build in 2026.
- **CASE** — 2015-era Intel server (4 cores / 8 threads, AVX2 only), 32 GB DDR4-2133, SATA SSD. Representative of a "cheap used server" — below the threshold for conversational use, but acceptable for the batch path (L1, L2 on demand).
