# ThreatClaw Registry

This directory contains the **registry manifests** that describe the WASM
channels and tools ThreatClaw can load at runtime through the skill
marketplace.

## Layout

```
registry/
├── channels/          — WASM channel manifests (Discord, Slack, Telegram, WhatsApp)
├── tools/             — WASM tool manifests (GitHub, Gmail, Google Suite, web-search, …)
├── mcp-servers/       — MCP server manifests
└── _bundles.json      — Curated bundles of skills for common use cases
```

Each `*.json` manifest describes a single skill: its human-readable
name, description, category, configuration schema, and the URL of the
pre-built WASM artifact.

## WASM artifact source — upstream NEAR AI

> ⚠️ **Supply-chain note** — please read before depending on these skills.

ThreatClaw is a fork of the [IronClaw](https://github.com/nearai/threatclaw)
project by NEAR AI. A subset of the channel and tool WASM binaries currently
referenced from these manifests are hosted on the **upstream repository's
GitHub releases**:

```
https://github.com/nearai/threatclaw/releases/download/v0.18.0/<skill>-wasm32-wasip2.tar.gz
```

What this means in practice:

- When a user installs one of these skills from the ThreatClaw dashboard,
  the binary is downloaded directly from the upstream repo, not from
  `threatclaw/threatclaw`.
- The integrity of each artifact is still verified (BLAKE3 hash check
  against the manifest, see ADR-007) before it is loaded into the
  sandbox.
- The WASM code is executed inside a capability-restricted Wasmtime
  sandbox (ADR-013, ADR-014), so a compromised upstream binary cannot
  escape the sandbox to access the host, the network beyond its
  allow-list, or any host filesystem paths outside its workspace.

However, this does create a **supply-chain dependency**: if the upstream
project disappears, changes URL structure, or is compromised at the
account level, affected skills stop working or start shipping
unexpected code. This is acceptable for the v1.0.x beta phase because
it lets us ship these skills today without re-auditing each WASM binary.

### Planned work (post v1.0.x)

Before v2.0.0 we plan to:

1. **Audit** each upstream WASM binary and publish the security
   review alongside the manifest.
2. **Re-host** the reviewed binaries as release assets on
   `threatclaw/threatclaw` so the supply chain is self-contained.
3. **Replace** channels that duplicate native Rust channels (the
   built-in Telegram/Slack/Discord integrations under `src/channels/`
   are now preferred over their WASM counterparts and may render some
   of the channel manifests obsolete).
4. **Sign** our own artifacts with a release key documented in
   `docs/security.md`.

Users who want zero supply-chain exposure to the upstream repo today
can delete the offending manifests from their local install — the
skill will disappear from the dashboard catalog but ThreatClaw itself
will continue to run on its native integrations.

## Adding a new skill

1. Drop a new `*.json` manifest in `registry/channels/`, `registry/tools/`,
   or `registry/mcp-servers/` (depending on its type).
2. Populate `id`, `name`, `description`, `version`, `wasm.url`,
   `wasm.sha256`, and any `config_schema` entries your skill needs.
3. Rebuild the core (`cargo build --release`) — `build.rs::embed_registry_catalog`
   will embed the manifest into the binary at compile time.
4. Optionally add the skill to a bundle in `_bundles.json`.
