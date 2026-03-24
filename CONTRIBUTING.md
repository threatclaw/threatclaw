# Contributing to ThreatClaw

ThreatClaw is an open-source cybersecurity agent for SMBs, built in Rust.
Contributions from the community make this project better for everyone.

## License Model

ThreatClaw uses a **dual-license model**:

- **Community**: AGPL v3 — free, open source, share-alike
- **Commercial**: Paid license for organizations that need proprietary use

### Contributor License Agreement (CLA)

Before your first contribution can be merged, you must sign our
[Contributor License Agreement](CLA.md).

**Why?** The CLA allows us to maintain the dual-license model. You keep
your copyright — you just grant us the right to distribute your code
under both the AGPL v3 and commercial licenses.

**How?** It's automatic. When you open a PR, the CLA Assistant bot will
ask you to sign with your GitHub account. Takes 2 minutes, once.

This is standard practice for dual-licensed projects (GitLab, MongoDB,
Grafana, Elastic all do this).

## How to Contribute

### Report a Bug

Open an issue using the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml).

### Request a Feature

Open an issue using the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.yml).

### Submit Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for your changes
4. Ensure `cargo test --lib` passes
5. Submit a Pull Request
6. Sign the CLA if it's your first contribution
7. Wait for review (48h max)

### Submit a Skill

See the [Skill Development Guide](docs/SKILL_DEVELOPMENT_GUIDE.md).
Skills go in `skills-community/` and must include a `skill.json` manifest.

## What We Accept

- Bug fixes with tests
- New enrichment sources (in `src/enrichment/`)
- New investigation graphs (in `src/graph/`)
- Community skills (in `skills-community/`)
- Documentation improvements
- Dashboard components and pages
- Translations (FR/EN)

## What We Don't Accept

- Changes that break STIX 2.1 compatibility
- Dependencies not audited for security
- Code without tests
- Changes to the WASM sandbox security model
- Changes that bypass the anonymization pipeline

## Development Setup

```bash
# Prerequisites: Rust 1.92+, Docker, Node.js 20+

# Install Rust WASM target
rustup target add wasm32-wasip2

# Start infrastructure
docker compose -f docker/docker-compose.yml up -d

# Build
cargo build

# Run tests
cargo test --lib

# Start the dashboard
cd dashboard && npm install && npm run dev
```

## Code Style

- **Rust**: follow `rustfmt` defaults, run `cargo clippy`
- **TypeScript**: follow project ESLint config
- **Commit messages**: `feat:`, `fix:`, `docs:`, `test:`, `chore:`
- **Language**: code in English, user-facing strings in French

## Security

**DO NOT** open public issues for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Contributor Recognition

All contributors with merged PRs are listed in:
- `CONTRIBUTORS.md` — permanent credit in the repository
- https://threatclaw.io/contributors — public website listing

Active contributors (3+ merged PRs) receive:
- ThreatClaw Pro license (free)
- "Core Contributor" badge on GitHub
- Direct influence on roadmap priorities

## Questions

- General: https://github.com/threatclaw/threatclaw/discussions
- Security: security@cyberconsulting.fr
- Commercial: commercial@threatclaw.io
