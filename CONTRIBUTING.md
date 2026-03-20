# Contributing to ThreatClaw

Thank you for your interest in contributing to ThreatClaw!

## How to Contribute

### Report a Bug
Open an issue using the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml).

### Request a Feature
Open an issue using the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.yml).

### Submit a Skill
See the [Skill Development Guide](docs/SKILL_DEVELOPMENT_GUIDE.md) and use the [Skill Submission template](.github/ISSUE_TEMPLATE/skill_submission.yml).

### Submit Code
1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for your changes
4. Ensure `cargo test` passes with 0 failures
5. Submit a Pull Request

## Development Setup

```bash
# Install Rust + WASM target
rustup target add wasm32-wasip2

# Start infrastructure
docker compose -f docker/docker-compose.core.yml up -d

# Build and test
cargo build
cargo test
```

## Code Style
- Rust: follow `rustfmt` defaults
- TypeScript: follow project ESLint config
- Commit messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`

## Security
**DO NOT** open public issues for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License
By contributing, you agree that your contributions will be licensed under Apache License 2.0.
