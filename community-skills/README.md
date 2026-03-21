# ThreatClaw Community Skills

This directory contains community-contributed skills for ThreatClaw.

## Create a new skill

1. Copy the `_template/` directory: `cp -r _template/ skill-your-name/`
2. Replace all `CHANGEME` in the files
3. Implement your check logic in `main.py`
4. Write at least 3 tests in `tests/test_main.py`
5. Submit a PR

See the full [Skill Development Guide](../docs/SKILL_DEVELOPMENT_GUIDE.md) for details.

## Existing skills

| Skill | Description | API | Status |
|-------|-------------|-----|--------|
| *Your skill here* | | | |

## Rules

- No `os.system()`, `subprocess`, `exec()`, `eval()`
- No file access outside `/app/` and `/tmp/`
- Graceful error handling (never crash)
- At least 3 unit tests
- Apache-2.0 license
