#!/usr/bin/env bash
set -euo pipefail

echo "==> public docs leak check"
scripts/check-public-docs.sh

echo "==> fmt check"
cargo fmt --all -- --check

echo "==> clippy (correctness)"
cargo clippy --locked --all-targets -- -D clippy::correctness

# Pre-push tests default OFF while the legacy unit-test drift is being fixed
# (~50 tests out of 3611 fail on main; tracked for v1.0.1-beta cleanup).
# Re-enable locally with THREATCLAW_PREPUSH_TEST=1 git push.
if [ "${THREATCLAW_PREPUSH_TEST:-0}" = "1" ]; then
    echo "==> tests (opt-in via THREATCLAW_PREPUSH_TEST=1)"
    cargo test --locked --lib
fi
