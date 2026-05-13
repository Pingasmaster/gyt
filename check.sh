#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Format + lint + test + build. No `--features` flags: gyt has no
# optional features at the moment, so they were noise that left this
# script broken whenever someone added a feature-gated piece.
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features -- --test-threads=1
cargo build --release --all-features
echo "all checks passed"
