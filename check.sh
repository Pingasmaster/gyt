#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features xz -- -D warnings
cargo test
cargo test --features xz
cargo build --release
cargo build --release --features xz
echo "all checks passed"
