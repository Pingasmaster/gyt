# gyt - Agent Guidelines

## Core Rule: Update Docs After Every Code Change

Whenever you finish a code change and are ready to commit, you MUST also update the relevant documentation (README.md, ARCHITECTURE.md, etc.) to reflect the change. Documentation is a first-class deliverable, not an afterthought.

## Project Overview

gyt (pronounced "gift" but with a 'g') is a modern version control system designed for AI agents and humans. It is NOT Git-compatible — it uses its own wire protocol, object format, and command set. It is designed to be production-ready: secure, fast, and auditable.

## Key Concepts

- **Object format**: `<kind> <size>\0<payload>` with BLAKE3 hashing
- **Wire protocol**: Custom REST-like endpoints (info/refs, objects/want, objects/have, refs/update)
- **Storage**: Loose objects in `.gyt/objects/XX/YYYYYY`. The raw object is `<kind> <size>\0<payload>` framing; on disk it is wrapped with XZ/LZMA compression (via the `lzma-rust2` crate). Files written before XZ-wrapping was added still decode (raw-passthrough fallback when the magic prefix is absent).
- **Signing**: ed25519-dalek cryptographically signed commits
- **CI**: Built-in `gyt ci` command with WASM sandbox or shell fallback

## Testing

- Always run `cargo test --all-features -- --test-threads=1` before committing
- Run `timeout 30 bash tests/smoke_comprehensive.sh` for end-to-end smoke test
- Wire protocol integration tests are in `tests/wire_integration.rs`

## Build

```bash
cargo build --release --all-features
cargo clippy --all-features -- -D warnings
```

## Branch Strategy

- `main` is the primary branch
- Features are developed on branches named after the feature
- No force-pushing to main

## Policy: No Push Webhooks

Webhooks / push notifications / CI triggers on push are **never** to be implemented. gyt is a standalone VCS — it does not integrate with external CI platforms or event systems. The built-in `gyt ci` command is the only CI mechanism. Do not design or propose any push-webhook, server-sent event, callback, or notification system. This is a hard boundary.

## CI Secrets & Env Vars

- Encrypted secrets: `.gyt/secrets/<name>` — AES-256-GCM, key at `~/.config/gyt/ci-key`
- Env vars: `.gyt/ci-env.toml` — plaintext, checkable
- Both injected as real env vars to shell CI scripts; secrets masked in output
- CLI: `gyt ci secret {init|set|list|remove}`, `gyt ci env {set|list|remove}`
