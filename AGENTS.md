# gyt - Agent Guidelines

## Core Rule: Update Docs After Every Code Change

Whenever you finish a code change and are ready to commit, you MUST also update the relevant documentation (README.md, ARCHITECTURE.md, etc.) to reflect the change. Documentation is a first-class deliverable, not an afterthought.

## Project Overview

gyt (pronounced "gift" but with a 'g') is a modern version control system designed for AI agents and humans. It is NOT Git-compatible — it uses its own wire protocol, object format, and command set. It is designed to be production-ready: secure, fast, and auditable.

## Key Concepts

- **Object format**: `<kind> <size>\0<payload>` with BLAKE3 hashing
- **Wire protocol**: Custom REST-like endpoints (info/refs, objects/want, objects/have, refs/update)
- **Storage**: Loose objects in `.gyt/objects/XX/YYYYYY`. The raw object is `<kind> <size>\0<payload>` framing; on disk it is wrapped with XZ/LZMA compression (via the `lzma-rust2` crate). Files written before XZ-wrapping was added still decode (raw-passthrough fallback when the magic prefix is absent).
- **Signing**: ed25519-dalek cryptographically signed commits. The server enforces signatures when its repo config has `sign_required = true` — every commit hitting `POST /refs/update` is verified against `<repo>.gyt/allowed_signers`.
- **Merge**: Real three-way merge (file-level Myers + tree-level reconciliation) in `src/merge3.rs`. Used by `merge`, `cherry-pick`, and `rebase`. Conflicts produce standard `<<<<<<<` / `=======` / `>>>>>>>` markers and leave `.gyt/MERGE_HEAD` (or `CHERRY_PICK_HEAD`, `REBASE_HEAD`).
- **Reflog**: Every HEAD/branch movement records an entry under `<gyt>/logs/<refname>`; `gyt reflog` reads it back.
- **CI**: Built-in `gyt ci` command. **WASM is the only supported runtime** — shell scripts and `--docker` were deliberately removed because neither can be confined to a useful sandbox on a multi-tenant host (`.sh` files in `.gyt-ci/` are warned about and skipped; `--docker` is rejected with a migration error). The wasmtime sandbox in `src/ci_wasm.rs` runs with an operator-controlled `CiPolicy` set by CLI flags only — a `.gyt-ci/` script (which lives inside the cloned repo) cannot widen the sandbox by any in-tree declaration. See `CLAUDE.md` for the full policy, caps, and flag set.

## Testing

- Always run `cargo test --all-features -- --test-threads=1` before committing
- Run `timeout 30 bash tests/smoke_comprehensive.sh` for end-to-end smoke test
- Wire protocol integration tests are in `tests/wire_integration.rs`

## Build & lint

```bash
cargo build --release --all-features
cargo clippy --all-features --all-targets -- -D warnings
```

## Clippy policy

We run with **every clippy group at `deny`** — `correctness`, `suspicious`,
`complexity`, `perf`, `style`, `pedantic`, `nursery`, and `cargo`. The full
configuration lives in the workspace `[lints.clippy]` table in `Cargo.toml`.
The only escape hatches are the `allow` entries listed there, each
preceded by a one-line reason describing why enforcement would harm
clarity or duplicate effort handled elsewhere.

Rules for contributors:

- **Default action is to fix.** If clippy fires, change the code, not the
  lint level.
- **Per-line/per-item `#[allow(clippy::xyz)]` requires a `// Reason:`
  comment** that names the *specific* situation the allow covers — not a
  generic "false positive" handwave. Bad reasons get rejected at review.
- **No module-wide `#![allow(...)]`** for clippy lints. If a whole module
  legitimately needs a relaxation, raise it as a new entry in the
  Cargo.toml allowlist with the same one-line justification.
- **Adding a new entry to the Cargo.toml allowlist requires its own
  one-line reason and reviewer approval.** Don't bundle this into an
  unrelated PR.
- **CI gates this.** `cargo clippy --all-features --all-targets -- -D
  warnings` must be clean on every push, and so must `cargo test
  --all-features -- --test-threads=1`.

The reasoning behind such a strict policy: this is a version-control
tool that handles user history. Subtle correctness bugs (loop counters
that desync from data, `match` arms that quietly do nothing, `Drop`
ordering surprises around locks) cause silent data loss. Catching them
at lint time is cheaper than catching them in `git bisect`.

## Branch Strategy

- `main` is the primary branch
- Features are developed on branches named after the feature
- No force-pushing to main

## Policy: No Push Webhooks

Webhooks / push notifications / CI triggers on push are **never** to be implemented. gyt is a standalone VCS — it does not integrate with external CI platforms or event systems. The built-in `gyt ci` command is the only CI mechanism. Do not design or propose any push-webhook, server-sent event, callback, or notification system. This is a hard boundary.

## CI Secrets & Env Vars

- Encrypted secrets: `.gyt/secrets/<name>` — AES-256-GCM, key at `~/.config/gyt/ci-key`
- Env vars: `.gyt/ci-env.toml` — plaintext, checkable
- Stored on disk under `.gyt/` only. WASM scripts must read them as files via the `read_file` hostcall — there is no env (`getenv`) hostcall linked into the sandbox, so secrets can never be injected as environment variables.
- CLI: `gyt ci secret {init|set|list|remove}`, `gyt ci env {set|list|remove}`
