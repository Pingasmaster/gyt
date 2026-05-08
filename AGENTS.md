# AGENTS.md — gyt Project Guide for AI Agents

This file is read by AI agents (including Hermes, Claude Code, etc.) when working on gyt. It encodes the project's design philosophy, conventions, and hard-won lessons so agents don't have to rediscover them.

## Project Identity

gyt is a **safe subset of Git** for both humans and AI agents. Not a one-to-one clone. Written in Rust.

## Golden Rules (Never Violate)

### Safety First
- **No hooks, no pre-push scripts, no arbitrary code execution.** gyt must be safe in untrusted environments (AI agents, CI, shared workspaces).
- **No unsafe code.** The crate has `#![forbid(unsafe_code)]` — do not remove it.
- **No interactive prompts.** Every command must work identically regardless of who (human or agent) issues it. No `[y/N]`, no pager, no editor popup.
- **`reset --hard` is blocked.** Redirect to `restore` or `switch` instead.
- **`branch -d` must refuse to delete unmerged branches** (like `git branch -d` does). Only `-D` (force) bypasses this check.

### Correctness
- **All dependencies are pinned to exact versions** (`=x.y.z` in Cargo.toml). No version ranges, no `^` — prevents supply chain attacks.
- **BLAKE3 content addressing** (32 bytes). Objects are identified by the hash of `"<kind> <size>\0<payload>"`.
- **Strict clippy** — `deny(clippy::all)` on correctness and suspicious lints. The `[lints.clippy]` block in Cargo.toml has explicit allow-lists for style/restriction lints only.
- **`ObjectKind::as_str(self)` takes `self` by value** (not `&self`). `ObjectKind` derives `Copy`, so callers don't notice. Keep it that way.

### Honesty (The Golden Honesty Rule)
- After every edit, re-run `cargo clippy --all-features -- -D warnings` and `cargo test --all-features`. Never claim something works without verification.
- **`#[allow(dead_code)]` is ONLY for scaffolding** that is a clear building block for a future feature. No other dead_code exceptions. Every dead_code allow must have an obvious justification (e.g., "public API for future commit phase").
- **`#[allow(clippy::...)])`** is only for:
  - `items_after_statements` — Rust's item-ordering rules force statics after `let` bindings.
  - `only_used_in_recursion` — clippy false positive for recursive functions.
  - `many_single_char_names` — Myers' diff algorithm uses `n`, `m`, `k`, `d`, `x`, `y` by convention.
  - `collapsible_if` is NEVER needed — edition 2024 has stable let-chains (`if let ... && ...`).
  - `manual_let_else` is NEVER needed — `let else` is stable since Rust 1.65.
- No `todo!()` or `unimplemented!()` in production code. If a feature is unfinished, return `GytError::Unsupported` with a clear message telling the user what to use instead.

### 3-Way Merge (Do Not Implement)
- **No three-way merges.** Only fast-forward (`--ff-only`). Complex merge conflicts are blocked rather than attempted. This is intentional — three-way merge logic is error-prone and conflicts require human intervention, which violates the safety and agent-friendly design goals.
- **No rebase when branches have diverged.** Same reason — would require three-way logic.

## Architecture Conventions

### Command Structure
Each command lives in `src/cmd/<name>.rs` with:
- `pub fn run(args: &[String]) -> Result<()>` — entry point
- `fn run_in(repo: &Repo, args: &[String]) -> Result<()>` — the actual logic (testable by passing a repo directly)
- Tests in `#[cfg(test)] mod tests { ... }` at the bottom

### Error Handling
All functions return `Result<T, GytError>` from `src/errors.rs`.

### Testing
- Use `crate::cmd::test_support::TestRepo` for integration tests.
- Use `crate::cmd::util::test_helpers::{lock, tmp_dir}` for parallel-safe temp directories.
- `TestRepo.new("prefix")` creates a temp repo. `.open()` gets a `Repo`. `.commit_next(&[...])` creates incremental commits.

### Networking
- Hand-rolled HTTP/1.1 (no reqwest).
- rustls for TLS (no openssl).
- gyt wire protocol: `/info/refs`, `/objects/want`, `/objects/have`, `/refs/update`.
- Test server: `net/server_stub.rs` is an in-memory server only used in `#[cfg(test)]`.

### Config & Dependencies
- No serde — hand-rolled JSON in `net/api.rs` for the REST API.
- No serde — hand-rolled TOML config parsing in `config.rs`.
- The `include_dir` macro embeds `.gytignore` templates.

## Known Design Decisions (Not Bugs)

| Topic | Decision | Why |
|---|---|---|
| Packfiles | None — loose objects only | Simpler, more transparent for agents |
| Reflog | None | Simple ref storage |
| Submodules | No | Too complex for v1 |
| Signed commits | No | GPG is optional infrastructure |
| Garbage collection | No | Not needed without packfiles |
| `merge` | `--ff-only` only | See "3-Way Merge" above |
| `rebase` | FF-only (no three-way) | See "3-Way Merge" above |
| `reset --hard` | Blocked | Use `restore` or `switch` instead |

## Version & Toolchain
- Edition 2024 (`edition = "2024"`)
- Rust version 1.96+ (`rust-version = "1.96"`)
- This means `let_chains` (`if let ... && ...`) is stable — use it instead of `#[allow(clippy::collapsible_if)]`.

## Build & Test Commands
```bash
cargo build --all-features
cargo clippy --all-features -- -D warnings
cargo test --all-features
```

## Features Not to Implement (Slop)
- `bisect`, `blame`, `archive`, `format-patch`, `notes`, `replace`
- `shortlog`, `rerere`, `describe`
- Interactive anything (`rebase -i`, `add -p`)
- `submodules`, `subtree`
- LFS, annex
- `gc`, `repack`, `fsck`
- pre-commit hooks, post-receive hooks (any hooks)
- Signed/annotated GPG features
