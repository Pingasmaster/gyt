# Architecture

This document describes the architecture, design decisions, and development history of gyt.

## Overview

gyt is a minimal, modern version-control system written in Rust. It is designed from scratch — not a Git clone, not Git-compatible. It has its own wire protocol, its own object format (BLAKE3, not SHA-1), and its own index format (GYTI). The design is focused on safety for both human and AI agent use.

### Key design properties

- **Single binary**: The entire project compiles to one binary with no runtime dependencies.
- **No unsafe code**: `#![forbid(unsafe_code)]` at the crate root.
- **Strict clippy**: `deny(clippy::all)` on correctness and suspicious lints.
- **BLAKE3 hashing**: 32-byte content-addressed object store.
- **Hand-rolled JSON**: No serde dependency for the REST API.

## Directory structure

```
gyt/
├── src/
│   ├── main.rs              # Entry point, dispatches to cli
│   ├── cli.rs               # Command-line parsing and dispatch
│   ├── merge3.rs            # Three-way merge engine (line + tree level)
│   ├── reflog.rs            # Append-only ref-movement log
│   ├── cmd/                 # Command implementations
│   │   ├── mod.rs           # Module declarations
│   │   ├── init.rs          # gyt init
│   │   ├── add.rs           # Stage files into index
│   │   ├── status.rs        # Working tree status
│   │   ├── clean.rs         # Remove untracked files
│   │   ├── commit.rs        # Create commit from index
│   │   ├── log.rs           # Walk commit history
│   │   ├── show.rs          # Display commit/object
│   │   ├── diff.rs          # Myers diff CLI wrapper
│   │   ├── blame.rs         # Line-by-line authorship
│   │   ├── branch.rs        # Branch management
│   │   ├── switch.rs        # Change HEAD to another branch
│   │   ├── restore.rs       # Restore files from index
│   │   ├── reset.rs         # Reset HEAD/index/workdir
│   │   ├── rm.rs            # Remove files from index
│   │   ├── tag.rs           # Create tags
│   │   ├── cherry_pick.rs   # Apply a commit's changes
│   │   ├── rebase.rs        # Replay commits onto upstream (three-way)
│   │   ├── merge.rs         # Real three-way merge with conflict markers
│   │   ├── reflog_cmd.rs    # `gyt reflog`
│   │   ├── pull.rs          # Fetch + merge
│   │   ├── push.rs          # Push to remote
│   │   ├── clone.rs         # Clone from remote
│   │   ├── fetch.rs         # Fetch objects from remote
│   │   ├── remote.rs        # Remote listing/management
│   │   ├── stash.rs         # Stash/unstash working changes
│   │   ├── worktree.rs      # Secondary worktrees
│   │   ├── grep_cmd.rs      # Pattern search
│   │   ├── gc.rs            # Garbage collect unreachable objects
│   │   ├── config_cmd.rs    # Read/list repository config
│   │   ├── serve.rs         # HTTP server CLI / flag parser
│   │   ├── ci.rs            # Built-in CI runner (WASM-only; policy flag parsing)
│   │   ├── ci_env.rs        # CI env-var store (.gyt/ci-env.toml)
│   │   ├── ci_secret.rs     # Encrypted CI secret store (AES-256-GCM)
│   │   ├── issue.rs         # `gyt issue` and `gyt discussion` (refs/issues/<N>)
│   │   ├── pr.rs            # `gyt pr` — pull requests (refs/prs/<N>)
│   │   ├── keygen.rs        # ed25519 keypair generation
│   │   ├── signing.rs       # Commit-signing helpers
│   │   ├── verify.rs        # Signature verification
│   │   ├── util.rs          # Shared utilities
│   │   ├── test_support.rs  # Test helpers (`#[cfg(test)]`)
│   │   └── getthefuckoutofmyrepo.rs  # Permanent history rewrite
│   ├── net/                 # Networking
│   │   ├── mod.rs           # Re-exports
│   │   ├── http.rs          # HTTP/1.1 client (hand-rolled)
│   │   ├── tls.rs           # rustls TLS client
│   │   ├── protocol.rs      # gyt wire protocol codec (XZ-compressed packfiles)
│   │   ├── router.rs        # REST URL routing
│   │   ├── server.rs        # Production HTTP server
│   │   ├── server_stub.rs   # Test-only in-memory server
│   │   ├── api.rs           # JSON DTOs (hand-rolled)
│   │   ├── refs_policy.rs   # FF + signature enforcement on refs/update
│   │   └── transport_tests.rs  # Client/server integration tests
│   ├── object/              # Object store
│   │   ├── mod.rs           # Object types and enum
│   │   ├── blob.rs          # Blob codec
│   │   ├── tree.rs          # Tree codec
│   │   ├── commit.rs        # Commit codec
│   │   ├── tag.rs           # Tag codec
│   │   └── store.rs         # Loose object storage
│   ├── compress.rs          # Object on-disk wrapping with XZ/LZMA (raw passthrough fallback for unwrapped files)
│   ├── ci_wasm.rs           # wasmtime sandbox + CiPolicy for WASM CI workflows
│   ├── fuzz.rs              # Fuzzing harnesses
│   ├── config.rs            # .gyt/config parser
│   ├── diff.rs              # Myers diff algorithm
│   ├── ignore.rs            # .gytignore matching
│   ├── index.rs             # GYTI index format
│   ├── issues.rs            # Canonical TOML codec for issues/discussions (shared with PRs)
│   ├── prs.rs               # PR-specific decode (state, source_ref, target_ref, ci_run/merge events)
│   ├── refs.rs              # Ref read/write/resolve
│   ├── repo.rs              # Repository opener / locking
│   ├── workdir.rs           # Working tree operations
│   ├── errors.rs            # Unified error types
│   ├── hash.rs              # BLAKE3 hashing
│   ├── fs_util.rs           # Filesystem utilities (atomic_write, dir fsync)
│   └── term.rs              # Terminal color helpers
├── tests/
│   ├── smoke_comprehensive.sh  # End-to-end smoke test
│   ├── e2e.rs                  # End-to-end CLI tests
│   ├── wire_integration.rs     # Wire-protocol integration tests
│   ├── internals.rs            # Internal-state assertions
│   ├── data_integrity.rs       # Corruption / data-loss invariants (145 tests; 4 marked #[ignore] soak)
│   ├── gc_race.rs              # gc vs. push race; issue/PR reachability
│   ├── issues.rs               # In-repo issues / discussions
│   ├── prs.rs                  # In-repo pull requests + ci_run ACL gate
│   ├── ci_wasm_sandbox.rs      # wasmtime sandbox enforcement
│   ├── ci_wasm_policy.rs       # CiPolicy field-by-field coverage
│   └── server_hardening.rs     # Pool exhaustion, panic isolation, request caps
├── Cargo.toml               # Dependencies + clippy config
├── check.sh                 # Full CI pipeline
└── rust-toolchain.toml      # Rust edition/year pinning
```

## Recent additions

Use `git log` for the authoritative timeline. The list below captures the load-bearing additions beyond the original bootstrap (objects → refs → workdir → core commands → branch ops → stash/worktree → HTTP client + wire → network commands → smoke test → server + merge engine):

- **WASM-only CI sandbox** — `src/ci_wasm.rs` + `src/cmd/ci.rs`. Operator-controlled `CiPolicy` set by CLI flags only; defaults are conservative (`repo_read` minus `.gyt/*`, `output_write` only, no network/subprocess/env). Default caps: 8 GiB memory, 1×10¹¹ wasm fuel, 4 h wall-time, 1 GiB per file, 256 MiB cumulative log, 8 MiB wasm stack. `--docker` and `.sh` execution were deliberately removed.
- **In-repo issues, discussions, and pull requests** — `src/issues.rs`, `src/prs.rs`, `src/cmd/issue.rs`, `src/cmd/pr.rs`. Stored at `refs/issues/<N>` / `refs/prs/<N>`, shared counter at `<gyt>/meta/issues_next`, whitelist-pushed by `cmd::clone::is_user_visible_ref`.
- **Server worker pool & non-blocking accept** — `src/net/server.rs` enforces `MAX_WORKERS = 256` with `try_acquire`-based admission and a `503 Service Unavailable` + `Retry-After: 1` response when the pool is exhausted. `MAX_REQUESTS_PER_CONN = 256` caps a single keep-alive client. Worker panics are caught with `catch_unwind` so the shared shutdown mutex can't be poisoned.
- **TLS 1.3 only + session resumption** — `src/net/tls.rs` pins client and server to `&[&rustls::version::TLS13]` and the `tls12` rustls feature is off in `Cargo.toml`, so the binary cannot speak TLS 1.2 at all. `Ticketer::new` enables TLS 1.3 ticket resumption with an in-memory cache of `SESSION_CACHE_ENTRIES = 4096`.
- **Push/GC race closure** — `<gyt>/objects.lock` is taken by `wire_objects_have` for the duration of its loose-object writes and by `gyt gc`'s prune phase (acquired after the reachability walk). A 60 s `GC_GRACE_SECS` mtime grace protects loose objects written by older clients. `compute_reachable` seeds `refs/issues/*` and `refs/prs/*`.
- **Server-side trust hardening** — `--auth-tokens <file>` TSV ACL (per-repo `rw`/`ro` patterns), `--signers <file>` (shared `allowed_signers` overriding per-repo), `--policy-config <file>` (server-side override for `[commit].sign_required`). All three close the "pusher edits their own trust config" loophole.
- **URL-embedded bearer tokens** — `https://<token>@host/repo` is parsed by `src/net/http.rs` into an `Authorization: Bearer <token>` header so real ACL flows work on the wire.

## Object format

### Repository layout

```
<repo>/
├── .gyt/
│   ├── HEAD              # Symbolic ref: ref: refs/heads/main
│   ├── config            # TOML config file
│   ├── objects/          # Loose objects: XX/YYYY...
│   ├── refs/
│   │   ├── HEAD          # Detached HEAD target
│   │   ├── heads/        # Branch refs
│   │   └── tags/         # Tag refs
│   ├── index             # GYTI v1 index
│   └── stash             # Stash refs (refs/stash chain)
└── (working tree)
```

### Object encoding

Each object is stored as `"<kind> <size>\0<payload>"` where:
- `<kind>` is one of: `blob`, `tree`, `commit`, `tag`
- `<size>` is the uncompressed payload byte count
- `\0` is a NUL separator
- on disk, the whole `<kind> <size>\0<payload>` framing is wrapped with an XZ/LZMA stream behind a 5-byte header: 4-byte magic (`67 79 74 01`) + 1-byte flag (bit 0 = xz). Files without the magic prefix are read as raw bytes (legacy fallback)

The filename is the BLAKE3 hash of the raw (uncompressed) payload, split into a 2-character prefix directory and the remaining suffix.

### Index format (GYTI v1)

```
Version (u32 LE)
Number of entries (u32 LE)
[Entry] × N
  CTIME seconds (u64 LE)
  CTIME nanoseconds (u32 LE)
  MTIME seconds (u64 LE)
  MTIME nanoseconds (u32 LE)
  File size (u32 LE)
  Mode (u16 LE)
  Hash (32 bytes)
  Path length (u16 LE)
  Path (variable)
Padding to 8-byte alignment
```

The version number includes a magic placeholder in production builds.

## Wire protocol

The gyt wire protocol is a minimal binary protocol over HTTP, used by clone/fetch/push:

1. `GET /info/refs` → returns ref names and hashes (similar to Git's info/refs)
2. `POST /objects/want` → client sends "want" list, server responds with pack data
3. `POST /objects/have` → client confirms which objects it already has
4. `POST /refs/update` → client requests ref updates (with optional `?force=1`)

The protocol codec (`net/protocol.rs`) handles encoding/decoding of all wire format messages.

Packfiles (the body of `objects/want` responses and `objects/have` uploads) carry a 1-byte version prefix: `0x01` = uncompressed inner stream, `0x02` = XZ-compressed inner stream. See `src/net/protocol.rs`. XZ is the only compression used by gyt — both for on-disk loose objects and for wire-protocol packfiles — provided by the `lzma-rust2` crate.

### Server hardening

`src/net/server.rs` enforces:

- `MAX_BODY_BYTES = 256 MiB` — request body cap, refused before allocation.
- `MAX_WORKERS = 256` — concurrent connections. Permits are acquired with `try_acquire`; if the pool is full the listener sends `POOL_FULL_RESPONSE` (`HTTP/1.1 503 Service Unavailable` with `Retry-After: 1` and `Connection: close`) and drops the socket rather than wedging the accept loop on a `Condvar`.
- `MAX_REQUESTS_PER_CONN = 256` — keep-alive cap; closes the connection after this many requests so a single client can't pin a worker forever.
- 30 s read+write timeouts per connection.
- Every worker runs inside `catch_unwind(AssertUnwindSafe(...))` so a panicked handler can't poison the shared `state.shutdown` mutex.
- `--signers <file>` and `--policy-config <file>` are validated at startup: if they were specified but the file doesn't exist, the server refuses to start rather than silently falling back to per-repo trust.

### TLS 1.3 only + session resumption

`src/net/tls.rs` configures both the client and the server with `builder_with_protocol_versions(&[&rustls::version::TLS13])`. The rustls `tls12` cargo feature is also off in `Cargo.toml`, so TLS 1.2 isn't even linked into the binary — a malicious peer cannot negotiate a downgrade, and an operator cannot accidentally re-enable 1.2 through configuration. A misconfigured peer fails fast at the ClientHello/ServerHello stage with a protocol-version alert.

TLS 1.3 ticket-based session resumption is enabled (`Ticketer::new`). `SESSION_CACHE_ENTRIES = 4096` keeps the in-memory cache rustls uses for ticket bookkeeping. Resumption skips the full certificate exchange and asymmetric handshake on repeat clones from the same client; a server cluster needs sticky load-balancing for resumption to fire across nodes.

## Error model

All functions return `Result<T, GytError>` where `GytError` is an enum with variants:

- `InvalidArgument` — bad user input
- `Repo` — repository structure issue
- `Refs` — ref read/write/resolve failure
- `Net` — network communication failure
- `Object` — object store issue
- `Parse` — parsing failure (config, wire protocol, etc.)
- `NotFound` — missing file/ref/object
- `Unsupported` — feature not implemented in v1

## Testing strategy

- **Unit tests**: Inline in every module via `#[cfg(test)]` modules
- **Integration tests**: `net/transport_tests.rs` spins up a server stub, tests HTTP client against it
- **Smoke tests**: `tests/smoke_comprehensive.sh` runs the full build and basic CLI commands
- **End-to-end CLI**: `tests/e2e.rs` drives the real binary as a subprocess
- **Data-integrity / corruption**: `tests/data_integrity.rs` — 145 subprocess-driven tests asserting no-loss/no-corruption invariants on bit flips, truncation, concurrent writes, smuggling attempts, lock semantics, push/clone round trips, packs, and signing. Of those 145, 141 run by default; 4 long-running soak tests are marked `#[ignore]` and opt in via `--ignored`.
- **In-repo issues / PRs**: `tests/issues.rs` (17 tests) and `tests/prs.rs` (13 tests, including `pr_ro_client_blocked_from_pushing_ci_run_event`) — number allocation, transport whitelist, state transitions, ACL gate on `ci_run` event publication.
- **CI sandbox**: `tests/ci_wasm_sandbox.rs` (12 tests) pins wasmtime engine config and hostcall surface; `tests/ci_wasm_policy.rs` (9 tests) exercises every `CiPolicy` field including the `.gyt/*` exclusion.
- **GC race**: `tests/gc_race.rs` covers the `objects.lock` + grace-window invariants and the issue/PR reachability seeds.
- **Server hardening**: `tests/server_hardening.rs` covers pool exhaustion (503 + `Retry-After`), per-connection request cap, and panic isolation.
- **Test harness**: Shared `test_support` module provides `init::init_at(&dir)`, `test_repo()`, and a global file lock for parallel test safety

## Canonical-encoding gate on the wire

`POST /{repo}/objects/have` re-decodes every commit, tag, and tree it
receives and re-encodes the decoded form; if it doesn't match the
incoming bytes byte-for-byte, the object is skipped. Without this
gate a pusher could craft an object whose BLAKE3 hash matches its
stored bytes but whose internal structure (out-of-order commit
headers, unsorted tree entries) breaks downstream readers that
assume canonical layout.

## Dependencies

| Crate | Purpose | Pinned? |
|-------|---------|---------|
| blake3 | Content hashing | Yes (exact version) |
| rustls | TLS for HTTP client | Yes |
| rustls-pki-types | TLS types | Yes |
| webpki-roots | Root certificates | Yes |
| lzma-rust2 | XZ compression (objects on disk + wire packfiles) | Yes |
| wasmtime / wasmtime-wasi | WASM sandbox for `gyt ci` | Yes |
| ed25519-dalek | Commit signing | Yes |
| rand | Key generation entropy | Yes |
| aes-gcm | CI secret encryption | Yes |
| include_dir | Include-dir macro | Yes |

All dependencies are pinned to exact versions for supply-chain safety.
