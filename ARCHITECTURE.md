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
│   │   ├── serve.rs         # HTTP server
│   │   ├── ci.rs            # Built-in CI runner (gyt ci)
│   │   ├── ci_env.rs        # CI env-var store (.gyt/ci-env.toml)
│   │   ├── ci_secret.rs     # Encrypted CI secret store (AES-256-GCM)
│   │   ├── keygen.rs        # ed25519 keypair generation
│   │   ├── signing.rs       # Commit-signing helpers
│   │   ├── verify.rs        # Signature verification
│   │   ├── util.rs          # Shared utilities
│   │   ├── test_support.rs  # Test helpers
│   │   └── getthefuckoutofmyrepo.rs  # Safety utility
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
│   ├── ci_wasm.rs           # wasmtime sandbox for WASM CI workflows
│   ├── fuzz.rs              # Fuzzing harnesses
│   ├── config.rs            # .gyt/config parser
│   ├── diff.rs              # Myers diff algorithm
│   ├── ignore.rs            # .gytignore matching
│   ├── index.rs             # GYTI index format
│   ├── refs.rs              # Ref read/write/resolve
│   ├── repo.rs              # Repository opener
│   ├── workdir.rs           # Working tree operations
│   ├── errors.rs            # Unified error types
│   ├── hash.rs              # BLAKE3 hashing
│   ├── fs_util.rs           # Filesystem utilities
│   └── term.rs              # Terminal color helpers
├── tests/
│   ├── smoke_comprehensive.sh  # End-to-end smoke test
│   └── wire_integration.rs     # Wire-protocol integration tests
├── Cargo.toml               # Dependencies + clippy config
├── check.sh                 # Full CI pipeline
└── rust-toolchain.toml      # Rust edition/year pinning
```

## Development phases

The project was built incrementally across multiple phases:

| Phase | Scope | Description |
|-------|-------|-------------|
| **1** | Bootstrap | Project skeleton, object store, BLAKE3 hashing |
| **2** | Objects | Blob/tree/commit/tag codecs, object store |
| **3a** | Index + Refs | GYTI index format, ref read/write/resolve |
| **3b** | .gytignore | Ignore file parser and matcher |
| **3c** | Workdir | File walking, blob hashing, conflict detection |
| **4a** | Core commands | init, add, commit, status, log, show, diff |
| **4b** | Branch ops | branch, switch, restore, reset, tag |
| **4c** | Stash + worktree | Stash pop/list/push/drop, secondary worktrees |
| **5** | (skipped) | — |
| **6a** | HTTP client | Hand-rolled HTTP/1.1 client, rustls TLS, wire protocol |
| **6b** | Network commands | clone, fetch, pull, push |
| **7** | Smoke test | End-to-end integration test script |
| **8** | Server + merge | HTTP server (serve), merge --ff-only, cherry-pick, rebase, grep |
| **8+** | Refinements | serve.rs refactor, test isolation, compress API, let_chains cleanup |

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
- **Smoke tests**: `tests/smoke.sh` runs the full build and basic CLI commands
- **Test harness**: Shared `test_support` module provides `init::init_at(&dir)`, `test_repo()`, and a global file lock for parallel test safety

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
