# gyt — A Modern Version Control System

**gyt** (pronounced "gift" with a 'g') is a modern, production-ready version control system designed for AI agents and human developers. It is written in Rust with zero `unsafe` code, uses BLAKE3 hashing, ed25519 signed commits, and a custom wire protocol.

> gyt is **not** Git-compatible. It has its own object format, wire protocol, and command set.

## Features

### Core VCS
- **Init / Add / Commit / Log / Diff / Show** — standard VCS operations
- **Branch / Switch / Merge / Rebase** — branch management with **real three-way merge**, conflict markers, merge commits
- **Cherry-pick / Reset / Restore / Stash / Worktree** — advanced workflow (cherry-pick and rebase use the same three-way engine; reset supports `--soft`, `--mixed`, `--hard`)
- **Reflog** — append-only audit log of HEAD/branch movement (`gyt reflog`)
- **Blame** — line-by-line authorship (`gyt blame <path>`)
- **Grep** — content search across history
- **Clean / RM** — file management
- **GC** — prune unreachable objects (keeps reflogs, stash, issues, PRs reachable)
- **GetTheFuckOutOfMyRepo** — permanently rewrite history to purge paths

### Cryptographic Signing
- **`gyt keygen`** — generate ed25519 signing keypair (stored at `~/.config/gyt/`)
- **`gyt commit --sign`** / `-S` — sign commits cryptographically
- **`gyt verify [<commit>]`** — verify a signed commit's signature
- **`sign_required = true`** in `.gyt/config.toml` — enforce signed commits client-side
- **Server-side enforcement**: when the server's repo config has `sign_required = true`, every commit reaching the server via `gyt push` is verified against the public keys listed in `<repo>.gyt/allowed_signers` (one 64-char hex pubkey per line, optionally followed by a label). Unsigned commits, commits with bad signatures, and commits signed by keys not in the allowed list are rejected.

All signing uses pure Rust `ed25519-dalek` — no OpenSSL, no libc dependency.

### Wire Protocol & Networking
Custom REST-like HTTP/1.1 protocol:
- `GET /<repo>/info/refs` — discover remote refs
- `POST /<repo>/objects/want` — batch-download objects
- `POST /<repo>/objects/have` — upload objects
- `POST /<repo>/refs/update` — update remote refs

### Issues, Discussions, and Pull Requests
- Issues live at `refs/issues/<N>`, discussions at the same prefix (they share the implementation and counter — only the `kind` field differs). PRs live at `refs/prs/<N>`. The ref points to a blob whose payload is canonical TOML; the encoder is `src/issues.rs::encode` and is shared between all three.
- Numbers are allocated under `repo.lock()` from `<gyt>/meta/issues_next`, so issues and discussions get globally unique numbers in the repo.
- The wire transport whitelists `refs/issues/*` and `refs/prs/*` (see `cmd::clone::is_user_visible_ref`) and `cmd::push::run` pushes them automatically; any other `refs/<prefix>/...` is dropped on clone by design.
- PRs add `source_ref`, `target_ref`, tri-state `state` (open / closed / merged), and two extra event kinds: `merge` and `ci_run`. `gyt pr ci-run <N>` runs the local `.gyt-ci/*.wasm` scripts through the same hardened sandbox and records the result as a `ci_run` event. Recording is local; *publishing* that event to the server requires an `rw` ACL entry.
- `gyt pr merge <N>` delegates to the existing merge engine (FF-only by default, `--no-ff` for a merge commit). The PR's `state` flips to `merged` once the target ref advances.

### Production Server (`gyt serve`)
- Multi-repository server from a `--repos` directory
- Optional **TLS** via `--cert` and `--key` flags. **TLS 1.3 only** — TLS 1.2 is disabled at both ends (server and built-in client), and the rustls `tls12` feature is not compiled in, so a downgrade is not possible. TLS 1.3 ticket-based session resumption is enabled by default (in-memory cache of `SESSION_CACHE_ENTRIES = 4096`), so repeat clones from the same client skip the full handshake.
- Optional **bearer-token authentication** via `--auth-token <secret>` (single token, rw on every repo), or **per-repo ACL** via `--auth-tokens <file>` (TSV of `<token>\t<repo-pattern>\t<rw|ro>`). The two are mutually exclusive.
- Optional `--signers <file>` — trusted `allowed_signers` shared across every hosted repo, overriding any per-repo `<gyt>/allowed_signers` so a write-capable pusher can't bootstrap their own key.
- Optional `--policy-config <file>` — server-side TOML overriding per-repo `[commit].sign_required` for the same anti-bootstrap reason.
- Optional `--webroot` for static file serving
- REST API dashboard for repo management
- **Hardened**: 256 MiB request body cap; bounded worker pool of 256 concurrent connections with **non-blocking accept** — when the pool is full the listener returns `503 Service Unavailable` with `Retry-After: 1` instead of stalling the accept thread; 30 s read+write timeouts per connection; 256-request cap per keep-alive connection so a single client can't pin a worker forever; per-worker `catch_unwind` so a panicked handler can't poison the shared shutdown mutex.
- **Fast-forward enforcement** on `POST /refs/update` unless the client passes `?force=1`
- **Signature verification** on push when the receiving repo opts in via `sign_required = true`
- **Audit log** at `<repo>.gyt/audit.log` recording every successful ref update with timestamp + actor
- **Push/GC coordination**: `wire_objects_have` and `gyt gc`'s prune phase both take `<repo>.gyt/objects.lock`, and `gc` additionally honors a 60 s mtime grace (`GC_GRACE_SECS`) on loose objects so a concurrent push can't lose data even against an older client that bypasses the lock.

### Built-in CI (`gyt ci`)
- Reads `.wasm` workflows from the `.gyt-ci/` directory. WASM is the **only** supported runtime — shell scripts and `--docker` were removed because neither can be confined to a useful sandbox on a multi-tenant host. `.sh` files in `.gyt-ci/` are surfaced as a loud deprecation warning and skipped; `--docker` is rejected with a migration error.
- **WASM sandbox** via wasmtime. WASI is not linked. `env`/`getenv` are not linked. Threads, SIMD, relaxed-SIMD, reference-types, multi-memory, and memory64 are disabled at the engine.
- **Operator-controlled `CiPolicy`**: the policy is set by CLI flags only. A `.gyt-ci/` script (which lives inside the cloned repo and is therefore not trusted) cannot widen the sandbox by any in-tree declaration.
  - Defaults: `repo_read` under the workdir except `.gyt/*`; `output_write` under the output dir only; no network; no subprocess; no env.
  - Widening flags: `--ci-read <PATH>`, `--ci-write <PATH>`, `--ci-repo-write`, `--ci-allow-network` (reserved vocabulary — currently a no-op because no socket hostcall is linked), `--ci-memory`, `--ci-fuel`, `--ci-time`.
  - Narrowing flags: `--ci-no-repo-read`, `--ci-no-output-write`.
  - `.gyt/*` is invisible to `read_file` / `write_file` even when `--ci-read` / `--ci-write` would otherwise include it.
- **Default caps** (sized for legitimate Android-class builds): 8 GiB memory, 1×10¹¹ wasm-instruction fuel, 4 h wall-time (enforced via `epoch_interruption` + a 1 Hz ticker), 1 GiB per `read_file` / `write_file`, 256 MiB cumulative log output per run, 8 MiB wasm stack.
- **Subcommands**:
  - `gyt ci --list` — enumerate available `.wasm` scripts.
  - `gyt ci --output <dir>` — redirect the output directory (defaults to `.gyt-ci-output`).
  - `gyt ci secret {init|set|list|remove}` — encrypted AES-256-GCM secret store at `.gyt/secrets/<name>` (key at `~/.config/gyt/ci-key`). Stored on disk only — WASM scripts read them as files; there is no env hostcall.
  - `gyt ci env {set|list|remove}` — plaintext CI env vars at `.gyt/ci-env.toml`. Same caveat: files, not env.

### Transport Security
- Plain HTTP requires `--insecure` flag (explicit opt-in)
- TLS via rustls (no OpenSSL)
- Bearer token authentication for write operations
- Wire protocol supports both clone and push over HTTP/TLS

## Quick Start

```bash
# Initialize a repository
cd my-project
gyt init

# Configure identity
gyt config --get user.name || echo "[user]\nname = \"Your Name\"\nemail = \"you@example.com\"" >> .gyt/config.toml

# Add files and commit
gyt add -A
gyt commit -m "Initial commit"

# Create and switch branches
gyt branch feature
gyt switch feature
echo "work" > new.txt && gyt add -A && gyt commit -m "Feature work"
gyt switch main

# View history
gyt log --oneline --graph --all
```

### Signed Commits

```bash
# Generate signing keypair
gyt keygen

# Sign commits
gyt commit --sign -m "Signed commit"

# Verify a commit
gyt verify HEAD

# Enforce signing for the repository
echo "[commit]\nsign_required = true" >> .gyt/config.toml
```

### Running a Server

```bash
# Basic server
gyt serve --listen 127.0.0.1:8080 --repos /srv/gyt

# With TLS
gyt serve --listen 0.0.0.0:443 --repos /srv/gyt \
  --cert /etc/certs/cert.pem --key /etc/certs/key.pem

# With authentication
gyt serve --listen 127.0.0.1:8080 --repos /srv/gyt \
  --auth-token my-secret-token

# Clone from a server
gyt clone --insecure http://127.0.0.1:8080/myrepo.gyt/

# Push to a remote
gyt push --insecure origin
```

### CI

```bash
# List available .wasm workflows
gyt ci --list

# Run CI with default policy (repo read-only minus .gyt/, output writable, no network)
gyt ci

# Widen the sandbox for a build cache
gyt ci --ci-read /var/cache/builds --ci-write /var/cache/builds

# Raise caps for a long Android build
gyt ci --ci-memory 16GB --ci-time 21600
```

## Architecture

### Object Storage
Objects are stored as content-addressed blobs in `.gyt/objects/XX/YYYYYY` where `XXYYYYYY` is the lowercase hex of the BLAKE3 hash of the raw payload. The raw object format is:

```
<kind> <size>\0<payload>
```

Supported kinds: `blob`, `tree`, `commit`, `tag`

On disk, the raw object is wrapped with XZ/LZMA compression behind a 5-byte header: a 4-byte magic prefix (`67 79 74 01`) followed by a 1-byte flag (bit 0 = xz). Files written before XZ-wrapping was added are still readable: any file without the magic prefix is decoded as raw bytes. XZ is the only compression used by gyt, both for on-disk objects and for wire-protocol packfiles.

### Commit Format

```
tree <hash>
parent <hash>
author <name> <email> <timestamp> <offset>
committer <name> <email> <timestamp> <offset>
signature <base64>
ai-assists <text>
reviewer <name> <email> <timestamp> <offset>

<message>
```

The `signature` line is a base64-encoded ed25519 signature over the commit payload *excluding* the signature line itself. The `ai-assists` and `reviewer` headers track AI collaboration metadata.

### Wire Protocol Pack Format

Objects are transferred in batches using a simple binary pack format. Each packfile is prefixed by a 1-byte version flag: `0x01` = uncompressed inner stream, `0x02` = XZ-compressed inner stream. The inner stream is a sequence of object records:

```
<4-byte little-endian name_len>
<name_len bytes of kind name (e.g., "commit")>
<4-byte little-endian payload_len>
<payload_len bytes>
<4-byte little-endian hash_len>
<hash_len bytes of BLAKE3 hash>
```

The XZ compression is provided by the `lzma-rust2` crate — the same compression used for on-disk loose objects.

### Ref Storage
Refs are stored as plain text files in `.gyt/refs/heads/` and `.gyt/refs/tags/`. Each file contains the 32-byte BLAKE3 hash of the target commit (lowercase hex). HEAD is `ref: refs/heads/main`.

## Commands

| Command | Description |
|---|---|
| `init` | Create a new repository |
| `add` | Stage files (`-A` stages removals too) |
| `status` | Show working tree status |
| `clean [-n]` | Remove untracked files (dry-run with `-n`) |
| `commit -m <msg> [--sign] [--allow-empty]` | Create a commit |
| `log [--oneline] [--graph] [--all]` | Show commit history |
| `show [--show-signature] <rev>` | Show a commit / tag / tree / blob |
| `diff [<rev>] [<rev>] [--cached\|--staged] [--stat]` | Show changes |
| `blame [<rev>] [--] <path>` | Line-by-line authorship |
| `branch [<name>] \| -d/-D <name> \| -m <old> <new>` | List, create, delete, rename branches |
| `switch [-c] <branch>` | Switch to a branch |
| `restore [--staged] [--worktree] [--source=<rev>] <path>...` | Restore files |
| `reset [--soft\|--mixed\|--hard [--force]] <rev>` | Reset HEAD (and optionally index / workdir) |
| `reflog [<ref>] [--all] [-n N]` | Show ref-movement history |
| `tag [<name> [<rev>]] \| -a -m <msg> \| -d <name> \| -l` | Create / list / delete tags |
| `rm [-f] <path>...` | Remove files |
| `grep <pattern> [<rev>]` | Search content |
| `gc` | Prune unreachable objects (keeps reflogs, stash, issues, PRs) |
| `cherry-pick <commit>` | Apply a commit's changes (three-way) |
| `rebase [--ff-only] [--abort] [--continue] <upstream>` | Replay commits onto upstream (three-way) |
| `merge [<rev>] [--ff-only] [--no-ff] [-m <msg>]` | Merge a ref into HEAD (real three-way) |
| `clone <url> [<dir>] [--insecure]` | Clone a repository |
| `fetch [<remote>] [<ref>] [--insecure] [--prune\|-p]` | Fetch from remote |
| `pull [<remote>] [--insecure]` | Fetch + merge |
| `push [<remote>] [<branch>] [--force\|--force-with-lease] [--insecure] [--all]` | Push to remote |
| `remote -v \| add <name> <url>` | List or add remotes |
| `config --list\|--get\|--set\|--unset [--global]` | Repository configuration |
| `stash {push\|pop\|apply\|list\|drop}` | Stash management |
| `worktree {add [-b <branch>] <path>\|list\|remove <path>}` | Worktree management |
| `keygen [--priv <path>] [--pub <path>]` | Generate ed25519 signing keypair |
| `verify [--pub <path>] [<commit-id>]` | Verify a signed commit |
| `issue {new\|list\|show\|comment\|close\|reopen\|label\|assign}` | Manage in-repo issues (`refs/issues/<N>`) |
| `discussion <subcommand>` | Same surface as `issue`, `kind=discussion` |
| `pr {new\|list\|show\|comment\|close\|reopen\|merge\|ci-run\|label\|assign}` | Manage in-repo pull requests (`refs/prs/<N>`) |
| `serve [--listen <a>] [--repos <d>] [--webroot <d>] [--cert/--key] [--auth-token/--auth-tokens] [--signers] [--policy-config]` | Start the production HTTP/TLS server |
| `ci [--list] [--output <dir>] [policy flags]` | Run sandboxed `.gyt-ci/*.wasm` workflows |
| `ci secret {init\|set <name>\|list\|remove <name>}` | Encrypted CI secret store |
| `ci env {set <name> <val>\|list\|remove <name>}` | Plaintext CI env vars |
| `getthefuckoutofmyrepo <path>...` | Permanently rewrite history to purge paths |

## Configuration

Config files are layered:
1. Global: `~/.config/gyt/config.toml` (or `$GYT_CONFIG_HOME/config.toml`) — defaults for every repo
2. Per-repo: `.gyt/config.toml` — overrides the global
3. Environment variables — override both

```toml
[user]
name = "Your Name"
email = "you@example.com"

[commit]
sign_required = true

[remote.origin]
url = "http://server:8080/myrepo.gyt/"
```

Set your identity once globally and skip the per-repo step:

```bash
mkdir -p ~/.config/gyt
printf '[user]\nname = "Your Name"\nemail = "you@example.com"\n' > ~/.config/gyt/config.toml
```

Environment variables:
- `GYT_AUTHOR_NAME` — override author name
- `GYT_AUTHOR_EMAIL` — override author email
- `GYT_CONFIG_HOME` — override the directory holding the global config
- `GYT_SIGNING_KEY` — override signing private key path
- `GYT_SIGNING_PUB` — override signing public key path
- `RUST_BACKTRACE=1` — enable backtrace on errors

## Building

Dependencies: Rust 1.96+. All other deps (including `lzma-rust2` for XZ compression of objects and packfiles) are pulled in by Cargo and pinned to exact versions.

```bash
# Debug build
cargo build --all-features

# Release build (optimized for size)
cargo build --release --all-features

# Lint (strict mode)
cargo clippy --all-features -- -D warnings

# Test
cargo test --all-features -- --test-threads=1
```

The release profile applies: LTO (thin), `codegen-units=1`, symbol stripping.

## Testing

```bash
# Unit + integration tests
cargo test --all-features -- --test-threads=1

# Wire protocol integration tests (spawns server, runs clone/push/fetch/pull)
cargo test --test wire_integration -- --test-threads=1 --nocapture

# Comprehensive smoke test (requires release build)
cargo build --release --all-features
bash tests/smoke_comprehensive.sh
```

### Test Coverage

Roughly 790 `#[test]` functions across the workspace at last count. Approximate split:

- **In-tree unit tests** (`#[cfg(test)]` modules under `src/`): ~298
- **`tests/e2e.rs`** — end-to-end CLI tests driving the real binary: ~237
- **`tests/data_integrity.rs`** — corruption / data-loss invariants: 145 subprocess-driven tests (141 run by default; 4 long-running soak tests are marked `#[ignore]` and opt in via `--ignored`)
- **`tests/internals.rs`** — internal-state assertions: 49
- **`tests/issues.rs`** — in-repo issues / discussions: 17
- **`tests/prs.rs`** — in-repo pull requests including the `rw`-gated `ci_run` flow: 13
- **`tests/ci_wasm_sandbox.rs`** + **`tests/ci_wasm_policy.rs`** — WASM sandbox & policy enforcement: 12 + 9
- **`tests/server_hardening.rs`** — pool exhaustion, panic isolation, request caps: 5
- **`tests/gc_race.rs`** — gc vs. push race + issue/PR reachability: 5
- **`tests/wire_integration.rs`** — clone, push/fetch/pull cycle, multi-branch: 5
- **Smoke tests** (`tests/smoke_comprehensive.sh`): an end-to-end shell script covering init, add, commit, branch, switch, diff, log, tag, merge, rebase, cherry-pick, remote, clone, push, fetch, pull.

## Security

- `#![forbid(unsafe_code)]` — zero unsafe code in the entire codebase
- No libc dependency — pure Rust throughout
- All dependencies pinned to exact versions (no range matching)
- TLS via rustls (no OpenSSL, no C libraries). TLS 1.3 only — the `tls12` rustls feature is not enabled, and both client and server pin `&[&rustls::version::TLS13]` at handshake-time.
- ed25519 signing with `ed25519-dalek` (pure Rust)
- WASM CI sandbox: strict filesystem isolation (repo read, output read+write, no network)
- Token-based authentication for server write operations
- Plain HTTP requires explicit `--insecure` flag

## CI System

gyt includes a built-in CI runner that does not require external CI infrastructure:

1. Place `.wasm` workflows in `.gyt-ci/`. `.sh` and `--docker` are deliberately not supported (see the "Built-in CI" feature section above for the security rationale).
2. Run `gyt ci` to execute all workflows under the default `CiPolicy`.
3. Use `gyt ci --list` to enumerate available workflows.
4. Widen the sandbox or raise caps with `--ci-read`, `--ci-write`, `--ci-repo-write`, `--ci-memory`, `--ci-fuel`, `--ci-time`.

WASM workflows run in a wasmtime sandbox whose only host functions are `log`, `read_file`, and `write_file`. WASI, `env`/`getenv`, threads, SIMD, relaxed-SIMD, reference-types, multi-memory, and memory64 are disabled. No network hostcall is linked — `--ci-allow-network` is reserved vocabulary today.

## License

GPL-3.0-or-later

---

*gyt — a modern VCS built for AI agents and humans.*
