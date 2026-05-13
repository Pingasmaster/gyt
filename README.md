# gyt — A Modern Version Control System

**gyt** (pronounced "gift" with a 'g') is a modern, production-ready version control system designed for AI agents and human developers. It is written in Rust with zero `unsafe` code, uses BLAKE3 hashing, ed25519 signed commits, and a custom wire protocol.

> gyt is **not** Git-compatible. It has its own object format, wire protocol, and command set.

## Features

### Core VCS
- **Init / Add / Commit / Log / Diff / Show** — standard VCS operations
- **Branch / Switch / Merge / Rebase** — branch management
- **Cherry-pick / Reset / Restore / Stash / Worktree** — advanced workflow
- **Grep** — content search across history
- **Clean / RM** — file management
- **GetTheFuckOutOfMyRepo** — bulk repository metadata cleanup

### Cryptographic Signing
- **`gyt keygen`** — generate ed25519 signing keypair (stored at `~/.config/gyt/`)
- **`gyt commit --sign`** / `-S` — sign commits cryptographically
- **`gyt verify [<commit>]`** — verify a signed commit's signature
- **`sign_required = true`** — enforce signed commits via `[commit]` section in `.gyt/config.toml`

All signing uses pure Rust `ed25519-dalek` — no OpenSSL, no libc dependency.

### Wire Protocol & Networking
Custom REST-like HTTP/1.1 protocol:
- `GET /<repo>/info/refs` — discover remote refs
- `POST /<repo>/objects/want` — batch-download objects
- `POST /<repo>/objects/have` — upload objects
- `POST /<repo>/refs/update` — update remote refs

### Production Server (`gyt serve`)
- Multi-repository server from a `--repos` directory
- Optional **TLS** via `--cert` and `--key` flags
- Optional **bearer-token authentication** via `--auth-token <secret>`
- Optional `--webroot` for static file serving
- REST API dashboard for repo management

### Built-in CI (`gyt ci`)
- Reads workflows from the `.gyt-ci/` directory
- **WASM sandbox** (default): `.wasm` files run via wasmtime with strict sandboxing (repo read-only, output read+write, no network)
- **Shell fallback**: `.sh` scripts run as fallback
- **Docker mode**: `--docker` flag runs workflows in containers
- **`--list`**: show available workflows
- **`--output`**: redirect output directory

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
# List available workflows
gyt ci --list

# Run CI (WASM preferred, shell fallback)
gyt ci

# Run in Docker container
gyt ci --docker
```

## Architecture

### Object Storage
Objects are stored as content-addressed blobs in `.gyt/objects/XX/YYYYYY` where `XXYYYYYY` is the lowercase hex of the BLAKE3 hash of the raw payload. The raw object format is:

```
<kind> <size>\0<payload>
```

Supported kinds: `blob`, `tree`, `commit`, `tag`

On disk, the raw object is wrapped with XZ/LZMA compression — a 4-byte magic prefix (`67 79 74 01`), a 1-byte flag (bit 0 = xz), then the LZMA stream. Files written before XZ-wrapping was always on are still readable: any file without the magic prefix is decoded as raw bytes. XZ is the only compression used by gyt, both for on-disk objects and for wire-protocol packfiles.

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
| `show <rev>` | Show a commit or object |
| `diff [<rev>] [--cached\|--staged] [--stat]` | Show changes |
| `branch [<name>]` | List or create branches |
| `switch <branch>` | Switch to a branch |
| `restore <path>...` | Discard unstaged changes |
| `reset [--soft\|--mixed] <rev>` | Reset HEAD |
| `tag <name> [<rev>]` | Create a tag |
| `rm <path>...` | Remove files |
| `grep <pattern>` | Search content |
| `cherry-pick <commit>` | Apply a commit's changes |
| `rebase <branch>` | Fast-forward rebase |
| `merge --ff-only <rev>` | Fast-forward merge |
| `clone <url> [<dir>]` | Clone a repository |
| `fetch [<remote>]` | Fetch from remote |
| `pull [<remote>]` | Fetch + merge |
| `push [<remote>]` | Push to remote |
| `remote -v` | List remotes |
| `config --list\|--get` | Repository configuration |
| `stash {push\|pop\|list\|drop}` | Stash management |
| `worktree {add\|list\|remove}` | Worktree management |
| `keygen` | Generate ed25519 signing keypair |
| `verify [<commit>]` | Verify a signed commit |
| `serve` | Start the production server |
| `ci` | Run CI workflows |
| `getthefuckoutofmyrepo` | Clear repo metadata |

## Configuration

`.gyt/config.toml` (TOML format):

```toml
[user]
name = "Your Name"
email = "you@example.com"

[commit]
sign_required = true

[remote.origin]
url = "http://server:8080/myrepo.gyt/"
```

Environment variables:
- `GYT_AUTHOR_NAME` — override author name
- `GYT_AUTHOR_EMAIL` — override author email
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

- **Unit tests**: 244+ tests across all modules (objects, refs, commands, networking)
- **Wire integration**: 3 tests covering clone, push/fetch/pull cycle, multi-branch cloning
- **Smoke tests**: 14-step end-to-end test covering init, add, commit, branch, switch, diff, log, tag, merge, rebase, cherry-pick, remote, clone, push, fetch, pull

## Security

- `#![forbid(unsafe_code)]` — zero unsafe code in the entire codebase
- No libc dependency — pure Rust throughout
- All dependencies pinned to exact versions (no range matching)
- TLS via rustls (no OpenSSL, no C libraries)
- ed25519 signing with `ed25519-dalek` (pure Rust)
- WASM CI sandbox: strict filesystem isolation (repo read, output read+write, no network)
- Token-based authentication for server write operations
- Plain HTTP requires explicit `--insecure` flag

## CI System

gyt includes a built-in CI runner that does not require external CI infrastructure:

1. Place workflows in `.gyt-ci/` as `.wasm` files (WASM sandbox) or `.sh` scripts
2. Run `gyt ci` to execute all workflows
3. Use `gyt ci --docker` for Docker-based execution
4. Use `gyt ci --list` to enumerate available workflows

WASM workflows run in a wasmtime sandbox with host function access only to `log`, `read_file` (repo, read-only), and `write_file` (output, read+write). No network access is available from the sandbox.

## License

GPL-3.0-or-later

---

*gyt — a modern VCS built for AI agents and humans.*
