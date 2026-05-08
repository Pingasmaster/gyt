# gyt

A small, modern version-control system designed to be safe for both human developers and AI agents.

## Philosophy

gyt is a **safe subset of Git**, not a one-to-one clone. The design priorities are:

1. **Safety first** -- No hooks, no pre-push scripts, no arbitrary code execution. Commands are limited to what is safe in untrusted environments (AI agents, CI, shared workspaces).
2. **Correctness** -- BLAKE3 content addressing, strict clippy (deny correctness), no unsafe code.
3. **Simplicity** -- Understandable codebase. Each command is small, testable, and easy to audit.
4. **AI-friendly** -- Commands work the same way regardless of who (human or agent) issues them. No interactive prompts that require user input mid-operation.

## What's implemented

| Category | Commands | Notes |
|----------|----------|-------|
| Core | `init`, `add`, `commit`, `status`, `rm` | Basic version control loop |
| History | `log`, `show`, `diff` | Linear history only (no DAG) |
| Branches | `branch`, `switch`, `restore`, `reset` | No force-delete |
| Tags | `tag` | Lightweight and annotated tags |
| Network | `clone`, `fetch`, `push`, `pull` | Over gyt wire protocol via HTTP |
| Server | `serve` | Read-only REST API + wire protocol server |
| Advanced | `stash`, `worktree`, `cherry-pick`, `rebase`, `merge` | Fast-forward only for merge/rebase |
| Utilities | `grep`, `getthefuckoutofmyrepo` | Pattern search; humorous safety command |

## Design decisions

- **No three-way merges** -- only fast-forward. Complex merge conflicts are blocked rather than attempted.
- **No packfiles** -- all objects are stored loose. No garbage collection.
- **No reflog** -- simple ref storage, no history of ref changes.
- **No hooks** -- pre/post commands are a security risk and UX problem for agents.
- **No signed commits** -- GPG is optional and not implemented.
- **No submodules** -- kept simple for the initial version.

## Object store

- **Hash**: BLAKE3 (32 bytes)
- **Types**: blob, tree, commit, tag
- **Format**: `"<kind> <size>\0<payload>"` compressed via xz (optional)
- **Storage**: `<gyt>/objects/XX/YYYY...` (2-char prefix / rest suffix)

## Wire protocol

Clients (clone, fetch, push) speak a gyt-specific protocol over HTTP:
- `/info/refs` -- list refs and capabilities
- `/objects/want` -- upload pack (fetch)
- `/objects/have` -- upload pack (push)
- `/refs/update` -- atomic ref update (push)

## REST API

`serve` provides a read-only JSON API:

| Endpoint | Description |
|----------|-------------|
| `GET /api/repos` | List repos in a directory |
| `GET /api/repos/:owner/:name` | Repo metadata |
| `GET /api/repos/:owner/:name/commits` | Paginated commit list |
| `GET /api/repos/:owner/:name/commits/:sha` | Commit detail |
| `GET /api/repos/:owner/:name/tree/:ref` | Tree browsing |
| `GET /api/repos/:owner/:name/refs` | Branch/tag listing |
| `GET /api/repos/:owner/:name/diff/:base..:head` | Diff between revisions |
| `GET /api/repos/:owner/:name/search` | Commit + code search |

## Building

```bash
cargo build          # debug build (no compression)
cargo build --features xz  # with xz compression
cargo build --release    # optimized release build
```

## Testing

```bash
cargo test              # unit tests
cargo test --features xz   # with xz compression
./check.sh             # full check: clippy + tests + build
```

## License

GPL-3.0-or-later. See LICENSE for details.
