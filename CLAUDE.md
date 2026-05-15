# CLAUDE.md — gyt project conventions

## Hard rules

### Never drop or weaken XZ compression

XZ/LZMA (via `lzma-rust2`) is the project's mandated compression for both:
- On-disk loose objects (`src/compress.rs`)
- Wire-protocol packfiles (`src/net/protocol.rs`)

**Do not propose, switch to, or "tune down" any other codec** (zstd, gzip, brotli, zlib, lz4, …) for any path. This applies to:
- `src/compress.rs::encode` / `xz_encode_raw` — XZ remains, with the existing extreme tuning at preset 9 (`nice_len = 273`, `depth_limit = 1000`) for payloads under `SIZE_XZ_HIGH`.
- `src/net/protocol.rs::encode_packfile` — XZ packfile version (`0x02`) is the active wire format. The `0x01` raw version stays as a decode-only fallback for legacy packs; `0x03` is not to be introduced as a different codec.
- The compression preset/level is part of the project's intent (best ratio, archival quality), not a tunable.

If a future change needs to make compression faster, the answer is to compress fewer things or compress them in parallel — never to swap the codec.

This rule supersedes any performance recommendation that suggests otherwise (including any prior recommendation by Claude to use zstd for the wire).

### CI runs WASM only — no shell, no docker

`gyt ci` executes `.wasm` files in `.gyt-ci/` only. The `run_in_docker`,
`run_shell_script`, `--docker` flag, and `.sh` collection paths were
deleted because neither could be confined to a useful sandbox on a
multi-tenant host. Do not reintroduce them.

The WASM sandbox in `src/ci_wasm.rs` is the supported execution path
and its caps are part of the security contract:

- `CI_MAX_MEMORY_BYTES = 256 MiB` — enforced by `CiLimits::memory_growing`
- `CI_INITIAL_FUEL = 1 000 000 000` instructions — terminates infinite loops
- `CI_MAX_FILE_BYTES = 64 MiB` per `read_file` / `write_file`
- `CI_MAX_LOG_BYTES = 16 MiB` cumulative per run
- `CI_MAX_WASM_STACK = 1 MiB`
- WASI is not linked. `env`/`getenv` are not linked. Threads, SIMD,
  reference-types, multi-memory, memory64 are disabled at the engine.
- `.gyt/` is invisible to `read_file` (CI secrets / signing keys / index
  must not be reachable from a workflow).

Tests pinning these in `tests/ci_wasm_sandbox.rs`.

### Issues and discussions are in-repo refs

Issues and discussions live at `refs/issues/<N>`, pointing to a blob
whose payload is canonical TOML (`src/issues.rs::encode`). The same
storage backs both — `gyt issue` and `gyt discussion` share the
implementation and differ only in the `kind` field (`issue` vs
`discussion`).

- Number allocation: `<gyt>/meta/issues_next` under `repo.lock()`. The
  counter is shared across issues and discussions, so each gets a
  globally unique number in the repo.
- Wire transport: `refs/issues/*` and `refs/prs/*` are whitelisted in
  `cmd::clone::is_user_visible_ref` and pushed automatically by
  `cmd::push::run`. Any other `refs/<prefix>/...` is dropped on clone
  by design (don't replicate arbitrary server-controlled namespaces).
- Tests: `tests/issues.rs` + unit tests in `src/issues.rs`.

### Pull requests are in-repo refs

PRs live at `refs/prs/<N>`, pointing to a TOML blob with the same shape
as issues plus `source_ref`, `target_ref`, a tri-state `state` (open/
closed/merged), and two extra event kinds: `merge` and `ci_run`. See
`src/prs.rs`. They share the wire path with issues (the
`is_user_visible_ref` whitelist).

PR-triggered CI is the *manual* model the user asked for:

- `gyt pr ci-run <N>` runs the local `.gyt-ci/*.wasm` scripts through
  the same hardened sandbox as `gyt ci`, then records a `ci_run` event
  with result `pass` or `fail: <reason>`.
- The execution happens on the *client*. There is no "server-side
  runner" in scope — server-side CI requires a worker pool, a workdir
  checkout per request, and result-blob persistence that the
  contributor model doesn't yet need.
- The "rw-only" admin gate is the server's *existing* refs/update ACL:
  pushing the recorded `ci_run` event to the server requires an `rw`
  ACL entry. A `ro` token can `ci-run` locally but cannot publish the
  result (verified in `tests/prs.rs::pr_ro_client_blocked_from_pushing_ci_run_event`).
- `gyt pr merge <N>` delegates to the existing merge implementation
  (FF-only by default, `--no-ff` for a merge commit). The PR's state
  flips to `merged` once the target ref advances.

URL-embedded bearer tokens: `https://<token>@host/repo` is now parsed
into an `Authorization: Bearer <token>` header by `src/net/http.rs`.
The previous test surface relied on tokenless requests being rejected;
this enables real ACL flows on the wire.

## Other operational notes

- See `AGENTS.md` for full contributor conventions (clippy policy, branch strategy, CI secrets, no push webhooks).

## Known data-integrity gaps tracked but not yet fixed

- **gc vs `objects/have` race.** `gc` holds `repo.lock()` while it walks reachability, but `wire_objects_have` writes loose objects WITHOUT taking the lock. A push uploading objects during a gc run can have those objects pruned before its ref-update lands. The plan calls for a separate `objects.lock` that both paths acquire; currently tracked in `tests/data_integrity.rs::gc_after_server_objects_have_without_ref_update_keeps_orphan_or_warns`.

## Recently fixed bugs (with regression tests)

- **`refs::walk` exposed atomic-write tmp files** — `/info/refs` returned 500 to every concurrent reader during any push and could leak a phantom tmp ref name to clients (silent client-repo corruption). Fixed in `src/refs.rs::walk` by skipping files whose name fails `validate_ref_name` and tolerating `read_ref` errors. Regression test: `tests/data_integrity.rs::info_refs_never_leaks_atomic_write_tmp_files`.
- **`gyt add` index race** — two concurrent `gyt add` invocations silently dropped one another's entries because `add` did not take the repo lock. Fixed in `src/cmd/add.rs::run` by acquiring `repo.lock()` before the index read-modify-write. Regression test: `tests/data_integrity.rs::parallel_add_no_index_corruption`.
- **`atomic_write` torn-write & durability** — pid-only tmp suffix could collide across containers (corrupt object); parent directory was not fsynced (rename could be lost across power loss on ext4/xfs). Fixed in `src/fs_util.rs::atomic_write` with per-(pid, thread, counter) suffix and dir fsync.
- **Wire `objects/have` accepted non-canonical trees** — a pusher could upload a tree with unsorted/duplicate entries; downstream consumers that assume sortedness misbehaved. Fixed in `src/net/server.rs::wire_objects_have` by mirroring the commit/tag canonicality gate.
