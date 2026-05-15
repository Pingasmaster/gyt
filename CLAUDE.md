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

The WASM sandbox in `src/ci_wasm.rs` is the supported execution path.
Permissions are operator-controlled via `CiPolicy` — a `.gyt-ci/`
script (which lives inside the cloned repo and therefore is NOT
trusted) cannot widen the sandbox by any in-tree declaration. The
only path to widening is a CLI flag passed to `gyt ci`.

Default caps (no flags) — sized for legitimate Android-class builds
so legitimate work doesn't bump into them:

- `CI_DEFAULT_MEMORY_BYTES = 8 GiB`
- `CI_DEFAULT_FUEL = 1×10^11` wasm instructions
- `CI_DEFAULT_WALL_TIME_SECS = 14400 (= 4 hours)`, enforced via
  `epoch_interruption` + a 1-Hz ticker
- `CI_MAX_FILE_BYTES = 1 GiB` per `read_file` / `write_file`
- `CI_MAX_LOG_BYTES = 256 MiB` cumulative per run
- `CI_MAX_WASM_STACK = 8 MiB`

Default permission set (CiPolicy::default()):

- read   : `repo_workdir/*` EXCEPT `.gyt/*` (always denied)
- write  : `output_dir/*` only
- network: NONE — no socket hostcall is linked
- subprocess: NONE — no fork/exec hostcall is linked
- env vars: NONE — no `getenv` hostcall is linked

Operator widenings (each requires an explicit CLI flag):

- `--ci-no-repo-read` / `--ci-no-output-write`  (narrow further)
- `--ci-repo-write`                              (allow writes to repo, still excludes `.gyt/`)
- `--ci-read <PATH>` / `--ci-write <PATH>`       (extra host paths)
- `--ci-allow-network`                           (reserved vocabulary; currently a no-op since no network hostcall is linked)
- `--ci-memory <SIZE>` / `--ci-fuel <N>` / `--ci-time <SECS>`  (raise/lower caps)

`.gyt/*` is invisible to `read_file` and `write_file` even when an
`--ci-read` / `--ci-write` would otherwise include it — this prevents
a malicious repo from talking the operator into pointing the sandbox
at its own metadata.

WASI is not linked. `env`/`getenv` are not linked. Threads, SIMD,
relaxed-SIMD, reference-types, multi-memory, memory64 are disabled
at the engine.

Tests pinning these in `tests/ci_wasm_sandbox.rs` (12 cases) and
`tests/ci_wasm_policy.rs` (9 cases covering each policy field).

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

### Single-host serving only

`gyt serve` is a single-host service. On startup it acquires
`<repos_root>/serve.lock` and refuses to start if another `gyt serve`
already holds it. This guards against two server processes on the
same host fighting over the per-process caches (audit-log rotation
Mutex, rate-limit map, response cache, pack cache) that all the
per-repo file locks do *not* coordinate.

It does NOT guard against two `gyt serve` processes on *different
hosts* sharing a network FS (NFS, GlusterFS, ceph-fuse). The stale-
reclamation in `FileLock` reads `/proc/<pid>` to decide whether a
crashed holder's lock is reclaimable, and `/proc` is per-host —
host B can't see host A's pids and may incorrectly conclude that
A's still-live lock is stale. Multi-host serving of one repo is
out of scope; shard repos across hosts and route at the LB.

### Advertising HTTP/3 via DNS HTTPS RR

`gyt serve` emits `Alt-Svc: h3=":<port>"; ma=86400` on every HTTPS
response when `--listen-h3` is configured (RFC 7838). Clients that
have already hit the HTTP/1.1 or HTTP/2 endpoint at least once
discover HTTP/3 from that header and switch on the next visit.

The faster path — and now the recommended one for production
deployments per RFC 9460 — is a DNS HTTPS resource record.
Browsers and DNS resolvers that support SVCB/HTTPS RRs see h3
*before* the first TCP handshake, so the very first connection
goes straight to QUIC.

Operator setup (BIND zone file syntax; equivalent forms in
Cloudflare / Route 53 / etc.):

```
repo.example.com.  3600  IN  HTTPS  1 . alpn="h3,h2" port=443
```

- `1` is the priority (lower = higher preference).
- `.` is the target (same name as the owner record).
- `alpn="h3,h2"` advertises both protocols, preferring h3.
- `port=443` is optional if the service runs on the default port.

DNS HTTPS RR is supported by Chrome 117+, Firefox 116+, Safari 17+,
and by `curl --doh-url`. Older clients fall back to the Alt-Svc
discovery path automatically — no extra config needed.

### TLS session-ticket key rotation

`--tls-ticket-key <file>` is the operator-controlled rotation point
for cross-replica TLS resumption. File is hex-encoded:

```
# Current key (32 bytes, 64 hex chars)
00112233...

# Optional previous key for one-rotation tolerance
ffeeddcc...
```

Multi-replica deployments behind a non-sticky LB need every replica
reading the same file. Rotate by pushing a new file with the new
key on line 1 and the old key on line 2 to every replica, then
restart each one. After the 12-hour ticket lifetime expires, push
again with the new key on line 1 only.

## Other operational notes

- See `AGENTS.md` for full contributor conventions (clippy policy, branch strategy, CI secrets, no push webhooks).

## Known data-integrity gaps tracked but not yet fixed

(none currently — the documented gc vs `objects/have` race is now closed; see below.)

## Recently fixed bugs (with regression tests)

- **gc vs `objects/have` race + missing issue/PR reachability seeds.** Closed by:
  - A new `<gyt>/objects.lock` taken by `wire_objects_have` for the duration of its loose-object writes, and by `gc`'s prune phase (acquired *after* the reachability walk so a long walk doesn't block uploads).
  - A 60s mtime grace inside `gc` (`GC_GRACE_SECS`) so any loose object recently written — including by an older client that bypasses the new lock — survives the prune.
  - `compute_reachable` now seeds `refs/issues/*` and `refs/prs/*`; without this, every issue / PR blob would be pruned immediately (a regression introduced by the issues feature).
  Regression tests: `tests/gc_race.rs::{unreachable_young_loose_object_survives_gc, issue_blob_survives_gc, pr_blob_survives_gc, concurrent_push_while_gc_runs_no_data_loss}`.

- **`refs::walk` exposed atomic-write tmp files** — `/info/refs` returned 500 to every concurrent reader during any push and could leak a phantom tmp ref name to clients (silent client-repo corruption). Fixed in `src/refs.rs::walk` by skipping files whose name fails `validate_ref_name` and tolerating `read_ref` errors. Regression test: `tests/data_integrity.rs::info_refs_never_leaks_atomic_write_tmp_files`.
- **`gyt add` index race** — two concurrent `gyt add` invocations silently dropped one another's entries because `add` did not take the repo lock. Fixed in `src/cmd/add.rs::run` by acquiring `repo.lock()` before the index read-modify-write. Regression test: `tests/data_integrity.rs::parallel_add_no_index_corruption`.
- **`atomic_write` torn-write & durability** — pid-only tmp suffix could collide across containers (corrupt object); parent directory was not fsynced (rename could be lost across power loss on ext4/xfs). Fixed in `src/fs_util.rs::atomic_write` with per-(pid, thread, counter) suffix and dir fsync.
- **Wire `objects/have` accepted non-canonical trees** — a pusher could upload a tree with unsorted/duplicate entries; downstream consumers that assume sortedness misbehaved. Fixed in `src/net/server.rs::wire_objects_have` by mirroring the commit/tag canonicality gate.
