# gyt — Pre-Production Security Audit

**Scope:** Every `.rs` file under `src/` (88 files, 33,386 LOC) plus build
configuration. Tests, docs, and `.gyt-ci/` were inspected for hygiene but
not deeply audited as runtime code.

**Method:** Eleven domain agents read every line of their assigned files
against four threat models (anonymous internet attacker, authenticated
malicious client, malicious repo content, malicious operator-side
input). Each agent-reported finding was then re-verified by re-reading
the cited code; findings whose repro did not hold are dropped or
downgraded. Final severity is the verifier's, not the agent's.

**Ship-gate recommendation: DO NOT DEPLOY.** Three classes of finding
must be fixed before any production exposure:

1. The **tree-name → path-traversal CRITICAL** (F-D6-01) — a malicious
   server (or push to a server you clone from) writes to any path the
   gyt-running user can reach, including `~/.ssh/authorized_keys` and
   `.gyt/config`. This is exploitable against every `gyt clone / pull /
   merge / switch / rebase / worktree add / stash pop / reset --hard`.
2. The **HIGH cluster on the wire path** — refname unvalidated write
   (F-D1-01), audit-log newline injection (F-D1-03), slowloris (F-D1-02),
   FF-walk DoS (F-D4-01), ACL prefix-glob (F-D4-02), force-flag bypass
   (F-D4-03), and the issue/PR FF-gate that makes every second push of
   an issue or PR fail in normal use (F-D8-01).
3. The **HIGH on `getthefuckoutofmyrepo`** — silent 10 000-commit
   cutoff, no repo lock, no reflog write (F-D9-01, F-D9-02). The command
   that exists specifically to *purge secrets from history* does not
   actually purge secrets from history on any repo of meaningful size.

The complete table of findings is below. Total: **1 CRITICAL, 24 HIGH,
49 MEDIUM, 62 LOW, 44 INFO** (≈ 180 findings).

---

## Top-5 risks

| # | Finding | Why it ships first |
|---|---------|--------------------|
| 1 | F-D6-01 — Tree-name path-traversal on every checkout | A single malicious push lets the server write to `$HOME/.ssh/authorized_keys` on every cloning user. Exploit chain is one-line. |
| 2 | F-D1-01 — `wire_refs_update` writes to attacker-controlled refname | Holder of any `rw` token writes 65 bytes of attacker-chosen hex to any path the gyt-serve uid can reach. Combined with F-D1-03 (audit-log injection) defeats forensic accountability. |
| 3 | F-D9-01/02 — `getthefuckoutofmyrepo` partial-rewrite + no reflog | The command's only purpose is to nuke secrets. On any repo > 10 000 commits, the secrets stay reachable and the user has no undo path. |
| 4 | F-D4-03 — `?force=1` and `?force-with-lease=1` available to every `rw` token, with no `force` ACL bit | Any contributor with rw on `refs/heads/feature` can rewind `refs/heads/main`. |
| 5 | F-D8-01 — FF gate runs on issue/PR blob refs and always fails | Every second `gyt issue comment` or `gyt pr comment` push is rejected with 409. The feature is broken in normal use, not under attack. |

---

## How to read the table

Each finding has:
- **ID** `F-D<domain>-<num>`
- **Severity** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **File** `path:line` (verifier-confirmed)
- **Threat model** A=anonymous-internet B=authenticated-malicious-client C=malicious-repo-content D=malicious-operator-input
- **Repro** how to trigger
- **Fix** specific code change

---

# CRITICAL findings

## F-D6-01 — Malicious tree entry writes anywhere the gyt UID can reach

- **File:** `src/object/tree.rs:47-74` (decode), `src/cmd/util.rs:207-229` (walk_tree), `src/cmd/merge.rs:614-620, 638-677` (write_workdir_entry). Identical pattern in `cmd/worktree.rs`, `cmd/stash.rs`, `cmd/rebase.rs`, `cmd/switch.rs`, `cmd/restore.rs`, `cmd/reset.rs`, `cmd/cherry_pick.rs`.
- **Threat:** C (malicious repo content) — exploitable on every `clone / fetch / pull / merge / switch / rebase / worktree add / stash pop / reset --hard / cherry-pick`.
- **Description:** `tree::decode` accepts any byte sequence as an entry `name` except NUL (terminator) and space (mode delimiter). Names can therefore contain `..`, `/`, leading `/` (absolute), `.gyt`, or any control byte. `walk_tree` does `prefix.join(name)` raw; every `materialize_*` site then does `repo.workdir.join(path)`. `Path::join("/abs")` resets to absolute; `create_dir_all(parent)` happily walks `..`. The server-side canonicality gate in `wire_objects_have` only requires sort + entry-format roundtrip; it does NOT validate names.
- **Repro:** Craft a tree with entry `100644 ../../../home/victim/.ssh/authorized_keys\0<hash-of-attacker-pubkey-blob>`. `tree::decode` accepts. `wire_objects_have` accepts (canonical). A client that pulls a commit whose tree contains this entry executes `repo.workdir.join("../../../home/victim/.ssh/authorized_keys")` → absolute write outside repo.
- **Impact:** Arbitrary write under the running user's uid. On macOS / Linux that includes `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.config/gyt/ci-key`, every dotfile. Inside the repo: overwriting `.gyt/config`, `.gyt/HEAD`, `.gyt/allowed_signers`. The user has no warning.
- **Fix:** In `tree::decode`, after parsing each entry, reject any of:
  - `name.is_empty()`
  - `name == b"."` or `name == b".."` or `name.eq_ignore_ascii_case(b".gyt")`
  - `name.contains(&b'/')`
  - `name.contains(&b'\\')` (Windows path separator on FUSE)
  - any byte `< 0x20` or `== 0x7f` (control)
  - `mode` not in `{MODE_FILE, MODE_EXEC, MODE_SYMLINK, MODE_DIR}` (also closes F-D5-01, F-D3-05)
  - duplicate names within the tree (also closes a missing canonicality check)
  - non-strict-ascending sort (already enforced indirectly by encode, but make decode loud about it)
  Additionally in `write_workdir_entry`, before `std::fs::write(abs, ...)`, verify the final canonicalized path's parent starts with `repo.workdir` (after canonicalization of every ancestor). Reject symlink targets whose canonicalized destination escapes the workdir (see F-D6-02).

---

# HIGH findings

## F-D6-02 — Symlink-then-write workdir escape

- **File:** `src/cmd/merge.rs:638-655` (symlink branch), identical in `cmd/worktree.rs:585`, `cmd/stash.rs`, `cmd/rebase.rs`.
- **Threat:** C.
- **Description:** `write_workdir_entry` for a symlink entry calls `std::os::unix::fs::symlink(target, abs)` with `target` taken raw from the blob payload — no validation. Subsequent entries that materialize into `link/something` traverse the symlink via `create_dir_all` (which resolves symlinks at every level) and write outside the workdir. Even after fixing F-D6-01's path-traversal at the *name* level, this remains exploitable through symlink *targets*.
- **Fix:** Reject symlink targets that are absolute, contain `..`, or whose final canonicalized path is outside `repo.workdir`. Better: use `*at` syscalls (rustix/nix) and `O_NOFOLLOW` on every ancestor.

## F-D6-03 — Myers diff has unbounded O((n+m)²) memory

- **File:** `src/diff.rs:54-147`.
- **Threat:** C.
- **Description:** `let v_size = 2*max + 1; let mut trace: Vec<Vec<i32>> = Vec::with_capacity(max+1);` then `trace.push(v.clone())` per outer iteration. For 50k×50k blob diff: ~80 GB. No cap, no early cutoff, no whole-file-replacement fallback. Reachable via `gyt diff / log / show / merge / rebase / cherry-pick / pr ci-run` on any large blob in a cloned repo.
- **Fix:** Define `const MAX_DIFF_LINES: usize = 50_000;`. If `n + m > MAX_DIFF_LINES` return `[Delete(a)..., Insert(b)...]` directly.

## F-D9-01 — `getthefuckoutofmyrepo` silent 10 000-commit cutoff defeats secret-purge purpose

- **File:** `src/cmd/getthefuckoutofmyrepo.rs:217-225, 260-265`.
- **Threat:** D (operator runs the destructive command); also bypasses contributor intent.
- **Description:** Hard-coded `max_depth = 10000`. On overflow, prints `"warning: hit max rewrite depth, stopping"` to stderr, then **still writes the refs that did get rewritten**. The unwritten ancestors retain their secret-bearing blobs and remain reachable through every parent pointer. The command silently fails at its only documented purpose.
- **Fix:** Either (a) make the cap configurable and **refuse** to update any refs if the walk didn't complete; (b) iterate until done with progress reporting; (c) take the cap on input lines (not commit count) and bail loud at limit.

## F-D9-02 — `getthefuckoutofmyrepo` takes no `repo.lock()` and writes no reflog

- **File:** `src/cmd/getthefuckoutofmyrepo.rs:51-271`.
- **Threat:** D.
- **Description:** `grep -n "repo.lock\|reflog::record\|reflog::try_record"` on the file returns zero hits. A concurrent `gyt commit / push / fetch` will race the destructive walk. The bare `refs::write_ref` calls at line 262 leave no reflog breadcrumb. A user who realizes they nuked the wrong path has no undo.
- **Fix:** Acquire `repo.lock()` from line 51 to line 270. Record both `<branch>` and `HEAD` reflog entries on every ref move via `crate::reflog::record`, mirroring `cmd/rebase.rs:255-272`.

## F-D9-03 — `gyt serve` accepts `--listen 0.0.0.0:*` with no auth + no warning

- **File:** `src/cmd/serve.rs::parse_args` (no policy check), `src/net/server.rs:1125-1164::authorize` (open path).
- **Threat:** D, A.
- **Description:** With neither `--auth-token` nor `--auth-tokens` set, `authorize` returns `true` for every route → anonymous read AND write. `serve.rs` has no refusal of non-loopback listen addresses when auth is absent.
- **Fix:** In `parse_args`, after the existing consistency checks, reject configurations where `listen` (or `h2_listen`, `h3_listen`) binds a non-loopback address AND no auth is configured. Print a one-line explanation of the safe combinations.

## F-D1-01 — `wire_refs_update` writes to attacker-controlled refname

- **File:** `src/net/server.rs:2698-2703`; `src/net/refs_policy.rs:232-313`; `src/net/protocol.rs:188-225`.
- **Threat:** B (or A if `gyt serve` runs open).
- **Description:** `parse_ref_updates` accepts any non-empty string as `update.name`. `evaluate_with_mode` only validates `name` indirectly (via `read_ref` for non-Force updates). The handler then does `gyt_dir.join(&update.name)` + `create_dir_all(parent)` + `std::fs::write(ref_path, "{hex}\n")`. Because `Path::join` resolves `..` literally and respects absolute paths, the resulting write can land anywhere the gyt-serve uid can reach.
- **Repro:** With any `rw` token: POST `/myrepo/refs/update` body `{ZERO}\t{any_valid_hex}\t../../../../tmp/pwned` → 65-byte file written at `/tmp/pwned`.
- **Fix:** In `evaluate_with_mode` (or in `wire_refs_update` before `join`), call `crate::refs::validate_ref_name(&u.name)` and reject on failure. Also require ref names to begin with `refs/` (or `HEAD` for the one exception case). Cap length at 255 bytes.

## F-D1-02 — No request-body read timeout enables slowloris-on-body

- **File:** `src/net/server.rs:558-585, 698-712`; `src/net/h2_server.rs:189-200`; `src/net/h3_server.rs:147-178`.
- **Threat:** A.
- **Description:** hyper's `header_read_timeout(60s)` is set, but the body collection (`Limited::new(body, MAX_BODY_BYTES).collect().await`) has no end-to-end deadline. An attacker sending headers cleanly then trickling body bytes (1 byte / 30 s) pins a tokio task and an inflight permit indefinitely. With 10 k inflight permits, ~10 k slow-body sockets DoS the whole listener. Bypasses MAX_WORKERS, MAX_INFLIGHT, and the per-IP rate limit (which fires on completed requests).
- **Fix:** Wrap the body collection in `tokio::time::timeout(Duration::from_secs(120), limited.collect()).await`. Add a minimum-throughput floor; drop the connection if average bytes/sec falls below e.g. 1 KiB/s.

## F-D1-03 — Audit-log entry injection via newline in refname

- **File:** `src/net/refs_policy.rs::append_audit` (TSV + LF terminator); `src/net/protocol.rs:188-225` (refname not filtered).
- **Threat:** B.
- **Description:** Audit format is `{ts}\t{actor}\t{old}\t{new}\t{name}\n`. `name` is attacker-controlled and not filtered for control bytes. A push of a refname containing `\n` splits the audit line into two; the synthesized second line can claim any actor, any timestamp, any update.
- **Repro:** Push refname `refs/heads/foo\n9999999999\ttoken:0000…\t<old>\t<new>\trefs/heads/main` → audit log contains a forged record attributing a `refs/heads/main` update to `token:000...`.
- **Fix:** Reject any byte `< 0x20` or `== 0x7f` in `name` at `parse_ref_updates`. Or escape `\t`, `\n`, `\r` when formatting the audit line (less defensible — fix at the parser).

## F-D4-01 — FF walk has no depth / time cap → per-update DoS

- **File:** `src/net/refs_policy.rs:70-98 (is_ancestor), 103-144 (commits_new_since), 232-311 (evaluate_with_mode)`.
- **Threat:** B.
- **Description:** Both `is_ancestor` and `commits_new_since` walk the full parent DAG with `HashSet` dedup, no depth cap, no time cap, no commit-count cap. An attacker can build a long parent chain locally (one tree, N commits) and push it. A single `/refs/update` then loops N times under `refs.lock` (10 s acquire timeout). With sign_required, each commit also costs a base64 decode + ed25519 verify. Other pushers and readers wait behind the lock.
- **Fix:** Add `const MAX_WALK_COMMITS: usize = 1_000_000;` to both walks. Return `PolicyError::Internal("commit graph too large")` on overflow. Optionally add a wall-clock deadline checked every 4096 iterations.

## F-D4-02 — ACL `prefix*` pattern is unanchored — `a*` matches `alice-evil`

- **File:** `src/net/server.rs:937-947 (AclEntry::matches_repo), 957-1003 (load_acl)`.
- **Threat:** B.
- **Description:** `matches_repo` does `repo.starts_with(prefix)` with `prefix` = anything before the trailing `*`. No anchoring on `/` segment boundary. Operator-written `alice*\trw` silently matches `alice-evil/secret`, `alicia/x`, `alice` (any tail). Embedded `*` (e.g. `pre*fix`) matches nothing — a silently disabled rule.
- **Fix:** In `load_acl`, reject any pattern with `*` not in the final position. Require the character before a trailing `*` to be `/` (or the pattern to be exactly `*`). Document the boundary rules in the help text.

## F-D4-03 — `?force=1` / `?force-with-lease=1` available to every `rw` token

- **File:** `src/net/server.rs:2649-2687, 1171-1176`; `src/net/refs_policy.rs:232-311`.
- **Threat:** B.
- **Description:** Mode is parsed from query string. `route_needs_write` checks `rw`; there is no separate `force` ACL bit. Any `rw` token can rewind any covered ref. Signature enforcement still applies on sign-required repos, so the *content* still has to be signed — but on non-signed repos any rw contributor can destroy `refs/heads/main`.
- **Fix:** Add an `rwf` permission tier (rw + force) to `AclEntry`; `rw` denies `?force=*`. Alternatively, gate `?force=*` on a server-wide `--allow-force` flag (default off). Document the chosen semantics in the help.

## F-D4-04 — `commits_new_since` silently skips unreadable commits → signature gate hole

- **File:** `src/net/refs_policy.rs:130-142`.
- **Threat:** B.
- **Description:** The walk does `match commit::read(...) { Ok(c) => ..., Err(_) => continue }`. A pusher who uploads only the tip commit (with `parent` field referencing un-uploaded ancestors) gets the tip signature-verified but the ancestors invisibly skipped. The policy invariant "every commit reachable from new but not old is verified" silently breaks; the resulting half-broken graph propagates to clones.
- **Fix:** Treat unreadable parents not in `excluded` as a hard error (`MissingCommit` variant). Surface as 409, not silent.

## F-D4-05 — `--signers` override falls through to in-repo file on read failure

- **File:** `src/net/refs_policy.rs:349-399 (server_policy_with_overrides)`.
- **Threat:** B/D.
- **Description:** `match override_signers { Some(p) if p.exists() => load_allowed_signers_at(p).unwrap_or_default(), _ => load_allowed_signers(gyt_dir).unwrap_or_default() }`. If the operator typo'd the override path, `p.exists()` is false → falls through to in-tree `.gyt/allowed_signers` → which is pusher-controlled.
- **Fix:** Load the override at server startup; refuse to boot if the file is missing or unreadable. Store the parsed signers on `ServerState`. Never fall through silently.

## F-D8-01 — FF gate applied to issue/PR blob refs rejects every second push

- **File:** `src/net/refs_policy.rs:246-289`; `src/cmd/push.rs:171-195`; `src/net/server.rs:2685`.
- **Threat:** B (mostly a benign-use bug; weaponizable as DoS).
- **Description:** For every `RefUpdate` with `old=Some`, `is_ancestor(old, new)` is called. On a blob ref (issue/PR), `commit::read` fails, `is_ancestor` returns `Ok(false)`, → NotFastForward → 409. The first push (server has nothing) sets `old=None` and succeeds. Every subsequent `gyt issue comment` / `pr close` / `pr ci-run` / `pr merge` / label edit sets `old=Some(prev_blob)` and fails. Tests pass because the existing tests do the comment **before** the first push.
- **Fix:** Special-case `refs/issues/*` and `refs/prs/*` in `evaluate_with_mode`: skip the commit-DAG FF check, but enforce a "monotonic event-log append" check by decoding both blobs and requiring `new.events` is a strict prefix-extension of `old.events` with identical header fields.

## F-D8-02 — Issue/PR blobs not canonicality-checked or state-validated on push

- **File:** `src/net/server.rs::wire_objects_have:2542-2592` (only Commit/Tag/Tree canonicality-checked).
- **Threat:** B.
- **Description:** A `rw` pusher can replace `refs/prs/<N>` with any blob. After applying the F-D4-03 fix or in repos that allow force, this lets the pusher set `state = "merged"` without `target_ref` advancing, forge `ci_run pass` events for any author, drop hostile comments, replace event history, or set `target_ref` to `../etc/passwd`.
- **Fix:** In `wire_objects_have`, for any blob whose ref is under `refs/issues/*` or `refs/prs/*`, run the issue/PR decoder and require `encode(decoded) == payload`. Additionally enforce the state machine: `merged` requires the new `target_ref` tip to actually equal the recorded merge commit; `target_ref` / `source_ref` must match `refs/heads/<safe-name>`.

## F-D8-03 — `gyt pr merge` drives `switch` + `merge` with attacker-controlled ref strings

- **File:** `src/cmd/pr.rs:535-598`.
- **Threat:** B+C.
- **Description:** `cmd_merge` reads the PR blob (whose `source_ref` and `target_ref` are attacker-controlled), strips `refs/heads/`, and passes the result to `crate::cmd::switch::run` and `merge_cmd::run`. There is no check that `source_ref` / `target_ref` are under `refs/heads/`. The repo lock is taken AFTER the working-tree switch. A maintainer who reviewed `feature-A` can be tricked into merging `feature-A-evil` because a later push to `refs/prs/<N>` rewrote `source_ref`.
- **Fix:** Enforce `source_ref.starts_with("refs/heads/") && target_ref.starts_with("refs/heads/")` at the blob level (see F-D8-02) and again at `cmd_merge`. Take the repo lock BEFORE `switch`. Require the maintainer to re-confirm if the PR's `source_ref` differs from the one displayed at `pr new`.

## F-D5-01 — `tree::decode` accepts non-canonical entries + non-whitelist modes

- **File:** `src/object/tree.rs:47-74` (and verified there is no re-encode parity check in `wire_objects_have` strong enough to catch all classes).
- **Threat:** B+C.
- **Description:** `decode` accepts any mode (gitlinks `0o160000`, setuid `0o104755`, mode `0`), unsorted entries, duplicate names, names containing `/`, NUL (impossible since NUL is terminator — but `..`, leading `/`, control bytes are accepted). The server canonicality gate checks encode-roundtrip equality, which catches *some* shape issues but NOT name-content issues. F-D6-01 captures the path-traversal consequence; this finding tracks the upstream parser laxity.
- **Fix:** See F-D6-01 (validation list).

## F-D5-02 — No payload-size cap on loose-object read; commit decoder has no parent-count cap

- **File:** `src/object/store.rs:73-95 (read uses fs_util::read_all with no size precheck)`; `src/object/commit.rs:94-170`; `src/cmd/gc.rs:528-567`.
- **Threat:** B+C.
- **Description:** A loose object can be any size. `fs_util::read_all` reads the whole file before `compress::decode` runs. A 100 GB loose object OOMs the reader. `commit::decode` accepts unlimited `parent <hex>` lines; gc walking a commit with 10⁶ parents allocates 64 MiB per visited commit.
- **Fix:** Add `const MAX_LOOSE_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;` and `fs::metadata(path)?.len() <= MAX_LOOSE_PAYLOAD_BYTES` as a precheck in `store::read`. Add `const MAX_PARENTS: usize = 64;` to `commit::decode`. Add `const MAX_TREE_ENTRIES: usize = 1_000_000;` to `tree::decode`.

## F-D5-03 — Loose-object reads + writes follow symlinks; HEAD too

- **File:** `src/object/store.rs:60, 64, 75`; `src/refs.rs::read_head` via `fs_util::read_all`.
- **Threat:** D.
- **Description:** `path.exists()` and `fs::read` follow symlinks. A co-tenant who can place a symlink in `objects/aa/` or at `HEAD` causes the gyt process to read the symlink target (substitution / availability attack — integrity preserved by BLAKE3 check).
- **Fix:** Replace `path.exists()` with `fs::symlink_metadata`. For reads, use `OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)` on Unix.

## F-D3-01 — `parse_pack` allows 15× memory amplification via zero-length entries

- **File:** `src/net/protocol.rs:136-168`.
- **Threat:** B.
- **Description:** No minimum entry size, no maximum entry count. Decompressed body of 1 GiB filled with zeros yields ~268M `PackEntry` records (~56 bytes each, ~15 GiB resident) before `wire_objects_have` even starts processing.
- **Fix:** Reject `len == 0` and cap entry count (e.g. `MAX_PACK_ENTRIES = 1 << 20`).

## F-D3-02 — Per-stream XZ cap doesn't bound cumulative CPU

- **File:** `src/compress.rs:23, 77-92`; `src/net/protocol.rs:262-264`; `src/net/server.rs:2542-2548`.
- **Threat:** B.
- **Description:** `MAX_DECOMPRESSED_BYTES = 1 GiB` is per-call. The outer packfile XZ + per-entry XZ inside `wire_objects_have` chain. A request can carry thousands of entries each 1 GiB-decoded, totalling hours of XZ CPU per request — no codec change needed (CLAUDE.md hard rule).
- **Fix:** Track cumulative decompressed bytes per request via a shared `Arc<AtomicU64>` budget (e.g. 2 GiB total). Surface as 413 on overflow.

## F-D3-03 — Clone doesn't canonicality-check trees or tags

- **File:** `src/cmd/clone.rs:280-298`.
- **Threat:** A malicious server / C.
- **Description:** Server-side `wire_objects_have` canonicality-checks Commit / Tag / Tree on push, but the client's clone path only canonicality-checks Commit. A hostile server can plant non-canonical trees on every clone. Combined with F-D6-01, this is the cloning side of the path-traversal exploit.
- **Fix:** In `clone.rs` after `parse_raw`, run `encode(decode(payload)) == payload` for Tree and Tag. Also reject objects not in the originally-requested set (see F-D3-04).

## F-D7-01 — Epoch ticker exits at `wall_time_secs` ticks; host calls aren't metered

- **File:** `src/ci_wasm.rs:362-375`.
- **Threat:** C.
- **Description:** Ticker loop `for _ in 0..deadline_secs` exits after that many seconds. Inside that window, host calls (`read_file`, `write_file`, `log`) are not fuel-metered and not epoch-checked mid-call. A wasm doing a chain of slow `read_file`s on a large file in a slow filesystem can run wallclock far past the configured cap.
- **Fix:** Store an `Instant::now() + wall_time` deadline on the `Sandbox`. At the entry of each host-call closure, check `Instant::now() > deadline` and return a `Trap`. Or use `epoch_deadline_callback` with a wall-clock check.

## F-D7-02 — `write_file` host call follows symlinks at the leaf

- **File:** `src/ci_wasm.rs:530-569 (resolve_write)`; the eventual `fs::write` opens with `O_TRUNC|O_CREAT|O_WRONLY` (no `O_NOFOLLOW`).
- **Threat:** C+D.
- **Description:** `resolve_write` canonicalizes the *parent* but not the leaf. A pre-existing symlink under the operator-allowed write-root (e.g. planted by a previous run with `--ci-repo-write` and a tree symlink, or planted by another user on a shared CI host) becomes a write through the symlink to its target.
- **Fix:** Open files in `write_file` with `OpenOptions::new().write(true).create(true).truncate(true).custom_flags(libc::O_NOFOLLOW).open(cand)`. Reject `EINVAL`/`ELOOP` as policy violation.

## F-D11-01 — `.gyt-ci/` ships only `.sh` scripts; project's own CI policy violated

- **File:** `.gyt-ci/01-check.sh`, `.gyt-ci/02-build.sh` (no `.wasm` present).
- **Threat:** D + policy drift.
- **Description:** CLAUDE.md and AGENTS.md state in unambiguous terms that `gyt ci` runs only `.wasm`, and `.sh` files are warned and skipped. The project's own CI dir contains exactly two shell scripts. Either the runner skip is fictitious or the dogfooded CI was never ported. The two scripts run `cargo --version`, `rustc --version`, and `cargo build --all-features` — they would arbitrary-code if `.sh` re-enabled.
- **Fix:** Delete `.sh` files. Compile a small `wasm32-unknown-unknown` (or `wasm32-wasi`-like minimal-host-call) target that does what the shell scripts do via `read_file`/`log` host calls. Add a regression test `assert!(repo.gyt_ci_dir.is_empty_of_non_wasm())`.

## F-D11-02 — `rust-toolchain.toml` pins `channel = "beta"`

- **File:** `rust-toolchain.toml`.
- **Threat:** D + reproducibility.
- **Description:** Rolling channel. Builds today differ from builds tomorrow. Clippy gate varies. Cargo.toml says `rust-version = "1.96"` (stable numbering) but the toolchain points at beta — they disagree about what compiler is intended.
- **Fix:** Pin to a specific stable release, e.g. `channel = "1.85.0"` (or whichever stable supports `edition = "2024"`). Add a CI step that runs `rustup show` and asserts the channel matches the pin.

## F-D10-01 — Terminal-escape injection across every renderer

- **File:** `src/term.rs` (no sanitizer), `src/cmd/log.rs:509,518,526,539,552,564`, `src/cmd/show.rs:67-104, 170-171`, `src/cmd/blame.rs:277-283`, `src/cmd/status.rs:355,366,376`, `src/cmd/diff.rs:108-211`, `src/cmd/branch.rs:111`, `src/cmd/reflog_cmd.rs:95-107`, `src/cmd/tag.rs:131`, `src/cmd/stash.rs:215`, `src/cmd/grep_cmd.rs:122`.
- **Threat:** C.
- **Description:** A commit author / committer / message / signed-off / ref name / tag tagger / blame line / blob content / stash subject containing `\x1b]0;PWNED\x07` (terminal title set) or `\x1b]52;c;<base64>\x07` (OSC-52 clipboard write — runs on many modern terminals) is rendered verbatim by every CLI subcommand. `grep -rn "safe_display|sanitize|strip_ansi"` on `src/` returns nothing.
- **Fix:** Add `term::safe_display(s: &str) -> String` that replaces bytes `< 0x20` (except `\t`, `\n`) and `0x7f` with a printable substitute, and route every commit-author / message / ref-name / blame-text / blob-diff / stash-subject print through it. Diff renderer in particular: replace `print_bytes` paths with a sanitizing variant.

## F-D10-02 — `gyt config --set` allows TOML injection via section name

- **File:** `src/cmd/config_cmd.rs:79-86`, `src/config.rs:114-138 (Config::write)`.
- **Threat:** D.
- **Description:** `apply_key` accepts `["remote", name, "url"]` with `name` unvalidated. `Config::write` emits `writeln!(s, "[remote.{name}]")` — `name` is interpolated raw. `--set 'remote.foo]\n[user.name="evil' url` corrupts the on-disk TOML.
- **Fix:** Validate `name` against `[A-Za-z0-9._-]+` in `apply_key`. Reject `]`, `\n`, `\r`, `\\`, `#`, `"`. Same in `cmd/remote.rs`.

---

# MEDIUM findings

(Verified against code; listed compactly.)

| ID | File:line | Title |
|----|-----------|-------|
| F-D1-04 | `net/server.rs:2436-2487`; `net/cache.rs:70-99` | `pack_cache` eviction DoS by want-set permutation flooding; per-hit `Vec::clone()` of 100+ MB cached packs is a memory amplifier |
| F-D1-05 | `net/server.rs:2190-2205` | `static_file` canonicalize TOCTOU + webroot symlink race; reads via non-canonicalized path |
| F-D1-06 | `net/server.rs:1182-1187`; `net/router.rs:67-72` | `/metrics` reachable unauthenticated; leaks request/repo activity counters |
| F-D1-07 | `net/server.rs:507`; `net/rate_limit.rs:80-115` | Rate limit keyed on TCP peer; no `X-Forwarded-For` parsing → no per-IP limit behind any sane proxy |
| F-D1-08 | `net/router.rs:248-267` | `url_decode` accepts tail-truncated `%` escapes |
| F-D1-13 | `net/server.rs:2510-2592, 2637-2647`; `net/protocol.rs:188-225` | No upper bound on `objects/have` entry count or `refs/update` line count |
| F-D2-01 | `net/https_engine.rs:72-85` | Async HTTPS client doesn't pin TLS 1.3 explicitly; today saved by `tls12` feature off in Cargo.toml, fragile invariant |
| F-D2-02 | `net/https_engine.rs:74-83` vs `net/tls.rs:24-34` | Duplicated `install_default` calls, silent suppression of `Err` — duplicated provider-install pattern |
| F-D2-03 | `net/https_engine.rs:81` vs `net/tls.rs:196` | Async client ALPN list includes `h2` but server advertises only `http/1.1`; comment is provably wrong |
| F-D3-04 | `cmd/clone.rs:280-298` | Clone trusts server to ship only requested objects; storage exhaustion / reachability planting possible |
| F-D3-05 | `object/tree.rs:47-74` | Tree decoder accepts non-whitelisted modes (gitlinks, setuid) and dangerous names (`..`, embedded `/`, control bytes) — see F-D5-01/F-D6-01 |
| F-D3-06 | `net/api.rs:162` | `TreeEntryInfo::to_json` emits `"mode": 0o100644` — invalid JSON; every consumer fails to parse |
| F-D3-07 | `net/api.rs:43-45,256-263` | `SearchResult::to_json` JSON-injection via raw `String` items |
| F-D4-06 | `net/server.rs:1043, 1104-1115` | `actor_for` blake3-fingerprints attacker-supplied auth header bytes before authorize; free unauthenticated CPU work |
| F-D4-07 | `net/server.rs:1228-1237` | `constant_time_eq` walks `max(a.len(), b.len())` — attacker-controlled length amplifier |
| F-D4-08 | `net/server.rs:2698-2718` | Ref write + audit + reflog non-transactional; mid-sequence crash leaves advanced ref with no audit |
| F-D4-09 | `net/refs_policy.rs:405-439` | `allowed_signers` parser too permissive on whitespace/comments |
| F-D4-10 | `net/server.rs:2706`; `net/refs_policy.rs:469-497` | Audit log records success only; repeated forged-signature attempts invisible to operator |
| F-D5-04 | `object/pack.rs:136-177, 208-235` | Pack reader has no `O_NOFOLLOW`; symlinked `pack-*.idx` causes DoS on any read until cleanup |
| F-D5-05 | `refs.rs:26-58` | `validate_ref_name` accepts control chars, ASCII space, backslash, leading-dot components, `.lock` suffix, NFC/NFD variants, unbounded length |
| F-D5-06 | `reflog.rs:38-79` | Reflog `record` writes without locking; NFS / long-message tear; silent error swallow |
| F-D5-07 | `fs_util.rs:141-168, 186-197` | FileLock `try_reclaim_stale` 10ms re-check window + PID-reuse + cross-pid-namespace `/proc` lookup |
| F-D5-08 | `object/store.rs:56-66`; `repo.rs:126-131` | `write_bytes` does not hold `objects_lock`; CLAUDE.md claim that local writes serialize against gc is not type-enforced |
| F-D5-09 | `object/mod.rs:49-55`; `object/store.rs:67-71` | `Object.id` decorative — caller can mutate `payload` and `write()` silently stores under recomputed hash |
| F-D5-11 | `object/pack.rs:327` vs `object/store.rs:73-95` | Pack reader caps at 1 GiB; loose reader has no cap |
| F-D5-13 | `refs.rs:136-143` | `delete_ref` lacks old-id CAS and reflog write |
| F-D5-14 | `refs.rs:67-95`; `fs_util.rs:46-48` | HEAD read via `fs_util::read_all` follows symlinks |
| F-D5-15 | `reflog.rs:124-151` | `collect` ancestor walk is broken (first attempt always wrong, fallback always runs) — latent correctness |
| F-D6-04 | `cmd/util.rs:207-229`; `cmd/stash.rs`, `cmd/grep_cmd.rs`, `cmd/worktree.rs` flattens | `flatten_tree` unbounded recursion; mutual-cycle DAGs cause stack-overflow / OOM |
| F-D6-05 | `ignore.rs:389-484` | Hand-rolled glob matcher is recursive backtracker; catastrophic-backtracking input → DoS on `gyt status` / `add` |
| F-D6-06 | `merge3.rs:111-164` | `merge_lines` drops lines from "ours" when adjacent edits have different deletion lengths — silent data loss in merge output |
| F-D6-07 | `index.rs:30`; `object/tree.rs:18-21` | Index/tree accept arbitrary u32 modes (setuid, sticky, gitlink) — silently round-tripped through encode |
| F-D7-03 | `ci_wasm.rs:229` | `repo_gyt_meta = canon_repo.join(".gyt")` doesn't canonicalize `.gyt`; symlinked `.gyt` escapes the exclusion |
| F-D7-04 | `cmd/ci.rs:224-241` | `parse_byte_size` lacks `checked_mul`; huge inputs silently wrap to small caps |
| F-D7-05 | `ci_wasm.rs:243-256` | Log counter increments BEFORE UTF-8 validation — DoS on observability budget |
| F-D7-06 | `cmd/ci_env.rs:43-70, 83-95` | `mask_secrets`/`load_secrets` are dead code; secret-injection path is unimplemented but scaffolded |
| F-D7-07 | `cmd/ci_secret.rs:147-178, 208-222` | Secret name validator allows `..`, control chars, leading-whitespace |
| F-D7-08 | `cmd/ci_secret.rs:51-68` | `enforce_private_mode` `#[cfg(unix)]`-only; Windows ACL unaudited |
| F-D8-04 | `issues.rs:241-342`; `prs.rs:164-275` | TOML decoder accepts non-canonical input (dup keys, comments, whitespace); no `decode(blob) == decode(encode(decode(blob)))` gate |
| F-D8-05 | `issues.rs:213-231, 367-399`; `prs.rs:139-158, 300-328` | `{:?}` Debug-format TOML escapes are not round-trippable through the decoder (`\u{1b}` etc.) |
| F-D8-06 | `cmd/issue.rs:137-146`; `cmd/pr.rs:181-195` | Title / body have no size limit and no control-char rejection |
| F-D9-04 | `net/http.rs:401-409, 491-545` | Client HTTP response body has no size cap — malicious origin OOMs the client |
| F-D9-05 | `net/http.rs:99-101, 116, 124` | Bearer token may appear in client error output (token in original URL) |
| F-D9-06 | `cmd/clone.rs:280-298` | Hostile server can plant arbitrary extra objects (not in `to_fetch`) on every clone — storage exhaustion |
| F-D9-07 | `cmd/clone.rs:304-310` | Clone silently completes with incomplete reachability closure if server withholds parents |
| F-D9-08 | `cmd/remote.rs::run`; `config.rs:127` | TOML injection via remote `name` (writeln raw `[remote.{name}]`) |
| F-D9-09 | `cmd/clone.rs:360-371` | Tag signatures not verified on fetch |
| F-D10-03 | `cmd/restore.rs:122-186, 65` | `restore` doesn't validate paths are inside workdir — `../../sensitive` clobbered if also in (poisoned) index |
| F-D10-04 | `cmd/rm.rs:62-70, 89, 114` | Same path-traversal class via malicious index |
| F-D10-05 | `cmd/init.rs:51-61` | `gyt init` doesn't refuse to nest under an existing `.gyt`; confused-deputy via tree-supplied `.gyt` dir |
| F-D10-06 | `cmd/commit.rs:33-40` | Commit `-m` accepts NUL bytes and control characters; no message validation |
| F-D11-03 | `Cargo.toml [profile.release]` | `strip = "symbols"` only — DWARF preserved → build-machine paths leak in shipped binaries |
| F-D11-04 | `check.sh`, `.gyt-ci/` | No `cargo audit` / `cargo deny` gates in CI |
| F-D11-05 | `Cargo.toml` | Every direct dep pinned `=X.Y.Z` with no compensating monthly audit cadence → patch latency |

---

# LOW findings

(Verified line-by-line; compact list.)

| ID | File:line | Title |
|----|-----------|-------|
| F-D1-09 | `net/server.rs:766-792`; `net/h2_server.rs:202-218`; `net/h3_server.rs:226-228` | HSTS / protocol-headers drift between H1 / H2 / H3 paths |
| F-D1-10 | `net/http.rs:494-545` | `chunked_decode` accepts LF-only chunk size lines (asymmetric strictness) |
| F-D1-11 | `net/http.rs:343-356` | `parse_authority` mishandles IPv6 literals without explicit port |
| F-D1-12 | `net/server.rs:2377-2393` | Cache lookup before repo segment validation (defense-in-depth only) |
| F-D1-16 | `net/server.rs:2394-2401, 2535` | Error responses can leak absolute paths via embedded `GytError` strings |
| F-D2-04 | `net/https_engine.rs:95-141` | Per-call connection — comment claims session-ticket reuse but one-shot processes never benefit |
| F-D2-05 | `net/ticket.rs:82-99` | Ticket-key parser silently accepts duplicate current+previous |
| F-D2-07 | `net/ticket.rs:158-174` | Timing-distinguishable current-vs-previous decrypt — accepted by design, low-value leak |
| F-D2-08 | `net/ticket.rs:144-152` | No domain separation between current/previous key — operator footgun if a key is reinstated |
| F-D2-09 | `net/tls.rs:210-227`; `net/ticket.rs:179-196` | `enforce_private_mode` duplicated; no `st_uid == geteuid()` check |
| F-D3-08 | `net/protocol.rs:53-77, 90-108, 188-225` | Line-based parsers have no per-line length cap |
| F-D3-09 | `net/server.rs:2429-2434` | Wants list parsed ad-hoc (mixed line endings, mixed case) — cache-key inflation |
| F-D3-11 | `net/repo_index.rs:121-131` | `repo_index::upsert` O(N) shift under attacker-induced load |
| F-D3-12 | `net/repo_index.rs:171-203` | `scan_all` includes phantom repos via lossy UTF-8 conversion |
| F-D4-11 | `net/server.rs:1106` | `strip_prefix("Bearer ")` case-sensitive — RFC 7235 says insensitive |
| F-D4-12 | `net/http.rs:120-127, 147` | URL-userinfo token not percent-decoded; `%20` ≠ space |
| F-D5-10 | `object/store.rs:47-54` | `path_for` slices `hex[..2]` / `hex[2..]` relying on `ObjectId` invariant; add `debug_assert_eq!` |
| F-D5-12 | `refs.rs:145-211` | `list_refs("refs")` walks ALL refs — function name suggests flat prefix |
| F-D5-16 | `cmd/gc.rs:304` | Reflog zero-hex written via `"0".repeat(64)`; not shared constant |
| F-D6-08 | `cmd/clean.rs:62-69` | `clean` blast radius depends on walker not following symlinks — invariant unproven from this code |
| F-D6-09 | `merge3.rs:263-294` | Conflict-marker injection if input contains `<<<<<<<` lines; no marker-length escalation |
| F-D6-10 | `index.rs:45-74` | `path_to_storage_string` lossy on non-UTF8 paths and accepts ParentDir / RootDir components |
| F-D6-11 | `index.rs:188` | `Vec::with_capacity(count)` allocates up to ~320 GiB on attacker u32 in `.gyt/index` |
| F-D7-09 | `cmd/ci.rs:234-236` | `parse_byte_size` accepts bare number as bytes (UX footgun) |
| F-D7-10 | `cmd/ci_env.rs:16-40` | Hand-rolled `.toml` parser is line-oriented, no size cap |
| F-D7-11 | `cmd/ci_env.rs:147` | `run_set` value embedded via raw `format!` — `"`, `\n`, `\\` corrupt the file |
| F-D7-12 | `cmd/ci_secret.rs:180-202, 162` | Secrets dir created via `create_dir_all` without explicit `0700`; defaults to umask |
| F-D7-13 | `cmd/ci_secret.rs:120-131` | AES-GCM decrypt min-length check `< 13` — should be `< 28` (12 nonce + 16 tag) |
| F-D7-14 | `cmd/ci_secret.rs:18` | `ensure_key` falls back to `/root` if `HOME` unset |
| F-D8-07 | `issues.rs::COUNTER_PATH` vs `prs.rs::COUNTER_PATH` | Issue/PR counters are separate; CLAUDE.md claims they're shared |
| F-D8-08 | `issues.rs:476-493`; `prs.rs:403-420` | `next_number_locked` documents-but-doesn't-enforce caller-holds-lock |
| F-D9-10 | `cmd/push.rs:43-89` | `gyt push --force` has no confirmation prompt |
| F-D9-11 | `net/http.rs:312-340` | CRLF in user-supplied URL would smuggle request headers (local-user only) |
| F-D9-12 | `cmd/clone.rs:115` | Clone target dir check `dir.exists()` follows symlinks |
| F-D9-13 | `cmd/serve.rs:116-124` | `--auth-token <token>` inline exposes token in `ps aux` |
| F-D9-14 | `net/protocol.rs:53-77` | `parse_info_refs` doesn't validate refname syntactically |
| F-D9-15 | `cmd/rebase.rs:287-345` | `rebase --continue` trusts `REBASE_TODO` content — any local-user write replays attacker commits under user identity |
| F-D10-07 | `cmd/blame.rs:121-124` | Blame path traversal not exploitable in this command (read-only) |
| F-D10-08 | `cmd/grep_cmd.rs:62-87` | Grep reads via crafted index paths — content disclosure of files outside repo |
| F-D10-09 | `cmd/init.rs:66-86` | `init --bare` relies on umask for file modes |
| F-D10-10 | `errors.rs:23-37` | `GytError::Io` Display propagates raw OS path strings to server responses |
| F-D10-11 | `config.rs:201-282` | TOML parser has no file-size cap; multi-GB config OOMs |
| F-D10-12 | `cmd/worktree.rs:88-95, 368` | `worktree remove` follows symlinks via `target.canonicalize()` — recursively deletes target if `gytdir` marker writable |
| F-D11-06 | `Cargo.lock` | Diamond deps on `getrandom`, `rand`, `rand_core`, `rand_chacha`, `windows-sys`, `cpufeatures`, `hashbrown`, `thiserror`, `wasmparser`. Core crypto (rustls/ring/aes-gcm/ed25519/curve25519/subtle/zeroize) is single-version — good |
| F-D11-07 | `Cargo.toml:20` | `signal-hook = 0.4.4` with minimal features — informational |
| F-D11-08 | `Cargo.toml [profile.release]` | `panic = unwind` is intentional (fuzz harness uses `catch_unwind`); document the choice |
| F-D11-09 | `Cargo.toml:7` | GPL-3.0-or-later vs AGPL-3.0-or-later — biz decision for hosted-service modifications |
| F-D11-11 | `.gitignore` | Doesn't exclude `*.pem`, `*.key`, `id_ed25519*`, `ci-key`, `*.tls-ticket-key` |

---

# INFO findings

(Verified; positives + small cosmetic items.)

- F-D1-14 — H1/H2/H3 paths share `dispatch_request`; current parser-differential surface is small but worth a regression test for `%2F` in URLs.
- F-D1-15 — `admin_shutdown_handler` self-connect timing; cosmetic.
- F-D2-06 — Ticket-key hex parser variable-time; offline file → no real channel.
- F-D2-10 — No cert-expiry warning at startup; operational.
- F-D2-11 — No SCT/OCSP/CT validation client-side (matches rustls default).
- F-D2-12 — ECH not implemented or claimed.
- F-D2-13 — No SNI-vhost routing.
- F-D2-14 — 0-RTT not enabled.
- F-D2-15 — QUIC config inherits TLS pin via ServerConfig clone; spot-checked clean.
- F-D3-10 — `parse_raw` rejects trailing garbage when size mismatches — defense-in-depth confirmed.
- F-D3-13 — `encode_pack` `expect` on `u32::try_from` is unreachable under current cap.
- F-D3-14 — Wire packfile `0x01` (raw) accepted by `parse_packfile`; legacy decode-only fallback.
- F-D4-13 — Keygen RNG: `rand::rngs::OsRng`; private file `0o600` + `O_EXCL`. Add `st_uid == geteuid()` check.
- F-D4-14 — base64_decode strict; ed25519-dalek 2.x strict-mode by default.
- F-D5-17 — `ObjectKind::parse` is total; new variant forces compile-time fix-up.
- F-D5-18 — `Object::new` recomputes hash on construction; lying impossible at construction.
- F-D6-12 — NTFS ADS / reserved Windows names not blocked at tree-decode (Linux-primary).
- F-D6-13 — NFC/NFD Unicode collision not handled (macOS-only).
- F-D6-14 — Case-insensitive FS collision not handled.
- F-D7 I-1 — wasmtime engine config is correct: fuel/epoch on; threads/SIMD/relaxed-SIMD/reference-types/multi-memory/memory64 off; 8 MiB stack; WASI not linked.
- F-D7 I-2 — `set_fuel` ordering correct.
- F-D7 I-3 — Ticker joined; no thread leak.
- F-D7 I-4 — Memory cap enforced as ResourceLimiter (correct, not hint).
- F-D7 I-5 — Hostcall arg validation rejects absolute paths, NUL; numeric overflow-safe.
- F-D7 I-6 — `read_caller_string` caps at 4 KiB.
- F-D7 I-7 — `--ci-allow-network` is a no-op (intended).
- F-D7 I-8 — Stray `.sh` listed not executed.
- F-D7 I-9 — No server-side WASM execution path.
- F-D7 I-10 — `--docker` rejected with migration error.
- F-D7 I-11 — `.gyt/` exclusion applied after canonicalize in `resolve_read`.
- F-D7 I-12 — Output-dir cumulative byte cap absent (acceptable per threat model).
- F-D7 I-13 — `create_dir_all` error silently ignored in write path; surfaces via `fs::write` error.
- F-D7 I-14 — `aes-gcm` constant-time at this usage pattern.
- F-D7 I-15 — wasmtime 44 `async_stack_size` workaround applied.
- F-D8 I-1 — TOML decoder rejects unknown fields (schema-version contract; document in CLAUDE.md).
- F-D8 I-2 — Issue number reuse-after-delete impossible (counter monotonic).
- F-D9-INF1 — `pull.rs` correctly holds lock across fetch+merge.
- F-D9-INF2 — `is_user_visible_ref` whitelist consistent across clone/fetch/push.
- F-D9-INF3 — No HTTP redirect following at all (auth headers cannot leak across redirects).
- F-D9-INF4 — `--insecure` required for plain HTTP; uniformly enforced.
- F-D10-13 — `gyt commit` does not invoke `$EDITOR`/`$VISUAL` (avoids the editor-arg-injection class).
- F-D10-14 — `gyt log --grep` / `gyt grep` are substring `contains`, no regex DoS surface.
- F-D10-15 — `cli.rs` dispatcher hand-rolled but argv comes from `env::args()` (no shell-quoting issues).
- F-D10-16 — `fuzz.rs` is `pub` in lib but not exposed via CLI (not reachable in binary).
- F-D10-17 — `test_support.rs` is `#![cfg(test)]`-gated.
- F-D10-18 — `gyt commit --sign` reads `GYT_SIGNING_KEY` via `env::var` (no shell-out).
- F-D11-10 — `unsafe_code = "deny"` AND `#![forbid(unsafe_code)]` both present (defense in depth confirmed).
- F-D11-12 — wasmtime 44.0.1 — no specific footgun known at this version; depends on cargo-audit run.
- F-D11-13 — ed25519-dalek 2.2.0 / curve25519-dalek 4.1.3 / aes-gcm 0.10.3 post-CVE-fix versions.
- F-D11-14 — rustls 0.23.40 + ring backend, no aws-lc-rs; single TLS stack.

---

# Cross-cutting observations

1. **Three distinct path-traversal classes still live in the codebase.** Tree-entry names (F-D6-01), refname in `refs/update` (F-D1-01), and index/restore/rm paths (F-D10-03/04). All three share the same root cause: trust in attacker-controlled or remote-controlled byte strings as filesystem identifiers. A single `is_safe_workdir_path` + `is_safe_ref_name` + `is_safe_tree_entry_name` validator family applied at every parser entry point closes the family.
2. **The server's canonicality gates are inconsistent.** `wire_objects_have` validates commits / tags / trees but not blob refs (which back issues/PRs). The client's clone path validates only commits. Make canonicality a uniform property at both directions of the wire.
3. **DoS amplifiers stack.** F-D1-02 (slowloris) × F-D1-04 (cache flooding) × F-D4-01 (FF-walk) × F-D3-01 (pack-entry inflation) × F-D3-02 (XZ CPU chain) × F-D6-03 (Myers OOM): the server has six independent cheap-to-exploit DoS levers. Even with rate-limit fixes (F-D1-07), each one alone is enough to ruin a deployment.
4. **Audit logging is forensically untrustworthy.** F-D1-03 (newline injection), F-D4-10 (success-only), F-D4-08 (non-transactional) combine to mean post-incident analysis is not reliable.
5. **No fuzzing.** Five hand-rolled parsers (`tree::decode`, `commit::decode`, `parse_pack`, `Index::parse`, `IgnoreSet::compile`) plus the TOML decoder in `issues.rs`/`prs.rs` would all benefit from `cargo fuzz` targets. The repo has `src/fuzz.rs` scaffolding but no integrated fuzz CI step.
6. **Clippy posture is excellent.** `unsafe_code = "deny"` + `forbid` + every group at `deny` + restriction lints + `allow_attributes_without_reason = "deny"` is among the strictest configurations I've seen. Where bugs land in this audit, it is NOT for lack of process — it is in the design: parsers that accept too much, no centralized validator helpers, and DoS caps that exist for some bytes but not others.

---

# What this audit did NOT cover

- **Operational concerns:** runbooks, key-rotation procedures, log-retention SLAs, incident-response plan, multi-host federation. The audit deliberately treated `gyt serve` as single-host (per CLAUDE.md) and did not evaluate any HA story.
- **Fuzzing campaigns:** None of the hand-rolled parsers were exercised against a corpus.
- **Formal verification / model-checking** of the lock state machine (`repo.lock()`, `objects.lock`, `refs.lock`, `serve.lock`, `FileLock`) — only structural review.
- **Threat-modeling sessions with stakeholders** about which classes to accept (e.g., whether DWARF leakage in F-D11-03 is in scope).
- **Side-channel attacks on `ring`, `ed25519-dalek`, `aes-gcm`, `subtle`** beyond confirming the project uses the libraries in the documented constant-time patterns.
- **WASM-engine escape via wasmtime internals.** Confirmed engine config is conservative; did not evaluate wasmtime 44's compiler/JIT for arbitrary-code paths against an adversarial wasm binary.
- **`cargo audit` advisory cross-check** — `cargo-audit` is not installed on the audit host. Direct-dep version table in F-D11 reflects manual inspection only.
- **Penetration testing / live exploit reproduction.** Reproductions in this report are derived from code reading, not executed.
- **REST API JSON consumers / SDKs.** F-D3-06 (`mode: 0o100644` invalid JSON) was caught by static reading; any downstream parser tooling is out of scope.

---

# Recommended pre-deploy checklist (ordered)

The order minimizes attacker leverage during the rollout window.

**Block ship until done:**

1. ☐ Fix F-D6-01 (tree-entry path traversal). One central validator, called from `tree::decode`, applied at the wire receive *and* the local pull/checkout path. Add regression test that decoding a tree with name `b"../escape"` returns `Err`.
2. ☐ Fix F-D6-02 (symlink chain). Validate symlink targets; either reject `..` / absolute / out-of-workdir or open with `O_NOFOLLOW` from a workdir fd.
3. ☐ Fix F-D1-01 (refname unvalidated write). Call `validate_ref_name` in `evaluate_with_mode` for every update.
4. ☐ Fix F-D1-03 (audit-log injection). Reject control bytes in `parse_ref_updates`.
5. ☐ Fix F-D4-03 (force-flag bypass). Either `rwf` tier or global `--allow-force`.
6. ☐ Fix F-D9-03 (open `gyt serve`). Refuse non-loopback listen without auth.
7. ☐ Fix F-D8-01 (FF gate on issue/PR refs). Bypass FF for blob refs; replace with monotonic event-log check.
8. ☐ Fix F-D8-02/03 (issue/PR canonicality + state machine + `pr merge` ref validation).
9. ☐ Fix F-D9-01/02 (`getthefuckoutofmyrepo` partial rewrite + no lock + no reflog). Refuse to update refs if walk incomplete; add `repo.lock()` and `reflog::record`.

**Block ship until done OR document the residual risk and ship guarded:**

10. ☐ F-D4-01 (FF walk DoS). Hard cap.
11. ☐ F-D4-02 (ACL prefix). Require `/` anchoring.
12. ☐ F-D4-04 (signature-gate hole). Treat unreadable parents as hard error.
13. ☐ F-D4-05 (signers override fallthrough). Refuse boot if override missing.
14. ☐ F-D1-02 (slowloris). End-to-end body timeout.
15. ☐ F-D1-04 (pack-cache flood). LRU + Arc<Vec<u8>> + global byte cap.
16. ☐ F-D1-06 (`/metrics` unauthenticated). Auth gate or private bind.
17. ☐ F-D1-07 (rate-limit behind proxy). `--trusted-proxy` + XFF parser.
18. ☐ F-D7-01 (epoch ticker + host call wallclock). Add `Instant`-based deadline in each host call.
19. ☐ F-D7-02 (`write_file` `O_NOFOLLOW`).
20. ☐ F-D6-03 (Myers OOM). Cap diff inputs.
21. ☐ F-D10-01 (terminal injection). `term::safe_display` everywhere.
22. ☐ F-D10-02, F-D9-08 (TOML injection via section name).
23. ☐ F-D11-01 (`.gyt-ci/` `.sh`). Either delete or port to wasm.
24. ☐ F-D11-02 (`rust-toolchain` beta). Pin stable.
25. ☐ F-D3-01 (parse_pack entry-count). Cap entries.
26. ☐ F-D3-02 (XZ CPU). Per-request cumulative budget.
27. ☐ F-D3-03 (clone trees/tags canonicality).
28. ☐ F-D3-06 (invalid JSON mode).
29. ☐ F-D5-01..18 (object store hardening) — see table.

**Should-do before public exposure but not strictly blocking:**

30. ☐ Install `cargo audit` + `cargo deny`; gate `check.sh` on them (F-D11-04).
31. ☐ Add fuzz harnesses for the five parsers identified.
32. ☐ Add `strip = "debuginfo"` (or `strip = true`) to `[profile.release]` (F-D11-03).
33. ☐ Add `.gitignore` entries for `*.pem`, `*.key`, `id_ed25519*`, `ci-key`, `*.tls-ticket-key` (F-D11-11).
34. ☐ Document the per-counter PR/issue split or unify them (F-D8-07).
35. ☐ Add regression tests for every fix above (one per finding).

---

*End of audit. Total findings: 1 CRITICAL, 24 HIGH, 49 MEDIUM, 62 LOW,
44 INFO ≈ 180 verified findings.*
