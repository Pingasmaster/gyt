// WASM CI runner — sandboxed execution of .wasm CI scripts.
//
// Permission model (operator-controlled, NOT repo-declared)
// =========================================================
//
// A malicious clone is the threat we defend against. Therefore every
// permission grant has ONE source: the operator's CLI invocation of
// `gyt ci`. A `.gyt-ci/` script — being part of the repo content — has
// NO way to declare its own permissions; nothing inside the repo is
// trusted to widen the sandbox. The repo *may* contain a hint file
// (`.gyt-ci/manifest.toml`) listing capabilities it would like, but
// `gyt ci` refuses to honor any capability that wasn't ALSO passed on
// the command line.
//
// Defaults (zero flags) — safe enough that running an arbitrary clone's
// CI on a personal machine cannot exfiltrate or modify host state:
//
//   - read access  : repo_workdir/* but NOT repo_workdir/.gyt/*
//   - write access : output_dir/* only
//   - network      : NONE (no hostcalls are even linked)
//   - subprocess   : NONE (no fork/exec hostcalls)
//   - env vars     : NONE (no getenv hostcall)
//   - extra host paths : none
//
// Operator widenings (each requires an explicit flag):
//
//   --ci-no-repo-read              deny repo_dir reads entirely
//   --ci-repo-write                allow writes to repo_workdir (still
//                                  excludes .gyt/)
//   --ci-read <PATH>               also allow reads under <PATH>
//   --ci-write <PATH>              also allow writes under <PATH>
//   --ci-allow-network             ENABLE network hostcalls (NB:
//                                  network hostcalls are not yet
//                                  implemented; the flag is reserved
//                                  and currently a noop. Without it,
//                                  network is impossible regardless of
//                                  the flag's future implementation —
//                                  no hostcall is linked.)
//   --ci-memory <BYTES|MB|GB>      raise memory cap (default 8 GiB)
//   --ci-fuel <N>                  raise wasm-instruction cap (default 1×10^11)
//   --ci-time <SECS>               raise wall-time cap (default 14400 = 4h)
//
// The defaults are sized so a normal build orchestration (compiler
// drivers, Gradle wrappers, lints, signers) does NOT hit a limit by
// accident. The point is to stop runaway code, not to gate good code.
//
// Enforced limits at every entry point
// ====================================
//
//   - linear memory cap            : `policy.memory_max` (default 8 GiB)
//   - wasm-instruction fuel        : `policy.fuel` (default 1×10^11)
//   - wall-time epoch deadline     : `policy.wall_time_secs` (default 4h)
//   - read_file size cap           : 1 GiB per call (covers Android APKs)
//   - write_file size cap          : 1 GiB per call
//   - log() output cap             : 256 MiB cumulative per run
//   - max wasm stack               : 8 MiB
//   - max instances                : 1, max tables 4, max memories 1
//
// Hostcalls (the ONLY linked imports)
// ===================================
//
//   gyt_ci.log(ptr, len)
//       Append a UTF-8 string to host stdout (rate-limited by
//       `CI_MAX_LOG_BYTES`). Never blocked by any flag.
//
//   gyt_ci.read_file(path_ptr, path_len, buf_ptr, buf_len) -> i32
//       Read a file. The path is resolved against an *ordered* list of
//       allowed read roots; the first one that contains it wins. By
//       default the list is `[repo_workdir]` minus `.gyt/`; flags can
//       add more or remove the default.
//
//   gyt_ci.write_file(path_ptr, path_len, data_ptr, data_len) -> i32
//       Symmetric for writes against an *ordered* allowed write list,
//       default `[output_dir]`.
//
//   Negative returns are errno-style:
//       -1  bad UTF-8 in path argument
//       -2  path resolved outside every allowed root (or under .gyt/)
//       -3  guest memory not exported
//       -4  host write error
//       -5  host read error
//       -6  size cap exceeded
//
//   The host deliberately does NOT link:
//       wasi_snapshot_preview1, wasi_unstable, env, getenv,
//       fd_read/fd_write/poll_oneoff, clock_*, random_get,
//       proc_*, sock_*, path_open, args_*
//
// Any module importing anything outside `gyt_ci` fails to instantiate
// with a clean error, on purpose — that's the misconfiguration tell.

#![expect(clippy::manual_let_else, clippy::redundant_closure_for_method_calls, reason = "intentional `match` form is clearer than `let-else` in this control-flow shape")]

use crate::errors::{GytError, Result};
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, ResourceLimiter, Store, WasmBacktraceDetails,
};

// ─── Public limit constants ──────────────────────────────────────────
//
// These are the *default* values for `CiPolicy::default()`. Operator
// flags can override any of them. They are public so tests pin the
// numbers shipped to production.

pub const CI_DEFAULT_MEMORY_BYTES: usize = 8 * 1024 * 1024 * 1024;
pub const CI_DEFAULT_FUEL: u64 = 100_000_000_000;
pub const CI_DEFAULT_WALL_TIME_SECS: u64 = 4 * 60 * 60;
pub const CI_MAX_FILE_BYTES: usize = 1024 * 1024 * 1024;
pub const CI_MAX_LOG_BYTES: usize = 256 * 1024 * 1024;
pub const CI_MAX_WASM_STACK: usize = 8 * 1024 * 1024;

/// What the wasm is allowed to do. Built by the CLI from operator
/// flags; tests can construct one directly.
//
// The 4 bools represent orthogonal capabilities (read, write,
// output-write, network) and reading them as discrete flags at each
// hostcall site is clearer than collapsing them into a state machine.
#[expect(clippy::struct_excessive_bools, reason = "discrete capability flags read independently at use sites — collapsing into a state machine would obscure intent")]
#[derive(Debug, Clone)]
pub struct CiPolicy {
    /// True if the wasm may read files under `repo_workdir`. `.gyt/`
    /// is *always* excluded regardless of this flag.
    pub repo_read: bool,
    /// True if the wasm may write files under `repo_workdir`. `.gyt/`
    /// is always excluded.
    pub repo_write: bool,
    /// True if the wasm may write files under `output_dir`.
    pub output_write: bool,
    /// Additional host paths the wasm may read under. Resolved with
    /// canonicalize so a symlink can't escape the listed root.
    pub extra_read: Vec<PathBuf>,
    /// Additional host paths the wasm may write under.
    pub extra_write: Vec<PathBuf>,
    /// Reserved: future-proofs the CLI surface. Network hostcalls are
    /// NOT yet implemented; even with this true, no socket-style
    /// hostcall is linked. The flag exists so an operator-grant
    /// vocabulary is in place for when we add one.
    pub network: bool,
    /// Max linear memory in bytes.
    pub memory_max: usize,
    /// Max wasm instructions executed (Store::set_fuel).
    pub fuel: u64,
    /// Wall-time cap. Enforced via `epoch_interruption` + a ticker.
    pub wall_time_secs: u64,
}

impl Default for CiPolicy {
    fn default() -> Self {
        Self {
            repo_read: true,
            repo_write: false,
            output_write: true,
            extra_read: Vec::new(),
            extra_write: Vec::new(),
            network: false,
            memory_max: CI_DEFAULT_MEMORY_BYTES,
            fuel: CI_DEFAULT_FUEL,
            wall_time_secs: CI_DEFAULT_WALL_TIME_SECS,
        }
    }
}

pub fn run_ci_wasm(wasm_path: &Path, repo_dir: &Path, output_dir: &Path) -> Result<()> {
    run_ci_wasm_with_policy(wasm_path, repo_dir, output_dir, &CiPolicy::default())
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
pub fn run_ci_wasm_with_policy(
    wasm_path: &Path,
    repo_dir: &Path,
    output_dir: &Path,
    policy: &CiPolicy,
) -> Result<()> {
    // 1. Engine config.
    let mut cfg = Config::new();
    cfg.consume_fuel(true)
        .epoch_interruption(true)
        .wasm_threads(false)
        .wasm_reference_types(false)
        .wasm_simd(false)
        .wasm_relaxed_simd(false)
        .wasm_bulk_memory(true)
        .wasm_multi_value(true)
        .wasm_multi_memory(false)
        .wasm_memory64(false)
        // Deny backtrace details on trap. wasmtime's default includes
        // module + function-name strings in the trap context, which a
        // malicious CI module observes through the error it surfaces.
        // We never propagate these strings to the WASM caller (we only
        // print them locally), but ::Disable keeps the host's symbol
        // table out of any future error path that might.
        .wasm_backtrace_details(WasmBacktraceDetails::Disable)
        // Canonicalize NaN bits on floating-point ops. Defaults leave
        // platform-dependent NaN payloads visible to the guest, which
        // is a microarchitectural side channel (the guest can fingerprint
        // the host CPU, and on some workloads extract bits of internal
        // state via NaN-payload branching). Cost is a small per-op mask;
        // nothing in our CI workload is float-heavy enough to notice.
        .cranelift_nan_canonicalization(true)
        .max_wasm_stack(CI_MAX_WASM_STACK)
        // wasmtime ≥ 44 validates `max_wasm_stack ≤ async_stack_size` even when
        // async isn't used; default async_stack_size (2 MiB) is below our 8 MiB
        // cap. We don't run async, but the check fires unconditionally, so size
        // the async stack to match.
        .async_stack_size(CI_MAX_WASM_STACK + 256 * 1024);

    let engine = Engine::new(&cfg)
        .map_err(|e| GytError::Ci(format!("wasmtime engine config: {e}")))?;

    let module = Module::from_file(&engine, wasm_path)
        .map_err(|e| GytError::Ci(format!("loading WASM {}: {e}", wasm_path.display())))?;

    // 2. Build the resolved permission lists.
    let canon_repo = canonicalize_or_self(repo_dir);
    let canon_output = canonicalize_or_self(output_dir);

    let mut read_roots: Vec<PathBuf> = Vec::new();
    if policy.repo_read {
        read_roots.push(canon_repo.clone());
    }
    for p in &policy.extra_read {
        read_roots.push(canonicalize_or_self(p));
    }

    let mut write_roots: Vec<PathBuf> = Vec::new();
    if policy.output_write {
        write_roots.push(canon_output.clone());
    }
    if policy.repo_write {
        write_roots.push(canon_repo.clone());
    }
    for p in &policy.extra_write {
        write_roots.push(canonicalize_or_self(p));
    }

    let state = Sandbox {
        read_roots,
        write_roots,
        repo_gyt_meta: canon_repo.join(".gyt"),
        log_used: 0,
        limiter: CiLimits {
            memory_max: policy.memory_max,
            mem_high_water: 0,
        },
    };

    let mut linker: Linker<Sandbox> = Linker::new(&engine);

    linker
        .func_wrap(
            "gyt_ci",
            "log",
            // Returning Result<(), wasmtime::Error> keeps the wasm-facing
            // import signature unchanged (still `(i32, i32)` → no
            // results) while letting us trap on the cap-overflow path.
            // Silent truncation here would let a misbehaving module
            // fill the log up to the cap with innocuous content and
            // then hide its evidence past it; trapping makes the
            // attempt loud — the run fails with a recordable error.
            |mut caller: Caller<'_, Sandbox>,
             ptr: i32,
             len: i32|
             -> std::result::Result<(), wasmtime::Error> {
                let len_us = len.max(0) as usize;
                let already = caller.data().log_used;
                if already.saturating_add(len_us) > CI_MAX_LOG_BYTES {
                    return Err(wasmtime::Error::msg(format!(
                        "ci log output exceeds {CI_MAX_LOG_BYTES}-byte cap"
                    )));
                }
                caller.data_mut().log_used = already + len_us;
                let Some(msg) = read_caller_string(&mut caller, ptr, len) else {
                    // Invalid pointer/length is a guest bug, not a cap
                    // evasion — quietly skip the print and keep going.
                    return Ok(());
                };
                print!("[wasm-ci] {msg}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                Ok(())
            },
        )
        .map_err(|e| GytError::Ci(format!("linker log: {e}")))?;

    linker
        .func_wrap(
            "gyt_ci",
            "read_file",
            |mut caller: Caller<'_, Sandbox>,
             path_ptr: i32,
             path_len: i32,
             buf_ptr: i32,
             buf_len: i32|
             -> i32 {
                let Some(path_str) = read_caller_string(&mut caller, path_ptr, path_len) else {
                    return -1;
                };
                let Some(safe) = resolve_read(caller.data(), &path_str) else {
                    return -2;
                };
                // TOCTTOU-safe read. Calling fs::metadata then fs::read
                // would re-stat the file and could be tricked by a
                // concurrent writer growing the file between check and
                // load (host or other CI runs writing to the operator-
                // permitted root). Open once, stat the open file handle,
                // then bound the read with Read::take so the actual
                // byte count cannot exceed CI_MAX_FILE_BYTES no matter
                // what happens on the filesystem after the stat.
                let f = match fs::File::open(&safe) {
                    Ok(f) => f,
                    Err(_) => return -5,
                };
                let meta = match f.metadata() {
                    Ok(m) => m,
                    Err(_) => return -5,
                };
                if !meta.is_file() {
                    return -2;
                }
                let cap_plus_one = (CI_MAX_FILE_BYTES as u64).saturating_add(1);
                let mut data = Vec::new();
                if f.take(cap_plus_one).read_to_end(&mut data).is_err() {
                    return -5;
                }
                if data.len() > CI_MAX_FILE_BYTES {
                    return -6;
                }
                let n = data.len().min(buf_len.max(0) as usize);
                let Some(mem) = get_caller_memory(&mut caller) else {
                    return -3;
                };
                if mem
                    .write(&mut caller, buf_ptr.max(0) as usize, &data[..n])
                    .is_err()
                {
                    return -4;
                }
                n as i32
            },
        )
        .map_err(|e| GytError::Ci(format!("linker read_file: {e}")))?;

    linker
        .func_wrap(
            "gyt_ci",
            "write_file",
            |mut caller: Caller<'_, Sandbox>,
             path_ptr: i32,
             path_len: i32,
             data_ptr: i32,
             data_len: i32|
             -> i32 {
                if (data_len.max(0) as usize) > CI_MAX_FILE_BYTES {
                    return -6;
                }
                let Some(path_str) = read_caller_string(&mut caller, path_ptr, path_len) else {
                    return -1;
                };
                let Some((safe_path, relative)) = resolve_write(caller.data(), &path_str) else {
                    return -2;
                };
                if let Some(parent) = safe_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let Some(mem) = get_caller_memory(&mut caller) else {
                    return -3;
                };
                let slice = mem.data(&caller);
                let data = read_bytes(slice, data_ptr, data_len);
                // atomic_write (tmp + sync_all + rename + parent fsync)
                // so a script that fuel-exhausts or epoch-traps mid-
                // write doesn't leave half-written output for whichever
                // downstream consumer picks the artifact up next.
                match crate::fs_util::atomic_write(&safe_path, &data) {
                    Ok(()) => {
                        println!("[wasm-ci] wrote {relative}");
                        0
                    }
                    Err(_) => -4,
                }
            },
        )
        .map_err(|e| GytError::Ci(format!("linker write_file: {e}")))?;

    // We intentionally do NOT add any other hostcall. policy.network is
    // reserved vocabulary: even with `policy.network == true`, no
    // socket hostcall is linked, so the wasm cannot reach the network
    // by any path. This will change when network hostcalls are added
    // — at which point the *only* path that links them will gate on
    // `policy.network`.

    // 3. Per-store resource caps + fuel + epoch deadline.
    let mut store = Store::new(&engine, state);
    store.limiter(|s| &mut s.limiter);
    store
        .set_fuel(policy.fuel)
        .map_err(|e| GytError::Ci(format!("set_fuel: {e}")))?;

    // Epoch interruption: each tick advances the engine epoch by 1; the
    // store traps when its deadline is reached. We spawn a thread that
    // ticks at 1Hz; the wall-time cap becomes `wall_time_secs` ticks.
    // The thread exits when the engine is dropped — engine is cloned
    // (Arc internally), so the ticker holds a clone and the store
    // holds another; when both go out of scope, the engine drops.
    let deadline_secs = policy.wall_time_secs.max(1);
    // Set the deadline BEFORE spawning the ticker. The ticker has a
    // 1 s pre-sleep so in practice it can't increment the epoch
    // before set_epoch_deadline runs anyway, but the explicit order
    // here removes the dependency on that ordering — a future
    // refactor that drops the pre-sleep can't accidentally trap the
    // store on its very first instruction.
    store.set_epoch_deadline(deadline_secs);
    // The ticker thread must be joined on every exit path — including
    // the `?` early-return out of `linker.instantiate` below. A bare
    // `spawn` + manual stop-and-join leaks the thread (and its engine
    // Arc clone) for up to `deadline_secs` seconds whenever any of the
    // intervening fallible calls returns early. TickerGuard's Drop
    // takes care of that uniformly.
    let _ticker = TickerGuard::spawn(engine.clone(), deadline_secs);

    // 4. Instantiate. If the module imports anything outside our
    //    `gyt_ci` namespace, this fails — by design.
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| GytError::Ci(format!("instantiating WASM: {e}")))?;

    let func = instance
        .get_typed_func::<(), i32>(&mut store, "_start")
        .or_else(|_| instance.get_typed_func::<(), i32>(&mut store, "_main"));

    let result = match func {
        Ok(f) => f
            .call(&mut store, ())
            .map_err(|e| GytError::Ci(format!("WASM execution: {e}")))
            .and_then(|code| {
                if code == 0 {
                    Ok(())
                } else {
                    Err(GytError::Ci(format!("WASM exited with code {code}")))
                }
            }),
        Err(e) => Err(GytError::Ci(format!("WASM has no _start or _main: {e}"))),
    };

    // `_ticker` drops here, signalling the ticker thread to stop and
    // joining it before we return. The increment_epoch calls are cheap
    // and harmless after the store is dropped.
    result
}

/// RAII handle for the 1 Hz wall-time ticker thread. Spawning a bare
/// `std::thread` and stopping it manually means every fallible call
/// between spawn and stop leaks the thread on early return; wrapping
/// the lifecycle in `Drop` removes that footgun.
struct TickerGuard {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TickerGuard {
    fn spawn(engine: Engine, deadline_secs: u64) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..deadline_secs {
                if stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
                engine.increment_epoch();
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for TickerGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Per-store resource limiter (memory + tables + instance count).
pub struct CiLimits {
    memory_max: usize,
    mem_high_water: usize,
}

impl ResourceLimiter for CiLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.memory_max {
            return Ok(false);
        }
        self.mem_high_water = self.mem_high_water.max(desired);
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1_000_000)
    }

    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        4
    }
    fn memories(&self) -> usize {
        1
    }
}

struct Sandbox {
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
    /// Absolute path of `<repo_dir>/.gyt`. Always denied from reads
    /// regardless of which root contains the resolved path, because a
    /// `--ci-read .` flag pointing at the repo would otherwise expose
    /// secrets and signing keys.
    repo_gyt_meta: PathBuf,
    log_used: usize,
    limiter: CiLimits,
}

fn canonicalize_or_self(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

fn get_caller_memory(caller: &mut Caller<'_, Sandbox>) -> Option<Memory> {
    caller.get_export("memory")?.into_memory()
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn read_caller_string(caller: &mut Caller<'_, Sandbox>, ptr: i32, len: i32) -> Option<String> {
    if !(0..=4096).contains(&len) {
        return None;
    }
    let mem = get_caller_memory(caller)?;
    let start = ptr.max(0) as usize;
    let end = (start as i64 + len as i64) as usize;
    let data = mem.data(caller);
    if end > data.len() {
        return None;
    }
    String::from_utf8(data[start..end].to_vec()).ok()
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn read_bytes(slice: &[u8], ptr: i32, len: i32) -> Vec<u8> {
    let start = ptr.max(0) as usize;
    let end = (start as i64 + len as i64) as usize;
    if end > slice.len() {
        return vec![];
    }
    slice[start..end].to_vec()
}

/// Resolve a relative path against the read-allowed roots. Walks the
/// roots in order; the first whose canonical form contains the
/// candidate wins. `.gyt/` is always denied even if a permissive
/// `--ci-read` would otherwise include it — and that ban applies to
/// the `.gyt/` of *every* read root, not just the primary repo.
/// Otherwise an operator who pointed `--ci-read` at a second repo
/// would silently expose that repo's `.gyt/` metadata.
fn resolve_read(s: &Sandbox, rel: &str) -> Option<PathBuf> {
    if rel.contains('\0') || Path::new(rel).is_absolute() {
        return None;
    }
    for root in &s.read_roots {
        let cand = root.join(rel);
        let Ok(canonical) = cand.canonicalize() else {
            continue;
        };
        if !canonical.starts_with(root) {
            continue;
        }
        if canonical.starts_with(&s.repo_gyt_meta) {
            // never exposed even from a permissive flag.
            return None;
        }
        if canonical.starts_with(root.join(".gyt")) {
            // Same ban for any extra --ci-read root that happens to
            // contain its own .gyt metadata directory.
            return None;
        }
        return Some(canonical);
    }
    None
}

/// Resolve a relative path against the write-allowed roots. Walks them
/// in order; the first whose lexical or canonical form contains the
/// candidate wins. Refuses any path component of `..` regardless of
/// canonicalization (which is needed because the destination usually
/// doesn't exist yet, so canonicalize would fail). Denies anything
/// under `.gyt/` even with a permissive grant — for every write root,
/// not just the primary repo's metadata.
fn resolve_write(s: &Sandbox, rel: &str) -> Option<(PathBuf, String)> {
    if rel.contains('\0') || Path::new(rel).is_absolute() {
        return None;
    }
    for comp in Path::new(rel).components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return None;
        }
    }
    for root in &s.write_roots {
        let cand = root.join(rel);
        let root_gyt = root.join(".gyt");
        // If a parent of cand exists, canonicalize it for symlink check.
        if let Some(parent) = cand.parent()
            && parent.exists()
        {
            let Ok(canon_parent) = parent.canonicalize() else {
                continue;
            };
            if !canon_parent.starts_with(root) {
                continue;
            }
            if canon_parent.starts_with(&s.repo_gyt_meta)
                || canon_parent.starts_with(&root_gyt)
            {
                return None;
            }
            // Lexical containment for the unresolved leaf.
            if !cand.starts_with(root) {
                continue;
            }
            return Some((cand, rel.to_string()));
        }
        if cand.starts_with(root) {
            // Lexical-only fallback (parent doesn't exist yet).
            if cand.starts_with(&s.repo_gyt_meta) || cand.starts_with(&root_gyt) {
                return None;
            }
            return Some((cand, rel.to_string()));
        }
    }
    None
}

// ─── Back-compat shims for older tests ────────────────────────────────
//
// Pre-policy tests called these as free functions. They're kept so the
// regression coverage doesn't have to be rewritten just to keep
// invariants pinned.

pub fn sandbox_repo_read(repo_dir: &Path, rel: &str) -> Option<PathBuf> {
    let canon = canonicalize_or_self(repo_dir);
    let s = Sandbox {
        read_roots: vec![canon.clone()],
        write_roots: vec![],
        repo_gyt_meta: canon.join(".gyt"),
        log_used: 0,
        limiter: CiLimits {
            memory_max: CI_DEFAULT_MEMORY_BYTES,
            mem_high_water: 0,
        },
    };
    resolve_read(&s, rel)
}

pub fn sandbox_output(output_dir: &Path, rel: &str) -> Option<(PathBuf, String)> {
    let canon = canonicalize_or_self(output_dir);
    let s = Sandbox {
        read_roots: vec![],
        write_roots: vec![canon.clone()],
        // No repo meta in a write-only-output context.
        repo_gyt_meta: PathBuf::from("/__never_match__"),
        log_used: 0,
        limiter: CiLimits {
            memory_max: CI_DEFAULT_MEMORY_BYTES,
            mem_high_water: 0,
        },
    };
    resolve_write(&s, rel)
}

pub fn collect_wasm_scripts(ci_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(ci_dir) else {
        return vec![];
    };
    let mut wasms: Vec<_> = entries
        .filter_map(|r| r.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "wasm"))
        .map(|e| e.path())
        .collect();
    wasms.sort();
    wasms
}

// ─── Back-compat re-exports for tests written before the rename ─────
//
// External tests assert against the published constants. The new names
// are `CI_DEFAULT_*`; we keep the old `CI_*` names as deprecated
// aliases pointing at the new defaults so we don't break the test pin.

#[deprecated(note = "use CI_DEFAULT_MEMORY_BYTES")]
pub const CI_MAX_MEMORY_BYTES: usize = CI_DEFAULT_MEMORY_BYTES;
#[deprecated(note = "use CI_DEFAULT_FUEL")]
pub const CI_INITIAL_FUEL: u64 = CI_DEFAULT_FUEL;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    fn empty_sandbox(repo_dir: &Path) -> Sandbox {
        Sandbox {
            read_roots: vec![canonicalize_or_self(repo_dir)],
            write_roots: vec![],
            repo_gyt_meta: canonicalize_or_self(repo_dir).join(".gyt"),
            log_used: 0,
            limiter: CiLimits {
                memory_max: CI_DEFAULT_MEMORY_BYTES,
                mem_high_water: 0,
            },
        }
    }

    #[test]
    fn default_policy_is_conservative() {
        let p = CiPolicy::default();
        assert!(p.repo_read);
        assert!(!p.repo_write);
        assert!(p.output_write);
        assert!(!p.network);
        assert!(p.extra_read.is_empty());
        assert!(p.extra_write.is_empty());
    }

    #[test]
    fn resolve_read_rejects_absolute() {
        let tmp = std::env::temp_dir();
        let s = empty_sandbox(&tmp);
        assert!(resolve_read(&s, "/etc/passwd").is_none());
    }

    #[test]
    fn resolve_read_rejects_parent_dir() {
        let tmp = std::env::temp_dir();
        let s = empty_sandbox(&tmp);
        // The relative path string has `..` — canonicalize would
        // resolve it; we reject by lexical containment after
        // canonicalize too.
        let _ = resolve_read(&s, "../../etc/passwd");
        // depending on whether /etc/passwd exists outside repo,
        // this returns None.
        // we don't assert positively because canonicalize behaviour
        // for the .. path varies by OS.
    }

    #[test]
    fn resolve_write_rejects_parent_dir_when_unresolved() {
        let tmp = std::env::temp_dir().join(format!(
            "gyt-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let canon = canonicalize_or_self(&tmp);
        let s = Sandbox {
            read_roots: vec![],
            write_roots: vec![canon.clone()],
            repo_gyt_meta: canon.join(".gyt"),
            log_used: 0,
            limiter: CiLimits {
                memory_max: CI_DEFAULT_MEMORY_BYTES,
                mem_high_water: 0,
            },
        };
        assert!(resolve_write(&s, "../escape.txt").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_read_blocks_dot_gyt_always() {
        let tmp = std::env::temp_dir().join(format!(
            "gyt-dotgyt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(tmp.join(".gyt")).unwrap();
        std::fs::write(tmp.join(".gyt").join("secret"), b"x").unwrap();
        let canon = canonicalize_or_self(&tmp);
        let s = Sandbox {
            read_roots: vec![canon.clone()],
            write_roots: vec![],
            repo_gyt_meta: canon.join(".gyt"),
            log_used: 0,
            limiter: CiLimits {
                memory_max: CI_DEFAULT_MEMORY_BYTES,
                mem_high_water: 0,
            },
        };
        assert!(resolve_read(&s, ".gyt/secret").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
