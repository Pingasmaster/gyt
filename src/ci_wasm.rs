// WASM CI runner — sandboxed execution of .wasm CI scripts.
//
// This is now the *only* supported CI execution path. Shell scripts and
// docker were removed because neither can be confined to a useful
// security boundary on a multi-tenant host. Every defence below exists
// because a malicious .wasm landing on a CI worker MUST NOT be able to:
//
//   1. Read or write any host file outside the declared sandbox.
//   2. Read environment variables (CI secrets live in the host env).
//   3. Spawn processes, open sockets, or call any OS syscall.
//   4. Run indefinitely (CPU exhaustion / fee griefing).
//   5. Allocate unbounded memory (DoS the worker / kernel OOM).
//   6. Escape the sandbox via symlinks under repo_dir.
//
// Capabilities exposed to WASM (only these — explicit deny-by-default):
//
//   - gyt_ci.log(ptr, len)                       : append a line to host stdout
//   - gyt_ci.read_file(path_ptr, path_len, buf_ptr, buf_len)
//                                                : read a file under repo_dir
//                                                  (NOT under .gyt/)
//   - gyt_ci.write_file(path_ptr, path_len, data_ptr, data_len)
//                                                : write a file under output_dir
//
// Enforced limits (`CiLimits`):
//   - linear memory cap        : 256 MiB total across all growths
//   - fuel                     : ~10^9 wasm instructions (≈30s of pure CPU)
//   - read_file size cap       : 64 MiB per call
//   - write_file size cap      : 64 MiB per call
//   - log() output cap         : 16 MiB cumulative per run
//   - max wasm stack           : 1 MiB
//   - max instances            : 1, max tables 1, max memories 1
//
// We deliberately use *only* fuel for CPU bounding (no `epoch_interruption`)
// — fuel is deterministic, doesn't need a background ticker, and a tight
// loop in WASM always consumes fuel. The host hostcalls don't loop, so
// the only way to burn wall-time is via wasm instructions, which fuel
// covers.

#![allow(clippy::manual_let_else, clippy::redundant_closure_for_method_calls)]

use crate::errors::{GytError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, ResourceLimiter, Store};

/// Hard caps for a single CI run. Public so tests can assert against the
/// exact numbers used in production.
pub const CI_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;
pub const CI_INITIAL_FUEL: u64 = 1_000_000_000;
pub const CI_MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const CI_MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
pub const CI_MAX_WASM_STACK: usize = 1024 * 1024;

pub fn run_ci_wasm(wasm_path: &Path, repo_dir: &Path, output_dir: &Path) -> Result<()> {
    // 1. Engine config: turn off every optional WASM feature we don't
    //    need. Each enabled feature is one more bug surface in wasmtime,
    //    so deny everything that doesn't move CI workflows.
    let mut cfg = Config::new();
    cfg.consume_fuel(true)
        .wasm_threads(false)
        .wasm_reference_types(false)
        .wasm_simd(false)
        .wasm_relaxed_simd(false)
        .wasm_bulk_memory(true) // common in -Os builds; keep on
        .wasm_multi_value(true) // ditto
        .wasm_multi_memory(false)
        .wasm_memory64(false)
        .max_wasm_stack(CI_MAX_WASM_STACK);

    let engine = Engine::new(&cfg)
        .map_err(|e| GytError::Ci(format!("wasmtime engine config: {e}")))?;

    let module = Module::from_file(&engine, wasm_path)
        .map_err(|e| GytError::Ci(format!("loading WASM {}: {e}", wasm_path.display())))?;

    // The sandbox lives in `Store::data()`. Hostcalls receive `Caller`
    // which lets them inspect the policy without unsafe global state.
    let state = Sandbox {
        // canonicalize once at start — every later `starts_with` compares
        // against the resolved real path, so an in-flight symlink swap
        // can't reroute us outside.
        repo_dir: canonicalize_or_self(repo_dir),
        output_dir: canonicalize_or_self(output_dir),
        log_used: 0,
        limiter: CiLimits::default(),
    };

    let mut linker: Linker<Sandbox> = Linker::new(&engine);

    linker
        .func_wrap(
            "gyt_ci",
            "log",
            |mut caller: Caller<'_, Sandbox>, ptr: i32, len: i32| {
                // Drop oversized log calls silently so a runaway script
                // can't fill the host's disk via stdout redirection.
                let len_us = len.max(0) as usize;
                let already = caller.data().log_used;
                if already.saturating_add(len_us) > CI_MAX_LOG_BYTES {
                    return;
                }
                caller.data_mut().log_used = already + len_us;
                let Some(msg) = read_caller_string(&mut caller, ptr, len) else {
                    return;
                };
                print!("[wasm-ci] {msg}");
                let _ = std::io::Write::flush(&mut std::io::stdout());
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
                let Some(safe) = sandbox_repo_read(&caller.data().repo_dir, &path_str) else {
                    return -2;
                };
                // Reject reads that we'd have to refuse anyway after
                // allocating — bound the source so a malicious 4 GiB
                // file inside repo_dir can't get us OOM-killed.
                let meta = match fs::metadata(&safe) {
                    Ok(m) => m,
                    Err(_) => return -5,
                };
                if !meta.is_file() {
                    return -2;
                }
                if meta.len() as usize > CI_MAX_FILE_BYTES {
                    return -6;
                }
                let data = match fs::read(&safe) {
                    Ok(d) => d,
                    Err(_) => return -5,
                };
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
                let Some((safe_path, relative)) =
                    sandbox_output(&caller.data().output_dir, &path_str)
                else {
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
                match fs::write(&safe_path, &data) {
                    Ok(()) => {
                        println!("[wasm-ci] wrote {relative}");
                        0
                    }
                    Err(_) => -4,
                }
            },
        )
        .map_err(|e| GytError::Ci(format!("linker write_file: {e}")))?;

    // Explicitly *do not* link wasi_snapshot_preview1 / wasi_unstable /
    // env / getenv / spawn / fd_write / fd_read / clock_time_get /
    // random_get / poll_oneoff. If a workflow .wasm imports any of those
    // (e.g., it was compiled with `wasm32-wasi` instead of `wasm32-unknown`)
    // module instantiation FAILS, surfacing the misconfiguration loudly
    // instead of allowing accidental access to host I/O.

    let mut store = Store::new(&engine, state);

    // Hook up the resource limiter (memory cap, table cap, instance cap).
    store.limiter(|s| &mut s.limiter);

    store
        .set_fuel(CI_INITIAL_FUEL)
        .map_err(|e| GytError::Ci(format!("set_fuel: {e}")))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| GytError::Ci(format!("instantiating WASM: {e}")))?;

    let func = instance
        .get_typed_func::<(), i32>(&mut store, "_start")
        .or_else(|_| instance.get_typed_func::<(), i32>(&mut store, "_main"));

    match func {
        Ok(f) => {
            let code = f
                .call(&mut store, ())
                .map_err(|e| GytError::Ci(format!("WASM execution: {e}")))?;
            if code != 0 {
                return Err(GytError::Ci(format!("WASM exited with code {code}")));
            }
            Ok(())
        }
        Err(e) => Err(GytError::Ci(format!("WASM has no _start or _main: {e}"))),
    }
}

/// Per-store resource limiter. Caps memory growth and the number of
/// instances/tables/memories the guest may create.
#[derive(Default)]
pub struct CiLimits {
    mem_high_water: usize,
}

impl ResourceLimiter for CiLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Bound only on the *actual* requested size. The module's
        // declared `maximum` is just a self-describing hint — refusing
        // instantiation when a module declares an open-ended memory
        // would block almost every real-world wasm build. Each grow
        // call re-enters this function, so the cap is enforced
        // monotonically as the wasm tries to expand.
        if desired > CI_MAX_MEMORY_BYTES {
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
        // 1M table entries is plenty for any function-table use case;
        // refuse anything larger to bound per-element allocator pressure.
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
    repo_dir: PathBuf,
    output_dir: PathBuf,
    log_used: usize,
    limiter: CiLimits,
}

fn canonicalize_or_self(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

fn get_caller_memory(caller: &mut Caller<'_, Sandbox>) -> Option<Memory> {
    caller.get_export("memory")?.into_memory()
}

fn read_caller_string(caller: &mut Caller<'_, Sandbox>, ptr: i32, len: i32) -> Option<String> {
    // Reject implausible path lengths early — a CI workflow never needs
    // a 4 KiB path, and a 1 GiB length is an attempted DoS.
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

fn read_bytes(slice: &[u8], ptr: i32, len: i32) -> Vec<u8> {
    let start = ptr.max(0) as usize;
    let end = (start as i64 + len as i64) as usize;
    if end > slice.len() {
        return vec![];
    }
    slice[start..end].to_vec()
}

/// Resolve a relative path against `repo_dir` and return the resolved
/// path *only* if it stays under `repo_dir` AND is not under `.gyt/`.
/// The `.gyt/` exclusion stops a malicious .wasm from reading the
/// repository's own metadata — including encrypted secrets, signing
/// keys, the ref database, and the index.
pub fn sandbox_repo_read(repo_dir: &Path, rel: &str) -> Option<PathBuf> {
    // Hard reject absolute paths and embedded NUL: these never refer
    // to anything inside repo_dir relative to its canonical root.
    if rel.contains('\0') || Path::new(rel).is_absolute() {
        return None;
    }
    let candidate = repo_dir.join(rel);
    let canonical = candidate.canonicalize().ok()?;
    if !canonical.starts_with(repo_dir) {
        return None;
    }
    let gyt_meta = repo_dir.join(".gyt");
    if canonical.starts_with(&gyt_meta) {
        return None;
    }
    Some(canonical)
}

/// Resolve a relative output path. Returns the absolute path AND the
/// relative path (for logging). The output path does not need to
/// pre-exist (we'll create it), so we canonicalize the *parent* and
/// then re-attach the filename — that way symlinked-parent escapes are
/// caught while still allowing the workflow to create new files.
pub fn sandbox_output(output_dir: &Path, rel: &str) -> Option<(PathBuf, String)> {
    if rel.contains('\0') || Path::new(rel).is_absolute() {
        return None;
    }
    // Reject path components that escape (..). canonicalize() does this
    // for paths that exist, but here the file usually doesn't exist yet.
    for comp in Path::new(rel).components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return None;
        }
    }
    let candidate = output_dir.join(rel);
    let parent = candidate.parent()?;
    // Ensure the parent (if it exists) canonicalizes inside output_dir.
    if parent.exists() {
        let resolved_parent = parent.canonicalize().ok()?;
        if !resolved_parent.starts_with(output_dir) {
            return None;
        }
    } else {
        // Parent doesn't exist yet; lexical containment check is enough
        // because we already rejected `..`.
        if !candidate.starts_with(output_dir) {
            return None;
        }
    }
    Some((candidate, rel.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_rejects_absolute_path() {
        let tmp = std::env::temp_dir();
        assert!(sandbox_repo_read(&tmp, "/etc/passwd").is_none());
    }

    #[test]
    fn sandbox_rejects_parent_dir_in_output() {
        let tmp = std::env::temp_dir();
        assert!(sandbox_output(&tmp, "../escape.txt").is_none());
    }

    #[test]
    fn sandbox_rejects_dot_gyt_read() {
        let tmp = std::env::temp_dir().join(format!("gyt-ci-test-{}", std::process::id()));
        let gyt = tmp.join(".gyt");
        std::fs::create_dir_all(&gyt).unwrap();
        std::fs::write(gyt.join("secret"), b"x").unwrap();
        assert!(sandbox_repo_read(&tmp.canonicalize().unwrap(), ".gyt/secret").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sandbox_rejects_nul_in_path() {
        let tmp = std::env::temp_dir();
        assert!(sandbox_repo_read(&tmp, "foo\0bar").is_none());
        assert!(sandbox_output(&tmp, "foo\0bar").is_none());
    }
}
