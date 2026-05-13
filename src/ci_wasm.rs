// WASM CI runner — sandboxed execution of .wasm CI scripts.
//
// Default CI format: .wasm files in .gyt-ci/ are run via wasmtime.
// Shell scripts (.sh) are the fallback.
//
// Sandbox guarantees:
// - Read access only to repo_dir
// - Read+write access only to output_dir
// - No network, no process spawning, no other filesystem access
// - stdout/stderr for logging

#![allow(clippy::manual_let_else, clippy::redundant_closure_for_method_calls)]

use crate::errors::{GytError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use wasmtime::{Caller, Engine, Linker, Memory, Module, Store};

pub fn run_ci_wasm(wasm_path: &Path, repo_dir: &Path, output_dir: &Path) -> Result<()> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, wasm_path)
        .map_err(|e| GytError::Ci(format!("loading WASM {}: {e}", wasm_path.display())))?;

    let state = Sandbox {
        repo_dir: repo_dir.to_path_buf(),
        output_dir: output_dir.to_path_buf(),
    };

    let mut linker: Linker<Sandbox> = Linker::new(&engine);

    linker
        .func_wrap(
            "gyt_ci",
            "log",
            |mut caller: Caller<'_, Sandbox>, ptr: i32, len: i32| {
                let data = read_caller_string(&mut caller, ptr, len);
                if let Some(msg) = data {
                    print!("[wasm-ci] {msg}");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
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
                let Some(safe) = sandbox_repo(caller.data().repo_dir.as_ref(), &path_str) else {
                    return -2;
                };
                match fs::read(&safe) {
                    Ok(data) => {
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
                    }
                    Err(_) => -5,
                }
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
                let Some(path_str) = read_caller_string(&mut caller, path_ptr, path_len) else {
                    return -1;
                };
                let Some((safe_path, relative)) =
                    sandbox_output(caller.data().output_dir.as_ref(), &path_str)
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

    linker
        .func_wrap(
            "gyt_ci",
            "getenv",
            |mut caller: Caller<'_, Sandbox>,
             name_ptr: i32,
             name_len: i32,
             out_ptr: i32,
             out_len: i32|
             -> i32 {
                // Read the env var name from WASM memory
                let Some(name) = read_caller_string(&mut caller, name_ptr, name_len) else {
                    return -2;
                };
                // Look up via std::env::var()
                let value = match std::env::var(&name) {
                    Ok(v) => v,
                    Err(_) => return -1,
                };
                // Write value into WASM memory (truncated to out_len)
                let Some(mem) = get_caller_memory(&mut caller) else {
                    return -3;
                };
                let start = out_ptr.max(0) as usize;
                let n = value.len().min(out_len.max(0) as usize);
                if mem.write(&mut caller, start, &value.as_bytes()[..n]).is_err() {
                    return -3;
                }
                0
            },
        )
        .map_err(|e| GytError::Ci(format!("linker getenv: {e}")))?;

    let mut store = Store::new(&engine, state);
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

struct Sandbox {
    repo_dir: PathBuf,
    output_dir: PathBuf,
}

fn get_caller_memory(caller: &mut Caller<'_, Sandbox>) -> Option<Memory> {
    caller.get_export("memory")?.into_memory()
}

fn read_caller_string(caller: &mut Caller<'_, Sandbox>, ptr: i32, len: i32) -> Option<String> {
    let mem = get_caller_memory(caller)?;
    let start = ptr.max(0) as usize;
    let end = (start as i32 + len).max(0) as usize;
    let data = mem.data(caller);
    if end > data.len() {
        return None;
    }
    String::from_utf8(data[start..end].to_vec()).ok()
}

fn read_bytes(slice: &[u8], ptr: i32, len: i32) -> Vec<u8> {
    let start = ptr.max(0) as usize;
    let end = (start as i32 + len).max(0) as usize;
    if end > slice.len() {
        return vec![];
    }
    slice[start..end].to_vec()
}

fn sandbox_repo(repo_dir: &Path, rel: &str) -> Option<PathBuf> {
    let candidate = repo_dir.join(rel);
    let canonical = candidate.canonicalize().ok()?;
    if canonical.starts_with(repo_dir) {
        Some(canonical)
    } else {
        None
    }
}

fn sandbox_output(output_dir: &Path, rel: &str) -> Option<(PathBuf, String)> {
    let candidate = output_dir.join(rel);
    let resolved = if candidate.exists() {
        candidate.canonicalize().ok()?
    } else {
        let _parent = candidate.parent()?;
        let out_str = output_dir.to_string_lossy();
        let cand_str = candidate.to_string_lossy();
        if !cand_str.starts_with(out_str.as_ref()) {
            return None;
        }
        candidate
    };
    if resolved.starts_with(output_dir) {
        Some((resolved, rel.to_string()))
    } else {
        None
    }
}

pub fn collect_wasm_scripts(ci_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(ci_dir) else {
        return vec![];
    };
    let mut wasms: Vec<_> = entries
        .filter_map(|r| r.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "wasm")
        })
        .map(|e| e.path())
        .collect();
    wasms.sort();
    wasms
}
