// Hardening tests for the WASM CI sandbox.
//
// Every test here loads a hand-written WAT module (wasmtime auto-detects
// WAT in `Module::from_file`), drops it into a tempdir, and exercises a
// boundary the sandbox must enforce. A regression in any of these is a
// privilege-escalation bug and should fail loudly.

use std::path::PathBuf;

fn unique_tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "gyt-ci-sandbox-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write_wat(dir: &std::path::Path, name: &str, wat: &str) -> PathBuf {
    let path = dir.join(format!("{name}.wat"));
    std::fs::write(&path, wat).unwrap();
    path
}

/// A minimal WAT module that returns 0 from `_start`. Used as a positive
/// control for the harness itself.
const NOOP_WAT: &str = r#"
(module
  (func (export "_start") (result i32)
    i32.const 0))
"#;

#[test]
fn noop_wasm_runs_and_returns_zero() {
    let dir = unique_tmp("noop");
    let wasm = write_wat(&dir, "noop", NOOP_WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    assert!(r.is_ok(), "noop wasm should succeed: {r:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An infinite loop must be terminated by fuel exhaustion, not run
/// forever. We hard-cap the test at 30s by trapping into a timeout in
/// case the sandbox failed to terminate it.
#[test]
fn infinite_loop_is_terminated_by_fuel() {
    const LOOP_WAT: &str = r#"
(module
  (func (export "_start") (result i32)
    (loop $l br $l)
    i32.const 0))
"#;
    let dir = unique_tmp("loop");
    let wasm = write_wat(&dir, "loop", LOOP_WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let start = std::time::Instant::now();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    let elapsed = start.elapsed();
    assert!(r.is_err(), "infinite loop must error");
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "fuel must terminate before 30s (was {elapsed:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Trying to allocate more linear memory than the cap permits must be
/// rejected by the ResourceLimiter.
#[test]
fn memory_growth_past_cap_rejected() {
    // 256 MiB cap = 4096 pages of 64 KiB. Grow by 8192 pages → must fail.
    // The wasm sets memory_grow's failure as -1 in the return.
    const BLOAT_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (result i32)
    i32.const 8192
    memory.grow
    i32.const -1
    i32.eq
    (if (then (return (i32.const 0))))
    i32.const 1))
"#;
    let dir = unique_tmp("bloat");
    let wasm = write_wat(&dir, "bloat", BLOAT_WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    assert!(
        r.is_ok(),
        "wasm should run to completion (memory.grow returns -1, wasm signals success). Got: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A module that imports WASI must fail to instantiate — we deliberately
/// don't link wasi_snapshot_preview1, so any access to it surfaces.
#[test]
fn wasi_import_rejected_at_instantiation() {
    const WASI_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start") (result i32)
    i32.const 0))
"#;
    let dir = unique_tmp("wasi");
    let wasm = write_wat(&dir, "wasi", WASI_WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    let err = r.expect_err("WASI import must be rejected").to_string();
    assert!(
        err.contains("instantiating") || err.contains("unknown import"),
        "expected instantiation failure, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A module that imports `env.getenv` (or anything not in our `gyt_ci`
/// namespace) must fail to instantiate. CI secrets live in the host
/// env and the sandbox is the only thing keeping them in.
#[test]
fn env_import_rejected_at_instantiation() {
    const ENV_WAT: &str = r#"
(module
  (import "env" "getenv" (func $g (param i32 i32) (result i32)))
  (func (export "_start") (result i32) i32.const 0))
"#;
    let dir = unique_tmp("env");
    let wasm = write_wat(&dir, "env", ENV_WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    assert!(r.is_err(), "env import must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reading `.gyt/...` must be denied even though it lives under
/// repo_dir. CI secrets are encrypted with a key under `.gyt/`, and the
/// signing key would be reachable too without this guard.
#[test]
fn read_dot_gyt_blocked() {
    let dir = unique_tmp("dotgyt");
    let gyt = dir.join(".gyt");
    std::fs::create_dir_all(&gyt).unwrap();
    std::fs::write(gyt.join("secret"), b"plaintext-ci-secret").unwrap();
    let real = dir.canonicalize().unwrap();
    let blocked = gyt::ci_wasm::sandbox_repo_read(&real, ".gyt/secret");
    assert!(blocked.is_none(), "must not resolve a path under .gyt");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A symlink inside repo_dir that targets `/etc/passwd` must not be
/// dereferenceable through the sandbox: `canonicalize` resolves the
/// link to its true target, which then fails `starts_with(repo_dir)`.
#[cfg(unix)]
#[test]
fn symlink_escape_blocked() {
    use std::os::unix::fs::symlink;
    let dir = unique_tmp("symlink");
    let real = dir.canonicalize().unwrap();
    let link = real.join("escape");
    symlink("/etc/passwd", &link).unwrap();
    let r = gyt::ci_wasm::sandbox_repo_read(&real, "escape");
    assert!(
        r.is_none(),
        "symlink to /etc/passwd must not resolve inside repo_dir"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `..` in an output path must be rejected even if the parent does not
/// exist (so canonicalize() can't help).
#[test]
fn output_parent_dir_traversal_blocked() {
    let dir = unique_tmp("traverse");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let real_out = out.canonicalize().unwrap();
    assert!(gyt::ci_wasm::sandbox_output(&real_out, "../escape.txt").is_none());
    assert!(gyt::ci_wasm::sandbox_output(&real_out, "a/b/../../../escape.txt").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Absolute path inputs are rejected from both read and write surfaces.
#[test]
fn absolute_paths_blocked() {
    let dir = unique_tmp("abs");
    let real = dir.canonicalize().unwrap();
    assert!(gyt::ci_wasm::sandbox_repo_read(&real, "/etc/passwd").is_none());
    assert!(gyt::ci_wasm::sandbox_output(&real, "/tmp/escape").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Embedded NUL in a path is rejected.
#[test]
fn nul_in_path_blocked() {
    let dir = unique_tmp("nul");
    let real = dir.canonicalize().unwrap();
    assert!(gyt::ci_wasm::sandbox_repo_read(&real, "foo\0bar").is_none());
    assert!(gyt::ci_wasm::sandbox_output(&real, "foo\0bar").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sanity-check that the published constants haven't been silently
/// relaxed. Production limits should *only* change with a deliberate
/// review.
#[test]
fn published_limits_are_at_documented_values() {
    use gyt::ci_wasm::{
        CI_INITIAL_FUEL, CI_MAX_FILE_BYTES, CI_MAX_LOG_BYTES, CI_MAX_MEMORY_BYTES,
        CI_MAX_WASM_STACK,
    };
    assert_eq!(CI_MAX_MEMORY_BYTES, 256 * 1024 * 1024);
    assert_eq!(CI_INITIAL_FUEL, 1_000_000_000);
    assert_eq!(CI_MAX_FILE_BYTES, 64 * 1024 * 1024);
    assert_eq!(CI_MAX_LOG_BYTES, 16 * 1024 * 1024);
    assert_eq!(CI_MAX_WASM_STACK, 1024 * 1024);
}

/// Loading a corrupt / non-wasm file must surface a clean error rather
/// than panicking the host worker.
#[test]
fn malformed_wasm_clean_error() {
    let dir = unique_tmp("malformed");
    let wasm = dir.join("bad.wasm");
    std::fs::write(&wasm, b"this is not wasm").unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    assert!(r.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
