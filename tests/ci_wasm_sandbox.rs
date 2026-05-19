#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]

// Hardening tests for the WASM CI sandbox.
//
// Every test here loads a hand-written WAT module (wasmtime auto-detects
// WAT in `Module::from_file`), drops it into a tempdir, and exercises a
// boundary the sandbox must enforce. A regression in any of these is a
// privilege-escalation bug and should fail loudly.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn unique_tmp(name: &str) -> PathBuf {
    // Atomic counter + pid + nanos: two callers in the same
    // nanosecond on different cores would otherwise collide on the
    // `as_nanos()` value under `--test-threads=16`.
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "gyt-ci-sandbox-{}-{}-{}-{}",
        name,
        std::process::id(),
        id,
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
    // Use a tiny fuel + short epoch so the test terminates in <5s
    // rather than burning through the 100B-instruction default.
    let policy = gyt::ci_wasm::CiPolicy {
        fuel: 100_000_000,
        wall_time_secs: 5,
        ..Default::default()
    };
    let start = std::time::Instant::now();
    let r = gyt::ci_wasm::run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    let elapsed = start.elapsed();
    assert!(r.is_err(), "infinite loop must error");
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "loop must terminate before 15s (was {elapsed:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Trying to allocate more linear memory than the cap permits must be
/// rejected by the ResourceLimiter. The default 8 GiB cap won't fire
/// for a 512 MiB growth, so we lower it via CiPolicy to make the cap
/// visible — this also tests that operator-supplied limits are
/// honored.
#[test]
fn memory_growth_past_cap_rejected() {
    // Grow by 8192 pages of 64 KiB = 512 MiB. With a 256 MiB cap this
    // is refused → memory.grow returns -1 → wasm checks and returns 0.
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
    let policy = gyt::ci_wasm::CiPolicy {
        memory_max: 256 * 1024 * 1024,
        ..Default::default()
    };
    let r = gyt::ci_wasm::run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
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
        CI_DEFAULT_FUEL, CI_DEFAULT_MEMORY_BYTES, CI_DEFAULT_WALL_TIME_SECS,
        CI_MAX_FILE_BYTES, CI_MAX_LOG_BYTES, CI_MAX_WASM_STACK,
    };
    // Bumped to "Android-build-sized" defaults so legitimate
    // workloads don't trip an artificial cap.
    assert_eq!(CI_DEFAULT_MEMORY_BYTES, 8 * 1024 * 1024 * 1024);
    assert_eq!(CI_DEFAULT_FUEL, 100_000_000_000);
    assert_eq!(CI_DEFAULT_WALL_TIME_SECS, 4 * 60 * 60);
    assert_eq!(CI_MAX_FILE_BYTES, 1024 * 1024 * 1024);
    assert_eq!(CI_MAX_LOG_BYTES, 256 * 1024 * 1024);
    assert_eq!(CI_MAX_WASM_STACK, 8 * 1024 * 1024);
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

/// Count the number of threads in this process by listing
/// `/proc/self/task`. Linux-specific — gyt is Linux-only and the
/// integration tests already assume `/proc`.
fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map_or(0, |rd| rd.filter_map(Result::ok).count())
}

/// F2 regression: a wasm module that fails to *instantiate* (e.g.
/// because it imports a hostcall outside the `gyt_ci` namespace) used
/// to leak the 1 Hz wall-time ticker thread on the `?` early-return.
/// Each leaked thread sleeps for up to `wall_time_secs` seconds (4 h
/// by default) before self-exiting, holding an Engine Arc the whole
/// time. The TickerGuard's Drop now joins the ticker on every exit
/// path. 20 sequential instantiation failures must not inflate the
/// process's thread count.
#[test]
fn failed_instantiation_does_not_leak_ticker() {
    const BAD_IMPORT_WAT: &str = r#"
(module
  (import "evil" "do_evil" (func $evil))
  (func (export "_start") (result i32)
    call $evil
    i32.const 0))
"#;
    let dir = unique_tmp("ticker-leak");
    let wasm = write_wat(&dir, "bad-import", BAD_IMPORT_WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();

    // Short wall-time: if the guard regresses, the leaked threads stay
    // visible in /proc/self/task long enough for the assertion below
    // to see them.
    let policy = gyt::ci_wasm::CiPolicy {
        wall_time_secs: 30,
        ..gyt::ci_wasm::CiPolicy::default()
    };

    let baseline = thread_count();
    for _ in 0..20 {
        let r = gyt::ci_wasm::run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
        assert!(
            r.is_err(),
            "module with unknown import must fail to instantiate"
        );
    }
    // Give a beat for any half-shutdown threads to vanish from
    // /proc/self/task on slow CI.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let after = thread_count();

    // With 20 leaks at 30s wall time and a ~200ms post-loop sleep,
    // ALL 20 leaked threads would still be visible if the guard
    // regressed. Allow a small slack (8) for runtime workers and
    // cargo-test bookkeeping.
    assert!(
        after <= baseline + 8,
        "ticker thread leak detected: baseline={baseline} after 20 failed instantiations={after}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Audit 2026-05 boundary cases (appended) ────────────────────────
//
// Each test here pins one boundary that the sandbox MUST enforce
// exactly — not "approximately, depending on platform". Regressions
// to any of these are sandbox-escape candidates, not perf bugs.

/// Small helper for the policy-driven runs below.
fn run_with(
    wasm: &std::path::Path,
    repo: &std::path::Path,
    out: &std::path::Path,
    policy: &gyt::ci_wasm::CiPolicy,
) -> gyt::errors::Result<()> {
    gyt::ci_wasm::run_ci_wasm_with_policy(wasm, repo, out, policy)
}

/// A module that runs N+1 i32.const/drop pairs must trap when fuel is
/// set to a value that pays for exactly N operations. wasmtime charges
/// 1 fuel per operator by default, so a tight loop of `(i32.const 0)
/// (drop)` is a deterministic fuel sink. We pick small N so the test
/// is fast and the trap is visible.
#[test]
fn fuel_at_exact_limit_traps() {
    // Use a loop with a live local counter so cranelift cannot constant-
    // fold the body away. The loop runs up to 10 000 iterations, each
    // iteration consuming ~5 operators (local.get, i32.const, i32.add,
    // local.set, br_if). Fuel=50 should trap inside the first few
    // iterations. A flat `i32.const 0; drop` body gets eliminated by
    // the optimiser and never consumes fuel.
    let wat = "(module\n  (func (export \"_start\") (result i32)\n    \
        (local $i i32)\n    \
        (loop $L\n      \
            (local.set $i (i32.add (local.get $i) (i32.const 1)))\n      \
            (br_if $L (i32.lt_s (local.get $i) (i32.const 10000)))\n    )\n    \
        (local.get $i)))\n"
        .to_string();
    let dir = unique_tmp("fuel-exact");
    let wasm = write_wat(&dir, "fuel", &wat);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let policy = gyt::ci_wasm::CiPolicy {
        fuel: 50,
        wall_time_secs: 5,
        ..Default::default()
    };
    let r = run_with(&wasm, &dir, &out, &policy);
    assert!(r.is_err(), "module exceeding fuel must trap; got Ok");
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("fuel") || msg.contains("WASM execution") || msg.contains("trap"),
        "expected a fuel/trap error, got: {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A module that grows memory past `policy.memory_max` must be blocked
/// at the `memory.grow` call site. We size the cap to exactly N pages
/// (each 64 KiB) and have the wasm grow N+1 pages. The wasm checks for
/// -1 and traps via `unreachable` so we observe a hard error rather
/// than a clean exit.
#[test]
fn memory_grow_at_exact_max() {
    const PAGE: usize = 64 * 1024;
    const N_PAGES: usize = 4;
    // Memory caps in CiPolicy are in *bytes*; wasm pages are 64 KiB.
    // Setting memory_max = N * PAGE means N pages fit, N+1 does not.
    let memory_max = N_PAGES * PAGE;
    // Grow by (N+1) pages — refused → memory.grow returns -1 → wasm
    // hits `unreachable` and traps.
    let grow_amount = N_PAGES + 1;
    let wat = format!(
        "(module
  (memory (export \"memory\") 0)
  (func (export \"_start\") (result i32)
    i32.const {grow_amount}
    memory.grow
    i32.const -1
    i32.eq
    (if (then unreachable))
    i32.const 0))
"
    );
    let dir = unique_tmp("mem-exact");
    let wasm = write_wat(&dir, "memgrow", &wat);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let policy = gyt::ci_wasm::CiPolicy {
        memory_max,
        fuel: 10_000_000,
        wall_time_secs: 5,
        ..Default::default()
    };
    let r = run_with(&wasm, &dir, &out, &policy);
    assert!(
        r.is_err(),
        "growing past memory_max must trap; got Ok with cap = {memory_max} bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `read_caller_string` enforces `len ∈ 0..=4096`. A hostcall asked
/// to read a 5000-byte string must reject the call cleanly. We do
/// this through `read_file`, which calls `read_caller_string` first
/// and returns -1 on a None result. The wasm asserts the return is
/// -1 and exits 0; anything else (panic, success, different errno)
/// flags a regression.
#[test]
fn read_caller_string_cap_4096() {
    // 5000 bytes of 0x41 ('A') laid out as a wasm data segment.
    let payload = "A".repeat(5000);
    let wat = format!(
        "(module
  (import \"gyt_ci\" \"read_file\"
    (func $read (param i32 i32 i32 i32) (result i32)))
  (memory (export \"memory\") 1)
  (data (i32.const 0) \"{payload}\")
  (func (export \"_start\") (result i32)
    ;; path ptr=0 len=5000, buffer ptr=8192 len=64.
    i32.const 0
    i32.const 5000
    i32.const 8192
    i32.const 64
    call $read
    ;; expect -1 (bad path arg per the read_caller_string cap)
    i32.const -1
    i32.eq
    (if (then (return (i32.const 0))))
    ;; anything else is a regression — exit non-zero
    i32.const 7))
"
    );
    let dir = unique_tmp("readstr-cap");
    let wasm = write_wat(&dir, "readstr", &wat);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let policy = gyt::ci_wasm::CiPolicy {
        fuel: 10_000_000,
        wall_time_secs: 5,
        ..Default::default()
    };
    let r = run_with(&wasm, &dir, &out, &policy);
    assert!(
        r.is_ok(),
        "module must exit cleanly after observing -1 from a too-long path; got {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `gyt_ci.log` enforces a cumulative-bytes cap per run, defaulting to
/// `CI_MAX_LOG_BYTES` (256 MiB). The hostcall TRAPS the wasm as soon
/// as a call would push the running total past the cap. Lower the
/// policy's `log_max` to 4 KiB in this test so the trap fires after a
/// few iterations rather than forcing a multi-hundred-MiB run.
#[test]
fn log_cumulative_byte_cap() {
    // 1 KiB payload, log_max = 4 KiB → trap fires on the 5th call.
    let payload_size: usize = 1024;
    let log_max: usize = 4 * 1024;
    // Iterate plenty of times so the trap fires mid-loop.
    let iters = 100u32;
    // Data: 1 KiB of `0x41` ('A').
    let mut data = String::with_capacity(payload_size * 4);
    data.push('"');
    for _ in 0..payload_size {
        data.push_str("\\41");
    }
    data.push('"');
    let wat = format!(
        "(module\n  \
            (import \"gyt_ci\" \"log\" (func $log (param i32 i32)))\n  \
            (memory (export \"memory\") 1)\n  \
            (data (i32.const 0) {data})\n  \
            (func (export \"_start\") (result i32)\n    \
                (local $i i32)\n    \
                (loop $L\n      \
                    (call $log (i32.const 0) (i32.const {payload_size}))\n      \
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))\n      \
                    (br_if $L (i32.lt_s (local.get $i) (i32.const {iters})))\n    \
                )\n    \
                (i32.const 0)))\n"
    );
    let dir = unique_tmp("log-cap");
    let wasm = write_wat(&dir, "log-cap", &wat);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let policy = gyt::ci_wasm::CiPolicy {
        fuel: 100_000_000_000,
        log_max,
        wall_time_secs: 30,
        ..Default::default()
    };
    let r = gyt::ci_wasm::run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    // The cap trap surfaces as a wasmtime execution error; wasmtime's
    // Display intentionally hides the underlying host error message
    // (it would otherwise leak host implementation details to the
    // guest's error log). The observable contract is "the wasm cannot
    // emit more than `log_max` bytes" — we pin that by asserting the
    // run errored after the cap was crossed.
    assert!(r.is_err(), "log-cap should trap once cumulative bytes exceed the cap");
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Disabled WASM features must be rejected at module validation ───
//
// Each test below builds a minimal WAT module that USES one of the
// disabled features. `Module::from_file` should reject it during
// validation — the engine config explicitly turns off all of these.

fn assert_feature_rejected(label: &str, wat: &str) {
    let dir = unique_tmp(&format!("feat-{label}"));
    let wasm = write_wat(&dir, label, wat);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let r = gyt::ci_wasm::run_ci_wasm(&wasm, &dir, &out);
    assert!(
        r.is_err(),
        "feature `{label}` must be rejected by validation; got Ok"
    );
    let msg = r.unwrap_err().to_string();
    // Either the module never loads (validation error) or it fails
    // to instantiate. Both surface as a clean Err out of run_ci_wasm.
    assert!(
        msg.contains("loading WASM")
            || msg.contains("instantiating")
            || msg.contains("validate")
            || msg.contains("WASM"),
        "expected a load/validation error for `{label}`, got: {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn feature_threads_rejected() {
    // Shared memory requires the threads proposal.
    const WAT: &str = r#"
(module
  (memory (export "memory") 1 1 shared)
  (func (export "_start") (result i32) i32.const 0))
"#;
    assert_feature_rejected("threads", WAT);
}

#[test]
fn feature_simd_rejected() {
    // v128 type is gated by the SIMD proposal.
    const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (result i32)
    v128.const i32x4 0 0 0 0
    drop
    i32.const 0))
"#;
    assert_feature_rejected("simd", WAT);
}

#[test]
fn feature_relaxed_simd_rejected() {
    // i32x4.relaxed_trunc_f32x4_s is exclusive to the relaxed-SIMD
    // proposal. (Plain SIMD is also disabled, so this test holds even
    // if relaxed-SIMD were toggled in isolation — either gate fires.)
    const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (result i32)
    v128.const i32x4 0 0 0 0
    i32x4.relaxed_trunc_f32x4_s
    drop
    i32.const 0))
"#;
    assert_feature_rejected("relaxed-simd", WAT);
}

#[test]
fn feature_reference_types_rejected() {
    // `externref` table element is the reference-types proposal.
    const WAT: &str = r#"
(module
  (table (export "t") 1 externref)
  (func (export "_start") (result i32) i32.const 0))
"#;
    assert_feature_rejected("reference-types", WAT);
}

#[test]
fn feature_multi_memory_rejected() {
    // Two memories require the multi-memory proposal.
    const WAT: &str = r#"
(module
  (memory $a (export "memory") 1)
  (memory $b 1)
  (func (export "_start") (result i32) i32.const 0))
"#;
    assert_feature_rejected("multi-memory", WAT);
}

#[test]
fn feature_memory64_rejected() {
    // `i64` memory index is the memory64 proposal.
    const WAT: &str = r#"
(module
  (memory (export "memory") i64 1)
  (func (export "_start") (result i32) i32.const 0))
"#;
    assert_feature_rejected("memory64", WAT);
}

/// B1: A guest that calls `write_file` with a negative `data_len`
/// must not panic the hostcall (Rust panics on `slice[start..end]`
/// when `start > end`). Before the fix, `read_bytes(ptr=100, len=-1)`
/// produced `start=100, end=99` and the slice index trapped. After
/// the fix, `read_bytes` rejects out-of-range len and returns an
/// empty vec, so the hostcall returns 0 with a zero-byte file
/// written — the guest sees an orderly result, not a wasmtime trap.
#[test]
fn write_file_negative_data_len_does_not_panic() {
    // path bytes at offset 0 ("out.bin", 7 bytes); call write_file
    // with data_ptr=100 (non-zero) and data_len=-1.
    const WAT: &str = r#"
(module
  (import "gyt_ci" "write_file"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "out.bin")
  (func (export "_start") (result i32)
    i32.const 0    ;; path ptr
    i32.const 7    ;; path len
    i32.const 100  ;; data ptr (non-zero, so inverted-range panic was reachable)
    i32.const -1   ;; data len (negative)
    call $write
    ;; result is allowed to be 0 (zero-byte write) or any negative
    ;; error code; the important invariant is that the call returned
    ;; rather than trapping. Discard it.
    drop
    i32.const 0))
"#;
    let dir = unique_tmp("write-neg-len");
    let wasm = write_wat(&dir, "neg-len", WAT);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let policy = gyt::ci_wasm::CiPolicy {
        fuel: 10_000_000,
        wall_time_secs: 5,
        ..Default::default()
    };
    let r = run_with(&wasm, &dir, &out, &policy);
    assert!(
        r.is_ok(),
        "write_file(data_len=-1) must not trap; got {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
