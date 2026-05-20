// Single-run-per-repo preemption for `gyt ci` / `gyt pr ci-run`.
//
// The contract (user-chosen model): at most one CI run per repo at a
// time. A newly-started run immediately preempts the in-progress one —
// no prompt, no warning. The mechanism is cooperative: each run claims
// `<gyt>/ci/current` with a random nonce via `CiOwner::acquire`; a
// still-running run's 1 Hz wall-time ticker re-reads that marker every
// second and, when it finds a newer nonce, trips the wasm epoch
// deadline so the run aborts at once. The aborted run returns a
// "preempted" error.
//
// This file pins the end-to-end behavior against a real wasm run.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default,
    reason = "integration tests: panicking on unexpected input is how a test signals failure; building a CiPolicy by mutating a few default fields is the clearest form here"
)]

use gyt::ci_wasm::{run_ci_wasm_watched, CiPolicy, CiSlot};
use gyt::config::CiJobMode;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn unique_tmp(name: &str) -> PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "gyt-ci-preempt-{}-{}-{}-{}",
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

// A wasm module that spins a very long countdown loop. With fuel set
// to u64::MAX and a generous wall-time cap it does not finish within
// the test window, so the ONLY thing that stops it is preemption (or
// the wall-time backstop, which we assert against).
const SPIN_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (result i32)
    (local $i i64)
    (local.set $i (i64.const 1000000000000))
    (block $done
      (loop $cont
        (local.set $i (i64.sub (local.get $i) (i64.const 1)))
        (br_if $done (i64.eqz (local.get $i)))
        (br $cont)))
    (i32.const 0)))
"#;

fn write_wat(dir: &Path, name: &str, wat: &str) -> PathBuf {
    let path = dir.join(format!("{name}.wat"));
    std::fs::write(&path, wat).unwrap();
    path
}

// A run that owns the marker and finishes on its own (the wasm is a
// trivial no-op) returns Ok, and the marker is released afterward.
#[test]
fn unpreempted_run_completes_and_releases() {
    let dir = unique_tmp("clean");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    // Trivial wasm: returns 0 immediately.
    let noop = write_wat(
        &dir,
        "noop",
        "(module (func (export \"_start\") (result i32) (i32.const 0)))",
    );
    let slot = CiSlot::enter(&dir, "noop", CiJobMode::Interrupt).unwrap();
    let watch = slot.watch();
    let r = run_ci_wasm_watched(&noop, &dir, &out, &CiPolicy::default(), watch.as_ref());
    assert!(r.is_ok(), "unpreempted run must succeed: {r:?}");
    assert!(slot.still_owner(), "slot should retain its claim");
    drop(slot);
    assert!(
        !dir.join("ci").join("noop.run").exists(),
        "marker must be released after the sole holder drops"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// interrupt mode: a long-running run A holds the domain on a worker
// thread; a second interrupt entry B steals A's nonce. A must abort
// within a few ticks with a preemption error (NOT wall-time, NOT clean
// success) and release the domain lock — which is precisely what lets
// B's blocking `enter` return.
#[test]
fn interrupt_mode_preempts_in_progress_run() {
    let dir = unique_tmp("preempt");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let spin = write_wat(&dir, "spin", SPIN_WAT);

    let spin_c = spin.clone();
    let dir_c = dir.clone();
    let out_c = out.clone();
    // Worker A holds the slot for the whole run, then drops it.
    let worker = std::thread::spawn(move || {
        let slot = CiSlot::enter(&dir_c, "spin", CiJobMode::Interrupt).unwrap();
        let watch = slot.watch();
        // No fuel limit (so fuel never traps first); generous wall-time
        // backstop so a broken preemption surfaces as a clear timeout
        // rather than a hang.
        let mut policy = CiPolicy::default();
        policy.fuel = u64::MAX;
        policy.wall_time_secs = 25;
        let r = run_ci_wasm_watched(&spin_c, &dir_c, &out_c, &policy, watch.as_ref());
        drop(slot);
        r
    });

    // Let A get going and survive at least one ownership tick.
    std::thread::sleep(Duration::from_millis(1500));

    // B preempts: entering Interrupt steals A's nonce (A's ticker trips
    // and the run aborts), then B blocks on the domain lock until A
    // releases it. B's `enter` returning is itself proof that A tore
    // down. Cap the wait well under the 25s wall-time backstop.
    let start = Instant::now();
    let slot_b = CiSlot::enter(&dir, "spin", CiJobMode::Interrupt).unwrap();
    let waited = start.elapsed();
    assert!(
        waited < Duration::from_secs(20),
        "B waited {waited:?} for A to release; preemption likely not firing"
    );

    let res = worker.join().unwrap();
    let err = res.expect_err("preempted run must return an error, not Ok");
    let msg = err.to_string();
    assert!(
        msg.contains("preempted"),
        "expected a preemption error, got: {msg}"
    );

    drop(slot_b);
    let _ = std::fs::remove_dir_all(&dir);
}

// queue mode: a second entry on the same domain blocks until the first
// holder releases, then proceeds. Tested at the slot level (no wasm) so
// it's deterministic: hold A, spawn B which blocks in `enter`, confirm
// B is still blocked, drop A, confirm B then proceeds.
#[test]
fn queue_mode_waits_for_holder_then_proceeds() {
    let dir = unique_tmp("queue");
    let a = CiSlot::enter(&dir, "build", CiJobMode::Queue).unwrap();
    assert!(a.still_owner());

    let dir_c = dir.clone();
    let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let entered_c = entered.clone();
    let waiter = std::thread::spawn(move || {
        // Blocks until A drops its slot (releases the domain lock).
        let b = CiSlot::enter(&dir_c, "build", CiJobMode::Queue).unwrap();
        entered_c.store(true, Ordering::SeqCst);
        assert!(b.still_owner());
        drop(b);
    });

    // While A holds the lock, B must NOT have entered.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !entered.load(Ordering::SeqCst),
        "queued waiter must not enter while the holder is active"
    );

    // Release A; B should now proceed.
    drop(a);
    waiter.join().unwrap();
    assert!(
        entered.load(Ordering::SeqCst),
        "queued waiter must proceed once the holder releases"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// parallel mode: two entries on the same domain are both inert (no
// lock, no marker) and coexist without blocking.
#[test]
fn parallel_mode_allows_concurrent_entries() {
    let dir = unique_tmp("par");
    let a = CiSlot::enter(&dir, "lint", CiJobMode::Parallel).unwrap();
    let b = CiSlot::enter(&dir, "lint", CiJobMode::Parallel).unwrap();
    assert!(a.still_owner() && b.still_owner());
    assert!(a.watch().is_none() && b.watch().is_none());
    assert!(
        !dir.join("ci").join("lint.run").exists(),
        "parallel entries must not write a marker"
    );
    drop(a);
    drop(b);
    let _ = std::fs::remove_dir_all(&dir);
}
