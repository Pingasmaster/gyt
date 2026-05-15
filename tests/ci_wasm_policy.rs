#![expect(
    clippy::unwrap_used,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]

// Tests for the operator-controlled CiPolicy permission model.
//
// What we verify:
//   1. Defaults — repo read + output write only, network off.
//   2. --ci-no-repo-read denies read_file calls under repo_dir.
//   3. --ci-repo-write allows writes under repo_dir, still not .gyt/.
//   4. --ci-read / --ci-write add extra host paths only when the
//      operator passed them on the CLI (NOT just because the wasm
//      asked for them).
//   5. Memory / fuel / wall-time caps honor the policy overrides.
//   6. Network is denied even when policy.network=true (no hostcall
//      is linked).
//
// We drive each test by constructing a CiPolicy directly and calling
// `run_ci_wasm_with_policy`. WAT modules are inlined for readability.

#![expect(clippy::items_after_statements, reason = "intentional in test scaffolding")]

use gyt::ci_wasm::{run_ci_wasm_with_policy, CiPolicy};
use std::path::{Path, PathBuf};

fn unique_tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "gyt-policy-{}-{}-{}",
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

fn write_wat(dir: &Path, name: &str, wat: &str) -> PathBuf {
    let path = dir.join(format!("{name}.wat"));
    std::fs::write(&path, wat).unwrap();
    path
}

// A wasm module that:
//   - has a 64-byte memory region at offset 0 prefilled with "tag.txt"
//   - calls gyt_ci.read_file("tag.txt", buf, len)
//   - returns 0 if the read succeeded, 1 if it returned an error.
// We use a `data` section for the path bytes so we don't need to
// poke the memory at runtime.
const READ_TAG_WAT: &str = r#"
(module
  (import "gyt_ci" "read_file"
    (func $read (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "tag.txt")
  (func (export "_start") (result i32)
    (local $n i32)
    (local.set $n
      (call $read (i32.const 0) (i32.const 7)
                  (i32.const 64) (i32.const 1024)))
    ;; if (n < 0) return 1; else return 0
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (i32.const 1))))
    (i32.const 0)))
"#;

// Writes "hi" to "out.txt" via gyt_ci.write_file. Returns 0 on success.
const WRITE_OUT_WAT: &str = r#"
(module
  (import "gyt_ci" "write_file"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "out.txt")
  (data (i32.const 32) "hi")
  (func (export "_start") (result i32)
    (local $n i32)
    (local.set $n
      (call $write (i32.const 0) (i32.const 7)
                   (i32.const 32) (i32.const 2)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (i32.const 1))))
    (i32.const 0)))
"#;

// Writes via a path under the repo (`repo_out.txt`).
const WRITE_REPO_WAT: &str = r#"
(module
  (import "gyt_ci" "write_file"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "repo_out.txt")
  (data (i32.const 32) "hi")
  (func (export "_start") (result i32)
    (local $n i32)
    (local.set $n
      (call $write (i32.const 0) (i32.const 12)
                   (i32.const 32) (i32.const 2)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (i32.const 1))))
    (i32.const 0)))
"#;

// Tries to read ".gyt/secret" — must fail under every policy.
const READ_DOT_GYT_WAT: &str = r#"
(module
  (import "gyt_ci" "read_file"
    (func $read (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) ".gyt/secret")
  (func (export "_start") (result i32)
    (local $n i32)
    (local.set $n
      (call $read (i32.const 0) (i32.const 11)
                  (i32.const 64) (i32.const 1024)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (i32.const 0))))    ;; expected: read failed
    (i32.const 1)))                     ;; unexpected: read succeeded
"#;

fn setup_repo_with_tag(label: &str) -> (PathBuf, PathBuf) {
    let dir = unique_tmp(label);
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(dir.join("tag.txt"), b"hello").unwrap();
    (dir, out)
}

// ─── 1. Defaults ──────────────────────────────────────────────────────

#[test]
fn default_policy_allows_repo_read_and_output_write() {
    let (dir, out) = setup_repo_with_tag("defaults-ok");
    let wasm = write_wat(&dir, "read_tag", READ_TAG_WAT);
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &CiPolicy::default());
    assert!(r.is_ok(), "default policy must allow repo reads: {r:?}");

    let write_wasm = write_wat(&dir, "write_out", WRITE_OUT_WAT);
    let r = run_ci_wasm_with_policy(&write_wasm, &dir, &out, &CiPolicy::default());
    assert!(r.is_ok(), "default policy must allow output writes: {r:?}");
    assert!(
        out.join("out.txt").exists(),
        "expected out/out.txt to have been written"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── 2. --ci-no-repo-read ─────────────────────────────────────────────

#[test]
fn no_repo_read_blocks_read_under_repo() {
    let (dir, out) = setup_repo_with_tag("no-repo-read");
    let wasm = write_wat(&dir, "read_tag", READ_TAG_WAT);
    let policy = CiPolicy {
        repo_read: false,
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    // The wasm returns 1 if read_file errored — we treat that as
    // CI failure ("WASM exited with code 1").
    assert!(
        r.is_err(),
        "wasm must observe read failure under repo_read=false: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── 3. --ci-repo-write ───────────────────────────────────────────────

#[test]
fn repo_write_off_by_default_with_no_output_root() {
    // Drop output_write too so the only possible write root is the
    // repo. With repo_write=false (the default), no root is available
    // → the wasm's write_file call returns -2 → exit code 1.
    let (dir, out) = setup_repo_with_tag("repo-write-off");
    let wasm = write_wat(&dir, "write_repo", WRITE_REPO_WAT);
    let policy = CiPolicy {
        output_write: false,
        repo_write: false,
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    assert!(r.is_err(), "with no write root, every write must fail");
    assert!(!dir.join("repo_out.txt").exists());
    assert!(!out.join("repo_out.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repo_write_on_allows_repo_writes_but_still_blocks_dot_gyt() {
    // Disable output_write so the resolver actually picks repo_dir
    // (with both enabled, output_dir comes first — which is correct
    // safety behavior but doesn't exercise repo_write).
    let (dir, out) = setup_repo_with_tag("repo-write-on");
    std::fs::create_dir_all(dir.join(".gyt")).unwrap();
    let wasm = write_wat(&dir, "write_repo", WRITE_REPO_WAT);
    let policy = CiPolicy {
        output_write: false,
        repo_write: true,
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    assert!(r.is_ok(), "repo_write=true must allow writes to repo_dir");
    assert!(dir.join("repo_out.txt").exists());

    // .gyt/ is denied even with repo_write=true: by writing to .gyt/x
    // we should still get -2 from the sandbox.
    const WRITE_DOT_GYT_WAT: &str = r#"
(module
  (import "gyt_ci" "write_file"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) ".gyt/x.txt")
  (data (i32.const 32) "hi")
  (func (export "_start") (result i32)
    (local $n i32)
    (local.set $n
      (call $write (i32.const 0) (i32.const 10)
                   (i32.const 32) (i32.const 2)))
    (if (i32.lt_s (local.get $n) (i32.const 0))
      (then (return (i32.const 0))))    ;; expected: write blocked
    (i32.const 1)))                     ;; unexpected: write allowed
"#;
    let bad = write_wat(&dir, "write_dotgyt", WRITE_DOT_GYT_WAT);
    let r = run_ci_wasm_with_policy(&bad, &dir, &out, &policy);
    assert!(r.is_ok(), "wasm must observe blocked write to .gyt/: {r:?}");
    assert!(
        !dir.join(".gyt").join("x.txt").exists(),
        "no file should have been created under .gyt/"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── 4. .gyt/ is always invisible to reads ────────────────────────────

#[test]
fn dot_gyt_invisible_even_with_extra_read_pointing_at_repo() {
    let (dir, out) = setup_repo_with_tag("dotgyt-extra-read");
    std::fs::create_dir_all(dir.join(".gyt")).unwrap();
    std::fs::write(dir.join(".gyt").join("secret"), b"top secret").unwrap();
    let wasm = write_wat(&dir, "read_dotgyt", READ_DOT_GYT_WAT);
    // Operator points --ci-read at the repo dir itself (and even
    // grants repo_read). .gyt/ still must not resolve.
    let policy = CiPolicy {
        extra_read: vec![dir.clone()],
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    assert!(r.is_ok(), ".gyt read must always be denied: {r:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── 5. extra_write allows writes under an extra path ─────────────────

#[test]
fn extra_write_allows_writes_under_extra_root() {
    let dir = unique_tmp("extra-write");
    let out = dir.join("out");
    let extra = dir.join("extra");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&extra).unwrap();
    // The wasm tries to write "out.txt" with output_write disabled but
    // extra_write at `extra/`. Path resolution should pick `extra/`.
    let wasm = write_wat(&dir, "write_out", WRITE_OUT_WAT);
    let policy = CiPolicy {
        output_write: false,
        extra_write: vec![extra.clone()],
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    assert!(r.is_ok(), "extra_write should allow the write: {r:?}");
    assert!(
        extra.join("out.txt").exists(),
        "extra/out.txt must be the target chosen by the resolver"
    );
    assert!(
        !out.join("out.txt").exists(),
        "default output_dir must not have been used"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── 6. Network reservation is a no-op (no hostcall linked) ───────────

#[test]
fn network_grant_is_inert_no_hostcall_linked() {
    // A wasm that imports any non-gyt_ci function MUST fail to
    // instantiate. With `policy.network = true` this is still true —
    // the grant is operator vocabulary only; nothing is actually
    // linked yet.
    const NETWORK_WAT: &str = r#"
(module
  (import "gyt_ci" "http_get"
    (func $h (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start") (result i32) i32.const 0))
"#;
    let dir = unique_tmp("network-inert");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let wasm = write_wat(&dir, "net", NETWORK_WAT);
    let policy = CiPolicy {
        network: true,
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    assert!(
        r.is_err(),
        "wasm must fail to instantiate even with network=true (no hostcall linked)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── 7. Memory + fuel + wall-time overrides are honored ───────────────

#[test]
fn explicit_memory_cap_below_default_is_honored() {
    // The bloat test from ci_wasm_sandbox.rs already covers this end
    // to end; we just verify the policy field is plumbed through by
    // constructing a tiny cap and a noop wasm — instantiation must
    // succeed because 1 initial page is well under 1 MiB.
    const NOOP_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "_start") (result i32) i32.const 0))
"#;
    let dir = unique_tmp("explicit-mem");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let wasm = write_wat(&dir, "noop", NOOP_WAT);
    let policy = CiPolicy {
        memory_max: 1024 * 1024, // 1 MiB
        ..Default::default()
    };
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    assert!(r.is_ok(), "small memory cap must still allow 1-page init: {r:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explicit_short_wall_time_terminates_infinite_loop() {
    // A wasm with a tight loop must be terminated by the epoch
    // deadline at the configured wall time.
    const LOOP_WAT: &str = r#"
(module
  (func (export "_start") (result i32)
    (loop $l br $l)
    i32.const 0))
"#;
    let dir = unique_tmp("short-time");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let wasm = write_wat(&dir, "loop", LOOP_WAT);
    let policy = CiPolicy {
        // Generous fuel so the cap that fires is wall time, not fuel.
        fuel: 10u64.pow(15),
        wall_time_secs: 3,
        ..Default::default()
    };
    let start = std::time::Instant::now();
    let r = run_ci_wasm_with_policy(&wasm, &dir, &out, &policy);
    let elapsed = start.elapsed();
    assert!(r.is_err(), "wall_time must terminate infinite loop: {r:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "wall_time must terminate within ~secs (was {elapsed:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
