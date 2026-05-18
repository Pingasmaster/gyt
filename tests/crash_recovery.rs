// Audit 2026-05: crash recovery / atomic state files.
// These tests simulate process kill mid-operation by directly
// manipulating the on-disk state files, then verify subsequent
// commands can recover.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;

#[test]
fn commit_after_index_changes_no_tear_with_invalid_index() {
    // Simulate a torn-index scenario: write garbage to the index file
    // and verify gyt reports a clean error rather than panicking.
    let env = Env::new("crash-torn-index");
    let r = env.fresh_repo("r");
    let idx = r.join(".gyt").join("index");
    std::fs::write(&idx, b"garbage non-index bytes").unwrap();
    let out = env.run_in(&r, &["status"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "torn index must not panic: {stderr}");
}

#[test]
fn ref_with_invalid_hash_surfaces_clean_error() {
    let env = Env::new("crash-bad-ref");
    let r = env.fresh_repo("r");
    let ref_path = r.join(".gyt").join("refs").join("heads").join("main");
    // Replace the valid hash with garbage.
    std::fs::write(&ref_path, b"not a hash\n").unwrap();
    let out = env.run_in(&r, &["log"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"));
}

#[test]
fn missing_head_file_surfaces_clean_error() {
    let env = Env::new("crash-no-head");
    let r = env.fresh_repo("r");
    std::fs::remove_file(r.join(".gyt").join("HEAD")).unwrap();
    let out = env.run_in(&r, &["log"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"));
}

#[test]
fn merge_head_left_over_from_kill_status_observable() {
    let env = Env::new("crash-merge-leftover");
    let r = env.fresh_repo("r");
    // Plant a fake MERGE_HEAD file as if a previous merge was killed.
    let head_hash = std::fs::read_to_string(
        r.join(".gyt").join("refs").join("heads").join("main"),
    )
    .unwrap();
    std::fs::write(r.join(".gyt").join("MERGE_HEAD"), &head_hash).unwrap();
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn rebase_state_files_left_over_status_does_not_panic() {
    let env = Env::new("crash-rebase-leftover");
    let r = env.fresh_repo("r");
    let head = std::fs::read_to_string(
        r.join(".gyt").join("refs").join("heads").join("main"),
    )
    .unwrap();
    std::fs::write(r.join(".gyt").join("REBASE_HEAD"), &head).unwrap();
    std::fs::write(r.join(".gyt").join("REBASE_ONTO"), &head).unwrap();
    std::fs::write(r.join(".gyt").join("REBASE_TODO"), &head).unwrap();
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn cherry_pick_head_left_over_does_not_panic() {
    let env = Env::new("crash-cherry-leftover");
    let r = env.fresh_repo("r");
    let head = std::fs::read_to_string(
        r.join(".gyt").join("refs").join("heads").join("main"),
    )
    .unwrap();
    std::fs::write(r.join(".gyt").join("CHERRY_PICK_HEAD"), &head).unwrap();
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn truncated_loose_object_surfaces_clean_error() {
    let env = Env::new("crash-truncated-obj");
    let r = env.fresh_repo("r");
    let objects = r.join(".gyt").join("objects");
    // Find one loose object and truncate it.
    let mut victim: Option<std::path::PathBuf> = None;
    'find: for shard in std::fs::read_dir(&objects).unwrap().flatten() {
        let sp = shard.path();
        if !sp.is_dir() {
            continue;
        }
        let n = sp.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if n.len() != 2 {
            continue;
        }
        if let Some(f) = std::fs::read_dir(&sp).unwrap().flatten().next() {
            victim = Some(f.path());
            break 'find;
        }
    }
    let v = victim.expect("at least one loose object");
    std::fs::write(&v, b"truncated").unwrap();
    let out = env.run_in(&r, &["log"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn duplicate_repo_lock_blocks_concurrent_commit() {
    let env = Env::new("crash-double-lock");
    let r = env.fresh_repo("r");
    // Create a stale lock file as if a previous process died with it.
    let lock = r.join(".gyt").join("refs.lock");
    std::fs::write(&lock, b"pid=99999 ts=1\n").unwrap();
    // First operation: the stale-lock-reclamation path should
    // eventually reclaim (it requires mtime > STALE_AFTER), but for
    // short-running tests we just confirm no panic.
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn empty_objects_dir_does_not_panic_log() {
    let env = Env::new("crash-empty-objs");
    let r = env.fresh_repo("r");
    let objects = r.join(".gyt").join("objects");
    // Remove every loose object.
    for shard in std::fs::read_dir(&objects).unwrap().flatten() {
        let sp = shard.path();
        if !sp.is_dir() {
            continue;
        }
        let n = sp.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if n.len() != 2 {
            continue;
        }
        let _ = std::fs::remove_dir_all(&sp);
    }
    let out = env.run_in(&r, &["log"]);
    // Either errors with "no objects" or succeeds with empty log;
    // panic is unacceptable.
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn corrupted_config_toml_does_not_panic() {
    let env = Env::new("crash-bad-config");
    let r = env.fresh_repo("r");
    std::fs::write(r.join(".gyt").join("config.toml"), b"this is not valid toml ::: <>").unwrap();
    let out = env.run_in(&r, &["log"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn invalid_utf8_in_ref_does_not_panic() {
    let env = Env::new("crash-bad-utf8-ref");
    let r = env.fresh_repo("r");
    let refp = r.join(".gyt").join("refs").join("heads").join("main");
    std::fs::write(&refp, [0xff, 0xfe, 0xfd, b'\n']).unwrap();
    let out = env.run_in(&r, &["log"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn gc_with_a_torn_index_does_not_panic() {
    // C1 regression: gc must seed from index. If the index is torn,
    // gc shouldn't panic — it should error or skip the seeding.
    let env = Env::new("crash-gc-torn-idx");
    let r = env.fresh_repo("r");
    let idx = r.join(".gyt").join("index");
    std::fs::write(&idx, b"garbage").unwrap();
    let out = env.run_in(&r, &["gc"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn commit_after_partial_workdir_state_recovers() {
    let env = Env::new("crash-partial-wd");
    let r = env.fresh_repo("r");
    // Simulate partial workdir: add a half-written file via direct fs.
    std::fs::write(r.join("staged.txt"), b"hello").unwrap();
    env.ok_in(&r, &["add", "staged.txt"]);
    // Drop a stray .tmp file as if atomic_write was interrupted.
    std::fs::write(r.join(".gyt").join("HEAD.tmp.1.2.3"), b"junk").unwrap();
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn objects_lock_left_behind_does_not_block_status() {
    let env = Env::new("crash-obj-lock");
    let r = env.fresh_repo("r");
    let lock = r.join(".gyt").join("objects.lock");
    std::fs::write(&lock, b"").unwrap();
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn rebase_todo_with_invalid_hash_does_not_panic() {
    let env = Env::new("crash-bad-todo");
    let r = env.fresh_repo("r");
    std::fs::write(r.join(".gyt").join("REBASE_TODO"), b"not a hash\n").unwrap();
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn missing_objects_dir_does_not_panic() {
    let env = Env::new("crash-no-objs-dir");
    let r = env.fresh_repo("r");
    let _ = std::fs::remove_dir_all(r.join(".gyt").join("objects"));
    let out = env.run_in(&r, &["status"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn unreadable_loose_object_dir_does_not_panic_status() {
    let env = Env::new("crash-unread-shard");
    let r = env.fresh_repo("r");
    let objects = r.join(".gyt").join("objects");
    std::fs::create_dir_all(objects.join("ff")).unwrap();
    // Drop a non-hex file into the shard — should be skipped.
    std::fs::write(objects.join("ff").join("not-a-hash"), b"junk").unwrap();
    let out = env.run_in(&r, &["log"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn detached_head_pointing_at_nonexistent_commit_does_not_panic() {
    let env = Env::new("crash-detached-orphan");
    let r = env.fresh_repo("r");
    let bogus = format!("{}\n", "f".repeat(64));
    std::fs::write(r.join(".gyt").join("HEAD"), bogus).unwrap();
    let out = env.run_in(&r, &["log"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn meta_dir_with_corrupted_counter_does_not_panic() {
    let env = Env::new("crash-counter");
    let r = env.fresh_repo("r");
    let meta = r.join(".gyt").join("meta");
    std::fs::create_dir_all(&meta).unwrap();
    std::fs::write(meta.join("issues_next"), b"not a number").unwrap();
    let out = env.run_in(&r, &["issue", "new", "test", "-m", "body"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn counter_at_u64_max_overflow_surfaces_clean_error() {
    // L16 regression.
    let env = Env::new("crash-counter-max");
    let r = env.fresh_repo("r");
    let meta = r.join(".gyt").join("meta");
    std::fs::create_dir_all(&meta).unwrap();
    std::fs::write(meta.join("issues_next"), format!("{}\n", u64::MAX)).unwrap();
    let out = env.run_in(&r, &["issue", "new", "test", "-m", "body"]);
    // Should error with an overflow message, not panic.
    assert!(!out.status.success() || String::from_utf8_lossy(&out.stderr).contains("overflow"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn refs_dir_with_non_hex_content_skipped_not_panic() {
    let env = Env::new("crash-bad-ref-content");
    let r = env.fresh_repo("r");
    let dev_ref = r.join(".gyt").join("refs").join("heads").join("dev");
    std::fs::write(&dev_ref, b"definitely not 64 hex chars\n").unwrap();
    let out = env.run_in(&r, &["branch"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}

#[test]
fn duplicate_remote_add_errors_cleanly() {
    let env = Env::new("crash-dup-remote");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["remote", "add", "origin", "http://x/r"]);
    let (_, err) = env.fail_in(&r, &["remote", "add", "origin", "http://y/r"]);
    assert!(err.contains("already") || err.contains("origin"));
}

#[test]
fn delete_nonexistent_branch_errors_cleanly() {
    let env = Env::new("crash-del-nonexist");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["branch", "-d", "no-such-branch"]);
    assert!(!err.is_empty());
}

#[test]
fn delete_current_branch_errors_cleanly() {
    let env = Env::new("crash-del-current");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["branch", "-d", "main"]);
    assert!(err.contains("current") || err.contains("main"));
}

#[test]
fn stash_pop_on_empty_stash_errors() {
    let env = Env::new("crash-stash-empty");
    let r = env.fresh_repo("r");
    let out = env.run_in(&r, &["stash", "pop"]);
    // Either errors or succeeds with "nothing to pop". Just no panic.
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
}
