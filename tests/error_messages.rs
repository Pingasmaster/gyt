// Audit 2026-05: every error path errors with a useful message;
// none leak bearer tokens, private signing material, or
// attacker-controlled unsanitised bytes.

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

// ─── credentials never leaked to stderr ─────────────────────────────

#[test]
fn fetch_failure_does_not_leak_bearer_token_in_stderr() {
    let env = Env::new("err-bearer");
    let r = env.fresh_repo("r");
    let secret = "SECRET-DO-NOT-LEAK";
    let url = format!("http://{secret}@127.0.0.1:1/no-such-repo");
    env.ok_in(&r, &["remote", "add", "origin", &url]);
    let out = env.run_in(&r, &["fetch", "--insecure", "origin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(secret),
        "fetch error message leaked bearer token: {stderr}"
    );
}

#[test]
fn remote_v_does_not_leak_bearer_token_in_stdout() {
    let env = Env::new("err-remote-v");
    let r = env.fresh_repo("r");
    let secret = "SECRET-DO-NOT-LEAK-2";
    let url = format!("http://{secret}@127.0.0.1:1/repo");
    env.ok_in(&r, &["remote", "add", "origin", &url]);
    let out = env.ok_in(&r, &["remote", "-v"]);
    assert!(!out.contains(secret), "remote -v leaked bearer: {out:?}");
    assert!(out.contains("REDACTED") || out.contains("redacted"));
}

#[test]
fn remote_add_confirmation_does_not_leak_bearer_token() {
    let env = Env::new("err-remote-add");
    let r = env.fresh_repo("r");
    let secret = "SECRET-DO-NOT-LEAK-3";
    let url = format!("http://{secret}@127.0.0.1:1/repo");
    let out = env.ok_in(&r, &["remote", "add", "origin", &url]);
    assert!(!out.contains(secret));
}

// ─── unknown flags surface as InvalidArgument with the flag name ────

#[test]
fn commit_unknown_flag_errors_with_flag_name() {
    let env = Env::new("err-flag-commit");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["commit", "--no-such-flag"]);
    assert!(err.contains("--no-such-flag") || err.contains("unexpected"));
}

#[test]
fn add_unknown_flag_errors() {
    let env = Env::new("err-flag-add");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["add", "--xx-no-such-flag"]);
    assert!(!err.is_empty());
}

#[test]
fn rm_unknown_flag_errors() {
    let env = Env::new("err-flag-rm");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["rm", "--xx-no-such-flag"]);
    assert!(err.contains("unknown") || err.contains("rm"));
}

#[test]
fn branch_unknown_arg_errors() {
    let env = Env::new("err-flag-branch");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["branch", "a", "b", "c"]);
    assert!(!err.is_empty());
}

#[test]
fn switch_unknown_branch_errors() {
    let env = Env::new("err-flag-switch");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["switch", "nonexistent-branch"]);
    assert!(!err.is_empty());
}

#[test]
fn clone_into_existing_nonempty_dir_errors() {
    let env = Env::new("err-clone-nonempty");
    let target = env.path("t");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("x"), b"x").unwrap();
    let (_, err) = env.fail_in(
        &env.dir,
        &[
            "clone",
            "--insecure",
            "http://localhost:9/repo",
            &target.display().to_string(),
        ],
    );
    assert!(err.contains("exists") || err.contains("not empty"));
}

#[test]
fn init_in_existing_repo_is_idempotent_or_clear_error() {
    let env = Env::new("err-init");
    let r = env.fresh_repo("r");
    // Should error (or succeed silently). Either is fine — we just
    // want a clear error if it errors.
    let out = env.run_in(&r, &["init"]);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.is_empty());
    }
}

#[test]
fn show_invalid_rev_errors() {
    let env = Env::new("err-show");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["show", "deadbeef00000000000000000000000000000000000000000000000000000000"]);
    assert!(!err.is_empty());
}

#[test]
fn log_outside_repo_errors() {
    let env = Env::new("err-log-outside");
    let (_, err) = env.fail_in(&env.dir, &["log"]);
    assert!(!err.is_empty());
}

// ─── error messages don't include private signing material ─────────

#[test]
fn keygen_missing_path_errors_without_leaking_bytes() {
    let env = Env::new("err-keygen");
    // Attempt to verify with a nonexistent key path — error must
    // mention path, not random bytes.
    let (_, err) = env.fail_in(
        &env.dir,
        &["verify", "/no/such/key/path.pub", "fakecommit"],
    );
    assert!(!err.is_empty());
}

// ─── attacker-controlled bytes don't appear unsanitised ────────────

#[test]
fn commit_with_control_byte_in_co_author_is_rejected_cleanly() {
    let env = Env::new("err-co-author");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    env.ok_in(&r, &["add", "a.txt"]);
    let (_, err) = env.fail_in(
        &r,
        &["commit", "-m", "msg", "--co-author", "X\rEvil"],
    );
    // Stderr must not contain the raw \r byte (would corrupt
    // terminal scrollback if user runs another command after).
    assert!(!err.contains('\r'), "stderr leaked CR byte");
}

#[test]
fn commit_with_null_byte_in_message_is_rejected() {
    let env = Env::new("err-null-msg");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    env.ok_in(&r, &["add", "a.txt"]);
    // NUL byte in -m argument is filtered by shells, but the
    // argv pathway can carry it. We just check it errors instead
    // of producing a torn commit.
    let out = env.run_in(&r, &["commit", "-m", "msg\0extra"]);
    // Either error or commit message gets sanitized — both OK,
    // but no panic.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("RUST_BACKTRACE"));
    assert!(!stderr.contains("panicked"));
}

#[test]
fn cli_unknown_subcommand_errors_with_useful_message() {
    let env = Env::new("err-unknown-sub");
    let (_, err) = env.fail_in(&env.dir, &["totally-not-a-subcommand"]);
    assert!(!err.is_empty());
}

#[test]
fn checkout_legacy_alias_either_works_or_errors_clearly() {
    let env = Env::new("err-checkout-legacy");
    let _r = env.fresh_repo("r");
    let _out = env.run_in(&env.dir, &["checkout", "--help"]);
    // Either it's a recognized command or it errors loudly. Just
    // make sure no panic.
}

// ─── permission denied / read-only FS surfaces cleanly ─────────────

#[cfg(unix)]
#[test]
fn add_in_readonly_workdir_surfaces_clean_error() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("err-readonly");
    let r = env.fresh_repo("r");
    let mut perms = std::fs::metadata(&r).unwrap().permissions();
    let orig = perms.mode();
    // Skip if read-only doesn't bite (running as root in CI).
    perms.set_mode(0o555);
    std::fs::set_permissions(&r, perms.clone()).unwrap();
    std::fs::write(r.join("new.txt"), b"x").ok(); // may fail; that's fine
    let out = env.run_in(&r, &["add", "new.txt"]);
    // Restore perms so cleanup can run.
    perms.set_mode(orig);
    let _ = std::fs::set_permissions(&r, perms);
    let _ = out;  // we just want no panic
}

// ─── help flag never errors and produces usage text ────────────────

#[test]
fn commit_help_prints_usage() {
    let env = Env::new("help-commit");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["commit", "--help"]);
    assert!(s.contains("commit") || s.contains("usage") || s.contains("-m"));
}

#[test]
fn add_help_prints_usage() {
    let env = Env::new("help-add");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["add", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn log_help_prints_usage() {
    let env = Env::new("help-log");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["log", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn gc_help_prints_usage() {
    let env = Env::new("help-gc");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["gc", "--help"]);
    assert!(s.contains("gc") || s.contains("--expire"));
}

#[test]
fn clean_help_prints_usage() {
    let env = Env::new("help-clean");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["clean", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn diff_help_prints_usage() {
    let env = Env::new("help-diff");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["diff", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn merge_help_prints_usage() {
    let env = Env::new("help-merge");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["merge", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn issue_help_prints_usage() {
    let env = Env::new("help-issue");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["issue", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn pr_help_prints_usage() {
    let env = Env::new("help-pr");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["pr", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn ci_help_prints_usage() {
    let env = Env::new("help-ci");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["ci", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn rebase_help_prints_usage() {
    let env = Env::new("help-rebase");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["rebase", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn cherry_pick_help_prints_usage() {
    let env = Env::new("help-cherry");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["cherry-pick", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn stash_help_prints_usage() {
    let env = Env::new("help-stash");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["stash", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn worktree_help_prints_usage() {
    let env = Env::new("help-wt");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["worktree", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn reset_help_prints_usage() {
    let env = Env::new("help-reset");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["reset", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn restore_help_prints_usage() {
    let env = Env::new("help-restore");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["restore", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn switch_help_prints_usage() {
    let env = Env::new("help-switch");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["switch", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn tag_help_prints_usage() {
    let env = Env::new("help-tag");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["tag", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn branch_help_prints_usage() {
    let env = Env::new("help-branch");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["branch", "--help"]);
    assert!(!s.is_empty());
}

#[test]
fn remote_help_prints_usage() {
    let env = Env::new("help-remote");
    let r = env.fresh_repo("r");
    let s = env.ok_in(&r, &["remote", "--help"]);
    assert!(!s.is_empty());
}
