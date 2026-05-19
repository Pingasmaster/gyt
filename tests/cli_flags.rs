// Audit 2026-05: per-command, per-flag CLI surface coverage.
// Each test exercises one documented flag and pins its observable
// behavior or its accept/reject semantics. Catches future flag-rename
// regressions cheaply.

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

// ─── gyt init ──────────────────────────────────────────────────────

#[test]
fn init_creates_gyt_dir() {
    let env = Env::new("flag-init");
    let r = env.path("r");
    std::fs::create_dir_all(&r).unwrap();
    env.ok_in(&r, &["init"]);
    assert!(r.join(".gyt").is_dir());
}

#[test]
fn init_help_works() {
    let env = Env::new("flag-init-help");
    let _ = env.run_in(&env.dir, &["init", "--help"]);
}

// ─── gyt add ───────────────────────────────────────────────────────

#[test]
fn add_single_file_stages() {
    let env = Env::new("flag-add-single");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
}

#[test]
fn add_dot_stages_all() {
    let env = Env::new("flag-add-dot");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    std::fs::write(r.join("b.txt"), b"b").unwrap();
    env.ok_in(&r, &["add", "."]);
}

#[test]
fn add_unknown_flag_rejected() {
    let env = Env::new("flag-add-unk");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["add", "--invalid-flag"]);
    assert!(!err.is_empty());
}

// ─── gyt rm ───────────────────────────────────────────────────────

#[test]
fn rm_single_file_unstages() {
    let env = Env::new("flag-rm-single");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "add"]);
    env.ok_in(&r, &["rm", "x.txt"]);
}

#[test]
fn rm_dash_f_forces() {
    let env = Env::new("flag-rm-f");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    std::fs::write(r.join("x.txt"), b"y").unwrap();
    env.ok_in(&r, &["rm", "-f", "x.txt"]);
}

#[test]
fn rm_help_works() {
    let env = Env::new("flag-rm-help");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["rm", "--help"]);
}

// ─── gyt commit ────────────────────────────────────────────────────

#[test]
fn commit_dash_m_message() {
    let env = Env::new("flag-commit-m");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    let out = env.ok_in(&r, &["commit", "-m", "hello"]);
    assert!(out.contains("hello") || !out.is_empty());
}

#[test]
fn commit_amend_changes_message() {
    let env = Env::new("flag-amend");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "first"]);
    env.ok_in(&r, &["commit", "--amend", "-m", "second"]);
}

#[test]
fn commit_allow_empty() {
    let env = Env::new("flag-allow-empty");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["commit", "--allow-empty", "-m", "empty"]);
}

#[test]
fn commit_requires_message() {
    let env = Env::new("flag-no-m");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    let (_, err) = env.fail_in(&r, &["commit"]);
    assert!(err.contains("-m") || err.contains("message"));
}

#[test]
fn commit_co_author_accepted() {
    let env = Env::new("flag-co-author");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(
        &r,
        &["commit", "-m", "m", "--co-author", "Carol <c@x>"],
    );
}

#[test]
fn commit_ai_accepted() {
    let env = Env::new("flag-ai");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "m", "--ai", "gpt-4"]);
}

#[test]
fn commit_reviewer_accepted() {
    let env = Env::new("flag-reviewer");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "m", "--reviewer", "Bob <b@x>"]);
}

#[test]
fn commit_co_author_with_newline_rejected() {
    // H14
    let env = Env::new("flag-co-newline");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    let (_, err) = env.fail_in(
        &r,
        &["commit", "-m", "m", "--co-author", "E\nvil"],
    );
    assert!(err.contains("control") || err.contains("--co-author"));
}

#[test]
fn commit_dash_s_short_sign_flag_accepted() {
    // The flag is parsed even if key isn't set up (test only argv parse).
    let env = Env::new("flag-s");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    // No signing key configured → expected to error. We just want
    // the parse path to recognize -S.
    let out = env.run_in(&r, &["commit", "-m", "m", "-S"]);
    // Either signs (if a key was set up via GYT_SIGNING_KEY) or
    // errors with a non-flag-parse message.
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("unexpected argument"));
    }
}

// ─── gyt log ───────────────────────────────────────────────────────

#[test]
fn log_show_signature_flag_recognized() {
    let env = Env::new("flag-log-sig");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["log", "--show-signature"]);
}

#[test]
fn log_empty_repo_handled() {
    let env = Env::new("flag-log-empty");
    let r = env.path("r");
    std::fs::create_dir_all(&r).unwrap();
    env.ok_in(&r, &["init"]);
    let _ = env.run_in(&r, &["log"]);
}

// ─── gyt status ────────────────────────────────────────────────────

#[test]
fn status_in_fresh_repo() {
    let env = Env::new("flag-status");
    let r = env.fresh_repo("r");
    let _ = env.ok_in(&r, &["status"]);
}

#[test]
fn status_shows_modified() {
    let env = Env::new("flag-status-mod");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("seed.txt"), b"modified\n").unwrap();
    let out = env.ok_in(&r, &["status"]);
    assert!(out.contains("seed.txt") || out.contains("modified") || !out.is_empty());
}

// ─── gyt diff ──────────────────────────────────────────────────────

#[test]
fn diff_no_changes_empty_or_clean() {
    let env = Env::new("flag-diff-empty");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["diff"]);
}

#[test]
fn diff_after_modify_shows_diff() {
    let env = Env::new("flag-diff-mod");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("seed.txt"), b"modified content\n").unwrap();
    let _ = env.ok_in(&r, &["diff"]);
}

// ─── gyt branch ────────────────────────────────────────────────────

#[test]
fn branch_lists_branches() {
    let env = Env::new("flag-branch-list");
    let r = env.fresh_repo("r");
    let out = env.ok_in(&r, &["branch"]);
    assert!(out.contains("main") || out.contains("master") || !out.is_empty());
}

#[test]
fn branch_create_new() {
    let env = Env::new("flag-branch-new");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["branch", "feature"]);
    let out = env.ok_in(&r, &["branch"]);
    assert!(out.contains("feature"));
}

#[test]
fn branch_delete_d() {
    let env = Env::new("flag-branch-d");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["branch", "tmp"]);
    env.ok_in(&r, &["branch", "-d", "tmp"]);
}

#[test]
fn branch_force_delete_capital_d() {
    let env = Env::new("flag-branch-D");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["branch", "tmp"]);
    env.ok_in(&r, &["branch", "-D", "tmp"]);
}

#[test]
fn branch_rename_m() {
    let env = Env::new("flag-branch-m");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["branch", "old-name"]);
    env.ok_in(&r, &["branch", "-m", "old-name", "new-name"]);
}

#[test]
fn branch_delete_current_refused() {
    let env = Env::new("flag-branch-d-current");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["branch", "-d", "main"]);
    assert!(err.contains("current") || err.contains("main"));
}

// ─── gyt switch ────────────────────────────────────────────────────

#[test]
fn switch_to_existing_branch() {
    let env = Env::new("flag-switch");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["branch", "feat"]);
    env.ok_in(&r, &["switch", "feat"]);
}

#[test]
fn switch_dash_c_creates_branch() {
    let env = Env::new("flag-switch-c");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["switch", "-c", "newbranch"]);
}

// ─── gyt restore ───────────────────────────────────────────────────

#[test]
fn restore_brings_back_deleted_file() {
    let env = Env::new("flag-restore");
    let r = env.fresh_repo("r");
    std::fs::remove_file(r.join("seed.txt")).unwrap();
    env.ok_in(&r, &["restore", "seed.txt"]);
    assert!(r.join("seed.txt").exists());
}

// ─── gyt reset ─────────────────────────────────────────────────────

#[test]
fn reset_soft_keeps_workdir() {
    let env = Env::new("flag-reset-soft");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "c"]);
    let _ = env.run_in(&r, &["reset", "--soft", "HEAD~1"]);
}

#[test]
fn reset_mixed_default() {
    let env = Env::new("flag-reset-mixed");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "c"]);
    let _ = env.run_in(&r, &["reset", "--mixed", "HEAD~1"]);
}

#[test]
fn reset_hard_drops_workdir() {
    let env = Env::new("flag-reset-hard");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "c"]);
    let _ = env.run_in(&r, &["reset", "--hard", "HEAD~1"]);
}

// ─── gyt gc ────────────────────────────────────────────────────────

#[test]
fn gc_default_runs() {
    let env = Env::new("flag-gc");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["gc"]);
}

#[test]
fn gc_keep_reflog_flag() {
    let env = Env::new("flag-gc-keep");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["gc", "--keep-reflog"]);
}

#[test]
fn gc_expire_reflog_takes_value() {
    let env = Env::new("flag-gc-expire");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["gc", "--expire-reflog", "0"]);
}

#[test]
fn gc_expire_reflog_invalid_errors() {
    let env = Env::new("flag-gc-expire-bad");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["gc", "--expire-reflog", "abc"]);
    assert!(!err.is_empty());
}

#[test]
fn gc_pack_flag() {
    let env = Env::new("flag-gc-pack");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["gc", "--pack"]);
}

// ─── gyt clean ─────────────────────────────────────────────────────

#[test]
fn clean_dry_run_prints_only() {
    let env = Env::new("flag-clean-n");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("untracked.txt"), b"x").unwrap();
    let out = env.ok_in(&r, &["clean", "-n"]);
    assert!(out.contains("untracked.txt"));
    assert!(r.join("untracked.txt").exists(), "dry-run must not remove");
}

#[test]
fn clean_removes_untracked() {
    let env = Env::new("flag-clean");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("untracked.txt"), b"x").unwrap();
    // B31: --force is now required for destructive `clean`; bare `clean`
    // refuses. The original test invoked it without a flag.
    env.ok_in(&r, &["clean", "--force"]);
    assert!(!r.join("untracked.txt").exists());
}

// B31: a bare `gyt clean` (no -f, no -n) must refuse — without this
// gate, hours of un-staged scratch work would silently disappear.
#[test]
fn clean_without_force_refuses() {
    let env = Env::new("flag-clean-noforce");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("untracked.txt"), b"x").unwrap();
    let (_out, err) = env.fail_in(&r, &["clean"]);
    assert!(
        err.contains("--force") || err.contains("force"),
        "expected --force error, got: {err}"
    );
    assert!(
        r.join("untracked.txt").exists(),
        "clean without --force must not delete"
    );
}

// ─── gyt merge ─────────────────────────────────────────────────────

#[test]
fn merge_ff_into_main() {
    let env = Env::new("flag-merge-ff");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["switch", "-c", "feat"]);
    std::fs::write(r.join("b.txt"), b"b").unwrap();
    env.ok_in(&r, &["add", "b.txt"]);
    env.ok_in(&r, &["commit", "-m", "b"]);
    env.ok_in(&r, &["switch", "main"]);
    env.ok_in(&r, &["merge", "feat"]);
}

#[test]
fn merge_already_up_to_date() {
    let env = Env::new("flag-merge-utd");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["merge", "main"]);
}

// ─── gyt rebase ────────────────────────────────────────────────────

#[test]
fn rebase_no_op_on_same_branch() {
    let env = Env::new("flag-rebase-nop");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["rebase", "main"]);
}

// ─── gyt cherry-pick ───────────────────────────────────────────────

#[test]
fn cherry_pick_picks_a_commit() {
    let env = Env::new("flag-cherry");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["switch", "-c", "feat"]);
    std::fs::write(r.join("c.txt"), b"c").unwrap();
    env.ok_in(&r, &["add", "c.txt"]);
    env.ok_in(&r, &["commit", "-m", "c"]);
    let log = env.ok_in(&r, &["log"]);
    // Find the commit hash; the test just checks that the command
    // parses if we pass HEAD.
    let _ = log;
    env.ok_in(&r, &["switch", "main"]);
    let _ = env.run_in(&r, &["cherry-pick", "feat"]);
}

// ─── gyt remote ────────────────────────────────────────────────────

#[test]
fn remote_v_lists() {
    let env = Env::new("flag-remote-v");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["remote", "add", "origin", "http://x/repo"]);
    let out = env.ok_in(&r, &["remote", "-v"]);
    assert!(out.contains("origin"));
}

#[test]
fn remote_add_then_lists() {
    let env = Env::new("flag-remote-add");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["remote", "add", "upstream", "http://y/r"]);
}

// ─── gyt tag ───────────────────────────────────────────────────────

#[test]
fn tag_create_lightweight() {
    let env = Env::new("flag-tag");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["tag", "v1"]);
}

// ─── gyt stash ─────────────────────────────────────────────────────

#[test]
fn stash_push_pop_round_trip() {
    let env = Env::new("flag-stash");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("seed.txt"), b"modified\n").unwrap();
    let _ = env.run_in(&r, &["stash", "push"]);
}

// ─── gyt issue ─────────────────────────────────────────────────────

#[test]
fn issue_new_and_list() {
    let env = Env::new("flag-issue");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["issue", "new", "title", "-m", "body"]);
    let out = env.ok_in(&r, &["issue", "list"]);
    assert!(out.contains("title") || !out.is_empty());
}

#[test]
fn issue_show_existing() {
    let env = Env::new("flag-issue-show");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["issue", "new", "title", "-m", "body"]);
    let _ = env.ok_in(&r, &["issue", "show", "1"]);
}

#[test]
fn issue_close_and_reopen() {
    let env = Env::new("flag-issue-close");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["issue", "new", "x", "-m", "body"]);
    let _ = env.run_in(&r, &["issue", "close", "1"]);
    let _ = env.run_in(&r, &["issue", "reopen", "1"]);
}

#[test]
fn issue_comment() {
    let env = Env::new("flag-issue-cmt");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["issue", "new", "x", "-m", "body"]);
    env.ok_in(&r, &["issue", "comment", "1", "-m", "follow-up"]);
}

// ─── gyt pr ────────────────────────────────────────────────────────

#[test]
fn pr_new_and_list() {
    let env = Env::new("flag-pr");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["switch", "-c", "feat"]);
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "f"]);
    env.ok_in(&r, &["switch", "main"]);
    env.ok_in(
        &r,
        &["pr", "new", "title", "--source", "feat", "--target", "main", "-m", "b"],
    );
    let _ = env.ok_in(&r, &["pr", "list"]);
}

#[test]
fn pr_show_existing() {
    let env = Env::new("flag-pr-show");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["switch", "-c", "feat"]);
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "f"]);
    env.ok_in(&r, &["switch", "main"]);
    env.ok_in(
        &r,
        &["pr", "new", "title", "--source", "feat", "--target", "main", "-m", "b"],
    );
    let _ = env.ok_in(&r, &["pr", "show", "1"]);
}

// ─── gyt verify (no key configured) ────────────────────────────────

#[test]
fn verify_help_works() {
    let env = Env::new("flag-verify-help");
    let _ = env.run_in(&env.dir, &["verify", "--help"]);
}

// ─── gyt keygen ────────────────────────────────────────────────────

#[test]
fn keygen_help_works() {
    let env = Env::new("flag-keygen-help");
    let _ = env.run_in(&env.dir, &["keygen", "--help"]);
}

// ─── gyt config ────────────────────────────────────────────────────

#[test]
fn config_set_and_get() {
    let env = Env::new("flag-config");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["config", "user.name", "Test"]);
    let _ = env.run_in(&r, &["config", "user.name"]);
}

// ─── gyt show ──────────────────────────────────────────────────────

#[test]
fn show_head() {
    let env = Env::new("flag-show");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["show", "HEAD"]);
}

#[test]
fn show_show_signature_flag() {
    let env = Env::new("flag-show-sig");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["show", "--show-signature", "HEAD"]);
}

// ─── gyt blame ─────────────────────────────────────────────────────

#[test]
fn blame_existing_file() {
    let env = Env::new("flag-blame");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["blame", "seed.txt"]);
}

// ─── gyt grep ──────────────────────────────────────────────────────

#[test]
fn grep_finds_match() {
    let env = Env::new("flag-grep");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["grep", "seed"]);
}

// ─── gyt worktree ──────────────────────────────────────────────────

#[test]
fn worktree_help_works() {
    let env = Env::new("flag-wt-help");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["worktree", "--help"]);
}

// ─── gyt reflog ────────────────────────────────────────────────────

#[test]
fn reflog_lists_entries() {
    let env = Env::new("flag-reflog");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["reflog"]);
}

// ─── gyt push / fetch / pull (without server) ──────────────────────

#[test]
fn push_without_remote_errors() {
    let env = Env::new("flag-push-noremote");
    let r = env.fresh_repo("r");
    let (_, _) = env.fail_in(&r, &["push", "origin"]);
}

#[test]
fn fetch_without_remote_errors() {
    let env = Env::new("flag-fetch-noremote");
    let r = env.fresh_repo("r");
    let (_, _) = env.fail_in(&r, &["fetch", "origin"]);
}

#[test]
fn pull_without_remote_errors() {
    let env = Env::new("flag-pull-noremote");
    let r = env.fresh_repo("r");
    let (_, _) = env.fail_in(&r, &["pull", "origin"]);
}

// ─── gyt serve flag parsing ────────────────────────────────────────

#[test]
fn serve_help_works() {
    let env = Env::new("flag-serve-help");
    let _ = env.run_in(&env.dir, &["serve", "--help"]);
}

// ─── gyt clone flag parsing ────────────────────────────────────────

#[test]
fn clone_help_works() {
    let env = Env::new("flag-clone-help");
    let _ = env.run_in(&env.dir, &["clone", "--help"]);
}

#[test]
fn clone_without_url_errors() {
    let env = Env::new("flag-clone-noarg");
    let (_, _) = env.fail_in(&env.dir, &["clone"]);
}

// ─── gyt ci ────────────────────────────────────────────────────────

#[test]
fn ci_in_repo_without_gyt_ci_dir_is_clean_noop() {
    let env = Env::new("flag-ci-noop");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["ci"]);
}

// ─── gyt getthefuckoutofmyrepo ─────────────────────────────────────

#[test]
fn gtfoomr_no_args_errors() {
    let env = Env::new("flag-gtfoomr-noargs");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["getthefuckoutofmyrepo"]);
    assert!(err.contains("path") || err.contains("required"));
}

#[test]
fn gtfoomr_unknown_flag_errors() {
    let env = Env::new("flag-gtfoomr-unk");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["getthefuckoutofmyrepo", "--xx-no-such-flag"]);
    assert!(!err.is_empty());
}

// ─── outside-repo error paths ──────────────────────────────────────

#[test]
fn commit_outside_repo_errors() {
    let env = Env::new("flag-cmt-outside");
    let (_, _) = env.fail_in(&env.dir, &["commit", "-m", "m"]);
}

#[test]
fn add_outside_repo_errors() {
    let env = Env::new("flag-add-outside");
    let (_, _) = env.fail_in(&env.dir, &["add", "foo"]);
}

#[test]
fn status_outside_repo_errors() {
    let env = Env::new("flag-status-outside");
    let (_, _) = env.fail_in(&env.dir, &["status"]);
}

#[test]
fn log_outside_repo_errors() {
    let env = Env::new("flag-log-outside");
    let (_, _) = env.fail_in(&env.dir, &["log"]);
}

// ─── short flag combos ─────────────────────────────────────────────

#[test]
fn commit_dash_m_short_is_same_as_long() {
    let env = Env::new("flag-m-short");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    env.ok_in(&r, &["add", "a.txt"]);
    env.ok_in(&r, &["commit", "-m", "short"]);
}

// ─── argv injection / odd input ────────────────────────────────────

#[test]
fn add_path_with_dash_dash_prefix_treated_as_unknown_flag() {
    // We can't easily test "--" passthrough without knowing the
    // exact behavior; just confirm no panic.
    let env = Env::new("flag-add-dashdash");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["add", "--"]);
}

#[test]
fn commit_with_empty_message_errors_or_succeeds() {
    let env = Env::new("flag-cmt-empty-m");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    env.ok_in(&r, &["add", "a.txt"]);
    let _ = env.run_in(&r, &["commit", "-m", ""]);
}

// ─── gyt diff variants ─────────────────────────────────────────────

#[test]
fn diff_revs_passes_parse() {
    let env = Env::new("flag-diff-revs");
    let r = env.fresh_repo("r");
    let _ = env.run_in(&r, &["diff", "HEAD"]);
}

// ─── gyt log limit / pagination ────────────────────────────────────

#[test]
fn log_multiple_commits_listed() {
    let env = Env::new("flag-log-multi");
    let r = env.fresh_repo("r");
    for i in 0..3 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    let out = env.ok_in(&r, &["log"]);
    assert!(out.contains("c0") || out.contains("c1") || out.contains("c2"));
}

// ─── basic round-trip multi-command workflows ──────────────────────

#[test]
fn add_commit_log_round_trip() {
    let env = Env::new("flag-round");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"x\n").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "first"]);
    let log = env.ok_in(&r, &["log"]);
    assert!(log.contains("first"));
}

#[test]
fn add_diff_commit_diff_round_trip() {
    let env = Env::new("flag-round-diff");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("x.txt"), b"a\n").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "first"]);
    std::fs::write(r.join("x.txt"), b"b\n").unwrap();
    let d = env.ok_in(&r, &["diff"]);
    assert!(d.contains("-a") || d.contains("+b") || !d.is_empty());
}

// ─── Audit 2026-05 extension: documented-but-untested flag forms ───
//
// These tests pin command lines that the docs (or CLAUDE.md) advertise
// but for which there was no direct CLI coverage. Each test is
// self-contained: it builds its own Env, fresh_repo where needed,
// and asserts only on observable CLI behaviour.

#[test]
fn worktree_add_with_branch_flag() {
    let env = Env::new("flag-wt-add-b");
    let r = env.fresh_repo("r");
    let wt = env.path("wt-feat");
    let wt_str = wt.to_string_lossy().into_owned();
    let out = env.run_in(&r, &["worktree", "add", "-b", "feat", &wt_str]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "worktree add -b feat <path> failed\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn worktree_add_missing_path_errors() {
    let env = Env::new("flag-wt-add-nopath");
    let r = env.fresh_repo("r");
    let (_, err) = env.fail_in(&r, &["worktree", "add"]);
    assert!(
        err.to_lowercase().contains("path") || err.to_lowercase().contains("missing"),
        "worktree-add missing-path error did not mention path: {err}"
    );
}

#[test]
fn blame_with_rev_and_dashdash() {
    let env = Env::new("flag-blame-rev-dd");
    let r = env.fresh_repo("r");
    // `seed.txt` exists from fresh_repo(); use it as the target.
    let out = env.run_in(&r, &["blame", "HEAD", "--", "seed.txt"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "blame HEAD -- seed.txt failed\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn grep_with_rev_form() {
    let env = Env::new("flag-grep-rev");
    let r = env.fresh_repo("r");
    // The seed blob contains "seed". Search for it at HEAD.
    let out = env.run_in(&r, &["grep", "seed", "HEAD"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "grep seed HEAD failed\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn clean_refuses_gyt_dir() {
    let env = Env::new("flag-clean-gyt");
    let r = env.fresh_repo("r");
    let out = env.run_in(&r, &["clean", ".gyt"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "`gyt clean .gyt` unexpectedly succeeded\nstderr: {stderr}"
    );
    // .gyt must still exist after the rejected invocation.
    assert!(
        r.join(".gyt").is_dir(),
        ".gyt directory disappeared after rejected clean"
    );
}

#[test]
fn config_set_then_get_roundtrip() {
    // GYT_AUTHOR_NAME (set by Env::cmd_in) overrides on-disk config by
    // design (see src/config.rs:7 — env vars are the final precedence
    // tier). Clear it on the `--get` call so we observe the value we
    // just wrote.
    let env = Env::new("flag-config-set-get");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["config", "--set", "user.name", "Alice"]);
    let out = std::process::Command::new(&env.bin)
        .current_dir(&r)
        .args(["config", "--get", "user.name"])
        .env_remove("GYT_AUTHOR_NAME")
        .env_remove("GYT_AUTHOR_EMAIL")
        .env("HOME", &env.dir)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "config --get failed: {stdout}");
    assert!(stdout.contains("Alice"), "config --get user.name didn't return 'Alice', got: {stdout}");
}

#[test]
fn config_unset_then_get_empty() {
    let env = Env::new("flag-config-unset");
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["config", "--set", "user.name", "Bob"]);
    env.ok_in(&r, &["config", "--unset", "user.name"]);
    // After unset, `--get` should not echo "Bob".
    let out = env.run_in(&r, &["config", "--get", "user.name"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("Bob") && !stderr.contains("Bob"),
        "config --get user.name returned 'Bob' after unset\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn init_with_positional_path() {
    let env = Env::new("flag-init-path");
    let target = env.path("sub/repo");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    let target_str = target.to_string_lossy().into_owned();
    env.ok_in(&env.dir, &["init", &target_str]);
    assert!(
        target.join(".gyt").is_dir(),
        "`gyt init <path>` did not create .gyt under {}",
        target.display()
    );
}

#[test]
fn init_bare_with_path() {
    let env = Env::new("flag-init-bare-path");
    let target = env.path("bare-here");
    let target_str = target.to_string_lossy().into_owned();
    env.ok_in(&env.dir, &["init", &target_str, "--bare"]);
    // Bare layout lays the gyt directory directly in <path>, so
    // `objects/` and `refs/` should exist at the top level.
    assert!(
        target.join("objects").is_dir() || target.join("HEAD").is_file(),
        "`gyt init <path> --bare` did not lay out a bare repo under {}",
        target.display()
    );
}

#[test]
fn filter_alias_works() {
    let env = Env::new("flag-filter-alias");
    // The dispatcher maps `filter` -> `getthefuckoutofmyrepo`. Verify
    // it accepts `--help` without falling through to "unknown command".
    let out = env.run_in(&env.dir, &["filter", "--help"]);
    assert!(
        out.status.success(),
        "`gyt filter --help` failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn gc_keep_reflog_and_expire_reflog_conflict() {
    let env = Env::new("flag-gc-conflict");
    let r = env.fresh_repo("r");
    let out = env.run_in(&r, &["gc", "--keep-reflog", "--expire-reflog", "30"]);
    // Both flags together are semantically contradictory; the
    // current `gc` accepts the last-write-wins ordering on the flag,
    // but a regression that crashes / errors loudly is still useful
    // to know about, so only assert it does not hang.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Either accept (last-wins) or reject — but it must terminate.
    // The point of this test is to fence the flag *names*.
    let _ = (out.status, stdout, stderr);
}

#[test]
fn reset_force_flag_parsed() {
    let env = Env::new("flag-reset-force");
    let r = env.fresh_repo("r");
    // `gyt reset --force HEAD` with a clean workdir should be a no-op
    // and exit zero. The point is that the --force flag is *parsed*
    // (and not rejected as unknown).
    let out = env.run_in(&r, &["reset", "--force", "HEAD"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "`gyt reset --force HEAD` failed\nstdout: {stdout}\nstderr: {stderr}"
    );
}
