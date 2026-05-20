// Rebase lifecycle tests for src/cmd/rebase.rs.
//
// Covers original-author preservation (anomaly #1), abort+restore, and
// continue-after-conflict replay.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::path::Path;
use std::process::Command;

fn cmd_as(env: &Env, cwd: &Path, name: &str, email: &str) -> Command {
    let mut c = env.cmd_in(cwd);
    c.env("GYT_AUTHOR_NAME", name).env("GYT_AUTHOR_EMAIL", email);
    c
}

#[track_caller]
fn ok_as(env: &Env, cwd: &Path, name: &str, email: &str, args: &[&str]) -> String {
    let o = cmd_as(env, cwd, name, email).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "gyt {} failed in {}:\nstdout: {}\nstderr: {}",
        args.join(" "),
        cwd.display(),
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn head_commit_id(repo: &Path) -> String {
    // Read .gyt/HEAD; if symbolic, follow ref file.
    let head_text = std::fs::read_to_string(repo.join(".gyt").join("HEAD")).unwrap();
    let trimmed = head_text.trim();
    if let Some(rest) = trimmed.strip_prefix("ref: ") {
        let ref_path = repo.join(".gyt").join(rest.trim());
        let s = std::fs::read_to_string(ref_path).unwrap();
        s.trim().to_string()
    } else if let Some(rest) = trimmed.strip_prefix("blake3:") {
        rest.trim().to_string()
    } else {
        panic!("unrecognised HEAD: {trimmed:?}");
    }
}

#[test]
fn rebase_preserves_original_author() {
    // FAILING TEST — code anomaly #1 — will be fixed in Phase C of
    // fan-out-subagents-to-jiggly-lagoon.md
    //
    // src/cmd/rebase.rs:244-248 sets `authors: vec![stamped]` from the
    // current rebaser identity, discarding the picked commit's original
    // author. Rebase should preserve "Alice" — instead it overwrites with
    // "Bob" (the rebaser).
    let env = Env::new("rebase-author");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    ok_as(&env, &repo, "Alice", "alice@example.com", &["init"]);

    // Initial commit on main by Alice.
    std::fs::write(repo.join("a.txt"), b"a\n").unwrap();
    ok_as(&env, &repo, "Alice", "alice@example.com", &["add", "a.txt"]);
    ok_as(
        &env,
        &repo,
        "Alice",
        "alice@example.com",
        &["commit", "-m", "main-initial"],
    );

    // Create side branch off main, commit by Alice.
    ok_as(&env, &repo, "Alice", "alice@example.com", &["switch", "-c", "feature"]);
    std::fs::write(repo.join("f.txt"), b"feat\n").unwrap();
    ok_as(&env, &repo, "Alice", "alice@example.com", &["add", "f.txt"]);
    ok_as(
        &env,
        &repo,
        "Alice",
        "alice@example.com",
        &["commit", "-m", "feat-by-alice"],
    );

    // Diverge main.
    ok_as(&env, &repo, "Alice", "alice@example.com", &["switch", "main"]);
    std::fs::write(repo.join("m.txt"), b"m\n").unwrap();
    ok_as(&env, &repo, "Alice", "alice@example.com", &["add", "m.txt"]);
    ok_as(&env, &repo, "Alice", "alice@example.com", &["commit", "-m", "main-div"]);

    // Now switch to feature and rebase onto main as Bob.
    ok_as(&env, &repo, "Bob", "bob@example.com", &["switch", "feature"]);
    ok_as(&env, &repo, "Bob", "bob@example.com", &["rebase", "main"]);

    // Inspect the rebased commit's author via `gyt show HEAD`.
    let out = ok_as(&env, &repo, "Bob", "bob@example.com", &["show", "HEAD"]);
    // `gyt show` formats the commit with `author <name> <email>` and
    // `committer <name> <email>` on separate lines. The author line must
    // remain Alice (rebase preserves authorship); Bob is allowed — and
    // expected — on the committer line (rebaser becomes committer, per
    // git semantics).
    let has_alice_author = out.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("author") && t.contains("Alice") && t.contains("alice@example.com")
    });
    let has_bob_author = out.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("author") && t.contains("Bob") && t.contains("bob@example.com")
    });
    assert!(has_alice_author, "rebase must preserve original author Alice; got:\n{out}");
    assert!(!has_bob_author, "Bob must not have overwritten the author line; got:\n{out}");
}

#[test]
fn rebase_abort_restores_head() {
    let env = Env::new("rebase-abort");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);

    std::fs::write(repo.join("a.txt"), b"line1\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "initial"]);

    // Feature branch modifies a.txt one way.
    env.ok_in(&repo, &["switch", "-c", "feature"]);
    std::fs::write(repo.join("a.txt"), b"feature-line\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feature-change"]);

    // Main modifies a.txt the other way.
    env.ok_in(&repo, &["switch", "main"]);
    std::fs::write(repo.join("a.txt"), b"main-line\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "main-change"]);

    // Capture pre-rebase feature head + workdir state.
    env.ok_in(&repo, &["switch", "feature"]);
    let pre_head = head_commit_id(&repo);
    let pre_workdir = std::fs::read(repo.join("a.txt")).unwrap();

    // Attempt rebase — should conflict.
    let out = env.run_in(&repo, &["rebase", "main"]);
    assert!(!out.status.success(), "expected rebase to conflict");

    let gyt = repo.join(".gyt");
    assert!(gyt.join("REBASE_HEAD").exists(), "REBASE_HEAD should exist mid-rebase");
    assert!(gyt.join("REBASE_TODO").exists(), "REBASE_TODO should exist mid-rebase");
    assert!(gyt.join("REBASE_ONTO").exists(), "REBASE_ONTO should exist mid-rebase");

    // Abort.
    env.ok_in(&repo, &["rebase", "--abort"]);

    // HEAD restored, state files gone, workdir restored.
    let post_head = head_commit_id(&repo);
    assert_eq!(post_head, pre_head, "abort must restore HEAD to pre-rebase tip");
    assert!(!gyt.join("REBASE_HEAD").exists(), "REBASE_HEAD must be removed");
    assert!(!gyt.join("REBASE_TODO").exists(), "REBASE_TODO must be removed");
    assert!(!gyt.join("REBASE_ONTO").exists(), "REBASE_ONTO must be removed");

    let post_workdir = std::fs::read(repo.join("a.txt")).unwrap();
    assert_eq!(
        post_workdir, pre_workdir,
        "workdir contents must match the pre-rebase state",
    );
}

#[test]
fn rebase_continue_replays_remaining() {
    let env = Env::new("rebase-continue");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);

    std::fs::write(repo.join("a.txt"), b"line1\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "initial"]);

    // Feature branch: 3 commits, the FIRST of which conflicts with main.
    env.ok_in(&repo, &["switch", "-c", "feature"]);

    // Feature commit 1: change a.txt — this is the conflicting commit.
    std::fs::write(repo.join("a.txt"), b"feature-c1\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feat-1-conflict"]);

    // Feature commit 2: add disjoint file b.txt.
    std::fs::write(repo.join("b.txt"), b"b-from-feat\n").unwrap();
    env.ok_in(&repo, &["add", "b.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feat-2-disjoint"]);

    // Feature commit 3: add another disjoint file c.txt.
    std::fs::write(repo.join("c.txt"), b"c-from-feat\n").unwrap();
    env.ok_in(&repo, &["add", "c.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feat-3-disjoint"]);

    // Main: change a.txt incompatibly.
    env.ok_in(&repo, &["switch", "main"]);
    std::fs::write(repo.join("a.txt"), b"main-side\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "main-change"]);

    // Rebase feature onto main — should conflict on commit 1.
    env.ok_in(&repo, &["switch", "feature"]);
    let out = env.run_in(&repo, &["rebase", "main"]);
    assert!(!out.status.success(), "expected conflict during rebase");
    assert!(repo.join(".gyt").join("REBASE_TODO").exists());

    // Resolve a.txt and stage.
    std::fs::write(repo.join("a.txt"), b"resolved\n").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);

    // Continue — remaining 2 commits should replay cleanly.
    env.ok_in(&repo, &["rebase", "--continue"]);

    // All three feature files plus the resolved a.txt land on feature.
    assert_eq!(
        std::fs::read(repo.join("a.txt")).unwrap(),
        b"resolved\n",
        "resolved a.txt must persist",
    );
    assert!(repo.join("b.txt").exists(), "feat-2 disjoint file must land");
    assert!(repo.join("c.txt").exists(), "feat-3 disjoint file must land");

    // Rebase state must be gone.
    let gyt = repo.join(".gyt");
    assert!(!gyt.join("REBASE_TODO").exists());
    assert!(!gyt.join("REBASE_HEAD").exists());
    assert!(!gyt.join("REBASE_ONTO").exists());

    // Log shows at least 4 commits on feature (initial + main + 3 replays
    // — exact count depends on whether main's commit is now an ancestor;
    // the replayed commits should produce 3 + the resolved one).
    let log = env.ok_in(&repo, &["log", "--oneline"]);
    let line_count = log.lines().count();
    assert!(
        line_count >= 4,
        "expected at least 4 commits after rebase --continue, got {line_count}:\n{log}"
    );
}
