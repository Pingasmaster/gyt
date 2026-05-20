// Property/edge tests for src/cmd/cherry_pick.rs.
//
// Covers the post-success cleanup of CHERRY_PICK_HEAD (anomaly #4),
// detached-HEAD picks, and behaviour when picking a commit whose tree
// already matches HEAD's tree.

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

fn head_commit_id(repo: &Path) -> String {
    let head_text = std::fs::read_to_string(repo.join(".gyt").join("HEAD")).unwrap();
    let trimmed = head_text.trim();
    if let Some(rest) = trimmed.strip_prefix("ref: ") {
        let ref_path = repo.join(".gyt").join(rest.trim());
        std::fs::read_to_string(ref_path).unwrap().trim().to_string()
    } else if let Some(rest) = trimmed.strip_prefix("blake3:") {
        rest.trim().to_string()
    } else {
        panic!("unrecognised HEAD: {trimmed:?}");
    }
}

fn read_ref(repo: &Path, ref_name: &str) -> String {
    std::fs::read_to_string(repo.join(".gyt").join(ref_name))
        .unwrap()
        .trim()
        .to_string()
}

fn is_head_detached(repo: &Path) -> bool {
    let head_text = std::fs::read_to_string(repo.join(".gyt").join("HEAD")).unwrap();
    head_text.trim().starts_with("blake3:")
}

#[test]
fn cherry_pick_head_cleaned_up_after_success() {
    // FAILING TEST — code anomaly #4 — will be fixed in Phase C of
    // fan-out-subagents-to-jiggly-lagoon.md
    //
    // src/cmd/cherry_pick.rs writes `.gyt/CHERRY_PICK_HEAD` on the
    // conflict path but nothing removes it after a successful pick.
    // A later `gyt status` (or any operation that checks for an
    // in-progress cherry-pick) is then permanently confused.
    let env = Env::new("cp-head-cleanup");
    let repo = env.fresh_repo("r");

    // Create feature branch with one commit adding feat.txt.
    env.ok_in(&repo, &["switch", "-c", "feature"]);
    std::fs::write(repo.join("feat.txt"), b"feat\n").unwrap();
    env.ok_in(&repo, &["add", "feat.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feat-commit"]);
    let feat_id = read_ref(&repo, "refs/heads/feature");

    // Back to main; cherry-pick the feature commit (disjoint — clean).
    env.ok_in(&repo, &["switch", "main"]);
    env.ok_in(&repo, &["cherry-pick", &feat_id]);

    let cherry_head = repo.join(".gyt").join("CHERRY_PICK_HEAD");
    assert!(
        !cherry_head.exists(),
        "CHERRY_PICK_HEAD must be removed after a successful cherry-pick; \
         found stale state file at {}",
        cherry_head.display()
    );
}

#[test]
fn cherry_pick_detached_head() {
    let env = Env::new("cp-detached");
    let repo = env.fresh_repo("r");

    // Build a feature commit to pick.
    env.ok_in(&repo, &["switch", "-c", "feature"]);
    std::fs::write(repo.join("feat.txt"), b"feat\n").unwrap();
    env.ok_in(&repo, &["add", "feat.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feat-pick-target"]);
    let feat_id = read_ref(&repo, "refs/heads/feature");

    // Advance main with an independent commit so feature's parent !=
    // main's tip. Without this divergence, cherry-picking feature onto
    // main reproduces an identical commit (same tree, same parent, same
    // message, same authors) — the test would then assert that the
    // cherry-pick produced a different oid, which is impossible.
    env.ok_in(&repo, &["switch", "main"]);
    std::fs::write(repo.join("m.txt"), b"m\n").unwrap();
    env.ok_in(&repo, &["add", "m.txt"]);
    env.ok_in(&repo, &["commit", "-m", "main-div"]);
    let main_tip = read_ref(&repo, "refs/heads/main");

    // Detach HEAD by writing the HEAD file directly to the main tip.
    std::fs::write(
        repo.join(".gyt").join("HEAD"),
        format!("blake3:{main_tip}\n"),
    )
    .unwrap();
    assert!(is_head_detached(&repo), "HEAD should now be detached");

    // Cherry-pick onto detached HEAD.
    env.ok_in(&repo, &["cherry-pick", &feat_id]);

    // Workdir got the new file.
    assert!(repo.join("feat.txt").exists(), "feat.txt must land");

    // HEAD must still be detached, now pointing at a new commit.
    assert!(
        is_head_detached(&repo),
        "HEAD must remain detached after cherry-pick",
    );
    let new_head = head_commit_id(&repo);
    assert_ne!(new_head, main_tip, "detached HEAD must advance to a new commit");
    assert_ne!(new_head, feat_id, "new commit is not the picked commit itself");

    // The main branch must NOT have moved.
    let main_after = read_ref(&repo, "refs/heads/main");
    assert_eq!(
        main_after, main_tip,
        "main branch must not advance on a detached-HEAD cherry-pick",
    );
}

#[test]
fn cherry_pick_no_op_commit() {
    // Pin behaviour for picking a commit whose tree is identical to
    // HEAD's tree. The cherry_pick.rs ANCESTRY_LOOKBACK detector
    // rejects picks where some recent ancestor has the same tree AND
    // the same message. We construct that case and assert the pick
    // refuses with the documented error.
    let env = Env::new("cp-noop");
    let repo = env.fresh_repo("r");

    // Add a file and commit (commit A).
    std::fs::write(repo.join("x.txt"), b"x\n").unwrap();
    env.ok_in(&repo, &["add", "x.txt"]);
    env.ok_in(&repo, &["commit", "-m", "added-x"]);
    let commit_a = read_ref(&repo, "refs/heads/main");

    // Now make an unrelated commit B so HEAD differs from A but the
    // ancestry still contains A.
    std::fs::write(repo.join("y.txt"), b"y\n").unwrap();
    env.ok_in(&repo, &["add", "y.txt"]);
    env.ok_in(&repo, &["commit", "-m", "added-y"]);

    // Cherry-picking A would produce the same tree+message as the
    // existing ancestor A — the detector must refuse.
    let (stdout, stderr) = env.fail_in(&repo, &["cherry-pick", &commit_a]);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("already")
            || combined.contains("equivalent")
            || combined.contains("ancestry"),
        "expected refusal mentioning already-applied/equivalent commit; got:\n{combined}",
    );
}
