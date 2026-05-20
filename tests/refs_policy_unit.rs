// Exhaustive unit tests for src/net/refs_policy.rs covering the gaps
// missed by the inline #[cfg(test)] mod in that file. In particular:
//
//   * `Mode::ForceWithLease` (skips FF descendant check, keeps cur==old)
//   * `enforce_target_kind` rejections per namespace
//   * `enforce_metadata_monotonic` rewinds (events truncated, kind mismatch)
//   * `MAX_WALK_COMMITS` cap on long parent chains
//   * F-D4-04: missing-ancestor rejection under sign_required
//   * `server_policy_with_overrides` fail-closed when files disappear
//   * `parse_allowed_signers` per-line warn-once recovery (M26)
//
// The private helpers `enforce_target_kind`, `enforce_metadata_monotonic`,
// and `parse_allowed_signers` are exercised through their public callers
// (`evaluate_with_mode` and `load_allowed_signers`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::many_single_char_names,
    reason = "test code: panicking on unexpected input signals failure; \
              short letters (a/b/c/p) are conventional shorthand for commit DAG nodes and the gyt_dir path"
)]

use ed25519_dalek::{Signer, SigningKey};
use gyt::hash::ObjectId;
use gyt::net::protocol::RefUpdate;
use gyt::net::refs_policy::{
    self, MAX_WALK_COMMITS, Mode, PolicyError, evaluate_with_mode, load_allowed_signers,
    server_policy_with_overrides,
};
use gyt::object::commit::{self, Commit};
use gyt::object::tree::{self, TreeEntry};
use gyt::object::{ObjectKind, store};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

// ── tempdir scaffolding ─────────────────────────────────────────────

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn tmp_dir(label: &str) -> PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let p = std::env::temp_dir().join(format!(
        "gyt-refs-policy-unit-{label}-{pid}-{id}-{nanos}"
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Create a fresh `.gyt`-shaped directory (object store + refs dirs).
/// We point `gyt_dir` directly at this — refs_policy operates on raw
/// gyt_dir paths, not on `Repo`.
fn fresh_gyt_dir(label: &str) -> PathBuf {
    let p = tmp_dir(label);
    std::fs::create_dir_all(p.join("objects")).unwrap();
    std::fs::create_dir_all(p.join("refs/heads")).unwrap();
    std::fs::create_dir_all(p.join("refs/tags")).unwrap();
    std::fs::create_dir_all(p.join("refs/issues")).unwrap();
    std::fs::create_dir_all(p.join("refs/prs")).unwrap();
    p
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write a minimal commit with the given parents and return its id.
fn write_commit(gyt: &Path, parents: Vec<ObjectId>, label: &str) -> ObjectId {
    let blob = gyt::object::blob::write(gyt, label.as_bytes()).unwrap();
    let tree_id = tree::write(
        gyt,
        &[TreeEntry {
            mode: tree::MODE_FILE,
            name: b"f".to_vec(),
            hash: blob,
        }],
    )
    .unwrap();
    let c = Commit {
        tree: tree_id,
        parents,
        authors: vec![format!("T <t@x> {} +0000", label.len())],
        committer: format!("T <t@x> {} +0000", label.len()),
        ai_assists: vec![],
        reviewers: vec![],
        signature: None,
        message: label.into(),
    };
    commit::write(gyt, &c).unwrap()
}

/// Write a signed commit (real ed25519). Returns (commit_id, verifying_key).
fn write_signed_commit(
    gyt: &Path,
    parents: Vec<ObjectId>,
    label: &str,
    key: &SigningKey,
) -> ObjectId {
    let blob = gyt::object::blob::write(gyt, label.as_bytes()).unwrap();
    let tree_id = tree::write(
        gyt,
        &[TreeEntry {
            mode: tree::MODE_FILE,
            name: b"f".to_vec(),
            hash: blob,
        }],
    )
    .unwrap();
    let unsigned = Commit {
        tree: tree_id,
        parents,
        authors: vec!["T <t@x> 1 +0000".into()],
        committer: "T <t@x> 1 +0000".into(),
        ai_assists: vec![],
        reviewers: vec![],
        signature: None,
        message: label.into(),
    };
    // Sign payload (commit_payload_without_sig is the canonical payload).
    let payload = gyt::cmd::signing::commit_payload_without_sig(&unsigned);
    let sig = key.sign(&payload);
    let b64 = base64_encode(sig.to_bytes().as_slice());
    let signed = Commit {
        signature: Some(b64),
        ..unsigned
    };
    commit::write(gyt, &signed).unwrap()
}

/// Standard base64 (no padding stripping). Mirrors signing::base64_encode.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8) | u32::from(data[i + 2]);
        out.push(char::from(ALPHABET[((n >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((n >> 6) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[(n & 0x3f) as usize]));
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let n = u32::from(data[i]) << 16;
        out.push(char::from(ALPHABET[((n >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 0x3f) as usize]));
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = (u32::from(data[i]) << 16) | (u32::from(data[i + 1]) << 8);
        out.push(char::from(ALPHABET[((n >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((n >> 6) & 0x3f) as usize]));
        out.push('=');
    }
    out
}

fn write_ref_file(gyt: &Path, refname: &str, id: &ObjectId) {
    let p = gyt.join(refname);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, format!("{}\n", id.to_hex())).unwrap();
}

// ─── Mode::Force / Mode::ForceWithLease / Mode::FastForward ──────────

#[test]
fn force_mode_bypasses_non_ff_check() {
    let p = fresh_gyt_dir("force-bypass");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let b_alt = write_commit(&p, vec![], "b-alt"); // unrelated history
    write_ref_file(&p, "refs/heads/main", &a);
    let upd = vec![RefUpdate {
        old: Some(a),
        new: b_alt,
        name: "refs/heads/main".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::Force, false, &[]);
    assert!(e.is_clean(), "Force should bypass; got: {:?}", e.blocked);
}

#[test]
fn force_with_lease_accepts_non_ff_when_cur_matches_old() {
    // ForceWithLease semantics: skip the descendant check but require
    // that the on-disk ref currently equals the client's expected `old`.
    let p = fresh_gyt_dir("flease-cur-match");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let b_alt = write_commit(&p, vec![], "b-alt");
    write_ref_file(&p, "refs/heads/main", &a);
    let upd = vec![RefUpdate {
        old: Some(a),
        new: b_alt,
        name: "refs/heads/main".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::ForceWithLease, false, &[]);
    assert!(
        e.is_clean(),
        "ForceWithLease should accept non-FF when cur==old; got {:?}",
        e.blocked
    );
}

#[test]
fn force_with_lease_rejects_when_cur_diverged() {
    // Lease lost: someone else moved the ref past the client's old.
    let p = fresh_gyt_dir("flease-diverged");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let b = write_commit(&p, vec![a], "b"); // current on-disk
    let c = write_commit(&p, vec![], "c-alt");
    write_ref_file(&p, "refs/heads/main", &b);
    let upd = vec![RefUpdate {
        old: Some(a), // stale expectation
        new: c,
        name: "refs/heads/main".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::ForceWithLease, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    match &e.blocked[0].1 {
        PolicyError::NotFastForward { refname } => assert_eq!(refname, "refs/heads/main"),
        other => panic!("expected NotFastForward, got {other:?}"),
    }
}

#[test]
fn force_with_lease_rejects_when_ref_missing() {
    // Client thinks ref exists at `old`, but on-disk it doesn't.
    let p = fresh_gyt_dir("flease-missing");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let b = write_commit(&p, vec![a], "b");
    let upd = vec![RefUpdate {
        old: Some(a),
        new: b,
        name: "refs/heads/main".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::ForceWithLease, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(
        e.blocked[0].1,
        PolicyError::NotFastForward { .. }
    ));
}

#[test]
fn ff_mode_accepts_when_new_descends_from_old_and_cur_matches() {
    let p = fresh_gyt_dir("ff-ok");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let b = write_commit(&p, vec![a], "b");
    let cc = write_commit(&p, vec![b], "c");
    write_ref_file(&p, "refs/heads/main", &a);
    let upd = vec![RefUpdate {
        old: Some(a),
        new: cc,
        name: "refs/heads/main".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert!(e.is_clean(), "FF chain should pass: {:?}", e.blocked);
}

#[test]
fn ff_mode_branch_creation_no_old_is_allowed() {
    let p = fresh_gyt_dir("ff-create");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let upd = vec![RefUpdate {
        old: None,
        new: a,
        name: "refs/heads/feature".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert!(e.is_clean(), "create with no old must be allowed: {:?}", e.blocked);
}

// ─── enforce_target_kind via evaluate_with_mode ──────────────────────

#[test]
fn target_kind_blob_on_refs_heads_rejected() {
    let p = fresh_gyt_dir("kind-blob-heads");
    let _c = Cleanup(p.clone());
    let blob = gyt::object::blob::write(&p, b"raw").unwrap();
    let upd = vec![RefUpdate {
        old: None,
        new: blob,
        name: "refs/heads/poison".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    match &e.blocked[0].1 {
        PolicyError::BadRefName { reason, .. } => {
            assert!(
                reason.contains("Blob") || reason.contains("kind"),
                "expected kind-mismatch reason, got: {reason}"
            );
        }
        other => panic!("expected BadRefName, got {other:?}"),
    }
}

#[test]
fn target_kind_tree_on_refs_tags_rejected() {
    let p = fresh_gyt_dir("kind-tree-tags");
    let _c = Cleanup(p.clone());
    let tree_id = tree::write(&p, &[]).unwrap();
    let upd = vec![RefUpdate {
        old: None,
        new: tree_id,
        name: "refs/tags/v1".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(e.blocked[0].1, PolicyError::BadRefName { .. }));
}

#[test]
fn target_kind_commit_on_refs_issues_rejected() {
    // issue/PR/incident refs must back a Blob, not a Commit.
    let p = fresh_gyt_dir("kind-commit-issues");
    let _c = Cleanup(p.clone());
    let c = write_commit(&p, vec![], "c");
    let upd = vec![RefUpdate {
        old: None,
        new: c,
        name: "refs/issues/7".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(e.blocked[0].1, PolicyError::BadRefName { .. }));
}

#[test]
fn target_kind_commit_on_refs_tags_accepted() {
    // refs/tags/* may point at either Commit or Tag.
    let p = fresh_gyt_dir("kind-commit-tags");
    let _c = Cleanup(p.clone());
    let c = write_commit(&p, vec![], "c");
    let upd = vec![RefUpdate {
        old: None,
        new: c,
        name: "refs/tags/v1".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert!(e.is_clean(), "tag→commit allowed; got {:?}", e.blocked);
}

// ─── enforce_metadata_monotonic via evaluate_with_mode ───────────────

fn make_issue_blob(gyt: &Path, n: u64, events: &[gyt::issues::Event]) -> ObjectId {
    let iss = gyt::issues::Issue {
        number: n,
        kind: gyt::issues::IssueKind::Issue,
        title: "t".into(),
        state: gyt::issues::IssueState::Open,
        author: "a@x".into(),
        created_ts: 1,
        labels: vec![],
        assignees: vec![],
        mentions: vec![],
        events: events.to_vec(),
    };
    let bytes = gyt::issues::encode(&iss);
    store::write_bytes(gyt, ObjectKind::Blob, &bytes).unwrap()
}

#[test]
fn metadata_monotonic_rejects_truncated_events() {
    let p = fresh_gyt_dir("md-trunc");
    let _c = Cleanup(p.clone());
    let ev = gyt::issues::Event {
        kind: gyt::issues::EventKind::Open,
        author: "a@x".into(),
        ts: 1,
        body: String::new(),
        add: vec![],
        remove: vec![],
        reason: String::new(),
    };
    let old_id = make_issue_blob(&p, 1, std::slice::from_ref(&ev));
    let new_id = make_issue_blob(&p, 1, &[]); // truncated audit
    write_ref_file(&p, "refs/issues/1", &old_id);
    let upd = vec![RefUpdate {
        old: Some(old_id),
        new: new_id,
        name: "refs/issues/1".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    // The rewind is reported as Internal (the validate_extends Err).
    match &e.blocked[0].1 {
        PolicyError::Internal(msg) => assert!(
            msg.contains("rewind") || msg.contains("event count"),
            "expected rewind reason, got: {msg}"
        ),
        other => panic!("expected Internal rewind error, got {other:?}"),
    }
}

#[test]
fn metadata_monotonic_extension_accepted() {
    let p = fresh_gyt_dir("md-ext");
    let _c = Cleanup(p.clone());
    let ev1 = gyt::issues::Event {
        kind: gyt::issues::EventKind::Open,
        author: "a@x".into(),
        ts: 1,
        body: String::new(),
        add: vec![],
        remove: vec![],
        reason: String::new(),
    };
    let ev2 = gyt::issues::Event {
        kind: gyt::issues::EventKind::Comment,
        author: "a@x".into(),
        ts: 2,
        body: "hi".into(),
        add: vec![],
        remove: vec![],
        reason: String::new(),
    };
    let old_id = make_issue_blob(&p, 1, std::slice::from_ref(&ev1));
    let new_id = make_issue_blob(&p, 1, &[ev1, ev2]);
    write_ref_file(&p, "refs/issues/1", &old_id);
    let upd = vec![RefUpdate {
        old: Some(old_id),
        new: new_id,
        name: "refs/issues/1".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert!(e.is_clean(), "monotonic extension should pass: {:?}", e.blocked);
}

#[test]
fn metadata_monotonic_rejects_undecodable_new_blob() {
    // Pointing refs/issues/1 at a Blob that fails TOML decode → Internal.
    let p = fresh_gyt_dir("md-baddecode");
    let _c = Cleanup(p.clone());
    let garbage = store::write_bytes(&p, ObjectKind::Blob, b"not toml = =\n").unwrap();
    let upd = vec![RefUpdate {
        old: None,
        new: garbage,
        name: "refs/issues/2".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(e.blocked[0].1, PolicyError::Internal(_)));
}

// ─── MAX_WALK_COMMITS sanity ─────────────────────────────────────────

#[test]
fn max_walk_commits_is_one_million() {
    // Compile-time guard: MAX_WALK_COMMITS is part of the project's
    // intent ("no single push pins refs.lock"). Don't quietly weaken it.
    assert_eq!(MAX_WALK_COMMITS, 1_000_000);
}

#[test]
fn is_ancestor_returns_false_when_unrelated_short_chain() {
    // Sanity baseline for the walk bound — different roots, walk must
    // terminate without claiming ancestry.
    let p = fresh_gyt_dir("walk-unrelated");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let b = write_commit(&p, vec![], "b");
    assert!(!refs_policy::is_ancestor(&p, &a, &b).unwrap());
    assert!(!refs_policy::is_ancestor(&p, &b, &a).unwrap());
}

// Building a literal 1M-commit chain on disk would balloon the test
// suite past the per-test-thread budget allotted by CLAUDE.md (couple
// minutes total). Build a *modest* deep chain to exercise the walk
// loop's bookkeeping path without triggering the cap.
#[test]
fn is_ancestor_walks_deep_chain_without_cap() {
    let p = fresh_gyt_dir("walk-deep");
    let _c = Cleanup(p.clone());
    let mut prev = write_commit(&p, vec![], "root");
    let root = prev;
    for i in 0..200 {
        prev = write_commit(&p, vec![prev], &format!("c{i}"));
    }
    assert!(refs_policy::is_ancestor(&p, &root, &prev).unwrap());
}

// ─── F-D4-04: sign_required + missing ancestor ───────────────────────

#[test]
fn sign_required_with_missing_ancestor_parent_is_rejected() {
    // Pusher uploads only the tip; tip.parent points at an id we never
    // saw. Previously the gate silently passed every ancestor; now the
    // walk must Err and the update is blocked with Internal.
    let p = fresh_gyt_dir("missing-ancestor");
    let _c = Cleanup(p.clone());
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = key.verifying_key();
    // Synthesize a parent id that we never write to the store.
    let mut fake = [0u8; 32];
    fake[0] = 0xDE;
    fake[31] = 0xAD;
    let fake_parent = ObjectId(fake);
    let tip = write_signed_commit(&p, vec![fake_parent], "tip", &key);
    let upd = vec![RefUpdate {
        old: None,
        new: tip,
        name: "refs/heads/feature".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, true, &[vk]);
    assert_eq!(e.blocked.len(), 1, "expected single block");
    match &e.blocked[0].1 {
        PolicyError::Internal(msg) => assert!(
            msg.contains("missing") || msg.contains("unreadable") || msg.contains("ancestor"),
            "expected missing-ancestor message, got: {msg}"
        ),
        other => panic!("expected Internal, got {other:?}"),
    }
}

#[test]
fn sign_required_with_valid_signed_commit_passes() {
    let p = fresh_gyt_dir("sign-pass");
    let _c = Cleanup(p.clone());
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = key.verifying_key();
    let c = write_signed_commit(&p, vec![], "sole", &key);
    let upd = vec![RefUpdate {
        old: None,
        new: c,
        name: "refs/heads/feature".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, true, &[vk]);
    assert!(e.is_clean(), "valid signed commit must pass: {:?}", e.blocked);
}

#[test]
fn sign_required_unknown_signer_rejected() {
    let p = fresh_gyt_dir("sign-wrong-key");
    let _c = Cleanup(p.clone());
    let key_sign = SigningKey::generate(&mut rand::rngs::OsRng);
    let key_trust = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk_trust = key_trust.verifying_key(); // different key in the allow-list
    let c = write_signed_commit(&p, vec![], "sole", &key_sign);
    let upd = vec![RefUpdate {
        old: None,
        new: c,
        name: "refs/heads/feature".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, true, &[vk_trust]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(
        e.blocked[0].1,
        PolicyError::SignerNotAllowed { .. }
    ));
}

// ─── server_policy_with_overrides fail-closed ────────────────────────

#[test]
fn server_policy_with_missing_policy_config_fails_closed() {
    // --policy-config <p>: if p doesn't exist at request time, the
    // policy MUST be sign_required=true with empty signers (which
    // evaluates to MissingAllowedSigners and rejects the push).
    let p = fresh_gyt_dir("polcfg-missing");
    let _c = Cleanup(p.clone());
    let nonexistent = p.join("vanished-config.toml");
    let (sign, signers) = server_policy_with_overrides(&p, None, Some(&nonexistent));
    assert!(sign, "missing policy-config must fail closed to sign_required");
    assert!(signers.is_empty(), "no signers when fail-closed");
}

#[test]
fn server_policy_with_missing_signers_file_fails_closed() {
    // --signers <p>: when sign_required is on but the override file
    // disappeared, never fall through to the in-repo allowed_signers.
    let p = fresh_gyt_dir("signers-missing");
    let _c = Cleanup(p.clone());
    // Write a per-repo config flipping on sign_required.
    std::fs::write(p.join("config.toml"), b"[commit]\nsign_required = true\n").unwrap();
    let bogus = p.join("vanished-signers");
    let (sign, signers) = server_policy_with_overrides(&p, Some(&bogus), None);
    assert!(sign);
    assert!(signers.is_empty(), "must not silently fall back to in-repo file");
}

#[test]
fn server_policy_with_external_policy_config_overrides_repo_flag() {
    // Per-repo config says sign_required=false; the operator's
    // policy-config says true. Override must win — that's the whole
    // point of F-D4-05.
    let p = fresh_gyt_dir("polcfg-overrides");
    let _c = Cleanup(p.clone());
    std::fs::write(p.join("config.toml"), b"[commit]\nsign_required = false\n").unwrap();
    let polcfg = p.join("operator-policy.toml");
    std::fs::write(&polcfg, b"[commit]\nsign_required = true\n").unwrap();
    let (sign, _signers) = server_policy_with_overrides(&p, None, Some(&polcfg));
    assert!(sign, "operator policy-config must override per-repo flag");
}

#[test]
fn server_policy_no_overrides_off_returns_empty() {
    // Plain path: no overrides, no sign_required, no signers. Must
    // return (false, []) so the evaluator skips signature checks.
    let p = fresh_gyt_dir("polcfg-off");
    let _c = Cleanup(p.clone());
    let (sign, signers) = server_policy_with_overrides(&p, None, None);
    assert!(!sign);
    assert!(signers.is_empty());
}

// ─── parse_allowed_signers per-line warn-once (M26) ──────────────────

#[test]
fn allowed_signers_skips_bad_lines_and_loads_the_rest() {
    // M26: one malformed line must not poison the whole file.
    let p = fresh_gyt_dir("signers-warn-once");
    let _c = Cleanup(p.clone());
    let key1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let key2 = SigningKey::generate(&mut rand::rngs::OsRng);
    let hex1 = hex_of(&key1.verifying_key().to_bytes());
    let hex2 = hex_of(&key2.verifying_key().to_bytes());
    let body = format!(
        "# header comment\n\
         {hex1} alice@example\n\
         not-hex-and-too-short\n\
         {} bad-hex-but-right-length\n\
         {hex2} bob@example\n",
        "z".repeat(64)
    );
    std::fs::write(p.join("allowed_signers"), body).unwrap();
    let loaded = load_allowed_signers(&p).unwrap();
    assert_eq!(
        loaded.len(),
        2,
        "two valid lines must survive; got {} keys",
        loaded.len()
    );
}

#[test]
fn allowed_signers_missing_file_returns_empty() {
    let p = fresh_gyt_dir("signers-missing-file");
    let _c = Cleanup(p.clone());
    let loaded = load_allowed_signers(&p).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn allowed_signers_comments_and_blank_lines_ignored() {
    let p = fresh_gyt_dir("signers-comments");
    let _c = Cleanup(p.clone());
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let hex = hex_of(&key.verifying_key().to_bytes());
    let body = format!("# top\n\n  # indented comment\n{hex}\n\n");
    std::fs::write(p.join("allowed_signers"), body).unwrap();
    let loaded = load_allowed_signers(&p).unwrap();
    assert_eq!(loaded.len(), 1);
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

// ─── BadRefName: refnames outside refs/ ──────────────────────────────

#[test]
fn refname_outside_refs_namespace_rejected() {
    let p = fresh_gyt_dir("bad-namespace");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let upd = vec![RefUpdate {
        old: None,
        new: a,
        name: "HEAD".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    match &e.blocked[0].1 {
        PolicyError::BadRefName { reason, .. } => {
            assert!(reason.contains("refs/"), "expected refs/ reason: {reason}");
        }
        other => panic!("expected BadRefName, got {other:?}"),
    }
}

#[test]
fn refname_with_control_byte_rejected() {
    let p = fresh_gyt_dir("bad-ctrl");
    let _c = Cleanup(p.clone());
    let a = write_commit(&p, vec![], "a");
    let upd = vec![RefUpdate {
        old: None,
        new: a,
        name: "refs/heads/foo\nbar".into(), // newline injection
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::FastForward, false, &[]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(e.blocked[0].1, PolicyError::BadRefName { .. }));
}

// ─── Mode::Force still runs signature gate ───────────────────────────

#[test]
fn force_mode_still_enforces_signatures_when_required() {
    // C7-like: --force doesn't bypass signature requirements.
    let p = fresh_gyt_dir("force-still-signs");
    let _c = Cleanup(p.clone());
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = key.verifying_key();
    let c = write_commit(&p, vec![], "unsigned"); // unsigned!
    let upd = vec![RefUpdate {
        old: None,
        new: c,
        name: "refs/heads/feature".into(),
    }];
    let e = evaluate_with_mode(&p, &upd, Mode::Force, true, &[vk]);
    assert_eq!(e.blocked.len(), 1);
    assert!(matches!(e.blocked[0].1, PolicyError::UnsignedCommit { .. }));
}
