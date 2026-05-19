// Server-side enforcement of ref-update policy: fast-forward checks and
// commit-signature verification.
//
// Two distinct policies, evaluated for every ref-update batch hitting the
// wire `/refs/update` endpoint:
//
//   1. Fast-forward: unless the client passes `?force=1` AND the server
//      allows it, the new commit must be a descendant of the old commit.
//      Branch creation (no old) is always allowed; tag updates follow the
//      same rule.
//
//   2. Signature: if the server-side repo config has `sign_required = true`,
//      every commit that is new to the repo (reachable from `new` but not
//      from `old`) must carry a valid ed25519 signature verifying against a
//      key listed in `.gyt/allowed_signers`.
//
// The `allowed_signers` file is one entry per line. Each line is a 64-char
// lowercase hex ed25519 public key, optionally followed by whitespace and a
// label (ignored). Blank lines and lines starting with `#` are skipped.

use crate::cmd::signing;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::commit;
use ed25519_dalek::{Verifier, VerifyingKey};
use std::collections::HashSet;
use std::path::Path;

/// Outcome of a policy check.
#[derive(Debug, Clone)]
pub enum PolicyError {
    NotFastForward { refname: String },
    UnsignedCommit { commit: ObjectId },
    BadSignature { commit: ObjectId },
    SignerNotAllowed { commit: ObjectId },
    MissingAllowedSigners,
    /// The refname failed `refs::validate_ref_name` (or wasn't under
    /// the `refs/` namespace gyt accepts over the wire). Closes
    /// F-D1-01 (refname write outside gyt_dir) and F-D1-03 (audit-log
    /// newline injection) at the policy layer.
    BadRefName { refname: String, reason: String },
    Internal(String),
}

impl PolicyError {
    pub fn user_message(&self) -> String {
        match self {
            Self::NotFastForward { refname } => {
                format!("ref {refname}: non-fast-forward update refused (use ?force=1 to override)")
            }
            Self::UnsignedCommit { commit } => {
                format!("commit {} is unsigned but sign_required is set", commit.to_hex())
            }
            Self::BadSignature { commit } => {
                format!("commit {}: signature failed verification", commit.to_hex())
            }
            Self::SignerNotAllowed { commit } => {
                format!(
                    "commit {}: signature did not match any allowed signer",
                    commit.to_hex()
                )
            }
            Self::MissingAllowedSigners => {
                "sign_required is set but .gyt/allowed_signers is missing or empty".to_string()
            }
            Self::BadRefName { refname, reason } => {
                format!("ref name refused: {reason} ({refname:?})")
            }
            Self::Internal(s) => format!("internal policy error: {s}"),
        }
    }
}

/// Hard cap on the number of commits any single FF / signature walk
/// is willing to visit. A pusher who locally builds a 10⁶-commit
/// chain (cheap: one tree, N commits) and pushes it would otherwise
/// trigger an O(N) DFS that pins refs.lock for the duration of the
/// walk, slowing every other pusher and reader behind the lock.
/// 1M is far above any plausible legitimate push (the kernel's git
/// history is ~10⁶ commits TOTAL; a single push delta is orders of
/// magnitude smaller).
pub const MAX_WALK_COMMITS: usize = 1_000_000;

/// Is `ancestor` an ancestor of `descendant` along the parent DAG?
/// Walks all parents (not just first-parent) so merge commits are handled.
/// Returns Ok(true) if reachable, Ok(false) otherwise, Err if a commit can't
/// be read OR if the walk exceeds MAX_WALK_COMMITS (closes F-D4-01).
pub fn is_ancestor(
    gyt_dir: &Path,
    ancestor: &ObjectId,
    descendant: &ObjectId,
) -> Result<bool> {
    if ancestor == descendant {
        return Ok(true);
    }
    let mut stack = vec![*descendant];
    let mut seen = HashSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_WALK_COMMITS {
            return Err(GytError::Repo(format!(
                "commit graph walk exceeded {MAX_WALK_COMMITS} commits"
            )));
        }
        if id == *ancestor {
            return Ok(true);
        }
        // If the commit isn't present, the caller is pushing without the
        // ancestor in our store; we treat that as "not an ancestor".
        let c = match commit::read(gyt_dir, &id) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for p in c.parents {
            stack.push(p);
        }
    }
    Ok(false)
}

/// Walk commits reachable from `new` that are NOT reachable from `old`.
/// Returns the list of new commit ids. If `old` is None, returns every
/// commit reachable from `new`. Bounded by MAX_WALK_COMMITS on both
/// halves (excluded set and new-commits set) — closes F-D4-01.
fn commits_new_since(
    gyt_dir: &Path,
    old: Option<&ObjectId>,
    new: &ObjectId,
) -> Result<Vec<ObjectId>> {
    let mut excluded: HashSet<ObjectId> = HashSet::new();
    if let Some(old_id) = old {
        let mut stack = vec![*old_id];
        while let Some(id) = stack.pop() {
            if !excluded.insert(id) {
                continue;
            }
            if excluded.len() > MAX_WALK_COMMITS {
                return Err(GytError::Repo(format!(
                    "excluded-commit walk exceeded {MAX_WALK_COMMITS} commits"
                )));
            }
            if let Ok(c) = commit::read(gyt_dir, &id) {
                for p in c.parents {
                    stack.push(p);
                }
            }
        }
    }
    // F-D4-04: a missing/unreadable PARENT was previously silent. With
    // sign_required, that meant a pusher who uploaded only the tip
    // commit (with `parent` set to a never-uploaded hash) got the tip
    // signature-checked but every ancestor escaped the gate. We now
    // distinguish two cases:
    //   - the starting `new` itself can't be read: that's OK (it may
    //     be a tag/blob ref; signature enforcement applies only to
    //     commits, so an empty list is correct).
    //   - any commit reached via a parent pointer can't be read:
    //     return Err. The pusher must upload every ancestor or push
    //     fails — no silent gate-bypass.
    // `is_parent_step` tracks whether we got here from a parent
    // pointer or from the initial seed.
    let mut out = Vec::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut stack: Vec<(ObjectId, bool)> = vec![(*new, false)];
    while let Some((id, is_parent_step)) = stack.pop() {
        if excluded.contains(&id) {
            continue;
        }
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_WALK_COMMITS {
            return Err(GytError::Repo(format!(
                "new-commit walk exceeded {MAX_WALK_COMMITS} commits"
            )));
        }
        let c = match commit::read(gyt_dir, &id) {
            Ok(c) => c,
            Err(e) => {
                if is_parent_step {
                    return Err(GytError::Repo(format!(
                        "commit graph references missing or unreadable ancestor {}: {e}",
                        id.to_hex()
                    )));
                }
                // The seed `new` is not a commit (e.g. tag/blob ref).
                // Empty result is correct — signature gate doesn't
                // apply to non-commit refs.
                continue;
            }
        };
        out.push(id);
        for p in c.parents {
            stack.push((p, true));
        }
    }
    Ok(out)
}

/// Load the allowed-signer public keys from `.gyt/allowed_signers`.
/// Returns an empty vec if the file is missing.
pub fn load_allowed_signers(gyt_dir: &Path) -> Result<Vec<VerifyingKey>> {
    let path = gyt_dir.join("allowed_signers");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| GytError::Repo(format!("read allowed_signers: {e}")))?;
    parse_allowed_signers(&text)
}

/// Verify a single commit object: it must have a signature line, the
/// signature must decode, and at least one of `allowed` must verify it.
fn verify_commit_signed(
    gyt_dir: &Path,
    id: &ObjectId,
    allowed: &[VerifyingKey],
) -> std::result::Result<(), PolicyError> {
    let c = commit::read(gyt_dir, id).map_err(|e| PolicyError::Internal(e.to_string()))?;
    let Some(b64) = &c.signature else {
        return Err(PolicyError::UnsignedCommit { commit: *id });
    };
    // Decode the base64 signature using the same strict decoder as
    // `gyt verify`. We re-encode the payload without the signature line to
    // obtain the bytes that were signed.
    let payload = signing::commit_payload_without_sig(&c);
    let sig_bytes = match signing::base64_decode(b64) {
        Some(b) if b.len() == 64 => b,
        _ => return Err(PolicyError::BadSignature { commit: *id }),
    };
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| PolicyError::BadSignature { commit: *id })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    for key in allowed {
        if key.verify(&payload, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(PolicyError::SignerNotAllowed { commit: *id })
}


/// Result of evaluating a ref-update batch against server policy.
pub struct PolicyEvaluation {
    pub blocked: Vec<(String, PolicyError)>,
}

impl PolicyEvaluation {
    pub const fn is_clean(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// What kind of update authorization the client requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Default: strict fast-forward (`new` must descend from `old` AND the
    /// on-disk ref must currently match `old`).
    FastForward,
    /// Lease semantics: skip the FF descendant check but keep the "current
    /// ref must equal the client's expected `old`" check. The client passes
    /// its local cached refs/remotes/... value as `old`; if the remote has
    /// moved beyond it, the push is rejected.
    ForceWithLease,
    /// Unconditional force: bypass both checks. Use sparingly.
    Force,
}

/// Check a list of ref updates against the configured server policy.
/// Convenience wrapper that converts a bool to a Mode. Existing callers
/// (tests) keep working.
pub fn evaluate(
    gyt_dir: &Path,
    updates: &[crate::net::protocol::RefUpdate],
    force: bool,
    sign_required: bool,
    allowed_signers: &[VerifyingKey],
) -> PolicyEvaluation {
    let mode = if force { Mode::Force } else { Mode::FastForward };
    evaluate_with_mode(gyt_dir, updates, mode, sign_required, allowed_signers)
}

/// Like `evaluate`, but lets the caller request `ForceWithLease` (the new
/// mode that splits the bool into two more useful flavors).
pub fn evaluate_with_mode(
    gyt_dir: &Path,
    updates: &[crate::net::protocol::RefUpdate],
    mode: Mode,
    sign_required: bool,
    allowed_signers: &[VerifyingKey],
) -> PolicyEvaluation {
    let mut blocked = Vec::new();

    for u in updates {
        // Gate every refname through the same validator the on-disk
        // writer uses, BEFORE any code path joins it onto gyt_dir.
        // Closes F-D1-01 (path traversal via refname) and F-D1-03
        // (audit-log newline injection) at the policy layer — neither
        // the FF check nor the on-disk write ever sees an unsafe
        // name. We also require that wire-side updates land under
        // `refs/`: HEAD and other top-level files are not pushable.
        if let Err(e) = crate::refs::validate_ref_name(&u.name) {
            blocked.push((
                u.name.clone(),
                PolicyError::BadRefName {
                    refname: u.name.clone(),
                    reason: e.to_string(),
                },
            ));
            continue;
        }
        if !u.name.starts_with("refs/") {
            blocked.push((
                u.name.clone(),
                PolicyError::BadRefName {
                    refname: u.name.clone(),
                    reason: "must begin with refs/".into(),
                },
            ));
            continue;
        }
        // C4: type-check the new ref's target object kind before any
        // FF logic. Previously a create-mode update (`u.old == None`)
        // could point `refs/heads/poison` at a blob — every future
        // reader then errored `commit::read` on the blob. Persistent
        // DoS on `refs/heads/*` from any rw client.
        if let Err(e) = enforce_target_kind(gyt_dir, &u.name, &u.new) {
            blocked.push((u.name.clone(), e));
            continue;
        }
        // B10: read the on-disk current value ONCE per update and use
        // that as the "old" for both the metadata-monotonic gate AND
        // the signature gate. Previously both paths trusted the
        // client-supplied `u.old`. Two real attacks closed by this:
        //   1. Under Mode::Force the FF gate is skipped, so the
        //      client could pass `u.old == u.new`. `commits_new_since`
        //      then seeded the excluded set with `new` itself, made
        //      the new-commits list empty, and the signature loop
        //      iterated nothing — every commit landed unsigned.
        //   2. For metadata refs (refs/issues/*, refs/prs/*,
        //      refs/incidents/*) the FF gate is bypassed entirely.
        //      A client could pass a bogus `u.old` id; the read in
        //      enforce_metadata_monotonic failed and returned Ok(()),
        //      letting the pusher truncate the events array.
        let cur_on_disk = read_ref(gyt_dir, &u.name).unwrap_or_default();
        // F-D8-01 / C3: issue/PR refs back blob objects (canonical
        // TOML), not commits. Skip the commit-DAG FF gate. Enforce
        // the monotonic-append invariant here: an rw client can
        // otherwise upload a blob with `events = []` and silently
        // erase the whole audit trail.
        let is_metadata_ref = u.name.starts_with("refs/issues/")
            || u.name.starts_with("refs/prs/")
            || u.name.starts_with("refs/incidents/");
        if is_metadata_ref {
            if let Err(e) = enforce_metadata_monotonic(gyt_dir, &u.name, cur_on_disk.as_ref(), &u.new) {
                blocked.push((u.name.clone(), e));
            }
            continue;
        }
        // Three modes have three different gate combinations. We always
        // run signature verification at the end if `sign_required`.
        let force = mode == Mode::Force;
        let with_lease = mode == Mode::ForceWithLease;
        if !force && let Some(old) = u.old {
            // Compare client-supplied old against the on-disk value; if
            // it doesn't exist or doesn't match, the client is racing.
            match cur_on_disk {
                None => {
                    blocked.push((
                        u.name.clone(),
                        PolicyError::NotFastForward {
                            refname: u.name.clone(),
                        },
                    ));
                    continue;
                }
                Some(actual) if actual != old => {
                    blocked.push((
                        u.name.clone(),
                        PolicyError::NotFastForward {
                            refname: u.name.clone(),
                        },
                    ));
                    continue;
                }
                Some(_) => {}
            }
            // True FF: new must descend from old. ForceWithLease skips
            // this check (the point of a lease is to allow rewinds /
            // rewrites as long as nobody else moved the ref first).
            if !with_lease {
                match is_ancestor(gyt_dir, &old, &u.new) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        blocked.push((
                            u.name.clone(),
                            PolicyError::NotFastForward {
                                refname: u.name.clone(),
                            },
                        ));
                        continue;
                    }
                }
            }
        }

        // Signature check for new commits brought in by this update.
        // B10: use the on-disk old, not u.old — under Mode::Force, a
        // pusher claiming u.old == u.new would otherwise zero out the
        // new-commit set and bypass the signature loop entirely.
        if sign_required {
            if allowed_signers.is_empty() {
                blocked.push((u.name.clone(), PolicyError::MissingAllowedSigners));
                continue;
            }
            let new_commits = match commits_new_since(gyt_dir, cur_on_disk.as_ref(), &u.new) {
                Ok(c) => c,
                Err(e) => {
                    blocked.push((u.name.clone(), PolicyError::Internal(e.to_string())));
                    continue;
                }
            };
            for id in &new_commits {
                if let Err(err) = verify_commit_signed(gyt_dir, id, allowed_signers) {
                    blocked.push((u.name.clone(), err));
                    break;
                }
            }
        }
    }

    PolicyEvaluation { blocked }
}

/// C4: refuse a ref-update whose target object kind doesn't match the
/// ref's namespace. `refs/heads/*` and `refs/remotes/*` must point at
/// a Commit; `refs/tags/*` may point at Commit or Tag; `refs/issues/*`
/// and `refs/prs/*` must point at a Blob. The new id MUST be present
/// in the local object store (the wire push completed before we got
/// here) — otherwise the FF logic can't run anyway.
fn enforce_target_kind(
    gyt_dir: &Path,
    refname: &str,
    new_id: &ObjectId,
) -> std::result::Result<(), PolicyError> {
    use crate::object::ObjectKind;
    // null-id is the "delete this ref" sentinel.
    if new_id.0.iter().all(|&b| b == 0) {
        return Ok(());
    }
    let obj = match crate::object::store::read(gyt_dir, new_id) {
        Ok(o) => o,
        Err(_) => {
            return Err(PolicyError::BadRefName {
                refname: refname.into(),
                reason: format!("target object {new_id} not present"),
            });
        }
    };
    let ok = if refname.starts_with("refs/heads/")
        || refname.starts_with("refs/remotes/")
    {
        obj.kind == ObjectKind::Commit
    } else if refname.starts_with("refs/tags/") {
        obj.kind == ObjectKind::Commit || obj.kind == ObjectKind::Tag
    } else if refname.starts_with("refs/issues/")
        || refname.starts_with("refs/prs/")
        || refname.starts_with("refs/incidents/")
    {
        obj.kind == ObjectKind::Blob
    } else {
        // Other refs/ namespaces are server-controlled; require Commit
        // by default (e.g. refs/stash). is_user_visible_ref already
        // limits what reaches the wire.
        obj.kind == ObjectKind::Commit
    };
    if !ok {
        return Err(PolicyError::BadRefName {
            refname: refname.into(),
            reason: format!(
                "wrong target kind {:?} for namespace",
                obj.kind
            ),
        });
    }
    Ok(())
}

/// C3 / F-D8-02: enforce the monotonic-append invariant on
/// `refs/issues/<N>` and `refs/prs/<N>` updates. The old blob (if any)
/// must decode as the matching kind, the new blob must decode, and
/// `new` must be a legitimate extension of `old` per the per-kind
/// `validate_extends` helper.
fn enforce_metadata_monotonic(
    gyt_dir: &Path,
    refname: &str,
    old_id: Option<&ObjectId>,
    new_id: &ObjectId,
) -> std::result::Result<(), PolicyError> {
    // Delete: null new id is the "drop this ref" path; no extension check.
    if new_id.0.iter().all(|&b| b == 0) {
        return Ok(());
    }
    // Read new blob.
    let new_obj = match crate::object::store::read(gyt_dir, new_id) {
        Ok(o) => o,
        Err(e) => {
            return Err(PolicyError::Internal(format!(
                "read new metadata blob: {e}"
            )));
        }
    };
    // B10: `old_id` is now the on-disk current ref id (read by the
    // caller via read_ref), not a client-supplied value. If the blob
    // it names cannot be read, the object store is internally
    // inconsistent — refuse the push rather than fall through to
    // create-mode (which would let the new blob land without any
    // extension check, indistinguishable from genuine first-write).
    if refname.starts_with("refs/issues/") {
        let new_iss = crate::issues::decode(&new_obj.payload)
            .map_err(|e| PolicyError::Internal(format!("decode new issue: {e}")))?;
        if let Some(oid) = old_id {
            let old_obj = crate::object::store::read(gyt_dir, oid).map_err(|e| {
                PolicyError::Internal(format!(
                    "on-disk old metadata blob {} unreadable: {e}",
                    oid.to_hex()
                ))
            })?;
            let old_iss = crate::issues::decode(&old_obj.payload)
                .map_err(|e| PolicyError::Internal(format!("decode old issue: {e}")))?;
            crate::issues::validate_extends(&old_iss, &new_iss)
                .map_err(|e| PolicyError::Internal(e.to_string()))?;
        }
    } else if refname.starts_with("refs/prs/") {
        let new_pr = crate::prs::decode(&new_obj.payload)
            .map_err(|e| PolicyError::Internal(format!("decode new pr: {e}")))?;
        if let Some(oid) = old_id {
            let old_obj = crate::object::store::read(gyt_dir, oid).map_err(|e| {
                PolicyError::Internal(format!(
                    "on-disk old metadata blob {} unreadable: {e}",
                    oid.to_hex()
                ))
            })?;
            let old_pr = crate::prs::decode(&old_obj.payload)
                .map_err(|e| PolicyError::Internal(format!("decode old pr: {e}")))?;
            crate::prs::validate_extends(&old_pr, &new_pr)
                .map_err(|e| PolicyError::Internal(e.to_string()))?;
        }
    } else if refname.starts_with("refs/incidents/") {
        let new_inc = crate::incidents::decode(&new_obj.payload)
            .map_err(|e| PolicyError::Internal(format!("decode new incident: {e}")))?;
        if let Some(oid) = old_id {
            let old_obj = crate::object::store::read(gyt_dir, oid).map_err(|e| {
                PolicyError::Internal(format!(
                    "on-disk old metadata blob {} unreadable: {e}",
                    oid.to_hex()
                ))
            })?;
            let old_inc = crate::incidents::decode(&old_obj.payload)
                .map_err(|e| PolicyError::Internal(format!("decode old incident: {e}")))?;
            crate::incidents::validate_extends(&old_inc, &new_inc)
                .map_err(|e| PolicyError::Internal(e.to_string()))?;
        }
    }
    Ok(())
}

fn read_ref(gyt_dir: &Path, refname: &str) -> std::io::Result<Option<ObjectId>> {
    // L21: delegate to crate::refs::read_ref so any future loose-vs-
    // packed handling change in one place is automatically picked up
    // here. Map the GytError into io::Result<Option<...>> for the
    // existing call sites.
    match crate::refs::read_ref(gyt_dir, refname) {
        Ok(id) => Ok(Some(id)),
        Err(crate::errors::GytError::Refs(_)) => Ok(None),
        Err(crate::errors::GytError::Io(e)) => Err(e),
        Err(e) => Err(std::io::Error::other(e.to_string())),
    }
}

/// Convenience: read sign_required from a repo's config without going
/// through the full Repo opener (server runs on raw gyt_dir paths).
pub fn read_sign_required(gyt_dir: &Path) -> bool {
    let path = gyt_dir.join("config.toml");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    crate::config::parse(&bytes)
        .is_ok_and(|c| c.sign_required)
}

/// Wrapper: load both the sign_required flag and allowed signers in one go.
pub fn server_policy(gyt_dir: &Path) -> (bool, Vec<VerifyingKey>) {
    server_policy_with_override(gyt_dir, None)
}

/// Same as `server_policy`, but if `override_signers` points at an
/// existing file the allowed signers come from there instead of the
/// per-repo `<gyt>/allowed_signers`. This is the recommended deployment:
/// keep the trust file *outside* the repo so a pusher with write access
/// cannot extend trust by editing the file and pushing.
pub fn server_policy_with_override(
    gyt_dir: &Path,
    override_signers: Option<&Path>,
) -> (bool, Vec<VerifyingKey>) {
    server_policy_with_overrides(gyt_dir, override_signers, None)
}

/// Same as `server_policy_with_override`, but also accepts a
/// `policy_config` path. When given, `[commit].sign_required` from that
/// file overrides the per-repo value — closing the bootstrap hole where
/// a pusher with write access to `.gyt/config.toml` could flip the flag
/// off and skip signature enforcement for their own next push.
pub fn server_policy_with_overrides(
    gyt_dir: &Path,
    override_signers: Option<&Path>,
    policy_config: Option<&Path>,
) -> (bool, Vec<VerifyingKey>) {
    // F-D4-05: if --policy-config is configured, never fall through to
    // the per-repo flag. If the file is unreadable / parse-fails at
    // request time (was OK at startup), conservatively fail closed —
    // sign_required = true with an empty allowed list, which evaluates
    // to MissingAllowedSigners and rejects the push. Falling back to
    // the per-repo flag would let a pusher with write access flip the
    // flag off, defeating the override.
    let sign_required = if let Some(p) = policy_config {
        if !p.exists() {
            // File vanished between startup and request: fail closed.
            return (true, Vec::new());
        }
        read_sign_required_from(p)
    } else {
        read_sign_required(gyt_dir)
    };
    if !sign_required {
        return (false, Vec::new());
    }
    // F-D4-05: if --signers is configured, the override path is the
    // ONLY source of trust. Never silently fall back to the in-repo
    // .gyt/allowed_signers — that's the file a pusher could edit to
    // bootstrap their own key. If the override file vanished or fails
    // to load at request time, return an empty allowed list so the
    // policy evaluator emits MissingAllowedSigners and rejects.
    let allowed = if let Some(p) = override_signers {
        if !p.exists() {
            return (true, Vec::new());
        }
        load_allowed_signers_at(p).unwrap_or_default()
    } else {
        load_allowed_signers(gyt_dir).unwrap_or_default()
    };
    (true, allowed)
}

/// Read `[commit].sign_required` from an arbitrary file path. Same TOML
/// subset as the per-repo config; missing/unreadable files imply `false`.
fn read_sign_required_from(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    crate::config::parse(&bytes).is_ok_and(|c| c.sign_required)
}

/// Load allowed-signer public keys from an arbitrary file path. Used by
/// the server-wide `--signers <file>` override; same format as the
/// in-repo file (one hex pubkey per line, `#`-comments allowed).
fn load_allowed_signers_at(path: &Path) -> Result<Vec<VerifyingKey>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| GytError::Repo(format!("read allowed_signers {}: {e}", path.display())))?;
    parse_allowed_signers(&text)
}

fn parse_allowed_signers(text: &str) -> Result<Vec<VerifyingKey>> {
    let mut out = Vec::new();
    // M26: skip individual bad lines (with a warn-once stderr message)
    // instead of failing the whole file. Previously, one malformed
    // line returned Err for the whole file → `unwrap_or_default()` at
    // the call site → empty allowed list → every signed push failed
    // silently with MissingAllowedSigners. Operator had no signal
    // that their file was malformed.
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let hex_part = line.split_whitespace().next().unwrap_or("");
        if hex_part.len() != 64 {
            audit_warn_once(&format!(
                "allowed_signers line {}: expected 64 hex chars, got {}; skipping",
                i + 1,
                hex_part.len()
            ));
            continue;
        }
        let mut bytes = [0u8; 32];
        let mut ok = true;
        for (j, b) in bytes.iter_mut().enumerate() {
            let pair = match hex_part.get(j * 2..j * 2 + 2) {
                Some(p) => p,
                None => {
                    ok = false;
                    break;
                }
            };
            match u8::from_str_radix(pair, 16) {
                Ok(v) => *b = v,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            audit_warn_once(&format!(
                "allowed_signers line {}: bad hex; skipping",
                i + 1
            ));
            continue;
        }
        match VerifyingKey::from_bytes(&bytes) {
            Ok(vk) => out.push(vk),
            Err(e) => audit_warn_once(&format!(
                "allowed_signers line {}: {e}; skipping",
                i + 1
            )),
        }
    }
    Ok(out)
}

/// Maximum size of the active `.gyt/audit.log` before rotation (8 MiB).
const AUDIT_LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Number of rotated generations to keep (`audit.log.1` .. `audit.log.5`).
/// At 8 MiB each, the on-disk audit footprint is bounded by ~48 MiB
/// (active log + 5 rotated). Older rotations are discarded.
const AUDIT_LOG_KEEP: usize = 5;

/// Single global mutex protecting the rotation sequence. Two threads
/// crossing the size threshold concurrently must not interleave the
/// descending-rename loop — that would clobber a generation. Process
/// granularity is enough because each server process owns its own
/// `<gyt>/audit.log`; cross-process locking would need a file lock and
/// we don't run two servers against the same audit log.
static AUDIT_ROTATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Append an entry to `<gyt>/audit.log` describing a successful ref update.
///
/// Audit is advisory — failures don't abort the ref update — but a
/// silent drop has burned operators before (disk full not noticed
/// until much later when an investigation can't find evidence of who
/// did what). We surface every distinct failure on stderr exactly once
/// per process so log spam doesn't flood the operator's terminal but
/// the first failure is impossible to miss.
///
/// Rotation: when the active log crosses `AUDIT_LOG_MAX_BYTES` we rename
/// `audit.log.{N-1} -> audit.log.N` down through `.1`, then rotate the
/// active file to `.1` and start a fresh `audit.log`. `audit.log.5`'s
/// rename to `.6` overwrites nothing; the oldest entries simply fall off.
pub fn append_audit(
    gyt_dir: &Path,
    update: &crate::net::protocol::RefUpdate,
    actor: Option<&str>,
) {
    use std::io::Write as _;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let actor_str = actor.unwrap_or("-");
    let old_hex = update
        .old.map_or_else(|| "0".repeat(64), super::super::hash::ObjectId::to_hex);
    let line = format!(
        "{ts}\t{actor_str}\t{}\t{}\t{}\n",
        old_hex,
        update.new.to_hex(),
        update.name
    );
    let path = gyt_dir.join("audit.log");
    rotate_audit_if_needed(gyt_dir, &path);
    let res = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = res {
        audit_warn_once(&format!("audit.log write failed: {e}"));
    }
}

/// Process-wide warn-once cache so repeated audit failures (the common
/// case once a disk fills) don't drown the operator in identical lines.
///
/// `LazyLock<Mutex<HashSet>>` is the modern stdlib pattern (stable in
/// 1.80) — it replaces the previous `Mutex<Option<HashSet>>` +
/// `get_or_insert_with()` dance. Same semantics, one fewer indirection
/// on every call, no `Option::None` to handle.
fn audit_warn_once(msg: &str) {
    use std::sync::{LazyLock, Mutex};
    static SEEN: LazyLock<Mutex<std::collections::HashSet<String>>> =
        LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
    let unseen = SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(msg.to_string());
    if unseen {
        eprintln!("gyt audit: {msg}");
    }
}

/// If `audit.log` exists, is a regular file, and exceeds the size
/// threshold, rotate it. Best-effort: any rename failure aborts the
/// rotation; the next call will retry. We never panic and never block
/// on disk I/O for long.
///
/// Concurrency: serialized via TWO locks. AUDIT_ROTATE_LOCK is the
/// in-process mutex that's been here since the audit-log was added.
/// `audit-rotate.lock` (a `FileLock`) is the cross-process guard
/// needed once multiple `gyt serve` processes can share a repos_root
/// (SO_REUSEPORT + `--allow-multiprocess`). Without the file lock,
/// two processes passing the threshold simultaneously would
/// interleave the descending-rename loop and lose one generation per
/// race; worse, with the same generation under two names you could
/// duplicate audit content across rotated files.
///
/// Symlink safety: `symlink_metadata` does *not* follow symlinks, so a
/// local attacker who has replaced `audit.log` with a symlink can't
/// trick the rename into clobbering a file elsewhere — we refuse to
/// rotate anything that isn't a plain regular file.
fn rotate_audit_if_needed(gyt_dir: &Path, path: &Path) {
    let _guard = AUDIT_ROTATE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Cross-process: take the file lock for the rotation. Tight
    // timeout because rotation is fast; if another process is mid-
    // rotate we just bail and let the next append retry.
    // L22: 500 ms is too tight on contended NFS — the rotation would
    // silently fail, the log would grow past AUDIT_LOG_MAX_BYTES, and
    // subsequent appends would keep colliding. 5 s gives realistic
    // NFS retransmits a chance to land.
    let _file_lock = match crate::fs_util::FileLock::acquire(
        &gyt_dir.join("audit-rotate.lock"),
        std::time::Duration::from_secs(5),
    ) {
        Ok(l) => l,
        Err(_) => return,
    };
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.file_type().is_file() {
        // Symlink, fifo, etc. Refuse to operate.
        return;
    }
    if meta.len() < AUDIT_LOG_MAX_BYTES {
        return;
    }
    let slot = |n: usize| gyt_dir.join(format!("audit.log.{n}"));
    // Drop the oldest, then shift each generation down by one. The
    // descending order matters: we must vacate slot N+1 before renaming
    // slot N into it.
    let _ = std::fs::remove_file(slot(AUDIT_LOG_KEEP));
    for n in (1..AUDIT_LOG_KEEP).rev() {
        let from = slot(n);
        let to = slot(n + 1);
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }
    let _ = std::fs::rename(path, slot(1));
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::object::commit;
    use crate::object::tree;

    fn make_commit(repo: &crate::repo::Repo, parents: Vec<ObjectId>, msg: &str) -> ObjectId {
        let blob = crate::object::blob::write(&repo.gyt_dir, msg.as_bytes()).unwrap();
        let tree_id = tree::write(
            &repo.gyt_dir,
            &[tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"f".to_vec(),
                hash: blob,
            }],
        )
        .unwrap();
        let c = commit::Commit {
            tree: tree_id,
            parents,
            authors: vec!["T <t@x> 1 +0000".into()],
            committer: "T <t@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: msg.into(),
        };
        commit::write(&repo.gyt_dir, &c).unwrap()
    }

    #[test]
    fn is_ancestor_finds_parent_chain() {
        let r = TestRepo::new("gyt-policy-anc");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        let b = make_commit(&repo, vec![a], "b");
        let c = make_commit(&repo, vec![b], "c");
        assert!(is_ancestor(&repo.gyt_dir, &a, &c).unwrap());
        assert!(!is_ancestor(&repo.gyt_dir, &c, &a).unwrap());
    }

    #[test]
    #[expect(clippy::many_single_char_names, reason = "single-letter names are conventional shorthand in this algorithm")] // Reason: a/b/c/m are the conventional letters for a merge DAG (parent, sibling, sibling, merge); renaming would obscure the test's intent.
    fn is_ancestor_handles_merge_parents() {
        let r = TestRepo::new("gyt-policy-merge-anc");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        let b = make_commit(&repo, vec![a], "b");
        let c = make_commit(&repo, vec![a], "c");
        let m = make_commit(&repo, vec![b, c], "m");
        assert!(is_ancestor(&repo.gyt_dir, &b, &m).unwrap());
        assert!(is_ancestor(&repo.gyt_dir, &c, &m).unwrap());
    }

    #[test]
    fn commits_new_since_excludes_old() {
        let r = TestRepo::new("gyt-policy-newsince");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        let b = make_commit(&repo, vec![a], "b");
        let c = make_commit(&repo, vec![b], "c");
        let new = commits_new_since(&repo.gyt_dir, Some(&a), &c).unwrap();
        let set: HashSet<ObjectId> = new.into_iter().collect();
        assert!(set.contains(&b));
        assert!(set.contains(&c));
        assert!(!set.contains(&a));
    }

    #[test]
    fn evaluate_rejects_non_ff() {
        let r = TestRepo::new("gyt-policy-noff");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        let b_alt = make_commit(&repo, vec![], "b-alt");
        // Pretend `refs/heads/main` is at `a` on disk:
        std::fs::create_dir_all(repo.gyt_dir.join("refs/heads")).unwrap();
        std::fs::write(
            repo.gyt_dir.join("refs/heads/main"),
            format!("{}\n", a.to_hex()),
        )
        .unwrap();
        let upd = vec![crate::net::protocol::RefUpdate {
            old: Some(a),
            new: b_alt,
            name: "refs/heads/main".into(),
        }];
        let e = evaluate(&repo.gyt_dir, &upd, false, false, &[]);
        assert_eq!(e.blocked.len(), 1);
        match &e.blocked[0].1 {
            PolicyError::NotFastForward { refname } => assert_eq!(refname, "refs/heads/main"),
            other => panic!("expected NotFastForward, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_ff_passes() {
        let r = TestRepo::new("gyt-policy-ff");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        let b = make_commit(&repo, vec![a], "b");
        std::fs::create_dir_all(repo.gyt_dir.join("refs/heads")).unwrap();
        std::fs::write(
            repo.gyt_dir.join("refs/heads/main"),
            format!("{}\n", a.to_hex()),
        )
        .unwrap();
        let upd = vec![crate::net::protocol::RefUpdate {
            old: Some(a),
            new: b,
            name: "refs/heads/main".into(),
        }];
        let e = evaluate(&repo.gyt_dir, &upd, false, false, &[]);
        assert!(e.is_clean(), "blocked: {:?}", e.blocked);
    }

    #[test]
    fn evaluate_signature_required_blocks_unsigned() {
        let r = TestRepo::new("gyt-policy-unsigned");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        // Stub a key — verification will fail (no signature) but we need a
        // non-empty allowed set to differentiate from MissingAllowedSigners.
        let keys = vec![VerifyingKey::from_bytes(&[0u8; 32]).unwrap_or_else(|_| {
            // Generate a real key for testing
            let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            sk.verifying_key()
        })];
        let upd = vec![crate::net::protocol::RefUpdate {
            old: None,
            new: a,
            name: "refs/heads/feature".into(),
        }];
        let e = evaluate(&repo.gyt_dir, &upd, false, true, &keys);
        assert!(!e.is_clean());
        match &e.blocked[0].1 {
            PolicyError::UnsignedCommit { .. } => {}
            other => panic!("expected UnsignedCommit, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_signature_required_no_signers_fails() {
        let r = TestRepo::new("gyt-policy-nosigners");
        let repo = r.open();
        let a = make_commit(&repo, vec![], "a");
        let upd = vec![crate::net::protocol::RefUpdate {
            old: None,
            new: a,
            name: "refs/heads/feature".into(),
        }];
        let e = evaluate(&repo.gyt_dir, &upd, false, true, &[]);
        assert!(matches!(
            e.blocked[0].1,
            PolicyError::MissingAllowedSigners
        ));
    }

    /// B10 regression: under Mode::Force the signature gate must use
    /// the on-disk current ref, not the client-supplied `u.old`. If
    /// it trusted `u.old`, a pusher could set `u.old == u.new` to
    /// make `commits_new_since` return an empty list, and every
    /// commit in the force-push would land unsigned despite
    /// `sign_required = true`.
    #[test]
    fn evaluate_force_mode_signature_uses_on_disk_old_not_client_old() {
        let r = TestRepo::new("gyt-policy-force-sig-bypass");
        let repo = r.open();
        // Establish an existing ref on disk pointing at `a`.
        let a = make_commit(&repo, vec![], "a");
        let b = make_commit(&repo, vec![a], "b"); // unsigned descendant
        std::fs::create_dir_all(repo.gyt_dir.join("refs/heads")).unwrap();
        std::fs::write(
            repo.gyt_dir.join("refs/heads/main"),
            format!("{}\n", a.to_hex()),
        )
        .unwrap();
        // Need a non-empty allowed-signers set so we distinguish a
        // bypass (PASS, len=0) from MissingAllowedSigners.
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let keys = vec![sk.verifying_key()];
        // Attacker claims old=new=b. Under the previous logic, that
        // would make excluded={b,…parents…} and new_commits=[], so the
        // signature loop ran on nothing and accepted the push. Now we
        // use the on-disk cur (=a) as the basis, so new_commits=[b]
        // and the unsigned-commit gate fires.
        let upd = vec![crate::net::protocol::RefUpdate {
            old: Some(b),
            new: b,
            name: "refs/heads/main".into(),
        }];
        let e = evaluate_with_mode(&repo.gyt_dir, &upd, Mode::Force, true, &keys);
        assert!(!e.is_clean(), "Force-mode signature bypass: blocked={:?}", e.blocked);
        assert!(
            matches!(e.blocked[0].1, PolicyError::UnsignedCommit { .. }),
            "expected UnsignedCommit, got {:?}",
            e.blocked[0].1
        );
    }

    /// B10 regression: enforce_metadata_monotonic now uses the on-disk
    /// current ref as `old`, not the client-supplied `u.old`. Without
    /// this, an rw client could provide a bogus old_id whose read
    /// failed, causing the previous code to return Ok(()) and let an
    /// arbitrary new blob bypass `validate_extends` (e.g. truncating
    /// the events array).
    #[test]
    fn evaluate_metadata_uses_on_disk_old_not_client_old() {
        use crate::issues::{Event, EventKind, Issue, IssueKind, IssueState};
        let r = TestRepo::new("gyt-policy-meta-bypass");
        let repo = r.open();
        let mut iss = Issue {
            number: 1,
            kind: IssueKind::Issue,
            title: "x".into(),
            state: IssueState::Open,
            author: "a".into(),
            created_ts: 1,
            labels: vec![],
            assignees: vec![],
            mentions: vec![],
            events: vec![Event {
                kind: EventKind::Comment,
                author: "a".into(),
                ts: 1,
                body: "c1".into(),
                add: vec![],
                remove: vec![],
                reason: String::new(),
            }],
        };
        let old_bytes = crate::issues::encode(&iss);
        let old_blob = crate::object::blob::write(&repo.gyt_dir, &old_bytes).unwrap();
        std::fs::create_dir_all(repo.gyt_dir.join("refs/issues")).unwrap();
        std::fs::write(
            repo.gyt_dir.join("refs/issues/1"),
            format!("{}\n", old_blob.to_hex()),
        )
        .unwrap();
        // Attacker prepares a NEW blob that truncates the events array
        // — would never pass validate_extends against the real old.
        iss.events.clear();
        iss.events.push(Event {
            kind: EventKind::Comment,
            author: "a".into(),
            ts: 2,
            body: "evil-overwrite".into(),
            add: vec![],
            remove: vec![],
            reason: String::new(),
        });
        let new_bytes = crate::issues::encode(&iss);
        let new_blob = crate::object::blob::write(&repo.gyt_dir, &new_bytes).unwrap();
        // Pusher lies about old_id (a never-uploaded hash).
        let bogus_old = ObjectId([0xaa; 32]);
        let upd = vec![crate::net::protocol::RefUpdate {
            old: Some(bogus_old),
            new: new_blob,
            name: "refs/issues/1".into(),
        }];
        let e = evaluate(&repo.gyt_dir, &upd, false, false, &[]);
        assert!(
            !e.is_clean(),
            "metadata-monotonic bypass: bogus old_id should have been rejected; got: {:?}",
            e.blocked
        );
    }

    #[test]
    fn load_allowed_signers_parses_hex() {
        let dir = std::env::temp_dir().join(format!(
            "gyt-allowed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut pk_hex = String::with_capacity(64);
        for b in sk.verifying_key().to_bytes() {
            use std::fmt::Write as _;
            write!(pk_hex, "{b:02x}").unwrap();
        }
        std::fs::write(
            dir.join("allowed_signers"),
            format!("# comment\n{pk_hex} alice@example\n\n"),
        )
        .unwrap();
        let got = load_allowed_signers(&dir).unwrap();
        assert_eq!(got.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

}
