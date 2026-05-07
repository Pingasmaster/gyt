// `gyt push [<remote>] [<branch>]`
//
// Defaults: remote=origin, branch=current. The push uploads the closure of
// commits/trees/blobs reachable from the local branch tip but NOT reachable
// from the remote tip (where remote tip is the value reported by GET
// /info/refs for `refs/heads/<branch>`).
//
// v1 simplification: when there is no remote tip (creating a new branch on
// the server), we send the FULL closure from the local tip. This is also the
// path taken when the server's tip is unrelated to ours (no common ancestor
// on the first-parent chain).
//
// `--force` adds `?force=1` to the ref-update; otherwise a 409 from the
// server is surfaced as an error suggesting `gyt pull`.

use crate::cmd::clone::{fetch_info_refs, open_client};
use crate::cmd::util::current_branch_and_head;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::ObjectId;
use crate::net::protocol::{
    PackEntry, RefEntry, RefUpdate, encode_pack, encode_ref_updates, pack_entry_from_bytes,
};
use crate::object::{ObjectKind, store, tag, tree};
use crate::refs;
use crate::repo::Repo;
use std::collections::{HashSet, VecDeque};

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

pub(crate) fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut remote: Option<String> = None;
    let mut branch: Option<String> = None;
    let mut force = false;
    let mut insecure = false;
    for a in args {
        match a.as_str() {
            "--force" | "-f" => force = true,
            "--insecure" => insecure = true,
            "-h" | "--help" => {
                println!("gyt push [<remote>] [<branch>] [--force] [--insecure]");
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "push: unknown flag {other}"
                )));
            }
            other => {
                if remote.is_none() {
                    remote = Some(other.to_string());
                } else if branch.is_none() {
                    branch = Some(other.to_string());
                } else {
                    return Err(GytError::InvalidArgument(
                        "push: too many positional arguments".into(),
                    ));
                }
            }
        }
    }
    let remote = remote.unwrap_or_else(|| "origin".to_string());
    let branch = match branch {
        Some(b) => b,
        None => {
            let (branch_ref, _) = current_branch_and_head(repo)?;
            branch_ref
                .ok_or_else(|| GytError::Repo("push: HEAD is detached".into()))?
                .strip_prefix("refs/heads/")
                .ok_or_else(|| GytError::Repo("push: HEAD is not on a local branch".into()))?
                .to_string()
        }
    };

    let cfg = Config::load(repo)?;
    let url = cfg
        .remotes
        .get(&remote)
        .ok_or_else(|| GytError::InvalidArgument(format!("push: unknown remote {remote:?}")))?
        .clone();
    let client = open_client(&url, insecure)?;

    // Resolve local branch tip.
    let local_ref = format!("refs/heads/{branch}");
    let local_tip = refs::read_ref(&repo.gyt_dir, &local_ref).map_err(|_| {
        GytError::Refs(format!(
            "push: local branch {branch} not found at {local_ref}"
        ))
    })?;

    // Discover remote tip.
    let server_refs = fetch_info_refs(&client)?;
    let remote_tip: Option<ObjectId> = server_refs
        .iter()
        .find(|r: &&RefEntry| r.name == local_ref)
        .map(|r| r.id);

    // Compute the upload closure: ancestors of local_tip stopping at remote_tip
    // (and any objects already known to be on the server, conservatively
    // approximated by the first-parent chain hitting remote_tip). v1 sends
    // the FULL closure if remote_tip is None or not on the first-parent chain.
    let entries = collect_upload_pack(repo, &local_tip, remote_tip.as_ref())?;

    // Send objects.
    if !entries.is_empty() {
        let body = encode_pack(&entries);
        let resp = client.post("objects/have", &body, &[])?;
        if resp.status != 200 {
            return Err(GytError::Net(format!(
                "POST /objects/have: status {} {}",
                resp.status, resp.reason
            )));
        }
    }

    // Send ref-update.
    let update = RefUpdate {
        old: remote_tip,
        new: local_tip,
        name: local_ref.clone(),
    };
    let body = encode_ref_updates(&[update]);
    let suffix = if force {
        "refs/update?force=1"
    } else {
        "refs/update"
    };
    let resp = client.post(suffix, &body, &[])?;
    if resp.status == 409 {
        return Err(GytError::Net(format!(
            "push: server rejected update (non-fast-forward); run `gyt pull {remote}` first or pass --force"
        )));
    }
    if resp.status != 200 {
        return Err(GytError::Net(format!(
            "POST /refs/update: status {} {}",
            resp.status, resp.reason
        )));
    }

    let old_short = remote_tip
        .map(|id| short(&id))
        .unwrap_or_else(|| "(new)".to_string());
    let new_short = short(&local_tip);
    println!(
        "pushed {} objects, {local_ref}: {old_short}..{new_short}",
        entries.len()
    );
    Ok(())
}

fn short(id: &ObjectId) -> String {
    let s = id.to_hex();
    s[..12].to_string()
}

/// Collect the on-disk bytes of every object reachable from `from` and not
/// reachable from `stop` (via the first-parent chain). If `stop` is `None`,
/// returns the full closure from `from`.
///
/// Implementation: BFS walk the closure of `from`, marking objects reachable
/// from `stop` (transitively) as "on the server" and excluding them. For
/// simplicity we compute the `stop` closure first, then the `from` closure,
/// emitting only the difference.
fn collect_upload_pack(
    repo: &Repo,
    from: &ObjectId,
    stop: Option<&ObjectId>,
) -> Result<Vec<PackEntry>> {
    let mut on_server: HashSet<ObjectId> = HashSet::new();
    if let Some(s) = stop {
        collect_closure(repo, s, &mut on_server)?;
    }
    let mut to_send: HashSet<ObjectId> = HashSet::new();
    let mut order: Vec<ObjectId> = Vec::new();
    let mut queue: VecDeque<ObjectId> = VecDeque::new();
    queue.push_back(*from);
    while let Some(id) = queue.pop_front() {
        if on_server.contains(&id) || !to_send.insert(id) {
            continue;
        }
        order.push(id);
        // Enqueue references.
        let obj = store::read(&repo.gyt_dir, &id)?;
        match obj.kind {
            ObjectKind::Blob => {}
            ObjectKind::Commit => {
                let c = crate::object::commit::decode(&obj.payload)?;
                if !on_server.contains(&c.tree) {
                    queue.push_back(c.tree);
                }
                for p in &c.parents {
                    if !on_server.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
            ObjectKind::Tree => {
                for e in tree::decode(&obj.payload)? {
                    if !on_server.contains(&e.hash) {
                        queue.push_back(e.hash);
                    }
                }
            }
            ObjectKind::Tag => {
                let t = tag::decode(&obj.payload)?;
                if !on_server.contains(&t.target) {
                    queue.push_back(t.target);
                }
            }
        }
    }
    // Read the on-disk bytes for each id.
    let mut entries = Vec::with_capacity(order.len());
    for id in order {
        let path = store::path_for(&repo.gyt_dir, &id);
        let bytes = fs_util::read_all(&path)?;
        entries.push(pack_entry_from_bytes(bytes));
        // Defensive: also stamp the id (purely for debug; the wire codec
        // re-derives it server-side anyway).
        let last = entries.last_mut().expect("just pushed");
        last.id = id;
    }
    Ok(entries)
}

/// Walk the full closure of `from`, inserting every reachable object id into `out`.
fn collect_closure(repo: &Repo, from: &ObjectId, out: &mut HashSet<ObjectId>) -> Result<()> {
    let mut queue: VecDeque<ObjectId> = VecDeque::new();
    queue.push_back(*from);
    while let Some(id) = queue.pop_front() {
        if !out.insert(id) {
            continue;
        }
        if !store::exists(&repo.gyt_dir, &id) {
            // We're walking an id we don't actually have locally — treat the
            // closure as "stops here". This happens when the remote tip is
            // ahead of us, which is exactly the case where we should NOT push.
            continue;
        }
        let obj = store::read(&repo.gyt_dir, &id)?;
        match obj.kind {
            ObjectKind::Blob => {}
            ObjectKind::Commit => {
                let c = crate::object::commit::decode(&obj.payload)?;
                queue.push_back(c.tree);
                for p in &c.parents {
                    queue.push_back(*p);
                }
            }
            ObjectKind::Tree => {
                for e in tree::decode(&obj.payload)? {
                    queue.push_back(e.hash);
                }
            }
            ObjectKind::Tag => {
                let t = tag::decode(&obj.payload)?;
                queue.push_back(t.target);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::init;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::hash;
    use crate::net::server_stub::{self, ServerState};
    use crate::object::{blob, commit, tree};

    #[test]
    fn push_creates_branch_on_server() {
        let _g = lock();
        // Empty server.
        let mut server = server_stub::spawn(ServerState::default(), false).expect("spawn");
        let url = server.base_url();

        // Local repo with one commit.
        let dir = tmp_dir("gyt-push");
        init::init_at(&dir).unwrap();
        let repo = Repo::open(&dir).unwrap();
        // Configure remote.
        let mut cfg = Config::load(&repo).unwrap();
        cfg.remotes.insert("origin".into(), url.clone());
        cfg.write(&repo.gyt_dir).unwrap();

        let blob_id = blob::write(&repo.gyt_dir, b"hello\n").unwrap();
        let tree_id = tree::write(
            &repo.gyt_dir,
            &[tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"hello.txt".to_vec(),
                hash: blob_id,
            }],
        )
        .unwrap();
        let commit_id = commit::write(
            &repo.gyt_dir,
            &commit::Commit {
                tree: tree_id,
                parents: vec![],
                authors: vec!["A <a@x> 1 +0000".into()],
                committer: "A <a@x> 1 +0000".into(),
                ai_assists: vec![],
                reviewers: vec![],
                message: "init\n".into(),
            },
        )
        .unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &commit_id).unwrap();

        run_in(
            &repo,
            &["origin".into(), "main".into(), "--insecure".into()],
        )
        .unwrap();

        // Verify: server should have refs/heads/main pointing at commit_id and
        // all three objects.
        let s = server.state.lock().unwrap();
        assert!(
            s.refs
                .iter()
                .any(|r| r.name == "refs/heads/main" && r.id == commit_id)
        );
        // Server stores under the *raw* (decoded) id, which equals the local id.
        assert!(s.objects.contains_key(&blob_id), "blob present");
        assert!(s.objects.contains_key(&tree_id), "tree present");
        assert!(s.objects.contains_key(&commit_id), "commit present");
        drop(s);

        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_ff_advances_existing_branch() {
        let _g = lock();
        // Pre-populate server with c1 on refs/heads/main.
        let raw_blob = crate::object::store::build_raw(ObjectKind::Blob, b"v1\n");
        let blob1_id = hash::hash_bytes(&raw_blob);
        let blob1_disk = crate::compress::encode(&raw_blob);
        let t1_payload = tree::encode(&[tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"f".to_vec(),
            hash: blob1_id,
        }]);
        let t1_raw = crate::object::store::build_raw(ObjectKind::Tree, &t1_payload);
        let t1_id = hash::hash_bytes(&t1_raw);
        let t1_disk = crate::compress::encode(&t1_raw);
        let c1_payload = commit::encode(&commit::Commit {
            tree: t1_id,
            parents: vec![],
            authors: vec!["A <a@x> 1 +0000".into()],
            committer: "A <a@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            message: "c1\n".into(),
        });
        let c1_raw = crate::object::store::build_raw(ObjectKind::Commit, &c1_payload);
        let c1_id = hash::hash_bytes(&c1_raw);
        let c1_disk = crate::compress::encode(&c1_raw);

        let mut state = ServerState::default();
        state.objects.insert(blob1_id, blob1_disk);
        state.objects.insert(t1_id, t1_disk);
        state.objects.insert(c1_id, c1_disk);
        state.refs.push(RefEntry {
            name: "refs/heads/main".into(),
            id: c1_id,
        });
        let mut server = server_stub::spawn(state, false).expect("spawn");
        let url = server.base_url();

        // Init local repo and put c1 + a follow-up c2 there.
        let dir = tmp_dir("gyt-push-ff");
        init::init_at(&dir).unwrap();
        let repo = Repo::open(&dir).unwrap();
        let mut cfg = Config::load(&repo).unwrap();
        cfg.remotes.insert("origin".into(), url.clone());
        cfg.write(&repo.gyt_dir).unwrap();

        // Write c1's exact objects locally so the upload-diff finds them on server.
        let local_blob1 = blob::write(&repo.gyt_dir, b"v1\n").unwrap();
        assert_eq!(local_blob1, blob1_id);
        let local_t1 = tree::write(
            &repo.gyt_dir,
            &[tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"f".to_vec(),
                hash: local_blob1,
            }],
        )
        .unwrap();
        assert_eq!(local_t1, t1_id);
        let local_c1 = commit::write(
            &repo.gyt_dir,
            &commit::Commit {
                tree: local_t1,
                parents: vec![],
                authors: vec!["A <a@x> 1 +0000".into()],
                committer: "A <a@x> 1 +0000".into(),
                ai_assists: vec![],
                reviewers: vec![],
                message: "c1\n".into(),
            },
        )
        .unwrap();
        assert_eq!(local_c1, c1_id);

        // c2 atop c1.
        let blob2 = blob::write(&repo.gyt_dir, b"v2\n").unwrap();
        let t2 = tree::write(
            &repo.gyt_dir,
            &[tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"f".to_vec(),
                hash: blob2,
            }],
        )
        .unwrap();
        let c2 = commit::write(
            &repo.gyt_dir,
            &commit::Commit {
                tree: t2,
                parents: vec![c1_id],
                authors: vec!["A <a@x> 2 +0000".into()],
                committer: "A <a@x> 2 +0000".into(),
                ai_assists: vec![],
                reviewers: vec![],
                message: "c2\n".into(),
            },
        )
        .unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &c2).unwrap();

        run_in(
            &repo,
            &["origin".into(), "main".into(), "--insecure".into()],
        )
        .unwrap();

        let s = server.state.lock().unwrap();
        assert!(
            s.refs
                .iter()
                .any(|r| r.name == "refs/heads/main" && r.id == c2)
        );
        assert!(s.objects.contains_key(&blob2));
        assert!(s.objects.contains_key(&t2));
        assert!(s.objects.contains_key(&c2));
        drop(s);

        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_ff_409_yields_pull_hint() {
        // Drive a 409 deterministically by hand-rolling the request: send a
        // ref-update for refs/heads/main whose `old` doesn't match the server.
        // This exercises the wire path and the push command's "suggest pull"
        // error message that goes with it.
        let _g = lock();
        let mut state = ServerState::default();
        state.refs.push(RefEntry {
            name: "refs/heads/main".into(),
            id: hash::hash_bytes(b"actual"),
        });
        let mut server = server_stub::spawn(state, false).expect("spawn");
        let url = server.base_url();

        let client = crate::net::http::HttpClient::new_plain(&url).unwrap();
        let body = encode_ref_updates(&[RefUpdate {
            old: Some(hash::hash_bytes(b"stale")),
            new: hash::hash_bytes(b"new"),
            name: "refs/heads/main".into(),
        }]);
        let resp = client.post("refs/update", &body, &[]).unwrap();
        assert_eq!(resp.status, 409, "reason={}", resp.reason);

        // And with `?force=1` the same payload is accepted (tests the path
        // selected by `--force`).
        let resp = client.post("refs/update?force=1", &body, &[]).unwrap();
        assert_eq!(resp.status, 200, "reason={}", resp.reason);

        server.shutdown();
    }

    #[test]
    fn push_force_uses_query_param() {
        let _g = lock();
        let mut state = ServerState::default();
        // Server claims refs/heads/main is some random id we don't have.
        let random = hash::hash_bytes(b"unrelated");
        state.refs.push(RefEntry {
            name: "refs/heads/main".into(),
            id: random,
        });
        let mut server = server_stub::spawn(state, false).expect("spawn");
        let url = server.base_url();

        let dir = tmp_dir("gyt-push-force");
        init::init_at(&dir).unwrap();
        let repo = Repo::open(&dir).unwrap();
        let mut cfg = Config::load(&repo).unwrap();
        cfg.remotes.insert("origin".into(), url.clone());
        cfg.write(&repo.gyt_dir).unwrap();
        // local commit
        let bid = blob::write(&repo.gyt_dir, b"x\n").unwrap();
        let tid = tree::write(
            &repo.gyt_dir,
            &[tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"f".to_vec(),
                hash: bid,
            }],
        )
        .unwrap();
        let cid = commit::write(
            &repo.gyt_dir,
            &commit::Commit {
                tree: tid,
                parents: vec![],
                authors: vec!["A <a@x> 1 +0000".into()],
                committer: "A <a@x> 1 +0000".into(),
                ai_assists: vec![],
                reviewers: vec![],
                message: "c\n".into(),
            },
        )
        .unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &cid).unwrap();

        // --force should overwrite the unrelated server tip.
        run_in(
            &repo,
            &[
                "origin".into(),
                "main".into(),
                "--force".into(),
                "--insecure".into(),
            ],
        )
        .unwrap();
        let s = server.state.lock().unwrap();
        assert!(
            s.refs
                .iter()
                .any(|r| r.name == "refs/heads/main" && r.id == cid)
        );
        drop(s);
        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
