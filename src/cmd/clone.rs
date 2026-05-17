// `gyt clone <url> [<dir>] [--insecure]`
//
// Initialise a fresh local repository from a remote `gyt-protocol v1` server.
// Strategy:
//   1. Initialise an empty repo at <dir>.
//   2. Persist the URL as the `origin` remote.
//   3. GET /info/refs to learn the server's refs.
//   4. Reachability walk: pop ids from a queue, batch-POST /objects/want,
//      verify each entry by decode→hash, write its on-disk bytes, then
//      enqueue the ids it references (commit→tree+parents, tree→entries,
//      tag→target). Repeat until the queue is empty.
//   5. Mirror refs/heads/* and refs/tags/* locally.
//   6. Set HEAD to refs/heads/main if present, else first branch.
//   7. Materialize the chosen tip's tree.

use crate::cmd::init;
use crate::cmd::merge;
use crate::compress;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::{self, ObjectId};
use crate::net::http::HttpClient;
use crate::net::protocol::{RefEntry, encode_wants, parse_info_refs, parse_packfile};
use crate::object::{ObjectKind, store, tag, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
pub fn run(args: &[String]) -> Result<()> {
    let mut url: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut insecure = false;
    let mut depth: Option<u32> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--insecure" => insecure = true,
            "--depth" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--depth needs a value".into())
                })?;
                let n: u32 = v.parse().map_err(|_| {
                    GytError::InvalidArgument(format!("--depth: not a number: {v}"))
                })?;
                if n == 0 {
                    return Err(GytError::InvalidArgument(
                        "--depth must be >= 1".into(),
                    ));
                }
                depth = Some(n);
            }
            "-h" | "--help" => {
                println!(
                    "gyt clone <url> [<dir>] [--insecure] [--depth <N>]\n\n\
                     --depth <N>   Shallow clone: stop walking commit parents\n\
                                   after N levels per ref tip. Boundary commits\n\
                                   are recorded in .gyt/shallow so the local\n\
                                   tree honors the truncation. The default is\n\
                                   to fetch the full history."
                );
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "clone: unknown flag {other}"
                )));
            }
            other => {
                if url.is_none() {
                    url = Some(other.to_string());
                } else if dir.is_none() {
                    dir = Some(other.to_string());
                } else {
                    return Err(GytError::InvalidArgument(
                        "clone: too many positional arguments".into(),
                    ));
                }
            }
        }
        i += 1;
    }
    let url = url.ok_or_else(|| GytError::InvalidArgument("clone <url> [<dir>]".into()))?;
    let dir = match dir {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(default_dir_from_url(&url)?),
    };
    clone_into(&url, &dir, insecure, depth)
}

fn default_dir_from_url(url: &str) -> Result<String> {
    // Take the trimmed last path segment, stripping a single trailing `/`.
    let trimmed = url.trim_end_matches('/');
    let last = trimmed
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GytError::InvalidArgument(format!("clone: cannot derive dir from {url}")))?;
    let name = last.strip_suffix(".gyt").unwrap_or(last);
    if name.is_empty() {
        return Err(GytError::InvalidArgument(format!(
            "clone: empty repo name in url {url}"
        )));
    }
    Ok(name.to_string())
}

fn clone_into(url: &str, dir: &PathBuf, insecure: bool, depth: Option<u32>) -> Result<()> {
    if dir.exists() {
        let mut iter = std::fs::read_dir(dir)?;
        if iter.next().is_some() {
            return Err(GytError::Repo(format!(
                "clone: target {} exists and is not empty",
                dir.display()
            )));
        }
    }
    println!("cloning {url} into {}...", dir.display());

    init::init_at(dir)?;
    let repo = Repo::open(dir)?;

    // Persist origin.
    let mut cfg = Config::load(&repo)?;
    cfg.remotes.insert("origin".into(), url.to_string());
    cfg.write(&repo.gyt_dir)?;

    let client = open_client(url, insecure)?;
    let server_refs = fetch_info_refs(&client)?;

    let n_objects = walk_and_fetch(&client, &repo, &server_refs, true, depth)?;

    // Mirror server refs locally. Includes refs/heads/*, refs/tags/*,
    // and the metadata namespaces (refs/issues/*, refs/prs/*) so that
    // issues, discussions and PRs travel with the repo. Anything outside
    // these namespaces is dropped — we don't want a malicious server to
    // be able to fill our ref database with arbitrary names.
    let mut n_refs = 0usize;
    for r in &server_refs {
        if is_user_visible_ref(&r.name) {
            refs::write_ref(&repo.gyt_dir, &r.name, &r.id)?;
            n_refs += 1;
        }
    }

    // Choose HEAD: prefer refs/heads/main; otherwise first branch in server_refs.
    let chosen = pick_head(&server_refs);
    if let Some(name) = chosen {
        refs::write_head(&repo.gyt_dir, &Head::Symbolic(name.clone()))?;
        if let Ok(commit_id) = refs::read_ref(&repo.gyt_dir, &name) {
            merge::materialize_commit(&repo, &commit_id)?;
        }
    }

    println!("done. cloned {n_objects} objects, {n_refs} refs.");
    Ok(())
}

/// Ref-name namespace whitelist for clone / fetch. We accept the
/// version-control names (heads / tags) plus the metadata namespaces
/// that carry issues, discussions and PRs.
pub fn is_user_visible_ref(name: &str) -> bool {
    name.starts_with("refs/heads/")
        || name.starts_with("refs/tags/")
        || name.starts_with("refs/issues/")
        || name.starts_with("refs/prs/")
}

fn pick_head(server_refs: &[RefEntry]) -> Option<String> {
    if server_refs.iter().any(|r| r.name == "refs/heads/main") {
        return Some("refs/heads/main".to_string());
    }
    for r in server_refs {
        if let Some(branch) = r.name.strip_prefix("refs/heads/") {
            let _ = branch;
            return Some(r.name.clone());
        }
    }
    None
}

pub fn open_client(url: &str, insecure: bool) -> Result<HttpClient> {
    if url.starts_with("http://") {
        if !insecure {
            return Err(GytError::Net(
                "clone: plain http requires --insecure".into(),
            ));
        }
        HttpClient::new_plain(url)
    } else {
        HttpClient::new(url)
    }
}

pub fn fetch_info_refs(client: &HttpClient) -> Result<Vec<RefEntry>> {
    let resp = client.get("info/refs", &[])?;
    if resp.status != 200 {
        return Err(GytError::Net(format!(
            "GET /info/refs: status {} {}",
            resp.status, resp.reason
        )));
    }
    parse_info_refs(&resp.body)
}

/// Walk the reachability closure starting from the heads/tags in `server_refs`,
/// downloading objects we don't already have. Returns the number of objects
/// downloaded.
///
/// If `mirror_all_refs` is true, all `server_refs` ids are seeds; otherwise
/// only refs/heads/* and refs/tags/* (used by clone & fetch alike — fetch
/// passes `true` too since the server only advertises heads/tags anyway).
pub fn walk_and_fetch(
    client: &HttpClient,
    repo: &Repo,
    server_refs: &[RefEntry],
    mirror_all_refs: bool,
    depth: Option<u32>,
) -> Result<usize> {
    let _ = mirror_all_refs;

    // Queue of ids to *walk*. Duplicates are allowed; the per-id depth
    // bookkeeping below short-circuits redundant walks. We need
    // duplicates so a commit re-discovered at a smaller depth can have
    // its parents re-enqueued at the correct lower depth — the previous
    // implementation locked depth at first discovery, which silently
    // dropped reachable objects when a shorter path to a deep commit
    // existed.
    let mut wants: VecDeque<ObjectId> = VecDeque::new();
    // Ids whose bytes are on disk. Once true, no further network fetch.
    let mut downloaded: HashSet<ObjectId> = HashSet::new();
    // Minimum depth at which we've observed an id. Only meaningful for
    // commits, but recorded eagerly because we don't know the kind
    // until we decode.
    let mut commit_depth: HashMap<ObjectId, u32> = HashMap::new();
    // The depth at which we *walked parents* for a commit. If
    // `commit_depth[id]` later drops below `walked_at[id]`, the commit
    // is re-walked so its parents get the smaller depth.
    let mut walked_at: HashMap<ObjectId, u32> = HashMap::new();
    // Cached commit payloads keep re-walks free of disk I/O. Trees and
    // blobs aren't cached because their walk is depth-independent.
    let mut commit_payloads: HashMap<ObjectId, Vec<u8>> = HashMap::new();
    let mut shallow_boundary: HashSet<ObjectId> = HashSet::new();
    let mut new_objects = 0usize;

    for r in server_refs {
        if is_user_visible_ref(&r.name) {
            commit_depth.entry(r.id).or_insert(0);
            if store::exists(&repo.gyt_dir, &r.id) {
                downloaded.insert(r.id);
            }
            wants.push_back(r.id);
        }
    }

    while !wants.is_empty() {
        // -- Step 1: batch-fetch every want that's not yet on disk.
        let mut to_fetch: HashSet<ObjectId> = HashSet::new();
        for id in &wants {
            if !downloaded.contains(id) {
                to_fetch.insert(*id);
            }
        }
        if !to_fetch.is_empty() {
            let fetch_vec: Vec<ObjectId> = to_fetch.into_iter().collect();
            // H4: track the requested set so we can reject any object
            // the server returns that we didn't ask for. Without this,
            // a hostile server can flood the client's `.gyt/objects/`
            // with arbitrary content per response (unbounded disk-fill).
            let requested: HashSet<ObjectId> = fetch_vec.iter().copied().collect();
            let body = encode_wants(&fetch_vec);
            let resp = client.post("objects/want", &body, &[])?;
            if resp.status != 200 {
                return Err(GytError::Net(format!(
                    "POST /objects/want: status {} {}",
                    resp.status, resp.reason
                )));
            }
            for entry in parse_packfile(&resp.body)? {
                let raw = compress::decode(&entry.bytes)?;
                let entry_id = hash::hash_bytes(&raw);
                if !requested.contains(&entry_id) {
                    return Err(GytError::Net(format!(
                        "clone: server returned unsolicited object {entry_id}"
                    )));
                }
                let (kind, payload) = store::parse_raw(&raw)?;
                // F-D3-03: mirror the server-side canonicality gate
                // on EVERY object kind the client persists. A hostile
                // server can otherwise plant non-canonical trees /
                // tags (unsorted entries, mode-out-of-whitelist,
                // unknown tag.kind) — they hash to whatever the bytes
                // say but downstream consumers misbehave. Commits
                // already had this check; trees and tags did not.
                match kind {
                    ObjectKind::Commit => {
                        crate::object::commit::decode(&payload).map_err(|e| {
                            GytError::Net(format!(
                                "clone: server returned non-canonical commit {entry_id}: {e}"
                            ))
                        })?;
                        commit_payloads.insert(entry_id, payload.clone());
                    }
                    ObjectKind::Tree => {
                        let entries = crate::object::tree::decode(&payload).map_err(|e| {
                            GytError::Net(format!(
                                "clone: server returned non-canonical tree {entry_id}: {e}"
                            ))
                        })?;
                        if crate::object::tree::encode(&entries) != payload {
                            return Err(GytError::Net(format!(
                                "clone: tree {entry_id} bytes don't round-trip through canonical encoder"
                            )));
                        }
                    }
                    ObjectKind::Tag => {
                        let t = crate::object::tag::decode(&payload).map_err(|e| {
                            GytError::Net(format!(
                                "clone: server returned non-canonical tag {entry_id}: {e}"
                            ))
                        })?;
                        if crate::object::tag::encode(&t) != payload {
                            return Err(GytError::Net(format!(
                                "clone: tag {entry_id} bytes don't round-trip through canonical encoder"
                            )));
                        }
                    }
                    ObjectKind::Blob => { /* blobs have no canonical form */ }
                }
                if !store::exists(&repo.gyt_dir, &entry_id) {
                    let path = store::path_for(&repo.gyt_dir, &entry_id);
                    fs_util::atomic_write(&path, &entry.bytes)?;
                    new_objects += 1;
                }
                downloaded.insert(entry_id);
            }
        }

        // -- Step 2: walk the batch. New parents/trees enqueued here
        //    accumulate in `wants` for the next iteration.
        let batch: Vec<ObjectId> = std::mem::take(&mut wants).into_iter().collect();
        for id in batch {
            if !downloaded.contains(&id) {
                // Server didn't ship it. We don't have its kind so we
                // can't walk; skip and trust the caller to notice the
                // ref it cares about doesn't resolve.
                continue;
            }
            walk_one(
                repo,
                &id,
                depth,
                &mut wants,
                &mut downloaded,
                &mut commit_depth,
                &mut walked_at,
                &commit_payloads,
                &mut shallow_boundary,
            )?;
        }
    }

    if depth.is_some() && !shallow_boundary.is_empty() {
        write_shallow(repo, &shallow_boundary)?;
    }

    Ok(new_objects)
}

#[expect(clippy::too_many_arguments, reason = "signature passes a fixed bundle of orthogonal params; a struct would just rename them")] // Reason: the shallow walker threads a handful of parallel maps; bundling into a struct would just rename them.
fn walk_one(
    repo: &Repo,
    id: &ObjectId,
    max_depth: Option<u32>,
    wants: &mut VecDeque<ObjectId>,
    downloaded: &mut HashSet<ObjectId>,
    commit_depth: &mut HashMap<ObjectId, u32>,
    walked_at: &mut HashMap<ObjectId, u32>,
    commit_payloads: &HashMap<ObjectId, Vec<u8>>,
    shallow_boundary: &mut HashSet<ObjectId>,
) -> Result<()> {
    // Resolve kind+payload. Commits live in the payload cache so
    // re-walks avoid hitting disk; everything else reads back through
    // the object store.
    let (kind, payload): (ObjectKind, Vec<u8>) = if let Some(p) = commit_payloads.get(id) {
        (ObjectKind::Commit, p.clone())
    } else {
        let obj = store::read(&repo.gyt_dir, id)?;
        (obj.kind, obj.payload)
    };
    match kind {
        ObjectKind::Blob => {}
        ObjectKind::Tree => {
            for e in tree::decode(&payload)? {
                enqueue_for_fetch(repo, &e.hash, wants, downloaded);
            }
        }
        ObjectKind::Tag => {
            let t = tag::decode(&payload)?;
            // A tag target restarts at depth 0 (treat as a fresh tip).
            let need = match commit_depth.get(&t.target) {
                None => true,
                Some(d) => *d > 0,
            };
            if need {
                commit_depth.insert(t.target, 0);
                enqueue_for_fetch(repo, &t.target, wants, downloaded);
            }
        }
        ObjectKind::Commit => {
            let d = commit_depth.get(id).copied().unwrap_or(0);
            // Already walked this commit at depth <= d? Skip.
            if let Some(prev) = walked_at.get(id).copied()
                && prev <= d
            {
                return Ok(());
            }
            walked_at.insert(*id, d);

            let c = crate::object::commit::decode(&payload)?;
            enqueue_for_fetch(repo, &c.tree, wants, downloaded);

            let next_d = d.saturating_add(1);
            // `--depth=N` means "fetch N commits per tip path". The tip
            // is at depth 0, so commits at depths 0..N-1 are fetched
            // and the depth-(N-1) commit is the boundary (its parents
            // at depth N are not fetched). The cutoff is therefore
            // `next_d >= N`, not `next_d > N`.
            let truncated = matches!(max_depth, Some(max) if next_d >= max);
            if truncated {
                if !c.parents.is_empty() {
                    shallow_boundary.insert(*id);
                }
            } else {
                // A shorter path to this commit means it is no longer
                // a real boundary — clear it if previously recorded.
                shallow_boundary.remove(id);
                for p in c.parents {
                    let should_update = match commit_depth.get(&p) {
                        None => true,
                        Some(old) => next_d < *old,
                    };
                    if should_update {
                        commit_depth.insert(p, next_d);
                        enqueue_for_fetch(repo, &p, wants, downloaded);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Push `id` onto the walk queue, marking it as already-downloaded
/// if it's present in the local store (so the next network batch
/// skips it).
fn enqueue_for_fetch(
    repo: &Repo,
    id: &ObjectId,
    wants: &mut VecDeque<ObjectId>,
    downloaded: &mut HashSet<ObjectId>,
) {
    if !downloaded.contains(id) && store::exists(&repo.gyt_dir, id) {
        downloaded.insert(*id);
    }
    wants.push_back(*id);
}

/// Persist `.gyt/shallow`: one boundary commit hex per line. The presence
/// of this file tells the local tree that the commits listed have their
/// parents intentionally absent from `objects/`, so log/gc/etc. should
/// treat them as roots rather than reporting missing objects.
fn write_shallow(repo: &Repo, boundary: &HashSet<ObjectId>) -> Result<()> {
    let mut ids: Vec<String> = boundary.iter().map(|id| id.to_hex()).collect();
    ids.sort();
    let mut body = String::with_capacity(ids.len() * 65);
    for id in &ids {
        body.push_str(id);
        body.push('\n');
    }
    fs_util::atomic_write(&repo.gyt_dir.join("shallow"), body.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::net::server_stub::{self, ServerState};
    use crate::object::ObjectKind;
    use crate::object::{commit, store::build_raw};

    fn mk_obj(kind: ObjectKind, payload: &[u8]) -> (ObjectId, Vec<u8>) {
        let raw = build_raw(kind, payload);
        let id = hash::hash_bytes(&raw);
        let stored = compress::encode(&raw);
        (id, stored)
    }

    fn populate_one_commit() -> (ServerState, ObjectId) {
        // blob
        let blob_payload = b"hello world\n".to_vec();
        let (blob_id, blob_disk) = mk_obj(ObjectKind::Blob, &blob_payload);
        // tree containing hello.txt -> blob
        let tree_entries = vec![tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"hello.txt".to_vec(),
            hash: blob_id,
        }];
        let tree_payload = tree::encode(&tree_entries);
        let (tree_id, tree_disk) = mk_obj(ObjectKind::Tree, &tree_payload);
        // commit
        let c = commit::Commit {
            tree: tree_id,
            parents: vec![],
            authors: vec!["A <a@x> 1 +0000".into()],
            committer: "A <a@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "init\n".into(),
        };
        let commit_payload = commit::encode(&c);
        let (commit_id, commit_disk) = mk_obj(ObjectKind::Commit, &commit_payload);

        let mut state = ServerState::default();
        state.objects.insert(blob_id, blob_disk);
        state.objects.insert(tree_id, tree_disk);
        state.objects.insert(commit_id, commit_disk);
        state.refs.push(RefEntry {
            name: "refs/heads/main".into(),
            id: commit_id,
        });
        (state, commit_id)
    }

    #[test]
    fn clones_one_commit() {
        let _g = lock();
        let (state, expected_commit) = populate_one_commit();
        let mut server = server_stub::spawn(state, false).expect("spawn");
        let url = server.base_url();

        let dir = tmp_dir("gyt-clone");
        // remove the empty dir; clone should create it
        std::fs::remove_dir_all(&dir).unwrap();

        clone_into(&url, &dir, true, None).unwrap();

        let repo = Repo::open(&dir).unwrap();
        // Verify head ref
        let main = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        assert_eq!(main, expected_commit);
        // Verify HEAD is symbolic to main
        match refs::read_head(&repo.gyt_dir).unwrap() {
            Head::Symbolic(s) => assert_eq!(s, "refs/heads/main"),
            other @ Head::Detached(_) => panic!("unexpected HEAD: {other:?}"),
        }
        // Verify workdir materialized
        let on_disk = std::fs::read(repo.workdir.join("hello.txt")).unwrap();
        assert_eq!(on_disk, b"hello world\n");
        // Verify origin remote stored
        let cfg = Config::load(&repo).unwrap();
        assert_eq!(
            cfg.remotes.get("origin").map(String::as_str),
            Some(url.as_str())
        );

        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_existing_nonempty_dir() {
        let _g = lock();
        let dir = tmp_dir("gyt-clone-exists");
        std::fs::write(dir.join("file"), b"x").unwrap();

        let err = clone_into("http://127.0.0.1:1/", &dir, true, None).unwrap_err();
        match err {
            GytError::Repo(_) => {}
            other => panic!("expected Repo error, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_dir_strips_gyt_suffix() {
        assert_eq!(
            default_dir_from_url("https://h/p/repo.gyt/").unwrap(),
            "repo"
        );
        assert_eq!(
            default_dir_from_url("https://h/p/repo.gyt").unwrap(),
            "repo"
        );
        assert_eq!(default_dir_from_url("https://h/p/repo/").unwrap(), "repo");
    }
}
