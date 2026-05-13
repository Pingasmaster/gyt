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
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let mut url: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut insecure = false;
    for a in args {
        match a.as_str() {
            "--insecure" => insecure = true,
            "-h" | "--help" => {
                println!("gyt clone <url> [<dir>] [--insecure]");
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
    }
    let url = url.ok_or_else(|| GytError::InvalidArgument("clone <url> [<dir>]".into()))?;
    let dir = match dir {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(default_dir_from_url(&url)?),
    };
    clone_into(&url, &dir, insecure)
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

fn clone_into(url: &str, dir: &PathBuf, insecure: bool) -> Result<()> {
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

    let n_objects = walk_and_fetch(&client, &repo, &server_refs, true)?;

    // Mirror server refs locally as heads/tags.
    let mut n_refs = 0usize;
    for r in &server_refs {
        if r.name.starts_with("refs/heads/") || r.name.starts_with("refs/tags/") {
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
) -> Result<usize> {
    let _ = mirror_all_refs;
    let mut wants: VecDeque<ObjectId> = VecDeque::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut downloaded = 0usize;

    for r in server_refs {
        if r.name.starts_with("refs/heads/") || r.name.starts_with("refs/tags/") {
            enqueue_if_new(repo, &r.id, &mut wants, &mut seen);
        }
    }

    while !wants.is_empty() {
        // Drain the current batch. `std::mem::take` swaps in a fresh empty
        // `VecDeque` and gives us ownership of the old one — same effect
        // as `drain(..).collect()` but avoids the `iter_with_drain` lint
        // (which warns that drain doesn't reduce VecDeque's capacity).
        let batch: Vec<ObjectId> = std::mem::take(&mut wants).into_iter().collect();
        if batch.is_empty() {
            break;
        }
        let body = encode_wants(&batch);
        let resp = client.post("objects/want", &body, &[])?;
        if resp.status != 200 {
            return Err(GytError::Net(format!(
                "POST /objects/want: status {} {}",
                resp.status, resp.reason
            )));
        }
        let entries = parse_packfile(&resp.body)?;
        // For each received object, verify and store; then enqueue its references.
        for entry in entries {
            let raw = compress::decode(&entry.bytes)?;
            let id = hash::hash_bytes(&raw);
            // Verify the raw header round-trips.
            let (kind, payload) = store::parse_raw(&raw)?;
            // For commits, require a canonical encoding so a malicious or
            // buggy server can't poison our store with a non-canonical
            // commit that later breaks `commit::read` for every future
            // reader. We trust `commit::decode` to enforce this — if it
            // rejects, refuse the pack.
            if kind == ObjectKind::Commit {
                crate::object::commit::decode(&payload).map_err(|e| {
                    GytError::Net(format!(
                        "clone: server returned non-canonical commit {id}: {e}"
                    ))
                })?;
            }
            // Already on disk? skip.
            if !store::exists(&repo.gyt_dir, &id) {
                let path = store::path_for(&repo.gyt_dir, &id);
                fs_util::atomic_write(&path, &entry.bytes)?;
                downloaded += 1;
            }
            // Enqueue references.
            enqueue_refs(repo, kind, &payload, &mut wants, &mut seen)?;
        }
    }
    Ok(downloaded)
}

fn enqueue_if_new(
    repo: &Repo,
    id: &ObjectId,
    wants: &mut VecDeque<ObjectId>,
    seen: &mut HashSet<ObjectId>,
) {
    if seen.insert(*id) && !store::exists(&repo.gyt_dir, id) {
        wants.push_back(*id);
    }
}

fn enqueue_refs(
    repo: &Repo,
    kind: ObjectKind,
    payload: &[u8],
    wants: &mut VecDeque<ObjectId>,
    seen: &mut HashSet<ObjectId>,
) -> Result<()> {
    match kind {
        ObjectKind::Blob => {}
        ObjectKind::Commit => {
            let c = crate::object::commit::decode(payload)?;
            enqueue_if_new(repo, &c.tree, wants, seen);
            for p in &c.parents {
                enqueue_if_new(repo, p, wants, seen);
            }
        }
        ObjectKind::Tree => {
            let entries = tree::decode(payload)?;
            for e in entries {
                enqueue_if_new(repo, &e.hash, wants, seen);
            }
        }
        ObjectKind::Tag => {
            let t = tag::decode(payload)?;
            enqueue_if_new(repo, &t.target, wants, seen);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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

        clone_into(&url, &dir, true).unwrap();

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

        let err = clone_into("http://127.0.0.1:1/", &dir, true).unwrap_err();
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
