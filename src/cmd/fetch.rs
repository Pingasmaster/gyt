// `gyt fetch [<remote>]` (default `origin`)
//
// Reads `<remote>`'s URL from config, GETs `/info/refs`, walks reachability
// just like clone — skipping objects we already have on disk — and updates
// `refs/remotes/<remote>/*` for each branch/tag advertised by the server.

use crate::cmd::clone::{fetch_info_refs, open_client, walk_and_fetch};
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::refs;
use crate::repo::Repo;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

pub(crate) fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut remote: Option<String> = None;
    let mut insecure = false;
    for a in args {
        match a.as_str() {
            "--insecure" => insecure = true,
            "-h" | "--help" => {
                println!("gyt fetch [<remote>] [--insecure]");
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "fetch: unknown flag {other}"
                )));
            }
            other => {
                if remote.is_some() {
                    return Err(GytError::InvalidArgument(
                        "fetch: at most one remote argument".into(),
                    ));
                }
                remote = Some(other.to_string());
            }
        }
    }
    let remote = remote.unwrap_or_else(|| "origin".to_string());
    let summary = fetch(repo, &remote, insecure)?;
    println!(
        "{} new objects from {}; updated {} refs.",
        summary.new_objects, remote, summary.updated_refs
    );
    Ok(())
}

pub(crate) struct FetchSummary {
    pub new_objects: usize,
    pub updated_refs: usize,
}

pub(crate) fn fetch(repo: &Repo, remote: &str, insecure: bool) -> Result<FetchSummary> {
    let cfg = Config::load(repo)?;
    let url = cfg
        .remotes
        .get(remote)
        .ok_or_else(|| GytError::InvalidArgument(format!("fetch: unknown remote {remote:?}")))?
        .clone();
    let client = open_client(&url, insecure)?;
    let server_refs = fetch_info_refs(&client)?;
    let n_objects = walk_and_fetch(&client, repo, &server_refs, true)?;

    // Update refs/remotes/<remote>/<name> for heads and tags.
    let mut updated = 0usize;
    for r in &server_refs {
        let mapped = if let Some(rest) = r.name.strip_prefix("refs/heads/") {
            Some(format!("refs/remotes/{remote}/{rest}"))
        } else {
            r.name
                .strip_prefix("refs/tags/")
                .map(|rest| format!("refs/remotes/{remote}/tags/{rest}"))
        };
        if let Some(local) = mapped {
            // Only count as "updated" if it actually changes.
            let prior = refs::read_ref(&repo.gyt_dir, &local).ok();
            if prior != Some(r.id) {
                refs::write_ref(&repo.gyt_dir, &local, &r.id)?;
                updated += 1;
            }
        }
    }
    Ok(FetchSummary {
        new_objects: n_objects,
        updated_refs: updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::clone;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::compress;
    use crate::hash::{self, ObjectId};
    use crate::net::protocol::RefEntry;
    use crate::net::server_stub::{self, ServerState};
    use crate::object::ObjectKind;
    use crate::object::store::build_raw;
    use crate::object::{commit, tree};

    fn mk_obj(kind: ObjectKind, payload: &[u8]) -> (ObjectId, Vec<u8>) {
        let raw = build_raw(kind, payload);
        let id = hash::hash_bytes(&raw);
        let stored = compress::encode(&raw).expect("encode");
        (id, stored)
    }

    #[test]
    fn fetch_advances_remote_tracking() {
        let _g = lock();

        // Build a one-commit repo on the server.
        let blob_payload = b"hello\n".to_vec();
        let (blob_id, blob_disk) = mk_obj(ObjectKind::Blob, &blob_payload);
        let t1_payload = tree::encode(&[tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"hello.txt".to_vec(),
            hash: blob_id,
        }]);
        let (t1_id, t1_disk) = mk_obj(ObjectKind::Tree, &t1_payload);
        let c1 = commit::Commit {
            tree: t1_id,
            parents: vec![],
            authors: vec!["A <a@x> 1 +0000".into()],
            committer: "A <a@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            message: "c1\n".into(),
        };
        let c1_payload = commit::encode(&c1);
        let (c1_id, c1_disk) = mk_obj(ObjectKind::Commit, &c1_payload);

        let mut state = ServerState::default();
        state.objects.insert(blob_id, blob_disk);
        state.objects.insert(t1_id, t1_disk);
        state.objects.insert(c1_id, c1_disk);
        state.refs.push(RefEntry {
            name: "refs/heads/main".into(),
            id: c1_id,
        });

        let mut server = server_stub::spawn(state, false).expect("spawn");
        let url = server.base_url();

        // Clone first.
        let dir = tmp_dir("gyt-fetch");
        std::fs::remove_dir_all(&dir).unwrap();
        clone::run(&[
            url.clone(),
            dir.to_string_lossy().into_owned(),
            "--insecure".into(),
        ])
        .unwrap();
        let repo = Repo::open(&dir).unwrap();

        // Add a second commit on the server stub atop c1.
        let blob2 = b"world\n".to_vec();
        let (b2_id, b2_disk) = mk_obj(ObjectKind::Blob, &blob2);
        let t2_payload = tree::encode(&[tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"hello.txt".to_vec(),
            hash: b2_id,
        }]);
        let (t2_id, t2_disk) = mk_obj(ObjectKind::Tree, &t2_payload);
        let c2 = commit::Commit {
            tree: t2_id,
            parents: vec![c1_id],
            authors: vec!["A <a@x> 2 +0000".into()],
            committer: "A <a@x> 2 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            message: "c2\n".into(),
        };
        let c2_payload = commit::encode(&c2);
        let (c2_id, c2_disk) = mk_obj(ObjectKind::Commit, &c2_payload);
        {
            let mut s = server.state.lock().unwrap();
            s.objects.insert(b2_id, b2_disk);
            s.objects.insert(t2_id, t2_disk);
            s.objects.insert(c2_id, c2_disk);
            for r in s.refs.iter_mut() {
                if r.name == "refs/heads/main" {
                    r.id = c2_id;
                }
            }
        }

        // Fetch.
        let summary = fetch(&repo, "origin", true).unwrap();
        assert!(summary.new_objects >= 3, "got {}", summary.new_objects);
        assert!(summary.updated_refs >= 1, "got {}", summary.updated_refs);

        // refs/remotes/origin/main should now point at c2.
        let got = refs::read_ref(&repo.gyt_dir, "refs/remotes/origin/main").unwrap();
        assert_eq!(got, c2_id);

        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
