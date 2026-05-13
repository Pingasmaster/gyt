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

pub fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut remote: Option<String> = None;
    let mut refspec: Option<String> = None;
    let mut insecure = false;
    let mut prune = false;
    for a in args {
        match a.as_str() {
            "--insecure" => insecure = true,
            "--prune" | "-p" => prune = true,
            "-h" | "--help" => {
                println!(
                    "gyt fetch [<remote>] [<ref>] [--insecure] [--prune|-p]\n\n\
                     Fetch objects and refs from the named remote (default origin).\n\
                     With <ref>, only refs whose short name matches are fetched\n\
                     (e.g. `gyt fetch origin main`). --prune deletes any local\n\
                     refs/remotes/<remote>/* that the server no longer advertises."
                );
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "fetch: unknown flag {other}"
                )));
            }
            other => {
                if remote.is_none() {
                    remote = Some(other.to_string());
                } else if refspec.is_none() {
                    refspec = Some(other.to_string());
                } else {
                    return Err(GytError::InvalidArgument(
                        "fetch: at most two positional arguments (<remote> [<ref>])".into(),
                    ));
                }
            }
        }
    }
    let remote = remote.unwrap_or_else(|| "origin".to_string());
    let summary = fetch_with_refspec(repo, &remote, refspec.as_deref(), insecure, prune)?;
    if summary.pruned_refs > 0 {
        println!(
            "{} new objects from {}; updated {} refs; pruned {} stale.",
            summary.new_objects, remote, summary.updated_refs, summary.pruned_refs
        );
    } else {
        println!(
            "{} new objects from {}; updated {} refs.",
            summary.new_objects, remote, summary.updated_refs
        );
    }
    Ok(())
}

pub struct FetchSummary {
    pub new_objects: usize,
    pub updated_refs: usize,
    pub pruned_refs: usize,
}

pub fn fetch(repo: &Repo, remote: &str, insecure: bool, prune: bool) -> Result<FetchSummary> {
    fetch_with_refspec(repo, remote, None, insecure, prune)
}

/// Like `fetch`, but if `refspec` is `Some(name)` only refs whose
/// short name (under `refs/heads/` or `refs/tags/`) equals that name are
/// fetched and mirrored to `refs/remotes/<remote>/...`. Useful for CI
/// fetching just a single branch without downloading every tag.
pub fn fetch_with_refspec(
    repo: &Repo,
    remote: &str,
    refspec: Option<&str>,
    insecure: bool,
    prune: bool,
) -> Result<FetchSummary> {
    let cfg = Config::load(repo)?;
    let url = cfg
        .remotes
        .get(remote)
        .ok_or_else(|| GytError::InvalidArgument(format!("fetch: unknown remote {remote:?}")))?
        .clone();
    let client = open_client(&url, insecure)?;
    let server_refs_all = fetch_info_refs(&client)?;
    let server_refs: Vec<_> = match refspec {
        Some(name) => server_refs_all
            .into_iter()
            .filter(|r| {
                r.name
                    .strip_prefix("refs/heads/")
                    .or_else(|| r.name.strip_prefix("refs/tags/"))
                    == Some(name)
            })
            .collect(),
        None => server_refs_all,
    };
    if let Some(name) = refspec
        && server_refs.is_empty()
    {
        return Err(GytError::Repo(format!(
            "fetch: refspec {name:?} did not match any ref on {remote}"
        )));
    }
    let n_objects = walk_and_fetch(&client, repo, &server_refs, true)?;

    // Update refs/remotes/<remote>/<name> for heads and tags.
    let mut updated = 0usize;
    let mut advertised_local: std::collections::HashSet<String> =
        std::collections::HashSet::new();
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
            advertised_local.insert(local);
        }
    }

    let mut pruned = 0usize;
    if prune {
        // Delete refs/remotes/<remote>/* that the server no longer
        // advertises. Operates on the namespace we exclusively manage.
        let prefix = format!("refs/remotes/{remote}");
        if let Ok(local_refs) = refs::list_refs(&repo.gyt_dir, &prefix) {
            for (name, _) in local_refs {
                if !advertised_local.contains(&name) {
                    refs::delete_ref(&repo.gyt_dir, &name)?;
                    pruned += 1;
                }
            }
        }
    }

    Ok(FetchSummary {
        new_objects: n_objects,
        updated_refs: updated,
        pruned_refs: pruned,
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
        let stored = compress::encode(&raw);
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
            signature: None,
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
            signature: None,
            message: "c2\n".into(),
        };
        let c2_payload = commit::encode(&c2);
        let (c2_id, c2_disk) = mk_obj(ObjectKind::Commit, &c2_payload);
        {
            let mut s = server.state.lock().unwrap();
            s.objects.insert(b2_id, b2_disk);
            s.objects.insert(t2_id, t2_disk);
            s.objects.insert(c2_id, c2_disk);
            for r in &mut s.refs {
                if r.name == "refs/heads/main" {
                    r.id = c2_id;
                }
            }
        }

        // Fetch.
        let summary = fetch(&repo, "origin", true, false).unwrap();
        assert!(summary.new_objects >= 3, "got {}", summary.new_objects);
        assert!(summary.updated_refs >= 1, "got {}", summary.updated_refs);

        // refs/remotes/origin/main should now point at c2.
        let got = refs::read_ref(&repo.gyt_dir, "refs/remotes/origin/main").unwrap();
        assert_eq!(got, c2_id);

        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_no_remote_configured_errors() {
        let _g = lock();
        let dir = tmp_dir("gyt-fetch-no-remote");
        crate::cmd::init::init_at(&dir).unwrap();
        let repo = Repo::open(&dir).unwrap();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            remotes: Default::default(),
            create_default_gytignore: false,
            sign_required: false,
        };
        cfg.write(&repo.gyt_dir).unwrap();
        let err = run_in(&repo, &[]).unwrap_err();
        assert!(
            err.to_string().contains("origin"),
            "expected origin error, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
