// `gyt pull [<remote>]` (default `origin`)
//
// Equivalent to `gyt fetch <remote>` followed by `gyt merge --ff-only
// refs/remotes/<remote>/<current-branch>`. Anything that isn't a clean
// fast-forward fails — by design, v1 has no three-way merge.

use crate::cmd::fetch::{self, FetchSummary};
use crate::cmd::merge;
use crate::cmd::util::current_branch_and_head;
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
    let mut insecure = false;
    for a in args {
        match a.as_str() {
            "--insecure" => insecure = true,
            "-h" | "--help" => {
                println!("gyt pull [<remote>] [--insecure]");
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "pull: unknown flag {other}"
                )));
            }
            other => {
                if remote.is_some() {
                    return Err(GytError::InvalidArgument(
                        "pull: at most one remote argument".into(),
                    ));
                }
                remote = Some(other.to_string());
            }
        }
    }
    let remote = remote.unwrap_or_else(|| "origin".to_string());

    let summary: FetchSummary = fetch::fetch(repo, &remote, insecure)?;
    println!(
        "fetch: {} new objects, {} refs updated",
        summary.new_objects, summary.updated_refs
    );

    // Determine current branch.
    let (branch_ref, _head_id) = current_branch_and_head(repo)?;
    let branch_ref = branch_ref
        .ok_or_else(|| GytError::Repo("pull: HEAD is detached; refusing to pull".into()))?;
    let branch = branch_ref
        .strip_prefix("refs/heads/")
        .ok_or_else(|| {
            GytError::Repo(format!("pull: HEAD is not on a local branch: {branch_ref}"))
        })?
        .to_string();

    let remote_ref = format!("refs/remotes/{remote}/{branch}");
    // Ensure the remote-tracking ref exists before asking merge to resolve it.
    refs::read_ref(&repo.gyt_dir, &remote_ref).map_err(|_| {
        GytError::Refs(format!(
            "pull: no remote-tracking ref {remote_ref}; did the server publish refs/heads/{branch}?"
        ))
    })?;

    // `resolve_rev` accepts `<remote>/<branch>` as a shorthand for the
    // remote-tracking ref. Pass that form so merge picks it up.
    let remote_short = format!("{remote}/{branch}");
    merge::run_in(repo, &["--ff-only".into(), remote_short])?;
    Ok(())
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
    fn pull_ff_advances_local_branch() {
        let _g = lock();
        // Build c1 on the server.
        let (b1_id, b1_disk) = mk_obj(ObjectKind::Blob, b"a\n");
        let t1 = tree::encode(&[tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"f".to_vec(),
            hash: b1_id,
        }]);
        let (t1_id, t1_disk) = mk_obj(ObjectKind::Tree, &t1);
        let c1 = commit::encode(&commit::Commit {
            tree: t1_id,
            parents: vec![],
            authors: vec!["A <a@x> 1 +0000".into()],
            committer: "A <a@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "c1\n".into(),
        });
        let (c1_id, c1_disk) = mk_obj(ObjectKind::Commit, &c1);

        let mut state = ServerState::default();
        state.objects.insert(b1_id, b1_disk);
        state.objects.insert(t1_id, t1_disk);
        state.objects.insert(c1_id, c1_disk);
        state.refs.push(RefEntry {
            name: "refs/heads/main".into(),
            id: c1_id,
        });
        let mut server = server_stub::spawn(state, false).expect("spawn");
        let url = server.base_url();

        // Clone, then advance server, then pull.
        let dir = tmp_dir("gyt-pull");
        std::fs::remove_dir_all(&dir).unwrap();
        clone::run(&[
            url.clone(),
            dir.to_string_lossy().into_owned(),
            "--insecure".into(),
        ])
        .unwrap();

        // Add c2 on server.
        let (b2_id, b2_disk) = mk_obj(ObjectKind::Blob, b"b\n");
        let t2 = tree::encode(&[tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"f".to_vec(),
            hash: b2_id,
        }]);
        let (t2_id, t2_disk) = mk_obj(ObjectKind::Tree, &t2);
        let c2 = commit::encode(&commit::Commit {
            tree: t2_id,
            parents: vec![c1_id],
            authors: vec!["A <a@x> 2 +0000".into()],
            committer: "A <a@x> 2 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "c2\n".into(),
        });
        let (c2_id, c2_disk) = mk_obj(ObjectKind::Commit, &c2);
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

        let repo = Repo::open(&dir).unwrap();
        run_in(&repo, &["--insecure".into()]).unwrap();

        let main = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        assert_eq!(main, c2_id);
        let on_disk = std::fs::read(repo.workdir.join("f")).unwrap();
        assert_eq!(on_disk, b"b\n");

        server.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pull_no_remote_configured_errors() {
        let _g = lock();
        let dir = tmp_dir("gyt-pull-no-remote");
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
        // Should fail because no remote "origin" is configured
        assert!(
            err.to_string().contains("origin"),
            "expected origin error, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
