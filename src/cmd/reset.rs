use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::object::{ObjectKind, commit, store, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Soft,
    Mixed,
}

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut mode = Mode::Mixed;
    let mut rev: Option<String> = None;
    for a in args {
        match a.as_str() {
            "--soft" => mode = Mode::Soft,
            "--mixed" => mode = Mode::Mixed,
            "--hard" => {
                return Err(GytError::Unsupported(
                    "reset --hard is not supported in gyt".into(),
                ));
            }
            other if !other.starts_with('-') => {
                if rev.is_some() {
                    return Err(GytError::InvalidArgument(
                        "reset: too many positional arguments".into(),
                    ));
                }
                rev = Some(other.to_string());
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "reset: unknown option {other}"
                )));
            }
        }
    }
    let rev = rev.ok_or_else(|| GytError::InvalidArgument("reset <rev>".into()))?;

    // Refuse on detached HEAD.
    let head = refs::read_head(&repo.gyt_dir)?;
    let head_ref = match &head {
        Head::Symbolic(r) => r.clone(),
        Head::Detached(_) => {
            return Err(GytError::Refs(
                "won't reset detached HEAD; use `gyt switch -c <branch>` first".into(),
            ));
        }
    };

    let target = resolve_rev(repo, &rev)?;
    // Confirm target is a commit.
    let obj = store::read(&repo.gyt_dir, &target)?;
    if obj.kind != ObjectKind::Commit {
        return Err(GytError::InvalidArgument(format!(
            "reset: <rev> {rev} is not a commit (got {})",
            obj.kind.as_str()
        )));
    }

    refs::write_ref(&repo.gyt_dir, &head_ref, &target)?;

    if mode == Mode::Mixed {
        let target_tree = commit::decode(&obj.payload)?.tree;
        let files = flatten_tree(&repo.gyt_dir, &target_tree)?;
        let mut idx = Index::new();
        for (path, e) in files {
            idx.insert(IndexEntry {
                ctime_secs: 0,
                mtime_secs: 0,
                size: 0,
                mode: e.mode,
                hash: e.hash,
                path: PathBuf::from(path),
            });
        }
        idx.write(&repo.index_path())?;
    }
    Ok(())
}

pub(crate) fn resolve_rev(repo: &Repo, rev: &str) -> Result<ObjectId> {
    if rev == "HEAD" {
        return refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir)?)?
            .ok_or_else(|| GytError::Refs("HEAD is unborn".into()));
    }
    if let Ok(id) = ObjectId::from_hex(rev) {
        return Ok(id);
    }
    for prefix in ["refs/heads", "refs/tags"] {
        if let Ok(id) = refs::read_ref(&repo.gyt_dir, &format!("{prefix}/{rev}")) {
            return Ok(id);
        }
    }
    Err(GytError::Refs(format!("cannot resolve rev: {rev}")))
}

#[derive(Debug, Clone)]
struct FlatEntry {
    mode: u32,
    hash: ObjectId,
}

fn flatten_tree(gyt_dir: &Path, tree_id: &ObjectId) -> Result<BTreeMap<String, FlatEntry>> {
    let mut out = BTreeMap::new();
    walk_tree(gyt_dir, tree_id, "", &mut out)?;
    Ok(out)
}

fn walk_tree(
    gyt_dir: &Path,
    tree_id: &ObjectId,
    prefix: &str,
    out: &mut BTreeMap<String, FlatEntry>,
) -> Result<()> {
    let entries = tree::read(gyt_dir, tree_id)?;
    for e in entries {
        let name = std::str::from_utf8(&e.name)
            .map_err(|_| GytError::Object("tree entry name is not utf-8".into()))?;
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if e.mode == tree::MODE_DIR {
            walk_tree(gyt_dir, &e.hash, &path, out)?;
        } else {
            out.insert(
                path,
                FlatEntry {
                    mode: e.mode,
                    hash: e.hash,
                },
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;

    #[test]
    fn reset_rejects_hard() {
        let r = TestRepo::new("gyt-reset-hard");
        let repo = r.open();
        let err = run_in(&repo, &["--hard".into(), "HEAD".into()]).unwrap_err();
        match err {
            GytError::Unsupported(_) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn reset_rejects_detached_head() {
        let r = TestRepo::new("gyt-reset-detached");
        let repo = r.open();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        refs::write_head(&repo.gyt_dir, &Head::Detached(head_id)).unwrap();
        let err = run_in(&repo, &["HEAD".into()]).unwrap_err();
        match err {
            GytError::Refs(msg) => assert!(msg.contains("detached"), "msg: {msg}"),
            other => panic!("expected Refs, got {other:?}"),
        }
    }

    #[test]
    fn reset_soft_moves_only_head_ref() {
        let r = TestRepo::new("gyt-reset-soft");
        let repo = r.open();
        let first = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        // make a second commit so HEAD advances
        let (second, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);
        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            second
        );

        // capture index before
        let idx_before = Index::read(&repo.index_path()).unwrap();
        run_in(&repo, &["--soft".into(), first.to_hex()]).unwrap();

        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            first
        );
        // Index unchanged: same entry hashes.
        let idx_after = Index::read(&repo.index_path()).unwrap();
        assert_eq!(idx_after.entries.len(), idx_before.entries.len());
        for (a, b) in idx_after.entries.iter().zip(idx_before.entries.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.path, b.path);
        }
    }

    #[test]
    fn reset_mixed_moves_head_and_resets_index() {
        let r = TestRepo::new("gyt-reset-mixed");
        let repo = r.open();
        let first = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        // Capture the first commit's tree to know what to expect in the index.
        let first_tree = commit::read(&repo.gyt_dir, &first).unwrap().tree;
        let (_, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);

        run_in(&repo, &["--mixed".into(), first.to_hex()]).unwrap();

        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            first
        );
        let idx = Index::read(&repo.index_path()).unwrap();
        let want = flatten_tree(&repo.gyt_dir, &first_tree).unwrap();
        assert_eq!(idx.entries.len(), want.len());
        for e in &idx.entries {
            let key = e.path.to_string_lossy().into_owned();
            let w = want.get(&key).expect("path in index but not in tree");
            assert_eq!(e.hash, w.hash);
            assert_eq!(e.mode, w.mode);
        }
    }

    #[test]
    fn reset_default_is_mixed() {
        let r = TestRepo::new("gyt-reset-default");
        let repo = r.open();
        let first = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let _ = r.commit_next(&[("hello.txt", b"v2\n", false)]);
        run_in(&repo, &[first.to_hex()]).unwrap();
        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            first
        );
    }

    #[test]
    fn reset_rejects_non_commit_rev() {
        let r = TestRepo::new("gyt-reset-noncommit");
        let repo = r.open();
        // Use a known blob id from initial commit.
        let blob_id = crate::object::blob::write(&repo.gyt_dir, b"hello\n").unwrap();
        let err = run_in(&repo, &[blob_id.to_hex()]).unwrap_err();
        match err {
            GytError::InvalidArgument(_) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
