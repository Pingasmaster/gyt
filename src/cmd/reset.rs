use crate::cmd::util::flatten_tree;
use crate::errors::{GytError, Result};
use crate::index::{Index, IndexEntry};
use crate::object::{ObjectKind, blob, commit, store};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Soft,
    Mixed,
    Hard,
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
            "--hard" => mode = Mode::Hard,
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

    let head = refs::read_head(&repo.gyt_dir)?;
    let head_ref = match &head {
        Head::Symbolic(r) => r.clone(),
        Head::Detached(_) => {
            return Err(GytError::Refs(
                "won't reset detached HEAD; use `gyt switch -c <branch>` first".into(),
            ));
        }
    };

    let target = crate::cmd::util::resolve_rev(repo, &rev)?;
    let obj = store::read(&repo.gyt_dir, &target)?;
    if obj.kind != ObjectKind::Commit {
        return Err(GytError::InvalidArgument(format!(
            "reset: <rev> {rev} is not a commit (got {})",
            obj.kind.as_str()
        )));
    }

    refs::write_ref(&repo.gyt_dir, &head_ref, &target)?;

    let target_tree = commit::decode(&obj.payload)?.tree;

    if mode == Mode::Hard {
        // Read current index before overwriting
        let current_index = Index::read(&repo.index_path())?;
        let files = flatten_tree(repo, &target_tree)?;

        // Remove files in working tree that are no longer in target tree
        for entry in &current_index.entries {
            if !files.contains_key(&entry.path) {
                let abs = repo.workdir.join(&entry.path);
                if abs.exists() {
                    let _ = fs::remove_file(&abs);
                }
            }
        }

        // Write new index from target tree
        let mut idx = Index::new();
        for (p, (mode_val, hash)) in &files {
            idx.insert(IndexEntry {
                ctime_secs: 0,
                mtime_secs: 0,
                size: 0,
                mode: *mode_val,
                hash: *hash,
                path: p.clone(),
            });
        }
        idx.write(&repo.index_path())?;

        // Materialize target tree into working tree
        for (p, (mode_val, hash)) in &files {
            let abs = repo.workdir.join(p);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent)?;
            }
            let payload = blob::read(&repo.gyt_dir, hash)?;
            fs::write(&abs, &payload)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = if mode_val & 0o111 != 0 {
                    std::fs::Permissions::from_mode(0o755)
                } else {
                    std::fs::Permissions::from_mode(0o644)
                };
                std::fs::set_permissions(&abs, perms)?;
            }
        }
    } else if mode == Mode::Mixed {
        let files = flatten_tree(repo, &target_tree)?;
        let mut idx = Index::new();
        for (p, (mode_val, hash)) in &files {
            idx.insert(IndexEntry {
                ctime_secs: 0,
                mtime_secs: 0,
                size: 0,
                mode: *mode_val,
                hash: *hash,
                path: p.clone(),
            });
        }
        idx.write(&repo.index_path())?;
    }
    // Soft: only ref updated above, index and workdir unchanged
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::hash::ObjectId;
    use crate::object::tree;
    use std::collections::BTreeMap;
    use std::path::Path;

    fn local_flatten_tree(gyt_dir: &Path, tree_id: &ObjectId) -> Result<BTreeMap<String, (u32, ObjectId)>> {
        let mut out = BTreeMap::new();
        walk_tree(gyt_dir, tree_id, "", &mut out)?;
        Ok(out)
    }

    fn walk_tree(
        gyt_dir: &Path,
        tree_id: &ObjectId,
        prefix: &str,
        out: &mut BTreeMap<String, (u32, ObjectId)>,
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
                out.insert(path, (e.mode, e.hash));
            }
        }
        Ok(())
    }

    #[test]
    fn reset_hard_resets_workdir_and_index() {
        let r = TestRepo::new("gyt-reset-hard");
        let repo = r.open();
        let first = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let first_tree = commit::read(&repo.gyt_dir, &first).unwrap().tree;
        let (_, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);

        // Modify workdir to have different content
        let v2_path = repo.workdir.join("hello.txt");
        fs::write(&v2_path, b"latest\n").unwrap();

        run_in(&repo, &["--hard".into(), first.to_hex()]).unwrap();

        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            first
        );
        // Workdir should be reset to first commit content
        let content = fs::read_to_string(&v2_path).unwrap();
        assert_eq!(content, "hello\n");
        // Index should match first tree
        let idx = Index::read(&repo.index_path()).unwrap();
        let want = local_flatten_tree(&repo.gyt_dir, &first_tree).unwrap();
        assert_eq!(idx.entries.len(), want.len());
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
        let (second, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);
        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            second
        );

        let idx_before = Index::read(&repo.index_path()).unwrap();
        run_in(&repo, &["--soft".into(), first.to_hex()]).unwrap();

        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            first
        );
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
        let first_tree = commit::read(&repo.gyt_dir, &first).unwrap().tree;
        let (_, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);

        run_in(&repo, &["--mixed".into(), first.to_hex()]).unwrap();

        assert_eq!(
            refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap(),
            first
        );
        let idx = Index::read(&repo.index_path()).unwrap();
        let want = local_flatten_tree(&repo.gyt_dir, &first_tree).unwrap();
        assert_eq!(idx.entries.len(), want.len());
        for e in &idx.entries {
            let key = e.path.to_string_lossy().into_owned();
            let w = want.get(&key).expect("path in index but not in tree");
            assert_eq!(e.hash, w.1);
            assert_eq!(e.mode, w.0);
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
        let blob_id = crate::object::blob::write(&repo.gyt_dir, b"hello\n").unwrap();
        let err = run_in(&repo, &[blob_id.to_hex()]).unwrap_err();
        match err {
            GytError::InvalidArgument(_) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }
}
