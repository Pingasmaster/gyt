// `gyt merge --ff-only <rev>`
//
// v1 only supports fast-forward merges. Anything else returns an error
// (no three-way / no-octopus / no-recursive). The semantics:
//   * Resolve `<rev>` to a commit id `target`.
//   * Walk the first-parent chain from `target`. If the current HEAD commit
//     is encountered along the way, the merge is a fast-forward — point
//     HEAD's underlying ref at `target`, materialize the workdir, and
//     replace the index.
//   * If HEAD is unborn (no current commit) we treat the merge as setting
//     the symbolic-HEAD branch to `target` (the clone-init case).
//   * Otherwise the histories diverged and we refuse.

use crate::cmd::util::{flatten_tree, resolve_rev};
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::object::{ObjectKind, blob, commit, store, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

pub(crate) fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut ff_only = false;
    let mut rev: Option<String> = None;
    for a in args {
        match a.as_str() {
            "--ff-only" => ff_only = true,
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "merge: unknown flag {other} (only --ff-only is supported)"
                )));
            }
            other => {
                if rev.is_some() {
                    return Err(GytError::InvalidArgument(
                        "merge: at most one revision argument".into(),
                    ));
                }
                rev = Some(other.to_string());
            }
        }
    }
    if !ff_only {
        return Err(GytError::Unsupported(
            "merge: only --ff-only is supported in v1".into(),
        ));
    }
    let rev = rev.ok_or_else(|| GytError::InvalidArgument("merge --ff-only <rev>".into()))?;
    let target = resolve_rev(repo, &rev)?;

    let head = refs::read_head(&repo.gyt_dir)?;
    let head_id = refs::resolve(&repo.gyt_dir, &head)?;

    match (head_id, &head) {
        (None, Head::Symbolic(name)) => {
            // Unborn — set the underlying ref to target and materialize.
            refs::write_ref(&repo.gyt_dir, name, &target)?;
            materialize_commit(repo, &target)?;
            let branch_label = name
                .strip_prefix("refs/heads/")
                .map(str::to_string)
                .unwrap_or_else(|| name.clone());
            println!(
                "Fast-forward (created): {branch_label} -> {}",
                short(&target)
            );
            Ok(())
        }
        (None, Head::Detached(_)) => {
            // No current commit; just point detached HEAD at target.
            refs::write_head(&repo.gyt_dir, &Head::Detached(target))?;
            materialize_commit(repo, &target)?;
            println!("Fast-forward (detached): -> {}", short(&target));
            Ok(())
        }
        (Some(current), _) => {
            if current == target {
                println!("Already up to date.");
                return Ok(());
            }
            if !is_ancestor(repo, &current, &target)? {
                return Err(GytError::Repo(
                    "merge: cannot fast-forward — divergent histories".into(),
                ));
            }
            // Update underlying ref, materialize, replace index.
            let label = match &head {
                Head::Symbolic(name) => {
                    refs::write_ref(&repo.gyt_dir, name, &target)?;
                    name.strip_prefix("refs/heads/")
                        .map(str::to_string)
                        .unwrap_or_else(|| name.clone())
                }
                Head::Detached(_) => {
                    refs::write_head(&repo.gyt_dir, &Head::Detached(target))?;
                    "HEAD".to_string()
                }
            };
            materialize_commit(repo, &target)?;
            println!(
                "Fast-forward: {label} {}..{}",
                short(&current),
                short(&target)
            );
            Ok(())
        }
    }
}

fn short(id: &ObjectId) -> String {
    let s = id.to_hex();
    s[..12].to_string()
}

/// Walk first-parent chain from `from` toward roots, looking for `ancestor`.
fn is_ancestor(repo: &Repo, ancestor: &ObjectId, from: &ObjectId) -> Result<bool> {
    let mut cur = *from;
    loop {
        if cur == *ancestor {
            return Ok(true);
        }
        let c = commit::read(&repo.gyt_dir, &cur)?;
        match c.parents.first() {
            Some(p) => cur = *p,
            None => return Ok(false),
        }
    }
}

/// Materialize the tree of `commit_id` into the workdir, replacing the index
/// to match. Mirrors the logic in `cmd::switch`. Conflict checks are *not*
/// performed here because fast-forward implies HEAD is an ancestor of target;
/// any locally-modified file relative to HEAD is something the caller is
/// implicitly choosing to overwrite. (v1 simplification — switch refuses
/// dirty-overwrite, but merge --ff-only of a clean tree is the common case
/// and we keep this small.)
pub(crate) fn materialize_commit(repo: &Repo, commit_id: &ObjectId) -> Result<()> {
    let obj = store::read(&repo.gyt_dir, commit_id)?;
    if obj.kind != ObjectKind::Commit {
        return Err(GytError::Object(format!(
            "expected commit, got {}",
            obj.kind.as_str()
        )));
    }
    let c = commit::decode(&obj.payload)?;
    let target_files = flatten_tree(repo, &c.tree)?;

    // Read current index so we can remove tracked files that are gone.
    let idx_path = repo.index_path();
    let cur_index = Index::read(&idx_path)?;

    // 1. Remove tracked files (per current index) not present in target tree.
    for entry in &cur_index.entries {
        if !target_files.contains_key(&entry.path) {
            let abs = repo.workdir.join(&entry.path);
            if std::fs::symlink_metadata(&abs).is_ok() {
                let _ = std::fs::remove_file(&abs);
            }
        }
    }

    // 2. Materialize files from target tree.
    for (path, (mode, hash)) in &target_files {
        let abs = repo.workdir.join(path);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_workdir_entry(&repo.gyt_dir, &abs, *mode, hash)?;
    }

    // 3. Replace the index to match the new tree.
    let mut new_idx = Index::new();
    for (path, (mode, hash)) in &target_files {
        new_idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: *mode,
            hash: *hash,
            path: PathBuf::from(path),
        });
    }
    new_idx.write(&idx_path)?;
    Ok(())
}

fn write_workdir_entry(gyt_dir: &Path, abs: &Path, mode: u32, hash: &ObjectId) -> Result<()> {
    if mode == tree::MODE_SYMLINK {
        let bytes = blob::read(gyt_dir, hash)?;
        let target = std::str::from_utf8(&bytes)
            .map_err(|_| GytError::Object("symlink target is not utf-8".into()))?;
        let _ = std::fs::remove_file(abs);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, abs)?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            let _ = target;
            return Err(GytError::Unsupported(
                "symlinks not supported on this platform".into(),
            ));
        }
    }
    let bytes = blob::read(gyt_dir, hash)?;
    if let Ok(md) = std::fs::symlink_metadata(abs)
        && md.file_type().is_symlink()
    {
        std::fs::remove_file(abs)?;
    }
    std::fs::write(abs, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let want = if mode == tree::MODE_EXEC {
            0o755
        } else {
            0o644
        };
        let mut perms = std::fs::metadata(abs)?.permissions();
        perms.set_mode(want);
        std::fs::set_permissions(abs, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::cmd::util::test_helpers::lock;

    #[test]
    fn ff_advances_to_target() {
        let _g = lock();
        let r = TestRepo::new("gyt-merge-ff");
        let repo = r.open();
        // Build B and C atop the initial commit (A).
        let (b_id, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);
        let (c_id, _) = r.commit_next(&[("hello.txt", b"v3\n", false)]);
        // Capture A from B's first parent.
        let b_commit = commit::read(&repo.gyt_dir, &b_id).unwrap();
        let a_id = b_commit.parents[0];
        // Move main back to A.
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &a_id).unwrap();
        // ff-merge to C should succeed.
        run_in(&repo, &["--ff-only".into(), c_id.to_hex()]).unwrap();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(head_id, c_id);
    }

    #[test]
    fn divergent_refuses() {
        let _g = lock();
        let r = TestRepo::new("gyt-merge-div");
        let repo = r.open();
        let initial = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        // Branch off: D from initial with different content.
        let alt_blob = blob::write(&repo.gyt_dir, b"alt\n").unwrap();
        let alt_tree = tree::write(
            &repo.gyt_dir,
            &[tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"hello.txt".to_vec(),
                hash: alt_blob,
            }],
        )
        .unwrap();
        let d = commit::Commit {
            tree: alt_tree,
            parents: vec![initial],
            authors: vec!["T <t@x> 1 +0000".into()],
            committer: "T <t@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            message: "alt\n".into(),
        };
        let d_id = commit::write(&repo.gyt_dir, &d).unwrap();
        // Move main forward on a different chain (B).
        let _b = r.commit_next(&[("hello.txt", b"v2\n", false)]);

        // Now main is at B; merge D should fail (divergent).
        let err = run_in(&repo, &["--ff-only".into(), d_id.to_hex()]).unwrap_err();
        match err {
            GytError::Repo(msg) => {
                assert!(msg.contains("divergent"), "msg: {msg}");
            }
            other => panic!("expected Repo error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_ff_flag() {
        let _g = lock();
        let r = TestRepo::new("gyt-merge-flag");
        let repo = r.open();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        // No --ff-only.
        let err = run_in(&repo, &[head_id.to_hex()]).unwrap_err();
        match err {
            GytError::Unsupported(_) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
