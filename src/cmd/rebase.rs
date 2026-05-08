use crate::cmd::util::resolve_rev;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::Index;
use crate::index::IndexEntry;
use crate::object::{ObjectKind, blob, commit as commit_obj, store, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::fs;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut ff_only = false;
    let mut upstream: Option<String> = None;
    let mut branch: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt rebase --ff-only <upstream> [<branch>]\n\n\
                     Fast-forward rebase: reapply commits on top of upstream."
                );
                return Ok(());
            }
            "--ff-only" => ff_only = true,
            other if !other.starts_with('-') => {
                if upstream.is_none() {
                    upstream = Some(other.to_string());
                } else if branch.is_none() {
                    branch = Some(other.to_string());
                }
            }
            _ => {
                return Err(GytError::InvalidArgument(format!(
                    "rebase: unknown flag {}",
                    args[i]
                )));
            }
        }
        i += 1;
    }

    if !ff_only {
        return Err(GytError::Unsupported(
            "rebase: only --ff-only is supported in v1".into(),
        ));
    }

    let upstream_rev = upstream.ok_or_else(|| {
        GytError::InvalidArgument("rebase --ff-only: <upstream> is required".into())
    })?;

    let target_id = resolve_rev(repo, &upstream_rev)?;
    let target_obj = store::read(&repo.gyt_dir, &target_id)?;
    if target_obj.kind != ObjectKind::Commit {
        return Err(GytError::InvalidArgument(format!(
            "rebase: {upstream_rev} is not a commit"
        )));
    }

    let head = refs::read_head(&repo.gyt_dir)?;
    let head_ref = match &head {
        Head::Symbolic(name) => name.clone(),
        Head::Detached(_) => {
            return Err(GytError::Refs(
                "rebase does not support detached HEAD".into(),
            ));
        }
    };

    let current_id = refs::resolve(&repo.gyt_dir, &head)?;

    // Fast-forward only: if current is an ancestor of target, just move HEAD
    if let Some(current) = current_id {
        // Check if current is ancestor of target by walking target's parents
        if is_ancestor(&repo.gyt_dir, &current, &target_id)? {
            refs::write_ref(&repo.gyt_dir, &head_ref, &target_id)?;
            let hex = &target_id.to_hex()[..8];
            println!("Fast-forwarded {head_ref} to {hex}");
            return Ok(());
        }
        return Err(GytError::Unsupported(
            "rebase: current branch is not an ancestor of upstream (no three-way rebase in v1)"
                .into(),
        ));
    }
    // Unborn HEAD: just point at target
    refs::write_ref(&repo.gyt_dir, &head_ref, &target_id)?;
    let hex = &target_id.to_hex()[..8];
    println!("Created {head_ref} at {hex}");

    // Also update working tree to match target
    let target_commit = commit_obj::read(&repo.gyt_dir, &target_id)?;
    let files = flatten_tree(&repo.gyt_dir, &target_commit.tree)?;

    // Update index
    let mut idx = Index::new();
    for (p, e) in &files {
        idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: e.mode,
            hash: e.hash,
            path: PathBuf::from(p),
        });
    }
    idx.write(&repo.index_path())?;

    // Update working tree
    for (p, e) in &files {
        let abs = repo.workdir.join(p);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        let payload = blob::read(&repo.gyt_dir, &e.hash)?;
        fs::write(&abs, &payload)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = if e.mode & 0o111 != 0 {
                std::fs::Permissions::from_mode(0o755)
            } else {
                std::fs::Permissions::from_mode(0o644)
            };
            std::fs::set_permissions(&abs, perms)?;
        }
    }

    Ok(())
}

fn is_ancestor(
    gyt_dir: &std::path::Path,
    ancestor: &ObjectId,
    descendant: &ObjectId,
) -> Result<bool> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut stack = vec![*descendant];

    while let Some(id) = stack.pop() {
        if id == *ancestor {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        let obj = store::read(gyt_dir, &id)?;
        if obj.kind == ObjectKind::Commit {
            let commit = commit_obj::read(gyt_dir, &id)?;
            for parent in &commit.parents {
                stack.push(*parent);
            }
        }
    }

    Ok(false)
}

#[derive(Debug, Clone)]
struct FlatEntry {
    mode: u32,
    hash: ObjectId,
}

fn flatten_tree(
    gyt_dir: &std::path::Path,
    tree_id: &ObjectId,
) -> Result<std::collections::BTreeMap<String, FlatEntry>> {
    let mut out = std::collections::BTreeMap::new();
    walk_tree(gyt_dir, tree_id, "", &mut out)?;
    Ok(out)
}

fn walk_tree(
    gyt_dir: &std::path::Path,
    tree_id: &ObjectId,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, FlatEntry>,
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
    fn rebase_rejects_without_ff_only() {
        let r = TestRepo::new("gyt-rebase-no-ff");
        let repo = r.open();
        let err = run_in(&repo, &["main".into()]).unwrap_err();
        match err {
            GytError::Unsupported(_) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn rebase_ff_only_works() {
        let r = TestRepo::new("gyt-rebase-ff");
        let mut repo = r.open();
        let main_id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();

        // Create a branch from main
        refs::write_ref(&repo.gyt_dir, "refs/heads/feature", &main_id).unwrap();

        // Advance main with a new commit
        let (main_id_v2, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);

        // Reopen to see the new state and switch HEAD to feature
        repo = Repo::open(&r.root).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();

        // Switch HEAD to feature branch
        refs::write_head(&repo.gyt_dir, &Head::Symbolic("refs/heads/feature".into())).unwrap();

        // Now rebase feature onto main
        let result = run_in(&repo, &["--ff-only".into(), "main".into()]);
        std::env::set_current_dir(&prev).unwrap();

        result.unwrap();

        // Verify feature now points to main's commit
        let feature_id = refs::read_ref(&repo.gyt_dir, "refs/heads/feature").unwrap();
        assert_eq!(feature_id, main_id_v2);
    }
}
