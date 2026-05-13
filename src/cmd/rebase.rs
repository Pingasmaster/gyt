// `gyt rebase <upstream>`
//
// Replays commits from `merge_base(HEAD, <upstream>)..HEAD` on top of
// <upstream>. Three-way merges each commit's changes against the new base.
//
// Modes:
//   * `--ff-only` — refuse if not a fast-forward (no replay required).
//   * `--abort`   — discard a rebase that left the repo with conflicts.
//   * default     — replay; on conflict, write conflict markers, drop the
//                   `.gyt/REBASE_HEAD` + `REBASE_TODO` state, and exit. The
//                   user resolves and re-runs `gyt rebase --continue`
//                   (TODO: not implemented yet — the user can resolve and
//                   run `gyt commit` then re-run `gyt rebase` for the
//                   remaining commits).

use crate::cmd::util::resolve_rev;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::merge3;
use crate::object::{ObjectKind, blob, commit as commit_obj, store, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut ff_only = false;
    let mut upstream: Option<String> = None;
    let mut abort = false;

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt rebase [--ff-only] [--abort] <upstream>\n\n\
                     Replay commits from merge-base..HEAD on top of <upstream>."
                );
                return Ok(());
            }
            "--ff-only" => ff_only = true,
            "--abort" => abort = true,
            other if !other.starts_with('-') => {
                if upstream.is_some() {
                    return Err(GytError::InvalidArgument(
                        "rebase: at most one upstream".into(),
                    ));
                }
                upstream = Some(other.to_string());
            }
            _ => {
                return Err(GytError::InvalidArgument(format!(
                    "rebase: unknown flag {arg}"
                )));
            }
        }
    }

    if abort {
        return run_abort(repo);
    }

    let upstream_rev = upstream
        .ok_or_else(|| GytError::InvalidArgument("rebase: <upstream> is required".into()))?;

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
    let Some(current) = current_id else {
        // Unborn HEAD: point at upstream.
        refs::write_ref(&repo.gyt_dir, &head_ref, &target_id)?;
        materialize_tree(repo, &commit_obj::read(&repo.gyt_dir, &target_id)?.tree)?;
        println!("Created {head_ref} at {}", short(&target_id));
        return Ok(());
    };

    if current == target_id {
        println!("Already up to date.");
        return Ok(());
    }

    // Fast-forward fast path.
    if is_ancestor(repo, &current, &target_id)? {
        refs::write_ref(&repo.gyt_dir, &head_ref, &target_id)?;
        materialize_tree(repo, &commit_obj::read(&repo.gyt_dir, &target_id)?.tree)?;
        let identity = identity_for(repo);
        let msg = format!("rebase: ff -> {}", short(&target_id));
        crate::reflog::record(
            &repo.gyt_dir,
            &head_ref,
            Some(&current),
            &target_id,
            &identity,
            &msg,
        );
        crate::reflog::record(
            &repo.gyt_dir,
            "HEAD",
            Some(&current),
            &target_id,
            &identity,
            &msg,
        );
        println!("Fast-forwarded {head_ref} to {}", short(&target_id));
        return Ok(());
    }

    if ff_only {
        return Err(GytError::Repo(
            "rebase --ff-only: current is not an ancestor of upstream".into(),
        ));
    }

    // Find merge base; collect HEAD..base in oldest-first order.
    let base = super::merge::merge_base(repo, &current, &target_id)?.ok_or_else(|| {
        GytError::Repo("rebase: no common ancestor between HEAD and upstream".into())
    })?;
    let commits = commits_between(repo, &base, &current)?;

    if commits.is_empty() {
        // Nothing to replay; just take upstream.
        refs::write_ref(&repo.gyt_dir, &head_ref, &target_id)?;
        materialize_tree(repo, &commit_obj::read(&repo.gyt_dir, &target_id)?.tree)?;
        return Ok(());
    }

    // Move HEAD to upstream as the new base.
    let mut cursor = target_id;
    materialize_tree(repo, &commit_obj::read(&repo.gyt_dir, &cursor)?.tree)?;

    for (idx, c) in commits.iter().enumerate() {
        let pc = commit_obj::read(&repo.gyt_dir, c)?;
        let base_tree = match pc.parents.first() {
            Some(p) => commit_obj::read(&repo.gyt_dir, p)?.tree,
            None => tree::write(&repo.gyt_dir, &[])?,
        };
        let cursor_tree = commit_obj::read(&repo.gyt_dir, &cursor)?.tree;
        let base_files = crate::cmd::util::flatten_tree(repo, &base_tree)?;
        let ours_files = crate::cmd::util::flatten_tree(repo, &cursor_tree)?;
        let theirs_files = crate::cmd::util::flatten_tree(repo, &pc.tree)?;

        let mut conflict_blobs: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
        let tm = merge3::merge_trees(&base_files, &ours_files, &theirs_files, |path, ours, theirs, base| {
            let ob = blob::read(&repo.gyt_dir, ours.1).unwrap_or_default();
            let tb = blob::read(&repo.gyt_dir, theirs.1).unwrap_or_default();
            let bb = match base {
                Some((_, h)) => blob::read(&repo.gyt_dir, h).unwrap_or_default(),
                None => Vec::new(),
            };
            let merged = merge3::merge_lines(&bb, &ob, &tb);
            if merged.clean {
                let bytes = merge3::render_with_markers(&merged, "ours", "theirs");
                match blob::write(&repo.gyt_dir, &bytes) {
                    Ok(h) => merge3::ContentResult::Resolved(h),
                    Err(_) => merge3::ContentResult::Conflict {
                        ours_hash: *ours.1,
                        theirs_hash: *theirs.1,
                    },
                }
            } else {
                let bytes = merge3::render_with_markers(&merged, "HEAD", "picked");
                conflict_blobs.insert(path.clone(), bytes);
                merge3::ContentResult::Conflict {
                    ours_hash: *ours.1,
                    theirs_hash: *theirs.1,
                }
            }
        });

        if !tm.conflicts.is_empty() {
            // Apply merged + markers, leave rebase state.
            apply_files_to_workdir(repo, &tm.merged)?;
            write_index_from_map(repo, &tm.merged)?;
            for (path, bytes) in &conflict_blobs {
                let abs = repo.workdir.join(path);
                if let Some(parent) = abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&abs, bytes)?;
            }
            let remaining: Vec<String> = commits
                .iter()
                .skip(idx + 1)
                .map(|c| c.to_hex())
                .collect();
            std::fs::write(
                repo.gyt_dir.join("REBASE_HEAD"),
                format!("{}\n", current.to_hex()),
            )?;
            std::fs::write(
                repo.gyt_dir.join("REBASE_ONTO"),
                format!("{}\n", target_id.to_hex()),
            )?;
            std::fs::write(repo.gyt_dir.join("REBASE_TODO"), remaining.join("\n"))?;
            return Err(GytError::Repo(format!(
                "rebase: conflicts replaying {}. Resolve files and re-commit, then run `gyt rebase --abort` to give up.",
                short(c)
            )));
        }

        apply_files_to_workdir(repo, &tm.merged)?;
        write_index_from_map(repo, &tm.merged)?;
        let new_tree = write_tree_from_map(repo, &tm.merged)?;
        let identity = identity_for(repo);
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let stamped = format!("{identity} {secs} +0000");
        let new_commit = commit_obj::Commit {
            tree: new_tree,
            parents: vec![cursor],
            authors: vec![stamped.clone()],
            committer: stamped,
            ai_assists: pc.ai_assists.clone(),
            reviewers: pc.reviewers.clone(),
            signature: None,
            message: pc.message.clone(),
        };
        let new_id = commit_obj::write(&repo.gyt_dir, &new_commit)?;
        cursor = new_id;
    }

    refs::write_ref(&repo.gyt_dir, &head_ref, &cursor)?;
    let identity = identity_for(repo);
    let msg = format!("rebase: {} commits onto {}", commits.len(), short(&target_id));
    crate::reflog::record(
        &repo.gyt_dir,
        &head_ref,
        Some(&current),
        &cursor,
        &identity,
        &msg,
    );
    crate::reflog::record(
        &repo.gyt_dir,
        "HEAD",
        Some(&current),
        &cursor,
        &identity,
        &msg,
    );
    println!("Rebased {} commits onto {}", commits.len(), short(&target_id));
    Ok(())
}

fn run_abort(repo: &Repo) -> Result<()> {
    let head_path = repo.gyt_dir.join("REBASE_HEAD");
    if !head_path.exists() {
        return Err(GytError::Repo("no rebase in progress".into()));
    }
    let prev_hex = std::fs::read_to_string(&head_path)?;
    let prev = ObjectId::from_hex(prev_hex.trim())?;
    let head = refs::read_head(&repo.gyt_dir)?;
    if let Head::Symbolic(name) = &head {
        refs::write_ref(&repo.gyt_dir, name, &prev)?;
        materialize_tree(repo, &commit_obj::read(&repo.gyt_dir, &prev)?.tree)?;
    }
    let _ = std::fs::remove_file(&head_path);
    let _ = std::fs::remove_file(repo.gyt_dir.join("REBASE_ONTO"));
    let _ = std::fs::remove_file(repo.gyt_dir.join("REBASE_TODO"));
    println!("Rebase aborted; HEAD restored to {}", short(&prev));
    Ok(())
}

fn identity_for(repo: &Repo) -> String {
    Config::load(repo)
        .ok()
        .and_then(|c| c.identity().ok())
        .unwrap_or_else(|| "-".to_string())
}

fn short(id: &ObjectId) -> String {
    let s = id.to_hex();
    s[..s.len().min(12)].to_string()
}

/// Commits reachable from `tip` but not from `base`, in oldest-first order
/// suitable for replay.
fn commits_between(repo: &Repo, base: &ObjectId, tip: &ObjectId) -> Result<Vec<ObjectId>> {
    use std::collections::HashSet;
    let mut excluded: HashSet<ObjectId> = HashSet::new();
    {
        let mut stack = vec![*base];
        while let Some(id) = stack.pop() {
            if !excluded.insert(id) {
                continue;
            }
            if let Ok(c) = commit_obj::read(&repo.gyt_dir, &id) {
                for p in c.parents {
                    stack.push(p);
                }
            }
        }
    }
    let mut newest_first: Vec<ObjectId> = Vec::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut stack = vec![*tip];
    while let Some(id) = stack.pop() {
        if excluded.contains(&id) {
            continue;
        }
        if !seen.insert(id) {
            continue;
        }
        let c = match commit_obj::read(&repo.gyt_dir, &id) {
            Ok(c) => c,
            Err(_) => continue,
        };
        newest_first.push(id);
        for p in c.parents {
            stack.push(p);
        }
    }
    newest_first.reverse();
    Ok(newest_first)
}

fn is_ancestor(repo: &Repo, ancestor: &ObjectId, from: &ObjectId) -> Result<bool> {
    super::merge::is_ancestor(repo, ancestor, from)
}

fn apply_files_to_workdir(repo: &Repo, merged: &BTreeMap<PathBuf, (u32, ObjectId)>) -> Result<()> {
    let cur_index = Index::read(&repo.index_path())?;
    for entry in &cur_index.entries {
        if !merged.contains_key(&entry.path) {
            let abs = repo.workdir.join(&entry.path);
            if std::fs::symlink_metadata(&abs).is_ok() {
                let _ = std::fs::remove_file(&abs);
            }
        }
    }
    for (path, (mode, hash)) in merged {
        let abs = repo.workdir.join(path);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_workdir_entry(&repo.gyt_dir, &abs, *mode, hash)?;
    }
    Ok(())
}

fn write_index_from_map(repo: &Repo, merged: &BTreeMap<PathBuf, (u32, ObjectId)>) -> Result<()> {
    let mut idx = Index::new();
    for (path, (mode, hash)) in merged {
        idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: *mode,
            hash: *hash,
            path: path.clone(),
        });
    }
    idx.write(&repo.index_path())?;
    Ok(())
}

fn write_tree_from_map(
    repo: &Repo,
    merged: &BTreeMap<PathBuf, (u32, ObjectId)>,
) -> Result<ObjectId> {
    let mut idx = Index::new();
    for (path, (mode, hash)) in merged {
        idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: *mode,
            hash: *hash,
            path: path.clone(),
        });
    }
    crate::cmd::util::build_tree_from_index(repo, &idx)
}

fn materialize_tree(repo: &Repo, tree_id: &ObjectId) -> Result<()> {
    let files = crate::cmd::util::flatten_tree(repo, tree_id)?;
    apply_files_to_workdir(repo, &files)?;
    write_index_from_map(repo, &files)?;
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

    #[test]
    fn rebase_ff_only_works() {
        let r = TestRepo::new("gyt-rebase-ff");
        let mut repo = r.open();
        let main_id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/feature", &main_id).unwrap();
        let (main_id_v2, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);
        repo = Repo::open(&r.root).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        refs::write_head(&repo.gyt_dir, &Head::Symbolic("refs/heads/feature".into())).unwrap();
        let result = run_in(&repo, &["--ff-only".into(), "main".into()]);
        std::env::set_current_dir(&prev).unwrap();
        result.unwrap();
        let feature_id = refs::read_ref(&repo.gyt_dir, "refs/heads/feature").unwrap();
        assert_eq!(feature_id, main_id_v2);
    }

    #[test]
    fn rebase_replays_commits_on_divergent_history() {
        let r = TestRepo::new("gyt-rebase-replay");
        let repo = r.open();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(&repo.gyt_dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        crate::cmd::branch::run(&["feature".to_string()]).unwrap();
        crate::cmd::switch::run(&["feature".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("feat.txt"), b"feat\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "feat-commit".to_string()]).unwrap();
        crate::cmd::switch::run(&["main".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("main2.txt"), b"main2\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "main2".to_string()]).unwrap();
        crate::cmd::switch::run(&["feature".to_string()]).unwrap();
        let res = run_in(&repo, &["main".into()]);
        std::env::set_current_dir(&prev).unwrap();
        res.expect("rebase clean");
        assert!(repo.workdir.join("feat.txt").exists());
        assert!(repo.workdir.join("main2.txt").exists());
    }
}
