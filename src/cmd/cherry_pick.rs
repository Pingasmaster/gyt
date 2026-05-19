// `gyt cherry-pick <commit>`
//
// Applies the *changes* introduced by <commit> on top of HEAD, using the
// same three-way engine as `gyt merge`:
//   base    = parent of <commit> (or empty tree if root)
//   ours    = HEAD tree
//   theirs  = <commit>'s tree
//
// On a clean merge we create a new commit on HEAD with the merged tree,
// reusing the picked commit's message. On conflicts we write conflict-
// marker files to the workdir and leave `.gyt/CHERRY_PICK_HEAD` plus
// `.gyt/MERGE_MSG` for the user to resolve and re-commit.

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

/// How far back in HEAD's first-parent chain we look for an already-applied
/// equivalent (same tree + same message) before falling through to a fresh
/// cherry-pick. 64 is plenty for any normal workflow without being so large
/// that we walk the entire repo on every pick.
const ANCESTRY_LOOKBACK: usize = 64;

pub fn run(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn print_help() {
    println!("gyt cherry-pick <commit>");
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let _lock = repo.lock()?;
    let mut rev: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("gyt cherry-pick <commit>");
                return Ok(());
            }
            other if !other.starts_with('-') => {
                if rev.is_some() {
                    return Err(GytError::InvalidArgument(
                        "cherry-pick: at most one revision".into(),
                    ));
                }
                rev = Some(other.to_string());
            }
            _ => {
                return Err(GytError::InvalidArgument(format!(
                    "cherry-pick: unknown flag {arg}"
                )));
            }
        }
    }
    let rev = rev
        .ok_or_else(|| GytError::InvalidArgument("cherry-pick: <commit> is required".into()))?;

    let target_id = resolve_rev(repo, &rev)?;
    let target_obj = store::read(&repo.gyt_dir, &target_id)?;
    if target_obj.kind != ObjectKind::Commit {
        return Err(GytError::InvalidArgument(format!(
            "cherry-pick: {rev} is not a commit"
        )));
    }
    let target_commit = commit_obj::read(&repo.gyt_dir, &target_id)?;

    let head = refs::read_head(&repo.gyt_dir)?;
    let head_id = refs::resolve(&repo.gyt_dir, &head)?;

    let head_tree = match head_id {
        Some(id) => commit_obj::read(&repo.gyt_dir, &id)?.tree,
        None => {
            // Unborn HEAD: just adopt the target tree directly.
            apply_tree_directly(repo, &target_commit.tree)?;
            let parents: Vec<ObjectId> = vec![];
            let new_id = make_commit(
                repo,
                target_commit.tree,
                parents,
                target_commit.message.clone(),
            )?;
            return finish(repo, &head, None, new_id, &target_commit.message);
        }
    };

    // Already-applied detection.
    //
    // Walk a short ancestry of HEAD (up to ANCESTRY_LOOKBACK commits) and
    // declare the pick "already applied" if any commit in that window has
    // the same *tree* AND the same *commit message* as the target. The
    // tree match alone is too loose (an empty commit after the same
    // changes would match every commit with the same final tree); the
    // message anchors the comparison to the specific change.
    //
    // NB: the previous heuristic compared `head_commit.authors` to the
    // target's authors, but cherry-pick *rewrites* authors to the picker's
    // identity — so that check could never fire and silently allowed
    // double-picks.
    if let Some(hid) = head_id {
        let mut cur = Some(hid);
        for _ in 0..ANCESTRY_LOOKBACK {
            let Some(id) = cur else { break };
            let c = commit_obj::read(&repo.gyt_dir, &id)?;
            if c.tree == target_commit.tree && c.message == target_commit.message {
                return Err(GytError::Repo(format!(
                    "HEAD ancestry already contains an equivalent commit: {} \"{}\"",
                    &id.to_hex()[..12],
                    target_commit.message.lines().next().unwrap_or("")
                )));
            }
            cur = c.parents.first().copied();
        }
    }

    let base_tree = match target_commit.parents.first() {
        Some(p) => commit_obj::read(&repo.gyt_dir, p)?.tree,
        None => crate::object::tree::write(&repo.gyt_dir, &[])?,
    };
    let theirs_tree = target_commit.tree;

    let base_files = crate::cmd::util::flatten_tree(repo, &base_tree)?;
    let ours_files = crate::cmd::util::flatten_tree(repo, &head_tree)?;
    let theirs_files = crate::cmd::util::flatten_tree(repo, &theirs_tree)?;

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
        // B13: write CHERRY_PICK_HEAD + MERGE_MSG BEFORE we splatter
        // conflict markers across the workdir. Mirrors M3 in
        // cmd/merge.rs — a crash after the markers but before the
        // state files would leave a dirty workdir with no in-progress
        // marker, so `gyt status` reports a clean cherry-pick state
        // while the workdir is half-merged. With this ordering a
        // crash before the state files leaves the workdir untouched.
        // M2: atomic_write so a crash mid-write doesn't tear the state.
        crate::fs_util::atomic_write(
            &repo.gyt_dir.join("CHERRY_PICK_HEAD"),
            format!("{}\n", target_id.to_hex()).as_bytes(),
        )?;
        std::fs::write(repo.gyt_dir.join("MERGE_MSG"), target_commit.message.as_bytes())?;
        apply_files_to_workdir(repo, &tm.merged)?;
        write_index_from_map(repo, &tm.merged)?;
        for (path, bytes) in &conflict_blobs {
            // H5: refuse if any ancestor is a symlink.
            let abs = crate::workdir::safe_workdir_path(&repo.workdir, path)?;
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&abs, bytes)?;
        }
        let conflict_list = tm
            .conflicts
            .iter()
            .map(|c| format!("  {:?}: {}", c.kind, c.path.display()))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(GytError::Repo(format!(
            "cherry-pick: conflicts (left in workdir; resolve and re-commit):\n{conflict_list}"
        )));
    }

    apply_files_to_workdir(repo, &tm.merged)?;
    write_index_from_map(repo, &tm.merged)?;
    let merged_tree_id = write_tree_from_map(repo, &tm.merged)?;

    let parents = head_id.map(|h| vec![h]).unwrap_or_default();
    let new_id = make_commit(repo, merged_tree_id, parents, target_commit.message.clone())?;
    finish(repo, &head, head_id, new_id, &target_commit.message)
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn finish(
    repo: &Repo,
    head: &Head,
    prev: Option<ObjectId>,
    new_id: ObjectId,
    target_msg: &str,
) -> Result<()> {
    let identity = Config::load(repo)
        .ok()
        .and_then(|c| c.identity().ok())
        .unwrap_or_else(|| "-".to_string());
    let first = target_msg.lines().next().unwrap_or("").to_string();
    let log_msg = format!("cherry-pick: {first}");
    match head {
        Head::Symbolic(name) => {
            refs::write_ref(&repo.gyt_dir, name, &new_id)?;
            crate::reflog::record(&repo.gyt_dir, name, prev.as_ref(), &new_id, &identity, &log_msg);
            crate::reflog::record(&repo.gyt_dir, "HEAD", prev.as_ref(), &new_id, &identity, &log_msg);
        }
        Head::Detached(_) => {
            refs::write_head(&repo.gyt_dir, &Head::Detached(new_id))?;
            crate::reflog::record(&repo.gyt_dir, "HEAD", prev.as_ref(), &new_id, &identity, &log_msg);
        }
    }
    let hex = new_id.to_hex();
    let short = &hex[..hex.len().min(8)];
    println!("[{short}] {first}");
    Ok(())
}

fn make_commit(
    repo: &Repo,
    tree: ObjectId,
    parents: Vec<ObjectId>,
    message: String,
) -> Result<ObjectId> {
    let cfg = Config::load(repo)?;
    let identity = cfg.identity()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let stamped = format!("{identity} {now} +0000");
    let c = commit_obj::Commit {
        tree,
        parents,
        authors: vec![stamped.clone()],
        committer: stamped,
        ai_assists: Vec::new(),
        reviewers: Vec::new(),
        signature: None,
        message,
    };
    // C7: honor sign_required.
    let c = crate::cmd::signing::maybe_sign_commit(repo, c, false)?;
    commit_obj::write(&repo.gyt_dir, &c)
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
        // H5: refuse if any ancestor is a symlink.
        let abs = crate::workdir::safe_workdir_path(&repo.workdir, path)?;
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

fn apply_tree_directly(repo: &Repo, tree_id: &ObjectId) -> Result<()> {
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
        crate::workdir::validate_symlink_target(target)?;
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
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::cmd::util::test_helpers::lock;
    use crate::config::Config;
    use std::fs;
    use std::path::Path;

    fn write_identity_config(gyt_dir: &Path) {
        let cfg = Config {
            user_name: Some("Test".into()),
            user_email: Some("t@x".into()),
            ..Config::default()
        };
        cfg.write(gyt_dir).unwrap();
    }

    #[test]
    fn cherry_pick_adds_disjoint_file_cleanly() {
        // Serializes with every other inline cwd-mutating cmd test
        // under `--test-threads=16`.
        let _g = lock();
        let r = TestRepo::new("gyt-cherry-pick-disjoint");
        write_identity_config(&r.gyt_dir());
        let repo = r.open();
        // Branch off feature, add feat.txt, then return to main.
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        crate::cmd::branch::run(&["feature".to_string()]).unwrap();
        crate::cmd::switch::run(&["feature".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("feat.txt"), b"feat\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "feat-commit".to_string()]).unwrap();
        let feat_id = refs::read_ref(&repo.gyt_dir, "refs/heads/feature").unwrap();
        crate::cmd::switch::run(&["main".to_string()]).unwrap();
        // Now cherry-pick the feature commit onto main.
        let result = run_in(&repo, &[feat_id.to_hex()]);
        std::env::set_current_dir(&prev).unwrap();
        result.unwrap();
        // feat.txt should now exist on main.
        let content = fs::read_to_string(repo.workdir.join("feat.txt")).unwrap();
        assert_eq!(content, "feat\n");
        // hello.txt (from initial commit) should still be there.
        let hello = fs::read_to_string(repo.workdir.join("hello.txt")).unwrap();
        assert_eq!(hello, "hello\n");
    }
}
