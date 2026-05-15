use crate::errors::{GytError, Result};
use crate::index::{Index, IndexEntry};
use crate::object::blob;
use crate::repo::Repo;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    repo.require_worktree()?;
    run_in(&repo, args)
}

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by `while i < args.len()`; path_args[0] is gated by the `path_args.len() == 1` check"
)]
fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(GytError::InvalidArgument(
            "usage: gyt restore [--staged] [--worktree] [--source=<rev>] <path>...".into(),
        ));
    }
    let mut staged = false;
    let mut worktree = false;
    let mut source: Option<String> = None;
    let mut path_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--staged" => {
                staged = true;
                i += 1;
            }
            "--worktree" | "--w" => {
                worktree = true;
                i += 1;
            }
            "--source" | "-s" => {
                i += 1;
                source = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("--source requires a revision".into())
                        })?
                        .clone(),
                );
                i += 1;
            }
            "--help" | "-h" => {
                println!("gyt restore [--staged] [--worktree] [--source=<rev>] <path>...");
                println!("  --staged       restore from --source (or HEAD) to the index (unstages)");
                println!("  --worktree     restore from --source (or the index) to the working tree (default)");
                println!("  --source <rev> pull blobs from <rev>'s tree instead of HEAD/index");
                println!("  If neither --staged nor --worktree is given, --worktree is implied.");
                println!("  If both are given, both operations are performed.");
                return Ok(());
            }
            arg if arg.starts_with("--source=") => {
                source = Some(arg.trim_start_matches("--source=").to_string());
                i += 1;
            }
            other => {
                path_args.push(other.to_string());
                i += 1;
            }
        }
    }

    // Default to --worktree if neither is given.
    if !staged && !worktree {
        worktree = true;
    }

    if path_args.is_empty() {
        return Err(GytError::InvalidArgument(
            "restore: at least one path required (or '.')".into(),
        ));
    }

    let mut idx = Index::read(&repo.index_path())?;

    // If --source <rev> is given, resolve its tree once and use it as the
    // authoritative source for both --staged and --worktree restores.
    // Otherwise we fall back to HEAD (for --staged) and the index (for
    // --worktree), matching git's defaults.
    let source_tree: Option<std::collections::BTreeMap<PathBuf, (u32, crate::hash::ObjectId)>> =
        if let Some(rev) = &source {
            let id = crate::cmd::util::resolve_rev(repo, rev)?;
            let obj = crate::object::store::read(&repo.gyt_dir, &id)?;
            // Accept either a commit or a raw tree object id.
            let tree_id = match obj.kind {
                crate::object::ObjectKind::Commit => {
                    crate::object::commit::decode(&obj.payload)?.tree
                }
                crate::object::ObjectKind::Tree => id,
                other => {
                    return Err(GytError::InvalidArgument(format!(
                        "restore --source: {rev} is a {} (need commit or tree)",
                        other.as_str()
                    )));
                }
            };
            Some(crate::cmd::util::flatten_tree(repo, &tree_id)?)
        } else {
            None
        };

    let targets: Vec<PathBuf> = if path_args.len() == 1 && path_args[0] == "." {
        // "." means all tracked entries: from the source if given, otherwise
        // from the index.
        if let Some(flat) = &source_tree {
            flat.keys().cloned().collect()
        } else {
            idx.entries.iter().map(|e| e.path.clone()).collect()
        }
    } else {
        path_args.iter().map(PathBuf::from).collect()
    };

    for path in &targets {
        if staged {
            let source_entry = if let Some(flat) = &source_tree {
                flat.get(path).copied()
            } else {
                // Default: HEAD's tree.
                let head = crate::refs::read_head(&repo.gyt_dir)?;
                let head_id = crate::refs::resolve(&repo.gyt_dir, &head)?;
                if let Some(id) = head_id {
                    let c = crate::object::commit::read(&repo.gyt_dir, &id)?;
                    let flat = crate::cmd::util::flatten_tree(repo, &c.tree)?;
                    flat.get(path).copied()
                } else {
                    None
                }
            };
            match source_entry {
                Some((mode, hash)) => {
                    idx.insert(IndexEntry {
                        ctime_secs: 0,
                        mtime_secs: 0,
                        size: 0,
                        mode,
                        hash,
                        path: path.clone(),
                    });
                }
                None => {
                    idx.remove(path);
                }
            }
        }

        if worktree {
            if let Some(flat) = &source_tree {
                // Pull directly from the source tree, bypassing the index.
                let Some((mode, hash)) = flat.get(path).copied() else {
                    eprintln!(
                        "gyt restore: {}: not in source tree, skipping",
                        path.display()
                    );
                    continue;
                };
                let synth = IndexEntry {
                    ctime_secs: 0,
                    mtime_secs: 0,
                    size: 0,
                    mode,
                    hash,
                    path: path.clone(),
                };
                restore_one(repo, &synth)?;
            } else {
                match idx.find(path) {
                    Some(entry) => restore_one(repo, entry)?,
                    None => {
                        eprintln!(
                            "gyt restore: {}: not in the index, skipping",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    if staged {
        idx.write(&repo.index_path())?;
    }

    Ok(())
}

fn restore_one(repo: &Repo, entry: &IndexEntry) -> Result<()> {
    use crate::object::tree;
    let abs = repo.workdir.join(&entry.path);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = blob::read(&repo.gyt_dir, &entry.hash)?;
    if entry.mode == tree::MODE_SYMLINK {
        let target = std::str::from_utf8(&bytes)
            .map_err(|_| GytError::Object("symlink target is not utf-8".into()))?;
        let _ = std::fs::remove_file(&abs);
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &abs)?;
        #[cfg(not(unix))]
        {
            let _ = target;
            return Err(GytError::Unsupported(
                "symlinks not supported on this platform".into(),
            ));
        }
    } else {
        if let Ok(md) = std::fs::symlink_metadata(&abs)
            && md.file_type().is_symlink()
        {
            std::fs::remove_file(&abs)?;
        }
        std::fs::write(&abs, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let want = if entry.mode == tree::MODE_EXEC {
                0o755
            } else {
                0o644
            };
            let mut perms = std::fs::metadata(&abs)?.permissions();
            perms.set_mode(want);
            std::fs::set_permissions(&abs, perms)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::index::Index;
    use crate::refs;

    #[test]
    fn restore_recreates_from_index() {
        let r = TestRepo::new("gyt-restore-rt");
        let repo = r.open();
        let p = repo.workdir.join("hello.txt");
        // Local edit.
        std::fs::write(&p, b"corrupted\n").unwrap();
        run_in(&repo, &["hello.txt".into()]).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello\n");
    }

    #[test]
    fn restore_dot_restores_all_tracked() {
        let r = TestRepo::new("gyt-restore-dot");
        let repo = r.open();
        std::fs::write(repo.workdir.join("hello.txt"), b"junk\n").unwrap();
        run_in(&repo, &[".".into()]).unwrap();
        assert_eq!(
            std::fs::read(repo.workdir.join("hello.txt")).unwrap(),
            b"hello\n"
        );
    }

    #[test]
    fn restore_skips_unknown_paths() {
        let r = TestRepo::new("gyt-restore-skip");
        let repo = r.open();
        // No error, just a warning.
        run_in(&repo, &["nope.txt".into()]).unwrap();
    }

    #[test]
    fn restore_staged_unstages_file() {
        let r = TestRepo::new("gyt-restore-staged");
        let repo = r.open();
        // Modify the index entry for hello.txt (staging a change).
        let mut idx = Index::read(&repo.index_path()).unwrap();
        let orig_entry = idx.find(&PathBuf::from("hello.txt")).unwrap().clone();
        let orig_mode = orig_entry.mode;
        let orig_hash = orig_entry.hash;
        // Change the hash to something else (simulating a staged change).
        idx.insert(IndexEntry {
            mode: orig_entry.mode,
            hash: crate::hash::hash_bytes(b"modified blob"),
            path: orig_entry.path.clone(),
            ..orig_entry
        });
        idx.write(&repo.index_path()).unwrap();

        // Now restore --staged should put the HEAD version back.
        run_in(&repo, &["--staged".into(), "hello.txt".into()]).unwrap();
        let idx2 = Index::read(&repo.index_path()).unwrap();
        let entry2 = idx2.find(&PathBuf::from("hello.txt")).unwrap();
        assert_eq!(entry2.hash, orig_hash, "hash should be restored from HEAD");
        assert_eq!(entry2.mode, orig_mode, "mode should be restored from HEAD");
    }

    #[test]
    fn restore_staged_with_path_not_in_head_removes_from_index() {
        let r = TestRepo::new("gyt-restore-staged-rm");
        let repo = r.open();
        // Add a new file to the index that doesn't exist in HEAD.
        let mut idx = Index::read(&repo.index_path()).unwrap();
        idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: crate::object::tree::MODE_FILE,
            hash: crate::hash::hash_bytes(b"new"),
            path: PathBuf::from("newfile.txt"),
        });
        idx.write(&repo.index_path()).unwrap();

        // Restore --staged should remove it from the index.
        run_in(&repo, &["--staged".into(), "newfile.txt".into()]).unwrap();
        let idx2 = Index::read(&repo.index_path()).unwrap();
        assert!(idx2.find(&PathBuf::from("newfile.txt")).is_none());
    }

    #[test]
    fn restore_staged_and_worktree_both() {
        let r = TestRepo::new("gyt-restore-both");
        let repo = r.open();
        let p = repo.workdir.join("hello.txt");
        // Change worktree.
        std::fs::write(&p, b"worktree change\n").unwrap();
        // Change index.
        let mut idx = Index::read(&repo.index_path()).unwrap();
        let orig_entry = idx.find(&PathBuf::from("hello.txt")).unwrap().clone();
        idx.insert(IndexEntry {
            hash: crate::hash::hash_bytes(b"index change"),
            path: orig_entry.path.clone(),
            ..orig_entry
        });
        idx.write(&repo.index_path()).unwrap();

        // Restore --staged --worktree should restore both.
        run_in(
            &repo,
            &["--staged".into(), "--worktree".into(), "hello.txt".into()],
        )
        .unwrap();
        let idx2 = Index::read(&repo.index_path()).unwrap();
        let entry2 = idx2.find(&PathBuf::from("hello.txt")).unwrap();
        let head = refs::read_head(&repo.gyt_dir).unwrap();
        let head_id = refs::resolve(&repo.gyt_dir, &head).unwrap().unwrap();
        let c = crate::object::commit::read(&repo.gyt_dir, &head_id).unwrap();
        let flat = crate::cmd::util::flatten_tree(&repo, &c.tree).unwrap();
        let (orig_mode, orig_hash) = flat[&PathBuf::from("hello.txt")];
        assert_eq!(entry2.hash, orig_hash);
        assert_eq!(entry2.mode, orig_mode);
        assert_eq!(std::fs::read(&p).unwrap(), b"hello\n");
    }
}
