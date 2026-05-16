use crate::cmd::branch as branch_cmd;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::object::{ObjectKind, blob, commit, store, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    repo.require_worktree()?;
    run_in(&repo, args)
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let _lock = repo.lock()?;
    let mut create = false;
    let mut name: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--create" => {
                create = true;
                i += 1;
                let n = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("switch -c <name>".into()))?;
                name = Some(n.clone());
                i += 1;
            }
            other if !other.starts_with('-') => {
                if name.is_some() {
                    return Err(GytError::InvalidArgument(
                        "switch: too many positional arguments".into(),
                    ));
                }
                name = Some(other.to_string());
                i += 1;
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "switch: unknown option {other}"
                )));
            }
        }
    }
    let branch = name.ok_or_else(|| GytError::InvalidArgument("switch <branch>".into()))?;
    branch_cmd::validate_branch_name(&branch)?;

    if create {
        // create branch at current HEAD
        let head = refs::read_head(&repo.gyt_dir)?;
        let id = refs::resolve(&repo.gyt_dir, &head)?
            .ok_or_else(|| GytError::Refs("HEAD is unborn; cannot create branch".into()))?;
        let ref_name = format!("refs/heads/{branch}");
        if refs::read_ref(&repo.gyt_dir, &ref_name).is_ok() {
            return Err(GytError::Refs(format!("branch {branch} already exists")));
        }
        refs::write_ref(&repo.gyt_dir, &ref_name, &id)?;
    }

    switch_to(repo, &branch)
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn switch_to(repo: &Repo, branch: &str) -> Result<()> {
    let ref_name = format!("refs/heads/{branch}");
    let target_id = refs::read_ref(&repo.gyt_dir, &ref_name)?;
    let target_tree_id = commit_tree(&repo.gyt_dir, &target_id)?;
    let target_files = flatten_tree(&repo.gyt_dir, &target_tree_id)?;

    // Determine which files would be overwritten and check for conflicts.
    let current_head_files = match refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir)?)? {
        Some(cid) => flatten_tree(&repo.gyt_dir, &commit_tree(&repo.gyt_dir, &cid)?)?,
        None => BTreeMap::new(),
    };

    let idx = Index::read(&repo.index_path())?;
    let mut conflicts = Vec::new();
    for path in target_files.keys() {
        let abs = repo.workdir.join(path);
        if !abs.exists() && std::fs::symlink_metadata(&abs).is_err() {
            continue;
        }
        let want = current_head_files.get(path);
        match want {
            Some(want_entry) => {
                let actual = hash_workdir_file(&abs, want_entry.mode)?;
                if actual != want_entry.hash {
                    conflicts.push(path.clone());
                }
            }
            None => {
                if idx.find(Path::new(path)).is_some() {
                    conflicts.push(path.clone());
                } else {
                    let target_entry = &target_files[path];
                    let actual = hash_workdir_file(&abs, target_entry.mode)?;
                    if actual != target_entry.hash {
                        conflicts.push(path.clone());
                    }
                }
            }
        }
    }
    // Files tracked in the current HEAD whose workdir version diverges from
    // HEAD and that won't exist in the target tree would be silently lost
    // by a switch — refuse.
    for (path, want_entry) in &current_head_files {
        if target_files.contains_key(path) {
            continue;
        }
        let abs = repo.workdir.join(path);
        if !abs.exists() && std::fs::symlink_metadata(&abs).is_err() {
            continue;
        }
        let actual = hash_workdir_file(&abs, want_entry.mode)?;
        if actual != want_entry.hash {
            conflicts.push(path.clone());
        }
    }
    if !conflicts.is_empty() {
        conflicts.sort();
        conflicts.dedup();
        return Err(GytError::Repo(format!(
            "switch would overwrite uncommitted changes:\n  {}",
            conflicts.join("\n  ")
        )));
    }

    // Materialize the target tree.
    // 1. Remove tracked files that are not in the new tree.
    for path in current_head_files.keys() {
        if !target_files.contains_key(path) {
            let abs = repo.workdir.join(path);
            if std::fs::symlink_metadata(&abs).is_ok() {
                let _ = std::fs::remove_file(&abs);
            }
        }
    }
    // 2. Write/update files from the new tree.
    for (path, entry) in &target_files {
        let abs = repo.workdir.join(path);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_workdir_entry(&repo.gyt_dir, &abs, entry)?;
    }

    // 3. Replace the index with one matching the new tree.
    let mut new_idx = Index::new();
    for (path, entry) in &target_files {
        new_idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: entry.mode,
            hash: entry.hash,
            path: PathBuf::from(path),
        });
    }
    new_idx.write(&repo.index_path())?;

    // 4. Move HEAD.
    let prev_head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir)?).ok().flatten();
    let new_head_id = refs::read_ref(&repo.gyt_dir, &ref_name).ok();
    refs::write_head(&repo.gyt_dir, &Head::Symbolic(ref_name.clone()))?;
    if let Some(new_id) = new_head_id {
        let identity = crate::config::Config::load(repo)
            .ok()
            .and_then(|c| c.identity().ok())
            .unwrap_or_else(|| "-".to_string());
        let short_branch = ref_name
            .strip_prefix("refs/heads/")
            .unwrap_or(&ref_name);
        let msg = format!("checkout: moving to {short_branch}");
        crate::reflog::record(
            &repo.gyt_dir,
            "HEAD",
            prev_head_id.as_ref(),
            &new_id,
            &identity,
            &msg,
        );
    }
    Ok(())
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

fn commit_tree(gyt_dir: &Path, commit_id: &ObjectId) -> Result<ObjectId> {
    let obj = store::read(gyt_dir, commit_id)?;
    if obj.kind != ObjectKind::Commit {
        return Err(GytError::Object(format!(
            "expected commit, got {}",
            obj.kind.as_str()
        )));
    }
    Ok(commit::decode(&obj.payload)?.tree)
}

fn hash_workdir_file(path: &Path, mode: u32) -> Result<ObjectId> {
    if mode == tree::MODE_SYMLINK {
        let target = std::fs::read_link(path)?;
        let bytes = target.to_string_lossy().into_owned().into_bytes();
        let raw = store::build_raw(ObjectKind::Blob, &bytes);
        Ok(crate::hash::hash_bytes(&raw))
    } else {
        crate::workdir::hash_blob(path)
    }
}

fn write_workdir_entry(gyt_dir: &Path, abs: &Path, entry: &FlatEntry) -> Result<()> {
    let bytes = blob::read(gyt_dir, &entry.hash)?;
    if entry.mode == tree::MODE_SYMLINK {
        let target = std::str::from_utf8(&bytes)
            .map_err(|_| GytError::Object("symlink target is not utf-8".into()))?;
        crate::workdir::validate_symlink_target(target)?;
        let _ = std::fs::remove_file(abs);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, abs)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = target;
            Err(GytError::Unsupported(
                "symlinks not supported on this platform".into(),
            ))
        }
    } else {
        if let Ok(md) = std::fs::symlink_metadata(abs)
            && md.file_type().is_symlink()
        {
            std::fs::remove_file(abs)?;
        }
        std::fs::write(abs, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let want = if entry.mode == tree::MODE_EXEC {
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
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::test_support::TestRepo;

    #[test]
    fn switch_to_existing_updates_head() {
        let r = TestRepo::new("gyt-switch-existing");
        let repo = r.open();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/feature", &head_id).unwrap();

        run_in(&repo, &["feature".into()]).unwrap();
        match refs::read_head(&repo.gyt_dir).unwrap() {
            Head::Symbolic(s) => assert_eq!(s, "refs/heads/feature"),
            other @ Head::Detached(_) => panic!("expected symbolic, got {other:?}"),
        }
    }

    #[test]
    fn switch_creates_with_minus_c() {
        let r = TestRepo::new("gyt-switch-c");
        let repo = r.open();
        run_in(&repo, &["-c".into(), "topic".into()]).unwrap();
        let _ = refs::read_ref(&repo.gyt_dir, "refs/heads/topic").unwrap();
        match refs::read_head(&repo.gyt_dir).unwrap() {
            Head::Symbolic(s) => assert_eq!(s, "refs/heads/topic"),
            other @ Head::Detached(_) => panic!("expected symbolic, got {other:?}"),
        }
    }

    #[test]
    fn switch_refuses_unknown_branch() {
        let r = TestRepo::new("gyt-switch-unknown");
        let repo = r.open();
        let err = run_in(&repo, &["nope".into()]).unwrap_err();
        match err {
            GytError::Refs(_) => {}
            other => panic!("expected Refs error, got {other:?}"),
        }
    }

    #[test]
    fn switch_refuses_dirty_when_overwriting() {
        let r = TestRepo::new("gyt-switch-dirty");
        let repo = r.open();
        // alt branch where hello.txt has different content
        let new_blob = blob::write(&repo.gyt_dir, b"different content\n").unwrap();
        let entries = vec![tree::TreeEntry {
            mode: tree::MODE_FILE,
            name: b"hello.txt".to_vec(),
            hash: new_blob,
        }];
        let new_tree = tree::write(&repo.gyt_dir, &entries).unwrap();
        let parent = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        let c = commit::Commit {
            tree: new_tree,
            parents: vec![parent],
            authors: vec!["T <t@x> 1 +0000".into()],
            committer: "T <t@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "alt\n".into(),
        };
        let cid = commit::write(&repo.gyt_dir, &c).unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/feature", &cid).unwrap();

        // Dirty the workdir.
        std::fs::write(repo.workdir.join("hello.txt"), b"local edits\n").unwrap();

        let err = run_in(&repo, &["feature".into()]).unwrap_err();
        match err {
            GytError::Repo(msg) => assert!(msg.contains("hello.txt"), "msg: {msg}"),
            other => panic!("expected Repo error, got {other:?}"),
        }
    }

    #[test]
    fn switch_materializes_target_tree() {
        let r = TestRepo::new("gyt-switch-mat");
        let repo = r.open();
        let blob1 = blob::write(&repo.gyt_dir, b"alpha\n").unwrap();
        let blob2 = blob::write(&repo.gyt_dir, b"beta\n").unwrap();
        let entries = vec![
            tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"a.txt".to_vec(),
                hash: blob1,
            },
            tree::TreeEntry {
                mode: tree::MODE_FILE,
                name: b"b.txt".to_vec(),
                hash: blob2,
            },
        ];
        let new_tree = tree::write(&repo.gyt_dir, &entries).unwrap();
        let parent = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        let c = commit::Commit {
            tree: new_tree,
            parents: vec![parent],
            authors: vec!["T <t@x> 1 +0000".into()],
            committer: "T <t@x> 1 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "alt\n".into(),
        };
        let cid = commit::write(&repo.gyt_dir, &c).unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/alt", &cid).unwrap();

        run_in(&repo, &["alt".into()]).unwrap();

        assert!(!repo.workdir.join("hello.txt").exists());
        assert_eq!(
            std::fs::read(repo.workdir.join("a.txt")).unwrap(),
            b"alpha\n"
        );
        assert_eq!(
            std::fs::read(repo.workdir.join("b.txt")).unwrap(),
            b"beta\n"
        );
    }
}
