// `gyt merge [<rev>] [--ff-only] [--no-ff]`
//
// Three modes:
//   1. Fast-forward when possible (HEAD is an ancestor of `<rev>`).
//   2. `--ff-only` forces fast-forward and refuses divergent histories.
//   3. Otherwise: real three-way merge using `merge3`. Finds the merge base
//      (LCA in the parent DAG), merges base/ours/theirs trees file by file,
//      runs line-level merge on overlapping edits, and either creates a
//      merge commit or leaves the repo in a "merging" state with conflict
//      markers in the workdir and `.gyt/MERGE_HEAD` + `.gyt/MERGE_MSG`
//      written for follow-up resolution.
//
// Mode collisions, add/add with different content, and modify/delete are
// surfaced as conflicts the user must resolve manually.

use crate::cmd::util::{flatten_tree, resolve_rev};
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::merge3;
use crate::object::{ObjectKind, blob, commit, store, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

pub fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut ff_only = false;
    let mut no_ff = false;
    let mut message: Option<String> = None;
    let mut rev: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ff-only" => ff_only = true,
            "--no-ff" => no_ff = true,
            "-m" | "--message" => {
                i += 1;
                message = Some(
                    args.get(i)
                        .ok_or_else(|| GytError::InvalidArgument("-m needs a value".into()))?
                        .clone(),
                );
            }
            "-h" | "--help" => {
                println!(
                    "gyt merge [<rev>] [--ff-only] [--no-ff] [-m <msg>]\n\n\
                     Merge <rev> into HEAD. Without --ff-only, falls back to a real \
                     three-way merge when histories have diverged."
                );
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "merge: unknown flag {other}"
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
        i += 1;
    }

    if ff_only && no_ff {
        return Err(GytError::InvalidArgument(
            "merge: --ff-only and --no-ff are mutually exclusive".into(),
        ));
    }

    let rev = rev.ok_or_else(|| GytError::InvalidArgument("merge: <rev> required".into()))?;
    let target = resolve_rev(repo, &rev)?;

    let head = refs::read_head(&repo.gyt_dir)?;
    let head_id = refs::resolve(&repo.gyt_dir, &head)?;

    let identity = crate::config::Config::load(repo)
        .ok()
        .and_then(|c| c.identity().ok())
        .unwrap_or_else(|| "-".to_string());

    // Unborn HEAD: anything is a fast-forward "creation".
    if head_id.is_none() {
        return ff_fast_forward(repo, &head, None, &target, &identity);
    }
    let current = head_id.unwrap();

    if current == target {
        println!("Already up to date.");
        return Ok(());
    }

    let already = is_ancestor(repo, &target, &current)?;
    if already {
        println!("Already up to date.");
        return Ok(());
    }

    let target_is_descendant = is_ancestor(repo, &current, &target)?;
    if target_is_descendant && !no_ff {
        return ff_fast_forward(repo, &head, Some(current), &target, &identity);
    }
    if ff_only {
        return Err(GytError::Repo(
            "merge: cannot fast-forward — divergent histories (rerun without --ff-only)".into(),
        ));
    }

    // Real three-way merge.
    three_way_merge(
        repo,
        &head,
        current,
        target,
        message.unwrap_or_else(|| format!("Merge {} into HEAD", short(&target))),
        &identity,
    )
}

fn ff_fast_forward(
    repo: &Repo,
    head: &Head,
    current: Option<ObjectId>,
    target: &ObjectId,
    identity: &str,
) -> Result<()> {
    let msg = format!("merge: fast-forward -> {}", short(target));
    match head {
        Head::Symbolic(name) => {
            refs::write_ref(&repo.gyt_dir, name, target)?;
            crate::reflog::record(
                &repo.gyt_dir,
                name,
                current.as_ref(),
                target,
                identity,
                &msg,
            );
            crate::reflog::record(
                &repo.gyt_dir,
                "HEAD",
                current.as_ref(),
                target,
                identity,
                &msg,
            );
            materialize_commit(repo, target)?;
            let label = name
                .strip_prefix("refs/heads/").map_or_else(|| name.clone(), str::to_string);
            match current {
                Some(c) => println!(
                    "Fast-forward: {label} {}..{}",
                    short(&c),
                    short(target)
                ),
                None => println!("Fast-forward (created): {label} -> {}", short(target)),
            }
        }
        Head::Detached(_) => {
            refs::write_head(&repo.gyt_dir, &Head::Detached(*target))?;
            crate::reflog::record(
                &repo.gyt_dir,
                "HEAD",
                current.as_ref(),
                target,
                identity,
                &msg,
            );
            materialize_commit(repo, target)?;
            match current {
                Some(c) => println!(
                    "Fast-forward (detached): {}..{}",
                    short(&c),
                    short(target)
                ),
                None => println!("Fast-forward (detached): -> {}", short(target)),
            }
        }
    }
    Ok(())
}

fn three_way_merge(
    repo: &Repo,
    head: &Head,
    ours: ObjectId,
    theirs: ObjectId,
    message: String,
    identity: &str,
) -> Result<()> {
    let base = merge_base(repo, &ours, &theirs)?
        .ok_or_else(|| GytError::Repo("merge: no common ancestor between HEAD and target".into()))?;

    let base_tree = commit::read(&repo.gyt_dir, &base)?.tree;
    let ours_tree = commit::read(&repo.gyt_dir, &ours)?.tree;
    let theirs_tree = commit::read(&repo.gyt_dir, &theirs)?.tree;

    let base_files = flatten_tree(repo, &base_tree)?;
    let ours_files = flatten_tree(repo, &ours_tree)?;
    let theirs_files = flatten_tree(repo, &theirs_tree)?;

    // Run the tree-level merge with a content resolver that invokes the
    // line-level engine and writes the resulting blob (clean or with
    // markers) into the object store.
    let mut conflicted_paths: Vec<(PathBuf, ConflictRender)> = Vec::new();
    let tm = merge3::merge_trees(&base_files, &ours_files, &theirs_files, |path, ours, theirs, base| {
        // Try a line-level merge of the three blobs.
        let ob = match blob::read(&repo.gyt_dir, ours.1) {
            Ok(b) => b,
            Err(_) => return merge3::ContentResult::Conflict {
                ours_hash: *ours.1,
                theirs_hash: *theirs.1,
            },
        };
        let tb = match blob::read(&repo.gyt_dir, theirs.1) {
            Ok(b) => b,
            Err(_) => return merge3::ContentResult::Conflict {
                ours_hash: *ours.1,
                theirs_hash: *theirs.1,
            },
        };
        let bb = match base {
            Some((_, h)) => blob::read(&repo.gyt_dir, h).unwrap_or_default(),
            None => Vec::new(),
        };
        let merged = merge3::merge_lines(&bb, &ob, &tb);
        let bytes = merge3::render_with_markers(&merged, "ours", "theirs");
        if merged.clean {
            match blob::write(&repo.gyt_dir, &bytes) {
                Ok(h) => merge3::ContentResult::Resolved(h),
                Err(_) => merge3::ContentResult::Conflict {
                    ours_hash: *ours.1,
                    theirs_hash: *theirs.1,
                },
            }
        } else {
            // Stash the rendered bytes (with markers) for writing into the
            // workdir later.
            let _ = path;
            conflicted_paths.push((path.clone(), ConflictRender::Content(bytes)));
            merge3::ContentResult::Conflict {
                ours_hash: *ours.1,
                theirs_hash: *theirs.1,
            }
        }
    });

    let has_tree_conflict = !tm.conflicts.is_empty();
    if has_tree_conflict {
        // Apply the clean parts (merged map) to the workdir + index. For
        // conflicted entries, write the rendered marker text (when
        // available) or fall back to "ours". Leave MERGE_HEAD/MERGE_MSG so
        // a follow-up `commit` records the merge.
        apply_files_to_workdir(repo, &tm.merged)?;
        write_index_from_map(repo, &tm.merged)?;
        for (path, render) in &conflicted_paths {
            let abs = repo.workdir.join(path);
            if let Some(parent) = abs.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match render {
                ConflictRender::Content(bytes) => std::fs::write(&abs, bytes)?,
            }
        }
        std::fs::write(
            repo.gyt_dir.join("MERGE_HEAD"),
            format!("{}\n", theirs.to_hex()).as_bytes(),
        )?;
        std::fs::write(repo.gyt_dir.join("MERGE_MSG"), message.as_bytes())?;
        let conflict_list = tm
            .conflicts
            .iter()
            .map(|c| format!("  {:?}: {}", c.kind, c.path.display()))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(GytError::Repo(format!(
            "merge: conflicts (left in workdir; resolve and re-commit):\n{conflict_list}"
        )));
    }

    // Clean merge — create the merge commit and advance HEAD.
    apply_files_to_workdir(repo, &tm.merged)?;
    write_index_from_map(repo, &tm.merged)?;

    // Reuse a tree id by writing the merged tree.
    let merged_tree_id = write_tree_from_map(repo, &tm.merged)?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let stamped = format!("{identity} {secs} +0000");
    let merge_commit = commit::Commit {
        tree: merged_tree_id,
        parents: vec![ours, theirs],
        authors: vec![stamped.clone()],
        committer: stamped,
        ai_assists: vec![],
        reviewers: vec![],
        signature: None,
        message,
    };
    let merge_id = commit::write(&repo.gyt_dir, &merge_commit)?;

    let msg = format!("merge: -> {}", short(&merge_id));
    match head {
        Head::Symbolic(name) => {
            refs::write_ref(&repo.gyt_dir, name, &merge_id)?;
            crate::reflog::record(&repo.gyt_dir, name, Some(&ours), &merge_id, identity, &msg);
            crate::reflog::record(&repo.gyt_dir, "HEAD", Some(&ours), &merge_id, identity, &msg);
        }
        Head::Detached(_) => {
            refs::write_head(&repo.gyt_dir, &Head::Detached(merge_id))?;
            crate::reflog::record(&repo.gyt_dir, "HEAD", Some(&ours), &merge_id, identity, &msg);
        }
    }
    println!(
        "Merge: {}..{} (base {}) -> {}",
        short(&ours),
        short(&theirs),
        short(&base),
        short(&merge_id)
    );
    Ok(())
}

enum ConflictRender {
    /// Marker-rendered bytes — write straight into the workdir.
    Content(Vec<u8>),
}

fn short(id: &ObjectId) -> String {
    let s = id.to_hex();
    s[..s.len().min(12)].to_string()
}

/// Walk first-parent chain (and all parents) from `from` looking for `ancestor`.
pub fn is_ancestor(repo: &Repo, ancestor: &ObjectId, from: &ObjectId) -> Result<bool> {
    if ancestor == from {
        return Ok(true);
    }
    let mut stack = vec![*from];
    let mut seen: HashSet<ObjectId> = HashSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if id == *ancestor {
            return Ok(true);
        }
        let c = match commit::read(&repo.gyt_dir, &id) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for p in c.parents {
            stack.push(p);
        }
    }
    Ok(false)
}

/// Find a merge base (lowest common ancestor) between two commits. Walks
/// both ancestries breadth-first; returns the first commit encountered that
/// is reachable from both, which is a "best" base in the absence of
/// criss-cross merges (good enough for typical workflows).
pub fn merge_base(
    repo: &Repo,
    a: &ObjectId,
    b: &ObjectId,
) -> Result<Option<ObjectId>> {
    let a_anc = ancestors_inclusive(repo, a);
    let mut queue = VecDeque::from([*b]);
    let mut seen: HashSet<ObjectId> = HashSet::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        if a_anc.contains(&id) {
            return Ok(Some(id));
        }
        if let Ok(c) = commit::read(&repo.gyt_dir, &id) {
            for p in c.parents {
                queue.push_back(p);
            }
        }
    }
    Ok(None)
}

fn ancestors_inclusive(repo: &Repo, id: &ObjectId) -> HashSet<ObjectId> {
    let mut out: HashSet<ObjectId> = HashSet::new();
    let mut stack = vec![*id];
    while let Some(cur) = stack.pop() {
        if !out.insert(cur) {
            continue;
        }
        if let Ok(c) = commit::read(&repo.gyt_dir, &cur) {
            for p in c.parents {
                stack.push(p);
            }
        }
    }
    out
}

fn apply_files_to_workdir(
    repo: &Repo,
    merged: &BTreeMap<PathBuf, (u32, ObjectId)>,
) -> Result<()> {
    // Drop tracked files that aren't in the merge result.
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

fn write_index_from_map(
    repo: &Repo,
    merged: &BTreeMap<PathBuf, (u32, ObjectId)>,
) -> Result<()> {
    let mut new_idx = Index::new();
    for (path, (mode, hash)) in merged {
        new_idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: *mode,
            hash: *hash,
            path: path.clone(),
        });
    }
    new_idx.write(&repo.index_path())?;
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
    // Reuse the same tree-builder that `commit` uses, by walking through
    // the helper exposed in `util`.
    crate::cmd::util::build_tree_from_index(repo, &idx)
}

/// Materialize the tree of `commit_id` into the workdir, replacing the index
/// to match. Mirrors the logic in `cmd::switch`. Conflict checks are *not*
/// performed here because fast-forward implies HEAD is an ancestor of target;
/// any locally-modified file relative to HEAD is something the caller is
/// implicitly choosing to overwrite. (v1 simplification — switch refuses
/// dirty-overwrite, but merge --ff-only of a clean tree is the common case
/// and we keep this small.)
pub fn materialize_commit(repo: &Repo, commit_id: &ObjectId) -> Result<()> {
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
        let (b_id, _) = r.commit_next(&[("hello.txt", b"v2\n", false)]);
        let (c_id, _) = r.commit_next(&[("hello.txt", b"v3\n", false)]);
        let b_commit = commit::read(&repo.gyt_dir, &b_id).unwrap();
        let a_id = b_commit.parents[0];
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &a_id).unwrap();
        run_in(&repo, &["--ff-only".into(), c_id.to_hex()]).unwrap();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(head_id, c_id);
    }

    fn write_identity(gyt_dir: &Path) {
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(gyt_dir).unwrap();
    }

    #[test]
    fn three_way_clean_merge_creates_merge_commit() {
        let _g = lock();
        let r = TestRepo::new("gyt-merge-3way");
        let repo = r.open();
        write_identity(&repo.gyt_dir);
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        // Branch off feature: change a different file from main.
        crate::cmd::branch::run(&["feature".to_string()]).unwrap();
        crate::cmd::switch::run(&["feature".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("feat.txt"), b"feat\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "feat".to_string()]).unwrap();
        let feat_id = refs::read_ref(&repo.gyt_dir, "refs/heads/feature").unwrap();
        crate::cmd::switch::run(&["main".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("other.txt"), b"other\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "main-side".to_string()]).unwrap();
        let result = run_in(&repo, &[feat_id.to_hex()]);
        std::env::set_current_dir(&prev).unwrap();
        result.expect("merge clean");
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        let merge = commit::read(&repo.gyt_dir, &head_id).unwrap();
        assert_eq!(merge.parents.len(), 2, "merge commit should have 2 parents");
        assert!(repo.workdir.join("feat.txt").exists());
        assert!(repo.workdir.join("other.txt").exists());
    }

    #[test]
    fn three_way_conflict_leaves_markers_and_merge_head() {
        let _g = lock();
        let r = TestRepo::new("gyt-merge-conflict");
        let repo = r.open();
        write_identity(&repo.gyt_dir);
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        crate::cmd::branch::run(&["feature".to_string()]).unwrap();
        crate::cmd::switch::run(&["feature".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("hello.txt"), b"FEATURE\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "feat".to_string()]).unwrap();
        let feat_id = refs::read_ref(&repo.gyt_dir, "refs/heads/feature").unwrap();
        crate::cmd::switch::run(&["main".to_string()]).unwrap();
        std::fs::write(repo.workdir.join("hello.txt"), b"MAIN\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "main".to_string()]).unwrap();
        let err = run_in(&repo, &[feat_id.to_hex()]).expect_err("expected conflict");
        std::env::set_current_dir(&prev).unwrap();
        match err {
            GytError::Repo(_) => {}
            other => panic!("expected Repo error, got {other:?}"),
        }
        assert!(repo.gyt_dir.join("MERGE_HEAD").exists());
        assert!(repo.gyt_dir.join("MERGE_MSG").exists());
        let body = std::fs::read_to_string(repo.workdir.join("hello.txt")).unwrap();
        assert!(body.contains("<<<<<<<"), "expected conflict markers: {body}");
        assert!(body.contains(">>>>>>>"));
    }
}
