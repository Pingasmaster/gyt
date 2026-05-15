// `gyt stash` — a tiny stash that stores WIP as commits at refs/stash.
//
// Layout:
//   refs/stash             -> latest stash commit
//   stash commit:
//     parents = [HEAD-at-stash-time, index-commit]
//     tree    = workdir tree captured at stash-time
//     parent[0] of the stash commit doubles as the chain to the previous
//     stash entry: when a new stash is pushed, refs/stash is updated to
//     point at the new commit, whose parents[0] is the *previous*
//     stash-commit (NOT the HEAD at the time of stash). For the very
//     first stash, parents[0] is HEAD.
//
// We rely on parents[0] being either "previous stash" or "the original
// HEAD" — to disambiguate, the stash commit's message starts with
// "WIP on " (auto-generated) or with the user-provided -m text. We chain
// stashes by walking `parents[0]` and stopping when the parent commit
// is not itself a stash commit (i.e. its message doesn't start with our
// stash marker AND it isn't reachable via further refs/stash chaining).
//
// To keep the chain unambiguous, we store the previous-stash-id (if any)
// as the FIRST parent and the index-commit as the SECOND parent. The
// original HEAD is encoded as a third parent on stash commits so we can
// recover it on pop.

use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::object::commit::{self as commit_obj, Commit};
use crate::object::tree::{self, MODE_DIR, MODE_EXEC, MODE_FILE, MODE_SYMLINK, TreeEntry};
use crate::object::{ObjectKind, store};
use crate::refs::{self, Head};
use crate::repo::Repo;
use crate::workdir;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const STASH_REF: &str = "refs/stash";

pub fn run(args: &[String]) -> Result<()> {
    let (sub, rest) = args
        .split_first()
        .map_or(("push", &[][..]), |(s, r)| (s.as_str(), r));
    match sub {
        "push" => cmd_push(rest),
        "list" => cmd_list(rest),
        "pop" => cmd_pop(rest),
        "apply" => cmd_apply(rest),
        "drop" => cmd_drop(rest),
        other => Err(GytError::InvalidArgument(format!(
            "stash: unknown subcommand {other:?} (expected push|list|pop|apply|drop)"
        ))),
    }
}

// -----------------------------------------------------------------------------
// push
// -----------------------------------------------------------------------------

fn cmd_push(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    do_push(&repo, args)
}

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by the `while i < args.len()` loop header (and an explicit `i >= args.len()` check after the i += 1 step)"
)]
fn do_push(repo: &Repo, args: &[String]) -> Result<()> {
    let _lock = repo.lock()?;
    // Parse `-m <msg>` (only flag we support).
    let mut user_msg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                i += 1;
                if i >= args.len() {
                    return Err(GytError::InvalidArgument(
                        "stash push: -m requires a message".into(),
                    ));
                }
                user_msg = Some(args[i].clone());
                i += 1;
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "stash push: unknown argument {other:?}"
                )));
            }
        }
    }

    let head = refs::read_head(&repo.gyt_dir)?;
    let head_commit = refs::resolve(&repo.gyt_dir, &head)?
        .ok_or_else(|| GytError::Repo("cannot stash with unborn HEAD".into()))?;

    let branch_label = match &head {
        Head::Symbolic(name) => short_branch_name(name),
        Head::Detached(_) => "(no branch)".to_string(),
    };

    // Build the index tree.
    let index_path = repo.index_path();
    let index = Index::read(&index_path)?;
    let index_tree = build_tree_from_index(&repo.gyt_dir, &index)?;

    // Build the workdir tree, hashing files as we go.
    let workdir_tree = build_tree_from_workdir(repo)?;

    // Author/committer.
    let cfg = Config::load(repo)?;
    let ident = cfg.identity()?;
    let now = current_unix_secs();
    let author_line = format!("{ident} {now} +0000");

    // Synthetic "index commit": parents=[HEAD], tree=index-tree.
    let index_commit_id = commit_obj::write(
        &repo.gyt_dir,
        &Commit {
            tree: index_tree,
            parents: vec![head_commit],
            authors: vec![author_line.clone()],
            committer: author_line.clone(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: format!("index on {branch_label}\n"),
        },
    )?;

    // Determine the previous stash (if any) — we put it as parents[0] so
    // walking parents[0] gives the chain. The original HEAD becomes
    // parents[2] so `pop` can recover the workdir/index baseline.
    let prev_stash = refs::read_ref(&repo.gyt_dir, STASH_REF).ok();

    // Read HEAD's commit subject for the auto message.
    let head_subject = first_line_of(&commit_obj::read(&repo.gyt_dir, &head_commit)?.message);
    let short_head = short_hex(&head_commit);
    let auto_msg = format!("WIP on {branch_label}: {short_head} {head_subject}");
    let stash_msg = match user_msg.as_deref() {
        Some(m) => format!("On {branch_label}: {m}\n"),
        None => format!("{auto_msg}\n"),
    };

    // Stash commit: parents = [prev-or-head, index-commit, original-head].
    let parents = vec![
        prev_stash.unwrap_or(head_commit),
        index_commit_id,
        head_commit,
    ];
    let stash_commit_id = commit_obj::write(
        &repo.gyt_dir,
        &Commit {
            tree: workdir_tree,
            parents,
            authors: vec![author_line.clone()],
            committer: author_line,
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: stash_msg.clone(),
        },
    )?;

    // Move refs/stash to the new commit.
    refs::write_ref(&repo.gyt_dir, STASH_REF, &stash_commit_id)?;

    // Reset workdir + index to HEAD's tree.
    let head_obj = commit_obj::read(&repo.gyt_dir, &head_commit)?;
    reset_workdir_and_index_to_tree(repo, &head_obj.tree)?;

    println!(
        "Saved working directory and index state {}",
        stash_msg.trim_end_matches('\n')
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// list
// -----------------------------------------------------------------------------

fn cmd_list(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    do_list(&repo, args)
}

fn do_list(repo: &Repo, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(GytError::InvalidArgument(
            "stash list: takes no arguments".into(),
        ));
    }
    let head = refs::read_head(&repo.gyt_dir)?;
    let branch_label = match &head {
        Head::Symbolic(name) => short_branch_name(name),
        Head::Detached(_) => "(no branch)".to_string(),
    };

    let chain = stash_chain(repo)?;
    for (i, id) in chain.iter().enumerate() {
        let c = commit_obj::read(&repo.gyt_dir, id)?;
        let subject = first_line_of(&c.message);
        // If the subject already starts with "WIP on" or "On" use as-is;
        // otherwise prepend the standard prefix.
        let line = if subject.starts_with("WIP on ") || subject.starts_with("On ") {
            subject
        } else {
            format!("WIP on {branch_label}: {subject}")
        };
        println!("stash@{{{i}}}: {line}");
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// pop
// -----------------------------------------------------------------------------

fn cmd_pop(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    do_pop(&repo, args)
}

#[expect(
    clippy::indexing_slicing,
    reason = "stash_commit.parents[1] is gated by `stash_commit.parents.len() < 2` early return"
)]
fn do_pop(repo: &Repo, args: &[String]) -> Result<()> {
    let _lock = repo.lock()?;
    if !args.is_empty() {
        return Err(GytError::InvalidArgument(
            "stash pop: takes no arguments (only stash@{0} is supported)".into(),
        ));
    }
    let top_id = refs::read_ref(&repo.gyt_dir, STASH_REF)
        .map_err(|_| GytError::Repo("no stash entries to pop".into()))?;

    let stash_commit = commit_obj::read(&repo.gyt_dir, &top_id)?;
    if stash_commit.parents.len() < 2 {
        return Err(GytError::Repo(
            "stash: malformed entry (missing index-commit parent)".into(),
        ));
    }

    // Conflict check: refuse if any tracked-or-untracked workdir file would
    // be overwritten with different content.
    let workdir_tree_id = stash_commit.tree;
    let target_files = flatten_tree(&repo.gyt_dir, &workdir_tree_id, Path::new(""))?;
    let conflicts = detect_conflicts(repo, &target_files)?;
    if !conflicts.is_empty() {
        let mut msg = String::from("stash pop: workdir has conflicting changes:\n");
        for p in &conflicts {
            msg.push_str("  ");
            msg.push_str(&p.to_string_lossy());
            msg.push('\n');
        }
        return Err(GytError::Repo(msg));
    }

    // Materialize workdir from workdir_tree.
    materialize_tree(repo, &workdir_tree_id)?;

    // Reset index to the index-commit's tree.
    let index_commit_id = stash_commit.parents[1];
    let index_commit = commit_obj::read(&repo.gyt_dir, &index_commit_id)?;
    let index = build_index_from_tree(repo, &index_commit.tree)?;
    index.write(&repo.index_path())?;

    // Drop top: move refs/stash to previous, or delete if none.
    drop_top(repo, &stash_commit)?;

    println!("Dropped stash@{{0}} ({top_id})");
    Ok(())
}

// -----------------------------------------------------------------------------
// apply
// -----------------------------------------------------------------------------

fn cmd_apply(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    do_apply(&repo, args)
}

#[expect(
    clippy::indexing_slicing,
    reason = "stash_commit.parents[1] is gated by `stash_commit.parents.len() < 2` early return"
)]
fn do_apply(repo: &Repo, args: &[String]) -> Result<()> {
    let _lock = repo.lock()?;
    if !args.is_empty() {
        return Err(GytError::InvalidArgument(
            "stash apply: takes no arguments (only stash@{0} is supported)".into(),
        ));
    }
    let top_id = refs::read_ref(&repo.gyt_dir, STASH_REF)
        .map_err(|_| GytError::Repo("no stash entries to apply".into()))?;

    let stash_commit = commit_obj::read(&repo.gyt_dir, &top_id)?;
    if stash_commit.parents.len() < 2 {
        return Err(GytError::Repo(
            "stash: malformed entry (missing index-commit parent)".into(),
        ));
    }

    // Conflict check: refuse if any tracked-or-untracked workdir file would
    // be overwritten with different content.
    let workdir_tree_id = stash_commit.tree;
    let target_files = flatten_tree(&repo.gyt_dir, &workdir_tree_id, Path::new(""))?;
    let conflicts = detect_conflicts(repo, &target_files)?;
    if !conflicts.is_empty() {
        let mut msg = String::from("stash apply: workdir has conflicting changes:\n");
        for p in &conflicts {
            msg.push_str("  ");
            msg.push_str(&p.to_string_lossy());
            msg.push('\n');
        }
        return Err(GytError::Repo(msg));
    }

    // Materialize workdir from workdir_tree.
    materialize_tree(repo, &workdir_tree_id)?;

    // Reset index to the index-commit's tree.
    let index_commit_id = stash_commit.parents[1];
    let index_commit = commit_obj::read(&repo.gyt_dir, &index_commit_id)?;
    let index = build_index_from_tree(repo, &index_commit.tree)?;
    index.write(&repo.index_path())?;

    // NOTE: intentionally do NOT drop the stash entry — apply leaves it intact.
    println!("Applied stash@{{0}} ({top_id})");
    Ok(())
}

// -----------------------------------------------------------------------------
// drop
// -----------------------------------------------------------------------------

fn cmd_drop(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    do_drop(&repo, args)
}

fn do_drop(repo: &Repo, args: &[String]) -> Result<()> {
    let _lock = repo.lock()?;
    let target = args.first().map_or("stash@{0}", String::as_str);
    if target != "stash@{0}" {
        return Err(GytError::Unsupported(format!(
            "stash drop: only stash@{{0}} is supported (got {target:?})"
        )));
    }
    let top_id = refs::read_ref(&repo.gyt_dir, STASH_REF)
        .map_err(|_| GytError::Repo("no stash entries to drop".into()))?;
    let stash_commit = commit_obj::read(&repo.gyt_dir, &top_id)?;
    drop_top(repo, &stash_commit)?;
    println!("Dropped stash@{{0}} ({top_id})");
    Ok(())
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

#[expect(
    clippy::indexing_slicing,
    reason = "parents[0] / parents[2] access is gated by `parents.len() >= 3` check in the same expression"
)]
fn drop_top(repo: &Repo, stash_commit: &Commit) -> Result<()> {
    // The "previous stash" lives in parents[0] iff it's a real previous
    // stash. If parents[0] == parents[2] (== original HEAD), there's no
    // previous stash to chain to.
    let has_prev =
        stash_commit.parents.len() >= 3 && stash_commit.parents[0] != stash_commit.parents[2];
    if has_prev {
        refs::write_ref(&repo.gyt_dir, STASH_REF, &stash_commit.parents[0])?;
    } else {
        refs::delete_ref(&repo.gyt_dir, STASH_REF)?;
    }
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "c.parents[0] / c.parents[2] is gated by `c.parents.len() >= 3` check in the same expression"
)]
fn stash_chain(repo: &Repo) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    let mut cur = refs::read_ref(&repo.gyt_dir, STASH_REF).ok();
    while let Some(id) = cur {
        let c = commit_obj::read(&repo.gyt_dir, &id)?;
        out.push(id);
        // If parents[0] != parents[2], parents[0] is a previous stash entry.
        if c.parents.len() >= 3 && c.parents[0] != c.parents[2] {
            cur = Some(c.parents[0]);
        } else {
            cur = None;
        }
    }
    Ok(out)
}

fn first_line_of(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

fn short_hex(id: &ObjectId) -> String {
    id.to_hex().chars().take(8).collect()
}

fn short_branch_name(refname: &str) -> String {
    refname
        .strip_prefix("refs/heads/")
        .unwrap_or(refname)
        .to_string()
}

fn current_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

// ---- Tree builders -----------------------------------------------------------

/// Build a tree object from the in-memory index and write all sub-trees to the
/// object store. Returns the root tree id.
pub fn build_tree_from_index(gyt_dir: &Path, index: &Index) -> Result<ObjectId> {
    // Group entries into a directory hierarchy.
    let mut root = DirNode::default();
    for e in &index.entries {
        let comps = path_components(&e.path);
        if comps.is_empty() {
            continue;
        }
        root.insert_file(&comps, e.mode, e.hash);
    }
    write_dir_node(gyt_dir, &root)
}

#[derive(Default)]
struct DirNode {
    files: BTreeMap<Vec<u8>, (u32, ObjectId)>,
    dirs: BTreeMap<Vec<u8>, Self>,
}

impl DirNode {
    #[expect(
        clippy::indexing_slicing,
        reason = "caller in build_tree_from_index guarantees comps is non-empty; comps[0] is in-range and comps[1..] is empty-slice-safe"
    )]
    fn insert_file(&mut self, comps: &[Vec<u8>], mode: u32, hash: ObjectId) {
        if comps.len() == 1 {
            self.files.insert(comps[0].clone(), (mode, hash));
        } else {
            let entry = self.dirs.entry(comps[0].clone()).or_default();
            entry.insert_file(&comps[1..], mode, hash);
        }
    }
}

fn write_dir_node(gyt_dir: &Path, node: &DirNode) -> Result<ObjectId> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    for (name, (mode, hash)) in &node.files {
        entries.push(TreeEntry {
            mode: *mode,
            name: name.clone(),
            hash: *hash,
        });
    }
    for (name, child) in &node.dirs {
        let child_id = write_dir_node(gyt_dir, child)?;
        entries.push(TreeEntry {
            mode: MODE_DIR,
            name: name.clone(),
            hash: child_id,
        });
    }
    tree::write(gyt_dir, &entries)
}

fn path_components(p: &Path) -> Vec<Vec<u8>> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned().into_bytes()),
            _ => None,
        })
        .collect()
}

/// Walk the workdir, hashing files into the object store, and build a tree.
fn build_tree_from_workdir(repo: &Repo) -> Result<ObjectId> {
    let ignore = crate::ignore::IgnoreSet::load_from_root(&repo.workdir)?;
    let entries = workdir::walk(&repo.workdir, &ignore)?;
    let mut root = DirNode::default();
    for e in &entries {
        if e.is_dir {
            continue;
        }
        let abs = repo.workdir.join(&e.path);
        // Symlinks: read the link target as the blob payload.
        let payload = if e.mode == MODE_SYMLINK {
            let target = std::fs::read_link(&abs)?;
            target.to_string_lossy().into_owned().into_bytes()
        } else {
            std::fs::read(&abs)?
        };
        let id = store::write_bytes(&repo.gyt_dir, ObjectKind::Blob, &payload)?;
        let mode = match e.mode {
            MODE_EXEC => MODE_EXEC,
            MODE_SYMLINK => MODE_SYMLINK,
            _ => MODE_FILE,
        };
        let comps = path_components(&e.path);
        if comps.is_empty() {
            continue;
        }
        root.insert_file(&comps, mode, id);
    }
    write_dir_node(&repo.gyt_dir, &root)
}

// ---- Tree consumers ----------------------------------------------------------

#[derive(Debug, Clone)]
struct FlatFile {
    path: PathBuf,
    mode: u32,
    hash: ObjectId,
}

fn flatten_tree(gyt_dir: &Path, tree_id: &ObjectId, prefix: &Path) -> Result<Vec<FlatFile>> {
    let mut out = Vec::new();
    flatten_recurse(gyt_dir, tree_id, prefix, &mut out)?;
    Ok(out)
}

fn flatten_recurse(
    gyt_dir: &Path,
    tree_id: &ObjectId,
    prefix: &Path,
    out: &mut Vec<FlatFile>,
) -> Result<()> {
    let entries = tree::read(gyt_dir, tree_id)?;
    for e in entries {
        let name_str = String::from_utf8_lossy(&e.name).into_owned();
        let p = if prefix.as_os_str().is_empty() {
            PathBuf::from(&name_str)
        } else {
            prefix.join(&name_str)
        };
        if e.mode == MODE_DIR {
            flatten_recurse(gyt_dir, &e.hash, &p, out)?;
        } else {
            out.push(FlatFile {
                path: p,
                mode: e.mode,
                hash: e.hash,
            });
        }
    }
    Ok(())
}

/// Materialize every file from `tree_id` into the workdir, removing tracked
/// files (per index) that aren't in the new tree, and clearing the index of
/// stale entries. The index is left unchanged here — caller is expected to
/// rewrite it explicitly.
fn materialize_tree(repo: &Repo, tree_id: &ObjectId) -> Result<()> {
    let files = flatten_tree(&repo.gyt_dir, tree_id, Path::new(""))?;
    for f in &files {
        let abs = repo.workdir.join(&f.path);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let payload = crate::object::blob::read(&repo.gyt_dir, &f.hash)?;
        if f.mode == MODE_SYMLINK {
            // Recreate the symlink from the blob payload (the link target).
            let _ = std::fs::remove_file(&abs);
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(
                    std::ffi::OsStr::new(std::str::from_utf8(&payload).unwrap_or("")),
                    &abs,
                )?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&abs, &payload)?;
            }
        } else {
            std::fs::write(&abs, &payload)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = if f.mode == MODE_EXEC {
                    std::fs::Permissions::from_mode(0o755)
                } else {
                    std::fs::Permissions::from_mode(0o644)
                };
                std::fs::set_permissions(&abs, perms)?;
            }
        }
    }
    Ok(())
}

/// Reset workdir + index to the given tree id. Files tracked in the current
/// index that are not in the target tree are removed from the workdir.
fn reset_workdir_and_index_to_tree(repo: &Repo, tree_id: &ObjectId) -> Result<()> {
    let target = flatten_tree(&repo.gyt_dir, tree_id, Path::new(""))?;
    let target_paths: std::collections::BTreeSet<PathBuf> =
        target.iter().map(|f| f.path.clone()).collect();

    // Remove tracked files (per old index) that aren't in the target tree.
    let old_index = Index::read(&repo.index_path())?;
    for e in &old_index.entries {
        if !target_paths.contains(&e.path) {
            let abs = repo.workdir.join(&e.path);
            if abs.exists() {
                let _ = std::fs::remove_file(&abs);
            }
        }
    }

    // Materialize target files.
    materialize_tree(repo, tree_id)?;

    // Build a fresh index from the tree.
    let new_index = build_index_from_tree(repo, tree_id)?;
    new_index.write(&repo.index_path())?;
    Ok(())
}

fn build_index_from_tree(repo: &Repo, tree_id: &ObjectId) -> Result<Index> {
    let files = flatten_tree(&repo.gyt_dir, tree_id, Path::new(""))?;
    let mut idx = Index::new();
    for f in &files {
        let abs = repo.workdir.join(&f.path);
        let (size, ctime, mtime) = match std::fs::symlink_metadata(&abs) {
            Ok(md) => {
                let size = md.len();
                #[cfg(unix)]
                let (c, m) = {
                    use std::os::unix::fs::MetadataExt;
                    (md.ctime(), md.mtime())
                };
                #[cfg(not(unix))]
                let (c, m) = (0i64, 0i64);
                (size, c, m)
            }
            Err(_) => (0u64, 0i64, 0i64),
        };
        idx.insert(IndexEntry {
            ctime_secs: ctime,
            mtime_secs: mtime,
            size,
            mode: f.mode,
            hash: f.hash,
            path: f.path.clone(),
        });
    }
    Ok(idx)
}

/// Detect conflicts between the workdir's current state and the files we'd
/// like to materialize from the stash tree. Returns the list of paths whose
/// current workdir contents differ from both the index and the target.
fn detect_conflicts(repo: &Repo, target: &[FlatFile]) -> Result<Vec<PathBuf>> {
    let index = Index::read(&repo.index_path())?;
    let mut conflicts = Vec::new();
    for f in target {
        let abs = repo.workdir.join(&f.path);
        if !abs.exists() {
            continue; // no conflict — we'll just create it
        }
        // Compare current workdir content to the target blob.
        let target_blob = crate::object::blob::read(&repo.gyt_dir, &f.hash)?;
        let Ok(current) = std::fs::read(&abs) else {
            continue;
        };
        if current == target_blob {
            continue;
        }
        // Different. If the file is also clean against the index (i.e. the
        // workdir matches the index), it's not a conflict — we'll overwrite.
        if let Some(ie) = index.find(&f.path) {
            let raw_id = workdir::hash_blob(&abs)?;
            if raw_id == ie.hash {
                continue;
            }
        }
        conflicts.push(f.path.clone());
    }
    Ok(conflicts)
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use std::path::{Path, PathBuf};

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(prefix: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn init_repo(root: &Path) -> Repo {
        std::fs::create_dir_all(root.join(".gyt/objects")).unwrap();
        std::fs::create_dir_all(root.join(".gyt/refs/heads")).unwrap();
        refs::write_head(
            &root.join(".gyt"),
            &Head::Symbolic("refs/heads/main".into()),
        )
        .unwrap();
        Repo::open(root).unwrap()
    }

    fn write_file(p: &Path, content: &[u8]) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    fn make_initial_commit(repo: &Repo, files: &[(&str, &[u8])]) -> ObjectId {
        // Materialize files in workdir, build index, build tree, write commit.
        let mut idx = Index::new();
        for (path, content) in files {
            let abs = repo.workdir.join(path);
            write_file(&abs, content);
            let id = store::write_bytes(&repo.gyt_dir, ObjectKind::Blob, content).unwrap();
            idx.insert(IndexEntry {
                ctime_secs: 0,
                mtime_secs: 0,
                size: content.len() as u64,
                mode: MODE_FILE,
                hash: id,
                path: PathBuf::from(*path),
            });
        }
        idx.write(&repo.index_path()).unwrap();
        let tree_id = build_tree_from_index(&repo.gyt_dir, &idx).unwrap();
        let cid = commit_obj::write(
            &repo.gyt_dir,
            &Commit {
                tree: tree_id,
                parents: vec![],
                authors: vec!["A <a@x> 1 +0000".into()],
                committer: "A <a@x> 1 +0000".into(),
                ai_assists: vec![],
                reviewers: vec![],
                signature: None,
                message: "initial\n".into(),
            },
        )
        .unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &cid).unwrap();
        cid
    }

    fn write_user_config(repo: &Repo, name: &str, email: &str) {
        let cfg = Config {
            user_name: Some(name.into()),
            user_email: Some(email.into()),
            remotes: Default::default(),
            create_default_gytignore: false,
            sign_required: false,
        };
        cfg.write(&repo.gyt_dir).unwrap();
    }

    #[test]
    fn stash_push_then_pop_round_trip() {
        let t = TmpDir::new("gyt-stash-rt");
        let repo = init_repo(t.path());
        write_user_config(&repo, "Alice", "a@x");

        make_initial_commit(&repo, &[("hello.txt", b"hi\n")]);

        // Modify the file.
        write_file(&repo.workdir.join("hello.txt"), b"hi modified\n");

        // Push the stash.
        do_push(&repo, &[]).unwrap();

        // Workdir should now match HEAD.
        let after = std::fs::read(repo.workdir.join("hello.txt")).unwrap();
        assert_eq!(after, b"hi\n");

        // refs/stash should exist.
        assert!(refs::read_ref(&repo.gyt_dir, STASH_REF).is_ok());

        // Pop.
        do_pop(&repo, &[]).unwrap();

        let after = std::fs::read(repo.workdir.join("hello.txt")).unwrap();
        assert_eq!(after, b"hi modified\n");

        // refs/stash should be gone.
        assert!(refs::read_ref(&repo.gyt_dir, STASH_REF).is_err());
    }

    #[test]
    fn stash_list_after_two_pushes() {
        let t = TmpDir::new("gyt-stash-list");
        let repo = init_repo(t.path());
        write_user_config(&repo, "Alice", "a@x");

        make_initial_commit(&repo, &[("hello.txt", b"hi\n")]);

        // First stash.
        write_file(&repo.workdir.join("hello.txt"), b"v1\n");
        do_push(&repo, &["-m".into(), "first".into()]).unwrap();
        // Second stash.
        write_file(&repo.workdir.join("hello.txt"), b"v2\n");
        do_push(&repo, &["-m".into(), "second".into()]).unwrap();

        let chain = stash_chain(&repo).unwrap();
        assert_eq!(
            chain.len(),
            2,
            "expected 2 stash entries, got {}",
            chain.len()
        );

        // Subjects: top (index 0) is the latest push ("second"), index 1 is "first".
        let c0 = commit_obj::read(&repo.gyt_dir, &chain[0]).unwrap();
        let c1 = commit_obj::read(&repo.gyt_dir, &chain[1]).unwrap();
        assert!(c0.message.contains("second"), "got: {}", c0.message);
        assert!(c1.message.contains("first"), "got: {}", c1.message);
    }

    #[test]
    fn stash_pop_with_no_stash_errors() {
        let t = TmpDir::new("gyt-stash-empty");
        let repo = init_repo(t.path());
        write_user_config(&repo, "Alice", "a@x");
        make_initial_commit(&repo, &[("hello.txt", b"hi\n")]);

        let res = do_pop(&repo, &[]);
        assert!(res.is_err(), "expected error popping empty stash");
    }
}
