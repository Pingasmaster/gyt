// `gyt worktree` — additional working trees.
//
// Layout for a secondary worktree at <path>:
//   <path>/.gyt                 -- a FILE containing "gytdir: <abs main .gyt>/worktrees/<name>\n"
//   <main .gyt>/worktrees/<name>/HEAD     -- "ref: refs/heads/<branch>\n"
//   <main .gyt>/worktrees/<name>/index    -- empty index
//   <main .gyt>/worktrees/<name>/gytdir   -- the absolute path to the worktree's .gyt FILE
//
// Branch refs live in the shared main .gyt/refs tree.

use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::object::commit as commit_obj;
use crate::object::tree::{self, MODE_DIR, MODE_EXEC, MODE_FILE, MODE_SYMLINK};
#[cfg(test)]
use crate::object::tree::TreeEntry;
use crate::refs::{self, Head};
use crate::repo::{GYT_DIR, Repo};
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let (sub, rest) = match args.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => {
            return Err(GytError::InvalidArgument(
                "worktree: expected subcommand (add|list|remove)".into(),
            ));
        }
    };
    match sub {
        "add" => cmd_add(rest),
        "list" => cmd_list(rest),
        "remove" => cmd_remove(rest),
        other => Err(GytError::InvalidArgument(format!(
            "worktree: unknown subcommand {other:?}"
        ))),
    }
}

// -----------------------------------------------------------------------------
// add
// -----------------------------------------------------------------------------

fn cmd_add(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    do_add(&repo, args)
}

fn do_add(repo: &Repo, args: &[String]) -> Result<()> {
    // Parse: [-b <branch>] <path> [<base-rev>]
    let mut new_branch: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-b" => {
                i += 1;
                if i >= args.len() {
                    return Err(GytError::InvalidArgument(
                        "worktree add: -b requires a branch name".into(),
                    ));
                }
                new_branch = Some(args[i].clone());
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "worktree add: unknown flag {other:?}"
                )));
            }
            _ => {
                positional.push(args[i].clone());
                i += 1;
            }
        }
    }

    if positional.is_empty() {
        return Err(GytError::InvalidArgument(
            "worktree add: missing <path>".into(),
        ));
    }
    let path_arg = &positional[0];
    let path = PathBuf::from(path_arg);
    if path.exists() {
        return Err(GytError::InvalidArgument(format!(
            "worktree add: path already exists: {}",
            path.display()
        )));
    }

    // Determine the target branch and its commit id.
    let branch_name: String;
    let branch_commit: ObjectId;
    if let Some(new) = new_branch.clone() {
        // Create new branch at base-rev (or HEAD).
        let base_rev = positional.get(1).cloned();
        let base_id = match base_rev {
            Some(s) => resolve_rev(repo, &s)?,
            None => {
                let head = refs::read_head(&repo.gyt_dir)?;
                refs::resolve(&repo.gyt_dir, &head)?.ok_or_else(|| {
                    GytError::Repo("worktree add: HEAD is unborn; pass a base-rev".into())
                })?
            }
        };
        let full_ref = format!("refs/heads/{new}");
        if refs::read_ref(&repo.gyt_dir, &full_ref).is_ok() {
            return Err(GytError::Refs(format!("branch {new} already exists")));
        }
        refs::write_ref(&repo.gyt_dir, &full_ref, &base_id)?;
        branch_name = new;
        branch_commit = base_id;
    } else {
        // No -b: the second positional must be an existing branch name.
        let name = positional.get(1).cloned().ok_or_else(|| {
            GytError::InvalidArgument(
                "worktree add: without -b, you must give an existing branch name".into(),
            )
        })?;
        let full_ref = format!("refs/heads/{name}");
        let id = refs::read_ref(&repo.gyt_dir, &full_ref).map_err(|_| {
            GytError::InvalidArgument(format!("worktree add: branch {name} does not exist"))
        })?;
        branch_name = name;
        branch_commit = id;
    }

    // Create the worktree directory.
    std::fs::create_dir_all(&path)?;
    let abs_path = path.canonicalize()?;
    let wt_name = abs_path
        .file_name()
        .ok_or_else(|| GytError::InvalidArgument("worktree add: empty basename".into()))?
        .to_string_lossy()
        .into_owned();

    // The per-worktree dir under main .gyt/worktrees/<name>/.
    let wt_dir = repo.gyt_dir.join("worktrees").join(&wt_name);
    if wt_dir.exists() {
        return Err(GytError::InvalidArgument(format!(
            "worktree add: {wt_name} already registered"
        )));
    }
    std::fs::create_dir_all(&wt_dir)?;

    // <wt_dir>/HEAD -> "ref: refs/heads/<branch>\n"
    refs::write_head(
        &wt_dir,
        &Head::Symbolic(format!("refs/heads/{branch_name}")),
    )?;

    // <wt_dir>/index -> empty index.
    Index::new().write(&wt_dir.join("index"))?;

    // <wt_dir>/gytdir -> abs path to <abs_path>/.gyt
    let marker_file = abs_path.join(GYT_DIR);
    crate::fs_util::atomic_write(
        &wt_dir.join("gytdir"),
        format!("{}\n", marker_file.display()).as_bytes(),
    )?;

    // <abs_path>/.gyt FILE -> "gytdir: <wt_dir>\n"
    crate::fs_util::atomic_write(
        &marker_file,
        format!("gytdir: {}\n", wt_dir.display()).as_bytes(),
    )?;

    // Materialize the branch's tree into <abs_path>.
    let head_commit = commit_obj::read(&repo.gyt_dir, &branch_commit)?;
    materialize_tree_to(&repo.gyt_dir, &head_commit.tree, &abs_path)?;

    // Build a per-worktree index from the tree and write it.
    let new_index = build_index_from_tree(&repo.gyt_dir, &head_commit.tree, &abs_path)?;
    new_index.write(&wt_dir.join("index"))?;

    // Print friendly summary.
    let subject = first_line_of(&head_commit.message);
    let short = short_hex(&branch_commit);
    println!("Preparing worktree ({branch_name})");
    println!("HEAD is now at {short} {subject}");
    Ok(())
}

// -----------------------------------------------------------------------------
// list
// -----------------------------------------------------------------------------

fn cmd_list(args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(GytError::InvalidArgument(
            "worktree list: takes no arguments".into(),
        ));
    }
    let cwd = std::env::current_dir()?;
    do_list_at(&cwd)
}

fn do_list_at(cwd: &Path) -> Result<()> {
    let (workdir, gyt_dir) = locate_repo(cwd)?;
    // The "main" .gyt may be different from gyt_dir if we're inside a
    // worktree. Detect it: if gyt_dir's path component contains
    // "/worktrees/<name>", the main is the parent's parent.
    let main_gyt = main_gyt_dir(&gyt_dir);

    // Main worktree info.
    let main_workdir = main_gyt
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| workdir.clone());
    print_worktree_line(&main_workdir, &main_gyt)?;

    // Aux worktrees in <main_gyt>/worktrees/<name>/.
    let wts_dir = main_gyt.join("worktrees");
    if wts_dir.is_dir() {
        let mut names: Vec<String> = std::fs::read_dir(&wts_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let wt_dir = wts_dir.join(&name);
            // Resolve the worktree's actual workdir from <wt_dir>/gytdir, which
            // contains the path to <abs_path>/.gyt FILE.
            let Ok(gytdir_marker) = std::fs::read_to_string(wt_dir.join("gytdir")) else {
                continue;
            };
            let marker_path = PathBuf::from(gytdir_marker.trim());
            let aux_workdir = match marker_path.parent() {
                Some(p) => p.to_path_buf(),
                None => continue,
            };
            print_worktree_line(&aux_workdir, &wt_dir)?;
        }
    }
    Ok(())
}

fn print_worktree_line(workdir: &Path, gyt_dir_for_head: &Path) -> Result<()> {
    let head = refs::read_head(gyt_dir_for_head)?;
    let main_gyt = main_gyt_dir(gyt_dir_for_head);
    let (branch_label, short) = match &head {
        Head::Symbolic(name) => {
            let id = refs::read_ref(&main_gyt, name).ok();
            let short = id
                .as_ref()
                .map(short_hex)
                .unwrap_or_else(|| "0000000".to_string());
            (
                name.strip_prefix("refs/heads/").unwrap_or(name).to_string(),
                short,
            )
        }
        Head::Detached(id) => ("(detached)".into(), short_hex(id)),
    };
    println!("{}  {}  [{}]", workdir.display(), short, branch_label);
    Ok(())
}

// -----------------------------------------------------------------------------
// remove
// -----------------------------------------------------------------------------

fn cmd_remove(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    do_remove_at(&cwd, args)
}

fn do_remove_at(cwd: &Path, args: &[String]) -> Result<()> {
    let target = args
        .first()
        .ok_or_else(|| GytError::InvalidArgument("worktree remove: missing <path>".into()))?
        .clone();
    let (_workdir, gyt_dir) = locate_repo(cwd)?;
    let main_gyt = main_gyt_dir(&gyt_dir);

    // Resolve the target to a (wt_dir, aux_workdir) pair.
    let (wt_dir, aux_workdir) = resolve_worktree(&main_gyt, &target)?;

    // Refuse if dirty.
    if worktree_is_dirty(&main_gyt, &wt_dir, &aux_workdir)? {
        return Err(GytError::Repo(format!(
            "worktree remove: {} is dirty",
            aux_workdir.display()
        )));
    }

    // Delete the workdir contents and the per-worktree dir.
    if aux_workdir.exists() {
        std::fs::remove_dir_all(&aux_workdir)?;
    }
    std::fs::remove_dir_all(&wt_dir)?;
    println!("Removed worktree {}", aux_workdir.display());
    Ok(())
}

fn resolve_worktree(main_gyt: &Path, target: &str) -> Result<(PathBuf, PathBuf)> {
    let wts_dir = main_gyt.join("worktrees");
    if !wts_dir.is_dir() {
        return Err(GytError::InvalidArgument(format!(
            "worktree remove: no such worktree: {target}"
        )));
    }
    // First try basename match (only if `target` has no separators).
    if !target.contains('/') && !target.contains('\\') {
        let by_basename = wts_dir.join(target);
        if by_basename.is_dir() {
            let aux = read_aux_workdir(&by_basename)?;
            return Ok((by_basename, aux));
        }
    }
    // Then absolute-path match: scan all worktrees.
    let candidate_abs = PathBuf::from(target).canonicalize().ok();
    for entry in std::fs::read_dir(&wts_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let wt_dir = entry.path();
        let Ok(aux) = read_aux_workdir(&wt_dir) else {
            continue;
        };
        // Collapsed via stable let-chains (edition 2024).
        if let Some(cabs) = &candidate_abs && aux == *cabs {
            return Ok((wt_dir, aux));
        }
        if aux.file_name().map(|s| s.to_string_lossy().into_owned()) == Some(target.to_string()) {
            return Ok((wt_dir, aux));
        }
    }
    Err(GytError::InvalidArgument(format!(
        "worktree remove: no such worktree: {target}"
    )))
}

fn read_aux_workdir(wt_dir: &Path) -> Result<PathBuf> {
    let s = std::fs::read_to_string(wt_dir.join("gytdir"))?;
    let p = PathBuf::from(s.trim());
    p.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| GytError::Repo("worktree gytdir marker has no parent".into()))
}

fn worktree_is_dirty(main_gyt: &Path, wt_dir: &Path, aux_workdir: &Path) -> Result<bool> {
    let head = refs::read_head(wt_dir)?;
    let Ok(head_commit) = refs::resolve(main_gyt, &head) else {
        return Ok(false);
    };
    let Some(head_commit) = head_commit else {
        return Ok(false);
    };
    let head_obj = commit_obj::read(main_gyt, &head_commit)?;
    let tree_files = flatten_tree(main_gyt, &head_obj.tree, Path::new(""))?;

    // Walk aux_workdir.
    let ignore = crate::ignore::IgnoreSet::load_from_root(aux_workdir).unwrap_or_default();
    let entries = crate::workdir::walk(aux_workdir, &ignore)?;

    // Check for untracked files.
    let tracked: std::collections::BTreeSet<PathBuf> =
        tree_files.iter().map(|f| f.path.clone()).collect();
    for e in &entries {
        if e.is_dir {
            continue;
        }
        if !tracked.contains(&e.path) {
            return Ok(true);
        }
    }
    // Check for modifications.
    for f in &tree_files {
        let abs = aux_workdir.join(&f.path);
        if !abs.exists() {
            return Ok(true);
        }
        let id = crate::workdir::hash_blob(&abs)?;
        if id != f.hash {
            return Ok(true);
        }
    }
    Ok(false)
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

/// Locate the repo from `start`, following the `.gyt` FILE indirection in
/// secondary worktrees.
///
/// Returns (workdir, gyt_dir). For a normal repo, `gyt_dir = workdir/.gyt`.
/// For a worktree, `workdir` is the directory containing the `.gyt` FILE, and
/// `gyt_dir` is the per-worktree directory `<main .gyt>/worktrees/<name>/`.
fn locate_repo(start: &Path) -> Result<(PathBuf, PathBuf)> {
    let mut p = start.canonicalize()?;
    loop {
        let candidate = p.join(GYT_DIR);
        if candidate.is_dir() {
            return Ok((p.clone(), candidate));
        }
        if candidate.is_file() {
            // Worktree marker: parse "gytdir: <abs path>".
            let bytes = std::fs::read(&candidate)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| GytError::Repo(".gyt file is not valid utf-8".into()))?;
            let line = text.trim_end_matches(['\n', '\r']);
            let rest = line
                .strip_prefix("gytdir:")
                .ok_or_else(|| GytError::Repo(format!("malformed .gyt file: {line:?}")))?
                .trim();
            return Ok((p.clone(), PathBuf::from(rest)));
        }
        if !p.pop() {
            return Err(GytError::Repo(format!(
                "no .gyt found from {}",
                start.display()
            )));
        }
    }
}

/// Return the main repo's `.gyt` directory given a `gyt_dir` that may be a
/// per-worktree directory (`.../.gyt/worktrees/<name>`) or the main `.gyt`
/// itself.
fn main_gyt_dir(gyt_dir: &Path) -> PathBuf {
    let comps: Vec<_> = gyt_dir.components().collect();
    // If the path ends with ".gyt/worktrees/<name>", main is gyt_dir/../..
    let n = comps.len();
    if n >= 3 {
        let third_last = comps[n - 3].as_os_str().to_string_lossy().into_owned();
        let second_last = comps[n - 2].as_os_str().to_string_lossy().into_owned();
        if third_last == GYT_DIR && second_last == "worktrees" {
            let mut p = gyt_dir.to_path_buf();
            p.pop();
            p.pop();
            return p;
        }
    }
    gyt_dir.to_path_buf()
}

fn first_line_of(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

fn short_hex(id: &ObjectId) -> String {
    id.to_hex().chars().take(8).collect()
}

fn resolve_rev(repo: &Repo, rev: &str) -> Result<ObjectId> {
    // Accept: full hex, or branch/tag name (refs/heads/<x>, refs/tags/<x>).
    // Collapsed via stable let-chains (edition 2024).
    if rev.len() == crate::hash::HEX_LEN && let Ok(id) = ObjectId::from_hex(rev) {
        return Ok(id);
    }
    if let Ok(id) = refs::read_ref(&repo.gyt_dir, &format!("refs/heads/{rev}")) {
        return Ok(id);
    }
    if let Ok(id) = refs::read_ref(&repo.gyt_dir, &format!("refs/tags/{rev}")) {
        return Ok(id);
    }
    if let Ok(id) = refs::read_ref(&repo.gyt_dir, rev) {
        return Ok(id);
    }
    Err(GytError::InvalidArgument(format!(
        "cannot resolve revision {rev:?}"
    )))
}

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

fn materialize_tree_to(gyt_dir: &Path, tree_id: &ObjectId, root: &Path) -> Result<()> {
    let files = flatten_tree(gyt_dir, tree_id, Path::new(""))?;
    for f in &files {
        let abs = root.join(&f.path);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let payload = crate::object::blob::read(gyt_dir, &f.hash)?;
        if f.mode == MODE_SYMLINK {
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

fn build_index_from_tree(gyt_dir: &Path, tree_id: &ObjectId, workdir: &Path) -> Result<Index> {
    let files = flatten_tree(gyt_dir, tree_id, Path::new(""))?;
    let mut idx = Index::new();
    for f in &files {
        let abs = workdir.join(&f.path);
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
        let mode = match f.mode {
            MODE_EXEC => MODE_EXEC,
            MODE_SYMLINK => MODE_SYMLINK,
            _ => MODE_FILE,
        };
        idx.insert(IndexEntry {
            ctime_secs: ctime,
            mtime_secs: mtime,
            size,
            mode,
            hash: f.hash,
            path: f.path.clone(),
        });
    }
    Ok(idx)
}



// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::object::ObjectKind;
    use crate::object::commit::Commit;
    use crate::object::store;
    use std::path::{Path, PathBuf};

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(prefix: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
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

    fn write_user_config(repo: &Repo, name: &str, email: &str) {
        let cfg = Config {
            user_name: Some(name.into()),
            user_email: Some(email.into()),
            remotes: Default::default(),
            create_default_gytignore: false,
        };
        cfg.write(&repo.gyt_dir).unwrap();
    }

    fn write_file(p: &Path, content: &[u8]) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, content).unwrap();
    }

    fn make_initial_commit(repo: &Repo, files: &[(&str, &[u8])]) -> ObjectId {
        let mut entries: Vec<TreeEntry> = Vec::new();
        for (path, content) in files {
            let abs = repo.workdir.join(path);
            write_file(&abs, content);
            let id = store::write_bytes(&repo.gyt_dir, ObjectKind::Blob, content).unwrap();
            entries.push(TreeEntry {
                mode: MODE_FILE,
                name: path.as_bytes().to_vec(),
                hash: id,
            });
        }
        let tree_id = tree::write(&repo.gyt_dir, &entries).unwrap();
        let cid = commit_obj::write(
            &repo.gyt_dir,
            &Commit {
                tree: tree_id,
                parents: vec![],
                authors: vec!["A <a@x> 1 +0000".into()],
                committer: "A <a@x> 1 +0000".into(),
                ai_assists: vec![],
                reviewers: vec![],
                message: "initial\n".into(),
            },
        )
        .unwrap();
        refs::write_ref(&repo.gyt_dir, "refs/heads/main", &cid).unwrap();
        cid
    }

    #[test]
    fn worktree_add_creates_dir_and_marker_file() {
        let t = TmpDir::new("gyt-wt-add");
        let repo = init_repo(t.path());
        write_user_config(&repo, "Alice", "a@x");
        make_initial_commit(&repo, &[("hello.txt", b"hi\n")]);

        let aux_path = t.path().join("aux");
        do_add(
            &repo,
            &[
                "-b".into(),
                "feature".into(),
                aux_path.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();

        // .gyt FILE present and points at main_gyt/worktrees/aux.
        let marker = aux_path.join(".gyt");
        assert!(
            marker.is_file(),
            "expected .gyt FILE at {}",
            marker.display()
        );
        let body = std::fs::read_to_string(&marker).unwrap();
        assert!(body.starts_with("gytdir: "));
        assert!(body.contains("worktrees/aux"));

        // Per-worktree dir present.
        let wt_dir = repo.gyt_dir.join("worktrees/aux");
        assert!(wt_dir.is_dir());
        assert!(wt_dir.join("HEAD").is_file());
        assert!(wt_dir.join("index").is_file());
        assert!(wt_dir.join("gytdir").is_file());

        // Workdir materialized.
        assert_eq!(std::fs::read(aux_path.join("hello.txt")).unwrap(), b"hi\n");
    }

    #[test]
    fn worktree_list_includes_main_and_aux() {
        let t = TmpDir::new("gyt-wt-list");
        let repo = init_repo(t.path());
        write_user_config(&repo, "Alice", "a@x");
        make_initial_commit(&repo, &[("hello.txt", b"hi\n")]);

        let aux_path = t.path().join("aux");
        do_add(
            &repo,
            &[
                "-b".into(),
                "feature".into(),
                aux_path.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();

        // Use locate_repo + main_gyt_dir directly to assert the structure.
        let (wd, gd) = locate_repo(&repo.workdir).unwrap();
        let main_gyt = main_gyt_dir(&gd);
        assert_eq!(main_gyt, repo.gyt_dir);
        assert_eq!(wd, repo.workdir);

        // From inside the aux worktree, locate_repo should follow the .gyt
        // file to the per-worktree dir.
        let (aux_wd, aux_gd) = locate_repo(&aux_path).unwrap();
        assert_eq!(aux_wd, aux_path.canonicalize().unwrap());
        assert_eq!(aux_gd, repo.gyt_dir.join("worktrees/aux"));
        assert_eq!(main_gyt_dir(&aux_gd), repo.gyt_dir);

        // do_list_at should not error.
        do_list_at(&repo.workdir).unwrap();
    }

    #[test]
    fn worktree_remove_dirty_refuses() {
        let t = TmpDir::new("gyt-wt-rm-dirty");
        let repo = init_repo(t.path());
        write_user_config(&repo, "Alice", "a@x");
        make_initial_commit(&repo, &[("hello.txt", b"hi\n")]);

        let aux_path = t.path().join("aux");
        do_add(
            &repo,
            &[
                "-b".into(),
                "feature".into(),
                aux_path.to_string_lossy().into_owned(),
            ],
        )
        .unwrap();

        // Make it dirty.
        std::fs::write(aux_path.join("hello.txt"), b"changed\n").unwrap();

        let res = do_remove_at(&repo.workdir, &[aux_path.to_string_lossy().into_owned()]);
        assert!(
            res.is_err(),
            "expected dirty worktree removal to be refused"
        );

        // Cleanup successful path: revert and remove.
        std::fs::write(aux_path.join("hello.txt"), b"hi\n").unwrap();
        do_remove_at(&repo.workdir, &[aux_path.to_string_lossy().into_owned()]).unwrap();
        assert!(!aux_path.exists());
        assert!(!repo.gyt_dir.join("worktrees/aux").exists());
    }
}
