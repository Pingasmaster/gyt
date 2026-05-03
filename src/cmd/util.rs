// Shared helpers for the `cmd` modules: rev resolution, tree helpers,
// and tree construction from index entries.

use crate::errors::{GytError, Result};
use crate::hash::{HEX_LEN, ObjectId};
use crate::index::{Index, IndexEntry};
use crate::object::{ObjectKind, commit, store, tag, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Resolve a textual revision to an ObjectId by trying, in order:
/// HEAD, branch refs, tag refs, remote refs, then a 64-hex BLAKE3 id.
/// Returns an error if not found.
pub fn resolve_rev(repo: &Repo, rev: &str) -> Result<ObjectId> {
    if rev == "HEAD" {
        let head = refs::read_head(&repo.gyt_dir)?;
        return refs::resolve(&repo.gyt_dir, &head)?
            .ok_or_else(|| GytError::Refs("HEAD has no commit yet".into()));
    }
    let candidates = [
        format!("refs/heads/{rev}"),
        format!("refs/tags/{rev}"),
        format!("refs/remotes/{rev}"),
    ];
    for name in &candidates {
        let p = repo.gyt_dir.join(name);
        if p.exists() {
            return refs::read_ref(&repo.gyt_dir, name);
        }
    }
    if rev.len() == HEX_LEN && rev.chars().all(|c| c.is_ascii_hexdigit()) {
        return ObjectId::from_hex(rev);
    }
    Err(GytError::NotFound(format!("revision {rev}")))
}

/// Resolve a textual revision to a tree id. Accepts commits, trees, and tags
/// (annotated tags are dereferenced, possibly recursively).
pub fn resolve_tree(repo: &Repo, rev: &str) -> Result<ObjectId> {
    let mut id = resolve_rev(repo, rev)?;
    loop {
        let obj = store::read(&repo.gyt_dir, &id)?;
        match obj.kind {
            ObjectKind::Commit => {
                let c = commit::decode(&obj.payload)?;
                return Ok(c.tree);
            }
            ObjectKind::Tree => return Ok(id),
            ObjectKind::Tag => {
                let t = tag::decode(&obj.payload)?;
                id = t.target;
                continue;
            }
            ObjectKind::Blob => {
                return Err(GytError::Object(format!(
                    "rev {rev} resolves to a blob, not a tree"
                )));
            }
        }
    }
}

/// Walk a tree object recursively. Returns a flat map: relative path
/// (forward-slash) -> (mode, blob ObjectId). Subtrees recurse; blob entries
/// are emitted as leaves.
pub fn flatten_tree(repo: &Repo, tree_id: &ObjectId) -> Result<BTreeMap<PathBuf, (u32, ObjectId)>> {
    let mut out = BTreeMap::new();
    walk_tree(repo, tree_id, Path::new(""), &mut out)?;
    Ok(out)
}

fn walk_tree(
    repo: &Repo,
    tree_id: &ObjectId,
    prefix: &Path,
    out: &mut BTreeMap<PathBuf, (u32, ObjectId)>,
) -> Result<()> {
    let entries = tree::read(&repo.gyt_dir, tree_id)?;
    for e in entries {
        let name = std::str::from_utf8(&e.name)
            .map_err(|_| GytError::Object("tree entry name is not utf-8".into()))?;
        let path = if prefix.as_os_str().is_empty() {
            PathBuf::from(name)
        } else {
            prefix.join(name)
        };
        if e.mode == tree::MODE_DIR {
            walk_tree(repo, &e.hash, &path, out)?;
        } else {
            out.insert(path, (e.mode, e.hash));
        }
    }
    Ok(())
}

/// Build a hierarchical tree structure from a flat list of index entries
/// and write each subtree object. Returns the root tree id.
pub fn build_tree_from_index(repo: &Repo, index: &Index) -> Result<ObjectId> {
    // Group entries by their immediate parent directory.
    let mut root = DirNode::default();
    for entry in &index.entries {
        insert_entry(&mut root, entry);
    }
    write_dir(repo, &root)
}

#[derive(Default)]
struct DirNode {
    files: Vec<(String, u32, ObjectId)>,
    subdirs: BTreeMap<String, DirNode>,
}

fn insert_entry(root: &mut DirNode, entry: &IndexEntry) {
    let comps: Vec<String> = entry
        .path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if comps.is_empty() {
        return;
    }
    let mut cur = root;
    for comp in &comps[..comps.len() - 1] {
        cur = cur.subdirs.entry(comp.clone()).or_default();
    }
    let leaf = comps.last().expect("non-empty");
    cur.files.push((leaf.clone(), entry.mode, entry.hash));
}

fn write_dir(repo: &Repo, node: &DirNode) -> Result<ObjectId> {
    let mut entries: Vec<tree::TreeEntry> = Vec::new();
    for (name, mode, hash) in &node.files {
        entries.push(tree::TreeEntry {
            mode: *mode,
            name: name.as_bytes().to_vec(),
            hash: *hash,
        });
    }
    for (name, sub) in &node.subdirs {
        let sub_id = write_dir(repo, sub)?;
        entries.push(tree::TreeEntry {
            mode: tree::MODE_DIR,
            name: name.as_bytes().to_vec(),
            hash: sub_id,
        });
    }
    tree::write(&repo.gyt_dir, &entries)
}

/// Resolve the symbolic HEAD to (Option<branch-name>, Option<commit-id>).
/// branch-name is `Some` when HEAD is symbolic (most common case).
pub fn current_branch_and_head(repo: &Repo) -> Result<(Option<String>, Option<ObjectId>)> {
    let head = refs::read_head(&repo.gyt_dir)?;
    let id = refs::resolve(&repo.gyt_dir, &head)?;
    let branch = match head {
        Head::Symbolic(name) => Some(name),
        Head::Detached(_) => None,
    };
    Ok((branch, id))
}

/// Test helpers shared across all `cmd::*` test modules. Tests that mutate
/// process-global state (current working directory, env vars) MUST hold this
/// lock for their entire critical section to avoid clobbering each other.
#[cfg(test)]
pub mod test_helpers {
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};

    static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

    pub fn lock() -> MutexGuard<'static, ()> {
        GLOBAL_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn tmp_dir(prefix: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        // Add a random component to dedupe within the same nanosecond.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
