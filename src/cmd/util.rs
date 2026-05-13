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
/// HEAD, HEAD~N (Nth ancestor along the first-parent chain), branch
/// refs, tag refs, remote refs, full or abbreviated BLAKE3 hex id.
/// Abbreviated hex resolves only when it uniquely matches one object
/// in the local store (loose or packed); ambiguous prefixes error.
/// Returns an error if not found.
pub fn resolve_rev(repo: &Repo, rev: &str) -> Result<ObjectId> {
    // `HEAD~N` — walk N first-parent commits back from HEAD.
    if let Some(rest) = rev.strip_prefix("HEAD~") {
        let n: u32 = rest
            .parse()
            .map_err(|_| GytError::InvalidArgument(format!("bad HEAD~N: {rev:?}")))?;
        let head = refs::read_head(&repo.gyt_dir)?;
        let mut id = refs::resolve(&repo.gyt_dir, &head)?
            .ok_or_else(|| GytError::Refs("HEAD has no commit yet".into()))?;
        for _ in 0..n {
            let obj = store::read(&repo.gyt_dir, &id)?;
            if obj.kind != ObjectKind::Commit {
                return Err(GytError::Object(format!(
                    "HEAD~ walk hit non-commit at {id}"
                )));
            }
            let c = commit::decode(&obj.payload)?;
            id = c
                .parents
                .first()
                .copied()
                .ok_or_else(|| GytError::NotFound(format!("{rev}: ran off root")))?;
        }
        return Ok(id);
    }
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
    // Abbreviated hex: at least 4 chars. Require unique match. We scan
    // both loose objects (objects/<2>/<62>) and pack indexes.
    if rev.len() >= 4 && rev.len() < HEX_LEN && rev.chars().all(|c| c.is_ascii_hexdigit()) {
        let matches = find_objects_with_prefix(&repo.gyt_dir, rev);
        return match matches.len() {
            0 => Err(GytError::NotFound(format!("revision {rev}"))),
            1 => Ok(matches[0]),
            _ => Err(GytError::InvalidArgument(format!(
                "revision {rev} is ambiguous ({} matches)",
                matches.len()
            ))),
        };
    }
    Err(GytError::NotFound(format!("revision {rev}")))
}

/// Find all object ids in the store whose hex form starts with `prefix`.
/// Scans loose `<2>/<62>` shards and the entries in every `.idx`.
fn find_objects_with_prefix(gyt_dir: &std::path::Path, prefix: &str) -> Vec<ObjectId> {
    let prefix_lower = prefix.to_ascii_lowercase();
    let mut out: Vec<ObjectId> = Vec::new();
    let objects = gyt_dir.join("objects");
    if let Ok(top) = std::fs::read_dir(&objects) {
        for shard in top.flatten() {
            let p = shard.path();
            let dir_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            if dir_name.len() != 2 || !dir_name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            // Quick reject: if the prefix's first 2 chars don't match this shard,
            // there's no point opening it.
            if prefix_lower.len() >= 2 && !dir_name.starts_with(&prefix_lower[..2]) {
                continue;
            }
            if let Ok(files) = std::fs::read_dir(&p) {
                for f in files.flatten() {
                    let fp = f.path();
                    let file_name = fp
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_string();
                    if file_name.len() != 62 || !file_name.bytes().all(|b| b.is_ascii_hexdigit()) {
                        continue;
                    }
                    let hex = format!("{dir_name}{file_name}");
                    if hex.starts_with(&prefix_lower)
                        && let Ok(id) = ObjectId::from_hex(&hex)
                    {
                        out.push(id);
                    }
                }
            }
        }
    }
    // Pack index scan.
    let pack_dir = objects.join("pack");
    if let Ok(it) = std::fs::read_dir(&pack_dir) {
        for f in it.flatten() {
            let p = f.path();
            if p.extension().and_then(|s| s.to_str()) != Some("idx") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&p)
                && bytes.len() >= 12
                && &bytes[..4] == b"GYPI"
            {
                let count =
                    u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
                // Entry layout in pack idx: 32B hash + 8B offset.
                let entries_start = 12;
                for i in 0..count {
                    let off = entries_start + i * 40;
                    if off + 32 > bytes.len() {
                        break;
                    }
                    let hash_bytes = &bytes[off..off + 32];
                    let mut hex = String::with_capacity(64);
                    for b in hash_bytes {
                        use std::fmt::Write as _;
                        let _ = write!(hex, "{b:02x}");
                    }
                    if hex.starts_with(&prefix_lower)
                        && let Ok(id) = ObjectId::from_hex(&hex)
                    {
                        out.push(id);
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
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
    subdirs: BTreeMap<String, Self>,
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
        GLOBAL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn tmp_dir(prefix: &str) -> PathBuf {
        #[allow(clippy::items_after_statements)]
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        // Add a random component to dedupe within the same nanosecond.
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
