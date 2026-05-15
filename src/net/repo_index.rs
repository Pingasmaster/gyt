// In-memory index of every repository under `repos_root`. Built once
// at server startup, kept up-to-date by wire_refs_update, and re-
// scanned periodically to catch operator-side `gyt init` outside the
// wire protocol.
//
// The /api/repos endpoint previously did O(N) work per request:
//   read_dir(repos_root) → for each owner → read_dir(owner) → for
//   each repo → open Repo, read HEAD, read default branch.
//
// For 1M repos that's ~3M filesystem operations per request, even
// when the same client paginates page after page over the same data.
// The 2-second response cache hid this somewhat, but the *first*
// request after every refs/update or cache expiry paid the full cost.
//
// Memory budget: at ~100 bytes per entry (two short strings, two
// commit hex strings) × 1M repos ≈ 100 MiB resident. Acceptable on
// any production-shape server.
//
// Pagination: O(per_page) — we hold a Vec sorted by (owner, name)
// and slice it directly. No more "skip N then take M" iteration.

use std::path::Path;
use std::sync::RwLock;

use crate::refs;
use crate::repo::Repo;

#[derive(Clone, Debug)]
pub struct RepoIndexEntry {
    pub owner: String,
    pub name: String,
    pub default_branch: String,
    pub head_commit: Option<String>,
}

pub struct RepoIndex {
    /// Sorted ascending by (owner, name). Held under an RwLock so the
    /// read path (which is the hot path — every /api/repos request)
    /// doesn't contend with itself; writes (refs/update + the
    /// periodic re-scan) take exclusive access for the short
    /// duration of an entry update.
    entries: RwLock<Vec<RepoIndexEntry>>,
}

impl RepoIndex {
    /// Scan `repos_root` from scratch and build a sorted index.
    /// O(N repos) work — at startup this is unavoidable; we want to
    /// know how many repos exist before the first request lands.
    /// Logs progress on stderr so an operator monitoring boot can
    /// tell the difference between "indexing" and "stuck."
    pub fn build(repos_root: &Path) -> Self {
        let started = std::time::Instant::now();
        let entries = scan_all(repos_root);
        eprintln!(
            "gyt serve: indexed {} repos in {:.2?}",
            entries.len(),
            started.elapsed()
        );
        Self {
            entries: RwLock::new(entries),
        }
    }

    /// Page through the index. Returns (page items, total count).
    /// Both args are 1-based for `page`, and `per_page` is the slice
    /// length. Out-of-range pages return an empty slice with the
    /// correct total — matching the existing /api/repos contract.
    pub fn list(&self, page: usize, per_page: usize) -> (Vec<RepoIndexEntry>, usize) {
        let g = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let total = g.len();
        let start = page.saturating_sub(1).saturating_mul(per_page);
        let end = start.saturating_add(per_page).min(total);
        if start >= total {
            return (Vec::new(), total);
        }
        (g[start..end].to_vec(), total)
    }

    /// Look up a single entry. None if not in the index.
    pub fn get(&self, owner: &str, name: &str) -> Option<RepoIndexEntry> {
        let g = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (owner, name);
        match g.binary_search_by(|e| (e.owner.as_str(), e.name.as_str()).cmp(&key)) {
            Ok(i) => Some(g[i].clone()),
            Err(_) => None,
        }
    }

    /// Re-read one repo's metadata and upsert it into the index. Call
    /// after a successful refs/update so the next /api/repos hit
    /// reflects the new head.
    pub fn refresh(&self, repos_root: &Path, owner: &str, name: &str) {
        let Some(entry) = scan_one(repos_root, owner, name) else {
            return;
        };
        self.upsert(entry);
    }

    /// Upsert (sorted-position) a single entry. Binary search + insert
    /// is O(N) on the shift, but updates are dominated by the disk
    /// I/O that produced the entry; in-place shift of 1M Vec entries
    /// is ~5 ms.
    pub fn upsert(&self, entry: RepoIndexEntry) {
        let mut g = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (entry.owner.as_str(), entry.name.as_str());
        match g.binary_search_by(|e| (e.owner.as_str(), e.name.as_str()).cmp(&key)) {
            Ok(i) => g[i] = entry,
            Err(i) => g.insert(i, entry),
        }
    }

    /// Drop an entry (e.g., operator removed a repo). Best-effort —
    /// missing keys are silently ignored.
    #[allow(dead_code)]
    pub fn remove(&self, owner: &str, name: &str) {
        let mut g = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (owner, name);
        if let Ok(i) = g.binary_search_by(|e| (e.owner.as_str(), e.name.as_str()).cmp(&key)) {
            g.remove(i);
        }
    }

    /// Wholesale rebuild from disk. Used by the periodic refresh
    /// thread so operator-side `gyt init` (outside the wire protocol)
    /// shows up in /api/repos within at most one refresh interval.
    pub fn rescan(&self, repos_root: &Path) {
        let fresh = scan_all(repos_root);
        let mut g = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *g = fresh;
    }

    pub fn count(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Read every `<repos_root>/<owner>/<name>` that looks like a non-bare
/// repo and return it sorted. Bare repos (no `.gyt` subdir but a HEAD
/// at the root) are detected the same way the wire path detects them.
/// We deliberately ignore everything that doesn't match — random
/// directories under repos_root shouldn't appear in /api/repos.
fn scan_all(repos_root: &Path) -> Vec<RepoIndexEntry> {
    let mut out = Vec::new();
    let Ok(top) = std::fs::read_dir(repos_root) else {
        return out;
    };
    for owner_ent in top.flatten() {
        if !owner_ent.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let owner = owner_ent.file_name().to_string_lossy().into_owned();
        let owner_path = owner_ent.path();
        let Ok(repos) = std::fs::read_dir(&owner_path) else {
            continue;
        };
        for repo_ent in repos.flatten() {
            if !repo_ent.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let name = repo_ent.file_name().to_string_lossy().into_owned();
            let repo_path = repo_ent.path();
            let is_non_bare = repo_path.join(".gyt").is_dir();
            let is_bare = repo_path.join("HEAD").is_file();
            if !is_non_bare && !is_bare {
                continue;
            }
            if let Some(entry) = read_metadata(&repo_path, &owner, &name) {
                out.push(entry);
            }
        }
    }
    out.sort_by(|a, b| (&a.owner, &a.name).cmp(&(&b.owner, &b.name)));
    out
}

/// Build a single entry by re-reading the repo's HEAD and default-
/// branch. Returns None if the path doesn't actually contain a repo
/// or the open fails — caller treats that as "drop from index."
fn scan_one(repos_root: &Path, owner: &str, name: &str) -> Option<RepoIndexEntry> {
    let path = repos_root.join(owner).join(name);
    read_metadata(&path, owner, name)
}

fn read_metadata(repo_path: &Path, owner: &str, name: &str) -> Option<RepoIndexEntry> {
    let repo = Repo::open(repo_path).ok()?;
    let head = refs::read_head(&repo.gyt_dir).ok()?;
    let default_branch = match &head {
        refs::Head::Symbolic(b) => b.trim_start_matches("refs/heads/").to_string(),
        refs::Head::Detached(_) => "main".to_string(),
    };
    let head_commit = refs::resolve(&repo.gyt_dir, &head)
        .ok()
        .flatten()
        .map(crate::hash::ObjectId::to_hex);
    Some(RepoIndexEntry {
        owner: owner.to_string(),
        name: name.to_string(),
        default_branch,
        head_commit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::init;

    fn tmp_root(prefix: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_bare(root: &Path, owner: &str, name: &str) {
        let dir = root.join(owner).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        init::init_at(&dir).unwrap();
    }

    #[test]
    fn build_lists_repos_sorted() {
        let root = tmp_root("repo-index-build");
        make_bare(&root, "bob", "z");
        make_bare(&root, "alice", "a");
        make_bare(&root, "alice", "m");
        let idx = RepoIndex::build(&root);
        assert_eq!(idx.count(), 3);
        let (page, total) = idx.list(1, 10);
        assert_eq!(total, 3);
        assert_eq!(
            page.iter()
                .map(|e| (e.owner.clone(), e.name.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("alice".to_string(), "a".to_string()),
                ("alice".to_string(), "m".to_string()),
                ("bob".to_string(), "z".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pagination_bounds_correct() {
        let root = tmp_root("repo-index-page");
        for i in 0..25u32 {
            make_bare(&root, "alice", &format!("r{i:02}"));
        }
        let idx = RepoIndex::build(&root);
        let (p1, total) = idx.list(1, 10);
        assert_eq!(total, 25);
        assert_eq!(p1.len(), 10);
        let (p3, _) = idx.list(3, 10);
        assert_eq!(p3.len(), 5);
        let (p4, _) = idx.list(4, 10);
        assert!(p4.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_picks_up_new_repo() {
        let root = tmp_root("repo-index-refresh");
        make_bare(&root, "alice", "a");
        let idx = RepoIndex::build(&root);
        assert_eq!(idx.count(), 1);
        make_bare(&root, "alice", "b");
        idx.refresh(&root, "alice", "b");
        assert_eq!(idx.count(), 2);
        assert!(idx.get("alice", "b").is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rescan_replaces_index() {
        let root = tmp_root("repo-index-rescan");
        make_bare(&root, "alice", "a");
        let idx = RepoIndex::build(&root);
        assert_eq!(idx.count(), 1);
        // Operator adds a repo directly on disk; the wire path
        // never sees it.
        make_bare(&root, "bob", "c");
        idx.rescan(&root);
        assert_eq!(idx.count(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }
}
