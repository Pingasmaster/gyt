//! Common test scaffolding for command-level tests.
//!
//! Builds a real `.gyt` directory in a tempdir with one initial commit so
//! command logic can run end-to-end without invoking other commands.

#![cfg(test)]

use crate::hash::ObjectId;
use crate::object::{commit, tree};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::path::{Path, PathBuf};

/// A tempdir-rooted repo with one commit on `refs/heads/main` (HEAD).
pub struct TestRepo {
    pub root: PathBuf,
    _keep: TmpDir,
}

impl TestRepo {
    /// Create a tempdir and initialize `.gyt` skeleton with no commits yet.
    pub fn empty(prefix: &str) -> Self {
        let keep = TmpDir::new(prefix);
        let root = keep.path().to_path_buf();
        let gyt = root.join(".gyt");
        std::fs::create_dir_all(gyt.join("objects")).unwrap();
        std::fs::create_dir_all(gyt.join("refs/heads")).unwrap();
        std::fs::create_dir_all(gyt.join("refs/tags")).unwrap();
        // Symbolic HEAD on an unborn refs/heads/main.
        refs::write_head(&gyt, &Head::Symbolic("refs/heads/main".into())).unwrap();
        Self { root, _keep: keep }
    }

    /// Create a tempdir with `.gyt` and one initial commit on main.
    pub fn new(prefix: &str) -> Self {
        let r = Self::empty(prefix);
        let _ = r.commit_initial(&[("hello.txt", b"hello\n", false)]);
        r
    }

    pub fn gyt_dir(&self) -> PathBuf {
        self.root.join(".gyt")
    }

    pub fn open(&self) -> Repo {
        Repo::open(&self.root).unwrap()
    }

    /// Create a fresh commit with the given files and write it to refs/heads/main.
    /// Returns (commit_id, tree_id).
    pub fn commit_initial(&self, files: &[(&str, &[u8], bool)]) -> (ObjectId, ObjectId) {
        let gyt = self.gyt_dir();
        let mut entries = Vec::new();
        for (name, content, exec) in files {
            let blob_id = crate::object::blob::write(&gyt, content).unwrap();
            // Materialize on disk too, for tests that expect tracked files in workdir.
            let p = self.root.join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, content).unwrap();
            #[cfg(unix)]
            if *exec {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&p).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&p, perms).unwrap();
            }
            let mode = if *exec {
                tree::MODE_EXEC
            } else {
                tree::MODE_FILE
            };
            entries.push(tree::TreeEntry {
                mode,
                name: name.as_bytes().to_vec(),
                hash: blob_id,
            });
        }
        let tree_id = tree::write(&gyt, &entries).unwrap();
        let c = commit::Commit {
            tree: tree_id,
            parents: vec![],
            authors: vec!["Tester <t@x> 1700000000 +0000".into()],
            committer: "Tester <t@x> 1700000000 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "init\n".into(),
        };
        let cid = commit::write(&gyt, &c).unwrap();
        refs::write_ref(&gyt, "refs/heads/main", &cid).unwrap();

        // Build an index entry set matching the tree (so reset/restore tests
        // see a sane baseline).
        crate::cmd::test_support::write_index_for_tree(&self.root, &tree_id);

        (cid, tree_id)
    }

    /// Create a follow-up commit with a different file set on top of HEAD.
    pub fn commit_next(&self, files: &[(&str, &[u8], bool)]) -> (ObjectId, ObjectId) {
        let gyt = self.gyt_dir();
        let head = refs::read_head(&gyt).unwrap();
        let parent = refs::resolve(&gyt, &head).unwrap();

        let mut entries = Vec::new();
        for (name, content, exec) in files {
            let blob_id = crate::object::blob::write(&gyt, content).unwrap();
            let p = self.root.join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, content).unwrap();
            let mode = if *exec {
                tree::MODE_EXEC
            } else {
                tree::MODE_FILE
            };
            entries.push(tree::TreeEntry {
                mode,
                name: name.as_bytes().to_vec(),
                hash: blob_id,
            });
        }
        let tree_id = tree::write(&gyt, &entries).unwrap();
        let c = commit::Commit {
            tree: tree_id,
            parents: parent.into_iter().collect(),
            authors: vec!["Tester <t@x> 1700000001 +0000".into()],
            committer: "Tester <t@x> 1700000001 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "next\n".into(),
        };
        let cid = commit::write(&gyt, &c).unwrap();
        // Move HEAD's underlying ref forward.
        if let Head::Symbolic(rname) = refs::read_head(&gyt).unwrap() {
            refs::write_ref(&gyt, &rname, &cid).unwrap();
        } else {
            refs::write_head(&gyt, &Head::Detached(cid)).unwrap();
        }
        crate::cmd::test_support::write_index_for_tree(&self.root, &tree_id);
        (cid, tree_id)
    }
}

/// Build an index file from a flat tree (no subtrees needed here).
pub fn write_index_for_tree(root: &Path, tree_id: &ObjectId) {
    let gyt = root.join(".gyt");
    let entries = tree::read(&gyt, tree_id).unwrap();
    let mut idx = crate::index::Index::new();
    for te in entries {
        let path = std::str::from_utf8(&te.name).unwrap().to_string();
        idx.insert(crate::index::IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: te.mode,
            hash: te.hash,
            path: PathBuf::from(path),
        });
    }
    idx.write(&gyt.join("index")).unwrap();
}

pub struct TmpDir(PathBuf);

impl TmpDir {
    pub fn new(prefix: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        // Add a per-call counter so prefix collisions across tests are avoided.
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
