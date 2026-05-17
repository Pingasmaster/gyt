// Working tree scan + helpers used by status/diff. The walker skips
// `.gyt/` and any path matched by the supplied IgnoreSet. Symlinks are
// listed but not descended into.

use crate::errors::{GytError, Result};
use crate::hash::{self, ObjectId};
use crate::ignore::IgnoreSet;
use crate::object::{ObjectKind, store};
use crate::repo::GYT_DIR;

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkdirEntry {
    /// Path relative to the workdir, in forward-slash form.
    pub path: PathBuf,
    pub is_dir: bool,
    /// Git-style file mode: 0o100644 / 0o100755 / 0o120000 / 0o040000.
    pub mode: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileState {
    Untracked,
    /// Workdir differs from index.
    Modified,
    /// Index differs from HEAD.
    Staged,
    /// Both `Staged` and `Modified`.
    StagedAndModified,
    /// Tracked in index but missing from workdir.
    Deleted,
    Unchanged,
}

#[derive(Debug, Default)]
pub struct StatusReport {
    pub entries: Vec<(PathBuf, FileState)>,
}

const MODE_REGULAR: u32 = 0o100_644;
const MODE_EXEC: u32 = 0o100_755;
const MODE_SYMLINK: u32 = 0o120_000;
const MODE_DIR: u32 = 0o040_000;

/// Verify that every ancestor of `rel` under `workdir` is either
/// missing or a real directory — never a symlink. Returns the joined
/// absolute path safe to open / write to.
///
/// Closes H5: every materializer site previously did
/// `fs::create_dir_all(parent); fs::write(abs, ...)`. Both follow
/// symlinks. If a workdir parent dir was replaced by a symlink to
/// `~/.ssh` (planted by a malicious local process, or by a previous
/// checkout of a tree whose entry name pointed at an attacker target),
/// the next checkout's write to `workdir/a/file.txt` lands in
/// `~/.ssh/file.txt`. `validate_symlink_target` only prevents *gyt*
/// from planting the trap — it does not detect a pre-existing trap.
///
/// This helper walks `rel`'s parent components one at a time, stating
/// each with `symlink_metadata` (which does NOT follow links), and
/// errors out if any existing ancestor is a symlink.
pub fn safe_workdir_path(workdir: &Path, rel: &Path) -> Result<PathBuf> {
    if rel.is_absolute() {
        return Err(GytError::Repo(format!(
            "safe_workdir_path: refusing absolute path {}",
            rel.display()
        )));
    }
    let mut cur = workdir.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            match comp {
                std::path::Component::Normal(name) => {
                    cur.push(name);
                    if let Ok(meta) = fs::symlink_metadata(&cur)
                        && meta.file_type().is_symlink()
                    {
                        return Err(GytError::Repo(format!(
                            "safe_workdir_path: ancestor {} is a symlink",
                            cur.display()
                        )));
                    }
                }
                std::path::Component::CurDir => {}
                _ => {
                    return Err(GytError::Repo(format!(
                        "safe_workdir_path: refusing path with non-normal component {}",
                        rel.display()
                    )));
                }
            }
        }
    }
    Ok(workdir.join(rel))
}

/// Atomically write `data` to `workdir/rel` after verifying no ancestor
/// is a symlink (H5). If the leaf already exists as a symlink, it is
/// removed first so the subsequent open doesn't follow it.
pub fn safe_workdir_write(workdir: &Path, rel: &Path, data: &[u8]) -> Result<()> {
    let abs = safe_workdir_path(workdir, rel)?;
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&abs)
        && meta.file_type().is_symlink()
    {
        fs::remove_file(&abs)?;
    }
    fs::write(&abs, data)?;
    Ok(())
}

/// Validate a symlink target before creating it on disk. A malicious
/// tree object can carry a blob whose contents (the symlink target) is
/// `/etc`, `..`, or anything else that would escape the workdir.
/// Without this gate, a subsequent file entry under the link (e.g.
/// `link/something`) is materialized through the link via
/// `create_dir_all` — git's classic symlink-then-write workdir escape
/// (CVE-2014-9390, CVE-2017-1000117, CVE-2019-1353).
///
/// Rules:
/// - target is non-empty
/// - target is not absolute (no leading `/`)
/// - no path component equals `..`
/// - no embedded NUL byte
/// - length ≤ 4096 bytes (PATH_MAX on Linux)
///
/// We intentionally do NOT canonicalize against the workdir here: the
/// target is a blob payload supplied by the tree object, and we want
/// the rule to be context-free so wire-side gates and read-side
/// materializers agree on what's safe.
pub fn validate_symlink_target(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(GytError::Object("symlink: empty target".into()));
    }
    if target.len() > 4096 {
        return Err(GytError::Object(format!(
            "symlink: target length {} exceeds 4096",
            target.len()
        )));
    }
    if target.as_bytes().contains(&0) {
        return Err(GytError::Object("symlink: NUL in target".into()));
    }
    let p = Path::new(target);
    if p.is_absolute() {
        return Err(GytError::Object(format!(
            "symlink: absolute target {target:?} not allowed"
        )));
    }
    for c in p.components() {
        if matches!(c, std::path::Component::ParentDir) {
            return Err(GytError::Object(format!(
                "symlink: target {target:?} contains parent reference"
            )));
        }
    }
    Ok(())
}

/// Convert a relative path to forward-slash form and return as a String.
fn rel_to_forward_slash(rel: &Path) -> String {
    let mut s = String::new();
    let mut first = true;
    for comp in rel.components() {
        let part = comp.as_os_str().to_string_lossy();
        if !first {
            s.push('/');
        }
        first = false;
        s.push_str(part.as_ref());
    }
    s
}

/// Compute the git-style mode for an entry from its `fs::Metadata`.
/// On Unix we honor the executable bit; on other platforms we fall back to
/// `MODE_REGULAR` for files.
fn mode_for(meta: &fs::Metadata) -> u32 {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return MODE_SYMLINK;
    }
    if ft.is_dir() {
        return MODE_DIR;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = meta.permissions().mode();
        if perm & 0o111 != 0 {
            return MODE_EXEC;
        }
        MODE_REGULAR
    }
    #[cfg(not(unix))]
    {
        MODE_REGULAR
    }
}

/// Recursively walk `workdir`, skipping `.gyt/` and any path matched by `ignore`.
/// Returns paths relative to `workdir`, forward-slash form. Symlinks are listed
/// but not descended into.
pub fn walk(workdir: &Path, ignore: &IgnoreSet) -> Result<Vec<WorkdirEntry>> {
    let mut out = Vec::new();
    walk_recurse(workdir, workdir, ignore, &mut out)?;
    // Stable, deterministic ordering for callers/tests.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn walk_recurse(
    root: &Path,
    dir: &Path,
    ignore: &IgnoreSet,
    out: &mut Vec<WorkdirEntry>,
) -> Result<()> {
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            return Err(GytError::Repo(format!(
                "failed to read directory {}: {e}",
                dir.display()
            )));
        }
    };
    for ent in read {
        let ent = ent?;
        let name = ent.file_name();
        let name_str = name.to_string_lossy();

        // Skip the repo's own metadata directory at any nesting level (we
        // only ever encounter it at root, but the check is cheap and safe).
        if name_str == GYT_DIR {
            continue;
        }

        let abs = ent.path();
        let rel = abs
            .strip_prefix(root)
            .map_err(|_| GytError::Repo("path not under workdir".into()))?
            .to_path_buf();
        let rel_str = rel_to_forward_slash(&rel);

        // We need to know if this is a directory before consulting ignore,
        // so use symlink_metadata (don't follow symlinks).
        let meta = ent.file_type()?;
        let is_dir = meta.is_dir() && !meta.is_symlink();

        if ignore.matched(&rel_str, is_dir) {
            continue;
        }

        let md = fs::symlink_metadata(&abs)?;
        let mode = mode_for(&md);
        out.push(WorkdirEntry {
            path: PathBuf::from(&rel_str),
            is_dir,
            mode,
        });

        if is_dir {
            walk_recurse(root, &abs, ignore, out)?;
        }
    }
    Ok(())
}

/// Hash the content of one workdir file as if it were stored as a Blob in
/// the object store. Returns the would-be ObjectId without writing anything.
/// Matches `object::store::write_bytes(_, ObjectKind::Blob, payload)`.
pub fn hash_blob(path: &Path) -> Result<ObjectId> {
    let payload = fs::read(path)?;
    let raw = store::build_raw(ObjectKind::Blob, &payload);
    Ok(hash::hash_bytes(&raw))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::object::blob;
    use std::fs;

    // Tiny tempdir helper, mirroring the pattern used in object::store.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(prefix: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn walk_skips_dot_gyt() {
        let t = TmpDir::new("gyt-walk-dotgyt");
        let root = t.path();
        // a real .gyt directory with some contents
        fs::create_dir_all(root.join(".gyt").join("objects")).unwrap();
        fs::write(root.join(".gyt").join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        // and one regular file
        fs::write(root.join("hello.txt"), b"hi\n").unwrap();

        let ignore = IgnoreSet::new();
        let entries = walk(root, &ignore).unwrap();
        for e in &entries {
            let s = e.path.to_string_lossy();
            assert!(!s.starts_with(".gyt"), "walker leaked .gyt entry: {s}");
        }
        assert!(
            entries.iter().any(|e| e.path == Path::new("hello.txt")),
            "expected hello.txt in walk: {entries:?}"
        );
    }

    #[test]
    fn walk_skips_ignored() {
        // With the stub IgnoreSet, nothing extra is ignored. We only assert
        // that .gyt is still skipped — full ignore-rule tests live in 3b.
        let t = TmpDir::new("gyt-walk-ignored");
        let root = t.path();
        fs::create_dir_all(root.join(".gyt")).unwrap();
        fs::write(root.join("a.txt"), b"a\n").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("b.txt"), b"b\n").unwrap();

        let ignore = IgnoreSet::new();
        let entries = walk(root, &ignore).unwrap();
        let paths: Vec<String> = entries
            .iter()
            .map(|e| e.path.to_string_lossy().into_owned())
            .collect();
        assert!(paths.iter().all(|p| !p.starts_with(".gyt")));
        assert!(paths.contains(&"a.txt".to_string()));
        assert!(paths.contains(&"sub".to_string()));
        assert!(paths.contains(&"sub/b.txt".to_string()));
    }

    #[test]
    fn hash_blob_matches_object_store_write() {
        let t = TmpDir::new("gyt-hashblob");
        let root = t.path();
        let dir = root.join(".gyt");
        fs::create_dir_all(dir.join("objects")).unwrap();

        let content: &[u8] = b"the quick brown fox\n";
        let file_path = root.join("fox.txt");
        fs::write(&file_path, content).unwrap();

        // Hash via the new helper.
        let id_via_hash = hash_blob(&file_path).unwrap();
        // Hash via writing to the store.
        let id_via_write = blob::write(&dir, content).unwrap();

        assert_eq!(id_via_hash, id_via_write);
    }
}
