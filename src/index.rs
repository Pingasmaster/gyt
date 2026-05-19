// GYTI v1 binary index.
// magic "GYTI" (4 bytes) + version u32 LE + entry_count u32 LE + entries.
// Each entry:
//   ctime_secs i64 LE, mtime_secs i64 LE, size u64 LE, mode u32 LE,
//   hash [u8;32], path_len u16 LE, path bytes (utf-8, forward-slash separated).

use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::{HASH_LEN, ObjectId};
use std::path::{Path, PathBuf};

/// Magic bytes that identify a GYT index file.
pub const MAGIC: &[u8; 4] = b"GYTI";
/// Current index format version.
pub const VERSION: u32 = 1;

const HEADER_LEN: usize = 4 + 4 + 4; // magic + version + count
const ENTRY_FIXED_LEN: usize = 8 + 8 + 8 + 4 + HASH_LEN + 2; // 62 bytes before path

/// A single entry in the index, representing one path tracked in the staging area.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Creation time in seconds since the Unix epoch.
    pub ctime_secs: i64,
    /// Modification time in seconds since the Unix epoch.
    pub mtime_secs: i64,
    /// File size in bytes.
    pub size: u64,
    /// Git-style file mode (e.g. 0o100644 for regular files).
    pub mode: u32,
    /// BLAKE3 hash of the blob content.
    pub hash: ObjectId,
    /// Path relative to the repository root.
    pub path: PathBuf,
}

/// The in-memory index (staging area) backed by a GYTI binary file on disk.
#[derive(Debug, Default)]
pub struct Index {
    /// List of indexed entries, sorted by path on write.
    pub entries: Vec<IndexEntry>,
}

/// Reject paths that would escape the workdir or shadow `.gyt/`
/// metadata. Called by `Index::decode` for every entry's path bytes
/// after UTF-8 validation. The same shape of check belongs at every
/// boundary that materializes index entries to the filesystem; doing
/// it at the parse seam guarantees no downstream consumer ever sees
/// one of these paths.
///
/// Rejects:
///   - empty paths
///   - absolute paths (`/...`)
///   - any `..` or `.` component
///   - empty components (e.g. `a//b`)
///   - backslash anywhere (NTFS/exFAT path separator confusion)
///   - NUL byte (path-truncation in C/Rust FFI boundaries)
///   - any `.gyt` component (case-insensitive — APFS/NTFS/casefolded ext4)
fn validate_index_path(path: &str, entry_idx: usize) -> Result<()> {
    if path.is_empty() {
        return Err(GytError::Index(format!(
            "empty path in entry {entry_idx}"
        )));
    }
    if path.starts_with('/') {
        return Err(GytError::Index(format!(
            "absolute path in entry {entry_idx}: {path:?}"
        )));
    }
    if path.contains('\0') {
        return Err(GytError::Index(format!(
            "path contains NUL in entry {entry_idx}: {path:?}"
        )));
    }
    if path.contains('\\') {
        return Err(GytError::Index(format!(
            "path contains backslash in entry {entry_idx}: {path:?}"
        )));
    }
    for comp in path.split('/') {
        if comp.is_empty() {
            return Err(GytError::Index(format!(
                "empty path component in entry {entry_idx}: {path:?}"
            )));
        }
        if comp == "." || comp == ".." {
            return Err(GytError::Index(format!(
                "path traversal component in entry {entry_idx}: {path:?}"
            )));
        }
        if comp.eq_ignore_ascii_case(".gyt") {
            return Err(GytError::Index(format!(
                "path enters .gyt/ in entry {entry_idx}: {path:?}"
            )));
        }
    }
    Ok(())
}

/// Normalize a path to a forward-slash relative string suitable for storage.
fn path_to_storage_string(path: &Path) -> String {
    // We're linux-only; normalize backslashes if any sneak in.
    let mut s = String::new();
    for (i, comp) in path.components().enumerate() {
        use std::path::Component;
        match comp {
            Component::Normal(os) => {
                if i > 0 {
                    s.push('/');
                }
                s.push_str(&os.to_string_lossy());
            }
            Component::CurDir => {}
            // Other components (RootDir, ParentDir, Prefix) shouldn't appear in
            // valid relative index paths; preserve them lossily for safety.
            other => {
                if i > 0 {
                    s.push('/');
                }
                s.push_str(&other.as_os_str().to_string_lossy());
            }
        }
    }
    // If for some reason the loop above produced an empty string but the input
    // was non-empty, fall back to the lossy original with separators normalized.
    if s.is_empty() && !path.as_os_str().is_empty() {
        s = path.to_string_lossy().replace('\\', "/");
    }
    s
}

fn path_storage_bytes(path: &Path) -> Vec<u8> {
    path_to_storage_string(path).into_bytes()
}

impl Index {
    /// Create a new, empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Find the index entry for the given path, or None if absent.
    pub fn find(&self, path: &Path) -> Option<&IndexEntry> {
        let key = path_storage_bytes(path);
        self.entries
            .iter()
            .find(|e| path_storage_bytes(&e.path) == key)
    }

    /// Insert or replace an entry in the index by its path.
    pub fn insert(&mut self, entry: IndexEntry) {
        let key = path_storage_bytes(&entry.path);
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| path_storage_bytes(&e.path) == key)
        {
            *slot = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Remove the entry matching the given path. Returns true if an entry was removed.
    pub fn remove(&mut self, path: &Path) -> bool {
        let key = path_storage_bytes(path);
        let before = self.entries.len();
        self.entries.retain(|e| path_storage_bytes(&e.path) != key);
        self.entries.len() != before
    }

    /// Read the index from a GYTI binary file on disk. Returns an empty index if the file does not exist.
    pub fn read(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = fs_util::read_all(path)?;
        Self::parse(&data)
    }

    /// Write the index as a GYTI binary file, sorted by path.
    pub fn write(&self, path: &Path) -> Result<()> {
        // Sort entries by their stored (forward-slash utf-8) bytes.
        let mut sorted: Vec<&IndexEntry> = self.entries.iter().collect();
        sorted.sort_by_key(|a| path_storage_bytes(&a.path));

        let mut buf: Vec<u8> = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        let count: u32 = sorted.len().try_into().map_err(|_| {
            GytError::Index(format!("too many entries to encode: {}", sorted.len()))
        })?;
        buf.extend_from_slice(&count.to_le_bytes());

        for e in sorted {
            buf.extend_from_slice(&e.ctime_secs.to_le_bytes());
            buf.extend_from_slice(&e.mtime_secs.to_le_bytes());
            buf.extend_from_slice(&e.size.to_le_bytes());
            buf.extend_from_slice(&e.mode.to_le_bytes());
            buf.extend_from_slice(&e.hash.0);
            let path_bytes = path_storage_bytes(&e.path);
            let path_len: u16 = path_bytes.len().try_into().map_err(|_| {
                GytError::Index(format!(
                    "path too long for u16 encoding: {} bytes",
                    path_bytes.len()
                ))
            })?;
            buf.extend_from_slice(&path_len.to_le_bytes());
            buf.extend_from_slice(&path_bytes);
        }

        fs_util::atomic_write(path, &buf)?;
        Ok(())
    }

    #[expect(
        clippy::indexing_slicing,
        clippy::expect_used,
        clippy::unwrap_in_result,
        reason = "every slice and try_into is bounded by an explicit data.len() check immediately above; expect()s on try_into can never fire because the slice length is exactly the array length"
    )]
    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            return Err(GytError::Index(format!(
                "index truncated: {} bytes (need at least {HEADER_LEN})",
                data.len()
            )));
        }
        if &data[..4] != MAGIC {
            return Err(GytError::Index(format!(
                "bad magic: expected {:?}, got {:?}",
                MAGIC,
                &data[..4]
            )));
        }
        let version = u32::from_le_bytes(data[4..8].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(GytError::Index(format!(
                "unsupported version: {version} (expected {VERSION})"
            )));
        }
        let count = u32::from_le_bytes(data[8..12].try_into().expect("4 bytes")) as usize;

        // `count` is attacker-controlled (it's a u32 from the on-disk
        // header). A maliciously-crafted index declaring `count = u32::MAX`
        // would otherwise trigger `Vec::with_capacity(~4B)` of IndexEntry
        // (≈80–100 B each → ~320–400 GB virtual alloc) and abort the
        // process. Reject any count that cannot possibly fit in the
        // remaining bytes before allocating.
        let min_remaining = data.len().saturating_sub(HEADER_LEN);
        if count.saturating_mul(ENTRY_FIXED_LEN) > min_remaining {
            return Err(GytError::Index(format!(
                "index claims {count} entries but only {min_remaining} bytes remain after header"
            )));
        }
        let mut entries = Vec::with_capacity(count);
        let mut off = HEADER_LEN;
        for i in 0..count {
            if data.len() < off + ENTRY_FIXED_LEN {
                return Err(GytError::Index(format!(
                    "index truncated in entry {i} fixed header"
                )));
            }
            let ctime_secs = i64::from_le_bytes(data[off..off + 8].try_into().expect("8 bytes"));
            off += 8;
            let mtime_secs = i64::from_le_bytes(data[off..off + 8].try_into().expect("8 bytes"));
            off += 8;
            let size = u64::from_le_bytes(data[off..off + 8].try_into().expect("8 bytes"));
            off += 8;
            let mode = u32::from_le_bytes(data[off..off + 4].try_into().expect("4 bytes"));
            off += 4;
            let mut hash_bytes = [0u8; HASH_LEN];
            hash_bytes.copy_from_slice(&data[off..off + HASH_LEN]);
            off += HASH_LEN;
            let path_len =
                u16::from_le_bytes(data[off..off + 2].try_into().expect("2 bytes")) as usize;
            off += 2;
            if data.len() < off + path_len {
                return Err(GytError::Index(format!(
                    "index truncated in entry {i} path ({path_len} bytes)"
                )));
            }
            let path_bytes = &data[off..off + path_len];
            let path_str = std::str::from_utf8(path_bytes)
                .map_err(|_| GytError::Index(format!("non-utf8 path bytes in entry {i}")))?;
            off += path_len;

            // Reject any path that would escape the workdir or shadow a
            // refs/lock file. Downstream materialization sites also call
            // workdir::safe_workdir_path which symlink-checks ancestors,
            // but rejecting at the parse seam is defense-in-depth: a
            // tampered-with `.gyt/index` can't smuggle a `../etc/passwd`
            // path past *any* future caller that forgets the helper.
            validate_index_path(path_str, i)?;

            entries.push(IndexEntry {
                ctime_secs,
                mtime_secs,
                size,
                mode,
                hash: ObjectId(hash_bytes),
                path: PathBuf::from(path_str),
            });
        }

        if off != data.len() {
            return Err(GytError::Index(format!(
                "trailing garbage after index entries: {} bytes left",
                data.len() - off
            )));
        }

        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::hash::{HASH_LEN, ObjectId};

    fn dummy_id(byte: u8) -> ObjectId {
        ObjectId([byte; HASH_LEN])
    }

    fn entry(path: &str, byte: u8) -> IndexEntry {
        IndexEntry {
            ctime_secs: 1_700_000_000 + i64::from(byte),
            mtime_secs: 1_700_000_500 + i64::from(byte),
            size: u64::from(byte) * 13 + 7,
            mode: 0o100_644,
            hash: dummy_id(byte),
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn round_trip_empty() {
        let t = tempdir::Dir::new("gyt-index-empty");
        let p = t.path().join("index");
        let idx = Index::new();
        idx.write(&p).unwrap();
        let back = Index::read(&p).unwrap();
        assert!(back.entries.is_empty());
    }

    #[test]
    fn round_trip_with_entries() {
        let t = tempdir::Dir::new("gyt-index-rt");
        let p = t.path().join("index");
        let mut idx = Index::new();
        idx.insert(entry("a.txt", 1));
        idx.insert(entry("dir/longer-name.rs", 2));
        idx.insert(entry("z/very/deeply/nested/file.bin", 3));
        idx.write(&p).unwrap();
        let back = Index::read(&p).unwrap();
        assert_eq!(back.entries.len(), 3);
        // After write, the file is sorted; read preserves on-disk order.
        let paths: Vec<String> = back
            .entries
            .iter()
            .map(|e| e.path.to_string_lossy().into_owned())
            .collect();
        let mut expected = paths.clone();
        expected.sort();
        assert_eq!(paths, expected);
        // Spot-check one round-tripped entry.
        let found = back.find(Path::new("dir/longer-name.rs")).unwrap();
        assert_eq!(found.size, 2 * 13 + 7);
        assert_eq!(found.mode, 0o100_644);
        assert_eq!(found.hash, dummy_id(2));
    }

    #[test]
    fn entries_sorted_on_write() {
        let t = tempdir::Dir::new("gyt-index-sorted");
        let p = t.path().join("index");
        let mut idx = Index::new();
        idx.insert(entry("zeta", 9));
        idx.insert(entry("alpha", 1));
        idx.insert(entry("middle/c", 3));
        idx.insert(entry("middle/b", 2));
        idx.write(&p).unwrap();
        let back = Index::read(&p).unwrap();
        let paths: Vec<String> = back
            .entries
            .iter()
            .map(|e| e.path.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            paths,
            vec![
                "alpha".to_string(),
                "middle/b".to_string(),
                "middle/c".to_string(),
                "zeta".to_string(),
            ]
        );
    }

    #[test]
    fn find_returns_correct_entry() {
        let mut idx = Index::new();
        idx.insert(entry("foo", 1));
        idx.insert(entry("bar/baz", 2));
        let e = idx.find(Path::new("bar/baz")).unwrap();
        assert_eq!(e.hash, dummy_id(2));
        assert!(idx.find(Path::new("nope")).is_none());
    }

    #[test]
    fn insert_replaces_same_path() {
        let mut idx = Index::new();
        idx.insert(entry("same", 1));
        idx.insert(entry("same", 2));
        assert_eq!(idx.entries.len(), 1);
        assert_eq!(idx.entries[0].hash, dummy_id(2));
    }

    #[test]
    fn remove_drops_entry() {
        let mut idx = Index::new();
        idx.insert(entry("a", 1));
        idx.insert(entry("b", 2));
        assert!(idx.remove(Path::new("a")));
        assert_eq!(idx.entries.len(), 1);
        assert!(!idx.remove(Path::new("a")));
    }

    #[test]
    fn read_missing_file_returns_empty() {
        let t = tempdir::Dir::new("gyt-index-missing");
        let p = t.path().join("does-not-exist");
        let idx = Index::read(&p).unwrap();
        assert!(idx.entries.is_empty());
    }

    #[test]
    fn rejects_bad_magic() {
        let t = tempdir::Dir::new("gyt-index-magic");
        let p = t.path().join("index");
        let mut buf = Vec::new();
        buf.extend_from_slice(b"XXXX");
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&p, &buf).unwrap();
        let err = Index::read(&p).unwrap_err();
        match err {
            GytError::Index(msg) => assert!(msg.contains("magic"), "got: {msg}"),
            other => panic!("expected Index error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_version() {
        let t = tempdir::Dir::new("gyt-index-version");
        let p = t.path().join("index");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&999u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        std::fs::write(&p, &buf).unwrap();
        let err = Index::read(&p).unwrap_err();
        match err {
            GytError::Index(msg) => assert!(msg.contains("version"), "got: {msg}"),
            other => panic!("expected Index error, got {other:?}"),
        }
    }

    // ── B3: reject unsafe paths in the index ─────────────────────
    //
    // Construct an on-disk index with one synthetic entry whose path
    // is dangerous, then assert `Index::read` returns Err. Doing the
    // construction by hand (rather than building an `Index` and
    // calling `.write()`) is intentional: `write` won't emit `..`
    // paths to begin with, so we can't round-trip them. The threat
    // model here is "attacker hand-edits `.gyt/index`".
    fn write_index_with_path(p: &Path, bad_path: &str) {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // one entry
        // Entry: 8+8+8+4+32 = 60 bytes of fixed header + path_len(2) + path.
        buf.extend_from_slice(&0i64.to_le_bytes()); // ctime
        buf.extend_from_slice(&0i64.to_le_bytes()); // mtime
        buf.extend_from_slice(&0u64.to_le_bytes()); // size
        buf.extend_from_slice(&0o100_644u32.to_le_bytes()); // mode
        buf.extend_from_slice(&[0u8; HASH_LEN]); // hash
        let pb = bad_path.as_bytes();
        buf.extend_from_slice(&u16::try_from(pb.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(pb);
        std::fs::write(p, &buf).unwrap();
    }

    fn assert_index_rejects_path(label: &str, bad_path: &str) {
        let t = tempdir::Dir::new(&format!("gyt-index-bad-{label}"));
        let p = t.path().join("index");
        write_index_with_path(&p, bad_path);
        let err = Index::read(&p).unwrap_err();
        let msg = match err {
            GytError::Index(m) => m,
            other => panic!("expected Index error for {label:?} path {bad_path:?}, got {other:?}"),
        };
        assert!(
            !msg.contains("trailing garbage"),
            "should have rejected at path validation, not later: {msg}"
        );
    }

    #[test]
    fn rejects_parent_traversal_path() {
        assert_index_rejects_path("dotdot", "../../etc/passwd");
    }

    #[test]
    fn rejects_absolute_path() {
        assert_index_rejects_path("absolute", "/etc/passwd");
    }

    #[test]
    fn rejects_dot_component_path() {
        assert_index_rejects_path("dot", "a/./b");
    }

    #[test]
    fn rejects_empty_component_path() {
        assert_index_rejects_path("empty-component", "a//b");
    }

    #[test]
    fn rejects_backslash_path() {
        assert_index_rejects_path("backslash", "a\\b");
    }

    #[test]
    fn rejects_nul_path() {
        assert_index_rejects_path("nul", "a\0b");
    }

    #[test]
    fn rejects_gyt_component_path() {
        // Either case must be rejected to defend case-insensitive
        // filesystems (APFS / NTFS / casefolded ext4) where `.GYT/`
        // would still shadow `.gyt/` metadata.
        assert_index_rejects_path("dotgyt-lower", ".gyt/config");
        assert_index_rejects_path("dotgyt-upper", ".GYT/config");
        assert_index_rejects_path("dotgyt-mixed", "a/.Gyt/x");
    }

    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new(prefix: &str) -> Self {
                let pid = std::process::id();
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.subsec_nanos());
                let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
