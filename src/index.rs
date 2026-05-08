// GYTI v1 binary index.
// magic "GYTI" (4 bytes) + version u32 LE + entry_count u32 LE + entries.
// Each entry:
//   ctime_secs i64 LE, mtime_secs i64 LE, size u64 LE, mode u32 LE,
//   hash [u8;32], path_len u16 LE, path bytes (utf-8, forward-slash separated).

use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::{ObjectId, HASH_LEN};
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

    fn parse(data: &[u8]) -> Result<Self> {
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
    use super::*;
    use crate::hash::{ObjectId, HASH_LEN};

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

    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new(prefix: &str) -> Self {
                let pid = std::process::id();
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0);
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
