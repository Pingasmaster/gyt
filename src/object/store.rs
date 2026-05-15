use crate::compress;
use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::{self, ObjectId};
use crate::object::{Object, ObjectKind};
use std::path::{Path, PathBuf};

// Loose-object on-disk format.
// Pre-hash bytes (and BLAKE3 input):  "<kind> <size>\0<payload>"
// On-disk bytes: compress::encode(pre_hash_bytes), which may magic-wrap with xz.

pub fn build_raw(kind: ObjectKind, payload: &[u8]) -> Vec<u8> {
    let header = format!("{} {}\0", kind.as_str(), payload.len());
    let mut buf = Vec::with_capacity(header.len() + payload.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[expect(
    clippy::indexing_slicing,
    reason = "raw[..nul] / raw[nul+1..] is gated by nul being a valid index from raw.iter().position(...) — so nul is in 0..raw.len() and nul+1 ≤ raw.len() (a valid empty-slice index)"
)]
pub fn parse_raw(raw: &[u8]) -> Result<(ObjectKind, Vec<u8>)> {
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| GytError::Object("missing NUL after object header".into()))?;
    let header = std::str::from_utf8(&raw[..nul])
        .map_err(|_| GytError::Object("non-utf8 object header".into()))?;
    let (kind_s, size_s) = header
        .split_once(' ')
        .ok_or_else(|| GytError::Object(format!("malformed header: {header:?}")))?;
    let kind = ObjectKind::parse(kind_s)?;
    let size: usize = size_s
        .parse()
        .map_err(|_| GytError::Object(format!("non-numeric size in header: {size_s:?}")))?;
    let payload = &raw[nul + 1..];
    if payload.len() != size {
        return Err(GytError::Object(format!(
            "header says size {size} but payload is {}",
            payload.len()
        )));
    }
    Ok((kind, payload.to_vec()))
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
pub fn path_for(repo: &Path, id: &ObjectId) -> PathBuf {
    let hex = id.to_hex();
    repo.join("objects").join(&hex[..2]).join(&hex[2..])
}

pub fn write_bytes(repo: &Path, kind: ObjectKind, payload: &[u8]) -> Result<ObjectId> {
    let raw = build_raw(kind, payload);
    let id = hash::hash_bytes(&raw);
    let path = path_for(repo, &id);
    if path.exists() {
        return Ok(id);
    }
    let stored = compress::encode(&raw);
    fs_util::atomic_write(&path, &stored)?;
    Ok(id)
}
pub fn write(repo: &Path, obj: &Object) -> Result<ObjectId> {
    let id = write_bytes(repo, obj.kind, &obj.payload)?;
    debug_assert_eq!(id, obj.id);
    Ok(id)
}

pub fn read(repo: &Path, id: &ObjectId) -> Result<Object> {
    let path = path_for(repo, id);
    if path.exists() {
        let stored = fs_util::read_all(&path)?;
        let raw = compress::decode(&stored)?;
        let observed = hash::hash_bytes(&raw);
        if observed != *id {
            return Err(GytError::Object(format!(
                "object {id} content hash mismatch (got {observed})"
            )));
        }
        let (kind, payload) = parse_raw(&raw)?;
        return Ok(Object {
            id: *id,
            kind,
            payload,
        });
    }
    if let Some(obj) = crate::object::pack::read_from_packs(repo, id)? {
        return Ok(obj);
    }
    Err(GytError::NotFound(format!("object {id}")))
}

pub fn exists(repo: &Path, id: &ObjectId) -> bool {
    path_for(repo, id).exists() || crate::object::pack::id_in_packs(repo, id)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use std::fs;

    fn tmp_repo() -> tempdir::Dir {
        tempdir::Dir::new("gyt-store-test")
    }

    #[test]
    fn round_trip_blob() {
        let t = tmp_repo();
        let dir = t.path().join(".gyt");
        fs::create_dir_all(dir.join("objects")).unwrap();
        let payload = b"hello blob".to_vec();
        let id = write_bytes(&dir, ObjectKind::Blob, &payload).unwrap();
        let obj = read(&dir, &id).unwrap();
        assert_eq!(obj.kind, ObjectKind::Blob);
        assert_eq!(obj.payload, payload);
        assert_eq!(obj.id, id);
    }

    #[test]
    fn dedup_via_hash() {
        let t = tmp_repo();
        let dir = t.path().join(".gyt");
        fs::create_dir_all(dir.join("objects")).unwrap();
        let id1 = write_bytes(&dir, ObjectKind::Blob, b"same").unwrap();
        let id2 = write_bytes(&dir, ObjectKind::Blob, b"same").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn xz_round_trip_with_magic_prefix() {
        let t = tmp_repo();
        let dir = t.path().join(".gyt");
        fs::create_dir_all(dir.join("objects")).unwrap();
        // Use a payload that is clearly compressible.
        let payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".repeat(200);
        let id = write_bytes(&dir, ObjectKind::Blob, &payload).unwrap();
        let on_disk = fs::read(path_for(&dir, &id)).unwrap();
        assert_eq!(
            &on_disk[..4],
            &crate::compress::MAGIC,
            "xz file is magic-wrapped"
        );
        let obj = read(&dir, &id).unwrap();
        assert_eq!(obj.payload, payload);
    }

    #[test]
    fn corrupt_object_detected() {
        let t = tmp_repo();
        let dir = t.path().join(".gyt");
        fs::create_dir_all(dir.join("objects")).unwrap();
        let id = write_bytes(&dir, ObjectKind::Blob, b"good content").unwrap();
        let p = path_for(&dir, &id);
        let mut bytes = fs::read(&p).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&p, &bytes).unwrap();
        let res = read(&dir, &id);
        assert!(res.is_err(), "expected hash mismatch error");
    }
}

#[cfg(test)]
mod tempdir {
    #![expect(
        clippy::unwrap_used,
        reason = "test scaffolding: tmp_dir creation failure in a test means the test cannot run, which is a fatal-loud signal"
    )]
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
