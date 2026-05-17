// Pack files for batching loose objects into a single on-disk blob.
//
// File layout under `<gyt>/objects/pack/`:
//   pack-<hex>.pack    Object stream + integrity trailer
//   pack-<hex>.idx     Sorted (hash → offset) lookup table
//
// The `<hex>` is the BLAKE3 of the .pack content (post-trailer hash
// excluded) so packs are content-addressed and idempotent.
//
// Pack file (.pack):
//   "GYTP"    (4B magic)
//   1         (u8 version)
//   0         (u8 flags - reserved for future delta-support bit)
//   00 00     (2B reserved)
//   N         (u32 LE entry count)
//   entry × N
//   pack_hash (32B BLAKE3 over everything above)
//
// Entry:
//   kind      (u8: 1=Blob 2=Commit 3=Tree 4=Tag)
//   hash      (32B BLAKE3 of the *raw* `<kind> <size>\0<payload>` bytes)
//   body_len  (u32 LE)
//   body      (body_len B - the same on-disk-encoded bytes a loose file
//              would contain, i.e. `compress::encode(raw)`)
//
// Index file (.idx):
//   "GYPI"    (4B magic - distinct from the GYTI workdir index)
//   1         (u8 version)
//   0         (u8 flags)
//   00 00     (2B reserved)
//   N         (u32 LE entry count)
//   (hash 32B, offset_in_pack u64 LE) × N   — sorted by hash ascending
//   pack_hash (32B BLAKE3 — same value as the .pack trailer, cross-ref)
//
// Lookup: binary-search the .idx for the hash. If present, seek into
// the .pack at the offset, parse the entry, decompress its body, and
// verify the resulting raw hash matches the request.

use crate::compress;
use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::{self, ObjectId};
use crate::object::{Object, ObjectKind, store};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const PACK_MAGIC: &[u8; 4] = b"GYTP";
const IDX_MAGIC: &[u8; 4] = b"GYPI";
const PACK_VERSION: u8 = 1;
const IDX_HEADER_LEN: usize = 4 + 1 + 1 + 2 + 4;
const IDX_ENTRY_LEN: usize = 32 + 8;
const HASH_LEN: usize = 32;
const TRAILER_LEN: usize = 32;

/// One entry to be written into a pack.
pub struct PackEntry {
    pub id: ObjectId,
    pub kind: ObjectKind,
    /// `compress::encode(build_raw(kind, payload))` — i.e. the same
    /// bytes that would live in a loose object file.
    pub on_disk: Vec<u8>,
}

/// Write `entries` to a new content-addressed pack at
/// `<gyt>/objects/pack/`. Returns the pack's on-disk hash (used for the
/// filename suffix). The .idx file is written alongside.
///
/// Existing duplicate entries (same id) are de-duplicated by keeping
/// only the first occurrence. Empty input is rejected — there is no
/// reason to create a zero-entry pack and it would confuse readers
/// that don't bother to mmap the file at all.
pub fn write_pack(gyt_dir: &Path, mut entries: Vec<PackEntry>) -> Result<ObjectId> {
    entries.sort_by_key(|e| e.id);
    entries.dedup_by_key(|e| e.id);
    if entries.is_empty() {
        return Err(GytError::Object("pack: refuse to write empty pack".into()));
    }
    let pack_dir = gyt_dir.join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir)
        .map_err(|e| GytError::Io(std::io::Error::other(format!("pack: mkdir: {e}"))))?;

    // Build the pack body and record per-entry offsets as we go.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(PACK_MAGIC);
    body.push(PACK_VERSION);
    body.push(0);
    body.extend_from_slice(&[0, 0]);
    let n: u32 = u32::try_from(entries.len())
        .map_err(|_| GytError::Object("pack: too many entries (>u32)".into()))?;
    body.extend_from_slice(&n.to_le_bytes());

    let mut offsets: Vec<(ObjectId, u64)> = Vec::with_capacity(entries.len());
    for e in &entries {
        let offset = u64::try_from(body.len())
            .map_err(|_| GytError::Object("pack: offset overflow".into()))?;
        offsets.push((e.id, offset));
        body.push(encode_kind(e.kind));
        body.extend_from_slice(e.id.as_bytes());
        let body_len: u32 = u32::try_from(e.on_disk.len())
            .map_err(|_| GytError::Object("pack: entry body too large (>4 GiB)".into()))?;
        body.extend_from_slice(&body_len.to_le_bytes());
        body.extend_from_slice(&e.on_disk);
    }
    let trailer = hash::hash_bytes(&body);
    body.extend_from_slice(trailer.as_bytes());

    // Build the matching index.
    let mut idx_buf: Vec<u8> =
        Vec::with_capacity(IDX_HEADER_LEN + offsets.len() * IDX_ENTRY_LEN + TRAILER_LEN);
    idx_buf.extend_from_slice(IDX_MAGIC);
    idx_buf.push(PACK_VERSION);
    idx_buf.push(0);
    idx_buf.extend_from_slice(&[0, 0]);
    idx_buf.extend_from_slice(&n.to_le_bytes());
    // entries already sorted by id from the sort above.
    for (id, off) in &offsets {
        idx_buf.extend_from_slice(id.as_bytes());
        idx_buf.extend_from_slice(&off.to_le_bytes());
    }
    idx_buf.extend_from_slice(trailer.as_bytes());

    let stem = format!("pack-{}", trailer.to_hex());
    let pack_path = pack_dir.join(format!("{stem}.pack"));
    let idx_path = pack_dir.join(format!("{stem}.idx"));
    fs_util::atomic_write(&pack_path, &body)?;
    fs_util::atomic_write(&idx_path, &idx_buf)?;
    Ok(trailer)
}

/// Look for `id` in any pack under `<gyt>/objects/pack/`. Returns the
/// fully-resolved `Object` (decompressed + hash-verified) if found.
pub fn read_from_packs(gyt_dir: &Path, id: &ObjectId) -> Result<Option<Object>> {
    let pack_dir = gyt_dir.join("objects").join("pack");
    let Ok(entries) = std::fs::read_dir(&pack_dir) else {
        return Ok(None);
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !stem.starts_with("pack-") || path.extension().and_then(|e| e.to_str()) != Some("idx") {
            continue;
        }
        if let Some(offset) = lookup_in_idx(&path, id)? {
            let pack_path = path.with_extension("pack");
            return Ok(Some(read_entry_at(&pack_path, offset, id)?));
        }
    }
    Ok(None)
}

/// Cheap existence check across all packs. Avoids decompression — just
/// confirms the hash is present in some .idx.
pub fn id_in_packs(gyt_dir: &Path, id: &ObjectId) -> bool {
    let pack_dir = gyt_dir.join("objects").join("pack");
    let Ok(entries) = std::fs::read_dir(&pack_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("idx") {
            continue;
        }
        if matches!(lookup_in_idx(&path, id), Ok(Some(_))) {
            return true;
        }
    }
    false
}

/// Process-wide cache of parsed .idx files. The key is the idx's
/// canonical path; the value is the file bytes plus the mtime we
/// observed when we cached them. A stale entry (mtime moved forward)
/// is dropped on the next access.
///
/// Why cache at all: with N packs per repo and frequent reads, the
/// pre-cache `lookup_in_idx` re-read every .idx from disk on every
/// `store::read` call. For a clone walking 100k objects across 250
/// packs that's 250 × 100k = 25M file opens. The cache turns the
/// hot read path into one mmap-equivalent per pack per process.
///
/// Packs are immutable — once written, neither the .pack nor the
/// .idx changes. The mtime check is only a defense against operator
/// surprise (e.g. someone restoring a backup file on top of a live
/// pack). Hit rate is effectively 100%.
struct IdxCacheEntry {
    bytes: Vec<u8>,
    mtime: SystemTime,
}

static IDX_CACHE: OnceLock<Mutex<HashMap<PathBuf, IdxCacheEntry>>> = OnceLock::new();

fn idx_cache() -> &'static Mutex<HashMap<PathBuf, IdxCacheEntry>> {
    IDX_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get the idx file bytes, hitting the cache when possible. The
/// returned Vec is cloned out of the cache so callers don't hold the
/// Mutex while binary-searching.
fn idx_bytes(idx_path: &Path) -> Result<Vec<u8>> {
    let canon = idx_path.canonicalize().unwrap_or_else(|_| idx_path.to_path_buf());
    // Probe mtime first so a stale entry can be dropped before we
    // copy bytes out.
    let mtime = std::fs::metadata(idx_path)
        .and_then(|m| m.modified())
        .unwrap_or(UNIX_EPOCH);
    {
        let g = idx_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = g.get(&canon)
            && entry.mtime == mtime
        {
            return Ok(entry.bytes.clone());
        }
    }
    let bytes = fs_util::read_all(idx_path)?;
    insert_into_idx_cache(canon, bytes.clone(), mtime);
    Ok(bytes)
}

/// L13: cap the idx cache so it doesn't grow without bound across
/// repos. Deleted-pack entries that nobody re-accesses linger forever
/// otherwise. Drop one arbitrary entry to make room when at capacity.
const MAX_IDX_CACHE_ENTRIES: usize = 4096;

fn insert_into_idx_cache(canon: PathBuf, bytes: Vec<u8>, mtime: std::time::SystemTime) {
    let mut g = idx_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if g.len() >= MAX_IDX_CACHE_ENTRIES
        && !g.contains_key(&canon)
        && let Some(victim) = g.keys().next().cloned()
    {
        g.remove(&victim);
    }
    g.insert(canon, IdxCacheEntry { bytes, mtime });
}

/// Binary-search `idx_path` for `id`, returning its offset in the
/// matching .pack file if present.
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    reason = "every bytes[..4]/[4]/[8..12]/[off..off+HASH_LEN]/[off+HASH_LEN..off+IDX_ENTRY_LEN] is gated by the `bytes.len() != expected` precondition checks above; try_into expects on 4-/8-byte slices cannot fail because the slice length matches the target array length exactly"
)]
fn lookup_in_idx(idx_path: &Path, id: &ObjectId) -> Result<Option<u64>> {
    let bytes = idx_bytes(idx_path)?;
    if bytes.len() < IDX_HEADER_LEN + TRAILER_LEN {
        return Err(GytError::Object(format!(
            "pack idx {}: too short",
            idx_path.display()
        )));
    }
    if &bytes[..4] != IDX_MAGIC {
        return Err(GytError::Object(format!(
            "pack idx {}: bad magic",
            idx_path.display()
        )));
    }
    if bytes[4] != PACK_VERSION {
        return Err(GytError::Object(format!(
            "pack idx {}: unsupported version {}",
            idx_path.display(),
            bytes[4]
        )));
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")) as usize;
    // Use checked arithmetic so a malicious `count` on a 32-bit host
    // cannot wrap `expected` to a small value that happens to equal
    // `bytes.len()`, letting the binary search below run with a huge
    // upper bound and panic on slice indexing. On 64-bit this can't
    // overflow today (u32::MAX * 40 fits in usize), but the check is
    // free and removes the implicit target-width assumption.
    let expected = count
        .checked_mul(IDX_ENTRY_LEN)
        .and_then(|n| n.checked_add(IDX_HEADER_LEN + TRAILER_LEN))
        .ok_or_else(|| {
            GytError::Object(format!(
                "pack idx {}: entry count {count} overflows expected size",
                idx_path.display()
            ))
        })?;
    if bytes.len() != expected {
        return Err(GytError::Object(format!(
            "pack idx {}: length mismatch (have {}, want {expected})",
            idx_path.display(),
            bytes.len()
        )));
    }

    let entries_start = IDX_HEADER_LEN;
    let target = id.as_bytes();
    // Manual binary search over fixed-stride entries.
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = usize::midpoint(lo, hi);
        let off = entries_start + mid * IDX_ENTRY_LEN;
        let hash_slice = &bytes[off..off + HASH_LEN];
        match hash_slice.cmp(target) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                let off_bytes: [u8; 8] = bytes[off + HASH_LEN..off + IDX_ENTRY_LEN]
                    .try_into()
                    .expect("8 bytes");
                return Ok(Some(u64::from_le_bytes(off_bytes)));
            }
        }
    }
    Ok(None)
}

#[expect(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "the expect on try_into to [u8; 4] cannot fail because the slice is exactly 4 bytes by const-size construction of `header` ([u8; 1 + HASH_LEN + 4])"
)]
fn read_entry_at(pack_path: &Path, offset: u64, expected_id: &ObjectId) -> Result<Object> {
    let mut f = File::open(pack_path)
        .map_err(|e| GytError::Io(std::io::Error::other(format!("pack open: {e}"))))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| GytError::Io(std::io::Error::other(format!("pack seek: {e}"))))?;
    let mut header = [0u8; 1 + HASH_LEN + 4];
    f.read_exact(&mut header)
        .map_err(|e| GytError::Io(std::io::Error::other(format!("pack header read: {e}"))))?;
    let kind = decode_kind(header[0])?;
    let mut stored_id = [0u8; HASH_LEN];
    stored_id.copy_from_slice(&header[1..=HASH_LEN]);
    if stored_id != *expected_id.as_bytes() {
        return Err(GytError::Object(format!(
            "pack {}: entry hash mismatch at offset {offset}",
            pack_path.display()
        )));
    }
    let body_len = u32::from_le_bytes(
        header[1 + HASH_LEN..1 + HASH_LEN + 4]
            .try_into()
            .expect("4 bytes"),
    ) as usize;
    // Hard-cap body length so a corrupt pack can't OOM us.
    if body_len > 1 << 30 {
        return Err(GytError::Object(format!(
            "pack {}: entry body too large ({body_len} bytes)",
            pack_path.display()
        )));
    }
    let mut body = vec![0u8; body_len];
    f.read_exact(&mut body)
        .map_err(|e| GytError::Io(std::io::Error::other(format!("pack body read: {e}"))))?;

    let raw = compress::decode(&body)?;
    let observed = hash::hash_bytes(&raw);
    if observed != *expected_id {
        return Err(GytError::Object(format!(
            "pack {}: decompressed hash mismatch (got {observed})",
            pack_path.display()
        )));
    }
    let (decoded_kind, payload) = store::parse_raw(&raw)?;
    if decoded_kind != kind {
        return Err(GytError::Object(format!(
            "pack {}: kind byte ({}) disagrees with payload header ({})",
            pack_path.display(),
            kind.as_str(),
            decoded_kind.as_str()
        )));
    }
    Ok(Object {
        id: *expected_id,
        kind,
        payload,
    })
}

const fn encode_kind(k: ObjectKind) -> u8 {
    match k {
        ObjectKind::Blob => 1,
        ObjectKind::Commit => 2,
        ObjectKind::Tree => 3,
        ObjectKind::Tag => 4,
    }
}

const fn decode_kind_inner(b: u8) -> Option<ObjectKind> {
    match b {
        1 => Some(ObjectKind::Blob),
        2 => Some(ObjectKind::Commit),
        3 => Some(ObjectKind::Tree),
        4 => Some(ObjectKind::Tag),
        _ => None,
    }
}

fn decode_kind(b: u8) -> Result<ObjectKind> {
    decode_kind_inner(b)
        .ok_or_else(|| GytError::Object(format!("pack: unknown entry kind byte {b}")))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::object::ObjectKind;

    fn tmp() -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = std::env::temp_dir().join(format!("gyt-pack-test-{pid}-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn mk_entry(kind: ObjectKind, payload: &[u8]) -> PackEntry {
        let raw = store::build_raw(kind, payload);
        let id = hash::hash_bytes(&raw);
        let on_disk = compress::encode(&raw);
        PackEntry {
            id,
            kind,
            on_disk,
        }
    }

    #[test]
    fn pack_round_trip_one_object() {
        let dir = tmp();
        let e = mk_entry(ObjectKind::Blob, b"hello pack");
        let id = e.id;
        write_pack(&dir, vec![e]).unwrap();
        let obj = read_from_packs(&dir, &id).unwrap().expect("found");
        assert_eq!(obj.kind, ObjectKind::Blob);
        assert_eq!(obj.payload, b"hello pack");
        assert!(id_in_packs(&dir, &id));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pack_handles_many_objects_with_dedup() {
        let dir = tmp();
        let mut entries = Vec::new();
        let mut ids = Vec::new();
        for i in 0..100u32 {
            let e = mk_entry(ObjectKind::Blob, format!("payload-{i}").as_bytes());
            ids.push(e.id);
            entries.push(e);
        }
        // Add a duplicate of #0 — write_pack should dedup it.
        let dup = mk_entry(ObjectKind::Blob, b"payload-0");
        entries.push(dup);
        write_pack(&dir, entries).unwrap();
        for id in &ids {
            assert!(id_in_packs(&dir, id));
            let obj = read_from_packs(&dir, id).unwrap().expect("found");
            assert_eq!(obj.kind, ObjectKind::Blob);
        }
        // A made-up id is not in the pack.
        let absent = hash::hash_bytes(b"nope");
        assert!(!id_in_packs(&dir, &absent));
        assert!(read_from_packs(&dir, &absent).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_pack_is_rejected() {
        let dir = tmp();
        let err = write_pack(&dir, vec![]).unwrap_err();
        assert!(matches!(err, GytError::Object(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
