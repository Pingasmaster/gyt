// gyt-protocol v1 codec. Phase 6a.
//
// Pure encoders/decoders, no I/O. Wire formats:
//
// /info/refs body  : zero or more lines "<hex>\t<refname>\n"
// wants list       : zero or more lines "<hex>\n"
// pack             : zero or more records "<u32 LE length><bytes...>",
//                    where <bytes> is exactly the on-disk loose-object form
//                    (compressed or raw — opaque to the codec)
// ref-update batch : zero or more lines "<old-hex>\t<new-hex>\t<refname>\n"
//                    where <old-hex> is 64 zeros to mean "no old (create)"

use crate::errors::{GytError, Result};
use crate::hash::{HEX_LEN, ObjectId};

/// One ref entry from `/info/refs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefEntry {
    pub name: String,
    pub id: ObjectId,
}

/// One pack entry: an object id and the raw on-disk bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackEntry {
    pub id: ObjectId,
    pub bytes: Vec<u8>,
}

/// One ref-update line. `old = None` means "create" (no prior value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: Option<ObjectId>,
    pub new: ObjectId,
    pub name: String,
}

const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------- /info/refs ----------

pub fn encode_info_refs(refs: &[RefEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(refs.len() * (HEX_LEN + 32));
    for r in refs {
        out.extend_from_slice(r.id.to_hex().as_bytes());
        out.push(b'\t');
        out.extend_from_slice(r.name.as_bytes());
        out.push(b'\n');
    }
    out
}

/// M21: caps to prevent a malicious server from blowing up client
/// memory / filesystem with millions of refs.
pub const MAX_INFO_REFS_ENTRIES: usize = 1_000_000;
pub const MAX_INFO_REF_NAME_LEN: usize = 1024;

pub fn parse_info_refs(body: &[u8]) -> Result<Vec<RefEntry>> {
    let s = std::str::from_utf8(body)
        .map_err(|_| GytError::Parse("info/refs: not valid utf-8".into()))?;
    let mut out = Vec::new();
    for (i, line) in s.split_inclusive('\n').enumerate() {
        if out.len() >= MAX_INFO_REFS_ENTRIES {
            return Err(GytError::Parse(format!(
                "info/refs: entry count exceeds {MAX_INFO_REFS_ENTRIES}"
            )));
        }
        let line = line.strip_suffix('\n').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let (hex, name) = line
            .split_once('\t')
            .ok_or_else(|| GytError::Parse(format!("info/refs line {i}: missing tab separator")))?;
        if name.is_empty() {
            return Err(GytError::Parse(format!(
                "info/refs line {i}: empty refname"
            )));
        }
        if name.len() > MAX_INFO_REF_NAME_LEN {
            return Err(GytError::Parse(format!(
                "info/refs line {i}: refname length {} exceeds {MAX_INFO_REF_NAME_LEN}",
                name.len()
            )));
        }
        let id = ObjectId::from_hex(hex)?;
        out.push(RefEntry {
            name: name.to_string(),
            id,
        });
    }
    Ok(out)
}

// ---------- wants ----------

pub fn encode_wants(ids: &[ObjectId]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ids.len() * (HEX_LEN + 1));
    for id in ids {
        out.extend_from_slice(id.to_hex().as_bytes());
        out.push(b'\n');
    }
    out
}

pub fn parse_wants(body: &[u8]) -> Result<Vec<ObjectId>> {
    let s =
        std::str::from_utf8(body).map_err(|_| GytError::Parse("wants: not valid utf-8".into()))?;
    let mut out = Vec::new();
    for (i, line) in s.split_inclusive('\n').enumerate() {
        let line = line.strip_suffix('\n').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.len() != HEX_LEN {
            return Err(GytError::Parse(format!(
                "wants line {i}: expected {HEX_LEN}-char hex, got {}",
                line.len()
            )));
        }
        out.push(ObjectId::from_hex(line)?);
    }
    Ok(out)
}

// ---------- pack ----------
#[expect(
    clippy::expect_used,
    reason = "the invariant guarded by this expect cannot fail (verified at the call site)"
)]
pub fn encode_pack(entries: &[PackEntry]) -> Vec<u8> {
    let mut total = 0usize;
    for e in entries {
        total += 4 + e.bytes.len();
    }
    let mut out = Vec::with_capacity(total);
    for e in entries {
        let len: u32 = u32::try_from(e.bytes.len())
            .expect("pack entry exceeds 4 GiB; codec does not support that");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&e.bytes);
    }
    out
}

/// Maximum number of PackEntry records `parse_pack` is willing to
/// produce. Each entry costs ~56 bytes resident even before its
/// `bytes` is allocated, so a 1 GiB decompressed body filled with
/// zero-length entries would otherwise spawn ~268 M records and
/// allocate ~15 GiB of RAM. 1M is far above any legitimate push
/// (an entire mid-sized monorepo cold-clones with <1M objects).
pub const MAX_PACK_ENTRIES: usize = 1_000_000;

#[expect(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "body[pos..pos+4] / body[pos..pos+len] slices are gated by explicit `body.len() - pos < 4 / < len` early returns; try_into onto [u8;4] from a verified 4-byte slice cannot fail"
)]
pub fn parse_pack(body: &[u8]) -> Result<Vec<PackEntry>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < 4 {
            return Err(GytError::Parse(format!(
                "pack: truncated length prefix at offset {pos}"
            )));
        }
        let len_bytes: [u8; 4] = body[pos..pos + 4].try_into().expect("checked above");
        let len = u32::from_le_bytes(len_bytes) as usize;
        pos += 4;
        // F-D3-01: reject zero-length entries. A malicious packfile
        // whose decompressed body is 1 GiB of all-zero u32 length
        // prefixes would otherwise produce ~268 M PackEntry records
        // with empty `bytes` vecs — ~15 GiB resident before the
        // caller even started processing. A legitimate gyt object
        // always has at least a "<kind> <size>\0" header so a 0-byte
        // entry is provably bogus.
        if len == 0 {
            return Err(GytError::Parse(format!(
                "pack: zero-length entry at offset {}",
                pos - 4
            )));
        }
        if body.len() - pos < len {
            return Err(GytError::Parse(format!(
                "pack: declared length {len} exceeds remaining {}",
                body.len() - pos
            )));
        }
        let bytes = body[pos..pos + len].to_vec();
        pos += len;
        // F-D3-01: cap entry count.
        if out.len() >= MAX_PACK_ENTRIES {
            return Err(GytError::Parse(format!(
                "pack: entry count exceeds MAX_PACK_ENTRIES={MAX_PACK_ENTRIES}"
            )));
        }
        // The codec doesn't decompress or verify — those are the caller's job.
        // We can however hash the *raw on-disk* bytes to fill in `id`. But the
        // protocol carries the id implicitly — it's the hash of the *decoded*
        // raw object, not of the on-disk wrapping. So callers must compute the
        // id themselves (decode -> hash) before storing. Until then, leave id
        // as a zero placeholder — readers must overwrite it.
        out.push(PackEntry {
            id: ObjectId([0u8; 32]),
            bytes,
        });
    }
    Ok(out)
}

// ---------- ref updates ----------

pub fn encode_ref_updates(updates: &[RefUpdate]) -> Vec<u8> {
    let mut out = Vec::with_capacity(updates.len() * (HEX_LEN * 2 + 32));
    for u in updates {
        match u.old {
            Some(id) => out.extend_from_slice(id.to_hex().as_bytes()),
            None => out.extend_from_slice(ZERO_HEX.as_bytes()),
        }
        out.push(b'\t');
        out.extend_from_slice(u.new.to_hex().as_bytes());
        out.push(b'\t');
        out.extend_from_slice(u.name.as_bytes());
        out.push(b'\n');
    }
    out
}

pub fn parse_ref_updates(body: &[u8]) -> Result<Vec<RefUpdate>> {
    let s = std::str::from_utf8(body)
        .map_err(|_| GytError::Parse("ref-updates: not valid utf-8".into()))?;
    let mut out = Vec::new();
    for (i, line) in s.split_inclusive('\n').enumerate() {
        let line = line.strip_suffix('\n').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, '\t');
        let old_hex = parts
            .next()
            .ok_or_else(|| GytError::Parse(format!("ref-updates line {i}: missing old hex")))?;
        let new_hex = parts
            .next()
            .ok_or_else(|| GytError::Parse(format!("ref-updates line {i}: missing new hex")))?;
        let name = parts
            .next()
            .ok_or_else(|| GytError::Parse(format!("ref-updates line {i}: missing refname")))?;
        if name.is_empty() {
            return Err(GytError::Parse(format!(
                "ref-updates line {i}: empty refname"
            )));
        }
        let old = if old_hex == ZERO_HEX {
            None
        } else {
            Some(ObjectId::from_hex(old_hex)?)
        };
        let new = ObjectId::from_hex(new_hex)?;
        out.push(RefUpdate {
            old,
            new,
            name: name.to_string(),
        });
    }
    Ok(out)
}

// ---------- packfile ----------
//
// Packfile format:
//   byte 0: version flag (0x01 = uncompressed, 0x02 = xz-compressed)
//   bytes 1..: body
//
// The body is the same format as encode_pack/parse_pack when uncompressed,
// or xz-compressed when version 0x02.

const PACKFILE_VERSION_RAW: u8 = 0x01;
const PACKFILE_VERSION_XZ: u8 = 0x02;
#[expect(
    clippy::expect_used,
    reason = "the invariant guarded by this expect cannot fail (verified at the call site)"
)]
pub fn encode_packfile(entries: &[PackEntry]) -> Vec<u8> {
    let inner = encode_pack(entries);
    let compressed = crate::compress::xz_encode_raw(&inner).expect("xz compression should not fail");
    let mut out = Vec::with_capacity(1 + compressed.len());
    out.push(PACKFILE_VERSION_XZ);
    out.extend_from_slice(&compressed);
    out
}

#[expect(
    clippy::indexing_slicing,
    reason = "body[0] / body[1..] is gated by the `body.is_empty()` early return"
)]
pub fn parse_packfile(body: &[u8]) -> Result<Vec<PackEntry>> {
    if body.is_empty() {
        return Err(GytError::Parse("packfile: empty body".into()));
    }
    match body[0] {
        PACKFILE_VERSION_RAW => parse_pack(&body[1..]),
        PACKFILE_VERSION_XZ => {
            let decompressed = crate::compress::xz_decode_raw(&body[1..])
                .map_err(|e| GytError::Parse(format!("packfile: xz decompress: {e}")))?;
            parse_pack(&decompressed)
        }
        v => Err(GytError::Parse(format!(
            "packfile: unknown version byte {v:#04x}"
        ))),
    }
}

/// Like `parse_packfile`, but increments a caller-supplied counter
/// with the number of bytes decompressed by the outer XZ stream (and
/// the raw size of v1 bodies). Used by `wire_objects_have` for the
/// optional heavy-decompression operator log — the counter is
/// observational only, never used to reject legitimate large pushes.
#[expect(
    clippy::indexing_slicing,
    reason = "body[0] and body[1..] are gated by the `body.is_empty()` early-return immediately above"
)]
pub fn parse_packfile_accumulating(
    body: &[u8],
    accumulator: &std::sync::atomic::AtomicU64,
) -> Result<Vec<PackEntry>> {
    if body.is_empty() {
        return Err(GytError::Parse("packfile: empty body".into()));
    }
    match body[0] {
        PACKFILE_VERSION_RAW => {
            accumulator.fetch_add(
                body.len() as u64 - 1,
                std::sync::atomic::Ordering::AcqRel,
            );
            parse_pack(&body[1..])
        }
        PACKFILE_VERSION_XZ => {
            let stored: Vec<u8> = {
                let mut v = Vec::with_capacity(5 + body.len() - 1);
                v.extend_from_slice(&crate::compress::MAGIC);
                v.push(crate::compress::FLAG_XZ);
                v.extend_from_slice(&body[1..]);
                v
            };
            let decompressed = crate::compress::decode_accumulating(&stored, accumulator)
                .map_err(|e| GytError::Parse(format!("packfile: xz decompress: {e}")))?;
            parse_pack(&decompressed)
        }
        v => Err(GytError::Parse(format!(
            "packfile: unknown version byte {v:#04x}"
        ))),
    }
}

// Re-export so other modules can build pack entries with a placeholder id.
pub const fn pack_entry_from_bytes(bytes: Vec<u8>) -> PackEntry {
    PackEntry {
        id: ObjectId([0u8; 32]),
        bytes,
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::hash::hash_bytes;

    fn id(s: &[u8]) -> ObjectId {
        hash_bytes(s)
    }

    #[test]
    fn round_trip_info_refs() {
        let refs = vec![
            RefEntry {
                name: "refs/heads/main".into(),
                id: id(b"a"),
            },
            RefEntry {
                name: "refs/tags/v1".into(),
                id: id(b"b"),
            },
        ];
        let bytes = encode_info_refs(&refs);
        let parsed = parse_info_refs(&bytes).unwrap();
        assert_eq!(parsed, refs);
    }

    #[test]
    fn parse_info_refs_empty() {
        assert!(parse_info_refs(b"").unwrap().is_empty());
    }

    #[test]
    fn round_trip_wants() {
        let ids = vec![id(b"x"), id(b"y"), id(b"z")];
        let bytes = encode_wants(&ids);
        let parsed = parse_wants(&bytes).unwrap();
        assert_eq!(parsed, ids);
    }

    #[test]
    fn round_trip_pack() {
        // F-D3-01 now rejects zero-length entries (every legitimate
        // gyt object has at least a `<kind> <size>\0` header). The
        // round-trip test was updated to use only non-empty entries.
        let entries = vec![
            PackEntry {
                id: ObjectId([0u8; 32]),
                bytes: b"x".to_vec(),
            },
            PackEntry {
                id: ObjectId([0u8; 32]),
                bytes: b"hello".to_vec(),
            },
            PackEntry {
                id: ObjectId([0u8; 32]),
                bytes: vec![0xab; 100_000],
            },
        ];
        let bytes = encode_pack(&entries);
        let parsed = parse_pack(&bytes).unwrap();
        assert_eq!(parsed.len(), entries.len());
        for (a, b) in parsed.iter().zip(entries.iter()) {
            assert_eq!(a.bytes, b.bytes);
        }
    }

    #[test]
    fn parse_pack_rejects_zero_length_entry() {
        // F-D3-01: a u32(0) prefix on its own would otherwise let an
        // attacker spawn ~268 M empty PackEntry records from 1 GiB of
        // decompressed zeros.
        let bytes = 0u32.to_le_bytes().to_vec();
        assert!(parse_pack(&bytes).is_err());
    }

    #[test]
    fn parse_pack_rejects_truncated_length() {
        // 3 bytes — not enough for the u32 length.
        assert!(parse_pack(&[0u8; 3]).is_err());
    }

    #[test]
    fn parse_pack_rejects_truncated_body() {
        // Length says 10, but body is only 4 bytes.
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(b"abcd");
        assert!(parse_pack(&buf).is_err());
    }

    #[test]
    fn round_trip_packfile() {
        // F-D3-01 rejects zero-length entries — use non-empty ones.
        let entries = vec![
            PackEntry {
                id: ObjectId([0u8; 32]),
                bytes: b"x".to_vec(),
            },
            PackEntry {
                id: ObjectId([0u8; 32]),
                bytes: b"hello".to_vec(),
            },
        ];
        let bytes = encode_packfile(&entries);
        // Should start with xz version byte
        assert_eq!(bytes[0], PACKFILE_VERSION_XZ);
        let parsed = parse_packfile(&bytes).unwrap();
        assert_eq!(parsed.len(), entries.len());
        for (a, b) in parsed.iter().zip(entries.iter()) {
            assert_eq!(a.bytes, b.bytes);
        }
    }

    #[test]
    fn parse_packfile_handles_raw_format() {
        // Old format (0x01 + raw data)
        let entries = vec![PackEntry {
            id: ObjectId([0u8; 32]),
            bytes: b"test".to_vec(),
        }];
        let inner = encode_pack(&entries);
        let mut raw = vec![PACKFILE_VERSION_RAW];
        raw.extend_from_slice(&inner);
        let parsed = parse_packfile(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].bytes, b"test");
    }

    #[test]
    fn parse_packfile_rejects_unknown_version() {
        assert!(parse_packfile(&[0xff, 0x00]).is_err());
    }

    #[test]
    fn parse_packfile_rejects_empty() {
        assert!(parse_packfile(b"").is_err());
    }

    #[test]
    fn round_trip_ref_updates_with_create() {
        let updates = vec![
            RefUpdate {
                old: None,
                new: id(b"new1"),
                name: "refs/heads/feature".into(),
            },
            RefUpdate {
                old: Some(id(b"old2")),
                new: id(b"new2"),
                name: "refs/heads/main".into(),
            },
        ];
        let bytes = encode_ref_updates(&updates);
        let parsed = parse_ref_updates(&bytes).unwrap();
        assert_eq!(parsed, updates);
    }

    #[test]
    fn parse_info_refs_rejects_bad_line() {
        assert!(parse_info_refs(b"no-tab-here\n").is_err());
    }
}
