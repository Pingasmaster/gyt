// Object on-disk wrapping using XZ/LZMA via lzma-rust2.
// On-disk layout when wrapped:
//   0x67 0x79 0x74 0x01  <flags>  <stream>
// flags bit 0: 1 = xz compressed.
// Files without the magic prefix are read as raw header+payload (for
// backwards-compat with any objects written before wrapping was always on).

use crate::errors::{GytError, Result};
use lzma_rust2::{XzOptions, XzReader, XzWriter};
use std::io::{Read, Write};

pub const MAGIC: [u8; 4] = [0x67, 0x79, 0x74, 0x01];
pub const FLAG_XZ: u8 = 0x01;

// Threshold below which we use a higher preset (more compression).
pub const SIZE_XZ_HIGH: usize = 10 * 1024 * 1024;

/// Hard cap on the decompressed size of a single xz stream. Anything larger
/// is treated as a decompression-bomb attempt and aborted before the
/// allocator commits the memory. The server's body cap is 256 MiB, so a
/// 1 GiB ceiling here still rejects obvious bombs while leaving headroom
/// for legitimate large packfiles.
pub const MAX_DECOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;

/// Per-request cumulative ceiling on bytes the XZ decoder is allowed to
/// emit. Closes F-D3-02: `MAX_DECOMPRESSED_BYTES` only caps ONE stream,
/// but `wire_objects_have` decodes the outer pack XZ AND every entry's
/// inner XZ. A pusher could chain thousands of entries each near the
/// 1 GiB ceiling and burn hours of CPU per request. 2 GiB total per
/// request is more than the 256 MiB body cap can imply legitimately
/// even with maximum compression ratio.
pub const MAX_REQUEST_XZ_OUTPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
#[expect(
    clippy::expect_used,
    reason = "the invariant guarded by this expect cannot fail (verified at the call site)"
)]
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let body = xz_encode_raw(payload).expect("xz encoding failed");
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(FLAG_XZ);
    out.extend_from_slice(&body);
    out
}

#[expect(
    clippy::indexing_slicing,
    reason = "every index/slice below is gated by the `stored.len() >= 5` check at the top of the if"
)]
pub fn decode(stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() >= 5 && stored[..4] == MAGIC {
        let flags = stored[4];
        let body = &stored[5..];
        if flags & FLAG_XZ != 0 {
            return xz_decode_raw(body);
        }
        return Ok(body.to_vec());
    }
    Ok(stored.to_vec())
}
#[expect(
    clippy::integer_division,
    reason = "intentional truncating integer division"
)]
pub fn xz_encode_raw(payload: &[u8]) -> Result<Vec<u8>> {
    let level: u32 = if payload.len() < SIZE_XZ_HIGH { 9 } else { 6 };
    let mut opts = XzOptions::with_preset(level);
    // Apply the "extreme"-equivalent tuning that xz-utils's `-9e` flag
    // gives: push the match-finder's `nice_len` to its max (273) and
    // raise `depth_limit` to 1000. Cost is encoder CPU time; ratio
    // improves a few percent on the kind of compressible payloads
    // gyt deals with (commits, trees, text blobs). For preset >= 4
    // (Normal mode, BT4 match-finder) this is meaningful; for the
    // fast presets we leave the defaults alone.
    if level >= 4 {
        opts.lzma_options.nice_len = 273;
        opts.lzma_options.depth_limit = 1000;
    }
    let body = Vec::with_capacity(payload.len() / 2 + 64);
    let mut w = XzWriter::new(body, opts).map_err(|e| GytError::Object(format!("xz init: {e}")))?;
    w.write_all(payload)?;
    w.finish()
        .map_err(|e| GytError::Object(format!("xz finish: {e}")))
}

pub fn xz_decode_raw(body: &[u8]) -> Result<Vec<u8>> {
    let r = XzReader::new(body, false);
    let mut bounded = r.take(MAX_DECOMPRESSED_BYTES + 1);
    // Pre-allocate up to 2× input but cap at 1 MiB — defending against an
    // attacker sending a tiny stream that decompresses huge by giving
    // ourselves a small starting buffer that grows as actual data arrives.
    let initial = (body.len().saturating_mul(2)).min(1024 * 1024);
    let mut out = Vec::with_capacity(initial);
    bounded.read_to_end(&mut out)?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(GytError::Object(format!(
            "xz: decompressed output exceeds {MAX_DECOMPRESSED_BYTES} bytes (decompression bomb?)"
        )));
    }
    Ok(out)
}

/// Same as `decode`, but also subtracts the produced output size from a
/// caller-supplied per-request budget. F-D3-02: a single push can
/// trigger N decode calls (outer pack XZ + per-entry inner XZ);
/// without a cumulative budget, an attacker can chain thousands of
/// near-1-GiB-decoded entries and burn server CPU for hours. Returns
/// `GytError::Object` once the budget is exhausted — the caller
/// (typically `wire_objects_have`) surfaces this as 413.
pub fn decode_with_budget(
    stored: &[u8],
    remaining: &std::sync::atomic::AtomicU64,
) -> Result<Vec<u8>> {
    let out = decode(stored)?;
    let produced = out.len() as u64;
    // saturating_sub via fetch_update: drop budget but never go below 0.
    let prev = remaining.load(std::sync::atomic::Ordering::Acquire);
    if produced > prev {
        remaining.store(0, std::sync::atomic::Ordering::Release);
        return Err(GytError::Object(format!(
            "xz: cumulative request decompressed output exceeded budget \
             (this entry added {produced} bytes, only {prev} were left)"
        )));
    }
    remaining.fetch_sub(produced, std::sync::atomic::Ordering::AcqRel);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    #[test]
    fn round_trip_default() {
        let p = b"hello world";
        let s = encode(p);
        let p2 = decode(&s).unwrap();
        assert_eq!(p2, p);
    }

    #[test]
    fn raw_passthrough_decodes() {
        let raw = b"raw bytes no magic";
        assert_eq!(decode(raw).unwrap(), raw);
    }

    #[test]
    fn encoded_starts_with_magic() {
        let s = encode(b"payload");
        assert_eq!(&s[..4], &MAGIC);
        assert_eq!(s[4], FLAG_XZ);
    }

    #[test]
    fn xz_raw_round_trip() {
        let payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".repeat(100);
        let enc = xz_encode_raw(&payload).unwrap();
        let dec = xz_decode_raw(&enc).unwrap();
        assert_eq!(dec, payload);
    }
}
