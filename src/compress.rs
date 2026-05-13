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

pub fn encode(payload: &[u8]) -> Vec<u8> {
    let body = xz_encode_raw(payload).expect("xz encoding failed");
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(FLAG_XZ);
    out.extend_from_slice(&body);
    out
}

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

pub fn xz_encode_raw(payload: &[u8]) -> Result<Vec<u8>> {
    let level: u32 = if payload.len() < SIZE_XZ_HIGH { 9 } else { 6 };
    let opts = XzOptions::with_preset(level);
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

#[cfg(test)]
mod tests {
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
