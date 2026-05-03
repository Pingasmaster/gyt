// Object on-disk wrapping. Raw passthrough by default; xz under feature flag.
// On-disk layout when wrapped:
//   0x67 0x79 0x74 0x01  <flags>  <stream>
// flags bit 0: 1 = xz compressed.
// Files without the magic prefix are read as raw header+payload.

#[cfg(not(feature = "xz"))]
use crate::errors::GytError;
use crate::errors::Result;

pub const MAGIC: [u8; 4] = [0x67, 0x79, 0x74, 0x01];
pub const FLAG_XZ: u8 = 0x01;

pub const SIZE_XZ_HIGH: usize = 10 * 1024 * 1024;

#[cfg(feature = "xz")]
pub fn encode(payload: &[u8]) -> Result<Vec<u8>> {
    xz_impl::encode(payload)
}

#[cfg(not(feature = "xz"))]
pub fn encode(payload: &[u8]) -> Result<Vec<u8>> {
    Ok(payload.to_vec())
}

pub fn decode(stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() >= 5 && stored[..4] == MAGIC {
        let flags = stored[4];
        let body = &stored[5..];
        if flags & FLAG_XZ != 0 {
            return decode_xz(body);
        }
        return Ok(body.to_vec());
    }
    Ok(stored.to_vec())
}

#[cfg(feature = "xz")]
fn decode_xz(body: &[u8]) -> Result<Vec<u8>> {
    xz_impl::decode(body)
}

#[cfg(not(feature = "xz"))]
fn decode_xz(_body: &[u8]) -> Result<Vec<u8>> {
    Err(GytError::Unsupported(
        "object is xz-compressed but `xz` feature is not enabled".into(),
    ))
}

#[cfg(feature = "xz")]
mod xz_impl {
    use super::{FLAG_XZ, MAGIC, SIZE_XZ_HIGH};
    use crate::errors::{GytError, Result};
    use lzma_rust2::{XzOptions, XzReader, XzWriter};
    use std::io::{Read, Write};

    pub fn encode(payload: &[u8]) -> Result<Vec<u8>> {
        let level: u32 = if payload.len() < SIZE_XZ_HIGH { 9 } else { 6 };
        let opts = XzOptions::with_preset(level);
        let mut header = Vec::with_capacity(5);
        header.extend_from_slice(&MAGIC);
        header.push(FLAG_XZ);
        let body = Vec::with_capacity(payload.len() / 2 + 64);
        let mut w =
            XzWriter::new(body, opts).map_err(|e| GytError::Object(format!("xz init: {e}")))?;
        w.write_all(payload)?;
        let body = w
            .finish()
            .map_err(|e| GytError::Object(format!("xz finish: {e}")))?;
        header.extend_from_slice(&body);
        Ok(header)
    }

    pub fn decode(body: &[u8]) -> Result<Vec<u8>> {
        let mut r = XzReader::new(body, false);
        let mut out = Vec::with_capacity(body.len() * 2);
        r.read_to_end(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default() {
        let p = b"hello world";
        let s = encode(p).unwrap();
        let p2 = decode(&s).unwrap();
        assert_eq!(p2, p);
    }

    #[test]
    fn raw_passthrough_decodes() {
        let raw = b"raw bytes no magic";
        assert_eq!(decode(raw).unwrap(), raw);
    }
}
