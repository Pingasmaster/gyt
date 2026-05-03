// BLAKE3 hashing + hex codec. Implementation lands in Phase 2.

use crate::errors::{GytError, Result};

pub const HASH_LEN: usize = 32;
pub const HEX_LEN: usize = HASH_LEN * 2;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId(pub [u8; HASH_LEN]);

impl ObjectId {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HASH_LEN {
            return Err(GytError::Parse(format!(
                "expected {HASH_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != HEX_LEN {
            return Err(GytError::Parse(format!(
                "expected {HEX_LEN} hex chars, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; HASH_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_nibble(s.as_bytes()[i * 2])?;
            let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(HEX_LEN);
        for b in self.0 {
            s.push(hex_char(b >> 4));
            s.push(hex_char(b & 0x0f));
        }
        s
    }
}

impl std::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectId({})", self.to_hex())
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

pub fn hash_bytes(bytes: &[u8]) -> ObjectId {
    let h = blake3::hash(bytes);
    ObjectId(*h.as_bytes())
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(GytError::Parse(format!("non-hex byte: {b:#x}"))),
    }
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + nibble - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_hex() {
        let id = hash_bytes(b"hello world");
        let s = id.to_hex();
        assert_eq!(s.len(), HEX_LEN);
        let id2 = ObjectId::from_hex(&s).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn rejects_short_hex() {
        assert!(ObjectId::from_hex("abc").is_err());
    }
}
