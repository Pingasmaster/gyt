// Shared TLS session-ticket key for cross-replica resumption.
//
// rustls's default `Ticketer::new()` auto-generates a key per process
// and rotates it on a schedule. That's perfect for a single host —
// but in a multi-replica deployment, a ticket issued by replica A
// cannot be decrypted by replica B because they have independent
// keys. Clients that hit replica B on retry pay the full TLS
// handshake.
//
// `SharedTicketer` reads a hex-encoded key file at startup. Every
// replica reading the same file uses the same key, so tickets are
// portable across replicas. Up to two keys can be present:
//
//   line 1 (required): 32 bytes hex — the *current* key (encrypt + decrypt)
//   line 2 (optional): 32 bytes hex — the *previous* key (decrypt only)
//
// Operator key rotation: push the new file to all replicas (e.g. via
// configmap reload + SIGHUP-style ticket-key reload — not yet wired;
// today, restart). The previous-key slot lets old tickets keep
// resuming for one rotation window before they expire naturally.
//
// Ticket framing (what we hand to rustls):
//
//   bytes 0..12: AES-GCM 96-bit nonce (random)
//   bytes 12..:  ciphertext || 16-byte GCM tag
//
// Decryption tries the current key first, then the previous key.
// We deliberately do NOT include a key identifier in the ticket:
// a positional "0=current, 1=previous" id breaks during rotation
// because the same logical key sits in different slots on
// pre-rotation and post-rotation replicas. AES-GCM's auth tag
// catches a wrong-key attempt cleanly, so try-each-key is correct
// and ~2× slower in the (rare) previous-key case — a price worth
// paying for rotation correctness.
//
// The encrypt/decrypt operations themselves come from the existing
// `aes-gcm = 0.10.3` dep — same crate the CI-secret store uses.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use rustls::server::ProducesTickets;
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

use crate::errors::{GytError, Result};

const TICKET_LIFETIME_SECS: u32 = 12 * 60 * 60; // 12 hours
const NONCE_LEN: usize = 12;

pub struct SharedTicketer {
    /// The current key — used for encrypt() and as the first decrypt
    /// candidate.
    current: Aes256Gcm,
    /// Optional previous key for one-rotation tolerance.
    previous: Option<Aes256Gcm>,
}

impl fmt::Debug for SharedTicketer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key material.
        f.debug_struct("SharedTicketer")
            .field("has_previous", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

impl SharedTicketer {
    /// Load keys from a text file. Lines starting with `#` and blank
    /// lines are ignored. The first non-blank line is the current key;
    /// the second is the optional previous key. Each key is exactly
    /// 64 hex characters (32 bytes).
    #[expect(
        clippy::indexing_slicing,
        reason = "lines[0] is gated by `lines.is_empty()` early return; lines[1] is gated by `lines.len() == 2` check"
    )]
    pub fn from_file(path: &Path) -> Result<Self> {
        enforce_private_mode(path)?;
        let body = std::fs::read_to_string(path).map_err(|e| {
            GytError::Net(format!("ticket key {}: {e}", path.display()))
        })?;
        let lines: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        if lines.is_empty() {
            return Err(GytError::Net(format!(
                "ticket key {} contains no key lines",
                path.display()
            )));
        }
        if lines.len() > 2 {
            return Err(GytError::Net(format!(
                "ticket key {} has {} key lines; max is 2 (current + previous)",
                path.display(),
                lines.len()
            )));
        }
        let current = parse_key(lines[0])?;
        let previous = if lines.len() == 2 {
            Some(parse_key(lines[1])?)
        } else {
            None
        };
        Ok(Self {
            current: Aes256Gcm::new(&current),
            previous: previous.map(|k| Aes256Gcm::new(&k)),
        })
    }
}

#[expect(
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "hex[i*2..i*2+2] for i in 0..32 fits because hex.len() == 64 is checked at function entry; hex is ASCII so byte ranges are char-boundary safe; bytes[i] is in-range because 0..32 matches the [u8; 32] size"
)]
fn parse_key(hex: &str) -> Result<Key<Aes256Gcm>> {
    if hex.len() != 64 {
        return Err(GytError::Net(format!(
            "ticket key must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        )));
    }
    // Zeroize the decoded key on scope exit so the raw 32-byte material
    // doesn't linger in stack memory after the Key copy is made.
    let mut bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        let b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| GytError::Net(format!("ticket key not valid hex: {e}")))?;
        bytes[i] = b;
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&*bytes))
}

impl ProducesTickets for SharedTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        TICKET_LIFETIME_SECS
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self.current.encrypt(nonce, plain).ok()?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Some(out)
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "cipher[..NONCE_LEN] / cipher[NONCE_LEN..] is gated by the `cipher.len() < NONCE_LEN` early return"
    )]
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < NONCE_LEN {
            return None;
        }
        let nonce = Nonce::from_slice(&cipher[..NONCE_LEN]);
        let body = &cipher[NONCE_LEN..];
        if let Ok(pt) = self.current.decrypt(nonce, body) {
            return Some(pt);
        }
        // Fall back to previous key (during the rotation window).
        if let Some(prev) = &self.previous
            && let Ok(pt) = prev.decrypt(nonce, body)
        {
            return Some(pt);
        }
        None
    }
}

/// Refuse to load a ticket-key file whose mode permits group/world
/// access. Same policy as TLS keys and ed25519 keys.
fn enforce_private_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let md = std::fs::metadata(path)
            .map_err(|e| GytError::Net(format!("stat {}: {e}", path.display())))?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(GytError::Net(format!(
                "ticket key {} has insecure mode {mode:o}; run `chmod 600 {}`",
                path.display(),
                path.display()
            )));
        }
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use std::io::Write as _;

    fn tmp_key(hex_lines: &[&str]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "gyt-ticket-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        for l in hex_lines {
            writeln!(f, "{l}").unwrap();
        }
        // chmod 600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(&p, perm).unwrap();
        }
        p
    }

    #[test]
    fn round_trip_current_key() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let p = tmp_key(&[key]);
        let t = SharedTicketer::from_file(&p).unwrap();
        let ct = t.encrypt(b"session state").unwrap();
        let pt = t.decrypt(&ct).unwrap();
        assert_eq!(pt, b"session state");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn rotation_old_ticket_still_decrypts() {
        let key_v1 = "11112222333344445555666677778888aaaabbbbccccddddeeeeffff00001111";
        let key_v2 = "ffffeeeeddddccccbbbbaaaa999988887777666655554444333322221111ffff";

        // Replica A used to run with v1 as current.
        let p_old = tmp_key(&[key_v1]);
        let t_old = SharedTicketer::from_file(&p_old).unwrap();
        let old_ticket = t_old.encrypt(b"long-lived session").unwrap();

        // Operator rotated: v2 is now current, v1 moved to previous.
        let p_new = tmp_key(&[key_v2, key_v1]);
        let t_new = SharedTicketer::from_file(&p_new).unwrap();

        // Replica B can still resume sessions started before rotation.
        let pt = t_new.decrypt(&old_ticket).unwrap();
        assert_eq!(pt, b"long-lived session");

        // And new tickets work too.
        let new_ticket = t_new.encrypt(b"fresh session").unwrap();
        assert_eq!(t_new.decrypt(&new_ticket).unwrap(), b"fresh session");

        // After a second rotation that drops v1, old tickets stop
        // working — that's the design.
        let key_v3 = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";
        let p_v3 = tmp_key(&[key_v3, key_v2]); // v1 now gone
        let t_v3 = SharedTicketer::from_file(&p_v3).unwrap();
        assert!(t_v3.decrypt(&old_ticket).is_none());
        let _ = std::fs::remove_file(p_old);
        let _ = std::fs::remove_file(p_new);
        let _ = std::fs::remove_file(p_v3);
    }

    #[test]
    fn rejects_wrong_length_key() {
        let p = tmp_key(&["deadbeef"]);
        assert!(SharedTicketer::from_file(&p).is_err());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn rejects_three_keys() {
        let p = tmp_key(&[
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "11223344556677889900bbccddeeff0011223344556677889900bbccddeeff00",
            "22334455667788990011ccddeeff001122334455667788990011ccddeeff0011",
        ]);
        assert!(SharedTicketer::from_file(&p).is_err());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn garbage_ticket_decrypts_to_none() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let p = tmp_key(&[key]);
        let t = SharedTicketer::from_file(&p).unwrap();
        // Random bytes won't pass AES-GCM's auth tag check.
        let bad = vec![0u8; NONCE_LEN + 32];
        assert!(t.decrypt(&bad).is_none());
        // Truncated tickets also rejected.
        assert!(t.decrypt(&bad[..5]).is_none());
        let _ = std::fs::remove_file(p);
    }
}
