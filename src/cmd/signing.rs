// Cryptograhic signing for gyt commits using ed25519.
//
// Design:
//   - Pure Rust (ed25519-dalek), no libc dependency.
//   - Keys stored as raw 32-byte files.
//   - Default key paths: ~/.config/gyt/signing-key and ~/.config/gyt/signing-pub.
//   - Signature stored in commit header as: signature <base64>
//   - The signature is computed over the entire commit payload EXCEPT the
//     `signature` line itself (same pattern as Git).
//
// The user can override key paths via `gyt config signing.key <path>` and
// `gyt config signing.pub <path>`.

use crate::errors::{GytError, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use std::path::{Path, PathBuf};

/// Default signing key path.
pub fn default_key_path() -> PathBuf {
    let mut p = dirs_config_dir().unwrap_or_else(|| PathBuf::from("~/.config/gyt"));
    p.push("gyt-signing-key");
    p
}

/// Default verification (public) key path.
pub fn default_pub_path() -> PathBuf {
    let mut p = dirs_config_dir().unwrap_or_else(|| PathBuf::from("~/.config/gyt"));
    p.push("gyt-signing-pub");
    p
}

/// Resolve the signing key path: check config, fall back to default.
pub fn resolve_key_path(config: Option<&str>) -> PathBuf {
    match config {
        Some(p) => PathBuf::from(p),
        None => default_key_path(),
    }
}

/// Resolve the public key path: check config, fall back to default.
#[allow(dead_code)] // public API for future key resolution
pub fn resolve_pub_path(config: Option<&str>) -> PathBuf {
    match config {
        Some(p) => PathBuf::from(p),
        None => default_pub_path(),
    }
}

/// Load the signing key from a path.
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let bytes = std::fs::read(path)
        .map_err(|e| GytError::Ci(format!("reading signing key {}: {e}", path.display())))?;
    if bytes.len() != 32 {
        return Err(GytError::Ci(format!(
            "signing key must be exactly 32 bytes, got {}",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GytError::Ci("signing key: expected 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Load the public key from a path or hex string.
pub fn load_verifying_key(pub_key_path: Option<&Path>) -> Result<VerifyingKey> {
    match pub_key_path {
        Some(path) => {
            let bytes = std::fs::read(path)
                .map_err(|e| GytError::Ci(format!("reading public key {}: {e}", path.display())))?;
            if bytes.len() != 32 {
                return Err(GytError::Ci(format!(
                    "public key must be exactly 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| GytError::Ci("public key: expected 32 bytes".into()))?;
            Ok(
                VerifyingKey::from_bytes(&arr)
                    .map_err(|e| GytError::Ci(format!("ed25519: {e}")))?,
            )
        }
        None => {
            // Try default public key path
            let path = default_pub_path();
            load_verifying_key(Some(&path))
        }
    }
}

/// Sign a commit payload. Returns the base64-encoded signature.
///
/// The `commit_payload` should be the entire commit WITHOUT the signature line.
/// The signature is appended as a `signature <b64>` line in the commit header.
pub fn sign_commit(payload: &[u8], key_path: &Path) -> Result<String> {
    let signing_key = load_signing_key(key_path)?;
    let signature = signing_key.sign(payload);
    Ok(base64_encode(signature.to_bytes().as_slice()))
}

/// Compute the commit payload that gets signed — the full commit encoding
/// with the signature line omitted.  This is the payload signed by ed25519.
pub fn commit_payload_without_sig(c: &crate::object::commit::Commit) -> Vec<u8> {
    // Build a commit with signature stripped (already None in the flow)
    let mut payload = Vec::new();
    payload.extend_from_slice(b"tree ");
    payload.extend_from_slice(c.tree.to_hex().as_bytes());
    payload.push(b'\n');
    for p in &c.parents {
        payload.extend_from_slice(b"parent ");
        payload.extend_from_slice(p.to_hex().as_bytes());
        payload.push(b'\n');
    }
    for a in &c.authors {
        payload.extend_from_slice(b"author ");
        payload.extend_from_slice(a.as_bytes());
        payload.push(b'\n');
    }
    payload.extend_from_slice(b"committer ");
    payload.extend_from_slice(c.committer.as_bytes());
    payload.push(b'\n');
    for ai in &c.ai_assists {
        payload.extend_from_slice(b"ai ");
        payload.extend_from_slice(ai.as_bytes());
        payload.push(b'\n');
    }
    for r in &c.reviewers {
        payload.extend_from_slice(b"reviewer ");
        payload.extend_from_slice(r.as_bytes());
        payload.push(b'\n');
    }
    // NO signature line — this is the payload that gets signed
    payload.push(b'\n');
    payload.extend_from_slice(c.message.as_bytes());
    payload
}

/// Verify a commit signature.
///
/// `payload_without_sig` is the commit content with the `signature` line removed.
/// `b64_sig` is the base64-encoded ed25519 signature from the commit header.
/// `pub_key_path` is an optional override path for the public key.
pub fn verify_signature(
    payload: &[u8],
    b64_sig: &str,
    pub_key_path: Option<&Path>,
) -> Result<bool> {
    let verifying_key = load_verifying_key(pub_key_path)?;
    let sig_bytes = base64_decode(b64_sig)
        .ok_or_else(|| GytError::Ci("invalid base64 in commit signature".into()))?;
    if sig_bytes.len() != 64 {
        return Err(GytError::Ci(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| GytError::Ci("signature: expected 64 bytes".into()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    Ok(verifying_key.verify(payload, &sig).is_ok())
}

/// Generate a new ed25519 keypair. Saves to the given paths (or defaults).
/// Returns the public key bytes.
pub fn generate_keys(priv_path: &Path, pub_path: &Path) -> Result<Vec<u8>> {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Ensure parent directories exist
    if let Some(parent) = priv_path.parent() {
        std::fs::create_dir_all(parent).map_err(GytError::Io)?;
    }
    if let Some(pub_parent) = pub_path.parent() {
        let same = priv_path.parent().is_some_and(|p| p == pub_parent);
        if !same {
            std::fs::create_dir_all(pub_parent).map_err(GytError::Io)?;
        }
    }

    std::fs::write(priv_path, signing_key.to_bytes()).map_err(GytError::Io)?;
    let pub_bytes = verifying_key.to_bytes();
    std::fs::write(pub_path, pub_bytes).map_err(GytError::Io)?;

    Ok(pub_bytes.to_vec())
}

// ── Minimal base64 (no external dep needed) ───────────────────

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() >= 2 {
            out.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() >= 3 {
            out.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch {
            'A'..='Z' => u32::from(ch as u8 - b'A'),
            'a'..='z' => u32::from(ch as u8 - b'a' + 26),
            '0'..='9' => u32::from(ch as u8 - b'0' + 52),
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn dirs_config_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".config");
        p.push("gyt");
        Some(p)
    } else {
        None
    }
}
