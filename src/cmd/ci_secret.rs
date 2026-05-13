// gyt CI secret management — AES-256-GCM encrypted secrets.
//
// Secrets are stored in .gyt/secrets/<name>, each file containing
// 12-byte random nonce || AES-256-GCM ciphertext.
// The encryption key lives at ~/.config/gyt/ci-key (32 raw bytes).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use crate::errors::{GytError, Result};
use rand::RngCore;
use std::io::Read;
use std::path::{Path, PathBuf};

const KEY_DIR: &str = ".config/gyt";
const KEY_FILE: &str = "ci-key";

fn key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(KEY_DIR).join(KEY_FILE)
}

/// Load the CI encryption key, generating a new one if it doesn't exist.
pub fn ensure_key() -> Result<[u8; 32]> {
    let path = key_path();
    if path.exists() {
        let raw =
            std::fs::read(&path).map_err(|e| GytError::Ci(format!("reading CI key: {e}")))?;
        if raw.len() != 32 {
            return Err(GytError::Ci("CI key must be exactly 32 bytes".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        Ok(key)
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| GytError::Ci(format!("creating key dir: {e}")))?;
        }
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        std::fs::write(&path, key)
            .map_err(|e| GytError::Ci(format!("writing CI key: {e}")))?;
        println!("Generated CI encryption key at {}", path.display());
        Ok(key)
    }
}

/// Encrypt plaintext with AES-256-GCM, returning [nonce(12) || ciphertext].
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_ref = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ref, plaintext)
        .map_err(|e| GytError::Ci(format!("encryption failed: {e}")))?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data from [nonce(12) || ciphertext] back to plaintext.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 13 {
        return Err(GytError::Ci("encrypted data too short".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GytError::Ci("decryption failed (wrong key or corrupted data)".into()))
}

fn secrets_dir(gyt_dir: &Path) -> PathBuf {
    gyt_dir.join("secrets")
}

pub fn run_init(_args: &[String]) -> Result<()> {
    let _ = ensure_key()?;
    println!("CI encryption key ready.");
    Ok(())
}

pub fn run_set(args: &[String], gyt_dir: &Path) -> Result<()> {
    if args.is_empty() || args[0] == "--help" {
        eprintln!("Usage: gyt ci secret set <name>");
        eprintln!();
        eprintln!("Reads the secret value from stdin. Encrypted with AES-256-GCM");
        eprintln!("and stored in .gyt/secrets/<name>.");
        eprintln!("The CI encryption key at ~/.config/gyt/ci-key is used.");
        return Ok(());
    }
    let name = &args[0];
    if name.contains('/') || name.contains('\\') || name.is_empty() {
        return Err(GytError::InvalidArgument("invalid secret name".into()));
    }
    let key = ensure_key()?;
    let sec_dir = secrets_dir(gyt_dir);
    std::fs::create_dir_all(&sec_dir)
        .map_err(|e| GytError::Ci(format!("creating secrets dir: {e}")))?;
    let mut value = Vec::new();
    std::io::stdin()
        .read_to_end(&mut value)
        .map_err(|e| GytError::Ci(format!("reading stdin: {e}")))?;
    // Strip trailing newline(s)
    while value.ends_with(b"\n") || value.ends_with(b"\r") {
        value.pop();
    }
    let encrypted = encrypt(&key, &value)?;
    let secret_path = sec_dir.join(name);
    std::fs::write(&secret_path, &encrypted)
        .map_err(|e| GytError::Ci(format!("writing secret {name}: {e}")))?;
    println!("Secret '{name}' stored.");
    Ok(())
}

pub fn run_list(_args: &[String], gyt_dir: &Path) -> Result<()> {
    let sec_dir = secrets_dir(gyt_dir);
    if !sec_dir.is_dir() {
        println!("No secrets stored.");
        return Ok(());
    }
    let mut names: Vec<String> = std::fs::read_dir(&sec_dir)
        .map_err(|e| GytError::Ci(format!("reading secrets dir: {e}")))?
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    if names.is_empty() {
        println!("No secrets stored.");
    } else {
        println!("Stored secrets:");
        for n in &names {
            println!("  {n}");
        }
    }
    Ok(())
}

pub fn run_remove(args: &[String], gyt_dir: &Path) -> Result<()> {
    if args.is_empty() || args[0] == "--help" {
        eprintln!("Usage: gyt ci secret remove <name>");
        return Ok(());
    }
    let name = &args[0];
    let secret_path = secrets_dir(gyt_dir).join(name);
    if !secret_path.exists() {
        return Err(GytError::NotFound(format!("secret '{name}' not found")));
    }
    std::fs::remove_file(&secret_path)
        .map_err(|e| GytError::Ci(format!("removing secret {name}: {e}")))?;
    println!("Secret '{name}' removed.");
    Ok(())
}
