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

fn key_path() -> Result<PathBuf> {
    // Reject an unset HOME loudly. The previous code fell back to `/root`,
    // which silently sent CI secrets to a predictable, world-known location
    // — fine if the process happened to be root, but a confusing
    // permission-denied error for any other user, and a footgun for any
    // automation that ran without HOME set (containers, systemd units).
    let home = std::env::var("HOME").map_err(|_| {
        GytError::Ci(
            "HOME is not set; cannot locate the CI secret key. \
             Set HOME or run from a user shell."
                .into(),
        )
    })?;
    Ok(PathBuf::from(home).join(KEY_DIR).join(KEY_FILE))
}

/// Load the CI encryption key, generating a new one if it doesn't exist.
/// On Unix the file is created with mode `0600`; the loader refuses to read
/// a key whose mode allows group or world access.
pub fn ensure_key() -> Result<[u8; 32]> {
    let path = key_path()?;
    if path.exists() {
        enforce_private_mode(&path)?;
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
        write_private_file(&path, &key)?;
        println!("Generated CI encryption key at {}", path.display());
        Ok(key)
    }
}

/// Refuse to read a key whose file mode allows group or world access.
fn enforce_private_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path)
            .map_err(|e| GytError::Ci(format!("stat {}: {e}", path.display())))?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(GytError::Ci(format!(
                "CI key {} has insecure mode {mode:o} — run `chmod 600 {}`",
                path.display(),
                path.display()
            )));
        }
    }
    let _ = path;
    Ok(())
}

/// Create the key file with O_EXCL + mode 0600 on Unix.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| GytError::Ci(format!("opening CI key for write: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| GytError::Ci(format!("writing CI key: {e}")))?;
        f.sync_all()
            .map_err(|e| GytError::Ci(format!("fsync CI key: {e}")))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|e| GytError::Ci(format!("opening CI key for write: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| GytError::Ci(format!("writing CI key: {e}")))?;
        f.sync_all()
            .map_err(|e| GytError::Ci(format!("fsync CI key: {e}")))?;
        Ok(())
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

#[expect(
    clippy::indexing_slicing,
    reason = "args[0] access is gated by args.is_empty() check"
)]
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

#[expect(
    clippy::indexing_slicing,
    reason = "args[0] access is gated by args.is_empty() check"
)]
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
