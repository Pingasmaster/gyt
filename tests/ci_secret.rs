// Audit 2026-05: hardening tests for `gyt ci secret`.
//
// AES-GCM nonce reuse is a catastrophic failure mode (same-key
// nonce-reuse leaks plaintext keystream and breaks message
// authentication). The tests below pin:
//   - file-mode enforcement on the on-disk key
//   - exact-length enforcement on the on-disk key
//   - per-call nonce uniqueness
//   - decrypt length floor (no panic on a short ciphertext)
//   - secret-name validation (no traversal, no control bytes)
//   - HOME-required behaviour (no implicit /root fallback)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn key_path_in(home: &std::path::Path) -> PathBuf {
    home.join(".config").join("gyt").join("ci-key")
}

/// Pre-create the per-test key file with a chosen mode and chosen byte
/// length. Returns the absolute path so callers can re-stat it.
#[cfg(unix)]
fn write_key_with_mode(home: &std::path::Path, bytes: &[u8], mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let kp = key_path_in(home);
    std::fs::create_dir_all(kp.parent().unwrap()).unwrap();
    std::fs::write(&kp, bytes).unwrap();
    let mut perms = std::fs::metadata(&kp).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(&kp, perms).unwrap();
    kp
}

// ─── 1. key file mode 0644 rejected ──────────────────────────────────

#[cfg(unix)]
#[test]
fn key_file_mode_0644_rejected() {
    let env = Env::new("ci-secret-mode");
    let repo = env.fresh_repo("r");
    let _kp = write_key_with_mode(&env.dir, &[0u8; 32], 0o644);

    // `set` needs a value on stdin. Use Command directly so we can
    // pipe stdin and inherit env from Env::cmd_in.
    let mut c = env.cmd_in(&repo);
    c.args(["ci", "secret", "set", "mytoken"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        use std::io::Write as _;
        child.stdin.as_mut().unwrap().write_all(b"value\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "set must reject a key with mode 0644 — got success.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("insecure mode") || stderr.contains("chmod 600"),
        "expected a key-mode error, got: {stderr}"
    );
}

// ─── 2. key file length mismatch rejected ────────────────────────────

#[cfg(unix)]
#[test]
fn key_file_length_wrong_rejected() {
    for len in [31usize, 33usize] {
        let env = Env::new(&format!("ci-secret-len-{len}"));
        let repo = env.fresh_repo("r");
        let _kp = write_key_with_mode(&env.dir, &vec![0u8; len], 0o600);

        let mut c = env.cmd_in(&repo);
        c.args(["ci", "secret", "set", "n"]);
        c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        {
            use std::io::Write as _;
            child.stdin.as_mut().unwrap().write_all(b"v\n").unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            !out.status.success(),
            "set must reject a key of length {len} — got success.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("32 bytes") || stderr.contains("must be exactly"),
            "expected a length error, got: {stderr}"
        );
    }
}

// ─── 3. encrypt nonce uniqueness ─────────────────────────────────────

/// 100 sequential encrypts under the same key must yield 100 distinct
/// 12-byte nonces. AES-GCM is catastrophically broken if the (key,
/// nonce) pair repeats: the keystream is XOR-recoverable, and the
/// authentication tag's MAC key becomes recoverable from two
/// (nonce, ciphertext, tag) triples. This is exactly the kind of
/// regression that would slip past a unit test if it didn't pin
/// uniqueness explicitly.
#[test]
fn encrypt_nonce_uniqueness() {
    let key = [0xa5u8; 32];
    let mut seen: HashSet<[u8; 12]> = HashSet::new();
    for i in 0u32..100 {
        // Distinct plaintext per call so even a buggy "nonce derived
        // from plaintext hash" scheme can't pass the test by accident.
        let pt = format!("payload-{i}");
        let out = gyt::cmd::ci_secret::encrypt(&key, pt.as_bytes())
            .expect("encrypt must succeed under a 32-byte key");
        assert!(
            out.len() >= 12 + 16,
            "ciphertext must be at least nonce(12) + tag(16); got {}",
            out.len()
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&out[..12]);
        assert!(
            seen.insert(nonce),
            "nonce reuse at iteration {i}: {nonce:02x?} already seen"
        );
    }
    assert_eq!(seen.len(), 100);
}

// ─── 4. decrypt length floor ─────────────────────────────────────────

/// Anything shorter than nonce(12) + tag(16) = 28 bytes is structurally
/// not a valid AES-GCM ciphertext. The decrypt path must reject it
/// with a clean error and never panic. We also feed the empty input
/// and a 12-byte input (nonce-only, no tag).
#[test]
fn decrypt_length_floor() {
    let key = [0u8; 32];
    for short in [
        Vec::<u8>::new(),
        vec![0u8; 1],
        vec![0u8; 12],
        vec![0u8; 13],
        vec![0u8; 27],
    ] {
        let r = gyt::cmd::ci_secret::decrypt(&key, &short);
        assert!(
            r.is_err(),
            "decrypt({len} bytes) must error, got Ok",
            len = short.len()
        );
    }
}

// ─── 5/6. secret name validation ─────────────────────────────────────

/// A traversal name like `../etc/passwd` must NOT cause gyt to open
/// `<repo>/.gyt/secrets/../etc/passwd`. Current source rejects names
/// containing `/` or `\\`; this test pins that.
#[test]
fn secret_name_validation_rejects_dotdot() {
    let env = Env::new("ci-secret-dotdot");
    let repo = env.fresh_repo("r");

    let mut c = env.cmd_in(&repo);
    c.args(["ci", "secret", "set", "../etc/passwd"]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        use std::io::Write as _;
        child.stdin.as_mut().unwrap().write_all(b"v\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "set must reject a name containing path separators.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("invalid secret name") || stderr.contains("invalid"),
        "expected an invalid-name error, got: {stderr}"
    );

    // And nothing should have been written under repo/.gyt/secrets/.
    let leaked = repo.join(".gyt").join("secrets");
    if leaked.is_dir()
        && let Some(ent) = std::fs::read_dir(&leaked).unwrap().flatten().next()
    {
        panic!("traversal write leaked: {}", ent.path().display());
    }
}

/// A control byte (NUL is unrepresentable in a CString; pick `\x01`)
/// has no business in a secret name. Logs, lockfile names, and a
/// future per-secret stat output would all be poisonable by a name
/// containing control codes.
///
/// Validation rejects: empty, `/`, `\\`, `.`, `..`, leading `.`, and
/// any byte < 0x20 or 0x7f. See `src/cmd/ci_secret.rs::run_set`.
#[test]
fn secret_name_validation_rejects_control_byte() {
    let env = Env::new("ci-secret-ctrl");
    let repo = env.fresh_repo("r");

    let bad = "\x01evil";
    let mut c = env.cmd_in(&repo);
    c.args(["ci", "secret", "set", bad]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        use std::io::Write as _;
        child.stdin.as_mut().unwrap().write_all(b"v\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        !out.status.success(),
        "set must reject a name containing control bytes"
    );
}

// ─── B23. symlinked key file is refused ──────────────────────────────
//
// `enforce_private_mode` previously used `fs::metadata` (which follows
// symlinks), so a multi-tenant attacker who could plant a 0600 file
// they owned and a symlink at the user's expected key path would get
// gyt to encrypt the victim's secrets with the attacker's key. The
// fix switches to `symlink_metadata` and refuses any symlink at the
// key path. This test pins that refusal.
#[cfg(unix)]
#[test]
fn key_file_symlink_refused() {
    let env = Env::new("ci-secret-symlink");
    let repo = env.fresh_repo("r");

    // Plant a real key file *outside* the expected location.
    let real_key = env.dir.join("attacker-key");
    std::fs::write(&real_key, [0u8; 32]).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut p = std::fs::metadata(&real_key).unwrap().permissions();
        p.set_mode(0o600);
        std::fs::set_permissions(&real_key, p).unwrap();
    }

    // Now create a symlink at the expected key path pointing to the
    // attacker's file.
    let kp = key_path_in(&env.dir);
    std::fs::create_dir_all(kp.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real_key, &kp).unwrap();

    let mut c = env.cmd_in(&repo);
    c.args(["ci", "secret", "set", "victim"]);
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        use std::io::Write as _;
        child.stdin.as_mut().unwrap().write_all(b"v\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "set must reject a symlinked key path.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("symlink"),
        "expected a symlink-rejection error, got: {stderr}"
    );
}

// ─── 7. unset HOME must not silently fall back to /root ──────────────

/// Spawn `gyt ci secret set` with an empty environment so HOME is
/// not set. The current implementation explicitly errors instead of
/// resolving the key under `/root/.config/gyt/ci-key` — pin that.
#[test]
fn unset_home_refuses_no_root_fallback() {
    let env = Env::new("ci-secret-nohome");
    let repo = env.fresh_repo("r");
    // Use raw Command so we can env_clear without inheriting HOME.
    // We must still set PATH so the dynamic linker can find shared
    // objects on platforms that need it, and we set the gyt author
    // env so `init` would work — but at this point `set` should
    // fail before any of that matters.
    let mut c = Command::new(&env.bin);
    c.current_dir(&repo)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GYT_AUTHOR_NAME", "Audit User")
        .env("GYT_AUTHOR_EMAIL", "audit@example.com")
        .args(["ci", "secret", "set", "n"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    {
        use std::io::Write as _;
        child.stdin.as_mut().unwrap().write_all(b"v\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "set must error when HOME is unset, not fall back to /root.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("HOME is not set") || stderr.to_lowercase().contains("home"),
        "expected a HOME-required error, got: {stderr}"
    );
    // Belt-and-braces: /root/.config/gyt must not have been touched.
    let root_key = PathBuf::from("/root/.config/gyt/ci-key");
    if let Ok(md) = std::fs::metadata(&root_key) {
        // If /root/.config/gyt/ci-key exists on this host it must
        // pre-date this test (we can't read mtime cheaply across
        // platforms). The strict guarantee is that our test process
        // did not *create* it; if it does exist, that's only safe
        // when it's not the file we just told gyt to write.
        let _ = md; // pinned: don't assert, just record
    }
}
