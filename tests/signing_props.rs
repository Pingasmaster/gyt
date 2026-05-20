// Audit 2026-05: signing/keygen/verify property tests.
//
// Pins the cryptographic and on-disk contract for ed25519 commit
// signing — key generation is non-deterministic, private files refuse
// to be overwritten, verification fails on tampered payloads and on
// substituted public keys, the base64 decoder rejects malleable
// non-zero-pad-bit inputs, and Unix file modes are 0600.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::integer_division,
    clippy::redundant_closure_for_method_calls,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;

// ─── 1. keygen produces non-deterministic keys ──────────────────────

#[test]
fn keygen_then_keygen_produces_distinct_keys() {
    let env = Env::new("sign-distinct");
    let p1 = env.path("p1");
    let s1 = env.path("s1");
    let p2 = env.path("p2");
    let s2 = env.path("s2");
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            p1.to_str().unwrap(),
            "--priv",
            s1.to_str().unwrap(),
        ],
    );
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            p2.to_str().unwrap(),
            "--priv",
            s2.to_str().unwrap(),
        ],
    );
    let b1 = std::fs::read(&s1).unwrap();
    let b2 = std::fs::read(&s2).unwrap();
    assert_eq!(b1.len(), 32, "private key must be 32 bytes");
    assert_eq!(b2.len(), 32, "private key must be 32 bytes");
    assert_ne!(b1, b2, "two keygen invocations must yield distinct keys");
}

// ─── 2. tampered on-disk commit blob → verify fails ─────────────────

#[test]
fn tampered_payload_verification_fails() {
    let env = Env::new("sign-tamper");
    let pubp = env.path("pub.key");
    let privp = env.path("priv.key");
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            pubp.to_str().unwrap(),
            "--priv",
            privp.to_str().unwrap(),
        ],
    );

    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"hello").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);

    // Signed commit.
    let out = env
        .cmd_in(&repo)
        .env("GYT_SIGNING_KEY", &privp)
        .env("GYT_SIGNING_PUB", &pubp)
        .args(["commit", "-m", "signed", "--sign"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "signed commit must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Resolve HEAD's commit hex and tamper with the on-disk blob.
    let head_ref = std::fs::read_to_string(repo.join(".gyt").join("HEAD")).unwrap();
    let target = head_ref
        .trim()
        .strip_prefix("ref: ")
        .map_or_else(|| head_ref.trim().to_string(), str::to_string);
    let commit_hex = if target.starts_with("refs/") {
        std::fs::read_to_string(repo.join(".gyt").join(&target))
            .unwrap()
            .trim()
            .to_string()
    } else {
        target
    };
    let blob_path = repo
        .join(".gyt")
        .join("objects")
        .join(&commit_hex[..2])
        .join(&commit_hex[2..]);
    assert!(blob_path.exists(), "commit blob must exist at {blob_path:?}");

    // Flip a byte in the middle of the stored (compressed) blob. This
    // either breaks decompression entirely or corrupts the payload —
    // either way `gyt verify` must return non-zero.
    let mut bytes = std::fs::read(&blob_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&blob_path, &bytes).unwrap();

    let out = env
        .cmd_in(&repo)
        .env("GYT_SIGNING_PUB", &pubp)
        .args(["verify", &commit_hex])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify on tampered blob must fail; stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let low = combined.to_lowercase();
    // Corrupting bytes inside an XZ-compressed commit blob produces any
    // of: a BAD SIGNATURE (if decode succeeds but verify fails), or an
    // LZMA/XZ-layer decode error ("dist overflow", "decompress", etc.),
    // or a generic IO error. All of these are valid "tampering caught"
    // signals — the test asserts that SOME failure is surfaced, not
    // which layer caught it.
    assert!(
        combined.contains("BAD SIGNATURE")
            || low.contains("verification failed")
            || low.contains("signature")
            || low.contains("decode")
            || low.contains("decompress")
            || low.contains("xz")
            || low.contains("dist overflow")
            || low.contains("io:"),
        "verify error must mention some tampering signal: {combined}"
    );
}

// ─── 3. swapping the public key file → verify fails ─────────────────

#[test]
fn replaced_public_key_verification_fails() {
    let env = Env::new("sign-swap-pub");
    let pub_a = env.path("a.pub");
    let priv_a = env.path("a.priv");
    let pub_b = env.path("b.pub");
    let priv_b = env.path("b.priv");
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            pub_a.to_str().unwrap(),
            "--priv",
            priv_a.to_str().unwrap(),
        ],
    );
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            pub_b.to_str().unwrap(),
            "--priv",
            priv_b.to_str().unwrap(),
        ],
    );

    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"hello").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    let out = env
        .cmd_in(&repo)
        .env("GYT_SIGNING_KEY", &priv_a)
        .env("GYT_SIGNING_PUB", &pub_a)
        .args(["commit", "-m", "signed-with-a", "--sign"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let head_ref = std::fs::read_to_string(repo.join(".gyt").join("HEAD")).unwrap();
    let target = head_ref.trim().strip_prefix("ref: ").unwrap().to_string();
    let commit_hex = std::fs::read_to_string(repo.join(".gyt").join(&target))
        .unwrap()
        .trim()
        .to_string();

    // Verify with pub_b — same shape but different key. Verification
    // must fail (sig was made with priv_a).
    let out = env
        .cmd_in(&repo)
        .env("GYT_SIGNING_PUB", &pub_b)
        .args(["verify", &commit_hex])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "verify with wrong pub key must fail: {combined}"
    );
    assert!(
        combined.contains("BAD SIGNATURE")
            || combined.to_lowercase().contains("verification failed"),
        "verify error must mention bad signature: {combined}"
    );
}

// ─── 4. sign required + no key → clear error ────────────────────────

#[test]
fn sign_required_without_key_errors_clearly() {
    let env = Env::new("sign-req-nokey");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    env.ok_in(
        &repo,
        &["config", "--set", "commit.sign_required", "true"],
    );
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);

    // Point GYT_SIGNING_KEY at a nonexistent file and try --sign.
    let bogus = env.path("does-not-exist.key");
    let out = env
        .cmd_in(&repo)
        .env("GYT_SIGNING_KEY", &bogus)
        .args(["commit", "-m", "first", "--sign"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "commit must fail without a key");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("signing key")
            || combined.to_lowercase().contains("reading signing key")
            || combined.to_lowercase().contains("no such")
            || combined.to_lowercase().contains("not found"),
        "error must clearly indicate the missing/unreadable key: {combined}"
    );

    // And without --sign at all on a sign-required repo: also fail,
    // pointing at the use --sign hint.
    let out = env
        .cmd_in(&repo)
        .args(["commit", "-m", "first"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("sign"),
        "no-sign error must mention signing: {combined}"
    );
}

// ─── 5. keygen refuses to overwrite an existing private key ─────────

#[cfg(unix)]
#[test]
fn keygen_refuses_overwriting_existing() {
    let env = Env::new("sign-no-overwrite");
    let pubp = env.path("pub.key");
    let privp = env.path("priv.key");
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            pubp.to_str().unwrap(),
            "--priv",
            privp.to_str().unwrap(),
        ],
    );
    let first = std::fs::read(&privp).unwrap();

    // Second invocation with the same private path must fail.
    let out = env
        .cmd_in(&env.dir)
        .args([
            "keygen",
            "--pub",
            pubp.to_str().unwrap(),
            "--priv",
            privp.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "keygen must refuse to overwrite an existing private key"
    );
    let after = std::fs::read(&privp).unwrap();
    assert_eq!(
        first, after,
        "private key bytes must be unchanged after the refused second keygen"
    );
}

// ─── 6. private-key file is mode 0600 on Unix ───────────────────────

#[cfg(unix)]
#[test]
fn private_key_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("sign-mode-0600");
    let pubp = env.path("pub.key");
    let privp = env.path("priv.key");
    env.ok_in(
        &env.dir,
        &[
            "keygen",
            "--pub",
            pubp.to_str().unwrap(),
            "--priv",
            privp.to_str().unwrap(),
        ],
    );
    let md = std::fs::metadata(&privp).unwrap();
    let mode = md.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "private signing key must be mode 0600 (got {mode:o})"
    );
}

// ─── 7. signing refuses to load a world-readable private key ────────

#[cfg(unix)]
#[test]
fn load_signing_key_insecure_mode_refused() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("sign-insecure-mode");
    let privp = env.path("priv.key");
    let pubp = env.path("pub.key");
    // Pre-create a valid 32-byte key file with insecure mode.
    std::fs::write(&privp, [0x42u8; 32]).unwrap();
    std::fs::write(&pubp, [0x55u8; 32]).unwrap();
    std::fs::set_permissions(&privp, std::fs::Permissions::from_mode(0o644)).unwrap();

    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);

    let out = env
        .cmd_in(&repo)
        .env("GYT_SIGNING_KEY", &privp)
        .env("GYT_SIGNING_PUB", &pubp)
        .args(["commit", "-m", "tries-to-sign", "--sign"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "signing must refuse a world-readable private key"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.to_lowercase().contains("insecure mode")
            || combined.to_lowercase().contains("chmod 600"),
        "error must point at the insecure mode: {combined}"
    );
}

// ─── 8. base64_decode rejects non-zero pad bits ─────────────────────

#[test]
fn base64_decode_rejects_non_zero_pad_bits() {
    // "AB==" decodes to 1 byte. The last sextet (B = 0b000001) has
    // 4 low bits that should be discarded. With strict decoding they
    // must be zero — they aren't here, so the decoder must reject.
    let out = gyt::cmd::signing::base64_decode("AB==");
    assert!(
        out.is_none(),
        "strict base64_decode must reject non-zero pad bits in \"AB==\""
    );

    // Sanity: a well-formed input still decodes.
    let ok = gyt::cmd::signing::base64_decode("AA==");
    assert_eq!(
        ok.as_deref(),
        Some(&[0u8][..]),
        "valid base64 must round-trip"
    );
}
