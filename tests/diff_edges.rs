// Edge-case tests for src/diff.rs and `gyt diff`.
//
// Covers the "No newline at end of file" marker (anomaly #3), binary
// detection, CRLF handling pin, Unicode normalization pin, and a
// large-input bounded-time check (ignored by default).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;

#[test]
fn diff_emits_no_newline_at_eof_marker() {
    // FAILING TEST — code anomaly #3 — will be fixed in Phase C of
    // fan-out-subagents-to-jiggly-lagoon.md
    //
    // src/diff.rs::render_unified currently does not emit the
    // `\ No newline at end of file` marker when one side of a diff is
    // missing its trailing newline. Pin the expected behaviour so the
    // Phase C fix has a concrete target.
    let env = Env::new("diff-no-newline");
    let repo = env.fresh_repo("r");

    // Stage and commit a file WITHOUT a trailing newline.
    std::fs::write(repo.join("a"), b"hello").unwrap();
    env.ok_in(&repo, &["add", "a"]);
    env.ok_in(&repo, &["commit", "-m", "no-newline"]);

    // Modify workdir to ADD a trailing newline.
    std::fs::write(repo.join("a"), b"hello\n").unwrap();

    let out = env.ok_in(&repo, &["diff"]);
    assert!(
        out.contains("\\ No newline at end of file"),
        "diff must emit the missing-newline marker; got:\n{out}"
    );
}

#[test]
fn diff_binary_files_emits_binary_marker() {
    let env = Env::new("diff-binary");
    let repo = env.fresh_repo("r");

    // A file with a NUL byte is "binary" by gyt's detector.
    let bin: Vec<u8> = vec![0x42, 0x00, 0x43, 0x44];
    std::fs::write(repo.join("b.bin"), &bin).unwrap();
    env.ok_in(&repo, &["add", "b.bin"]);
    env.ok_in(&repo, &["commit", "-m", "added binary"]);

    // Modify the binary in the workdir.
    let bin2: Vec<u8> = vec![0x99, 0x00, 0x01, 0x02];
    std::fs::write(repo.join("b.bin"), &bin2).unwrap();

    let out = env.ok_in(&repo, &["diff"]);
    assert!(
        out.contains("Binary files differ"),
        "binary file diff must announce binary nature; got:\n{out}"
    );
}

#[test]
fn diff_crlf_lines_pinned() {
    // Pin the CURRENT behaviour: split_lines only splits on `\n`, so a
    // CRLF line and an LF line on opposite sides of the diff are seen
    // as different (the `\r` is part of the line content). This test
    // documents the status quo — if the implementation grows CRLF-
    // aware splitting later, update the expectation accordingly.
    let env = Env::new("diff-crlf");
    let repo = env.fresh_repo("r");

    std::fs::write(repo.join("t.txt"), b"line1\r\nline2\r\n").unwrap();
    env.ok_in(&repo, &["add", "t.txt"]);
    env.ok_in(&repo, &["commit", "-m", "crlf"]);

    std::fs::write(repo.join("t.txt"), b"line1\nline2\n").unwrap();

    let out = env.ok_in(&repo, &["diff"]);
    // Status-quo: a diff IS produced (the two byte sequences differ
    // and are not currently normalised by the engine).
    assert!(
        !out.is_empty(),
        "current behaviour: CRLF vs LF produces a non-empty diff; got empty output",
    );
    // And the diff carries a hunk header — proves the unified-diff path
    // ran rather than the binary fallback.
    assert!(
        out.contains("@@"),
        "expected unified-diff hunk header; got:\n{out}",
    );
}

#[test]
fn diff_unicode_nfc_vs_nfd_pinned() {
    // Pin the current behaviour: gyt does not normalise Unicode, so
    // the same visible string in NFC vs NFD has different byte
    // sequences and a diff is produced. If a future change adds
    // normalisation, update this test.
    let env = Env::new("diff-unicode-nf");
    let repo = env.fresh_repo("r");

    // U+00E9 (NFC: é, single codepoint c3 a9 in utf-8)
    let nfc: &[u8] = b"caf\xc3\xa9\n";
    // U+0065 U+0301 (NFD: e + combining acute, 65 cc 81)
    let nfd: &[u8] = b"cafe\xcc\x81\n";

    std::fs::write(repo.join("u.txt"), nfc).unwrap();
    env.ok_in(&repo, &["add", "u.txt"]);
    env.ok_in(&repo, &["commit", "-m", "nfc"]);

    std::fs::write(repo.join("u.txt"), nfd).unwrap();

    let out = env.ok_in(&repo, &["diff"]);
    assert!(
        !out.is_empty(),
        "current behaviour: NFC vs NFD produces a non-empty diff",
    );
    assert!(
        out.contains("@@"),
        "expected unified-diff hunk header; got:\n{out}",
    );
}

#[test]
fn diff_large_completes_in_bounded_time() {
    // 60k lines side-A vs 60k all-different lines side-B. Above
    // MAX_DIFF_LINES (50k) the engine degrades to coarse delete-all/
    // insert-all and must NOT spin in the Θ((n+m)²) Myers trace.
    // With the degrade path active the run is sub-second; we give it
    // 30s as a generous upper bound that still catches any reversion
    // to the quadratic path on a slow CI box.
    let env = Env::new("diff-large");
    let repo = env.fresh_repo("r");

    let mut a = String::with_capacity(60_000 * 8);
    for i in 0..60_000_u32 {
        a.push_str(&format!("A-{i}\n"));
    }
    std::fs::write(repo.join("big.txt"), a.as_bytes()).unwrap();
    env.ok_in(&repo, &["add", "big.txt"]);
    env.ok_in(&repo, &["commit", "-m", "big-A"]);

    let mut b = String::with_capacity(60_000 * 8);
    for i in 0..60_000_u32 {
        b.push_str(&format!("B-{i}\n"));
    }
    std::fs::write(repo.join("big.txt"), b.as_bytes()).unwrap();

    let started = std::time::Instant::now();
    let _ = env.ok_in(&repo, &["diff"]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "60k-line diff took {elapsed:?}, expected <30s (degrade path should activate)",
    );
}
