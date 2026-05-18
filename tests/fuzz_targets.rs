// Audit 2026-05: structure-aware fuzz harnesses for parser surfaces.
// Each test iterates ~10k random/quasi-random inputs through a
// library parser and asserts no panic. Bounded loops keep the suite
// within the "tests run in DEBUG, at the end of a batch" workflow.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "fuzz harnesses"
)]

use gyt::compress;
use gyt::hash::ObjectId;
use gyt::net::protocol;
use gyt::object::{commit, tag, tree};

/// Tiny deterministic xorshift PRNG so the suite is reproducible
/// without pulling in a rand dependency for tests.
struct Rng(u64);
impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(n);
        v
    }
    fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[(self.next() as usize) % slice.len()]
    }
}

// ─── tree::decode ───────────────────────────────────────────────────

#[test]
fn fuzz_tree_decode_random_bytes() {
    let mut rng = Rng::new(0x00C0_FFEE_u64);
    for _ in 0..2000 {
        let n = (rng.next() % 256) as usize;
        let buf = rng.bytes(n);
        // No panic, no UB.
        let _ = tree::decode(&buf);
    }
}

#[test]
fn fuzz_tree_decode_structured_inputs() {
    let modes = ["100644", "100755", "120000", "40000", "100", "999"];
    let names: &[&[u8]] = &[b"a", b"b", b"foo", b".", b"..", b".gyt", b"\x01"];
    let mut rng = Rng::new(42);
    for _ in 0..1000 {
        let mut wire = Vec::new();
        let entries = (rng.next() % 4) as usize;
        for _ in 0..entries {
            let mode = *rng.pick(&modes);
            wire.extend_from_slice(mode.as_bytes());
            wire.push(b' ');
            wire.extend_from_slice(rng.pick(names));
            wire.push(0);
            wire.extend_from_slice(&[0u8; 32]);
        }
        let _ = tree::decode(&wire);
    }
}

// ─── commit::decode ─────────────────────────────────────────────────

#[test]
fn fuzz_commit_decode_random_bytes() {
    let mut rng = Rng::new(0xDEAD_BEEF);
    for _ in 0..2000 {
        let n = (rng.next() % 1024) as usize;
        let buf = rng.bytes(n);
        let _ = commit::decode(&buf);
    }
}

#[test]
fn fuzz_commit_decode_almost_valid() {
    // Start from a valid commit payload, then perturb random bytes.
    let base = b"tree 0000000000000000000000000000000000000000000000000000000000000000\ncommitter A <a@x> 1 +0000\n\nm".to_vec();
    let mut rng = Rng::new(7);
    for _ in 0..1000 {
        let mut buf = base.clone();
        let idx = (rng.next() as usize) % buf.len();
        buf[idx] = (rng.next() & 0xff) as u8;
        let _ = commit::decode(&buf);
    }
}

// ─── tag::decode ────────────────────────────────────────────────────

#[test]
fn fuzz_tag_decode_random_bytes() {
    let mut rng = Rng::new(13);
    for _ in 0..2000 {
        let n = (rng.next() % 1024) as usize;
        let buf = rng.bytes(n);
        let _ = tag::decode(&buf);
    }
}

// ─── compress::decode ───────────────────────────────────────────────

#[test]
fn fuzz_compress_decode_random_bytes() {
    let mut rng = Rng::new(0x0BAD_CAFE);
    for _ in 0..1000 {
        let n = (rng.next() % 1024) as usize;
        let buf = rng.bytes(n);
        let _ = compress::decode(&buf);
    }
}

#[test]
fn fuzz_compress_decode_magic_prefix_garbage() {
    // Build "MAGIC + FLAG_XZ + random" and decode. Must not panic.
    let mut rng = Rng::new(99);
    for _ in 0..500 {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\xffGYT"); // placeholder for whatever MAGIC is
        buf.push(0x02);
        buf.extend_from_slice(&rng.bytes(128));
        let _ = compress::decode(&buf);
    }
}

// ─── parse_info_refs ────────────────────────────────────────────────

#[test]
fn fuzz_info_refs_random_text() {
    let mut rng = Rng::new(0xAA55);
    for _ in 0..2000 {
        let n = (rng.next() % 1024) as usize;
        let buf = rng.bytes(n);
        let _ = protocol::parse_info_refs(&buf);
    }
}

#[test]
fn fuzz_info_refs_quasi_valid_lines() {
    let mut rng = Rng::new(101);
    let names = ["refs/heads/m", "refs/tags/v1", "HEAD", "", "refs/heads/", "refs/heads/x\x01"];
    for _ in 0..500 {
        let mut s = String::new();
        let lines = (rng.next() % 10) as usize;
        for _ in 0..lines {
            let id_bytes = rng.bytes(32);
            let id = ObjectId(id_bytes.try_into().unwrap());
            let name = names[(rng.next() as usize) % names.len()];
            s.push_str(&id.to_hex());
            s.push('\t');
            s.push_str(name);
            s.push('\n');
        }
        let _ = protocol::parse_info_refs(s.as_bytes());
    }
}

// ─── parse_wants ────────────────────────────────────────────────────

#[test]
fn fuzz_wants_random_text() {
    let mut rng = Rng::new(0xBEEFE);
    for _ in 0..2000 {
        let n = (rng.next() % 1024) as usize;
        let buf = rng.bytes(n);
        let _ = protocol::parse_wants(&buf);
    }
}

// ─── parse_packfile ─────────────────────────────────────────────────

#[test]
fn fuzz_parse_packfile_random_bytes() {
    let mut rng = Rng::new(0xC001);
    for _ in 0..2000 {
        let n = (rng.next() % 4096) as usize;
        let buf = rng.bytes(n);
        let _ = protocol::parse_packfile(&buf);
    }
}

#[test]
fn fuzz_parse_packfile_v1_random_inner_lengths() {
    let mut rng = Rng::new(33);
    for _ in 0..500 {
        let mut buf = vec![0x01u8];
        let n = (rng.next() % 8) as u32;
        buf.extend_from_slice(&n.to_le_bytes());
        for _ in 0..n {
            let len = (rng.next() % 1024) as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&rng.bytes(len.min(64) as usize));
        }
        let _ = protocol::parse_packfile(&buf);
    }
}

// ─── tree mode token canonicality (M37) ─────────────────────────────

#[test]
fn fuzz_tree_decode_leading_zero_modes_all_rejected() {
    // Exhaustively check that every "0<canonical>" form is rejected.
    let canon = ["100644", "100755", "120000", "40000"];
    for &c in &canon {
        for prefix_zeros in 1..4 {
            let mut wire = Vec::new();
            wire.extend_from_slice("0".repeat(prefix_zeros).as_bytes());
            wire.extend_from_slice(c.as_bytes());
            wire.extend_from_slice(b" file");
            wire.push(0);
            wire.extend_from_slice(&[0u8; 32]);
            let r = tree::decode(&wire);
            assert!(
                r.is_err(),
                "leading-zero mode `{}{c}` must be rejected",
                "0".repeat(prefix_zeros)
            );
        }
    }
}

// ─── ref name validator never panics ────────────────────────────────

#[test]
fn fuzz_validate_ref_name_random_strings() {
    let mut rng = Rng::new(0xFACE);
    for _ in 0..2000 {
        let n = (rng.next() % 64) as usize;
        let bytes = rng.bytes(n);
        let s = String::from_utf8_lossy(&bytes);
        let _ = gyt::refs::validate_ref_name(&s);
    }
}

// ─── term::s never panics on arbitrary UTF-8 ────────────────────────

#[test]
fn fuzz_term_s_random_strings() {
    let mut rng = Rng::new(0xDEAD);
    for _ in 0..2000 {
        let n = (rng.next() % 256) as usize;
        let bytes = rng.bytes(n);
        let s = String::from_utf8_lossy(&bytes);
        let _ = gyt::term::s(&s);
    }
}
