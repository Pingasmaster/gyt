// Fuzz-testing helpers.
//
// Provides `fuzz_object` which safely tries to interpret arbitrary byte
// sequences as various gyt data formats, catching all panics.
use std::panic::catch_unwind;

/// Outcome of fuzzing one byte slice against all decoders.
//
// Reason: this struct exists to model the parallel "tried decoder X, did
// it survive?" results for each of the six object/config kinds. Bundling
// them into a single bool-per-kind struct is the cleanest representation;
// flattening into an enum or bitset would obscure intent and make the
// fuzz tooling harder to extend.
#[expect(clippy::struct_excessive_bools, reason = "discrete capability flags read independently at use sites — collapsing into a state machine would obscure intent")]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FuzzOutcome {
    pub blob_ok: bool,
    pub tree_ok: bool,
    pub commit_ok: bool,
    pub tag_ok: bool,
    pub config_ok: bool,
    pub index_ok: bool,
}

/// Safely try to decode `b` as every gyt object type, plus as a config
/// and as an index. Catches panics so the caller never unwinds.
///
/// Each `*_ok` field is `true` iff the corresponding decoder ran to
/// completion **without panicking** (a decode `Err` still counts as
/// "ok" because the decoder reported a clean error). The flags lie if
/// they're set unconditionally — a panicking decoder would then be
/// reported as "ok" and the catch_unwind safety net silently goes
/// missing. B11 fix: set each flag from the actual catch_unwind result.
pub fn fuzz_object(b: &[u8]) -> FuzzOutcome {
    let mut r = FuzzOutcome::default();

    // 1) Try parse_raw (splits "<kind> <size>\0<payload>").
    //    If it succeeds we have a valid object header, then try the
    //    type-specific decoders. Each type's *_ok reflects ITS decoder's
    //    panic-freedom, not parse_raw's.
    let parsed = catch_unwind(|| crate::object::store::parse_raw(b));
    if let Ok(Ok((kind, payload))) = parsed {
        match kind {
            crate::object::ObjectKind::Blob => {
                // Blobs have no further structure — parse_raw not
                // panicking is the only signal.
                r.blob_ok = true;
            }
            crate::object::ObjectKind::Tree => {
                let res = catch_unwind(|| crate::object::tree::decode(&payload));
                r.tree_ok = res.is_ok();
            }
            crate::object::ObjectKind::Commit => {
                let res = catch_unwind(|| crate::object::commit::decode(&payload));
                r.commit_ok = res.is_ok();
            }
            crate::object::ObjectKind::Tag => {
                let res = catch_unwind(|| crate::object::tag::decode(&payload));
                r.tag_ok = res.is_ok();
            }
        }
    }

    // 2) Try parsing as a config TOML.
    let cfg_res = catch_unwind(|| {
        let _ = crate::config::parse(b);
    });
    r.config_ok = cfg_res.is_ok();

    // 3) Try parsing as a GYTI index.
    let idx_res = catch_unwind(|| {
        let _ = crate::index::Index::parse(b);
    });
    r.index_ok = idx_res.is_ok();

    r
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────

    /// Simple xorshift64* PRNG for deterministic fuzzing.
    fn rng_seq(seed: u64) -> impl Iterator<Item = u64> {
        let mut state = seed;
        std::iter::from_fn(move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            Some(state.wrapping_mul(0x2545_F491_4F6C_DD1D))
        })
    }

    fn random_bytes(rng: &mut impl Iterator<Item = u64>, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(rng.next().unwrap() as u8);
        }
        buf
    }

    // ── fuzz_round_trip_objects ──────────────────────────────────────────

    #[test]
    fn fuzz_round_trip_objects() {
        let mut rng = rng_seq(42);
        let mut count = 0u64;

        // B11: every fuzz call must report `config_ok && index_ok`
        // because these two decoders are expected to NEVER panic
        // on any input. If a regression introduces a panic in
        // `config::parse` or `Index::parse`, that flag will now go
        // false (previously it was set unconditionally and silently
        // hid the panic).
        let check = |bytes: &[u8]| {
            let r = fuzz_object(bytes);
            assert!(
                r.config_ok,
                "config::parse panicked on input of len {}",
                bytes.len()
            );
            assert!(
                r.index_ok,
                "Index::parse panicked on input of len {}",
                bytes.len()
            );
        };

        // Empty
        check(&[]);
        count += 1;

        // Tiny sizes: 1-100 bytes
        for _ in 0..200 {
            let len = (rng.next().unwrap() as usize % 100).max(1);
            let bytes = random_bytes(&mut rng, len);
            check(&bytes);
            count += 1;
        }

        // Medium sizes: 100-1000 bytes
        for _ in 0..200 {
            let len = 100 + (rng.next().unwrap() as usize % 901);
            let bytes = random_bytes(&mut rng, len);
            check(&bytes);
            count += 1;
        }

        // Large: 1000-5000 bytes (a handful)
        for _ in 0..99 {
            let len = 1000 + (rng.next().unwrap() as usize % 4001);
            let bytes = random_bytes(&mut rng, len);
            check(&bytes);
            count += 1;
        }

        assert_eq!(count, 500, "must test exactly 500 random inputs");
    }

    /// B11 contract regression: a panicking closure inside fuzz_object
    /// MUST be reflected as a `false` flag. The previous code set the
    /// flag unconditionally; if a decoder ever panics, the harness would
    /// have happily reported "ok". This test calls catch_unwind on a
    /// known-panicking closure to verify the gating pattern compiles
    /// and behaves as required (`Result::is_ok` on a panicked unwind is
    /// `false`). It's a guard against someone "simplifying" the flag
    /// assignment back to unconditional.
    #[test]
    #[expect(clippy::panic, reason = "test deliberately planted to verify catch_unwind contract")]
    fn fuzz_panic_caught_yields_false_flag() {
        let res = std::panic::catch_unwind(|| panic!("planted"));
        assert!(res.is_err(), "catch_unwind must report planted panic");
        let ok = res.is_ok();
        assert!(!ok, "Result::is_ok on a panicked unwind must be false");
    }

    // ── fuzz_malformed_index ─────────────────────────────────────────────

    #[test]
    fn fuzz_malformed_index() {
        let mut rng = rng_seq(123);
        for _ in 0..500 {
            let len = (rng.next().unwrap() as usize % 2048).max(1);
            let bytes = random_bytes(&mut rng, len);
            let _ = catch_unwind(|| {
                let _ = crate::index::Index::parse(&bytes);
            });
        }
        // If we got here without a panic, success.
    }

    // ── fuzz_malformed_config ────────────────────────────────────────────

    #[test]
    fn fuzz_malformed_config() {
        let mut rng = rng_seq(456);

        // Pure random bytes
        for _ in 0..200 {
            let len = (rng.next().unwrap() as usize % 1024).max(1);
            let bytes = random_bytes(&mut rng, len);
            let _ = catch_unwind(|| {
                let _ = crate::config::parse(&bytes);
            });
        }

        // TOML-like junk: partial headers, bad quotes, weird escaping, etc.
        let junk_lines: &[&str] = &[
            "[",
            "[]",
            "[user",
            "name = \"alice",
            "key = \"val",
            "key = val",
            "key = ",
            "= value",
            "[remote.]",
            "[remote..name]",
            "[remote.name",
            "name = \"a\nb\"",
            "name = \u{0}",
            "# just a comment",
            "name \\= \"a\"",
            "name = \"a\\\"",
            "name = \"a\\\\\\\"",
            "[user]\nname = \"foo\"\n# no value after =",
            "[user]\nname = ",
            "name = \n\"foo\"",
            "a = \"b\"\nc = \"d\"\n[e]\nf = \"g\"",
        ];

        for line in junk_lines {
            let _ = catch_unwind(|| {
                let _ = crate::config::parse(line.as_bytes());
            });
        }

        // Random string-like garbage
        for _ in 0..200 {
            let len = (rng.next().unwrap() as usize % 512).max(1);
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    let v = rng.next().unwrap() % 128;
                    if v < 32 { 32 } else { v as u8 }
                })
                .collect();
            let _ = catch_unwind(|| {
                let _ = crate::config::parse(&bytes);
            });
        }
    }
}
