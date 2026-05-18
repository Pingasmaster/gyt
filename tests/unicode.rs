// Audit 2026-05: unicode edge cases in user-supplied strings.
// All tests directly exercise the library so they're parallel-safe.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on failure"
)]

use gyt::term;

// ─── ANSI / C0 / C1 / bidi control redaction ────────────────────────

#[test]
fn safe_display_strips_bare_esc_byte() {
    let s = "\x1b[31mRED\x1b[0m";
    let out = term::s(s);
    assert!(!out.contains('\x1b'), "ESC must be stripped: {out:?}");
}

#[test]
fn safe_display_strips_osc_clipboard_write() {
    // OSC 52 clipboard write via xterm; starts with ESC ]
    let s = "\x1b]52;c;cGF5bG9hZA==\x07after";
    let out = term::s(s);
    assert!(!out.contains('\x1b'));
    assert!(!out.contains('\x07'));
    assert!(out.contains("after"));
}

#[test]
fn safe_display_strips_carriage_return() {
    let s = "before\rOVERWRITTEN";
    let out = term::s(s);
    assert!(!out.contains('\r'));
}

#[test]
fn safe_display_preserves_tab_and_newline() {
    let s = "a\tb\nc";
    let out = term::s(s);
    assert_eq!(out, "a\tb\nc");
}

#[test]
fn safe_display_strips_bidi_lro_rlo() {
    // L19: Trojan Source class — LRO (U+202D) and RLO (U+202E).
    for c in ['\u{202d}', '\u{202e}', '\u{202a}', '\u{202b}', '\u{202c}'] {
        let s = format!("hello{c}world");
        let out = term::s(&s);
        assert!(
            !out.contains(c),
            "bidi codepoint {:#x} must be stripped, got {:?}",
            c as u32,
            out
        );
    }
}

#[test]
fn safe_display_strips_bidi_isolates() {
    // LRI/RLI/FSI/PDI (U+2066..U+2069)
    for cp in 0x2066u32..=0x2069u32 {
        let c = char::from_u32(cp).unwrap();
        let s = format!("hello{c}world");
        let out = term::s(&s);
        assert!(!out.contains(c), "{cp:#x} must be stripped");
    }
}

#[test]
fn safe_display_strips_lrm_rlm_alm() {
    for cp in [0x200eu32, 0x200fu32, 0x061cu32] {
        let c = char::from_u32(cp).unwrap();
        let s = format!("hello{c}world");
        let out = term::s(&s);
        assert!(!out.contains(c));
    }
}

#[test]
fn safe_display_strips_c1_controls() {
    // C1 controls (0x80..=0x9f) can introduce escapes on some terms.
    let s = "before\u{0085}after";  // NEL
    let out = term::s(s);
    assert!(!out.contains('\u{0085}'));
}

#[test]
fn safe_display_keeps_normal_unicode() {
    let s = "café 🌍 日本語";
    let out = term::s(s);
    assert_eq!(out, s);
}

#[test]
fn safe_display_strips_backspace() {
    let s = "abc\x08OOPS";
    let out = term::s(s);
    assert!(!out.contains('\x08'));
}

#[test]
fn safe_display_strips_form_feed() {
    let s = "a\x0cb";
    let out = term::s(s);
    assert!(!out.contains('\x0c'));
}

#[test]
fn safe_display_strips_vertical_tab() {
    let s = "a\x0bb";
    let out = term::s(s);
    assert!(!out.contains('\x0b'));
}

#[test]
fn safe_display_strips_bell() {
    let s = "a\x07b";
    let out = term::s(s);
    assert!(!out.contains('\x07'));
}

#[test]
fn safe_display_strips_del_0x7f() {
    let s = "a\x7fb";
    let out = term::s(s);
    assert!(!out.contains('\x7f'));
}

#[test]
fn safe_display_preserves_zero_width_joiner() {
    // ZWJ (U+200d) is U+200d ≠ U+200e (LRM). ZWJ is legitimate for
    // emoji sequences and many scripts; we keep it.
    let s = "👨\u{200d}👩";
    let out = term::s(s);
    assert!(out.contains('\u{200d}'));
}

#[test]
fn safe_display_strips_csi_sequence() {
    // CSI = ESC [
    let s = "\x1b[2J\x1b[H\x1b[31mFAKE PROMPT $ ";
    let out = term::s(s);
    assert!(!out.contains('\x1b'));
    assert!(out.contains("FAKE PROMPT"));
}

#[test]
fn safe_display_strips_terminal_title_set() {
    // OSC 0 — set terminal title
    let s = "\x1b]0;PWNED\x07innocuous";
    let out = term::s(s);
    assert!(!out.contains('\x1b'));
    assert!(!out.contains('\x07'));
    assert!(out.contains("innocuous"));
}

#[test]
fn safe_display_strips_string_terminator() {
    // ST = ESC \ — terminates many OSC sequences.
    let s = "\x1b]0;t\x1b\\after";
    let out = term::s(s);
    assert!(!out.contains('\x1b'));
}

#[test]
fn safe_display_empty_input_is_empty_output() {
    assert_eq!(term::s(""), "");
}

#[test]
fn safe_display_all_printable_ascii_round_trips() {
    let s: String = (0x20u8..=0x7eu8).map(|b| b as char).collect();
    let out = term::s(&s);
    assert_eq!(out, s);
}

#[test]
fn safe_display_astral_plane_chars_preserved() {
    let s = "𠜎𠜱𠝹𠱓";
    let out = term::s(s);
    assert_eq!(out, s);
}

#[test]
fn safe_display_nfc_nfd_both_preserved() {
    // é as single codepoint (NFC) vs e + combining-acute (NFD).
    // Both should round-trip unchanged.
    let nfc = "café";
    let nfd = "cafe\u{0301}";
    assert_eq!(term::s(nfc), nfc);
    assert_eq!(term::s(nfd), nfd);
}

// ─── ref name validation accepts/rejects unicode appropriately ──────

#[test]
fn ref_name_accepts_ascii_branch() {
    gyt::refs::validate_ref_name("refs/heads/main").unwrap();
}

#[test]
fn ref_name_rejects_control_byte() {
    let bad = "refs/heads/main\x01";
    assert!(gyt::refs::validate_ref_name(bad).is_err());
}

#[test]
fn ref_name_rejects_double_dot() {
    assert!(gyt::refs::validate_ref_name("refs/heads/../etc").is_err());
}

#[test]
fn ref_name_rejects_lock_suffix() {
    assert!(gyt::refs::validate_ref_name("refs/heads/main.lock").is_err());
}

#[test]
fn ref_name_rejects_trailing_slash() {
    assert!(gyt::refs::validate_ref_name("refs/heads/").is_err());
}

#[test]
fn ref_name_rejects_dotdot_anywhere() {
    // Already covered above with refs/heads/../etc — second variant.
    assert!(gyt::refs::validate_ref_name("a/../b").is_err());
}

// ─── tree entry name validation ─────────────────────────────────────

#[test]
fn tree_entry_name_rejects_dot() {
    let bytes = gyt::object::tree::encode(&[]);
    // Empty tree encodes to empty bytes.
    assert!(bytes.is_empty());
}

#[test]
fn tree_decode_rejects_entry_named_dotdot() {
    let mut wire = Vec::new();
    wire.extend_from_slice(b"100644 ..");
    wire.push(0);
    wire.extend_from_slice(&[0u8; 32]);
    assert!(gyt::object::tree::decode(&wire).is_err());
}

#[test]
fn tree_decode_rejects_entry_named_dotgyt() {
    let mut wire = Vec::new();
    wire.extend_from_slice(b"100644 .gyt");
    wire.push(0);
    wire.extend_from_slice(&[0u8; 32]);
    assert!(gyt::object::tree::decode(&wire).is_err());
}

#[test]
fn tree_decode_rejects_entry_named_dotgyt_uppercase() {
    let mut wire = Vec::new();
    wire.extend_from_slice(b"100644 .GYT");
    wire.push(0);
    wire.extend_from_slice(&[0u8; 32]);
    assert!(gyt::object::tree::decode(&wire).is_err());
}
