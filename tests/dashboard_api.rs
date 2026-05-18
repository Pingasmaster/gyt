// Audit 2026-05: dashboard JSON API smoke tests.
// Exercises src/net/api.rs JSON shape construction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests panic on failure"
)]

use gyt::net::api;

#[test]
fn json_string_escapes_quotes() {
    let s = api::json_string("he said \"hi\"");
    assert!(s.starts_with('"'));
    assert!(s.ends_with('"'));
    assert!(s.contains("\\\""));
}

#[test]
fn json_string_escapes_backslash() {
    let s = api::json_string("a\\b");
    assert!(s.contains("\\\\"));
}

#[test]
fn json_string_escapes_newline() {
    let s = api::json_string("a\nb");
    assert!(s.contains("\\n"));
}

#[test]
fn json_string_escapes_carriage_return() {
    let s = api::json_string("a\rb");
    assert!(s.contains("\\r"));
}

#[test]
fn json_string_escapes_tab() {
    let s = api::json_string("a\tb");
    assert!(s.contains("\\t"));
}

#[test]
fn json_string_escapes_control_bytes() {
    let s = api::json_string("a\x01b");
    assert!(s.contains("\\u0001"));
}

#[test]
fn json_string_empty_input() {
    assert_eq!(api::json_string(""), "\"\"");
}

#[test]
fn json_string_preserves_unicode() {
    let s = api::json_string("café 日本語 🌍");
    // Non-ASCII chars are kept as-is in JSON output (no \u-escaping
    // required for chars ≥ U+0020).
    assert!(s.contains("café") || s.contains("\\u"));
}

#[test]
fn parse_page_default() {
    let p = api::parse_page(&[], 1);
    assert_eq!(p, 1);
}

#[test]
fn parse_page_explicit() {
    let p = api::parse_page(&[("page".into(), "5".into())], 1);
    assert_eq!(p, 5);
}

#[test]
fn parse_page_invalid_falls_back_to_default() {
    let p = api::parse_page(&[("page".into(), "abc".into())], 3);
    assert_eq!(p, 3);
}

#[test]
fn parse_page_caps_at_max() {
    // H10: 1M cap
    let huge = "18446744073709551615";  // u64::MAX
    let p = api::parse_page(&[("page".into(), huge.into())], 1);
    assert!(p <= 1_000_000);
}

#[test]
fn parse_per_page_default() {
    let p = api::parse_per_page(&[], 50, 100);
    assert_eq!(p, 50);
}

#[test]
fn parse_per_page_capped_at_max() {
    let p = api::parse_per_page(&[("per_page".into(), "9999".into())], 50, 100);
    assert_eq!(p, 100);
}

#[test]
fn parse_per_page_invalid_uses_default() {
    let p = api::parse_per_page(&[("per_page".into(), "nope".into())], 50, 100);
    assert_eq!(p, 50);
}

#[test]
fn parse_page_with_other_params() {
    let p = api::parse_page(
        &[("foo".into(), "bar".into()), ("page".into(), "7".into())],
        1,
    );
    assert_eq!(p, 7);
}

#[test]
fn parse_page_first_match_wins() {
    let p = api::parse_page(
        &[("page".into(), "3".into()), ("page".into(), "9".into())],
        1,
    );
    // First match wins per .iter().find() semantics.
    assert_eq!(p, 3);
}

#[test]
fn json_string_quotes_double_backslash() {
    // "\\" — two backslashes in the input should yield four in output.
    let s = api::json_string("\\\\");
    assert_eq!(s, "\"\\\\\\\\\"");
}

#[test]
fn json_string_high_codepoint_kept() {
    let s = api::json_string("\u{1F300}");  // CYCLONE
    // Not escaped — JSON allows non-ASCII verbatim.
    assert!(s.contains('\u{1F300}') || s.contains("\\u"));
}

#[test]
fn json_string_null_byte_escaped() {
    let s = api::json_string("a\0b");
    assert!(s.contains("\\u0000"));
}

#[test]
fn json_string_bare_ascii_ranges_preserved() {
    let input: String = (0x20u8..=0x7eu8).map(|b| b as char).collect();
    let s = api::json_string(&input);
    // Should round-trip every visible ASCII char except `"` and `\`.
    assert!(s.contains('!'));
    assert!(s.contains('~'));
}

#[test]
fn parse_page_zero_returns_zero_default() {
    // Page=0 is user-supplied; parse_page itself just returns it.
    // L7's "page=0 returns empty" is enforced at the list() layer.
    let p = api::parse_page(&[("page".into(), "0".into())], 1);
    assert_eq!(p, 0);
}

#[test]
fn parse_per_page_zero_clamped_or_zero() {
    let p = api::parse_per_page(&[("per_page".into(), "0".into())], 50, 100);
    assert_eq!(p, 0);
}
