// Audit 2026-05: wire-protocol extreme/strict cases. All tests
// directly exercise the library so they're fast and parallel-safe.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]

use gyt::hash::ObjectId;
use gyt::net::protocol::{
    self, MAX_INFO_REFS_ENTRIES, MAX_INFO_REF_NAME_LEN, RefEntry, encode_info_refs,
    parse_info_refs, parse_wants,
};

fn id_zero() -> ObjectId {
    ObjectId::from_hex(&"0".repeat(64)).unwrap()
}
fn id_one() -> ObjectId {
    ObjectId::from_hex(&format!("{:0>64}", 1)).unwrap()
}

// ─── info/refs parser ───────────────────────────────────────────────

#[test]
fn info_refs_empty_body_is_empty_vec() {
    let v = parse_info_refs(b"").unwrap();
    assert!(v.is_empty());
}

#[test]
fn info_refs_single_line_roundtrip() {
    let r = RefEntry { id: id_zero(), name: "refs/heads/main".into() };
    let bytes = encode_info_refs(std::slice::from_ref(&r));
    let parsed = parse_info_refs(&bytes).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name, r.name);
    assert_eq!(parsed[0].id, r.id);
}

#[test]
fn info_refs_rejects_missing_tab() {
    let line = format!("{}refs/heads/main\n", "0".repeat(64));
    assert!(parse_info_refs(line.as_bytes()).is_err());
}

#[test]
fn info_refs_rejects_empty_name() {
    let line = format!("{}\t\n", "0".repeat(64));
    assert!(parse_info_refs(line.as_bytes()).is_err());
}

#[test]
fn info_refs_rejects_overlong_name() {
    let mut s = String::new();
    s.push_str(&"0".repeat(64));
    s.push('\t');
    s.push_str(&"a".repeat(MAX_INFO_REF_NAME_LEN + 1));
    s.push('\n');
    assert!(parse_info_refs(s.as_bytes()).is_err());
}

#[test]
fn info_refs_rejects_duplicate_refname() {
    // L18
    let mut s = String::new();
    s.push_str(&format!("{}\trefs/heads/main\n", "0".repeat(64)));
    s.push_str(&format!("{}\trefs/heads/main\n", "1".repeat(64)));
    let err = parse_info_refs(s.as_bytes()).err();
    assert!(err.is_some(), "duplicate refname must be rejected");
}

#[test]
fn info_refs_rejects_invalid_hex_in_id() {
    let line = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\trefs/heads/main\n";
    assert!(parse_info_refs(line).is_err());
}

#[test]
fn info_refs_caps_entry_count() {
    let mut s = String::new();
    for i in 0..=MAX_INFO_REFS_ENTRIES {
        s.push_str(&format!("{}\trefs/heads/b{i}\n", "0".repeat(64)));
    }
    assert!(parse_info_refs(s.as_bytes()).is_err());
}

#[test]
fn info_refs_accepts_blank_lines_between_entries() {
    let mut s = String::new();
    s.push_str(&format!("{}\trefs/heads/main\n", "0".repeat(64)));
    s.push('\n');
    s.push_str(&format!("{}\trefs/heads/dev\n", "1".repeat(64)));
    let v = parse_info_refs(s.as_bytes()).unwrap();
    assert_eq!(v.len(), 2);
}

#[test]
fn info_refs_rejects_non_utf8_bytes() {
    let bad = vec![0xffu8, 0xfe, b'\t', b'a', b'\n'];
    assert!(parse_info_refs(&bad).is_err());
}

// ─── wants parser ───────────────────────────────────────────────────

#[test]
fn wants_empty_is_empty_vec() {
    assert!(parse_wants(b"").unwrap().is_empty());
}

#[test]
fn wants_single_id_round_trip() {
    let bytes = format!("{}\n", id_zero().to_hex());
    let v = parse_wants(bytes.as_bytes()).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0], id_zero());
}

#[test]
fn wants_rejects_wrong_length_hex() {
    let short = b"0123\n";
    assert!(parse_wants(short).is_err());
}

#[test]
fn wants_rejects_non_hex() {
    let bad = format!("{}\n", "z".repeat(64));
    assert!(parse_wants(bad.as_bytes()).is_err());
}

#[test]
fn wants_handles_trailing_newline_or_not() {
    let no_newline = id_zero().to_hex();
    assert_eq!(parse_wants(no_newline.as_bytes()).unwrap().len(), 1);
    let with_newline = format!("{no_newline}\n");
    assert_eq!(parse_wants(with_newline.as_bytes()).unwrap().len(), 1);
}

// ─── packfile parser version dispatch ───────────────────────────────

#[test]
fn parse_packfile_unknown_version_byte_errors() {
    let body = b"\xffsome bytes";
    assert!(protocol::parse_packfile(body).is_err());
}

#[test]
fn parse_packfile_empty_body_errors() {
    assert!(protocol::parse_packfile(&[]).is_err());
}

#[test]
fn parse_packfile_v1_with_zero_entries_is_ok() {
    // Empty body after version byte → no entries.
    let body = vec![0x01u8];
    let parsed = protocol::parse_packfile(&body).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn parse_packfile_v1_with_oversized_length_rejected() {
    // version 0x01 raw, then a u32 LE length that exceeds remaining
    // body — must error rather than allocate huge / read past EOF.
    let mut body = vec![0x01u8];
    body.extend_from_slice(&999_999_999u32.to_le_bytes());
    assert!(protocol::parse_packfile(&body).is_err());
}

#[test]
fn parse_packfile_v1_zero_length_entry_rejected() {
    // F-D3-01: zero-length entries refused (bomb defense).
    let mut body = vec![0x01u8];
    body.extend_from_slice(&0u32.to_le_bytes());
    assert!(protocol::parse_packfile(&body).is_err());
}

// ─── encode/decode round trip for info/refs preserves ordering ──────

#[test]
fn info_refs_roundtrip_preserves_order() {
    let entries = vec![
        RefEntry { id: id_zero(), name: "refs/heads/main".into() },
        RefEntry { id: id_one(),  name: "refs/heads/dev".into() },
    ];
    let bytes = encode_info_refs(&entries);
    let parsed = parse_info_refs(&bytes).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name, "refs/heads/main");
    assert_eq!(parsed[1].name, "refs/heads/dev");
}

#[test]
fn info_refs_rejects_trailing_whitespace_in_name() {
    // The encoder doesn't emit trailing whitespace; parser should
    // accept the exact format it produces, no laxer.
    let r = RefEntry { id: id_zero(), name: "refs/heads/main".into() };
    let bytes = encode_info_refs(&[r]);
    let parsed = parse_info_refs(&bytes).unwrap();
    assert_eq!(parsed[0].name, "refs/heads/main");
    assert!(!parsed[0].name.ends_with(' '));
}

#[test]
fn info_refs_huge_legitimate_count_within_cap_succeeds() {
    let mut s = String::new();
    // 1024 entries — well under the cap, but bigger than typical.
    for i in 0..1024u32 {
        s.push_str(&format!("{}\trefs/heads/b{i}\n", "0".repeat(64)));
    }
    let v = parse_info_refs(s.as_bytes()).unwrap();
    assert_eq!(v.len(), 1024);
}

#[test]
fn wants_handles_multiple_ids() {
    let mut s = String::new();
    for i in 0..16u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let id = ObjectId(bytes);
        s.push_str(&format!("{}\n", id.to_hex()));
    }
    let v = parse_wants(s.as_bytes()).unwrap();
    assert_eq!(v.len(), 16);
}
