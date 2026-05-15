// Integration tests that exercise the HTTP client against the in-process
// server stub. Plain HTTP (loopback only).

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test module: expect/unwrap on test scaffolding is how the test signals failure"
)]

use crate::compress;
use crate::hash::{self, ObjectId};
use crate::net::http::HttpClient;
use crate::net::protocol::{
    self, PackEntry, RefEntry, RefUpdate, encode_ref_updates, encode_wants,
    parse_info_refs, parse_packfile,
};
use crate::net::server_stub::{self, ServerState};
use crate::object::ObjectKind;
use crate::object::store::build_raw;
use std::collections::HashMap;

fn mk_object(payload: &[u8]) -> (ObjectId, Vec<u8>) {
    let raw = build_raw(ObjectKind::Blob, payload);
    let id = hash::hash_bytes(&raw);
    let stored = compress::encode(&raw);
    (id, stored)
}

fn empty_state() -> ServerState {
    ServerState::default()
}

#[test]
fn get_info_refs_returns_expected_refs() {
    let mut state = empty_state();
    let id_a = hash::hash_bytes(b"aaa");
    let id_b = hash::hash_bytes(b"bbb");
    state.refs.push(RefEntry {
        name: "refs/heads/main".into(),
        id: id_a,
    });
    state.refs.push(RefEntry {
        name: "refs/tags/v1".into(),
        id: id_b,
    });

    let mut server = server_stub::spawn(state, false).expect("spawn server");
    let client = HttpClient::new_plain(&server.base_url()).expect("client");

    let resp = client.get("info/refs", &[]).expect("get");
    assert_eq!(resp.status, 200);
    let parsed = parse_info_refs(&resp.body).expect("parse refs");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name, "refs/heads/main");
    assert_eq!(parsed[0].id, id_a);
    assert_eq!(parsed[1].name, "refs/tags/v1");
    assert_eq!(parsed[1].id, id_b);

    server.shutdown();
}

#[test]
fn post_objects_want_returns_pack() {
    let mut state = empty_state();
    let (id1, on_disk1) = mk_object(b"hello");
    let (id2, on_disk2) = mk_object(b"world!");
    let mut objs = HashMap::new();
    objs.insert(id1, on_disk1.clone());
    objs.insert(id2, on_disk2.clone());
    state.objects = objs;

    let mut server = server_stub::spawn(state, false).expect("spawn server");
    let client = HttpClient::new_plain(&server.base_url()).expect("client");

    let body = encode_wants(&[id1, id2]);
    let resp = client
        .post(
            "objects/want",
            &body,
            &[("Content-Type", "application/x-gyt-wants")],
        )
        .expect("post");
    assert_eq!(resp.status, 200, "reason={}", resp.reason);

    let entries = parse_packfile(&resp.body).expect("parse pack");
    assert_eq!(entries.len(), 2);
    // Verify decoding & hashing matches.
    for entry in &entries {
        let raw = compress::decode(&entry.bytes).expect("decode");
        let id = hash::hash_bytes(&raw);
        assert!(id == id1 || id == id2);
    }
    server.shutdown();
}

#[test]
fn ref_updates_apply_and_reject_non_ff() {
    let mut state = empty_state();
    let id_old = hash::hash_bytes(b"old");
    let id_new = hash::hash_bytes(b"new");
    state.refs.push(RefEntry {
        name: "refs/heads/main".into(),
        id: id_old,
    });

    let mut server = server_stub::spawn(state, false).expect("spawn server");
    let client = HttpClient::new_plain(&server.base_url()).expect("client");

    // 1) Stale old -> 409.
    let bad = encode_ref_updates(&[RefUpdate {
        old: Some(hash::hash_bytes(b"wrong-old")),
        new: id_new,
        name: "refs/heads/main".into(),
    }]);
    let resp = client
        .post(
            "refs/update",
            &bad,
            &[("Content-Type", "application/x-gyt-refupdate")],
        )
        .expect("post bad");
    assert_eq!(resp.status, 409, "reason={}", resp.reason);

    // 2) Correct old -> 200.
    let good = encode_ref_updates(&[RefUpdate {
        old: Some(id_old),
        new: id_new,
        name: "refs/heads/main".into(),
    }]);
    let resp = client
        .post(
            "refs/update",
            &good,
            &[("Content-Type", "application/x-gyt-refupdate")],
        )
        .expect("post good");
    assert_eq!(resp.status, 200, "reason={}", resp.reason);

    // 3) Server state actually updated.
    let resp = client.get("info/refs", &[]).expect("get refs");
    let parsed = parse_info_refs(&resp.body).expect("parse refs");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].id, id_new);

    server.shutdown();
}

#[test]
fn create_ref_with_no_old() {
    let mut server = server_stub::spawn(empty_state(), false).expect("spawn");
    let client = HttpClient::new_plain(&server.base_url()).expect("client");

    let new_id = hash::hash_bytes(b"feature-tip");
    let body = encode_ref_updates(&[RefUpdate {
        old: None,
        new: new_id,
        name: "refs/heads/feature".into(),
    }]);
    let resp = client.post("refs/update", &body, &[]).expect("post");
    assert_eq!(resp.status, 200);

    // Force-update path: should also be accepted with stale old when force=1.
    let stale = encode_ref_updates(&[RefUpdate {
        old: Some(hash::hash_bytes(b"wrong-old")),
        new: hash::hash_bytes(b"forced-new"),
        name: "refs/heads/feature".into(),
    }]);
    let resp = client
        .post("refs/update?force=1", &stale, &[])
        .expect("post forced");
    assert_eq!(resp.status, 200);

    server.shutdown();
}

#[test]
fn chunked_response_is_decoded() {
    let mut state = empty_state();
    let id1 = hash::hash_bytes(b"aaa");
    state.refs.push(RefEntry {
        name: "refs/heads/main".into(),
        id: id1,
    });

    // chunk_responses = true on the stub.
    let mut server = server_stub::spawn(state, true).expect("spawn");
    let client = HttpClient::new_plain(&server.base_url()).expect("client");

    let resp = client.get("info/refs", &[]).expect("get");
    assert_eq!(resp.status, 200);
    // Verify we did not see a Content-Length header — chunked path was used.
    assert!(resp.header("Content-Length").is_none());
    let parsed = parse_info_refs(&resp.body).expect("parse refs");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].id, id1);

    server.shutdown();
}

#[test]
fn objects_have_round_trip() {
    let mut server = server_stub::spawn(empty_state(), false).expect("spawn");
    let client = HttpClient::new_plain(&server.base_url()).expect("client");

    let (id1, on_disk1) = mk_object(b"hello");
    let (id2, on_disk2) = mk_object(b"world");

    let body = protocol::encode_packfile(&[
        PackEntry {
            id: id1,
            bytes: on_disk1.clone(),
        },
        PackEntry {
            id: id2,
            bytes: on_disk2.clone(),
        },
    ]);
    let resp = client.post("objects/have", &body, &[]).expect("post");
    assert_eq!(resp.status, 200, "reason={}", resp.reason);

    // Now verify by fetching them back via /objects/want.
    let want = encode_wants(&[id1, id2]);
    let resp = client.post("objects/want", &want, &[]).expect("want");
    assert_eq!(resp.status, 200);
    let entries = parse_packfile(&resp.body).expect("parse pack");
    assert_eq!(entries.len(), 2);

    server.shutdown();
}
