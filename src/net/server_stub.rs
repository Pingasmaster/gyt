// Tiny test-only HTTP/1.1 server. Phase 6a.
//
// Plain HTTP, single-thread per connection, ephemeral port. Holds a snapshot
// of refs and a map of objects (id -> on-disk bytes), and exposes:
//   GET  /info/refs       -> encode_info_refs
//   POST /objects/want    -> encode_pack of the wanted object bytes
//   POST /objects/have    -> consume pack, store entries (id := hash of decoded raw)
//   POST /refs/update     -> apply ref-updates with ff-only check (?force=1 to bypass)
//
// All POST bodies are read by Content-Length (the client always sends one).
// Responses are sent with Content-Length OR `Transfer-Encoding: chunked` based
// on the per-server configuration `chunk_responses`.
//
// For tests only — never used in production.

use crate::compress;
use crate::errors::Result;
use crate::hash::{self, ObjectId};
use crate::net::protocol::{self, PackEntry, RefEntry, encode_info_refs, encode_packfile};
use crate::object;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Default)]
pub struct ServerState {
    pub refs: Vec<RefEntry>,
    pub objects: HashMap<ObjectId, Vec<u8>>, // id -> on-disk bytes
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<ServerState>>,
    shutdown: Arc<Mutex<bool>>,
    join: Option<thread::JoinHandle<()>>,
    pub chunk_responses: bool,
}

impl ServerHandle {
    pub fn base_url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    pub fn shutdown(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Wake the accept loop by connecting once.
        let _ = TcpStream::connect(self.addr);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.shutdown();
        }
    }
}

pub fn spawn(state: ServerState, chunk_responses: bool) -> Result<ServerHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let state = Arc::new(Mutex::new(state));
    let shutdown = Arc::new(Mutex::new(false));
    let s_clone = state.clone();
    let sd_clone = shutdown.clone();
    let join = thread::spawn(move || {
        for stream in listener.incoming() {
            if *sd_clone.lock().unwrap() {
                return;
            }
            match stream {
                Ok(s) => {
                    let st = s_clone.clone();
                    let sd2 = sd_clone.clone();
                    thread::spawn(move || {
                        let _ = handle_conn(s, st, chunk_responses, sd2);
                    });
                }
                Err(_) => return,
            }
        }
    });
    Ok(ServerHandle {
        addr,
        state,
        shutdown,
        join: Some(join),
        chunk_responses,
    })
}

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
}

// Reason: each thread spawned to handle a connection takes owned `Arc`s
// rather than references because the spawn outlives the calling stack
// frame. Clippy can't see across the spawn boundary.
#[allow(clippy::needless_pass_by_value)]
fn handle_conn(
    stream: TcpStream,
    state: Arc<Mutex<ServerState>>,
    chunked: bool,
    shutdown: Arc<Mutex<bool>>,
) -> std::io::Result<()> {
    if *shutdown.lock().unwrap() {
        return Ok(());
    }
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let req = match read_request(&mut reader) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_response(
                &mut writer,
                400,
                "Bad Request",
                &[("Content-Type", "text/plain")],
                e.to_string().as_bytes(),
                false,
            );
            return Ok(());
        }
    };

    // Strip query string for routing.
    let (path, query) = match req.target.find('?') {
        Some(i) => (&req.target[..i], Some(&req.target[i + 1..])),
        None => (req.target.as_str(), None),
    };

    let (status, reason, body, ctype) = route(&req.method, path, query, &req.body, &state);

    let _ = write_response(
        &mut writer,
        status,
        reason,
        &[("Content-Type", ctype)],
        &body,
        chunked,
    );
    Ok(())
}

// Reason: this is the in-memory test stub. Locks are held across small
// codec calls and `Vec` builds for code clarity; the alternative (fine-
// grained scopes around every helper) hurts readability without buying
// throughput because the test stub is single-threaded per request.
#[allow(clippy::significant_drop_tightening)]
fn route(
    method: &str,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    state: &Arc<Mutex<ServerState>>,
) -> (u16, &'static str, Vec<u8>, &'static str) {
    match (method, path) {
        ("GET", "/info/refs") => {
            let s = state.lock().unwrap();
            let body = encode_info_refs(&s.refs);
            (200, "OK", body, "application/x-gyt-refs")
        }
        ("POST", "/objects/want") => {
            let wanted = match protocol::parse_wants(body) {
                Ok(w) => w,
                Err(e) => {
                    return (400, "Bad Request", e.to_string().into_bytes(), "text/plain");
                }
            };
            let s = state.lock().unwrap();
            let mut entries: Vec<PackEntry> = Vec::with_capacity(wanted.len());
            for id in &wanted {
                if let Some(bytes) = s.objects.get(id) {
                    entries.push(PackEntry {
                        id: *id,
                        bytes: bytes.clone(),
                    });
                } else {
                    return (
                        404,
                        "Not Found",
                        format!("missing object {id}").into_bytes(),
                        "text/plain",
                    );
                }
            }
            let body = encode_packfile(&entries);
            (200, "OK", body, "application/x-gyt-pack")
        }
        ("POST", "/objects/have") => {
            let entries = match protocol::parse_packfile(body) {
                Ok(e) => e,
                Err(e) => {
                    return (400, "Bad Request", e.to_string().into_bytes(), "text/plain");
                }
            };
            let mut s = state.lock().unwrap();
            for entry in entries {
                // Decode -> hash to derive id (matches client behaviour).
                let raw = match compress::decode(&entry.bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        return (
                            400,
                            "Bad Request",
                            format!("decode: {e}").into_bytes(),
                            "text/plain",
                        );
                    }
                };
                // Sanity-check by re-parsing the raw object header.
                if object::store::parse_raw(&raw).is_err() {
                    return (
                        400,
                        "Bad Request",
                        b"malformed object".to_vec(),
                        "text/plain",
                    );
                }
                let id = hash::hash_bytes(&raw);
                s.objects.insert(id, entry.bytes);
            }
            (200, "OK", Vec::new(), "text/plain")
        }
        ("POST", "/refs/update") => {
            let force = query
                .is_some_and(|q| q.split('&').any(|p| p == "force=1"));
            let updates = match protocol::parse_ref_updates(body) {
                Ok(u) => u,
                Err(e) => {
                    return (400, "Bad Request", e.to_string().into_bytes(), "text/plain");
                }
            };
            let mut s = state.lock().unwrap();
            // Verify ff-only unless force=1.
            if !force {
                for u in &updates {
                    let cur = s.refs.iter().find(|r| r.name == u.name).map(|r| r.id);
                    match (u.old, cur) {
                        (None, None) => {} // create, ok
                        (None, Some(_)) => {
                            return (
                                409,
                                "Conflict",
                                format!("ref {} already exists", u.name).into_bytes(),
                                "text/plain",
                            );
                        }
                        (Some(_), None) => {
                            return (
                                409,
                                "Conflict",
                                format!("ref {} does not exist", u.name).into_bytes(),
                                "text/plain",
                            );
                        }
                        (Some(want_old), Some(actual_old)) => {
                            if want_old != actual_old {
                                return (
                                    409,
                                    "Conflict",
                                    format!("ref {} stale old", u.name).into_bytes(),
                                    "text/plain",
                                );
                            }
                        }
                    }
                }
            }
            for u in &updates {
                if let Some(existing) = s.refs.iter_mut().find(|r| r.name == u.name) {
                    existing.id = u.new;
                } else {
                    s.refs.push(RefEntry {
                        name: u.name.clone(),
                        id: u.new,
                    });
                }
            }
            (200, "OK", Vec::new(), "text/plain")
        }
        _ => (404, "Not Found", b"no route".to_vec(), "text/plain"),
    }
}

fn read_request<R: BufRead>(reader: &mut R) -> std::io::Result<Request> {
    // Read until \r\n\r\n.
    let mut header_buf = Vec::with_capacity(512);
    loop {
        let n_before = header_buf.len();
        let n = reader.read_until(b'\n', &mut header_buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in request",
            ));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() == n_before {
            return Err(std::io::Error::other("no progress"));
        }
        if header_buf.len() > 64 * 1024 {
            return Err(std::io::Error::other("headers too large"));
        }
    }
    let header_str =
        std::str::from_utf8(&header_buf).map_err(|_| std::io::Error::other("non-utf8 headers"))?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| std::io::Error::other("no request line"))?;
    let mut parts = req_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| std::io::Error::other("bad request line"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| std::io::Error::other("bad request line"))?
        .to_string();
    // version ignored

    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(Request {
        method,
        target,
        body,
    })
}

fn write_response<W: Write>(
    w: &mut W,
    status: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    chunked: bool,
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    out.extend_from_slice(b"Connection: close\r\n");
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        // Split body into a couple of chunks if non-empty, to exercise the decoder.
        if !body.is_empty() {
            let mid = body.len() / 2;
            let (a, b) = body.split_at(mid);
            if !a.is_empty() {
                out.extend_from_slice(format!("{:x}\r\n", a.len()).as_bytes());
                out.extend_from_slice(a);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(format!("{:x}\r\n", b.len()).as_bytes());
            out.extend_from_slice(b);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
    }
    w.write_all(&out)?;
    w.flush()?;
    Ok(())
}
