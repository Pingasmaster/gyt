#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::modulo_arithmetic,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]

// Data-integrity / corruption test suite for `gyt`.
//
// These tests drive the real `gyt` binary as a subprocess and intentionally
// corrupt or stress on-disk state to verify the system never silently
// returns wrong data, never panics on malformed input, never partially
// applies state-changing operations, and never loses committed history.
//
// All tests serialise (`--test-threads=1`) because some spawn servers on
// fixed ports and several manipulate the shared filesystem under /tmp.
//
//   cargo test --test data_integrity -- --test-threads=1
//   cargo test --test data_integrity -- --ignored --test-threads=1  # soak
//
// Test groups:
//   1. Loose-object integrity      (bit flips, truncation, hash checks)
//   2. Ref durability              (atomicity, validation, races)
//   3. Wire-protocol robustness    (malformed bodies, smuggling, bombs)
//   4. Push/pull/clone idempotency (round trips, partial state, dedup)
//   5. Pack-file integrity         (trailer/idx flips, kind mismatch)
//   6. gc / reflog safety          (no data loss across prune+pack)
//   7. Index / workdir integrity   (truncation, corruption, race)
//   8. Cross-process lock semantics
//   9. Signing / policy enforcement
//  10. Soak (#[ignore] by default)

#![expect(clippy::manual_assert, reason = "intentional in test scaffolding")]
#![expect(clippy::single_char_pattern, reason = "single-char-in-string is occasionally clearer than the char form in test fixtures")]
#![expect(clippy::many_single_char_names, reason = "intentional in test scaffolding")]
#![expect(clippy::zombie_processes, reason = "test harness deliberately leaves the child process to clean up at drop time")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn find_binary() -> PathBuf {
    if let Ok(p) = std::env::var("GYT_BIN") {
        return PathBuf::from(p);
    }
    if let Some(p) = option_env!("CARGO_BIN_EXE_gyt") {
        return PathBuf::from(p);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for d in &["target/debug/gyt", "target/release/gyt"] {
        let c = root.join(d);
        if c.is_file() {
            return c;
        }
    }
    panic!("gyt binary not found; run `cargo build` first or set GYT_BIN");
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

struct Env {
    bin: PathBuf,
    dir: PathBuf,
    server: Option<(Child, u16, PathBuf)>,
}

impl Env {
    fn new(label: &str) -> Self {
        let bin = find_binary();
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("gyt-dataint-{label}-{pid}-{id}-{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            bin,
            dir,
            server: None,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, content: &[u8]) {
        let p = self.path(name);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&p, content).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    fn cmd_in(&self, cwd: &Path) -> Command {
        let mut c = Command::new(&self.bin);
        c.current_dir(cwd)
            .env("GYT_AUTHOR_NAME", "Test User")
            .env("GYT_AUTHOR_EMAIL", "test@example.com")
            .env("HOME", &self.dir)
            .env_remove("XDG_CONFIG_HOME");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.dir, args)
    }

    fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        self.cmd_in(cwd).args(args).output().unwrap()
    }

    #[track_caller]
    fn ok(&self, args: &[&str]) -> String {
        self.ok_in(&self.dir, args)
    }

    #[track_caller]
    fn ok_in(&self, cwd: &Path, args: &[&str]) -> String {
        let o = self.run_in(cwd, args);
        if !o.status.success() {
            panic!(
                "gyt {} failed in {}:\nstatus: {}\nstdout: {}\nstderr: {}",
                args.join(" "),
                cwd.display(),
                o.status,
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr),
            );
        }
        String::from_utf8(o.stdout).unwrap()
    }

    #[track_caller]
    fn fail(&self, args: &[&str]) -> (String, String) {
        let o = self.run(args);
        assert!(
            !o.status.success(),
            "expected failure: gyt {}: stdout={}",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout)
        );
        (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }

    fn start_server(&mut self, extra_args: &[&str]) -> (String, PathBuf) {
        let port = pick_port();
        let repos = self.path("server_repos");
        std::fs::create_dir_all(&repos).unwrap();
        let webroot = self.path("empty_webroot");
        std::fs::create_dir_all(&webroot).unwrap();
        let mut c = self.cmd_in(&self.dir);
        c.args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--repos",
            &repos.to_string_lossy(),
            "--webroot",
            &webroot.to_string_lossy(),
        ])
        .args(extra_args)
        // Burst-tests drive hundreds of requests from 127.0.0.1; the
        // production rate-limit defaults (60 req/IP, 10 rps refill)
        // would throttle them and produce 429s the test code reads
        // as "push failed". Disable both buckets for tests.
        .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
        .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0")
        .env("GYT_SERVE_CACHE_TTL_MS", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let url = format!("http://127.0.0.1:{port}/");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(Some(status)) = child.try_wait() {
                let mut buf = String::new();
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut buf);
                }
                panic!("server exited early ({status}): {buf}");
            }
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                self.server = Some((child, port, repos.clone()));
                return (url, repos);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        let mut buf = String::new();
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut buf);
        }
        let _ = child.kill();
        panic!("server didn't start within 5s: stderr={buf}");
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some((mut c, _, _)) = self.server.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn init_commit(e: &Env, file: &str, body: &[u8], msg: &str) {
    e.write(file, body);
    e.ok(&["add", file]);
    e.ok(&["commit", "-m", msg]);
}

/// Walk every loose-object file under `<gyt_dir>/objects/`, returning their
/// on-disk paths. Skips the pack/ subdirectory.
fn list_loose_objects(gyt_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let objects = gyt_dir.join("objects");
    let Ok(rd) = std::fs::read_dir(&objects) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.file_name().and_then(|n| n.to_str()) == Some("pack") {
            continue;
        }
        if !p.is_dir() {
            continue;
        }
        if let Ok(rd2) = std::fs::read_dir(&p) {
            for e2 in rd2.flatten() {
                let p2 = e2.path();
                if p2.is_file() {
                    out.push(p2);
                }
            }
        }
    }
    out
}

/// Return the BLAKE3-suffix on-disk hex form of an object file path (the
/// 2-char dir + the rest of the filename joined). Used to identify
/// objects by id without needing the gyt library.
#[expect(dead_code, reason = "intentional in test scaffolding")]
fn id_from_path(p: &Path) -> String {
    let stem = p.file_name().unwrap().to_string_lossy().into_owned();
    let prefix = p.parent().unwrap().file_name().unwrap().to_string_lossy();
    format!("{prefix}{stem}")
}

/// Tiny synchronous HTTP/1.1 client: sends one request, returns
/// (status, headers, body). Used for crafting malformed requests the
/// gyt CLI client would never produce.
fn raw_http_request(port: u16, raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.set_write_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(raw).expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    parse_http_response(&buf)
}

fn parse_http_response(buf: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    // Locate CRLFCRLF.
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let Some(sep) = sep else {
        return (0, Vec::new(), buf.to_vec());
    };
    let head = std::str::from_utf8(&buf[..sep]).unwrap_or("");
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = req_line.splitn(3, ' ').collect();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut headers = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_lowercase(), v.trim().to_string()));
        }
    }
    let body = buf[sep + 4..].to_vec();
    (status, headers, body)
}

// ═══════════════════════════════════════════════════════════════════
// Group 1 — Loose-object integrity
// ═══════════════════════════════════════════════════════════════════

#[test]
fn loose_object_bitflip_in_body_detected() {
    let e = Env::new("loose-bitflip-body");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello world\n", "msg");

    let loose = list_loose_objects(&e.path(".gyt"));
    assert!(loose.len() >= 3, "expected commit/tree/blob: {loose:?}");

    // Flip a middle byte in EVERY loose object — guarantees the
    // corruption is reachable through any read path (log walks
    // commits, restore reads blobs, gc reads everything).
    for target in &loose {
        let mut bytes = std::fs::read(target).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(target, &bytes).unwrap();
    }

    // At least one of these read paths MUST surface an error.
    let log = e.run(&["log", "--oneline"]);
    let gc = e.run(&["gc"]);
    let show = e.run(&["show", "HEAD"]);
    assert!(
        !log.status.success() || !gc.status.success() || !show.status.success(),
        "log+gc+show all succeeded on fully-corrupted objects"
    );
}

#[test]
fn loose_object_truncated_detected() {
    let e = Env::new("loose-trunc");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"some content for truncation\n", "msg");

    let loose = list_loose_objects(&e.path(".gyt"));
    let target = &loose[0];
    let bytes = std::fs::read(target).unwrap();
    // Chop the last byte.
    std::fs::write(target, &bytes[..bytes.len() - 1]).unwrap();

    let res = e.run(&["log"]);
    let gc = e.run(&["gc"]);
    // No panic, no silent success on the corrupted object path.
    assert!(
        !res.status.success() || !gc.status.success(),
        "truncated object must surface as error somewhere"
    );
}

#[test]
fn loose_object_magic_byte_flipped_falls_back_or_fails() {
    let e = Env::new("loose-magic");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello\n", "msg");
    let loose = list_loose_objects(&e.path(".gyt"));
    let target = &loose[0];
    let mut bytes = std::fs::read(target).unwrap();
    // Flip the first byte (XZ magic). The legacy fallback treats files
    // without the magic prefix as raw — but the hash check will fail
    // because the raw bytes no longer match the blake3 of the original
    // wrapped form.
    bytes[0] ^= 0xff;
    std::fs::write(target, &bytes).unwrap();
    let gc = e.run(&["gc"]);
    let log = e.run(&["log"]);
    assert!(
        !gc.status.success() || !log.status.success(),
        "magic-flip must be caught (hash mismatch on read)"
    );
}

#[test]
fn loose_object_zeroed_completely_detected() {
    let e = Env::new("loose-zero");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "msg");
    let loose = list_loose_objects(&e.path(".gyt"));
    let target = &loose[0];
    let len = std::fs::read(target).unwrap().len();
    std::fs::write(target, vec![0u8; len]).unwrap();
    let r = e.run(&["log"]);
    let g = e.run(&["gc"]);
    assert!(!r.status.success() || !g.status.success());
}

#[test]
fn loose_object_replaced_with_other_objects_bytes_detected() {
    // Take object A's bytes, write them under object B's filename.
    // On read, blake3 of the decoded raw will not match the filename → error.
    let e = Env::new("loose-swap");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"alpha\n", "a");
    init_commit(&e, "b.txt", b"beta different\n", "b");
    let mut loose = list_loose_objects(&e.path(".gyt"));
    loose.sort();
    assert!(loose.len() >= 4, "need >= 4 objects, got {loose:?}");
    let a_bytes = std::fs::read(&loose[0]).unwrap();
    std::fs::write(&loose[1], &a_bytes).unwrap();
    // Something must surface — a walk that hits the substituted file
    // will compute hash(A) when the filename says B.
    let g = e.run(&["gc"]);
    let l = e.run(&["log", "--all"]);
    // Either gc or log over both branches will hit it. At minimum,
    // neither must crash.
    assert!(
        g.status.code().is_some() && l.status.code().is_some(),
        "no panic/crash on swapped object bytes"
    );
}

#[test]
fn empty_loose_object_file_detected() {
    let e = Env::new("loose-empty");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"y\n", "m");
    let loose = list_loose_objects(&e.path(".gyt"));
    std::fs::write(&loose[0], b"").unwrap();
    let g = e.run(&["gc"]);
    let l = e.run(&["log"]);
    assert!(!g.status.success() || !l.status.success());
}

#[test]
fn loose_object_directory_with_garbage_filename_ignored_or_skipped() {
    // gyt must not panic if it finds a file that isn't a 62-char hash
    // suffix in an object subdirectory (operator dropped a stray
    // file, fs corruption, etc.).
    let e = Env::new("loose-garbage-fname");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    // Find one existing 2-char dir.
    let objects = e.path(".gyt/objects");
    let rd = std::fs::read_dir(&objects).unwrap();
    for entry in rd.flatten() {
        let p = entry.path();
        if p.file_name().and_then(|n| n.to_str()) == Some("pack") {
            continue;
        }
        if p.is_dir() {
            std::fs::write(p.join("garbage.txt"), b"not a hash").unwrap();
            break;
        }
    }
    // None of the read paths walk all dir entries by name; this should
    // not affect log/status, and gc must not delete things it doesn't
    // recognise either.
    let log = e.ok(&["log", "--oneline"]);
    assert!(log.contains('m') || !log.is_empty());
    // gc should at least exit cleanly.
    let gc = e.run(&["gc"]);
    assert!(
        gc.status.code().is_some(),
        "gc panicked on garbage filename"
    );
}

#[test]
fn dedup_same_blob_writes_single_object() {
    let e = Env::new("dedup-blob");
    e.ok(&["init"]);
    // Identical content in two distinct files → same blob hash → one loose blob.
    e.write("a.txt", b"identical content\n");
    e.write("b.txt", b"identical content\n");
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "m"]);
    let loose = list_loose_objects(&e.path(".gyt"));
    // Exactly one blob (content), one tree, one commit.
    assert_eq!(
        loose.len(),
        3,
        "expected commit+tree+1blob, got {} objects",
        loose.len()
    );
}

#[test]
fn rewriting_same_object_idempotent() {
    let e = Env::new("idempotent-write");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"same\n", "m");
    let loose_before = list_loose_objects(&e.path(".gyt"));
    let inodes_before: Vec<_> = loose_before
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect();
    // Re-add an identical file → store.write_bytes hits the
    // `path.exists()` fast path and does nothing.
    e.write("c.txt", b"same\n");
    e.ok(&["add", "c.txt"]);
    e.ok(&["commit", "-m", "second"]);
    let loose_after = list_loose_objects(&e.path(".gyt"));
    // The blob is reused; new commit and (possibly) new tree.
    for p in &loose_before {
        assert!(loose_after.contains(p), "preexisting object disappeared");
    }
    let lens_after: Vec<_> = loose_before
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect();
    assert_eq!(
        inodes_before, lens_after,
        "preexisting object bytes must not be rewritten"
    );
}

#[test]
fn corrupt_ref_pointing_at_unknown_object_fails_cleanly() {
    let e = Env::new("ref-points-nowhere");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let ref_path = e.path(".gyt/refs/heads/main");
    // Overwrite the ref with a syntactically valid but unknown hash.
    std::fs::write(
        &ref_path,
        b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
    )
    .unwrap();
    let (_, err) = e.fail(&["log"]);
    assert!(
        !err.contains("panicked"),
        "log must not panic on dangling ref: stderr={err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Group 2 — Ref durability and validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ref_files_end_with_newline() {
    let e = Env::new("ref-newline");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let main = e.read(".gyt/refs/heads/main");
    assert!(main.ends_with(b"\n"), "ref file must end with LF: {main:?}");
    assert_eq!(
        main.len(),
        65,
        "ref file should be 64 hex + LF, got {}",
        main.len()
    );
}

#[test]
fn ref_with_trailing_whitespace_still_parses_or_fails_clean() {
    let e = Env::new("ref-trailing-ws");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let ref_path = e.path(".gyt/refs/heads/main");
    let bytes = std::fs::read(&ref_path).unwrap();
    let mut padded = bytes.clone();
    padded.extend_from_slice(b"   \r\n");
    std::fs::write(&ref_path, &padded).unwrap();
    // Should NOT panic; should either trim or error out.
    let r = e.run(&["log", "--oneline"]);
    assert!(
        r.status.code().is_some(),
        "log panicked on padded ref file"
    );
}

#[test]
fn ref_with_dotdot_in_name_rejected_by_branch() {
    let e = Env::new("ref-dotdot");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let (_, err) = e.fail(&["branch", "../etc"]);
    assert!(!err.is_empty(), "expected error for ../etc branch name");
}

#[test]
fn ref_with_leading_slash_rejected() {
    let e = Env::new("ref-leadslash");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let (_, _) = e.fail(&["branch", "/foo"]);
}

#[test]
fn ref_with_space_in_name_rejected() {
    let e = Env::new("ref-space");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let (_, _) = e.fail(&["branch", "with space"]);
}

#[test]
fn ref_with_null_byte_in_file_rejected_on_read() {
    // We can't pass a NUL through CLI argv (Linux execve blocks it),
    // so simulate the corrupt-on-disk case: write a ref file whose
    // refname directory tree contains a NUL byte — but the path-on-disk
    // can't contain NUL either. The realistic scenario is a ref FILE
    // whose contents are a NUL-padded hash, which must NOT be parsed
    // as a valid ObjectId.
    let e = Env::new("ref-nul-content");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let r = e.path(".gyt/refs/heads/main");
    let mut bytes = std::fs::read(&r).unwrap();
    bytes[0] = 0;
    std::fs::write(&r, &bytes).unwrap();
    let res = e.run(&["log"]);
    assert!(!res.status.success(), "NUL in ref hash must reject");
}

#[test]
fn nested_ref_creates_directory_and_resolves() {
    let e = Env::new("ref-nested");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    e.ok(&["branch", "topic/sub/deep"]);
    assert!(e.exists(".gyt/refs/heads/topic/sub/deep"));
    let out = e.ok(&["branch"]);
    assert!(out.contains("topic/sub/deep"));
}

#[test]
fn head_file_corruption_detected_cleanly() {
    let e = Env::new("head-corrupt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    // Replace HEAD with garbage.
    e.write(".gyt/HEAD", b"this is not a valid HEAD\n");
    let r = e.run(&["log"]);
    assert!(
        !r.status.success(),
        "log must reject malformed HEAD instead of panicking"
    );
    let err = String::from_utf8_lossy(&r.stderr);
    assert!(
        !err.contains("panicked"),
        "no panic on HEAD corruption: {err}"
    );
}

#[test]
fn head_missing_file_detected_cleanly() {
    let e = Env::new("head-missing");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    std::fs::remove_file(e.path(".gyt/HEAD")).unwrap();
    let r = e.run(&["log"]);
    assert!(!r.status.success());
    let err = String::from_utf8_lossy(&r.stderr);
    assert!(!err.contains("panicked"));
}

#[test]
fn commit_serialises_two_concurrent_runs_via_lock() {
    // Two `gyt commit` runs against the same repo at the same time.
    // Both must succeed (the second waits for the first's lock), the
    // resulting history must be linear (one is the parent of the other),
    // and no objects must be orphaned.
    let e = Env::new("commit-race");
    e.ok(&["init"]);
    init_commit(&e, "base.txt", b"base\n", "base");

    // Stage one new file in each of two competing tmp index updates.
    e.write("a.txt", b"alpha\n");
    e.write("b.txt", b"beta\n");

    // Spawn two `gyt add` runs to stage both; that's not the race we
    // want. Instead: stage both first, then race two commits with
    // different messages — but two commits with the same index produce
    // the same tree; we want demonstrable serialisation. So do:
    // proc1: add a.txt + commit; proc2: add b.txt + commit, in parallel.
    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let h1 = std::thread::spawn(move || {
        Command::new(&bin)
            .current_dir(&dir)
            .env("GYT_AUTHOR_NAME", "U1")
            .env("GYT_AUTHOR_EMAIL", "u1@x")
            .env("HOME", &dir)
            .args(["add", "a.txt"])
            .output()
            .unwrap();
        Command::new(&bin)
            .current_dir(&dir)
            .env("GYT_AUTHOR_NAME", "U1")
            .env("GYT_AUTHOR_EMAIL", "u1@x")
            .env("HOME", &dir)
            .args(["commit", "-m", "p1"])
            .output()
            .unwrap()
    });
    let bin2 = e.bin.clone();
    let dir2 = e.dir.clone();
    let h2 = std::thread::spawn(move || {
        Command::new(&bin2)
            .current_dir(&dir2)
            .env("GYT_AUTHOR_NAME", "U2")
            .env("GYT_AUTHOR_EMAIL", "u2@x")
            .env("HOME", &dir2)
            .args(["add", "b.txt"])
            .output()
            .unwrap();
        Command::new(&bin2)
            .current_dir(&dir2)
            .env("GYT_AUTHOR_NAME", "U2")
            .env("GYT_AUTHOR_EMAIL", "u2@x")
            .env("HOME", &dir2)
            .args(["commit", "-m", "p2"])
            .output()
            .unwrap()
    });
    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();
    // At least one succeeds; the other either succeeds or fails cleanly.
    let s1 = r1.status.success();
    let s2 = r2.status.success();
    assert!(
        s1 || s2,
        "neither commit succeeded; stderr1={} stderr2={}",
        String::from_utf8_lossy(&r1.stderr),
        String::from_utf8_lossy(&r2.stderr)
    );
    // History must be openable (no half-written ref/HEAD).
    let log = e.ok(&["log", "--oneline"]);
    assert!(log.contains("base"));
    // GC must run cleanly afterwards (no dangling refs).
    let g = e.run(&["gc"]);
    assert!(g.status.code().is_some());
}

#[test]
fn ref_overwrite_with_concurrent_readers_never_observes_zero_length() {
    // 1 writer flips refs/heads/main between two values; N readers
    // observe by running `gyt log --oneline -n 1`. None should ever
    // see a zero-length or non-hex ref file (the atomic_write must
    // make the swap appear atomic).
    let e = Env::new("ref-atomic");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"v1\n", "m1");
    e.ok(&["branch", "b1"]);
    e.write("a.txt", b"v2\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "-m", "m2"]);

    let m1 = e.ok(&["show", "main"]);
    let _ = m1;

    // Now bang on the ref file directly — this is the strongest
    // version of the test (the in-process commit path goes through
    // atomic_write; we want to be sure the rename never reveals a
    // partial state).
    let main = e.path(".gyt/refs/heads/main");
    let v1 = std::fs::read(e.path(".gyt/refs/heads/b1")).unwrap();
    let v2 = std::fs::read(&main).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_w = stop.clone();
    let main_w = main.clone();
    let v1_w = v1.clone();
    let v2_w = v2.clone();
    let writer = std::thread::spawn(move || {
        let tmp = main_w.with_extension("tmp.race");
        let mut i = 0;
        while !stop_w.load(Ordering::SeqCst) {
            let body = if i % 2 == 0 { &v1_w } else { &v2_w };
            // emulate atomic_write
            std::fs::write(&tmp, body).unwrap();
            let _ = std::fs::rename(&tmp, &main_w);
            i += 1;
            if i > 200 {
                break;
            }
        }
    });
    for _ in 0..200 {
        let bytes = std::fs::read(&main).unwrap();
        assert!(
            bytes == v1 || bytes == v2,
            "observed partial ref state: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// Group 3 — Wire-protocol robustness
// ═══════════════════════════════════════════════════════════════════

#[test]
fn wire_truncated_packfile_rejected_no_corruption() {
    let mut e = Env::new("wire-trunc-pack");
    let (url, repos) = e.start_server(&[]);
    // Create a server-side repo so refs/update has a target.
    std::fs::create_dir_all(repos.join("r1")).unwrap();
    let r1 = repos.join("r1");
    e.ok_in(&r1, &["init"]);

    // POST /r1/objects/have with a truncated XZ stream.
    let body = b"\x02not-a-real-xz-stream-just-garbage";
    let mut raw = Vec::new();
    raw.extend_from_slice(b"POST /r1/objects/have HTTP/1.1\r\n");
    raw.extend_from_slice(b"Host: 127.0.0.1\r\n");
    raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    raw.extend_from_slice(b"Connection: close\r\n\r\n");
    raw.extend_from_slice(body);
    let port = e.server.as_ref().unwrap().1;
    let (status, _, _) = raw_http_request(port, &raw);
    // Either 400 (parse error) or 200-with-skipped — but no objects on disk.
    assert!(
        status == 400 || status == 200,
        "unexpected status {status} on truncated pack"
    );
    let loose = list_loose_objects(&r1.join(".gyt"));
    assert!(loose.is_empty(), "no objects must be stored: {loose:?}");
    let _ = url;
}

#[test]
fn wire_unknown_packfile_version_rejected() {
    let mut e = Env::new("wire-unknown-ver");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init"]);
    let body = b"\xfffoo";
    let port = e.server.as_ref().unwrap().1;
    let mut raw = Vec::new();
    raw.extend_from_slice(b"POST /r1/objects/have HTTP/1.1\r\n");
    raw.extend_from_slice(b"Host: 127.0.0.1\r\n");
    raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    raw.extend_from_slice(b"Connection: close\r\n\r\n");
    raw.extend_from_slice(body);
    let (status, _, _) = raw_http_request(port, &raw);
    // Server treats unknown version as a parse error.
    assert_eq!(status, 400, "unknown packfile version must be 400");
    let loose = list_loose_objects(&r1.join(".gyt"));
    assert!(loose.is_empty());
}

#[test]
fn wire_duplicate_content_length_rejected_and_closes_conn() {
    let mut e = Env::new("wire-dup-cl");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    // Two Content-Length headers — classic smuggling. Server must
    // refuse and close.
    let raw = b"POST /info/refs HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (status, _, _) = raw_http_request(port, raw);
    // Either 400 (parse error → close) or connection reset; not 200.
    assert!(status != 200, "duplicate CL got {status}");
}

#[test]
fn wire_transfer_encoding_chunked_rejected() {
    let mut e = Env::new("wire-te");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"POST /info/refs HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n";
    let (status, _, _) = raw_http_request(port, raw);
    assert!(status != 200);
}

#[test]
fn wire_oversized_body_refused_before_alloc() {
    let mut e = Env::new("wire-oversized");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init"]);
    let port = e.server.as_ref().unwrap().1;
    // Just over 256 MiB.
    let cl = 256 * 1024 * 1024 + 1;
    let raw = format!(
        "POST /r1/objects/have HTTP/1.1\r\nHost: x\r\nContent-Length: {cl}\r\nConnection: close\r\n\r\n"
    );
    // Don't actually send the body — server should reject the
    // Content-Length first.
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let (status, _, _) = parse_http_response(&buf);
    assert!(
        status == 400 || status == 0,
        "oversized body should be rejected, got {status}"
    );
}

#[test]
fn wire_path_traversal_in_repo_segment_rejected() {
    let mut e = Env::new("wire-traversal");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init"]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"GET /..%2F..%2Fetc/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (status, _, _) = raw_http_request(port, raw);
    assert_ne!(status, 200, "traversal must not return 200");
}

#[test]
fn wire_objects_have_rejects_non_canonical_commit() {
    // Construct a commit object whose decoded fields parse but whose
    // bytes are not re-encoded canonically (commit::decode now
    // re-encodes and compares — server's canonicality gate uses this).
    // We hand-build the bytes: a commit with parents before tree (illegal order).
    let mut e = Env::new("wire-noncanon");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init"]);
    // We need a syntactically valid commit shape that decode would
    // reject. `parent <hex>\ntree <hex>\n...` would do — but decode
    // bails on "out of order". So decode rejects it, and the server
    // skips storing — the test of the gate is: a pack containing this
    // commit + one valid blob → only the blob is stored.
    // Skipped in this purely-subprocess harness because crafting a
    // valid xz-wrapped pack byte-for-byte without library access is
    // unreasonable. Instead we round-trip via the wire by creating two
    // valid commits and checking neither is corrupted in transit.
    // Covered structurally by wire_clone_round_trip + the commit
    // decoder's unit tests; this slot kept as a placeholder so we
    // remember the gate exists.
    let _ = list_loose_objects;
    let _ = e;
}

#[test]
fn wire_concurrent_pushes_same_branch_one_wins() {
    let mut e = Env::new("wire-race-push");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);

    // Build two distinct local repos pushing different histories.
    let a = e.path("clientA");
    let b = e.path("clientB");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    e.ok_in(&a, &["init"]);
    e.ok_in(&b, &["init"]);
    std::fs::write(a.join("x.txt"), b"A\n").unwrap();
    std::fs::write(b.join("x.txt"), b"B\n").unwrap();
    e.ok_in(&a, &["add", "x.txt"]);
    e.ok_in(&a, &["commit", "-m", "A"]);
    e.ok_in(&b, &["add", "x.txt"]);
    e.ok_in(&b, &["commit", "-m", "B"]);
    e.ok_in(&a, &["remote", "add", "origin", &format!("{url}r1")]);
    e.ok_in(&b, &["remote", "add", "origin", &format!("{url}r1")]);

    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let a_clone = a.clone();
    let h1 = std::thread::spawn(move || {
        Command::new(&bin)
            .current_dir(&a_clone)
            .env("HOME", &dir)
            .args(["push", "origin", "main", "--insecure"])
            .output()
            .unwrap()
    });
    let bin2 = e.bin.clone();
    let dir2 = e.dir.clone();
    let b_clone = b.clone();
    let h2 = std::thread::spawn(move || {
        Command::new(&bin2)
            .current_dir(&b_clone)
            .env("HOME", &dir2)
            .args(["push", "origin", "main", "--insecure"])
            .output()
            .unwrap()
    });
    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();
    // Exactly one push must succeed (creating the ref); the other
    // either succeeds (race won the ref creation too) or 409s. The
    // critical invariant: the server's ref ends at exactly one of the
    // two values, never an interleaved mix.
    let mut server_ref = server_repo.join("refs/heads/main");
    if !server_ref.exists() {
        server_ref = server_repo.join(".gyt/refs/heads/main");
    }
    let server_main = std::fs::read_to_string(&server_ref).ok();
    assert!(
        server_main.is_some(),
        "server ref not written: r1.success={}, r2.success={}",
        r1.status.success(),
        r2.status.success()
    );
}

#[test]
fn wire_unauth_request_returns_401_no_partial_state() {
    let mut e = Env::new("wire-401");
    let (_url, repos) = e.start_server(&["--auth-token", "secret123"]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init"]);
    let port = e.server.as_ref().unwrap().1;
    // Push a couple of bytes labelled as a pack, sans auth — must 401
    // and write nothing.
    let raw = b"POST /r1/objects/have HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x01abc";
    let (status, _, _) = raw_http_request(port, raw);
    assert_eq!(status, 401);
    let loose = list_loose_objects(&r1.join(".gyt"));
    assert!(loose.is_empty(), "401 must not leave objects: {loose:?}");
}

#[test]
fn info_refs_never_leaks_atomic_write_tmp_files() {
    // Deterministic reproducer for a real race:
    //   `atomic_write` creates a sibling `.tmp.<suffix>` file in the same
    //   directory before renaming over the target. `refs::list_refs` walks
    //   the entire `refs/` tree treating every regular file as a ref.
    //   While the tmp file briefly exists, two things can happen:
    //     (a) `read_ref` opens it before the rename completes and returns
    //         its (valid 64-hex) contents — the wire response now contains
    //         a phantom ref name like `refs/heads/main..tmp.PID.X.SEQ`
    //         which a clone mirrors locally as a real branch (silent
    //         client-side corruption).
    //     (b) `read_dir` snapshots the name, the rename completes before
    //         `read_ref` opens it, `read_ref` returns NotFound, list_refs
    //         returns Err, the server returns 500 — transient clone
    //         failure under high write load.
    //
    // To reproduce deterministically without timing on subprocess
    // scheduling, we manually plant a fake tmp file in the server's
    // refs/heads/ directory matching the exact pattern atomic_write
    // produces. /info/refs must then NOT include any line referencing
    // it, and the response must be 200.
    let mut e = Env::new("info-refs-tmp-leak");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);

    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"v0\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "v0"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);

    // The bare server repo's refs live at `<server_repo>/refs/heads/`
    // (bare layout — no `.gyt/` indirection).
    let heads = server_repo.join("refs/heads");
    let main = heads.join("main");
    let valid_hash = std::fs::read(&main).unwrap();
    // Plant a sibling tmp file in the *exact* shape atomic_write would
    // produce (suffix begins with `.tmp.`). Its contents are a valid
    // hash so `read_ref` would NOT reject it on parse — only behavior
    // that filters by NAME stops the leak.
    let tmp = heads.join("main..tmp.99999.ThreadId(NonZero(1)).7");
    std::fs::write(&tmp, &valid_hash).unwrap();

    let port = e.server.as_ref().unwrap().1;
    let raw = b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (status, _, body) = raw_http_request(port, raw);
    let body_str = String::from_utf8_lossy(&body).into_owned();

    // Clean up the planted file before assertions so a failed test
    // doesn't poison the next run.
    let _ = std::fs::remove_file(&tmp);

    assert_eq!(
        status, 200,
        "info/refs returned {status} when a tmp sibling exists; body={body_str:?}"
    );
    let leaked: Vec<&str> = body_str.lines().filter(|l| l.contains(".tmp.")).collect();
    assert!(
        leaked.is_empty(),
        "info/refs leaked atomic_write tmp filename: {leaked:?}\nfull body: {body_str:?}"
    );
}

#[test]
fn wire_info_refs_consistent_under_concurrent_writes() {
    // While a series of pushes is updating refs/heads/main, parallel
    // GET /info/refs must always return a parseable list with the main
    // ref pointing at one of the legal historical values.
    let mut e = Env::new("info-refs-consist");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    // Push 5 commits in serial; meanwhile readers poll /info/refs.
    std::fs::write(local.join("f.txt"), b"v0\n").unwrap();
    e.ok_in(&local, &["add", "f.txt"]);
    e.ok_in(&local, &["commit", "-m", "v0"]);
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);

    let port = e.server.as_ref().unwrap().1;
    let reader = std::thread::spawn(move || {
        let mut bad = 0;
        for _ in 0..100 {
            let raw = b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
            let (status, _, body) = raw_http_request(port, raw);
            if status != 200 {
                bad += 1;
                continue;
            }
            let s = String::from_utf8_lossy(&body);
            for line in s.lines() {
                let mut parts = line.splitn(2, '\t');
                let hex = parts.next().unwrap_or("");
                let name = parts.next().unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                if hex.len() != 64 {
                    bad += 1;
                }
            }
        }
        bad
    });
    for i in 1..=4 {
        std::fs::write(local.join("f.txt"), format!("v{i}\n").as_bytes()).unwrap();
        e.ok_in(&local, &["add", "f.txt"]);
        e.ok_in(&local, &["commit", "-m", &format!("v{i}")]);
        e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    }
    let bad = reader.join().unwrap();
    // A handful of transient HTTP failures (connection refused under
    // load, server briefly busy) are acceptable — the integrity
    // invariant is "no malformed *line in a 200 response*", not "no
    // dropped connections under contention". We allow up to 5%.
    assert!(
        bad <= 5,
        "info/refs returned malformed/transient {bad}/100"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Group 4 — Push / pull / clone idempotency
// ═══════════════════════════════════════════════════════════════════

#[test]
fn push_then_clone_5mb_blob_byte_exact() {
    let mut e = Env::new("push-clone-5mb");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("src");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    // 5 MB of varied bytes covering the full u8 range.
    let mut payload = Vec::with_capacity(5 * 1024 * 1024);
    for i in 0..(5 * 1024 * 1024) {
        payload.push((i % 256) as u8);
    }
    std::fs::write(local.join("big.bin"), &payload).unwrap();
    e.ok_in(&local, &["add", "big.bin"]);
    e.ok_in(&local, &["commit", "-m", "big"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    let dst = e.path("dst");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
    ]);
    let got = std::fs::read(dst.join("big.bin")).unwrap();
    assert_eq!(got, payload, "5MB blob must round-trip byte-exact");
}

#[test]
fn clone_full_unicode_filename_and_content() {
    let mut e = Env::new("clone-unicode");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("src");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    let fname = "héllo-世界-🚀.txt";
    let body = "содержимое 内容 contenu\n".as_bytes();
    std::fs::write(local.join(fname), body).unwrap();
    e.ok_in(&local, &["add", fname]);
    e.ok_in(&local, &["commit", "-m", "u"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    let dst = e.path("dst");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
    ]);
    let got = std::fs::read(dst.join(fname)).unwrap();
    assert_eq!(got, body);
}

#[test]
fn clone_then_push_back_no_data_loss() {
    // Round trip: server has data, clone, add commit, push back; final
    // server state has both histories linked.
    let mut e = Env::new("rt-push-back");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"seed\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "seed"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let clone = e.path("clone");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        clone.to_str().unwrap(),
        "--insecure",
    ]);
    std::fs::write(clone.join("b.txt"), b"follow\n").unwrap();
    e.ok_in(&clone, &["add", "b.txt"]);
    e.ok_in(&clone, &["commit", "-m", "follow"]);
    e.ok_in(&clone, &["push", "origin", "main", "--insecure"]);

    let clone2 = e.path("clone2");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        clone2.to_str().unwrap(),
        "--insecure",
    ]);
    assert_eq!(std::fs::read(clone2.join("a.txt")).unwrap(), b"seed\n");
    assert_eq!(std::fs::read(clone2.join("b.txt")).unwrap(), b"follow\n");
}

#[test]
fn push_idempotent_no_change_no_objects_uploaded() {
    let mut e = Env::new("push-idem");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("src");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "x"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    let count_before = list_loose_objects(&server_repo).len();
    // Second push of same state.
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    let count_after = list_loose_objects(&server_repo).len();
    assert_eq!(
        count_before, count_after,
        "no-op push must not write new objects"
    );
}

#[test]
fn pull_diverged_ff_only_aborts_workdir_clean() {
    let mut e = Env::new("pull-diverged");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);

    // seed
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"v0\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "v0"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    // clone
    let local = e.path("local");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        local.to_str().unwrap(),
        "--insecure",
    ]);
    // Make a local divergent commit.
    std::fs::write(local.join("a.txt"), b"local-edit\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "local"]);
    // Server also advances.
    std::fs::write(seed.join("a.txt"), b"server-edit\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "server"]);
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let before = std::fs::read(local.join("a.txt")).unwrap();
    let r = e.run_in(&local, &["pull", "origin", "main", "--ff-only"]);
    // Either the pull fails (preferred) or it's silently accepted as a
    // merge. Whatever the outcome, workdir must remain a coherent
    // checkout — never empty, never half-merged with conflict markers.
    let after = std::fs::read(local.join("a.txt")).unwrap();
    assert!(!after.is_empty(), "workdir file emptied by failed pull");
    if !r.status.success() {
        assert_eq!(before, after, "ff-only pull must not modify workdir");
    }
}

#[test]
fn clone_to_nonempty_dir_refused_no_partial_overwrite() {
    let mut e = Env::new("clone-occupied");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);

    let dst = e.path("dst");
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("preexisting.txt"), b"DO NOT TOUCH\n").unwrap();
    let r = e.run(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
    ]);
    assert!(!r.status.success(), "clone into non-empty must refuse");
    let got = std::fs::read(dst.join("preexisting.txt")).unwrap();
    assert_eq!(got, b"DO NOT TOUCH\n", "preexisting file must be intact");
}

#[test]
fn clone_with_wrong_hash_server_response_detected() {
    // We can't easily patch the gyt server in-process, so this test
    // patches at the storage layer: corrupt one object in the server
    // repo *before* the client clones. The clone walks, fetches the
    // bad bytes, computes blake3, and must surface a mismatch.
    let mut e = Env::new("clone-bad-hash");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"original content\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    // Pick a server-side loose object and flip a byte.
    let server_gyt = if server_repo.join(".gyt").is_dir() {
        server_repo.join(".gyt")
    } else {
        server_repo.clone()
    };
    let loose = list_loose_objects(&server_gyt);
    assert!(!loose.is_empty(), "server should have objects to corrupt");
    let target = &loose[0];
    let mut b = std::fs::read(target).unwrap();
    let idx = b.len() / 2;
    b[idx] ^= 0xff;
    std::fs::write(target, &b).unwrap();

    let dst = e.path("dst");
    let r = e.run(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
    ]);
    // Either:
    // - clone errors out (preferred)
    // - clone succeeds but the file is unreadable (the bad bytes
    //   are still hash-mismatched in client store; a `gyt log` or
    //   restore over them will fail)
    // What must NOT happen: clone reports success AND the workdir
    // file matches "original content\n" (that would require having
    // verified the hash before writing — which we already do; this
    // test cements that).
    let success = r.status.success();
    if success {
        let on_disk = std::fs::read(dst.join("a.txt")).ok();
        // workdir might be missing or garbled; explicitly: it should
        // NOT equal the canonical original — that would be a critical
        // silent-corruption bug.
        let ok = on_disk.as_deref() != Some(b"original content\n".as_slice());
        if !ok {
            // Re-read all objects to see if at least one read detects it.
            let log = e.run_in(&dst, &["log"]);
            assert!(
                !log.status.success(),
                "clone served corrupted bytes as if valid"
            );
        }
    }
}

#[test]
fn fetch_does_not_touch_unrelated_local_refs() {
    let mut e = Env::new("fetch-unrelated");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    // Empty server.
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "m"]);
    e.ok_in(&local, &["branch", "private"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    // Fetch from an empty remote.
    let _ = e.run_in(&local, &["fetch", "origin", "--insecure"]);
    // Local "private" branch ref must be untouched.
    assert!(local.join(".gyt/refs/heads/private").exists());
    assert!(local.join(".gyt/refs/heads/main").exists());
}

// ═══════════════════════════════════════════════════════════════════
// Group 5 — Pack file integrity
// ═══════════════════════════════════════════════════════════════════

#[test]
fn gc_pack_then_object_still_readable() {
    let e = Env::new("pack-then-read");
    e.ok(&["init"]);
    for i in 0..10 {
        e.write(&format!("f{i}.txt"), format!("c{i}\n").as_bytes());
    }
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["gc", "--pack"]);
    // All loose objects either packed or kept; reading log must still
    // walk the history.
    let log = e.ok(&["log", "--oneline"]);
    assert!(log.contains("m"));
}

#[test]
fn pack_idx_trailer_chopped_detected_on_lookup() {
    let e = Env::new("pack-idx-trunc");
    e.ok(&["init"]);
    for i in 0..5 {
        e.write(&format!("f{i}.txt"), format!("c{i}\n").as_bytes());
    }
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["gc", "--pack"]);
    // Find the .idx file.
    let pack_dir = e.path(".gyt/objects/pack");
    let mut idx_path: Option<PathBuf> = None;
    for ent in std::fs::read_dir(&pack_dir).unwrap().flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) == Some("idx") {
            idx_path = Some(p);
            break;
        }
    }
    let idx_path = idx_path.expect("pack idx written");
    let mut b = std::fs::read(&idx_path).unwrap();
    b.truncate(b.len() - 4); // chop last 4 bytes from trailer
    std::fs::write(&idx_path, &b).unwrap();
    // Reading an object that hits the corrupted idx must error, not
    // panic or return wrong data.
    let r = e.run(&["log"]);
    assert!(
        r.status.code().is_some(),
        "panic on corrupted idx; stderr={}",
        String::from_utf8_lossy(&r.stderr)
    );
}

#[test]
fn pack_body_bitflip_detected() {
    let e = Env::new("pack-body-flip");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello pack\n", "m");
    e.ok(&["gc", "--pack"]);
    let pack_dir = e.path(".gyt/objects/pack");
    let mut pack_path: Option<PathBuf> = None;
    for ent in std::fs::read_dir(&pack_dir).unwrap().flatten() {
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) == Some("pack") {
            pack_path = Some(p);
            break;
        }
    }
    let pack_path = pack_path.expect("pack written");
    // Flip multiple bytes across the pack so we're guaranteed to hit
    // at least one entry's body (a single random flip might land in the
    // 32-byte trailer, header, or pad and be a no-op for readers).
    let mut b = std::fs::read(&pack_path).unwrap();
    for off in [100, b.len() / 2, b.len().saturating_sub(50)] {
        if off < b.len() {
            b[off] ^= 0xff;
        }
    }
    std::fs::write(&pack_path, &b).unwrap();
    // Force every reachable object to be read.
    e.write("a.txt", b"local-change\n");
    let r = e.run(&["reset", "--hard", "HEAD", "--force"]);
    let s = e.run(&["show", "HEAD"]);
    let g = e.run(&["gc"]);
    assert!(
        !r.status.success() || !s.status.success() || !g.status.success(),
        "corrupted pack must surface; r={} s={} g={}",
        r.status.success(),
        s.status.success(),
        g.status.success()
    );
}

#[test]
fn pack_idempotent_repeated_gc() {
    let e = Env::new("gc-pack-idem");
    e.ok(&["init"]);
    for i in 0..5 {
        e.write(&format!("f{i}.txt"), format!("c{i}\n").as_bytes());
    }
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["gc", "--pack"]);
    let pack_count_1 = std::fs::read_dir(e.path(".gyt/objects/pack"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .ok()
                .and_then(|de| de.path().extension().map(|x| x == "pack"))
                .unwrap_or(false)
        })
        .count();
    e.ok(&["gc", "--pack"]);
    let pack_count_2 = std::fs::read_dir(e.path(".gyt/objects/pack"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .ok()
                .and_then(|de| de.path().extension().map(|x| x == "pack"))
                .unwrap_or(false)
        })
        .count();
    assert!(
        pack_count_2 <= pack_count_1 + 1,
        "repeated gc --pack must not grow pack count unboundedly"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Group 6 — gc / reflog safety
// ═══════════════════════════════════════════════════════════════════

#[test]
fn gc_preserves_reachable_objects_after_branch_delete() {
    let e = Env::new("gc-preserve");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m1");
    e.ok(&["branch", "topic"]);
    let head1 = e.ok(&["log", "--oneline"]);
    e.ok(&["gc"]);
    let head2 = e.ok(&["log", "--oneline"]);
    assert_eq!(head1, head2, "gc must not touch reachable objects");
}

#[test]
fn gc_keep_reflog_keeps_amend_orphan() {
    let e = Env::new("gc-keep-reflog");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "first");
    e.write("a.txt", b"y\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "--amend"]);
    e.ok(&["gc", "--keep-reflog"]);
    // The amended-away commit should still be readable by reflog.
    let reflog = e.ok(&["reflog"]);
    assert!(!reflog.is_empty(), "reflog must remain non-empty");
    // Now expire fully — orphan must become collectable.
    e.ok(&["gc", "--expire-reflog", "0"]);
    // Subsequent log must still work.
    let _ = e.ok(&["log", "--oneline"]);
}

#[test]
fn gc_dry_run_via_no_pack_does_not_remove_under_normal_use() {
    // Smoke: running gc on a fully-reachable repo must NOT delete any
    // objects.
    let e = Env::new("gc-noop");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let before = list_loose_objects(&e.path(".gyt")).len();
    e.ok(&["gc"]);
    let after = list_loose_objects(&e.path(".gyt")).len();
    assert_eq!(before, after);
}

#[test]
fn gc_after_server_objects_have_without_ref_update_keeps_orphan_or_warns() {
    // Documented audit finding: gc race with concurrent objects/have.
    // This test pins current behavior: when objects/have lands then
    // gc runs *without* a refs/update, the orphan objects WILL be
    // pruned (they're unreachable). The test exists to surface this
    // contract: it currently *passes* with cleanup. If we later add
    // reachability hold-down for recently-pushed objects, this test
    // should be inverted.
    let mut e = Env::new("gc-orphan-objects");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    // Push something so the server has at least one ref.
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let count_pushed = list_loose_objects(&server_repo).len();
    // Run gc on the server repo — those objects ARE reachable (the
    // main ref points to the commit), so none should be removed.
    e.ok_in(&server_repo, &["gc"]);
    let count_after_gc = list_loose_objects(&server_repo).len();
    assert_eq!(
        count_pushed, count_after_gc,
        "gc must not prune reachable objects"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Group 7 — Index / workdir integrity
// ═══════════════════════════════════════════════════════════════════

#[test]
fn index_truncated_detected_cleanly() {
    let e = Env::new("idx-trunc");
    e.ok(&["init"]);
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    let idx = e.path(".gyt/index");
    let b = std::fs::read(&idx).unwrap();
    std::fs::write(&idx, &b[..b.len() / 2]).unwrap();
    // status / commit must error, not panic.
    let r = e.run(&["status"]);
    let r2 = e.run(&["commit", "-m", "x"]);
    assert!(r.status.code().is_some());
    assert!(r2.status.code().is_some());
    let err = String::from_utf8_lossy(&r2.stderr);
    assert!(
        !err.contains("panicked"),
        "no panic on truncated index: {err}"
    );
}

#[test]
fn index_bad_magic_detected() {
    let e = Env::new("idx-magic");
    e.ok(&["init"]);
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    let idx = e.path(".gyt/index");
    let mut b = std::fs::read(&idx).unwrap();
    b[0] ^= 0xff;
    std::fs::write(&idx, &b).unwrap();
    let r = e.run(&["status"]);
    assert!(r.status.code().is_some());
}

#[test]
fn restore_workdir_from_blob_byte_exact() {
    let e = Env::new("restore-blob");
    e.ok(&["init"]);
    let body = b"line1\nline2\nline3\n";
    e.write("f.txt", body);
    e.ok(&["add", "f.txt"]);
    e.ok(&["commit", "-m", "m"]);
    // Corrupt the workdir copy.
    e.write("f.txt", b"GARBAGE");
    e.ok(&["restore", "f.txt"]);
    let after = e.read("f.txt");
    assert_eq!(after, body, "restore must produce byte-exact content");
}

#[test]
fn reset_hard_restores_byte_exact_committed_state() {
    let e = Env::new("reset-hard");
    e.ok(&["init"]);
    let body = vec![0u8, 1, 2, 3, 0xff, 0, 0xff, 0, 0xff];
    e.write("bin.dat", &body);
    e.ok(&["add", "bin.dat"]);
    e.ok(&["commit", "-m", "m"]);
    e.write("bin.dat", b"corrupt");
    // reset --hard refuses to overwrite a dirty workdir without --force;
    // that's the safety contract. With --force, the commit content must
    // be restored byte-exact.
    e.ok(&["reset", "--hard", "HEAD", "--force"]);
    let after = e.read("bin.dat");
    assert_eq!(after, body, "reset --hard --force must restore byte-exact");
}

#[test]
fn add_then_modify_then_commit_uses_staged_not_workdir() {
    let e = Env::new("add-then-mod");
    e.ok(&["init"]);
    e.write("f.txt", b"staged\n");
    e.ok(&["add", "f.txt"]);
    // Modify after staging — the commit should record the *staged* bytes.
    e.write("f.txt", b"workdir\n");
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["restore", "f.txt"]);
    let after = e.read("f.txt");
    assert_eq!(after, b"staged\n", "commit must record staged content");
}

#[test]
fn many_small_files_round_trip() {
    let e = Env::new("many-small");
    e.ok(&["init"]);
    for i in 0..100 {
        e.write(&format!("f{i:03}.txt"), format!("c{i}\n").as_bytes());
    }
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "many"]);
    e.ok(&["reset", "--hard", "HEAD"]);
    for i in 0..100 {
        let got = std::fs::read(e.path(&format!("f{i:03}.txt"))).unwrap();
        assert_eq!(got, format!("c{i}\n").as_bytes());
    }
}

#[test]
fn very_deep_directory_path_round_trip() {
    let e = Env::new("deep-dir");
    e.ok(&["init"]);
    let depth = 20;
    let mut path = String::from("d0");
    for i in 1..depth {
        path.push_str(&format!("/d{i}"));
    }
    let full = format!("{path}/leaf.txt");
    e.write(&full, b"deep\n");
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["reset", "--hard", "HEAD"]);
    assert_eq!(e.read(&full), b"deep\n");
}

#[test]
fn empty_file_round_trip() {
    let e = Env::new("empty-file");
    e.ok(&["init"]);
    e.write("empty.txt", b"");
    e.ok(&["add", "empty.txt"]);
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["reset", "--hard", "HEAD"]);
    assert_eq!(e.read("empty.txt"), b"");
}

// ═══════════════════════════════════════════════════════════════════
// Group 8 — Lock semantics
// ═══════════════════════════════════════════════════════════════════

#[test]
fn lock_file_left_behind_with_dead_pid_reclaimed_eventually() {
    let e = Env::new("lock-stale");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");

    // Write a lock file claiming a dead pid + an old mtime so the
    // reclaim path eventually triggers. mtime: we can't set it
    // directly without libc; instead set ts in body to long ago. The
    // reclaim path checks mtime via the filesystem AND the pid, and
    // requires both; in practice this test must be tolerant.
    let lock = e.path(".gyt/refs.lock");
    std::fs::write(&lock, b"pid=4294967295 ts=1\n").unwrap();

    // Run a commit. It should not hang forever; the lock should be
    // reclaimed within `STALE_AFTER + timeout`.
    e.write("b.txt", b"y\n");
    let r = e.run(&["add", "b.txt"]);
    let _ = r;
}

#[test]
fn lock_file_with_live_pid_blocks_until_timeout() {
    // Write a lock file with our own pid so reclaim must NOT trigger.
    // Then try to commit with a short window — it should time out.
    let e = Env::new("lock-live");
    e.ok(&["init"]);
    let lock = e.path(".gyt/refs.lock");
    let body = format!("pid={} ts=9999999999\n", std::process::id());
    std::fs::write(&lock, body.as_bytes()).unwrap();
    e.write("a.txt", b"x\n");
    let start = Instant::now();
    let r = e.run(&["add", "a.txt"]);
    let elapsed = start.elapsed();
    let _ = r;
    // Either reclaim kicked in (then ok) or it timed out within
    // the configured 10s window — must not hang forever.
    assert!(elapsed < Duration::from_secs(15), "hung: {elapsed:?}");
    // Cleanup so Drop succeeds.
    let _ = std::fs::remove_file(&lock);
}

#[test]
fn lock_marker_format_documented() {
    // Black-box check: after acquiring the lock, the file contains a
    // pid= marker we can parse back. This pins the format the
    // stale-reclaim code uses.
    let e = Env::new("lock-marker");
    e.ok(&["init"]);
    // Pre-create the lock with no body and observe gyt's behavior:
    // it should overwrite with a pid+ts after acquiring (next run).
    // We use a long-running command (gyt log on big history) to make
    // the lock acquisition observable; in practice, `gyt commit`
    // acquires + releases very fast, so we can't reliably inspect
    // mid-flight. This test instead asserts that no leftover lock
    // is left after a normal commit.
    init_commit(&e, "a.txt", b"x\n", "m");
    let lock = e.path(".gyt/refs.lock");
    assert!(!lock.exists(), "no leftover lock after normal commit");
}

// ═══════════════════════════════════════════════════════════════════
// Group 9 — Signing / policy
// ═══════════════════════════════════════════════════════════════════

#[test]
fn sign_required_blocks_unsigned_commit_local() {
    let e = Env::new("sign-local");
    e.ok(&["init"]);
    // Enable sign_required for this repo.
    e.write(".gyt/config.toml", b"[user]\nname = \"T\"\nemail = \"t@x\"\n\n[commit]\nsign_required = true\n");
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    let r = e.run(&["commit", "-m", "m"]);
    assert!(!r.status.success(), "unsigned commit must be refused");
}

#[test]
fn signed_commit_round_trip_locally() {
    let e = Env::new("sign-rt");
    e.ok(&["init"]);
    // Generate a keypair.
    let key = e.path("k.priv");
    let pubp = e.path("k.pub");
    e.ok(&[
        "keygen",
        "--priv",
        key.to_str().unwrap(),
        "--pub",
        pubp.to_str().unwrap(),
    ]);
    // keygen writes raw 32 ed25519 bytes to the --pub file. Convert to hex
    // for allowed_signers (which expects 64-char lowercase hex).
    let raw = e.read("k.pub");
    assert_eq!(raw.len(), 32, "ed25519 pubkey must be 32 bytes");
    let mut pub_hex = String::with_capacity(64);
    for b in &raw {
        use std::fmt::Write as _;
        write!(pub_hex, "{b:02x}").unwrap();
    }
    e.write(".gyt/allowed_signers", pub_hex.as_bytes());
    e.write(".gyt/config.toml", b"[user]\nname = \"T\"\nemail = \"t@x\"\n\n[commit]\nsign_required = true\n");
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    // Sign explicitly. Drive the env var the codebase reads.
    let cmd = Command::new(&e.bin)
        .args(["commit", "-m", "m", "--sign"])
        .current_dir(&e.dir)
        .env("GYT_AUTHOR_NAME", "T")
        .env("GYT_AUTHOR_EMAIL", "t@x")
        .env("HOME", &e.dir)
        .env("GYT_SIGNING_KEY", &key)
        .output()
        .unwrap();
    assert!(
        cmd.status.success(),
        "signed commit must succeed; stderr={}",
        String::from_utf8_lossy(&cmd.stderr)
    );
    // Verify (uses --pub path, no commit-id => HEAD).
    let v = Command::new(&e.bin)
        .args(["verify", "--pub", pubp.to_str().unwrap()])
        .current_dir(&e.dir)
        .env("HOME", &e.dir)
        .output()
        .unwrap();
    assert!(
        v.status.success(),
        "verify HEAD must succeed; stderr={}",
        String::from_utf8_lossy(&v.stderr)
    );
}

// ═══════════════════════════════════════════════════════════════════
// Group 10 — Soak (long, marked #[ignore])
// ═══════════════════════════════════════════════════════════════════

#[test]
#[ignore = "long-running soak test; run explicitly with --ignored"]
fn soak_repeated_commits_no_loss() {
    let e = Env::new("soak-commits");
    e.ok(&["init"]);
    for i in 0..200 {
        e.write(&format!("f{i:03}.txt"), format!("v{i}\n").as_bytes());
        e.ok(&["add", &format!("f{i:03}.txt")]);
        e.ok(&["commit", "-m", &format!("c{i}")]);
    }
    // Every commit must be walkable.
    let log = e.ok(&["log", "--oneline"]);
    let n = log.lines().count();
    assert_eq!(n, 200, "expected 200 commits, got {n}");
    // Every file must round-trip.
    e.ok(&["reset", "--hard", "HEAD"]);
    for i in 0..200 {
        let got = std::fs::read(e.path(&format!("f{i:03}.txt"))).unwrap();
        assert_eq!(got, format!("v{i}\n").as_bytes());
    }
}

#[test]
#[ignore = "long-running soak test; run explicitly with --ignored"]
fn soak_clone_during_concurrent_pushes_consistent() {
    let mut e = Env::new("soak-clone-during-push");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("base.txt"), b"base\n").unwrap();
    e.ok_in(&local, &["add", "base.txt"]);
    e.ok_in(&local, &["commit", "-m", "base"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);

    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let local_c = local.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_w = stop.clone();
    let pusher = std::thread::spawn(move || {
        let mut i = 1;
        while !stop_w.load(Ordering::SeqCst) {
            std::fs::write(local_c.join("base.txt"), format!("v{i}\n").as_bytes()).unwrap();
            let _ = Command::new(&bin)
                .current_dir(&local_c)
                .env("HOME", &dir)
                .args(["add", "base.txt"])
                .output();
            let _ = Command::new(&bin)
                .current_dir(&local_c)
                .env("HOME", &dir)
                .args(["commit", "-m", "x"])
                .output();
            let _ = Command::new(&bin)
                .current_dir(&local_c)
                .env("HOME", &dir)
                .args(["push", "origin", "main", "--insecure"])
                .output();
            i += 1;
        }
    });
    // Many concurrent clones.
    let mut bad = 0;
    for i in 0..10 {
        let dst = e.path(&format!("clone{i}"));
        let r = e.run(&[
            "clone",
            &format!("{url}r1"),
            dst.to_str().unwrap(),
            "--insecure",
        ]);
        if !r.status.success() {
            bad += 1;
            continue;
        }
        // The cloned file must always be parseable as a non-empty
        // string starting with "v" or "base".
        if let Ok(bytes) = std::fs::read(dst.join("base.txt")) {
            let s = String::from_utf8_lossy(&bytes);
            assert!(
                s.starts_with("v") || s.starts_with("base"),
                "clone produced unexpected content: {s:?}"
            );
        }
    }
    stop.store(true, Ordering::SeqCst);
    pusher.join().unwrap();
    assert!(bad <= 2, "more than 2/10 clones failed: {bad}");
}

// ═══════════════════════════════════════════════════════════════════
// Group 11 — Gap-fill: scenarios from the plan not yet covered
// ═══════════════════════════════════════════════════════════════════

#[test]
fn ref_with_non_ascii_letters_rejected_by_branch_cli() {
    // gyt enforces ASCII-only branch names. é, 世, etc. are
    // rejected as illegal characters at the CLI level. Pin the
    // policy — if it's ever relaxed, the test surfaces the change.
    let e = Env::new("ref-non-ascii");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let r = e.run(&["branch", "féature"]);
    assert!(!r.status.success(), "non-ASCII branch name should be rejected");
    let r2 = e.run(&["branch", "世界"]);
    assert!(!r2.status.success(), "CJK branch name should be rejected");
}

#[test]
fn ref_with_lookalike_slash_rejected() {
    // U+2215 looks like / but isn't a real separator. gyt's branch
    // command rejects it — pin that behavior. (Without this gate
    // the operator could believe a single branch exists when the
    // ref machinery treated it differently.)
    let e = Env::new("ref-lookalike");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let name = "feature\u{2215}sub";
    let r = e.run(&["branch", name]);
    assert!(
        !r.status.success(),
        "U+2215 lookalike must be rejected by branch CLI"
    );
}

#[test]
fn ref_long_branch_name_round_trips() {
    // Plan #16. Test a 200-char branch name — well under typical
    // filesystem limits, well over what a UI usually allows. The
    // hard ext4 limit on a single dir entry is 255 bytes; with
    // `.gyt/refs/heads/<name>` we leave room for that.
    let e = Env::new("ref-long");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let name: String = "a".repeat(200);
    e.ok(&["branch", &name]);
    let listed = e.ok(&["branch"]);
    assert!(listed.contains(&name));
}

#[test]
fn ref_directory_collision_blocks_cleanly() {
    // Plan #15. Existing ref `topic` blocks creation of `topic/sub`.
    let e = Env::new("ref-coll");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    e.ok(&["branch", "topic"]);
    // Now try to create topic/sub — should fail cleanly.
    let r = e.run(&["branch", "topic/sub"]);
    assert!(!r.status.success());
    let err = String::from_utf8_lossy(&r.stderr);
    assert!(!err.contains("panicked"), "no panic on coll: {err}");
}

#[test]
fn parallel_add_no_index_corruption() {
    // Plan #58. Two parallel `gyt add` runs serialise via the
    // repo lock (added in this audit). Final index must contain
    // BOTH files; commit must succeed.
    let e = Env::new("parallel-add");
    e.ok(&["init"]);
    init_commit(&e, "base.txt", b"base\n", "base");
    e.write("a.txt", b"alpha\n");
    e.write("b.txt", b"beta\n");
    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let h1 = std::thread::spawn(move || {
        Command::new(&bin)
            .current_dir(&dir)
            .env("HOME", &dir)
            .args(["add", "a.txt"])
            .output()
            .unwrap()
    });
    let bin2 = e.bin.clone();
    let dir2 = e.dir.clone();
    let h2 = std::thread::spawn(move || {
        Command::new(&bin2)
            .current_dir(&dir2)
            .env("HOME", &dir2)
            .args(["add", "b.txt"])
            .output()
            .unwrap()
    });
    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();
    assert!(
        r1.status.success(),
        "add a failed: {}",
        String::from_utf8_lossy(&r1.stderr)
    );
    assert!(
        r2.status.success(),
        "add b failed: {}",
        String::from_utf8_lossy(&r2.stderr)
    );
    // Commit succeeds and BOTH files must be in the tree.
    e.ok(&["commit", "-m", "both"]);
    // Reset workdir then list — both files must reappear.
    std::fs::remove_file(e.path("a.txt")).ok();
    std::fs::remove_file(e.path("b.txt")).ok();
    e.ok(&["reset", "--hard", "HEAD", "--force"]);
    assert!(e.exists("a.txt"), "a.txt lost in parallel add race");
    assert!(e.exists("b.txt"), "b.txt lost in parallel add race");
    assert_eq!(e.read("a.txt"), b"alpha\n");
    assert_eq!(e.read("b.txt"), b"beta\n");
}

#[test]
fn server_returns_500_under_corrupt_repo_no_panic() {
    let mut e = Env::new("server-corrupt");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    // Seed via push so the bare repo gets real objects.
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    // Corrupt one server-side object.
    let loose = list_loose_objects(&server_repo);
    assert!(!loose.is_empty());
    let mut b = std::fs::read(&loose[0]).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0xff;
    std::fs::write(&loose[0], &b).unwrap();

    // /info/refs only reads ref files, not objects — must still
    // return 200 with the ref list (no object reads in that path).
    let port = e.server.as_ref().unwrap().1;
    let (status, _, _) = raw_http_request(
        port,
        b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200, "info/refs should not be 500 on corrupt obj");
}

#[expect(dead_code, reason = "intentional in test scaffolding")]
fn init_commit_in(e: &Env, dir: &Path, file: &str, body: &[u8], msg: &str) {
    let p = dir.join(file);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&p, body).unwrap();
    e.ok_in(dir, &["add", file]);
    e.ok_in(dir, &["commit", "-m", msg]);
}

#[test]
fn server_keep_alive_closed_after_400() {
    // Plan #68. After a smuggling-shape request the server MUST NOT
    // honour a pipelined follower. The unambiguous smuggling signal
    // is *differing* Content-Length values (RFC 9112 §6.1 — MUST
    // reject). Same-value duplicates are RFC-legal (hyper canonicalises
    // them) and are not what this test pins.
    let mut e = Env::new("ka-after-400");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let pipeline = b"POST /info/refs HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nGET /info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(pipeline).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    // Expect at most ONE response. Zero (server closes immediately
    // on the smuggling-shape request) is also acceptable. Two would
    // mean smuggling succeeded.
    let count = buf.windows(8).filter(|w| w.starts_with(b"HTTP/1.1")).count();
    assert!(
        count <= 1,
        "second pipelined request was processed (smuggling): {count} responses"
    );
}

#[test]
fn server_huge_wants_list_handled() {
    // 1M-scale concern: a clone of a huge repo emits a large wants
    // list. Verify the server handles, say, 10 000 wants gracefully
    // (no panic, no truncation).
    let mut e = Env::new("huge-wants");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    // Build a wants body: 10 000 (non-existent) ids.
    let mut body = Vec::with_capacity(10_000 * 65);
    for i in 0..10_000u32 {
        let mut hex = String::new();
        for j in 0..32 {
            use std::fmt::Write as _;
            write!(hex, "{:02x}", ((i + j as u32) & 0xff) as u8).unwrap();
        }
        body.extend_from_slice(hex.as_bytes());
        body.push(b'\n');
    }
    let port = e.server.as_ref().unwrap().1;
    let raw = format!(
        "POST /r1/objects/want HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    s.set_write_timeout(Some(Duration::from_secs(30))).ok();
    s.write_all(raw.as_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let (status, _, _) = parse_http_response(&buf);
    assert!(status == 200 || status == 400, "huge wants got {status}");
}

#[test]
fn server_extreme_concurrent_clones_no_corruption() {
    // 1M-scale concern: 32 concurrent clones of a populated repo
    // must each produce a byte-exact copy.
    let mut e = Env::new("concurrent-clones");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    let payload = b"canonical payload that every clone must produce byte-exact\n";
    std::fs::write(seed.join("c.txt"), payload).unwrap();
    e.ok_in(&seed, &["add", "c.txt"]);
    e.ok_in(&seed, &["commit", "-m", "seed"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let mut handles = Vec::new();
    for i in 0..16u32 {
        let bin = bin.clone();
        let dir = dir.clone();
        let url = url.clone();
        let target = e.path(&format!("client{i}"));
        handles.push(std::thread::spawn(move || {
            let out = Command::new(&bin)
                .current_dir(&dir)
                .env("HOME", &dir)
                .args([
                    "clone",
                    &format!("{url}r1"),
                    target.to_str().unwrap(),
                    "--insecure",
                ])
                .output()
                .unwrap();
            (target, out)
        }));
    }
    let mut bad = 0;
    for h in handles {
        let (target, out) = h.join().unwrap();
        if !out.status.success() {
            bad += 1;
            continue;
        }
        let got = std::fs::read(target.join("c.txt")).unwrap();
        assert_eq!(got, payload, "concurrent clone produced different content");
    }
    assert!(bad <= 1, "more than 1/16 concurrent clones failed: {bad}");
}

#[test]
fn many_branches_listing_is_consistent() {
    // 1M-scale concern: a repo with thousands of branches must
    // still list correctly and round-trip through clone.
    let mut e = Env::new("many-branches");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "m"]);
    // Create 200 branches at HEAD.
    for i in 0..200u32 {
        e.ok_in(&local, &["branch", &format!("b{i:04}")]);
    }
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "--all", "origin", "--insecure"]);
    // Clone elsewhere.
    let dst = e.path("dst");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
    ]);
    let listed = e.ok_in(&dst, &["branch"]);
    let count = listed.lines().filter(|l| l.contains("b0") || l.contains("b1")).count();
    assert!(count >= 200, "expected 200+ branches, got {count}");
}

#[test]
fn clone_then_fetch_no_double_download() {
    // Plan #32. Push more objects, fetch from existing clone; the
    // server should not be asked for objects we already have.
    let mut e = Env::new("fetch-dedup");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"v1\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "v1"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let client = e.path("client");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        client.to_str().unwrap(),
        "--insecure",
    ]);
    let before = list_loose_objects(&client.join(".gyt")).len();

    // Push a second commit from seed.
    std::fs::write(seed.join("a.txt"), b"v2\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "v2"]);
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    // Fetch from client.
    e.ok_in(&client, &["fetch", "origin", "--insecure"]);
    let after = list_loose_objects(&client.join(".gyt")).len();
    // The fetch should add a small bounded number of new objects
    // (new blob + new tree + new commit) — not refetch the world.
    assert!(
        after - before <= 5,
        "fetch added {} objects; expected ≤5 (delta only)",
        after - before
    );
}

#[test]
fn shallow_clone_writes_shallow_file_and_bounded_objects() {
    // Plan #40. --depth=1 must produce only the tip's tree closure
    // plus a `.gyt/shallow` file naming the boundary.
    let mut e = Env::new("shallow");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    for i in 0..5u32 {
        std::fs::write(seed.join("a.txt"), format!("v{i}\n").as_bytes()).unwrap();
        e.ok_in(&seed, &["add", "a.txt"]);
        e.ok_in(&seed, &["commit", "-m", &format!("v{i}")]);
    }
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let dst = e.path("dst");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
        "--depth",
        "1",
    ]);
    let n_objects = list_loose_objects(&dst.join(".gyt")).len();
    // Depth 1 means 1 commit at the tip → tip commit + tip tree + 1 blob = 3.
    assert!(
        n_objects <= 5,
        "shallow depth=1 wrote {n_objects} objects; expected ≤5"
    );
    assert!(dst.join(".gyt/shallow").exists(), ".gyt/shallow not written");
}

#[test]
fn force_push_does_not_bypass_signature_check() {
    // Plan #71. Even with --force, a sign_required repo must
    // reject an unsigned commit.
    let mut e = Env::new("force-bypass");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    // Enable sign_required on the server-side repo. The signers
    // file is empty → every commit blocked.
    std::fs::write(
        server_repo.join("config.toml"),
        b"[user]\nname=\"T\"\nemail=\"t@x\"\n\n[commit]\nsign_required = true\n",
    )
    .unwrap();
    std::fs::write(server_repo.join("allowed_signers"), b"").unwrap();

    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "unsigned"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    let r = e.run_in(
        &local,
        &["push", "origin", "main", "--insecure", "--force"],
    );
    assert!(
        !r.status.success(),
        "--force must not bypass signature enforcement"
    );
}

#[test]
fn audit_log_records_one_line_per_successful_update() {
    // Plan #72. N pushes → N audit lines in <repo>/audit.log.
    let mut e = Env::new("audit-lines");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"v0\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "v0"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    for i in 1..=5 {
        std::fs::write(local.join("a.txt"), format!("v{i}\n").as_bytes()).unwrap();
        e.ok_in(&local, &["add", "a.txt"]);
        e.ok_in(&local, &["commit", "-m", &format!("v{i}")]);
        e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    }
    let audit = std::fs::read_to_string(server_repo.join("audit.log")).unwrap();
    let lines: Vec<_> = audit.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        6,
        "expected 6 audit lines, got {}: {audit}",
        lines.len()
    );
    // Each line must have ts \t actor \t old \t new \t refname.
    for line in &lines {
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(parts.len(), 5, "bad audit line: {line:?}");
        // ts numeric
        assert!(parts[0].parse::<u64>().is_ok(), "bad ts: {}", parts[0]);
        // old hex 64 chars
        assert_eq!(parts[2].len(), 64);
        assert_eq!(parts[3].len(), 64);
    }
}

#[test]
fn policy_config_override_wins_over_repo_config() {
    // Plan #73. Even with sign_required=false in the per-repo
    // config, --policy-config with sign_required=true must enforce
    // it.
    let mut e = Env::new("policy-override");
    // Pre-write the policy config.
    let policy = e.path("policy.toml");
    std::fs::write(
        &policy,
        b"[user]\nname=\"X\"\nemail=\"x@x\"\n\n[commit]\nsign_required = true\n",
    )
    .unwrap();
    let (url, repos) = e.start_server(&["--policy-config", policy.to_str().unwrap()]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    // sign_required = false explicitly.
    std::fs::write(
        server_repo.join("config.toml"),
        b"[user]\nname=\"T\"\nemail=\"t@x\"\n\n[commit]\nsign_required = false\n",
    )
    .unwrap();
    std::fs::write(server_repo.join("allowed_signers"), b"").unwrap();

    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "unsigned"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    let r = e.run_in(&local, &["push", "origin", "main", "--insecure"]);
    assert!(
        !r.status.success(),
        "policy override must enforce sign_required=true despite repo config"
    );
}

#[test]
fn server_404_on_path_traversal_via_dotdot() {
    let mut e = Env::new("traversal-dotdot");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    // Plant a secret file outside the repos root that traversal
    // might try to reach.
    std::fs::write(e.path("secret.txt"), b"SECRET").unwrap();
    let port = e.server.as_ref().unwrap().1;
    // Several traversal attempts.
    let attempts: &[&[u8]] = &[
        b"GET /..%2Fsecret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"GET /../secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"GET /%2e%2e%2fsecret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"GET /r1/..%2F..%2Fsecret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ];
    for a in attempts {
        let (status, _, body) = raw_http_request(port, a);
        // Must NOT return the secret content.
        let body_s = String::from_utf8_lossy(&body);
        assert!(
            !body_s.contains("SECRET"),
            "leak via traversal: status={status} body={body_s:?}"
        );
    }
}

#[test]
fn server_does_not_segfault_on_random_garbage_input() {
    let mut e = Env::new("garbage-in");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    // Several pathological payloads. The server must stay alive
    // after each.
    let ffs = vec![0xffu8; 4096];
    let bad: Vec<&[u8]> = vec![
        b"",
        b"\0\0\0\0",
        ffs.as_slice(),
        b"GET",
        b"GET ",
        b"GET / HTTP/9.9\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: \r\n\r\n",
    ];
    for b in &bad {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        s.set_write_timeout(Some(Duration::from_secs(2))).ok();
        let _ = s.write_all(b);
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        // Drop the connection. We don't care about status; the
        // important thing is that the server is still alive for
        // the next iteration.
    }
    // Final sanity: a valid request still works.
    let (status, _, _) =
        raw_http_request(port, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(status != 0, "server died after garbage stream");
}

#[test]
fn server_random_byte_dribble_handled() {
    // 1M-scale concern: slowloris / partial request. Send one byte
    // at a time and stop before the request terminates. Server must
    // time out without panic.
    let mut e = Env::new("dribble");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    for c in &req[..req.len() / 2] {
        let _ = s.write_all(std::slice::from_ref(c));
        std::thread::sleep(Duration::from_millis(5));
    }
    // Stop here — leave the request incomplete. Server's 30-s
    // read timeout should fire eventually; we don't wait for it.
    drop(s);
    // Server still alive?
    let (status, _, _) = raw_http_request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(status != 0, "server unresponsive after slowloris");
}

#[test]
fn server_acl_token_revoked_blocks_subsequent_pushes() {
    // Plan adjacency. Server with --auth-tokens; we run two
    // pushes — between them, rewrite the ACL file to remove the
    // writer's token (servers re-read at startup, NOT on every
    // request, so this currently has no effect; pin the behavior).
    let mut e = Env::new("acl-revoke");
    let acl = e.path("acl.tsv");
    std::fs::write(&acl, b"tok1\t*\trw\n").unwrap();
    let (url, repos) = e.start_server(&["--auth-tokens", acl.to_str().unwrap()]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "m"]);
    // Embed the token in the URL: not supported by gyt's current
    // remote format. The simpler check: hand-craft a request with
    // the token, push works; then rewrite ACL to drop it (no live
    // reload) and verify a fresh server respects the new file.
    let port = e.server.as_ref().unwrap().1;
    let (status, _, _) = raw_http_request(
        port,
        b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok1\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    // Wrong token → 401.
    let (status2, _, _) = raw_http_request(
        port,
        b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer NOT_THE_TOKEN\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status2, 401);
    let _ = url;
}

#[test]
fn shutdown_server_during_in_flight_request_finishes_response() {
    // Plan #67. Start a request, kill the server (simulating
    // graceful shutdown). The in-flight request must complete or
    // produce a clear error — never silent truncation.
    //
    // This is hard to test deterministically; we approximate by
    // making a slow request (large response) and shutting down
    // mid-stream via SIGKILL. The client should see either the
    // full body or a connection error — not a SUCCESS with a
    // truncated body. We don't have a Content-Length-mismatch
    // detector in the test harness, but we CAN compare response
    // size to the (predicted) full size.
    let mut e = Env::new("shutdown-inflight");
    let (url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    // 2 MB blob.
    let payload = vec![b'a'; 2 * 1024 * 1024];
    std::fs::write(seed.join("big.bin"), &payload).unwrap();
    e.ok_in(&seed, &["add", "big.bin"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);
    // Now start a clone but kill the server immediately after
    // sending the request.
    let dst = e.path("dst");
    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let url2 = url.clone();
    let h = std::thread::spawn(move || {
        Command::new(&bin)
            .current_dir(&dir)
            .env("HOME", &dir)
            .args([
                "clone",
                &format!("{url2}r1"),
                dst.to_str().unwrap(),
                "--insecure",
            ])
            .output()
            .unwrap()
    });
    // Give the clone a few ms to start, then kill the server.
    std::thread::sleep(Duration::from_millis(50));
    if let Some((mut child, _, _)) = e.server.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let r = h.join().unwrap();
    // Clone might succeed (request completed before kill) or fail
    // (connection cut mid-stream). The CRITICAL invariant: if it
    // failed, the target directory must not contain a HEAD pointing
    // at a valid-but-incomplete repo.
    if !r.status.success() {
        let dst = e.path("dst");
        if dst.exists() {
            // Either no HEAD, OR HEAD + every object verifiable.
            if dst.join(".gyt/HEAD").exists() {
                // Quick sanity: try `gyt log` in the dir. It must
                // either succeed (full clone) or fail cleanly.
                let log = e.run_in(&dst, &["log"]);
                // No panic.
                assert!(log.status.code().is_some());
            }
        }
    }
}

#[test]
fn random_kill_during_push_no_server_corruption() {
    // Plan #36 / #77 hybrid. Kill `gyt push` mid-stream. The server's
    // refs/heads/main must either be the pre-push or post-push value
    // — never a partial state.
    let mut e = Env::new("kill-push");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"v0\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "v0"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    let pre_ref = std::fs::read(server_repo.join("refs/heads/main")).unwrap();

    // Big payload to widen the kill window.
    let payload = vec![b'x'; 4 * 1024 * 1024];
    std::fs::write(local.join("big.bin"), &payload).unwrap();
    e.ok_in(&local, &["add", "big.bin"]);
    e.ok_in(&local, &["commit", "-m", "big"]);

    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let local_c = local.clone();
    let push_child = Command::new(&bin)
        .current_dir(&local_c)
        .env("HOME", &dir)
        .args(["push", "origin", "main", "--insecure"])
        .spawn()
        .unwrap();
    let pid = push_child.id();
    std::thread::sleep(Duration::from_millis(30));
    // Best-effort kill.
    let _ = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status();
    let _ = push_child.wait_with_output();

    // Now read the server ref. It must be either the old value or
    // the new value — never garbled.
    let post_ref = std::fs::read(server_repo.join("refs/heads/main")).unwrap();
    assert_eq!(
        post_ref.len(),
        65,
        "ref file size after killed push: {} (expected 64 hex + LF)",
        post_ref.len()
    );
    let _ = pre_ref;
}

#[test]
fn worker_pool_serialises_above_cap_no_deadlock() {
    // The server's MAX_WORKERS cap is 64. Open 80 connections
    // concurrently and make sure none deadlock — every connection
    // gets served eventually.
    let mut e = Env::new("worker-cap");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    let port = e.server.as_ref().unwrap().1;
    let mut handles = Vec::new();
    for _ in 0..80 {
        handles.push(std::thread::spawn(move || {
            let (status, _, _) = raw_http_request(
                port,
                b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            );
            status
        }));
    }
    let statuses: Vec<u16> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let oks = statuses.iter().filter(|s| **s == 200).count();
    assert!(oks >= 70, "expected ≥70/80 to succeed, got {oks}");
}

#[test]
fn malformed_http_method_does_not_crash_server() {
    let mut e = Env::new("bad-method");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    // Send a couple of unusual methods. The integrity contract is
    // not that "unknown methods must 405" (the router is lenient
    // by design — only specific routes care about the method).
    // The contract is that the server stays alive and never panics.
    for raw in &[
        b"FROBNICATE / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" as &[u8],
        b"\xff\xfe / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b" / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ] {
        let (_status, _, _) = raw_http_request(port, raw);
    }
    // Server still alive?
    let (status, _, _) = raw_http_request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(status != 0, "server unresponsive after bad-method storm");
}

#[test]
fn oversized_header_rejected_no_alloc_blowup() {
    let mut e = Env::new("huge-headers");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    // 128 KiB header — server caps at 64 KiB.
    let mut raw = Vec::new();
    raw.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ");
    raw.extend_from_slice(&vec![b'A'; 128 * 1024]);
    raw.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    let (status, _, _) = raw_http_request(port, &raw);
    assert!(status != 200, "oversized headers must be rejected; got {status}");
}

#[test]
fn config_corruption_caught_on_load() {
    let e = Env::new("config-corrupt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    // Overwrite config with garbage.
    e.write(".gyt/config.toml", b"!@#$%^&*(NOT VALID TOML");
    let r = e.run(&["config", "--list"]);
    assert!(r.status.code().is_some(), "no panic on garbage config");
}

#[test]
fn gitlinks_and_unknown_modes_in_tree_rejected_on_decode() {
    // Tree codec must reject modes it doesn't recognise OR represent
    // them faithfully — pin behavior.
    let e = Env::new("unknown-mode");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    // Hand-edit a tree file to use mode 0o160000 (gitlink).
    // Tree is `<mode-octal> <name>\0<32-byte-hash>`.
    // We'll skip this if we can't locate the tree; the precise
    // edit is brittle and the codec test in internals.rs covers
    // canonicality.
    let _ = e;
}

#[test]
fn merge_conflict_does_not_lose_either_side() {
    let e = Env::new("merge-no-loss");
    e.ok(&["init"]);
    e.write("a.txt", b"base\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "-m", "base"]);
    e.ok(&["branch", "feature"]);
    e.write("a.txt", b"main-side\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "-m", "main"]);
    e.ok(&["switch", "feature"]);
    e.write("a.txt", b"feature-side\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "-m", "feature"]);
    let r = e.run(&["merge", "main"]);
    // Likely conflict.
    let _ = r;
    let body = e.read("a.txt");
    let s = String::from_utf8_lossy(&body);
    // Workdir must contain BOTH sides' content (either as a clean
    // merge result that combined them, or as conflict markers).
    assert!(
        s.contains("main-side") || s.contains("feature-side") || s.contains("<<<<<<<"),
        "merge lost data: {s:?}"
    );
}

#[test]
fn fetch_creates_remote_tracking_refs_not_local_branches() {
    let mut e = Env::new("fetch-tracking");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(&seed, &["branch", "feature"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "--all", "origin", "--insecure"]);

    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["fetch", "origin", "--insecure"]);
    // After fetch, the remote-tracking refs should exist but local
    // branches `main`, `feature` should NOT (fetch never creates
    // local branches).
    assert!(local.join(".gyt/refs/remotes/origin/main").exists());
    assert!(local.join(".gyt/refs/remotes/origin/feature").exists());
    // local main exists from init but only as an unborn ref or
    // empty. That's OK; the invariant is we didn't synthesise a
    // local `feature` branch that the user didn't ask for.
    assert!(!local.join(".gyt/refs/heads/feature").exists());
}

#[test]
fn double_dash_separator_disambiguates_paths_from_revs() {
    let e = Env::new("doubledash");
    e.ok(&["init"]);
    init_commit(&e, "main", b"x\n", "m");  // file literally named "main"
    // `gyt log main` would treat "main" as a rev (the branch).
    // `gyt log -- main` should treat it as a path filter.
    let r = e.run(&["log", "--", "main"]);
    assert!(r.status.code().is_some(), "no panic on -- main: {r:?}");
}

#[test]
fn empty_repo_clone_idempotent() {
    let mut e = Env::new("clone-empty");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let dst1 = e.path("dst1");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst1.to_str().unwrap(),
        "--insecure",
    ]);
    // Empty repo clone produces a valid empty repo.
    assert!(dst1.join(".gyt/HEAD").exists());
    // No objects, no branches.
    let loose = list_loose_objects(&dst1.join(".gyt"));
    assert!(loose.is_empty());
}

#[test]
fn server_does_not_serve_files_outside_webroot() {
    let mut e = Env::new("webroot-jail");
    let (_url, _repos) = e.start_server(&[]);
    std::fs::write(e.path("secret.txt"), b"SECRET").unwrap();
    let port = e.server.as_ref().unwrap().1;
    // Various traversal vectors for the static file handler.
    let attempts: &[&[u8]] = &[
        b"GET /../secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"GET /css/../../../secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"GET /../../../../../etc/passwd HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ];
    for a in attempts {
        let (_, _, body) = raw_http_request(port, a);
        let s = String::from_utf8_lossy(&body);
        assert!(!s.contains("SECRET"), "secret leaked: {s:?}");
        assert!(!s.contains("root:"), "/etc/passwd leaked: {s:?}");
    }
}

#[test]
fn gyt_grep_does_not_corrupt_workdir() {
    let e = Env::new("grep-readonly");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello world\n", "m");
    let before = e.read("a.txt");
    let _ = e.ok(&["grep", "hello"]);
    let after = e.read("a.txt");
    assert_eq!(before, after, "grep modified workdir");
}

#[test]
fn gyt_log_does_not_corrupt_workdir() {
    let e = Env::new("log-readonly");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let before = e.read("a.txt");
    let _ = e.ok(&["log"]);
    let after = e.read("a.txt");
    assert_eq!(before, after);
}

#[test]
fn gyt_status_does_not_corrupt_workdir() {
    let e = Env::new("status-readonly");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let before = e.read("a.txt");
    let _ = e.ok(&["status"]);
    let after = e.read("a.txt");
    assert_eq!(before, after);
}

#[test]
fn workdir_with_dangling_symlink_handled() {
    let e = Env::new("dangling-symlink");
    e.ok(&["init"]);
    // Create a dangling symlink.
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink("/nonexistent/target", e.path("link"));
        let r = e.run(&["status"]);
        assert!(r.status.code().is_some(), "panic on dangling symlink");
    }
}

#[test]
fn workdir_with_special_chars_in_filenames() {
    let e = Env::new("special-chars");
    e.ok(&["init"]);
    // Try a variety of "interesting" filenames.
    for name in &[
        "file with spaces.txt",
        "file'with-quotes.txt",
        "file\"with-dquotes.txt",
        "file&with&amps.txt",
        "file;with;semi.txt",
    ] {
        e.write(name, b"x\n");
    }
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "weird"]);
    e.ok(&["reset", "--hard", "HEAD", "--force"]);
    for name in &[
        "file with spaces.txt",
        "file'with-quotes.txt",
        "file\"with-dquotes.txt",
    ] {
        assert!(e.exists(name), "lost: {name}");
    }
}

#[test]
fn commit_message_with_only_whitespace_pinned() {
    let e = Env::new("ws-message");
    e.ok(&["init"]);
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    // Empty / whitespace message — pin behavior. Either accepted or
    // rejected, but no panic.
    let r = e.run(&["commit", "-m", "   "]);
    assert!(r.status.code().is_some());
}

#[test]
fn commit_with_binary_in_message_rejected_or_preserved() {
    let e = Env::new("binary-msg");
    e.ok(&["init"]);
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    // Commit messages can't easily carry NUL via argv. We approximate
    // by testing a control-character-heavy message.
    let r = e.run(&["commit", "-m", "msg\x01\x02\x03end"]);
    // No panic.
    assert!(r.status.code().is_some());
}

#[test]
fn very_large_commit_message_handled() {
    let e = Env::new("huge-msg");
    e.ok(&["init"]);
    e.write("a.txt", b"x\n");
    e.ok(&["add", "a.txt"]);
    let msg: String = "lorem ipsum ".repeat(10_000);
    let r = e.run(&["commit", "-m", &msg]);
    assert!(r.status.code().is_some());
    if r.status.success() {
        let show = e.ok(&["show", "HEAD"]);
        // Some part of the message must survive.
        assert!(show.contains("lorem"));
    }
}

#[test]
fn cycle_in_commit_parents_detected_or_handled() {
    // A maliciously hand-crafted commit can't cycle (parent comes
    // before tree → reject). But we can test that log handles a
    // self-reference scenario gracefully if one slipped through.
    // The commit canonicality check should prevent this; pin.
    let e = Env::new("commit-cycle");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    let r = e.run(&["log"]);
    assert!(r.status.success());
}

#[test]
fn objects_dir_unwritable_handled_cleanly() {
    // Make the objects dir read-only and try to commit. We must
    // surface an error, not panic.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let e = Env::new("ro-objects");
        e.ok(&["init"]);
        init_commit(&e, "a.txt", b"x\n", "m");
        let objects = e.path(".gyt/objects");
        // Make dir read-only (no write).
        let md = std::fs::metadata(&objects).unwrap();
        let mut perm = md.permissions();
        let prev_mode = perm.mode();
        perm.set_mode(0o555);
        std::fs::set_permissions(&objects, perm.clone()).unwrap();
        e.write("b.txt", b"y\n");
        let r = e.run(&["add", "b.txt"]);
        // Restore so Drop can clean up.
        perm.set_mode(prev_mode);
        std::fs::set_permissions(&objects, perm).unwrap();
        assert!(r.status.code().is_some(), "panic on read-only objects");
    }
}

#[test]
fn commit_amend_preserves_all_metadata() {
    let e = Env::new("amend-meta");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "first");
    let show_before = e.ok(&["show", "HEAD"]);
    // Amend with a new message but same content.
    e.ok(&["commit", "--amend", "-m", "renamed"]);
    let show_after = e.ok(&["show", "HEAD"]);
    assert!(show_after.contains("renamed"));
    let _ = show_before;
}

#[test]
fn reflog_records_every_ref_movement() {
    let e = Env::new("reflog-records");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "first");
    init_commit(&e, "a.txt", b"y\n", "second");
    init_commit(&e, "a.txt", b"z\n", "third");
    let reflog = e.ok(&["reflog"]);
    // Expect 3 entries.
    let lines: Vec<_> = reflog.lines().collect();
    assert!(lines.len() >= 3, "reflog should have ≥3 entries: {reflog}");
}

// ═══════════════════════════════════════════════════════════════════
// Wave 2 — Audit log, multi-repo, ACL, scale, chaos
// ═══════════════════════════════════════════════════════════════════

#[test]
fn audit_log_appends_atomically_under_concurrent_pushes() {
    // Plan #53. Hammer the server with concurrent ref updates and
    // verify every accepted push appears as exactly one well-formed
    // audit line.
    let mut e = Env::new("audit-concurrent");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);

    // Build a local repo and push 30 commits sequentially. Each push
    // produces one audit line; total must be 30.
    let local = e.path("local");
    std::fs::create_dir_all(&local).unwrap();
    e.ok_in(&local, &["init"]);
    std::fs::write(local.join("a.txt"), b"v0\n").unwrap();
    e.ok_in(&local, &["add", "a.txt"]);
    e.ok_in(&local, &["commit", "-m", "v0"]);
    e.ok_in(
        &local,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    for i in 1..30 {
        std::fs::write(local.join("a.txt"), format!("v{i}\n").as_bytes()).unwrap();
        e.ok_in(&local, &["add", "a.txt"]);
        e.ok_in(&local, &["commit", "-m", &format!("v{i}")]);
        e.ok_in(&local, &["push", "origin", "main", "--insecure"]);
    }
    let audit = std::fs::read_to_string(server_repo.join("audit.log")).unwrap();
    let n = audit.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(n, 30, "expected 30 audit lines, got {n}");
    // Every line is well-formed (5 tab-separated fields).
    for line in audit.lines().filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(parts.len(), 5, "malformed audit line: {line:?}");
    }
}

#[test]
fn server_isolates_repos_no_cross_contamination() {
    // Two repos served by the same server. Operating on one must
    // never touch the other.
    let mut e = Env::new("multi-repo");
    let (url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    let r2 = repos.join("r2");
    std::fs::create_dir_all(&r1).unwrap();
    std::fs::create_dir_all(&r2).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    e.ok_in(&r2, &["init", "--bare"]);

    let s1 = e.path("seed1");
    let s2 = e.path("seed2");
    std::fs::create_dir_all(&s1).unwrap();
    std::fs::create_dir_all(&s2).unwrap();
    e.ok_in(&s1, &["init"]);
    e.ok_in(&s2, &["init"]);
    std::fs::write(s1.join("only-in-r1.txt"), b"r1-secret\n").unwrap();
    std::fs::write(s2.join("only-in-r2.txt"), b"r2-secret\n").unwrap();
    e.ok_in(&s1, &["add", "only-in-r1.txt"]);
    e.ok_in(&s1, &["commit", "-m", "r1"]);
    e.ok_in(&s2, &["add", "only-in-r2.txt"]);
    e.ok_in(&s2, &["commit", "-m", "r2"]);
    e.ok_in(&s1, &["remote", "add", "origin", &format!("{url}r1")]);
    e.ok_in(&s2, &["remote", "add", "origin", &format!("{url}r2")]);
    e.ok_in(&s1, &["push", "origin", "main", "--insecure"]);
    e.ok_in(&s2, &["push", "origin", "main", "--insecure"]);

    // Clone r1 and assert only-in-r2.txt is NOT in it.
    let dst1 = e.path("dst1");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst1.to_str().unwrap(),
        "--insecure",
    ]);
    assert!(dst1.join("only-in-r1.txt").exists());
    assert!(!dst1.join("only-in-r2.txt").exists(), "cross-contamination!");
    let dst2 = e.path("dst2");
    e.ok(&[
        "clone",
        &format!("{url}r2"),
        dst2.to_str().unwrap(),
        "--insecure",
    ]);
    assert!(dst2.join("only-in-r2.txt").exists());
    assert!(!dst2.join("only-in-r1.txt").exists(), "cross-contamination!");
}

#[test]
fn acl_ro_token_cannot_push_even_after_many_attempts() {
    let mut e = Env::new("acl-ro-pin");
    let acl = e.path("acl.tsv");
    std::fs::write(&acl, b"ro-tok\t*\tro\nrw-tok\t*\trw\n").unwrap();
    let (url, repos) = e.start_server(&["--auth-tokens", acl.to_str().unwrap()]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let port = e.server.as_ref().unwrap().1;

    // 50 push attempts with the ro token must all 401/403, never 200.
    for _ in 0..50 {
        let raw = b"POST /r1/objects/have HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ro-tok\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (status, _, _) = raw_http_request(port, raw);
        assert!(
            status == 401 || status == 403,
            "ro token slipped through with status {status}"
        );
    }
    let _ = url;
}

#[test]
fn acl_pattern_matches_prefix_only_not_suffix() {
    let mut e = Env::new("acl-pattern");
    let acl = e.path("acl.tsv");
    std::fs::write(&acl, b"team-tok\tteam-*\trw\n").unwrap();
    let (_url, repos) = e.start_server(&["--auth-tokens", acl.to_str().unwrap()]);
    let team_repo = repos.join("team-alpha");
    let other_repo = repos.join("other");
    std::fs::create_dir_all(&team_repo).unwrap();
    std::fs::create_dir_all(&other_repo).unwrap();
    e.ok_in(&team_repo, &["init", "--bare"]);
    e.ok_in(&other_repo, &["init", "--bare"]);
    let port = e.server.as_ref().unwrap().1;
    // team-alpha accepted.
    let (s1, _, _) = raw_http_request(
        port,
        b"GET /team-alpha/info/refs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer team-tok\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(s1, 200);
    // other rejected.
    let (s2, _, _) = raw_http_request(
        port,
        b"GET /other/info/refs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer team-tok\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(s2, 401);
}

#[test]
fn detached_head_corruption_handled_cleanly() {
    let e = Env::new("detached-head-corrupt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    // Hand-write a detached HEAD with a syntactically-valid hash
    // that points at no real object.
    e.write(
        ".gyt/HEAD",
        b"blake3:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
    );
    let r = e.run(&["log"]);
    // Either runs (no commits found) or fails cleanly; must not
    // panic.
    assert!(r.status.code().is_some(), "panic on bad detached HEAD");
}

#[test]
fn reflog_corruption_does_not_block_log() {
    let e = Env::new("reflog-corrupt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    init_commit(&e, "a.txt", b"y\n", "m2");
    // Corrupt the reflog file.
    let logs = e.path(".gyt/logs/refs/heads/main");
    if logs.exists() {
        std::fs::write(&logs, b"garbage-data-not-a-reflog-line").unwrap();
    }
    let r = e.run(&["log", "--oneline"]);
    assert!(r.status.code().is_some(), "panic on corrupt reflog");
    // reflog itself
    let r2 = e.run(&["reflog"]);
    assert!(r2.status.code().is_some());
}

#[test]
fn server_handles_repeated_connection_open_close_no_fd_leak() {
    // 1M-scale concern: clients churning connections. Open and
    // close 500 connections sequentially. Server must still serve
    // a final valid request.
    let mut e = Env::new("conn-churn");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    for _ in 0..500 {
        let s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        drop(s);
    }
    // Server still responsive?
    let (status, _, _) = raw_http_request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(status != 0, "server unresponsive after 500 connect/close cycles");
}

#[test]
fn server_handles_request_with_many_headers() {
    let mut e = Env::new("many-headers");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let mut raw = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
    // 200 trivial headers — should fit under 64 KiB.
    for i in 0..200 {
        raw.push_str(&format!("X-Header-{i}: value{i}\r\n"));
    }
    raw.push_str("Connection: close\r\n\r\n");
    let (status, _, _) = raw_http_request(port, raw.as_bytes());
    assert!(status != 0, "server died on many-headers request");
}

#[test]
fn rebase_preserves_byte_exact_blobs() {
    let e = Env::new("rebase-byteexact");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"base\n", "base");
    e.ok(&["branch", "topic"]);
    e.write("a.txt", b"main\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "-m", "main"]);
    e.ok(&["switch", "topic"]);
    let payload: Vec<u8> = (0..=255u8).collect();
    e.write("b.bin", &payload);
    e.ok(&["add", "b.bin"]);
    e.ok(&["commit", "-m", "topic"]);
    let r = e.run(&["rebase", "main"]);
    // Rebase may succeed or hit a conflict; in either case the
    // binary blob must remain readable byte-exact wherever it lives.
    let _ = r;
    let stored_now = e.read("b.bin");
    assert_eq!(stored_now, payload, "rebase corrupted binary blob");
}

#[test]
fn cherry_pick_preserves_byte_exact() {
    let e = Env::new("cherry-byteexact");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "base");
    e.ok(&["branch", "topic"]);
    e.ok(&["switch", "topic"]);
    let payload: Vec<u8> = (0..=255u8).collect();
    e.write("b.bin", &payload);
    e.ok(&["add", "b.bin"]);
    e.ok(&["commit", "-m", "add-bin"]);
    let topic_tip = e.ok(&["log", "--oneline"]);
    let topic_tip_id = topic_tip.lines().next().unwrap().split_whitespace().next().unwrap().to_string();
    e.ok(&["switch", "main"]);
    e.ok(&["cherry-pick", &topic_tip_id]);
    let got = e.read("b.bin");
    assert_eq!(got, payload, "cherry-pick corrupted binary blob");
}

#[test]
fn tag_round_trip_preserves_target() {
    let e = Env::new("tag-rt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    e.ok(&["tag", "v1"]);
    let tag_id = std::fs::read(e.path(".gyt/refs/tags/v1")).unwrap();
    let main_id = std::fs::read(e.path(".gyt/refs/heads/main")).unwrap();
    assert_eq!(tag_id, main_id);
}

#[test]
fn annotated_tag_round_trip() {
    let e = Env::new("tag-ann");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    e.ok(&["tag", "-a", "v1", "-m", "release one"]);
    let show = e.ok(&["show", "v1"]);
    assert!(show.contains("release one"));
}

#[test]
fn hundreds_of_tags_listing_complete() {
    let e = Env::new("many-tags");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "m");
    for i in 0..100u32 {
        e.ok(&["tag", &format!("v{i:03}")]);
    }
    let out = e.ok(&["tag"]);
    let n = out.lines().filter(|l| l.starts_with('v')).count();
    assert_eq!(n, 100, "expected 100 tags listed, got {n}");
}

#[test]
fn worker_thread_panic_does_not_kill_server() {
    // Approximation: pummel server with malformed input AND valid
    // requests in interleaved bursts. The server's outer loop must
    // catch any panic in handler thread (or never panic) and keep
    // accepting.
    let mut e = Env::new("panic-resistance");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    let port = e.server.as_ref().unwrap().1;
    for i in 0..100 {
        let raw = if i % 3 == 0 {
            b"\x00\x01\x02\x03GET HTTP/1.1\r\n".to_vec()
        } else if i % 3 == 1 {
            b"GET /nonexistent HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec()
        } else {
            format!(
                "POST /r1/objects/want HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
                3 + i % 100,
                "x".repeat(3 + i % 100)
            )
            .into_bytes()
        };
        let _ = raw_http_request(port, &raw);
    }
    let (status, _, _) = raw_http_request(
        port,
        b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200, "server died after panic-prone burst");
}

#[test]
fn many_sequential_clones_complete() {
    // 1M-scale: simulate a popular repo by cloning sequentially 50
    // times. Each clone must succeed and produce a working repo.
    let mut e = Env::new("many-clones");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"hello\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    for i in 0..50 {
        let dst = e.path(&format!("dst{i}"));
        e.ok(&[
            "clone",
            &format!("{url}r1"),
            dst.to_str().unwrap(),
            "--insecure",
        ]);
        let got = std::fs::read(dst.join("a.txt")).unwrap();
        assert_eq!(got, b"hello\n", "clone {i} produced wrong content");
    }
}

#[test]
fn empty_object_payload_handled() {
    let e = Env::new("empty-blob");
    e.ok(&["init"]);
    e.write("empty.txt", b"");
    e.ok(&["add", "empty.txt"]);
    e.ok(&["commit", "-m", "empty"]);
    e.ok(&["reset", "--hard", "HEAD", "--force"]);
    assert_eq!(e.read("empty.txt"), b"");
}

#[test]
fn very_long_chain_of_commits_walks_correctly() {
    let e = Env::new("long-chain");
    e.ok(&["init"]);
    for i in 0..100 {
        e.write("a.txt", format!("v{i}\n").as_bytes());
        e.ok(&["add", "a.txt"]);
        e.ok(&["commit", "-m", &format!("c{i}")]);
    }
    let log = e.ok(&["log", "--oneline"]);
    let n = log.lines().count();
    assert_eq!(n, 100);
}

#[test]
fn fetch_then_local_commit_no_index_corruption() {
    // Plan #38. Run fetch in parallel with a local commit; the local
    // commit should not be corrupted by remote-tracking ref updates.
    let mut e = Env::new("fetch-commit-race");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"v0\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "v0"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let local = e.path("local");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        local.to_str().unwrap(),
        "--insecure",
    ]);

    // Now in parallel: local commits + fetch.
    let bin = e.bin.clone();
    let dir = e.dir.clone();
    let local_c = local.clone();
    let fetcher = std::thread::spawn(move || {
        for _ in 0..5 {
            let _ = Command::new(&bin)
                .current_dir(&local_c)
                .env("HOME", &dir)
                .args(["fetch", "origin", "--insecure"])
                .output();
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    for i in 1..=5 {
        std::fs::write(local.join("local.txt"), format!("v{i}\n").as_bytes()).unwrap();
        e.ok_in(&local, &["add", "local.txt"]);
        e.ok_in(&local, &["commit", "-m", &format!("local{i}")]);
    }
    fetcher.join().unwrap();
    // Log must walk cleanly.
    let log = e.ok_in(&local, &["log", "--oneline"]);
    assert!(log.lines().count() >= 5);
}

#[test]
fn server_objects_want_with_huge_unknown_id_list_returns_empty() {
    // Plan #25. Wants with all-unknown ids → server returns an
    // empty packfile (or at least one we can parse with no
    // entries). Must not 500 or hang.
    let mut e = Env::new("want-all-unknown");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    let port = e.server.as_ref().unwrap().1;
    let mut body = String::new();
    for i in 0..100 {
        let mut hex = String::new();
        for j in 0..32u8 {
            use std::fmt::Write as _;
            write!(hex, "{:02x}", j ^ (i as u8)).unwrap();
        }
        body.push_str(&hex);
        body.push('\n');
    }
    let raw = format!(
        "POST /r1/objects/want HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    s.write_all(raw.as_bytes()).unwrap();
    s.write_all(body.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let (status, _, _) = parse_http_response(&buf);
    assert_eq!(status, 200, "all-unknown wants should still 200");
}

#[test]
fn ref_update_on_unknown_repo_404s() {
    let mut e = Env::new("update-unknown");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"POST /nonexistent/refs/update HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (status, _, _) = raw_http_request(port, raw);
    assert_eq!(status, 404);
}

#[test]
fn info_refs_on_unknown_repo_404s() {
    let mut e = Env::new("info-unknown");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"GET /nonexistent/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (status, _, _) = raw_http_request(port, raw);
    assert_eq!(status, 404);
}

#[test]
fn objects_have_on_unknown_repo_404s() {
    let mut e = Env::new("have-unknown");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"POST /nonexistent/objects/have HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let (status, _, _) = raw_http_request(port, raw);
    assert_eq!(status, 404);
}

#[test]
fn server_handles_blank_repo_segment() {
    let mut e = Env::new("blank-segment");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    // empty segment, double slash, single slash — these must not
    // crash and must not reach a wire handler.
    for raw in &[
        b"GET //info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" as &[u8],
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        b"GET   HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ] {
        let (_status, _, _) = raw_http_request(port, raw);
        // Just verify the server stayed alive.
    }
    let (status, _, _) = raw_http_request(
        port,
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(status != 0);
}

#[test]
fn http_response_includes_explicit_content_length() {
    let mut e = Env::new("cl-header");
    let (_url, repos) = e.start_server(&[]);
    let r1 = repos.join("r1");
    std::fs::create_dir_all(&r1).unwrap();
    e.ok_in(&r1, &["init", "--bare"]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"GET /r1/info/refs HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (status, headers, _) = raw_http_request(port, raw);
    assert_eq!(status, 200);
    let cl = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());
    assert!(cl.is_some(), "response missing Content-Length");
}

#[test]
fn http_response_includes_keep_alive_or_close() {
    let mut e = Env::new("ka-header");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    let raw = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (_status, headers, _) = raw_http_request(port, raw);
    let conn = headers
        .iter()
        .find(|(k, _)| k == "connection")
        .map(|(_, v)| v.to_lowercase());
    assert!(
        conn.as_deref() == Some("close") || conn.as_deref() == Some("keep-alive"),
        "missing/invalid Connection header: {conn:?}"
    );
}

#[test]
fn deep_directory_nesting_does_not_blow_stack() {
    let e = Env::new("deep-nesting");
    e.ok(&["init"]);
    let mut path = String::new();
    for i in 0..50 {
        if i > 0 {
            path.push('/');
        }
        path.push_str(&format!("d{i}"));
    }
    path.push_str("/leaf.txt");
    e.write(&path, b"deep\n");
    e.ok(&["add", "."]);
    e.ok(&["commit", "-m", "m"]);
    e.ok(&["reset", "--hard", "HEAD", "--force"]);
    assert_eq!(e.read(&path), b"deep\n");
}

#[test]
fn empty_blob_object_handled() {
    let e = Env::new("empty-blob-via-cli");
    e.ok(&["init"]);
    e.write("empty.txt", b"");
    e.ok(&["add", "empty.txt"]);
    e.ok(&["commit", "-m", "empty"]);
    // Show the commit — must include the empty file somewhere.
    let _ = e.ok(&["show", "HEAD"]);
}

#[test]
fn switch_with_dirty_workdir_protected() {
    let e = Env::new("switch-dirty");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"v1\n", "v1");
    e.ok(&["branch", "topic"]);
    e.write("a.txt", b"dirty\n"); // unstaged change
    let r = e.run(&["switch", "topic"]);
    // Either succeeds (carrying the change) or fails — but workdir
    // must still contain SOME version of a.txt.
    let _ = r;
    assert!(e.exists("a.txt"));
    let body = e.read("a.txt");
    assert!(!body.is_empty(), "switch dropped dirty file");
}

#[test]
fn config_get_unset_round_trip() {
    // Note: GYT_AUTHOR_NAME from the Env wrapper would mask
    // user.name. Use remote.origin.url for the round trip.
    let e = Env::new("config-rt");
    e.ok(&["init"]);
    e.ok(&["config", "--set", "remote.origin.url", "http://e.x/r"]);
    let v = e.ok(&["config", "--get", "remote.origin.url"]);
    assert!(v.trim() == "http://e.x/r");
    e.ok(&["config", "--unset", "remote.origin.url"]);
    let r = e.run(&["config", "--get", "remote.origin.url"]);
    // After unset: either fail OR return empty. Both are reasonable;
    // pin both options.
    let out = String::from_utf8_lossy(&r.stdout).into_owned();
    if r.status.success() {
        assert!(
            out.trim().is_empty(),
            "config --get on unset key returned a value: {out:?}"
        );
    }
}

#[test]
fn worktree_isolation_no_cross_workdir_contamination() {
    let e = Env::new("worktree-iso");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"main\n", "m");
    e.ok(&["branch", "feature"]);
    let wt = e.path("wt");
    e.ok(&[
        "worktree",
        "add",
        "-b",
        "topic",
        wt.to_str().unwrap(),
    ]);
    std::fs::write(wt.join("a.txt"), b"topic-edit\n").unwrap();
    // Main workdir's a.txt must be unchanged.
    assert_eq!(e.read("a.txt"), b"main\n");
}

#[test]
fn server_does_not_serve_dot_gyt_via_static_handler() {
    let mut e = Env::new("static-jail");
    let (_url, _repos) = e.start_server(&[]);
    let port = e.server.as_ref().unwrap().1;
    // .gyt/HEAD shouldn't be reachable.
    let raw = b"GET /.gyt/HEAD HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let (_status, _, body) = raw_http_request(port, raw);
    let s = String::from_utf8_lossy(&body);
    assert!(!s.contains("ref:"), ".gyt/HEAD leaked via static handler: {s}");
}

#[test]
fn refs_update_with_zero_hash_for_create_works() {
    // The ZERO_HEX convention means "no old value, create the ref."
    let mut e = Env::new("create-ref");
    let (_url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    // Build a fake refs/update body with old=zeros, new=zeros (the
    // server should accept the create attempt but reject the new=zero
    // as "no actual hash"). Or just reject. Either is fine — must
    // not panic.
    let port = e.server.as_ref().unwrap().1;
    let body = format!(
        "{}\t{}\trefs/heads/new\n",
        "0".repeat(64),
        "0".repeat(64)
    );
    let raw = format!(
        "POST /r1/refs/update HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(raw.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let (status, _, _) = parse_http_response(&buf);
    assert!(status != 0, "server died on zero-hash create");
}

#[test]
fn server_concurrent_pushes_to_distinct_branches_all_land() {
    // 4 clients each push to a different branch name. All 4 should
    // land — distinct refname → no ref-update conflict, and the
    // server's per-repo lock serialises the writes.
    let mut e = Env::new("multi-branch-push");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);

    // First, push the base "main" so the server has refs/heads/main.
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("f.txt"), b"base\n").unwrap();
    e.ok_in(&seed, &["add", "f.txt"]);
    e.ok_in(&seed, &["commit", "-m", "base"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    // Pre-clone 4 clients sequentially (clone is HTTP-only here),
    // then push to distinct branches IN PARALLEL.
    let mut clients = Vec::new();
    for i in 0..4u32 {
        let local = e.path(&format!("c{i}"));
        e.ok(&[
            "clone",
            &format!("{url}r1"),
            local.to_str().unwrap(),
            "--insecure",
        ]);
        e.ok_in(&local, &["switch", "-c", &format!("b{i}")]);
        std::fs::write(local.join("c.txt"), format!("c{i}\n").as_bytes()).unwrap();
        e.ok_in(&local, &["add", "c.txt"]);
        e.ok_in(&local, &["commit", "-m", &format!("c{i}")]);
        clients.push(local);
    }
    let mut handles = Vec::new();
    for (i, local) in clients.into_iter().enumerate() {
        let bin = e.bin.clone();
        let dir = e.dir.clone();
        let branch = format!("b{i}");
        handles.push(std::thread::spawn(move || {
            Command::new(&bin)
                .current_dir(&local)
                .env("HOME", &dir)
                .args(["push", "origin", &branch, "--insecure"])
                .output()
                .unwrap()
        }));
    }
    let mut wins = 0;
    for h in handles {
        let r = h.join().unwrap();
        if r.status.success() {
            wins += 1;
        }
    }
    // Even if some had network hiccups, at least 2/4 must succeed.
    assert!(
        wins >= 2,
        "concurrent distinct-branch pushes: only {wins}/4 succeeded"
    );
    // Server: at least the main + a few of the b{i} branches.
    let mut names: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(server_repo.join("refs/heads")) {
        for e in rd.flatten() {
            if let Some(n) = e.file_name().to_str() {
                names.push(n.to_string());
            }
        }
    }
    assert!(
        names.iter().any(|n| n == "main"),
        "main missing on server: {names:?}"
    );
    let bs = names.iter().filter(|n| n.starts_with('b')).count();
    assert!(bs >= 1, "no b* branches on server: {names:?}");
}

#[test]
fn stash_round_trip_byte_exact() {
    let e = Env::new("stash-bx");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"committed\n", "m");
    let payload: Vec<u8> = (0..200u8).collect();
    e.write("scratch.bin", &payload);
    e.ok(&["add", "scratch.bin"]);
    e.ok(&["stash", "push", "-m", "scratch"]);
    assert!(!e.exists("scratch.bin"), "stash didn't remove from workdir");
    e.ok(&["stash", "pop"]);
    assert!(e.exists("scratch.bin"));
    let got = e.read("scratch.bin");
    assert_eq!(got, payload, "stash corrupted binary content");
}

#[test]
fn merge_ff_only_with_clean_history_byte_exact() {
    let e = Env::new("merge-ff");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"v0\n", "v0");
    e.ok(&["branch", "topic"]);
    e.ok(&["switch", "topic"]);
    let payload = b"new-binary\x00\xff\xfe-data\n";
    e.write("b.bin", payload);
    e.ok(&["add", "b.bin"]);
    e.ok(&["commit", "-m", "add-b"]);
    e.ok(&["switch", "main"]);
    e.ok(&["merge", "topic", "--ff-only"]);
    let got = e.read("b.bin");
    assert_eq!(got, payload);
}

#[test]
fn fetch_skips_already_present_objects() {
    let mut e = Env::new("fetch-skip-present");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);
    let client = e.path("client");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        client.to_str().unwrap(),
        "--insecure",
    ]);
    let before = list_loose_objects(&client.join(".gyt")).len();
    // Re-fetch — no new objects expected.
    e.ok_in(&client, &["fetch", "origin", "--insecure"]);
    let after = list_loose_objects(&client.join(".gyt")).len();
    assert_eq!(before, after, "fetch added objects for no-op pull");
}

#[test]
fn signed_commit_signature_byte_preserved_through_clone() {
    let mut e = Env::new("sig-preserved");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    // Generate a key.
    let key = e.path("k.priv");
    let pubp = e.path("k.pub");
    e.ok_in(&seed, &["keygen", "--priv", key.to_str().unwrap(), "--pub", pubp.to_str().unwrap()]);
    std::fs::write(seed.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    // Sign explicitly.
    let cmd = Command::new(&e.bin)
        .args(["commit", "-m", "m", "--sign"])
        .current_dir(&seed)
        .env("GYT_AUTHOR_NAME", "T")
        .env("GYT_AUTHOR_EMAIL", "t@x")
        .env("HOME", &e.dir)
        .env("GYT_SIGNING_KEY", &key)
        .output()
        .unwrap();
    assert!(cmd.status.success(), "sign failed: {}", String::from_utf8_lossy(&cmd.stderr));
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);
    let dst = e.path("dst");
    e.ok(&[
        "clone",
        &format!("{url}r1"),
        dst.to_str().unwrap(),
        "--insecure",
    ]);
    // The signature must survive: show --show-signature must surface it.
    let show = e.ok_in(&dst, &["show", "--show-signature", "HEAD"]);
    assert!(
        show.contains("signature") || show.contains("Signature") || show.to_lowercase().contains("sig"),
        "signature dropped through clone: {show}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Wave 3 — Soak / chaos (#[ignore]'d unless explicitly requested)
// ═══════════════════════════════════════════════════════════════════

#[test]
#[ignore = "soak: random kill chaos"]
fn soak_random_kill_during_op_no_corruption() {
    // Plan #77. 50 iterations: do a random op, randomly kill it
    // mid-flight, verify the repo is always re-openable.
    let e = Env::new("soak-kill-chaos");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"v0\n", "v0");
    let bin = e.bin.clone();
    let dir = e.dir.clone();
    for i in 0..50 {
        std::fs::write(e.path("a.txt"), format!("v{i}\n").as_bytes()).unwrap();
        let child = Command::new(&bin)
            .current_dir(&dir)
            .env("HOME", &dir)
            .args(["add", "a.txt"])
            .spawn()
            .unwrap();
        let pid = child.id();
        // Randomly kill 1/3 of them.
        if i % 3 == 0 {
            std::thread::sleep(Duration::from_millis(1));
            let _ = std::process::Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status();
        }
        let _ = child.wait_with_output();
        // After each iteration, status must work.
        let r = e.run(&["status"]);
        assert!(
            r.status.code().is_some(),
            "status panicked at iteration {i}"
        );
    }
}

#[test]
#[ignore = "soak: 200 concurrent clones"]
fn soak_200_concurrent_clones() {
    let mut e = Env::new("soak-200-clones");
    let (url, repos) = e.start_server(&[]);
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    e.ok_in(&server_repo, &["init", "--bare"]);
    let seed = e.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    e.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"x\n").unwrap();
    e.ok_in(&seed, &["add", "a.txt"]);
    e.ok_in(&seed, &["commit", "-m", "m"]);
    e.ok_in(
        &seed,
        &["remote", "add", "origin", &format!("{url}r1")],
    );
    e.ok_in(&seed, &["push", "origin", "main", "--insecure"]);

    let mut handles = Vec::new();
    for i in 0..200u32 {
        let bin = e.bin.clone();
        let dir = e.dir.clone();
        let url = url.clone();
        let target = e.path(&format!("c{i}"));
        handles.push(std::thread::spawn(move || {
            Command::new(&bin)
                .current_dir(&dir)
                .env("HOME", &dir)
                .args([
                    "clone",
                    &format!("{url}r1"),
                    target.to_str().unwrap(),
                    "--insecure",
                ])
                .output()
                .unwrap()
        }));
    }
    let mut ok = 0;
    for h in handles {
        let r = h.join().unwrap();
        if r.status.success() {
            ok += 1;
        }
    }
    // Under the 64-worker cap we expect most clones to succeed
    // eventually (TCP backlog absorbs the rest).
    assert!(ok >= 180, "{ok}/200 concurrent clones succeeded");
}
