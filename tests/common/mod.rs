// Shared test helpers for the May 2026 audit batch's new test files.
// Imported via `#[path = "common/mod.rs"] mod common;` in each test file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    dead_code,
    reason = "test helpers — not every test file uses every helper"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

pub static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

pub fn find_binary() -> PathBuf {
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
    panic!("gyt binary not found")
}

pub fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

pub struct Env {
    pub bin: PathBuf,
    pub dir: PathBuf,
}

impl Env {
    pub fn new(label: &str) -> Self {
        let bin = find_binary();
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("gyt-{label}-{pid}-{id}-{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { bin, dir }
    }
    pub fn path(&self, n: &str) -> PathBuf {
        self.dir.join(n)
    }
    pub fn cmd_in(&self, cwd: &Path) -> Command {
        let mut c = Command::new(&self.bin);
        c.current_dir(cwd)
            .env("GYT_AUTHOR_NAME", "Audit User")
            .env("GYT_AUTHOR_EMAIL", "audit@example.com")
            .env("HOME", &self.dir)
            .env_remove("XDG_CONFIG_HOME");
        c
    }
    pub fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        self.cmd_in(cwd).args(args).output().unwrap()
    }
    #[track_caller]
    pub fn ok_in(&self, cwd: &Path, args: &[&str]) -> String {
        let o = self.cmd_in(cwd).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "gyt {} failed in {}:\nstdout: {}\nstderr: {}",
            args.join(" "),
            cwd.display(),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
    #[track_caller]
    pub fn fail_in(&self, cwd: &Path, args: &[&str]) -> (String, String) {
        let o = self.cmd_in(cwd).args(args).output().unwrap();
        assert!(!o.status.success(), "gyt {} unexpectedly succeeded", args.join(" "));
        (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }
    pub fn fresh_repo(&self, label: &str) -> PathBuf {
        let r = self.path(label);
        std::fs::create_dir_all(&r).unwrap();
        self.ok_in(&r, &["init"]);
        std::fs::write(r.join("seed.txt"), b"seed\n").unwrap();
        self.ok_in(&r, &["add", "seed.txt"]);
        self.ok_in(&r, &["commit", "-m", "seed"]);
        r
    }
}
