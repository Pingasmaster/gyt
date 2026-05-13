use crate::errors::{GytError, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp.{}",
        path.extension().and_then(|s| s.to_str()).unwrap_or(""),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_all(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

/// Cross-process mutex implemented as an O_EXCL lockfile. Holding a
/// `FileLock` guarantees that no other process holding the same lock path
/// can simultaneously exist. Release happens on `Drop`.
///
/// Tested on Unix where `OpenOptions::create_new` maps to `O_EXCL`. On
/// Windows the equivalent semantics apply (file creation is exclusive).
///
/// This is intentionally simple — no fairness, no shared-mode, no deadlock
/// detection — because the lockfile is held only across short ref-update
/// sequences (read-old-ref, FF check, signature check, atomic_write).
/// Stale locks left behind by a crashed process are detected by the
/// `STALE_AFTER` timeout: any lockfile older than that is reclaimed.
pub struct FileLock {
    path: PathBuf,
    // Carry the file handle so future hardening (writing pid + timestamp)
    // can extend this without changing the API.
    _file: fs::File,
}

const STALE_AFTER: Duration = Duration::from_mins(1);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

impl FileLock {
    /// Acquire `path` exclusively. Blocks (with polling) up to `timeout`
    /// for another holder to release. Reclaims stale locks safely.
    ///
    /// Stale-lock reclamation is the tricky part: a crashed holder leaves
    /// a lockfile behind that no one will ever remove, so we have to be
    /// willing to delete it eventually — but a naive "older than N
    /// seconds → delete" check has a TOCTOU window where a legitimate
    /// holder releases and a new holder acquires between our stat and
    /// our unlink, and we wipe the new holder's live lock.
    ///
    /// Our defense: when we observe a stale lockfile, we read the pid we
    /// recorded into it on acquisition, *then* re-stat and re-read after
    /// a tiny sleep. We only `remove_file` if both observations report
    /// the same pid AND both still claim the file is old. That gives a
    /// fresh acquirer (who wrote a new pid) the chance to fail the check
    /// and survive.
    pub fn acquire(path: &Path, timeout: Duration) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
            {
                Ok(mut f) => {
                    // Record pid + timestamp so a future acquirer that
                    // suspects this lock is stale can confirm the holder
                    // hasn't churned.
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    // Errors here don't block lock acquisition — the file
                    // exists and is held by us; an empty body just makes
                    // future stale-reclamation slightly more conservative.
                    let _ = writeln!(f, "pid={} ts={ts}", std::process::id());
                    let _ = f.sync_all();
                    return Ok(Self {
                        path: path.to_path_buf(),
                        _file: f,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if try_reclaim_stale(path)? {
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(GytError::Repo(format!(
                            "could not acquire lock {} within {timeout:?}",
                            path.display()
                        )));
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(e) => return Err(GytError::Io(e)),
            }
        }
    }
}

/// Return `true` if we successfully reclaimed a stale lock at `path`.
/// "Stale" requires *all three* of:
///   1. The recorded pid is no longer alive (or the file has no pid).
///   2. The file's mtime is older than `STALE_AFTER`.
///   3. A small re-check 10 ms later reports the same pid and same mtime
///      — i.e. nobody's actively using this lock right now.
fn try_reclaim_stale(path: &Path) -> Result<bool> {
    let (pid1, mtime1) = match read_lock_marker(path) {
        Some(m) => m,
        None => return Ok(false),
    };
    if mtime1.elapsed().unwrap_or(Duration::ZERO) <= STALE_AFTER {
        return Ok(false);
    }
    if let Some(pid) = pid1
        && pid_alive(pid)
    {
        return Ok(false);
    }
    // Brief re-check. If pid/mtime changed in the meantime, a fresh
    // holder has acquired this lock; back off.
    std::thread::sleep(Duration::from_millis(10));
    let (pid2, mtime2) = match read_lock_marker(path) {
        Some(m) => m,
        None => return Ok(false),
    };
    if pid1 != pid2 || mtime1 != mtime2 {
        return Ok(false);
    }
    // Best-effort delete; if it races with someone else's unlink, the
    // next `create_new` attempt will simply succeed.
    let _ = fs::remove_file(path);
    Ok(true)
}

/// Read `(pid, mtime)` from a lockfile. Returns None if the file is gone
/// or its contents can't be parsed.
fn read_lock_marker(path: &Path) -> Option<(Option<u32>, std::time::SystemTime)> {
    let md = fs::metadata(path).ok()?;
    let mtime = md.modified().ok()?;
    let body = fs::read_to_string(path).ok().unwrap_or_default();
    // Look for "pid=<n>" anywhere in the body.
    let pid = body
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("pid="))
        .and_then(|s| s.parse::<u32>().ok());
    Some((pid, mtime))
}

/// True if the given pid is alive on this host. We can't shell out to
/// libc::kill(pid, 0) (no libc policy), so we use `/proc/<pid>` —
/// available on Linux and on macOS with `/proc` mounted. When `/proc`
/// itself isn't present we conservatively report "alive" so we never
/// reclaim a lock we can't verify; when `/proc` is present and a
/// specific pid's entry is missing, the process is dead.
fn pid_alive(pid: u32) -> bool {
    if !std::path::Path::new("/proc").is_dir() {
        // We can't introspect — assume alive so stale reclamation never
        // accidentally deletes a real holder's lock on this platform.
        return true;
    }
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
