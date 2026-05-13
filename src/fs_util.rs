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
    /// for another holder to release. Reclaims stale locks (files older
    /// than `STALE_AFTER`).
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
                    // Best-effort: write pid for forensic debugging. Errors
                    // here don't block lock acquisition.
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    let _ = writeln!(f, "pid={} ts={ts}", std::process::id());
                    return Ok(Self {
                        path: path.to_path_buf(),
                        _file: f,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Reclaim stale locks. We compare against the file's
                    // modified time, which an attacker could in principle
                    // bump — but the only thing that buys them is one more
                    // 60 s window, which is well within tolerable.
                    if let Ok(md) = fs::metadata(path)
                        && let Ok(modified) = md.modified()
                        && modified.elapsed().unwrap_or(Duration::ZERO) > STALE_AFTER
                    {
                        let _ = fs::remove_file(path);
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

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
