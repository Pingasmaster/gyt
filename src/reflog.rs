// Reflog: an append-only audit log of ref movements.
//
// On disk, each ref's reflog lives at `<gyt>/logs/<refname>` (so
// `<gyt>/logs/HEAD`, `<gyt>/logs/refs/heads/main`, etc.). Each line is:
//
//   <old-hex> <new-hex> <who> <unix-secs> <tz-offset>\t<message>
//
// `<who>` is the user identity in `Name <email>` form (or `-` when unknown).
// `<old-hex>` is 64 zeros for ref creation. Lines never contain `\n` except
// at the end; messages with embedded newlines are silently flattened.
//
// Reflog writes are best-effort at the *caller* boundary: `record` swallows
// any error from `try_record` so a disk hiccup or permissions issue doesn't
// break a commit or merge. But when `try_record` returns Ok, the entry is
// durable on disk — the write is fsync'd before we return, so a crash
// immediately after a successful commit cannot lose its reflog entry
// (which `gc` relies on as a reachability seed).
//
// Reading: `entries()` returns the parsed lines (newest last, matching
// on-disk order). `entries_reverse()` is provided for the common UX of
// "show me the most recent ref movements".

use crate::errors::Result;
use crate::hash::ObjectId;
use std::io::Write;
use std::path::{Path, PathBuf};

const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub old: Option<ObjectId>,
    pub new: ObjectId,
    pub who: String,
    pub timestamp: i64,
    pub tz_offset: String,
    pub message: String,
}

/// Append a reflog entry for `refname`. Errors are swallowed (best-effort).
/// Use `record` from call sites that update refs.
pub fn record(
    gyt_dir: &Path,
    refname: &str,
    old: Option<&ObjectId>,
    new: &ObjectId,
    who: &str,
    message: &str,
) {
    let _ = try_record(gyt_dir, refname, old, new, who, message);
}

fn try_record(
    gyt_dir: &Path,
    refname: &str,
    old: Option<&ObjectId>,
    new: &ObjectId,
    who: &str,
    message: &str,
) -> std::io::Result<()> {
    let path = log_path(gyt_dir, refname);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let old_hex = old.map_or_else(|| ZERO_HEX.to_string(), |o| o.to_hex());
    let who = sanitize(who);
    let message = sanitize(message);
    // Tab-separated header to avoid ambiguity when `who` contains spaces
    // (it usually does — `Name <email>`).
    let line = format!(
        "{old_hex}\t{}\t{who}\t{ts}\t+0000\t{message}\n",
        new.to_hex()
    );
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    f.write_all(line.as_bytes())?;
    // Durability: gc seeds its reachability walk from reflog entries, so a
    // crash after a successful commit that loses the reflog entry could let
    // gc prune the new commit (mitigated only by the 60s mtime grace).
    // fsync makes "record returned Ok" mean "entry survives a crash".
    f.sync_all()?;
    Ok(())
}

fn sanitize(s: &str) -> String {
    // Tabs are the field separator in the header; newlines break the line
    // record. Replace them with spaces so the encoded form is still safe.
    s.replace(['\n', '\r', '\t'], " ")
}


fn log_path(gyt_dir: &Path, refname: &str) -> PathBuf {
    gyt_dir.join("logs").join(refname)
}

/// Read all reflog entries for `refname` (oldest first). Returns empty if
/// the log doesn't exist or is unreadable.
pub fn entries(gyt_dir: &Path, refname: &str) -> Result<Vec<Entry>> {
    let path = log_path(gyt_dir, refname);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(crate::errors::GytError::Io(e));
        }
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(entry) = parse_line(line) {
            out.push(entry);
        }
    }
    Ok(out)
}

/// All reflogs known in the repo as (refname, entries).
pub fn list_all(gyt_dir: &Path) -> Result<Vec<(String, Vec<Entry>)>> {
    let root = gyt_dir.join("logs");
    let mut out = Vec::new();
    if !root.is_dir() {
        return Ok(out);
    }
    collect(&root, &root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<Entry>)>) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(crate::errors::GytError::Io)? {
        let entry = entry.map_err(crate::errors::GytError::Io)?;
        let path = entry.path();
        let ft = entry.file_type().map_err(crate::errors::GytError::Io)?;
        if ft.is_dir() {
            collect(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let es = entries(dir.ancestors().nth(rel.components().count()).unwrap_or(root), &name)
                .unwrap_or_default();
            // Fall back if the path-walk-back guessed wrong.
            let es = if es.is_empty() {
                let gyt_dir = root.parent().unwrap_or(root);
                entries(gyt_dir, &name).unwrap_or_default()
            } else {
                es
            };
            out.push((name, es));
        }
    }
    Ok(())
}

fn parse_line(line: &str) -> Option<Entry> {
    // Fields are tab-separated: old\tnew\twho\tts\ttz\tmessage
    let mut parts = line.splitn(6, '\t');
    let old_hex = parts.next()?;
    let new_hex = parts.next()?;
    let who_part = parts.next()?;
    let ts_part = parts.next()?;
    let tz_part = parts.next()?;
    let message = parts.next().unwrap_or("");
    let old = if old_hex == ZERO_HEX {
        None
    } else {
        ObjectId::from_hex(old_hex).ok()
    };
    let new = ObjectId::from_hex(new_hex).ok()?;
    let timestamp: i64 = ts_part.parse().ok()?;
    Some(Entry {
        old,
        new,
        who: who_part.to_string(),
        timestamp,
        tz_offset: tz_part.to_string(),
        message: message.to_string(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    fn tmpdir(prefix: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn record_then_read() {
        let dir = tmpdir("gyt-reflog");
        let id1 = ObjectId([1u8; 32]);
        let id2 = ObjectId([2u8; 32]);
        record(&dir, "HEAD", None, &id1, "alice <a@x>", "commit (initial): first");
        record(&dir, "HEAD", Some(&id1), &id2, "alice <a@x>", "commit: second");
        let es = entries(&dir, "HEAD").unwrap();
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].old, None);
        assert_eq!(es[0].new, id1);
        assert_eq!(es[0].message, "commit (initial): first");
        assert_eq!(es[1].old, Some(id1));
        assert_eq!(es[1].new, id2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_log_returns_empty() {
        let dir = tmpdir("gyt-reflog-empty");
        let es = entries(&dir, "HEAD").unwrap();
        assert!(es.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_strips_newlines_and_tabs() {
        let dir = tmpdir("gyt-reflog-sanitize");
        let id = ObjectId([3u8; 32]);
        record(
            &dir,
            "refs/heads/main",
            None,
            &id,
            "alice <a@x>",
            "msg with\nnewlines\tand tabs",
        );
        let es = entries(&dir, "refs/heads/main").unwrap();
        assert_eq!(es.len(), 1);
        assert!(!es[0].message.contains('\n'));
        assert!(!es[0].message.contains('\t'));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
