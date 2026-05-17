// Ref read/write/resolve.
//
// On-disk layout under `<repo>/.gyt/`:
//   HEAD                                 -- "ref: refs/heads/<name>\n" or "blake3:<hex>\n"
//   refs/heads/<name>                    -- "<hex>\n"
//   refs/tags/<name>                     -- "<hex>\n"
//   refs/remotes/<remote>/<name>         -- "<hex>\n"

use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::{HEX_LEN, ObjectId};
use std::path::{Path, PathBuf};

/// Current state of HEAD — either pointing at a symbolic ref or a detached commit.
#[derive(Debug, Clone)]
pub enum Head {
    /// HEAD points to a symbolic reference like `refs/heads/main`.
    Symbolic(String),
    /// HEAD is detached at the given ObjectId.
    Detached(ObjectId),
}

const HEAD_REF_PREFIX: &str = "ref: ";
const HEAD_DETACHED_PREFIX: &str = "blake3:";

/// Maximum total byte length of a ref name. Below `PATH_MAX` (4096 on
/// Linux) with room for the gyt_dir prefix in `ref_path`.
pub const MAX_REF_NAME_LEN: usize = 255;

/// Validate a ref name. Single chokepoint for the wire-side and disk-
/// side validators alike. Made `pub` so `net::refs_policy` can call it
/// before any `gyt_dir.join(name)` happens at request time
/// (closes F-D1-01 path traversal and F-D1-03 audit-log injection).
///
/// Rejects:
/// - empty / length > MAX_REF_NAME_LEN
/// - leading / trailing '/'
/// - components equal to `.`, `..`, or empty
/// - any byte < 0x20 or == 0x7f  (closes audit-log newline injection)
/// - backslash (Windows FUSE / NTFS path separator)
/// - components ending in `.lock`
/// - any `..` substring (defense in depth)
pub fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(GytError::Refs("empty ref name".into()));
    }
    if name.len() > MAX_REF_NAME_LEN {
        return Err(GytError::Refs(format!(
            "ref name length {} exceeds {MAX_REF_NAME_LEN}",
            name.len()
        )));
    }
    if name.starts_with('/') {
        return Err(GytError::Refs(format!(
            "ref name must not start with '/': {name:?}"
        )));
    }
    if name.ends_with('/') {
        return Err(GytError::Refs(format!(
            "ref name must not end with '/': {name:?}"
        )));
    }
    for b in name.bytes() {
        if b < 0x20 || b == 0x7f {
            return Err(GytError::Refs(format!(
                "ref name contains control byte {b:#x}: {name:?}"
            )));
        }
        if b == b'\\' {
            return Err(GytError::Refs(format!(
                "ref name contains backslash: {name:?}"
            )));
        }
    }
    for comp in name.split('/') {
        if comp.is_empty() {
            return Err(GytError::Refs(format!(
                "ref name has empty component: {name:?}"
            )));
        }
        if comp == ".." || comp == "." {
            return Err(GytError::Refs(format!(
                "ref name has '..' or '.' component: {name:?}"
            )));
        }
        // Case-insensitive: case-insensitive filesystems (e.g. APFS,
        // exFAT, Windows NTFS by default) treat `.LOCK` and `.lock` as
        // the same file, so a `.LOCK`-suffixed refname would still
        // shadow a real lockfile.
        let cb = comp.as_bytes();
        if let Some(tail) = cb.get(cb.len().saturating_sub(5)..)
            && tail.eq_ignore_ascii_case(b".lock")
            && cb.len() >= 5
        {
            return Err(GytError::Refs(format!(
                "ref name component ends in .lock: {name:?}"
            )));
        }
    }
    if name.contains("..") {
        return Err(GytError::Refs(format!("ref name contains '..': {name:?}")));
    }
    Ok(())
}

fn ref_path(repo_gyt_dir: &Path, name: &str) -> Result<PathBuf> {
    validate_ref_name(name)?;
    Ok(repo_gyt_dir.join(name))
}

/// Read the HEAD file from the repository's `.gyt/` directory.
pub fn read_head(repo_gyt_dir: &Path) -> Result<Head> {
    let p = repo_gyt_dir.join("HEAD");
    if !p.exists() {
        return Err(GytError::Refs(format!("HEAD not found at {}", p.display())));
    }
    let bytes = fs_util::read_all(&p)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| GytError::Refs("HEAD is not valid utf-8".into()))?;
    let line = text.trim_end_matches(['\n', '\r']);

    if let Some(rest) = line.strip_prefix(HEAD_REF_PREFIX) {
        let target = rest.trim();
        validate_ref_name(target)?;
        return Ok(Head::Symbolic(target.to_string()));
    }
    if let Some(rest) = line.strip_prefix(HEAD_DETACHED_PREFIX) {
        let hex = rest.trim();
        if hex.len() != HEX_LEN {
            return Err(GytError::Refs(format!(
                "HEAD detached hash has wrong length: {}",
                hex.len()
            )));
        }
        let id = ObjectId::from_hex(hex)
            .map_err(|e| GytError::Refs(format!("HEAD detached hash invalid: {e}")))?;
        return Ok(Head::Detached(id));
    }
    Err(GytError::Refs(format!("malformed HEAD: {line:?}")))
}

/// Write HEAD to the repository's `.gyt/` directory.
pub fn write_head(repo_gyt_dir: &Path, head: &Head) -> Result<()> {
    let p = repo_gyt_dir.join("HEAD");
    let body = match head {
        Head::Symbolic(name) => {
            validate_ref_name(name)?;
            format!("{HEAD_REF_PREFIX}{name}\n")
        }
        Head::Detached(id) => format!("{HEAD_DETACHED_PREFIX}{}\n", id.to_hex()),
    };
    fs_util::atomic_write(&p, body.as_bytes())
}

/// Read the ObjectId pointed to by a ref (e.g. `refs/heads/main`).
pub fn read_ref(repo_gyt_dir: &Path, name: &str) -> Result<ObjectId> {
    let p = ref_path(repo_gyt_dir, name)?;
    // M4: refuse symlinked refs — a planted symlink would let a
    // 64-hex-shaped file outside `.gyt/` be accepted as the ref tip.
    let meta = std::fs::symlink_metadata(&p)
        .map_err(|_| GytError::Refs(format!("ref {name} not found")))?;
    if meta.file_type().is_symlink() {
        return Err(GytError::Refs(format!(
            "ref {name} is a symlink (refusing to follow)"
        )));
    }
    let bytes = fs_util::read_all(&p)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| GytError::Refs(format!("ref {name} is not valid utf-8")))?;
    let hex = text.trim();
    if hex.len() != HEX_LEN {
        return Err(GytError::Refs(format!(
            "ref {name} hash has wrong length: {}",
            hex.len()
        )));
    }
    ObjectId::from_hex(hex).map_err(|e| GytError::Refs(format!("ref {name} parse error: {e}")))
}

/// Write an ObjectId into a ref (e.g. `refs/heads/main`).
pub fn write_ref(repo_gyt_dir: &Path, name: &str, id: &ObjectId) -> Result<()> {
    let p = ref_path(repo_gyt_dir, name)?;
    let body = format!("{}\n", id.to_hex());
    fs_util::atomic_write(&p, body.as_bytes())
}

pub fn delete_ref(repo_gyt_dir: &Path, name: &str) -> Result<()> {
    let p = ref_path(repo_gyt_dir, name)?;
    if !p.exists() {
        return Err(GytError::Refs(format!("ref {name} not found")));
    }
    std::fs::remove_file(&p)?;
    // fsync the containing directory so the unlink survives a power
    // loss. Without this, on ext4/xfs the ref file can re-appear after
    // a crash even though the application observed the delete succeed.
    // Best-effort: on platforms where opening a directory for sync
    // fails (some non-Unix targets) we accept the weaker durability
    // rather than fail the user's `gyt branch -d` call. Mirrors the
    // pattern fs_util::atomic_write uses for renames.
    if let Some(parent) = p.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn list_refs(repo_gyt_dir: &Path, prefix: &str) -> Result<Vec<(String, ObjectId)>> {
    validate_ref_name(prefix)?;
    let root = repo_gyt_dir.join(prefix);
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    walk(&root, prefix, repo_gyt_dir, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[expect(clippy::only_used_in_recursion, reason = "parameter threads recursion state, used to keep the signature stable")]
fn walk(
    dir: &Path,
    prefix: &str,
    repo_gyt_dir: &Path,
    out: &mut Vec<(String, ObjectId)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(&path, prefix, repo_gyt_dir, out)?;
        } else if ft.is_file() {
            // Reconstruct ref name from path relative to repo_gyt_dir.
            let rel = path.strip_prefix(repo_gyt_dir).map_err(|_| {
                GytError::Refs(format!(
                    "ref path {} not under repo {}",
                    path.display(),
                    repo_gyt_dir.display()
                ))
            })?;
            // Convert to forward-slash string.
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            // Skip files whose name is not a valid ref name. The big
            // case this catches: `atomic_write` writes a sibling tmp
            // file like `refs/heads/main..tmp.<pid>.<tid>.<seq>` and
            // briefly leaves it in the directory before renaming over
            // the target. The double-dot would make the whole listing
            // fail (`..` is rejected by `validate_ref_name`) and the
            // server's /info/refs would 500 for the duration of every
            // concurrent push. Filtering invalid names here keeps the
            // listing well-formed and stops a phantom tmp ref from
            // ever leaving the server.
            if validate_ref_name(&name).is_err() {
                continue;
            }
            // The same atomic_write rename window can also delete the
            // sibling file between our `read_dir` snapshot and our
            // `read_ref` open. Drop those rather than failing the
            // entire listing.
            let id = match read_ref(repo_gyt_dir, &name) {
                Ok(id) => id,
                Err(GytError::Refs(_)) => continue,
                Err(e) => return Err(e),
            };
            out.push((name, id));
        }
    }
    Ok(())
}

pub fn resolve(repo_gyt_dir: &Path, head: &Head) -> Result<Option<ObjectId>> {
    match head {
        Head::Detached(id) => Ok(Some(*id)),
        Head::Symbolic(name) => {
            let p = ref_path(repo_gyt_dir, name)?;
            if !p.exists() {
                return Ok(None);
            }
            Ok(Some(read_ref(repo_gyt_dir, name)?))
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::hash::HASH_LEN;

    fn dummy_id(byte: u8) -> ObjectId {
        ObjectId([byte; HASH_LEN])
    }

    fn setup() -> (tempdir::Dir, PathBuf) {
        let t = tempdir::Dir::new("gyt-refs");
        let gyt = t.path().join(".gyt");
        std::fs::create_dir_all(gyt.join("refs/heads")).unwrap();
        std::fs::create_dir_all(gyt.join("refs/tags")).unwrap();
        std::fs::create_dir_all(gyt.join("refs/remotes")).unwrap();
        (t, gyt)
    }

    #[test]
    fn head_round_trip_symbolic() {
        let (_t, gyt) = setup();
        write_head(&gyt, &Head::Symbolic("refs/heads/main".into())).unwrap();
        match read_head(&gyt).unwrap() {
            Head::Symbolic(s) => assert_eq!(s, "refs/heads/main"),
            other @ Head::Detached(_) => panic!("expected symbolic, got {other:?}"),
        }
        // Verify file content exactly.
        let body = std::fs::read_to_string(gyt.join("HEAD")).unwrap();
        assert_eq!(body, "ref: refs/heads/main\n");
    }

    #[test]
    fn head_round_trip_detached() {
        let (_t, gyt) = setup();
        let id = dummy_id(0xab);
        write_head(&gyt, &Head::Detached(id)).unwrap();
        match read_head(&gyt).unwrap() {
            Head::Detached(got) => assert_eq!(got, id),
            other @ Head::Symbolic(_) => panic!("expected detached, got {other:?}"),
        }
        let body = std::fs::read_to_string(gyt.join("HEAD")).unwrap();
        assert_eq!(body, format!("blake3:{}\n", id.to_hex()));
    }

    #[test]
    fn unborn_head_resolves_to_none() {
        let (_t, gyt) = setup();
        write_head(&gyt, &Head::Symbolic("refs/heads/main".into())).unwrap();
        let head = read_head(&gyt).unwrap();
        let resolved = resolve(&gyt, &head).unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn read_write_branch_ref() {
        let (_t, gyt) = setup();
        let id = dummy_id(0x42);
        write_ref(&gyt, "refs/heads/main", &id).unwrap();
        let got = read_ref(&gyt, "refs/heads/main").unwrap();
        assert_eq!(got, id);
        // Resolve via symbolic HEAD.
        write_head(&gyt, &Head::Symbolic("refs/heads/main".into())).unwrap();
        let head = read_head(&gyt).unwrap();
        assert_eq!(resolve(&gyt, &head).unwrap(), Some(id));
    }

    #[test]
    fn list_refs_returns_branches() {
        let (_t, gyt) = setup();
        write_ref(&gyt, "refs/heads/main", &dummy_id(1)).unwrap();
        write_ref(&gyt, "refs/heads/feature", &dummy_id(2)).unwrap();
        write_ref(&gyt, "refs/heads/nested/topic", &dummy_id(3)).unwrap();
        write_ref(&gyt, "refs/tags/v1", &dummy_id(4)).unwrap();

        let heads = list_refs(&gyt, "refs/heads").unwrap();
        let names: Vec<&str> = heads.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "refs/heads/feature",
                "refs/heads/main",
                "refs/heads/nested/topic"
            ]
        );
        // Sanity: contents match.
        assert_eq!(
            heads
                .iter()
                .find(|(n, _)| n == "refs/heads/feature")
                .unwrap()
                .1,
            dummy_id(2)
        );
    }

    #[test]
    fn delete_ref_removes_file() {
        let (_t, gyt) = setup();
        write_ref(&gyt, "refs/heads/tmp", &dummy_id(5)).unwrap();
        assert!(gyt.join("refs/heads/tmp").exists());
        delete_ref(&gyt, "refs/heads/tmp").unwrap();
        assert!(!gyt.join("refs/heads/tmp").exists());
        // Deleting again is an error.
        assert!(delete_ref(&gyt, "refs/heads/tmp").is_err());
    }

    #[test]
    fn rejects_invalid_ref_name() {
        let (_t, gyt) = setup();
        let id = dummy_id(0);
        // Empty.
        assert!(write_ref(&gyt, "", &id).is_err());
        // Leading slash.
        assert!(write_ref(&gyt, "/refs/heads/main", &id).is_err());
        // ".." component.
        assert!(write_ref(&gyt, "refs/../heads/main", &id).is_err());
        // Empty component.
        assert!(write_ref(&gyt, "refs//heads/main", &id).is_err());
        // Trailing slash.
        assert!(write_ref(&gyt, "refs/heads/", &id).is_err());
    }

    #[test]
    fn rejects_malformed_head() {
        let (_t, gyt) = setup();
        std::fs::write(gyt.join("HEAD"), b"garbage\n").unwrap();
        let err = read_head(&gyt).unwrap_err();
        match err {
            GytError::Refs(_) => {}
            other => panic!("expected Refs error, got {other:?}"),
        }
    }

    #[test]
    fn read_head_missing_is_error() {
        let (_t, gyt) = setup();
        // No HEAD written.
        assert!(read_head(&gyt).is_err());
    }

    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new(prefix: &str) -> Self {
                let pid = std::process::id();
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.subsec_nanos());
                let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
