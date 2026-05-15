use crate::errors::{GytError, Result};
use std::path::{Path, PathBuf};

pub const GYT_DIR: &str = ".gyt";

/// Handle to a GYT repository, giving access to its working directory and
/// internal `.gyt/` metadata store.
///
/// Two layouts are recognized:
/// * **Non-bare**: a working tree at `<workdir>` with metadata in
///   `<workdir>/.gyt/`. `Repo::open` walks up to find this.
/// * **Bare** (created by `gyt init --bare`): the gyt layout lives
///   directly at `<workdir>` — there's no `.gyt/` subdir, and `bare`
///   marker file at the root tags it. For bare repos `workdir == gyt_dir`
///   and the `is_bare` flag is set; commands that require a working tree
///   (add, status, switch, …) should refuse.
#[derive(Debug, Clone)]
pub struct Repo {
    /// Root working directory for the repository. For a bare repo this
    /// equals `gyt_dir`.
    pub workdir: PathBuf,
    /// Path to the gyt metadata directory. For a non-bare repo this is
    /// `<workdir>/.gyt`; for a bare repo it is `<workdir>` itself.
    pub gyt_dir: PathBuf,
    /// True when the repository has no working tree.
    pub is_bare: bool,
}

impl Repo {
    /// Open a GYT repository.
    ///
    /// Looks first for a non-bare layout (walks up from `start` to find a
    /// `.gyt/` directory). If `start` itself contains a bare layout
    /// (a `HEAD` file + `objects/` directory alongside a `bare` marker),
    /// it's opened as bare.
    pub fn open(start: &Path) -> Result<Self> {
        let mut p = start.canonicalize()?;
        // Bare layout check at `start` (no walk-up — bare repos are
        // explicitly addressed by path, never inferred via ancestry).
        if Self::looks_bare(&p) {
            return Ok(Self {
                workdir: p.clone(),
                gyt_dir: p,
                is_bare: true,
            });
        }
        loop {
            let candidate = p.join(GYT_DIR);
            if candidate.is_dir() {
                return Ok(Self {
                    workdir: p,
                    gyt_dir: candidate,
                    is_bare: false,
                });
            }
            // Also accept the bare layout at every level walked, so
            // `gyt log` inside e.g. `/srv/myrepo.gyt/objects/` still
            // finds the repo at `/srv/myrepo.gyt/`.
            if Self::looks_bare(&p) {
                return Ok(Self {
                    workdir: p.clone(),
                    gyt_dir: p,
                    is_bare: true,
                });
            }
            if !p.pop() {
                return Err(GytError::Repo(format!(
                    "no .gyt directory found from {}",
                    start.display()
                )));
            }
        }
    }

    /// True if `p` has the on-disk layout of a bare repo: `HEAD` regular
    /// file *and* `objects/` directory directly inside. We deliberately
    /// don't require the `bare` marker file — older bare repos may
    /// predate that — but we use both checks together as a strong tell.
    fn looks_bare(p: &Path) -> bool {
        p.join("HEAD").is_file() && p.join("objects").is_dir() && p.join("refs").is_dir()
    }

    /// Error out if the caller is about to touch the working tree on a
    /// bare repo. Commands that read history (log, show, diff between
    /// commits, …) can still run; commands like add / status / switch
    /// / restore must reject this case.
    pub fn require_worktree(&self) -> Result<()> {
        if self.is_bare {
            return Err(GytError::Repo(
                "this is a bare repository (no working tree)".into(),
            ));
        }
        Ok(())
    }

    /// Acquire an exclusive cross-process lock on the repository. Hold
    /// for the duration of any operation that updates refs (commit,
    /// reset, merge, rebase, cherry-pick, tag, branch, switch, …) so
    /// two concurrent CLI processes can't race against each other. The
    /// server uses the same lock file via `wire_refs_update`, so server
    /// pushes and local CLI writes also serialize cleanly.
    ///
    /// The lock file lives at `<gyt>/refs.lock`. Callers should bind the
    /// returned `FileLock` to a `let _lock = ...` so it drops at end of
    /// scope.
    pub fn lock(&self) -> Result<crate::fs_util::FileLock> {
        crate::fs_util::FileLock::acquire(
            &self.gyt_dir.join("refs.lock"),
            std::time::Duration::from_secs(10),
        )
    }

    /// Object-store lock. Separate from `lock()` (the refs lock) so a
    /// long gc pass holding the refs lock for the reachability walk
    /// doesn't prevent concurrent uploads from streaming new loose
    /// objects in — but the *prune* phase of gc and every loose-object
    /// write *do* serialize against each other.
    ///
    /// Without this, the `gc` race documented in CLAUDE.md is real: a
    /// push that wrote a loose object during the gc walk would have it
    /// reclaimed before the push's refs/update lands, leaving a
    /// dangling ref on the server. With `objects.lock` held during the
    /// prune, the prune cannot observe a half-written loose object;
    /// combined with the mtime grace below it cannot reclaim an object
    /// the pusher is about to reference.
    pub fn objects_lock(&self) -> Result<crate::fs_util::FileLock> {
        crate::fs_util::FileLock::acquire(
            &self.gyt_dir.join("objects.lock"),
            std::time::Duration::from_secs(30),
        )
    }

    /// Path to the `.gyt/objects` directory.
    #[allow(dead_code)]
    pub fn objects_dir(&self) -> PathBuf {
        self.gyt_dir.join("objects")
    }

    /// Path to the `.gyt/refs` directory.
    #[allow(dead_code)]
    pub fn refs_dir(&self) -> PathBuf {
        self.gyt_dir.join("refs")
    }

    /// Path to the `.gyt/HEAD` file.
    #[allow(dead_code)]
    pub fn head_path(&self) -> PathBuf {
        self.gyt_dir.join("HEAD")
    }

    /// Path to the index file inside the `.gyt/` directory.
    pub fn index_path(&self) -> PathBuf {
        self.gyt_dir.join("index")
    }
}
