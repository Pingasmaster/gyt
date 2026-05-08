use crate::errors::{GytError, Result};
use std::path::{Path, PathBuf};

pub const GYT_DIR: &str = ".gyt";

/// Handle to a GYT repository, giving access to its working directory and
/// internal `.gyt/` metadata store.
#[derive(Debug, Clone)]
pub struct Repo {
    /// Root working directory for the repository.
    pub workdir: PathBuf,
    /// Path to the `.gyt/` directory within the working directory.
    pub gyt_dir: PathBuf,
}

impl Repo {
    /// Open a GYT repository by walking up from `start` to find a `.gyt/` directory.
    pub fn open(start: &Path) -> Result<Self> {
        let mut p = start.canonicalize()?;
        loop {
            let candidate = p.join(GYT_DIR);
            if candidate.is_dir() {
                return Ok(Self {
                    workdir: p,
                    gyt_dir: candidate,
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
