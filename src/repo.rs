use crate::errors::{GytError, Result};
use std::path::{Path, PathBuf};

pub const GYT_DIR: &str = ".gyt";

#[derive(Debug, Clone)]
pub struct Repo {
    pub workdir: PathBuf,
    pub gyt_dir: PathBuf,
}

impl Repo {
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

    pub fn objects_dir(&self) -> PathBuf {
        self.gyt_dir.join("objects")
    }

    pub fn refs_dir(&self) -> PathBuf {
        self.gyt_dir.join("refs")
    }

    pub fn head_path(&self) -> PathBuf {
        self.gyt_dir.join("HEAD")
    }

    pub fn index_path(&self) -> PathBuf {
        self.gyt_dir.join("index")
    }
}
