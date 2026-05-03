// Working tree scan + status. Real implementation lands in Phase 3c.

#[derive(Debug, Default)]
pub struct WorkdirEntry {
    pub path: std::path::PathBuf,
    pub is_dir: bool,
}

pub mod diff {
    pub struct Hunk;
}
