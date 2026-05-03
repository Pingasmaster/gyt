// GYTI v1 binary index. Real implementation lands in Phase 3a.
// magic "GYTI" u32 LE + version u32 + entry_count u32 + entries.

use crate::errors::Result;
use crate::hash::ObjectId;
use std::path::PathBuf;

pub const MAGIC: &[u8; 4] = b"GYTI";
pub const VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub ctime_secs: i64,
    pub mtime_secs: i64,
    pub size: u64,
    pub mode: u32,
    pub hash: ObjectId,
    pub path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Index {
    pub entries: Vec<IndexEntry>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&self, _path: &std::path::Path) -> Result<()> {
        unimplemented!("phase 3a")
    }

    pub fn read(_path: &std::path::Path) -> Result<Self> {
        unimplemented!("phase 3a")
    }
}
