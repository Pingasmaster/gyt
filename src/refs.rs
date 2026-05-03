// Ref read/write/resolve. Real implementation lands in Phase 3a.

use crate::errors::Result;
use crate::hash::ObjectId;

#[derive(Debug, Clone)]
pub enum Head {
    Symbolic(String),
    Detached(ObjectId),
}

pub fn read_head(_repo: &std::path::Path) -> Result<Head> {
    unimplemented!("phase 3a")
}

pub fn write_head(_repo: &std::path::Path, _head: &Head) -> Result<()> {
    unimplemented!("phase 3a")
}

pub fn read_ref(_repo: &std::path::Path, _name: &str) -> Result<ObjectId> {
    unimplemented!("phase 3a")
}

pub fn write_ref(_repo: &std::path::Path, _name: &str, _id: &ObjectId) -> Result<()> {
    unimplemented!("phase 3a")
}
