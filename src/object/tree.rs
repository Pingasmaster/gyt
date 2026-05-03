// Tree object. Phase 2.

use crate::hash::ObjectId;

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub hash: ObjectId,
}
