// Commit object. Phase 2.

use crate::hash::ObjectId;

#[derive(Debug, Clone)]
pub struct Commit {
    pub tree: ObjectId,
    pub parents: Vec<ObjectId>,
    pub author: String,
    pub committer: String,
    pub message: String,
}
