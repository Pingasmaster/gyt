// Object types and store. Real wiring lands in Phase 2.

use crate::errors::{GytError, Result};
use crate::hash::ObjectId;

pub mod blob;
pub mod commit;
pub mod store;
pub mod tag;
pub mod tree;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "blob" => Ok(Self::Blob),
            "tree" => Ok(Self::Tree),
            "commit" => Ok(Self::Commit),
            "tag" => Ok(Self::Tag),
            other => Err(GytError::Object(format!("unknown object kind: {other}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Object {
    #[allow(dead_code)]
    pub id: ObjectId,
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
}

impl Object {
    #[allow(dead_code)]
    pub fn new(kind: ObjectKind, payload: Vec<u8>) -> Self {
        let raw = store::build_raw(kind, &payload);
        let id = crate::hash::hash_bytes(&raw);
        Self { id, kind, payload }
    }
}
