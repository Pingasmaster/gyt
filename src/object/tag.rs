// Annotated tag object. Phase 2.

use crate::hash::ObjectId;
use crate::object::ObjectKind;

#[derive(Debug, Clone)]
pub struct Tag {
    pub target: ObjectId,
    pub kind: ObjectKind,
    pub name: String,
    pub tagger: String,
    pub message: String,
}
