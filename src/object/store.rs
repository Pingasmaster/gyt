// Loose object reader/writer. Real implementation lands in Phase 2.

use crate::errors::Result;
use crate::hash::ObjectId;
use crate::object::Object;

pub fn write(_repo: &std::path::Path, _obj: &Object) -> Result<ObjectId> {
    unimplemented!("phase 2")
}

pub fn read(_repo: &std::path::Path, _id: &ObjectId) -> Result<Object> {
    unimplemented!("phase 2")
}
