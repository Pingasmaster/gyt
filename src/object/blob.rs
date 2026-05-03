// Blob = an opaque byte payload. The "object" is just the bytes; the
// store layer prepends the standard "<kind> <size>\0" header before
// hashing and storing.

use crate::errors::Result;
use crate::hash::ObjectId;
use crate::object::{Object, ObjectKind, store};
use std::path::Path;

pub fn write(repo: &Path, payload: &[u8]) -> Result<ObjectId> {
    store::write_bytes(repo, ObjectKind::Blob, payload)
}

pub fn read(repo: &Path, id: &ObjectId) -> Result<Vec<u8>> {
    let Object { kind, payload, .. } = store::read(repo, id)?;
    if kind != ObjectKind::Blob {
        return Err(crate::errors::GytError::Object(format!(
            "expected blob, got {}",
            kind.as_str()
        )));
    }
    Ok(payload)
}
