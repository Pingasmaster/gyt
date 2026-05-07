// Annotated tag object format (utf-8 text):
//   object <hex>
//   type <kind>
//   tag <name>
//   tagger <name> <email> <unix-secs> <tz-offset>
//   <blank line>
//   <message bytes>

use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::{ObjectKind, store};
use std::fmt::Write;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub target: ObjectId,
    pub kind: ObjectKind,
    pub name: String,
    pub tagger: String,
    pub message: String,
}

pub fn encode(t: &Tag) -> Vec<u8> {
    let mut s = String::new();
    writeln!(s, "object {}", t.target).unwrap();
    writeln!(s, "type {}", t.kind.as_str()).unwrap();
    writeln!(s, "tag {}", t.name).unwrap();
    writeln!(s, "tagger {}", t.tagger).unwrap();
    s.push('\n');
    s.push_str(&t.message);
    s.into_bytes()
}

pub fn decode(payload: &[u8]) -> Result<Tag> {
    let text =
        std::str::from_utf8(payload).map_err(|_| GytError::Object("tag: non-utf8".into()))?;
    let (header, message) = text
        .split_once("\n\n")
        .ok_or_else(|| GytError::Object("tag: missing blank line".into()))?;
    let mut target: Option<ObjectId> = None;
    let mut kind: Option<ObjectKind> = None;
    let mut name: Option<String> = None;
    let mut tagger: Option<String> = None;
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("object ") {
            target = Some(ObjectId::from_hex(rest)?);
        } else if let Some(rest) = line.strip_prefix("type ") {
            kind = Some(ObjectKind::parse(rest)?);
        } else if let Some(rest) = line.strip_prefix("tag ") {
            name = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("tagger ") {
            tagger = Some(rest.to_string());
        } else {
            return Err(GytError::Object(format!("tag: unknown line {line:?}")));
        }
    }
    Ok(Tag {
        target: target.ok_or_else(|| GytError::Object("tag: missing object".into()))?,
        kind: kind.ok_or_else(|| GytError::Object("tag: missing type".into()))?,
        name: name.ok_or_else(|| GytError::Object("tag: missing tag name".into()))?,
        tagger: tagger.ok_or_else(|| GytError::Object("tag: missing tagger".into()))?,
        message: message.to_string(),
    })
}

pub fn write(repo: &Path, t: &Tag) -> Result<ObjectId> {
    store::write_bytes(repo, ObjectKind::Tag, &encode(t))
}

pub fn read(repo: &Path, id: &ObjectId) -> Result<Tag> {
    let obj = store::read(repo, id)?;
    if obj.kind != ObjectKind::Tag {
        return Err(GytError::Object(format!(
            "expected tag, got {}",
            obj.kind.as_str()
        )));
    }
    decode(&obj.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;

    #[test]
    fn round_trip_tag() {
        let t = Tag {
            target: hash::hash_bytes(b"c"),
            kind: ObjectKind::Commit,
            name: "v0.1.0".into(),
            tagger: "Bob <b@x> 1700000000 +0000".into(),
            message: "release notes\n".into(),
        };
        assert_eq!(decode(&encode(&t)).unwrap(), t);
    }
}
