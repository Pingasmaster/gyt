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

/// The tag header has a fixed canonical order: object, type, tag, tagger.
/// `decode` rejects any out-of-order line so the encoded form is unique
/// (same justification as the commit-side `Section` enum).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TagSection {
    Object = 0,
    Type = 1,
    Tag = 2,
    Tagger = 3,
}

fn advance_tag_section(state: &mut TagSection, next: TagSection, name: &str) -> Result<()> {
    if next < *state {
        return Err(GytError::Object(format!(
            "tag: header {name} out of canonical order"
        )));
    }
    *state = next;
    Ok(())
}

pub fn decode(payload: &[u8]) -> Result<Tag> {
    let text =
        std::str::from_utf8(payload).map_err(|_| GytError::Object("tag: non-utf8".into()))?;
    let (header, message) = text
        .split_once("\n\n")
        .ok_or_else(|| GytError::Object("tag: missing blank line".into()))?;

    let mut cur = TagSection::Object;

    let mut target: Option<ObjectId> = None;
    let mut kind: Option<ObjectKind> = None;
    let mut name: Option<String> = None;
    let mut tagger: Option<String> = None;
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("object ") {
            if target.is_some() {
                return Err(GytError::Object("tag: multiple object lines".into()));
            }
            advance_tag_section(&mut cur, TagSection::Object, "object")?;
            target = Some(ObjectId::from_hex(rest)?);
        } else if let Some(rest) = line.strip_prefix("type ") {
            if kind.is_some() {
                return Err(GytError::Object("tag: multiple type lines".into()));
            }
            advance_tag_section(&mut cur, TagSection::Type, "type")?;
            kind = Some(ObjectKind::parse(rest)?);
        } else if let Some(rest) = line.strip_prefix("tag ") {
            if name.is_some() {
                return Err(GytError::Object("tag: multiple tag lines".into()));
            }
            advance_tag_section(&mut cur, TagSection::Tag, "tag")?;
            name = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("tagger ") {
            if tagger.is_some() {
                return Err(GytError::Object("tag: multiple tagger lines".into()));
            }
            advance_tag_section(&mut cur, TagSection::Tagger, "tagger")?;
            tagger = Some(rest.to_string());
        } else {
            return Err(GytError::Object(format!("tag: unknown line {line:?}")));
        }
    }
    let t = Tag {
        target: target.ok_or_else(|| GytError::Object("tag: missing object".into()))?,
        kind: kind.ok_or_else(|| GytError::Object("tag: missing type".into()))?,
        name: name.ok_or_else(|| GytError::Object("tag: missing tag name".into()))?,
        tagger: tagger.ok_or_else(|| GytError::Object("tag: missing tagger".into()))?,
        message: message.to_string(),
    };
    // Defense in depth: re-encode must reproduce the input byte-for-byte.
    let re_encoded = encode(&t);
    if re_encoded != payload {
        return Err(GytError::Object(
            "tag: non-canonical encoding (re-encode differs from input)".into(),
        ));
    }
    Ok(t)
}

pub fn write(repo: &Path, t: &Tag) -> Result<ObjectId> {
    store::write_bytes(repo, ObjectKind::Tag, &encode(t))
}

#[allow(dead_code)]
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
