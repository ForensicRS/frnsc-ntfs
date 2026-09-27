//! `$OBJECT_ID` (0x40): distributed link tracking identifiers.

use super::{guid, AttrResult};

/// Decoded `$OBJECT_ID`. Only the object id is mandatory; the birth ids are optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectId {
    pub object_id: String,
    pub birth_volume_id: Option<String>,
    pub birth_object_id: Option<String>,
    pub domain_id: Option<String>,
}

impl ObjectId {
    pub fn parse(v: &[u8]) -> AttrResult<Self> {
        if v.len() < 16 || v.len() > 64 {
            return Err("$OBJECT_ID length outside 16..=64");
        }
        let opt = |at: usize| -> AttrResult<Option<String>> {
            match v.get(at..at + 16) {
                Some(b) if b.iter().any(|&x| x != 0) => guid(b).map(Some),
                _ => Ok(None),
            }
        };
        Ok(Self {
            object_id: guid(v)?,
            birth_volume_id: opt(16)?,
            birth_object_id: opt(32)?,
            domain_id: opt(48)?,
        })
    }
}
