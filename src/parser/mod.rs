//! `ArtifactParserFactory` implementations: each finds its loose NTFS files in the run's VFS and
//! emits one `ForensicData` per record.

pub mod companions;
pub mod discovery;
pub mod i30;
pub mod mft;
pub mod mirror;
pub mod schema;
pub mod sds;
pub mod usn;

pub use i30::{I30ParserFactory, I30ParserOptions};
pub use mft::{MftParserFactory, MftParserOptions};
pub use sds::SdsParserFactory;
pub use usn::{UsnParserFactory, UsnParserOptions};

use forensic_rs::prelude::*;

/// Hex-encodes at most `max` bytes.
pub(crate) fn hex(bytes: &[u8], max: usize) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len().min(max) * 2);
    for b in bytes.iter().take(max) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(crate) fn texts<I, S>(items: I) -> Vec<Text>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    items.into_iter().map(|s| Text::Owned(s.into())).collect()
}

/// Owner SIDs by security id, from a `$Secure:$SDS` next to `artifact` (if any).
pub(crate) fn sds_owners(
    fs: &dyn FileSystem,
    artifact: &FPath,
) -> Option<std::collections::BTreeMap<u32, String>> {
    sds::owners_for(fs, artifact)
}

#[cfg(test)]
mod tests {
    use forensic_rs::prelude::*;

    #[test]
    fn artifact_tags_are_core_variants_that_round_trip() {
        for (artifact, expected) in [
            (super::i30::i30_artifact(), WindowsArtifacts::I30),
            (super::usn::usn_artifact(), WindowsArtifacts::UsnJrnl),
            (super::sds::sds_artifact(), WindowsArtifacts::Secure),
        ] {
            assert_eq!(artifact, Artifact::Windows(expected));
            let text = artifact.to_string();
            assert_eq!(
                forensic_rs::artifact::artifact_from_str(&text),
                artifact,
                "{text}"
            );
        }
    }
}
