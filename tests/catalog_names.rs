//! The parsers name the ForensicArtifacts definitions they read.

use forensic_rs::prelude::*;
use frnsc_ntfs::parser::{MftParserFactory, UsnParserFactory};

fn declared(descriptor: &ParserDescriptor) -> Vec<&str> {
    descriptor
        .requirements
        .iter()
        .filter_map(|r| match r {
            Requirement::Artifact(a) => Some(&*a.name),
            _ => None,
        })
        .collect()
}

#[test]
fn the_mft_and_usn_parsers_declare_their_definitions() {
    assert_eq!(
        declared(MftParserFactory::default().descriptor()),
        ["NTFSMFTFiles"]
    );
    assert_eq!(
        declared(UsnParserFactory::default().descriptor()),
        ["NTFSUSNJournal"]
    );
}
