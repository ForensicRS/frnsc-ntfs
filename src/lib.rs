//! Pure Rust NTFS parser for forensic-rs.
//!
//! Every parser in this crate works on a **loose file**: an extracted `$MFT`, a `$MFTMirr`, a
//! `$I30` index allocation, a `$UsnJrnl:$J`, a `$Secure:$SDS` or a `$Boot`. None of them needs the disk image,
//! a partition table or any other crate. The optional `volume` feature adds a whole-volume
//! `FileSystem` on top of the same decoders.
//!
//! # Library use (no pipeline)
//!
//! ```no_run
//! use frnsc_ntfs::mft::Mft;
//!
//! let file = std::fs::File::open("evidence/$MFT").unwrap();
//! let mft = Mft::from_reader(file).unwrap();
//! for entry in mft.entries() {
//!     match entry {
//!         Ok(entry) => {
//!             let path = mft.path_of(&entry);
//!             println!("{} {} deleted={}", entry.reference, path.path, !entry.in_use());
//!         }
//!         Err(e) => eprintln!("corrupt record: {e}"),
//!     }
//! }
//! ```
//!
//! # Pipeline use
//!
//! Register [`parser::MftParserFactory`], [`parser::I30ParserFactory`],
//! [`parser::UsnParserFactory`] and [`parser::SdsParserFactory`] with a `TriagePipeline`. They find
//! their files in the run's VFS by name (and by configurable globs) and emit one `ForensicData` per
//! record.
//!
//! # Forensic rules this crate follows
//!
//! * Evidence never panics the parser: every read is bounds-checked, every loop advances.
//! * A missing or zero timestamp is `None`, never the epoch. Raw FILETIMEs are kept beside the
//!   decoded dates.
//! * Damage is recorded, not refused: a torn record, a stale parent or a timestomp sign is an
//!   [`anomaly::NtfsAnomaly`] carried on the record. One unreadable record is one `Err` item and
//!   the stream goes on.
//! * Deleted metadata is graded `Recovery::DeletedMetadata`; names carved from slack are
//!   `Recovery::Slack` and only admitted through a strict validation gate
//!   ([`recovery`]).
//! * Output order is deterministic (entry order, `BTreeMap`s).

pub mod anomaly;
pub mod attr;
pub mod boot;
pub mod error;
pub mod fields;
pub mod fixup;
pub mod indx;
pub mod mft;
pub mod parser;
pub mod record;
pub mod recovery;
pub mod reference;
pub mod runlist;
pub mod secure;
pub mod source;
pub mod time;
pub mod usn;
#[cfg(feature = "volume")]
pub mod volume;

#[doc(hidden)]
pub mod fixtures;

pub use anomaly::{NtfsAnomaly, NtfsIndicator};
pub use boot::BootSector;
pub use mft::{Mft, MftEntry, MftMirr, MirrorComparison, MirrorVerdict};
pub use reference::FileRef;
