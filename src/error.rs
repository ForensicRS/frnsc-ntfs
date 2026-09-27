//! Error helpers: every error this crate raises names the `ntfs` artifact type.

use forensic_rs::prelude::*;

/// Artifact type name used in every [`ForensicError`] this crate builds.
pub const ARTIFACT: &str = "ntfs";

/// A structure at `position` (byte offset in the source file) is damaged beyond parsing.
pub fn corrupted(position: u64, reason: impl Into<CompactString>) -> ForensicError {
    ForensicError::format_corrupted(ARTIFACT, position, reason.into())
}

/// The input is not the expected NTFS structure at all.
pub fn invalid(reason: impl Into<CompactString>) -> ForensicError {
    ForensicError::invalid_format(ARTIFACT, reason)
}

/// Converts an I/O error from the evidence source.
pub fn io(error: std::io::Error, context: impl Into<CompactString>) -> ForensicError {
    ForensicError::io_error_with_source(error, context)
}
