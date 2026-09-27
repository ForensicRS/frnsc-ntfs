# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- **Loose-file parsers**, with no disk image needed:
  - `$MFT` (`mft::Mft`, `parser::MftParserFactory`): fixups (including pre-applied copies),
    extension records, `$SI`/`$FN` and the other attributes, full paths through deleted and
    reused parents, hard links, resident data of deleted files, timestomp checks, and names
    carved from record and `$INDEX_ROOT` slack.
  - `$I30` (`indx`, `parser::I30ParserFactory`): `INDX` records, and slack carving behind a
    parent-checked gate, cross-checked against a companion `$MFT`.
  - `$UsnJrnl:$J` (`usn`, `parser::UsnParserFactory`): V2, V3 and V4 records, sparse-prefix
    skipping, resynchronisation after damage, and MFT path resolution.
  - `$Secure:$SDS` (`secure`, `parser::SdsParserFactory`): owner, group and DACL, with hash and
    mirror checks. Owner SIDs fill `file.uid` on MFT records, as do resident
    `$SECURITY_DESCRIPTOR`s.
  - `$Boot` (`boot::BootSector`).
- **`volume` feature:**
  - `volume::Volume` and `NtfsFs`: a read-only `FileSystem` with `AlternateStreams`,
    `Unallocated`, `PathAttributes` and `MediaMap`.
  - `NtfsFormatFactory`, with `HopCost::View`.
  - Data runs, sparse data, the valid data length, LZNT1 compression units, and a fragmented
    `$MFT`.
  - `$MFTMirr` and backup boot sector checks.
  - Deleted-file content recovery behind a `$Bitmap` and cross-claim gate (`deleted_files`,
    `open_deleted`), and `index_slack`.
- `NtfsAnomaly` (each with a benign explanation) and `NtfsIndicator`.
- Examples `mft_dump` and `volume_ls`.
