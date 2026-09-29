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
  - `$MFTMirr` (`mft::mirror::MftMirr`, parsed by `parser::MftParserFactory`): the mirrored copy
    of the first records, and a record-by-record cross-check against the `$MFT` beside it. A
    disagreement carries **both sides** — each one's raw record bytes as stored, the offset and the
    stream that offset belongs to, the sequence and update sequence numbers as read, the header
    fields that differ, and the first differing byte. `$MFT` and `$MFTMirr` share the catalog name
    `NTFSMFTFiles`, so both are tagged `WindowsArtifacts::MFT`. A copy extracted with the fixups
    already reverted (`ntfscat`) is `fixup_only`, not a mismatch; a side whose fixups do **not**
    verify is `fixup_torn`, never absorbed into `fixup_only`. Only a `$MFTMirr` in the same
    directory as a `$MFT` is cross-checked against it, and the check record's provenance retains
    both files. A `$MFTMirr` collected without its `$MFT` is still parsed, and its summary says the
    check did not run.
  - `$I30` (`indx`, `parser::I30ParserFactory`): `INDX` records, and slack carving behind a
    parent-checked gate, cross-checked against a companion `$MFT`.
  - `$UsnJrnl:$J` (`usn`, `parser::UsnParserFactory`): V2, V3 and V4 records, sparse-prefix
    skipping, resynchronisation after damage, and MFT path resolution.
  - `$Secure:$SDS` (`secure`, `parser::SdsParserFactory`): owner, group and DACL, with hash and
    mirror checks. Owner SIDs fill `file.uid` on MFT records, as do resident
    `$SECURITY_DESCRIPTOR`s.
  - `$Boot` (`boot::BootSector`).
  - `$I30`, USN and `$SDS` records are tagged with the core `WindowsArtifacts::I30`, `UsnJrnl`
    and `Secure` (serialized `Windows::I30`, `Windows::UsnJrnl`, `Windows::Secure`), not
    `Other("NTFS_I30")`, `Other("UsnJrnl")` and `Other("NTFS_Secure_SDS")`.
- **`volume` feature:**
  - `volume::Volume` and `NtfsFs`: a read-only `FileSystem` with `AlternateStreams`,
    `Unallocated`, `PathAttributes`, `MediaMap` and `DeletedFiles`.
  - `NtfsFormatFactory`, with `HopCost::View`.
  - Data runs, sparse data, the valid data length, LZNT1 compression units, and a fragmented
    `$MFT`.
  - Backup boot sector check, and the `$MFTMirr` cross-check at the LCN the **boot sector**
    declares (asking the `$MFT` where its own mirror lives would be circular); the full result,
    both sides included, is on `Volume::mirror`.
  - Deleted-file content recovery behind a `$Bitmap` and cross-claim gate (`deleted_files`,
    `open_deleted`), and `index_slack`. The same files are reachable through the core
    `DeletedFiles` capability (`fs.as_deleted()`, id = file reference), so tools find them
    through `ContainerFs` paths such as `disk.raw/p1`. A path that can't be verified to the root is
    `None` there; `deleted_files` keeps its `PathStatus` and anomalies. The scan runs once per
    `NtfsFs`, and `DeletedFile` gained the record's own `name`.
- `NtfsAnomaly` (each with a benign explanation) and `NtfsIndicator`.
- Examples `mft_dump` and `volume_ls`.

### Fixed

- `si_created_before_fn_created` flagged 72,095 of 76,612 `$MFT` entries on a real Windows Server
  2008 R2 triage, mostly installed files that keep their original `$SI` times, and produced one
  High finding for all of them. `$SI created < $FN created` alone is now the indicator
  `si_created_before_fn`. The anomaly (`TIMESTAMP_DIVERGENCE`) needs a second sign, named in
  its message: the `$SI` change time is also before `$FN` created (every `$SI` time backdated,
  which `SetFileTime` can't do), or the `$SI` times are whole seconds while the `$FN` ones are
  not.
- Loose metadata files exported with an extension or an encoded separator were not found:
  `$UsnJrnl_$J.bin` (forecopy, Brimor Labs), `$MFT.bin`, `$J.raw`, `$UsnJrnl%3a$J`. Names are
  now compared after decoding `%3A` and removing one `.bin`, `.raw` or `.dat`, for discovery and
  for companion lookup.
