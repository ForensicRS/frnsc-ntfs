# frnsc-ntfs

Pure Rust NTFS parser for [forensic-rs](https://github.com/ForensicRS/forensic-rs): `$MFT`, `$I30`,
`$UsnJrnl:$J`, `$Secure:$SDS`, `$Boot`, and recovery of deleted entries. It parses loose metadata
files on their own; with the `volume` feature it also mounts a whole volume.

Part of the [ForensicRS](https://github.com/ForensicRS) ecosystem.

## Two layers

| | Needs | Gives you |
|---|---|---|
| **Loose files** (default) | the extracted file only (KAPE, FTK, RawCopy, `ntfscat`, ...) | parsers + `ArtifactParserFactory`s for `$MFT`, `$I30`, `$J`, `$SDS`; `$Boot` geometry |
| **Volume** (`--features volume`) | a partition image, or a partition from a disk image | `NtfsFs`: read-only `FileSystem` + ADS + unallocated space + deleted-file content |

The two layers share one set of record and attribute decoders. The volume layer needs the
storage-media APIs of the local forensic-rs `media-images` branch (`ReadAt`, `HopCost`, `MediaMap`).

## Library use

```rust
use frnsc_ntfs::mft::Mft;

let mft = Mft::from_reader(std::fs::File::open("C/$MFT")?)?;
for entry in mft.entries() {
    let entry = entry?; // an unreadable record is one Err; iteration goes on
    let path = mft.path_of(&entry);
    println!("{} {} deleted={} {:?}", entry.reference, path.path, !entry.in_use(), path.status);
    if let Some(bytes) = entry.resident_data("") {
        // small files (< ~700 B) keep their content in the record, deleted or not
    }
}
```

```rust
// --features volume
use frnsc_ntfs::volume::{NtfsFs, Volume};
use forensic_rs::prelude::*;

let fs = NtfsFs::from_volume(Volume::from_reader(std::fs::File::open("vol.img")?)?);
let data = fs.read_all(FPath::new("Windows/System32/drivers/etc/hosts"))?;
let (deleted, report) = fs.deleted_files()?;
for f in &deleted {
    if f.value().content.is_readable() {
        let file = fs.open_deleted(f.value())?; // Recovered<Box<dyn VirtualFile>>
    }
}
```

Examples: `cargo run -p frnsc-ntfs --example mft_dump -- '$MFT'` and
`cargo run -p frnsc-ntfs --features volume --example volume_ls -- vol.img`.

## Pipeline use

Register the factories with a `TriagePipeline`. Each one finds its files in the run's VFS by name:
`$MFT`; `$J`/`$UsnJrnl:$J`/`$UsnJrnl%3A$J`; `$SDS`/`$Secure:$SDS`/`$Secure%3A$SDS`; `*$I30`,
`*.indx`. Extra glob patterns can be configured. Companion files are used when present: `$Boot`
gives the MFT record size, `$SDS` gives owner SIDs, and a `$MFT` resolves paths for `$I30` and
USN records.

| Factory | Records |
|---|---|
| `MftParserFactory` (`windows.ntfs.mft`) | one per file (`ntfs.record_type = mft_entry`), deleted included; names carved from record and `$INDEX_ROOT` slack; one `mft_summary` |
| `I30ParserFactory` (`windows.ntfs.i30`) | live index entries, and deleted entries carved from index slack |
| `UsnParserFactory` (`windows.ntfs.usnjrnl`) | one event per journal record, with `@timestamp` and `event.action` |
| `SdsParserFactory` (`windows.ntfs.sds`) | one per security descriptor: owner, group, DACL |

For the volume, register `NtfsFormatFactory` with a `MountResolver`. It stacks after an image or
volume-system factory, e.g. `disk.raw/p1/Windows/...` with frnsc-vsys.

Fields use ECS names where they exist (`file.path`, `file.created`, `file.uid`, ...). Everything
else is `ntfs.*`; the full list is in `src/fields.rs`. Every FILETIME is emitted twice: decoded,
and raw (`*_raw`). A zero FILETIME gives no date.

## Forensic behaviour

- **Deleted entries** are graded `Recovery::DeletedMetadata`. Their paths are rebuilt through
  deleted parents: NTFS bumps a record's sequence when it frees it, so a parent at sequence + 1
  that is not in use is the same directory.
- **Parent reused** (the sequence doesn't match): the path is re-rooted under `\$Orphan`, with
  `ntfs.path_status = stale_parent` and a `STALE_REFERENCE` anomaly.
- **Timestomping:** `$SI` created earlier than `$FN` created raises `TIMESTAMP_DIVERGENCE`. The
  anomaly carries its benign explanation: installers and image deployment do this too. Weaker
  signs go to `ntfs.indicators` only, and raise no finding: whole-second `$SI`, implausible
  dates, `$SI` older than the volume.
- **Slack names** are carved from MFT record slack, `$INDEX_ROOT` and `$I30` `INDX` slack, and
  graded `Recovery::Slack`. They are only admitted through a strict gate:
  - the entry is structurally consistent;
  - the name is strict UTF-16 with no control characters;
  - all four timestamps are set and fall between 1980 and 2100;
  - the sizes are consistent;
  - **the parent is the directory being scanned**.

  Rejections are counted, never emitted.
- **Deleted content** (volume) is returned only when:
  - the record is intact;
  - the run list lies inside the volume;
  - every stored cluster is still free in `$Bitmap`;
  - no other deleted file claims the same clusters.

  Otherwise the result is `Reallocated` or `CrossClaimed`, with an `ALLOCATION_CONFLICT`
  anomaly and no bytes. A reuse followed by a second free cannot be detected, which is why this
  content is never graded as allocated.
- **Damage is recorded, not refused.** This covers torn records, bad or pre-applied fixups, a
  `BAAD` signature, record number mismatches, a truncated `$MFT`, a `$MFTMirr` mismatch, the
  backup boot sector being used, a truncated image, malformed runs, `$SDS` hash or mirror
  mismatches, and damaged USN stretches. Each `NtfsAnomaly` has a `benign_explanation()`.
- **Output is deterministic** (entry order, sorted maps), and parsing never panics on evidence.
  Every parser is fuzzed with truncated prefixes and random corruption in its tests.

## Coverage and limitations

Parsed:
- `FILE` records: 1 KiB and 4 KiB, 512 and 4 KiB sectors, fixups including pre-applied copies,
  extension records, and resident and non-resident `$ATTRIBUTE_LIST`s.
- Attributes: `$SI` v1 and v3, `$FN` in every namespace, `$DATA` (ADS, `Zone.Identifier`),
  `$OBJECT_ID`, `$REPARSE_POINT` (symlink, junction, WOF, cloud, ...), `$EA`, `$LOGGED_UTILITY_STREAM`,
  `$VOLUME_*`, `$INDEX_ROOT`/`$INDEX_ALLOCATION`, and resident `$SECURITY_DESCRIPTOR`.
- Volume data: data runs (fragmented, sparse, past the valid data length), LZNT1 compression
  units, and a fragmented `$MFT`.

Not (yet) parsed:
- `$LogFile`.
- WOF/CompactOS decompression (XPRESS/LZX). These files are reported with `ntfs.wof`; their
  stored bytes are the compressed stream.
- EFS decryption: encrypted files return their raw ciphertext and set `ntfs.efs`.
- `$UpCase` collation: names compare with Unicode simple uppercase.
- VSS snapshots and BitLocker.
- Directory listings in the volume come from `$FILE_NAME` parent references of in-use records,
  not from walking the `$I30` B-tree. Carve the `$I30` slack with `NtfsFs::index_slack`.

## Development

```sh
cargo test -p frnsc-ntfs                       # loose-file layer
cargo test -p frnsc-ntfs --features volume     # + volume, conformance battery, disk stack
../forensic-testenv/tools/fetch.py --crate frnsc-ntfs   # real mkntfs/ntfs-3g sample (tests skip without it)
```

Real samples come from `forensic-testenv/generators/ntfs_mkntfs.sh`. Unit and integration tests
build their NTFS structures in `src/fixtures/` and never use real case data.
