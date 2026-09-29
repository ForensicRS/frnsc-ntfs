# frnsc-ntfs agent guide

The workspace `AGENTS.md` applies. The rules below are specific to this crate.

## Layout

- **Loose-file layer (always built):**
  - `boot`, `fixup`, `record/`, `attr/`, `runlist`, `mft/` (including `mft/mirror.rs`, the
    `$MFTMirr` parser and the `$MFT` cross-check), `indx/`, `usn/`, `secure/`, `recovery/`,
    `parser/`;
  - it reads through `source::RecordSource` and never names `ReadAt`.
- **Volume layer:** `volume/`, behind the `volume` feature. It uses the forensic-rs storage-media
  APIs (`ReadAt`, `HopCost`, `MediaMap`) through `volume::format::ReadAtSource`, and implements the
  core `DeletedFiles` capability (`volume/deleted.rs`). Keep those types out of the loose-file
  layer, so it builds against released forensic-rs.
- **Field names:** every `ntfs.*` key lives in `fields.rs`. Don't put string literals for field
  names anywhere else.
- **Anomalies:** a new `NtfsAnomaly` variant needs `name()`, `flag()`, `benign_explanation()` and
  `Display`. A heuristic that ordinary NTFS behaviour triggers is an `NtfsIndicator`, not an
  anomaly: a flag becomes a `Finding` through the pipeline tally.
- **Fixtures:** `fixtures/` builds records, `INDX` nodes, USN records, `$SDS` entries, and (with
  `volume`) whole volumes. Tests must use these, never real case data.

## Rules that are easy to break here

- **Every read on evidence is bounded.**
  - Use the helpers in `attr/mod.rs` (`u16_at` and friends) or `ByteReader`.
  - Every loop over attributes, index entries, runs, USN or `$SDS` records must advance by at
    least 1 byte per iteration.
  - Allocation caps are the constants named `MAX_*`.
- **One bad record is one `Err` item.** `Mft::entries()`, `UsnReader` and the factories keep
  going after it. A damaged USN stretch is reported once, not once for every 8 bytes.
- **Sequence numbers decide identity.** A record freed by NTFS has its sequence bumped, so a
  reference at `seq` and a free record at `seq + 1` are the same file (`paths.rs`,
  `index.rs::extension_belongs`, `recovery::parent_matches`). Anything else is a reuse.
- **A formatted but unused record is not a deleted file:** `Slot::Free` is not in use, not an
  extension, and has no `$FILE_NAME`. Don't emit it.
- **Fixups:** some collectors (and `ntfscat`) export records with fixups already reverted. That
  is `FixupStatus::PreApplied`, which is consistent and not an anomaly. Only a mix of values is
  `Torn`. The same asymmetry is why a `$MFT`/`$MFTMirr` comparison applies the fixups to both
  sides before deciding: raw bytes alone would call a clean volume a mismatch
  (`MirrorVerdict::FixupOnly`).
- **A cross-check carries both sides.** `$MFT` vs `$MFTMirr` is never reduced to a boolean: every
  `MirrorRecordCheck` keeps each side's raw record bytes as stored, the offset *and the stream it
  is relative to*, the sequence and update sequence numbers, and the fields that differ. Locate
  the mirror from the **boot sector**, never from the `$MFT` (that would be circular).
- **Recovery gates are strict.** Carved names must match the parent being scanned. Deleted
  content needs every stored cluster free and unclaimed. Don't add a fallback that returns
  partial content.

## Testing

- **Unit tests** sit next to the code. Every parser has a truncated-prefix test and a
  random-corruption test (xorshift, no dependency).
- **`tests/*_pipeline.rs` and `tests/kape_export.rs`** run the factories through `TriagePipeline`
  (`tests/common`). `tests/mftmirr_pipeline.rs` covers the `$MFTMirr` records and the cross-check.
- **`tests/fs_conformance.rs`** runs `forensic_rs::fs_conformance_battery!` on `NtfsFs`.
- **`tests/stack.rs`** checks disk → GPT (frnsc-vsys, a dev-dependency) → NTFS through
  `ContainerFs`.
- **`tests/real_samples.rs`** uses the `ntfs-mkntfs-*` artifacts from
  `forensic-testenv/generators/ntfs_mkntfs.sh`. Its truth is rebuilt from the generator's inputs.
  There is no loose `$MFTMirr` artifact yet, so the mirror tests cut it out of the registered
  `ntfs-mkntfs-volume` at the LCN its `$Boot` declares — real bytes, nothing synthesised.
