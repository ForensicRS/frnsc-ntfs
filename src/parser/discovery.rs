//! Finding loose NTFS metadata files in a VFS (KAPE/triage exports, extracted files).
//!
//! Collection tools spell stream names differently (`$UsnJrnl:$J`, `$UsnJrnl%3A$J`, `$J`), so each
//! artifact has a list of accepted names, matched case-insensitively on the file name after
//! [normalize] (a percent-encoded `:`, and one export extension such as forecopy's and Brimor
//! Labs' `$UsnJrnl_$J.bin`). Callers can add explicit glob patterns for anything else.

use std::collections::BTreeSet;

use forensic_rs::core::fs::walk::WalkOptions;
use forensic_rs::prelude::*;

pub const MFT_NAMES: &[&str] = &["$MFT"];
pub const MFTMIRR_NAMES: &[&str] = &["$MFTMirr"];
pub const BOOT_NAMES: &[&str] = &["$Boot"];
pub const USN_NAMES: &[&str] = &[
    "$J",
    "$UsnJrnl:$J",
    "$UsnJrnl%3A$J",
    "$UsnJrnl_$J",
    "$UsnJrnl.$J",
];
pub const SDS_NAMES: &[&str] = &[
    "$SDS",
    "$Secure:$SDS",
    "$Secure%3A$SDS",
    "$Secure_$SDS",
    "$Secure.$SDS",
];

/// Whether `name` looks like an exported `$I30` index allocation.
pub fn is_i30_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("$i30") || lower.ends_with(".indx") || lower.ends_with(".i30")
}

/// Found files and walk failures, kept apart so failures can be reported.
#[derive(Debug, Default)]
pub struct Found {
    pub paths: Vec<FPathBuf>,
    pub errors: Vec<ForensicError>,
}

/// Walks `fs` (to `max_depth`) for files whose name matches `accept`, plus every match of
/// `patterns`. Result is sorted and deduplicated.
pub fn find(
    fs: &dyn FileSystem,
    accept: &dyn Fn(&str) -> bool,
    patterns: &[String],
    max_depth: u32,
) -> Found {
    let mut paths = BTreeSet::new();
    let mut errors = Vec::new();
    let opts = WalkOptions::default()
        .with_max_depth(Some(max_depth))
        .with_skip_errors(false);
    for item in walk(fs, &opts) {
        match item {
            Ok(entry) => {
                if entry.file_type == VFileType::File
                    && entry.path.as_path().file_name().is_some_and(accept)
                {
                    paths.insert(entry.path);
                }
            }
            Err(e) => errors.push(e),
        }
    }
    for p in patterns {
        match glob(fs, p) {
            Ok(found) => paths.extend(found),
            Err(e) => errors.push(e),
        }
    }
    Found {
        paths: paths.into_iter().collect(),
        errors,
    }
}

fn walk(fs: &dyn FileSystem, opts: &WalkOptions) -> Vec<ForensicResult<DirEntry>> {
    fs.walk(FPath::new(""), opts).collect()
}

fn glob(fs: &dyn FileSystem, pattern: &str) -> ForensicResult<Vec<FPathBuf>> {
    fs.glob(pattern)
}

/// Extensions export tools append to a metadata file's name (`$MFT.bin`, `$UsnJrnl_$J.bin`).
const EXPORT_EXTENSIONS: &[&str] = &[".bin", ".raw", ".dat"];

/// A file name as it would be on the volume: `%3A` decoded to `:`, and one trailing export
/// extension removed (never the whole name).
pub fn normalize(name: &str) -> String {
    let decoded = name.replace("%3A", ":").replace("%3a", ":");
    let lower = decoded.to_ascii_lowercase();
    for ext in EXPORT_EXTENSIONS {
        if lower.len() > ext.len() && lower.ends_with(ext) {
            return decoded[..decoded.len() - ext.len()].to_string();
        }
    }
    decoded
}

/// Whether `name`, once [normalize]d, is one of `names` (case-insensitive).
fn is_one_of(names: &[&str], name: &str) -> bool {
    let name = normalize(name);
    names.iter().any(|x| x.eq_ignore_ascii_case(&name))
}

/// Accepts one of `names` (case-insensitive, after [normalize]).
pub fn named(names: &'static [&'static str]) -> impl Fn(&str) -> bool {
    move |n: &str| is_one_of(names, n)
}

/// Looks for a companion file (e.g. `$Boot` next to `$MFT`) in the artifact's directory and up to
/// two ancestors (KAPE puts `$J` under `$Extend`).
pub fn companion(fs: &dyn FileSystem, artifact: &FPath, names: &[&str]) -> Option<FPathBuf> {
    let mut dir = artifact.parent();
    for _ in 0..3 {
        let d = dir?;
        let Ok(entries) = fs.read_dir(d) else {
            dir = d.parent();
            continue;
        };
        let mut hits: Vec<FPathBuf> = entries
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(err) => {
                    // A companion is optional; an unreadable entry only means it is not used.
                    forensic_rs::debug!("companion lookup in {}: {}", d.as_str(), err);
                    None
                }
            })
            .filter(|e| e.file_type == VFileType::File)
            .filter(|e| {
                e.path
                    .as_path()
                    .file_name()
                    .is_some_and(|n| is_one_of(names, n))
            })
            .map(|e| e.path)
            .collect();
        hits.sort();
        if let Some(first) = hits.into_iter().next() {
            return Some(first);
        }
        dir = d.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    #[test]
    fn finds_names_and_companions() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("case/C/$MFT", vec![1])
            .with_file("case/C/$Boot", vec![2])
            .with_file("case/C/$Extend/$UsnJrnl%3A$J", vec![3])
            .with_file("case/C/other.txt", vec![4]);
        let f = find(&fs, &named(MFT_NAMES), &[], 8);
        assert!(f.errors.is_empty());
        assert_eq!(f.paths, vec![FPathBuf::from("case/C/$MFT")]);
        let j = find(&fs, &named(USN_NAMES), &[], 8);
        assert_eq!(j.paths.len(), 1);
        assert_eq!(
            companion(&fs, j.paths[0].as_path(), MFT_NAMES),
            Some(FPathBuf::from("case/C/$MFT"))
        );
        assert_eq!(
            companion(&fs, f.paths[0].as_path(), BOOT_NAMES),
            Some(FPathBuf::from("case/C/$Boot"))
        );
        assert!(is_i30_name("Windows$I30"));
    }

    #[test]
    fn exported_names_with_an_extension_match() {
        // forecopy / Brimor Labs style: `_` for the stream separator and a `.bin` extension.
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("host/CopiedFiles/ntfs/$MFT.bin", vec![1])
            .with_file("host/CopiedFiles/ntfs/$UsnJrnl_$J.bin", vec![2])
            .with_file("host/CopiedFiles/ntfs/$Secure_$SDS.BIN", vec![3])
            .with_file("other/$J.raw", vec![4])
            // The `$Max` stream's file, and a name that is only an extension, are not matches.
            .with_file("host/CopiedFiles/ntfs/$UsnJrnl", vec![5])
            .with_file("host/.bin", vec![6]);
        let usn = find(&fs, &named(USN_NAMES), &[], 8);
        assert_eq!(
            usn.paths,
            vec![
                FPathBuf::from("host/CopiedFiles/ntfs/$UsnJrnl_$J.bin"),
                FPathBuf::from("other/$J.raw"),
            ]
        );
        assert_eq!(find(&fs, &named(SDS_NAMES), &[], 8).paths.len(), 1);
        assert_eq!(
            companion(&fs, usn.paths[0].as_path(), MFT_NAMES),
            Some(FPathBuf::from("host/CopiedFiles/ntfs/$MFT.bin"))
        );
        assert_eq!(normalize("$UsnJrnl%3a$J"), "$UsnJrnl:$J");
        assert_eq!(normalize(".bin"), ".bin");
    }
}
