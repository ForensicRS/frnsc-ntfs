//! Lists every file of an NTFS volume image, then the deleted files and what the recovery gate
//! decided about their content.
//!
//!     cargo run -p frnsc-ntfs --features volume --example volume_ls -- path/to/volume.img

use forensic_rs::prelude::*;
use frnsc_ntfs::volume::{NtfsFs, Volume};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: volume_ls <image>");
        std::process::exit(2);
    };
    let file = std::fs::File::open(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let vol = Volume::from_reader(file).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    for a in &vol.anomalies {
        println!("volume anomaly: {}: {a}", a.name());
    }
    let fs = NtfsFs::from_volume(vol);
    for entry in fs.walk(FPath::new(""), &Default::default()) {
        match entry {
            Ok(e) => {
                let size = e.metadata.as_ref().map_or(0, |m| m.size);
                println!("{:?}\t{}\t{}", e.file_type, size, e.path.as_str());
            }
            Err(err) => eprintln!("walk error: {err}"),
        }
    }
    match fs.deleted_files() {
        Ok((files, report)) => {
            for f in &files {
                let v = f.value();
                println!(
                    "deleted\t{}\t{}\t{}\t{}",
                    v.reference,
                    v.metadata.size,
                    v.content.name(),
                    v.path.path
                );
            }
            println!("recovery: {report:?}");
        }
        Err(e) => eprintln!("deleted scan failed: {e}"),
    }
}
