//! Dumps a loose `$MFT` as TSV: one line per file, deleted entries included.
//!
//!     cargo run -p frnsc-ntfs --example mft_dump -- path/to/$MFT

use frnsc_ntfs::mft::Mft;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: mft_dump <$MFT>");
        std::process::exit(2);
    };
    let file = std::fs::File::open(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(1);
    });
    let mft = match Mft::from_reader(file) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };
    println!("entry\tseq\tin_use\tdir\tsize\tpath\tpath_status\tstreams\tanomalies");
    for item in mft.entries() {
        match item {
            Ok(e) => {
                let p = mft.path_of(&e);
                let streams: Vec<String> = e
                    .alternate_streams()
                    .map(|s| format!("{}:{}", s.name, s.size()))
                    .collect();
                let anomalies: Vec<&str> = e.anomalies.iter().map(|a| a.name()).collect();
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    e.reference.entry,
                    e.reference.sequence,
                    e.in_use(),
                    e.is_directory(),
                    e.data().map_or(0, |d| d.size()),
                    p.path,
                    p.status.name(),
                    streams.join(","),
                    anomalies.join(",")
                );
            }
            Err(err) => eprintln!("error: {err}"),
        }
    }
}
