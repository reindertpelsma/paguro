//! The storage torture harness.
//!
//! DESIGN.md is explicit that **this is built before anything else**: a
//! sacrificial NTFS volume, a Windows VM, and a block layer refusing exactly what
//! the module would refuse — then defrag, `chkdsk`, shrink, conversion, Windows
//! Update and power loss at every write boundary, against §11 Q1–Q3.
//!
//! Stage 1 (here, now): a model check of the range test against a naive oracle,
//! and differential tests of the kernel module's C core (range test, NTFS
//! parser, claim checks) against the Rust specification (`ntfsdiff.rs`):
//! `paguro-harness ntfs-exhaustive` runs the full-strength version.
//! Stage 2: drive QEMU + a Windows guest over a dm-error-backed image and dump
//! `$LogFile`, `$BadClus` and the runlist after every scenario.

mod cntfs;
mod cref;
mod model;
mod ntfsdiff;
#[path = "../../paguro-core/tests/synth/mod.rs"]
mod synth;

type Check = fn(u64, u64) -> Result<(), String>;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        // Every fixture, exhaustive byte mutation, truncation, I/O faults
        // and the fuzz corpora, C against Rust (ntfsdiff.rs).
        "ntfs-exhaustive" => return exit(ntfsdiff::exhaustive()),
        // Fuzz seeds for fuzz/ and kernel/dm-paguro/test/fuzz/.
        "ntfs-seeds" => {
            let dir = std::env::args().nth(2).unwrap_or_else(|| "seeds".into());
            match ntfsdiff::write_seeds(std::path::Path::new(&dir)) {
                Ok(n) => println!("{n} seeds in {dir}"),
                Err(e) => exit(Err(e)),
            }
            return;
        }
        // Sectors the core reads to add a volume and claim (rec, seq) on a
        // fixture image: the VM test fails each one in turn (dm-error).
        "ntfs-reads" => {
            let a: Vec<String> = std::env::args().skip(2).collect();
            let (Some(img), Some(rec), Some(seq)) = (a.first(), a.get(1), a.get(2)) else {
                return exit(Err("usage: ntfs-reads <image.gz> <rec> <seq>".into()));
            };
            let img = ntfsdiff::image(img.trim_end_matches(".gz"));
            let r = ntfsdiff::reads(&img, rec.parse().unwrap_or(0), seq.parse().unwrap_or(0));
            for s in r {
                println!("{s}");
            }
            return;
        }
        _ => {}
    }
    let rounds: u64 = arg.parse().unwrap_or(100_000);
    let checks: [(&str, Check); 6] = [
        ("range model (Rust spec vs oracle)", model::check),
        ("kernel C vs Rust spec", cref::check),
        ("NTFS core C vs Rust, mutated synthetic volumes", |r, s| {
            ntfsdiff::random_synthetic(r / 10, s)
        }),
        ("claim checks C vs Rust", ntfsdiff::random_claims),
        ("runlist decoder C vs Rust", ntfsdiff::random_runlists),
        ("NTFS fixtures and named corruptions", |_, _| {
            ntfsdiff::manifest()
                .iter()
                .try_for_each(ntfsdiff::check_case)
        }),
    ];
    for (name, check) in checks {
        match check(rounds, 0x5eed) {
            Ok(()) => println!("{name}: {rounds} rounds, no divergence"),
            Err(e) => {
                eprintln!("{name} DIVERGED: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn exit(r: Result<(), String>) {
    if let Err(e) = r {
        eprintln!("DIVERGED: {e}");
        std::process::exit(1);
    }
}
