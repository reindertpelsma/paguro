//! The storage torture harness.
//!
//! DESIGN.md is explicit that **this is built before anything else**: a
//! sacrificial NTFS volume, a Windows VM, and a block layer refusing exactly what
//! the module would refuse — then defrag, `chkdsk`, shrink, conversion, Windows
//! Update and power loss at every write boundary, against §11 Q1–Q3.
//!
//! Stage 1 (here, now): a model check of the range test against a naive oracle,
//! and a differential test of the kernel module's C against that Rust spec.
//! Stage 2: drive QEMU + a Windows guest over a dm-error-backed image and dump
//! `$LogFile`, `$BadClus` and the runlist after every scenario.

mod cref;
mod model;

type Check = fn(u64, u64) -> Result<(), String>;

fn main() {
    let rounds: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(100_000);
    let checks: [(&str, Check); 2] = [
        ("range model (Rust spec vs oracle)", model::check),
        ("kernel C vs Rust spec", cref::check),
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
