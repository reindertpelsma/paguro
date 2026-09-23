//! The storage torture harness.
//!
//! DESIGN.md is explicit that **this is built before anything else**: a
//! sacrificial NTFS volume, a Windows VM, and a block layer refusing exactly what
//! the module would refuse — then defrag, `chkdsk`, shrink, conversion, Windows
//! Update and power loss at every write boundary, against §11 Q1–Q3.
//!
//! Stage 1 (here, now): a model check of the range test against a naive oracle.
//! Stage 2: drive QEMU + a Windows guest over a dm-error-backed image and dump
//! `$LogFile`, `$BadClus` and the runlist after every scenario.

mod model;

fn main() {
    let rounds: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(100_000);
    match model::check(rounds, 0x5eed) {
        Ok(()) => println!("range model: {rounds} rounds, no divergence"),
        Err(e) => {
            eprintln!("range model DIVERGED: {e}");
            std::process::exit(1);
        }
    }
}
