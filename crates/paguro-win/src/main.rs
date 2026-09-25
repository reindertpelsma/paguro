//! `paguro.exe` (INTERFACES.md §11.2). All logic is in the library; this
//! only binds the real platform and writes the rendered result.

use std::io::Write;

fn main() {
    #[cfg(windows)]
    let api = paguro_win_real::RealApi::new();
    #[cfg(not(windows))]
    let api = paguro_win::mock::MockApi::standard();
    #[cfg(not(windows))]
    eprintln!("paguro: not Windows — running against the in-memory mock machine");
    let r = paguro_win::cli::run(&api, std::env::args_os());
    let _ = std::io::stdout().write_all(r.stdout.as_bytes());
    let _ = std::io::stderr().write_all(r.stderr.as_bytes());
    std::process::exit(r.code);
}
