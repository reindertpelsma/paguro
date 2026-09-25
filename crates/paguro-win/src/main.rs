//! `paguro.exe` (INTERFACES.md §11.2, §11.7). All logic is in the library;
//! this binds the platform, finds the service, and writes the result.
//!
//! With the paguro service installed, every command goes to it over
//! `\\.\pipe\paguro` (a thin client); without it, or with `--direct` /
//! `PAGURO_DIRECT=1`, the same method runs in this process. On a non-Windows
//! host (development), `PAGURO_UNIX_SOCKET` names a `paguro-service console
//! --mock --unix` socket to use instead.

use std::io::Write;

use paguro_win::cli::{self, Transport};

fn connect() -> Option<Box<dyn Transport>> {
    if std::env::var_os("PAGURO_DIRECT").is_some() {
        return None;
    }
    #[cfg(windows)]
    {
        use paguro_win::real::pipe::{Connect, connect};
        match connect() {
            Connect::Service(t) => Some(t),
            Connect::NoService => None,
            Connect::Refused(why) => {
                eprintln!("paguro: not using the paguro service ({why}); running directly");
                None
            }
        }
    }
    #[cfg(unix)]
    {
        let path = std::env::var_os("PAGURO_UNIX_SOCKET")?;
        let s = std::os::unix::net::UnixStream::connect(path).ok()?;
        let r = s.try_clone().ok()?;
        Some(Box::new(paguro_win::client::StreamTransport::new(
            Box::new(r),
            Box::new(s),
        )))
    }
}

fn absolute(p: &str) -> Option<String> {
    let path = std::path::Path::new(p);
    if cfg!(windows) && path.is_relative() {
        std::path::absolute(path)
            .ok()
            .map(|a| a.display().to_string())
    } else {
        None
    }
}

fn main() {
    #[cfg(windows)]
    let api = paguro_win::real::RealApi::new();
    #[cfg(not(windows))]
    let api = paguro_win::mock::MockApi::standard();
    #[cfg(not(windows))]
    if std::env::var_os("PAGURO_UNIX_SOCKET").is_none() {
        eprintln!("paguro: not Windows — running against the in-memory mock machine");
    }
    let r = cli::run_with(
        &api,
        std::env::args_os(),
        &connect,
        &|l| eprintln!("{l}"),
        &absolute,
    );
    let _ = std::io::stdout().write_all(r.stdout.as_bytes());
    let _ = std::io::stderr().write_all(r.stderr.as_bytes());
    std::process::exit(r.code);
}
