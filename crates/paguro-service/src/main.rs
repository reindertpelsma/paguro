//! `paguro.exe` (INTERFACES.md §11.2, §11.7, §11.7a): the command line, the
//! service and the installer in one binary.
//!
//! ```text
//! paguro service              the Windows service (run by the service control manager)
//! paguro service console …    the service in the foreground (debugging, tests)
//! paguro <command> …          the command line
//! ```
//!
//! All logic is in the libraries; this binds the platform, finds the
//! service, and writes the result.
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
    let args: Vec<String> = std::env::args().collect();
    match args.get(1..).unwrap_or(&[]) {
        [] => no_arguments(),
        [s] if s == "service" => service(),
        [s, c, rest @ ..] if s == "service" && c == "console" => {
            paguro_service::console::console(rest)
        }
        _ => cli(),
    }
}

/// A double-click or the Start menu (INTERFACES §11.7a): the GUI, or the
/// offer to install paguro first. Never a console window: with the
/// manifest's detached console policy (Windows 11 24H2 on) there is none,
/// and on older Windows the one created for us is released at once.
fn no_arguments() {
    #[cfg(windows)]
    let (api, console) = (paguro_win::real::RealApi::new(), release_own_console());
    #[cfg(not(windows))]
    let (api, console) = (paguro_win::mock::MockApi::standard(), true);
    use paguro_win::cmd::setup::{Launch, launch};
    match launch(&api) {
        Ok(Launch::Gui(app)) => start_gui(&app),
        Ok(Launch::NoGui) => tell(
            console,
            "paguro",
            "This paguro has no GUI (the CLI-only build). Use it from a terminal: paguro --help",
        ),
        Ok(Launch::OfferInstall) => {
            let q = "paguro is not installed on this PC.\n\nInstall it now? Windows asks for administrator permission once.";
            if !ask(console, "Install paguro", q) {
                return;
            }
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "paguro".into());
            let r = paguro_win::cli::run_with(
                &api,
                [exe.as_str(), "install"],
                &|| None,
                &|_| {},
                &|_| None,
            );
            if r.code != 0 {
                let why = if r.stderr.trim().is_empty() {
                    r.stdout
                } else {
                    r.stderr
                };
                tell(console, "paguro was not installed", why.trim());
                std::process::exit(r.code);
            }
            if console {
                print!("{}", r.stdout);
            }
            match launch(&api) {
                Ok(Launch::Gui(app)) => start_gui(&app),
                _ => tell(
                    console,
                    "paguro",
                    "paguro is installed. Use it from a terminal: paguro --help",
                ),
            }
        }
        Err(e) => tell(console, "paguro", &e.message),
    }
}

fn start_gui(app: &str) {
    if let Err(e) = std::process::Command::new(app).spawn() {
        eprintln!("paguro: cannot start {app}: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn release_own_console() -> bool {
    use windows::Win32::System::Console::{FreeConsole, GetConsoleProcessList, GetConsoleWindow};
    // SAFETY: plain calls; the buffer outlives them.
    unsafe {
        if GetConsoleWindow().is_invalid() {
            return false;
        }
        let mut pids = [0u32; 4];
        // Only us: Windows made this console for a double-click (older
        // Windows, no detached policy). Give it back at once.
        if GetConsoleProcessList(&mut pids) == 1 {
            let _ = FreeConsole();
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn msgbox(title: &str, text: &str, question: bool) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MessageBoxW,
    };
    use windows::core::HSTRING;
    let flags = if question {
        MB_YESNO | MB_ICONQUESTION
    } else {
        MB_OK | MB_ICONINFORMATION
    };
    // SAFETY: valid strings; no owner window.
    unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from(title), flags) == IDYES }
}

#[cfg(not(windows))]
fn msgbox(title: &str, text: &str, _question: bool) -> bool {
    eprintln!("{title}: {text}");
    false
}

fn tell(console: bool, title: &str, text: &str) {
    if console {
        eprintln!("{title}: {text}");
    } else {
        msgbox(title, text, false);
    }
}

fn ask(console: bool, title: &str, text: &str) -> bool {
    if !console {
        return msgbox(title, text, true);
    }
    eprint!("{text} [Y/n] ");
    let mut l = String::new();
    std::io::stdin().read_line(&mut l).is_ok() && !matches!(l.trim(), "n" | "N" | "no" | "No")
}

#[cfg(windows)]
fn service() {
    if let Err(e) = paguro_service::win::run_service() {
        eprintln!(
            "paguro service: {e}: this runs under the service control manager (`paguro service install`), or use `paguro service console`"
        );
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn service() {
    eprintln!("paguro service: only on Windows; use `paguro service console --mock`");
    std::process::exit(2);
}

fn cli() {
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
