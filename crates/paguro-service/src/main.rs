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
        rest if !has_console() && !rest.iter().any(|a| a == "--json" || a == "--report") => {
            windowed(rest)
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
    let (api, console) = (paguro_win::real::RealApi::new(), has_console());
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

/// Run without a console (Apps & Features runs `paguro.exe uninstall` and
/// `paguro.exe repair`; a shortcut; the Run box): ask with dialogs what a
/// terminal would have asked, and show the outcome in a message box.
fn windowed(args: &[String]) {
    #[cfg(windows)]
    let api = paguro_win::real::RealApi::new();
    #[cfg(not(windows))]
    let api = paguro_win::mock::MockApi::standard();
    let me = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "paguro".into());
    let mut argv: Vec<String> = std::iter::once(me).chain(args.iter().cloned()).collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    if args.first().map(String::as_str) == Some("uninstall") && !has("--dry-run") {
        if !has("--yes") {
            if !msgbox_ex(
                "Uninstall paguro",
                "Remove paguro from this PC?\n\nLinux will no longer start from this PC. One restart goes through paguro to clean up, then Windows starts again.",
                true,
                true,
            ) {
                return;
            }
            argv.push("--yes".into());
        }
        if !has("--keep-images") && !has("--delete-images") {
            let delete = msgbox_ex(
                "Uninstall paguro: your Linux installations",
                "Delete the Linux disk images too?\n\nYes: they are deleted, with everything in them.\nNo: they are kept (you can delete them yourself later).",
                true,
                true,
            );
            argv.push(
                if delete {
                    "--delete-images"
                } else {
                    "--keep-images"
                }
                .into(),
            );
        }
    }
    let r = paguro_win::cli::run_with(&api, argv.iter(), &connect, &|_| {}, &|_| None);
    // What a person reads: the lines, and for a failure its one-line reason
    // (not the structured detail a terminal would also print).
    let reason = r.stderr.lines().next().unwrap_or("").trim().to_string();
    let text = if r.code == 0 || r.code == 8 {
        r.stdout.trim().to_string()
    } else {
        reason
    };
    let text = text.as_str();
    let title = if r.code == 0 || r.code == 8 {
        "paguro"
    } else {
        "paguro: not done"
    };
    msgbox(title, if text.is_empty() { "Done." } else { text }, false);
    std::process::exit(r.code);
}

/// Whether a person can read our output and answer at a terminal. No:
/// started from Explorer, the Start menu or Apps & Features (no console, and
/// no redirected standard output either). A process with redirected output
/// (CI, a script, another program) is never "windowed": nobody would see a
/// message box, and it would wait for ever.
#[cfg(windows)]
fn has_console() -> bool {
    use windows::Win32::System::Console::{
        FreeConsole, GetConsoleProcessList, GetConsoleWindow, GetStdHandle, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    // SAFETY: plain calls; the buffer outlives them.
    unsafe {
        let usable = |h: windows::core::Result<windows::Win32::Foundation::HANDLE>| {
            h.is_ok_and(|h| !h.is_invalid() && !h.0.is_null())
        };
        let console = !GetConsoleWindow().is_invalid();
        if !console {
            // Output goes somewhere a caller reads: stay a command line.
            return usable(GetStdHandle(STD_OUTPUT_HANDLE))
                || usable(GetStdHandle(STD_ERROR_HANDLE));
        }
        let mut pids = [0u32; 4];
        if GetConsoleProcessList(&mut pids) == 1 {
            // A console made for us alone (older Windows, started from
            // Explorer or Settings): give it back and use dialogs instead.
            let _ = FreeConsole();
            return false;
        }
    }
    true
}

#[cfg(not(windows))]
fn has_console() -> bool {
    true
}

fn start_gui(app: &str) {
    if let Err(e) = std::process::Command::new(app).spawn() {
        eprintln!("paguro: cannot start {app}: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn msgbox(title: &str, text: &str, question: bool) -> bool {
    msgbox_ex(title, text, question, false)
}

/// `default_no`: the destructive questions start on No.
#[cfg(windows)]
fn msgbox_ex(title: &str, text: &str, question: bool, default_no: bool) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON2, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MessageBoxW,
    };
    use windows::core::HSTRING;
    let mut flags = if question {
        MB_YESNO | MB_ICONQUESTION
    } else {
        MB_OK | MB_ICONINFORMATION
    };
    if default_no {
        flags |= MB_DEFBUTTON2;
    }
    // SAFETY: valid strings; no owner window.
    unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from(title), flags) == IDYES }
}

#[cfg(not(windows))]
fn msgbox_ex(title: &str, text: &str, question: bool, _default_no: bool) -> bool {
    msgbox(title, text, question)
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
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        // Nobody to answer (a script, CI): never wait for input.
        eprintln!(
            "{title}: {text}\n(not asked: standard input is not a terminal; run `paguro install`)"
        );
        return false;
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
