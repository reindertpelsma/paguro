//! A passphrase from the console without echo. The prompt goes to stderr,
//! so `--json` stdout stays one document.

use std::io::{BufRead, Write};

use windows::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};
use zeroize::Zeroizing;

use crate::api::{ApiError, ApiResult, ErrorKind};

pub fn read_secret(prompt: &str) -> ApiResult<Zeroizing<String>> {
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    // SAFETY: the standard input handle of this process.
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
        .map_err(|e| ApiError::new(ErrorKind::Other, "GetStdHandle", e.message()))?;
    let mut mode = CONSOLE_MODE::default();
    // SAFETY: out-pointer to a local. Failure means stdin is not a console.
    let console = unsafe { GetConsoleMode(h, &mut mode) }.is_ok();
    if console {
        // SAFETY: same handle; echo is restored below on every path.
        let _ = unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    }
    let mut line = Zeroizing::new(String::new());
    let r = std::io::stdin().lock().read_line(&mut line);
    if console {
        // SAFETY: restores the mode read above.
        let _ = unsafe { SetConsoleMode(h, mode) };
        let _ = writeln!(err);
    }
    r.map_err(|e| ApiError::new(ErrorKind::Other, "ReadConsoleW", e.to_string()))?;
    while line.ends_with(['\r', '\n']) {
        line.pop();
    }
    Ok(line)
}
