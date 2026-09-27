//! `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`'s `BootExecute`
//! (a REG_MULTI_SZ) and the system volume's dirty bit (DESIGN.md §4.4
//! "Prevention, so users rarely meet it"): in the paguro VM, `chkdsk /r` or
//! `/b` on a volume it cannot lock schedules a boot-time bad-sector scan by
//! adding a forced autochk entry here -- exactly the read that would race
//! DESIGN.md §4.4's tripwire on the next boot. This module only ever
//! removes that entry and restores the plain default
//! (`autocheck autochk *`).
//!
//! **It never touches the dirty bit.** Windows exposes no way to tell
//! "chkdsk's own scheduling set this" from "an unclean shutdown set this"
//! (there is exactly one bit, with no provenance) -- and a read-write
//! ntfs3 mount depends on the same bit meaning what it says (DESIGN.md's
//! Rule 3, §2946). Clearing it here could suppress a real repair, so a real
//! one is left for the user to run natively, with a notice explaining why
//! (`Notice` below).
//!
//! All parsing/rewriting is pure and tested without touching the registry;
//! [`enforce`] is the only impure entry point, over `reg.exe`/`fsutil.exe`
//! like this crate's other registry reads (`crate::cmd::checks::fast_startup`).

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::{WinApi, join};
use crate::ctx::Ctx;

pub const KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager";
pub const VALUE: &str = "BootExecute";
pub const DEFAULT: &str = "autocheck autochk *";

/// `reg query KEY /v VALUE`'s stdout -> the REG_MULTI_SZ's entries. `None`:
/// the value line was not found (the query failed, or the value is absent
/// -- treated as "nothing to fix": this never invents a `BootExecute`
/// Windows did not have).
pub fn parse(reg_query_stdout: &str) -> Option<Vec<String>> {
    let line = reg_query_stdout
        .lines()
        .find(|l| l.trim_start().starts_with(VALUE) && l.contains("REG_MULTI_SZ"))?;
    let rest = line.split_once("REG_MULTI_SZ")?.1.trim();
    if rest.is_empty() {
        return Some(Vec::new());
    }
    // `reg query`'s display joins entries with a literal `\0`; some builds
    // also trail one after the last entry, which would otherwise read back
    // as a spurious empty entry.
    let mut entries: Vec<String> = rest.split("\\0").map(str::to_string).collect();
    if entries.last().is_some_and(String::is_empty) {
        entries.pop();
    }
    Some(entries)
}

/// An entry that forces autochk to scan for bad sectors (`/r` or `/b`) --
/// the kind chkdsk writes here when it cannot lock the volume it targets,
/// regardless of what it names as the target (`*`, `\??\C:`, a volume
/// GUID...).
fn is_forced_scan(entry: &str) -> bool {
    let lower = entry.to_ascii_lowercase();
    lower.contains("autochk")
        && lower
            .split_whitespace()
            .any(|tok| tok == "/r" || tok == "/b")
}

pub fn has_forced_scan(entries: &[String]) -> bool {
    entries.iter().any(|e| is_forced_scan(e))
}

/// `entries` with every forced scan removed and the plain default present
/// exactly once; `None` if nothing needed changing (the common case: no
/// scan was scheduled, or it already reads exactly the default).
pub fn without_forced_scan(entries: &[String]) -> Option<Vec<String>> {
    let mut kept: Vec<String> = entries
        .iter()
        .filter(|e| !is_forced_scan(e))
        .cloned()
        .collect();
    if !kept.iter().any(|e| e == DEFAULT) {
        kept.insert(0, DEFAULT.to_string());
    }
    (kept != entries).then_some(kept)
}

/// `reg add KEY /v VALUE /t REG_MULTI_SZ /d ... /f`'s `/d` argument.
pub fn join_for_reg_add(entries: &[String]) -> String {
    entries.join("\\0")
}

/// `fsutil dirty query C:`'s stdout -> the dirty bit; `None`: unparseable
/// (a locale where the message differs, or the command failed).
pub fn parse_dirty(out: &str) -> Option<bool> {
    let l = out.lines().find(|l| {
        let l = l.to_ascii_lowercase();
        l.contains("is dirty") || l.contains("is not dirty")
    })?;
    Some(!l.to_ascii_lowercase().contains("is not dirty"))
}

/// What one pass found and fixed, for the notice (event log + `paguro
/// status`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Notice {
    pub message: String,
    /// The dirty bit at the time, left untouched either way (see the
    /// module documentation).
    pub dirty: Option<bool>,
}

pub fn notice_path(api: &dyn WinApi) -> String {
    join(&api.program_data(), "paguro\\vm-notices.json")
}

fn save_notice(api: &dyn WinApi, n: &Notice) {
    let _ = api.create_dir_all(&join(&api.program_data(), "paguro"));
    let body = json!({ "chkdsk": n, "at_unix": api.now_unix() }).to_string();
    let _ = api.write_file(&notice_path(api), body.as_bytes());
}

/// One pass: read `BootExecute`, remove any forced scan, write it back if
/// that changed anything, and return the notice raised (if any). Never
/// touches the dirty bit. Errors from `reg.exe`/`fsutil.exe` are logged,
/// not propagated -- this must never stop the service.
pub fn enforce(ctx: &Ctx<'_>, log: &dyn Fn(&str)) -> Option<Notice> {
    let drive = ctx.api.system_drive();
    let dirty = ctx
        .api
        .run("fsutil.exe", &["dirty", "query", &drive], None)
        .ok()
        .and_then(|o| parse_dirty(&o.stdout));
    let q = match ctx.api.run("reg.exe", &["query", KEY, "/v", VALUE], None) {
        Ok(o) if o.ok() => o.stdout,
        Ok(o) => {
            log(&format!(
                "chkdsk-guard: reg query {VALUE}: {}",
                o.stderr.trim()
            ));
            return None;
        }
        Err(e) => {
            log(&format!("chkdsk-guard: reg query {VALUE}: {e}"));
            return None;
        }
    };
    let Some(entries) = parse(&q) else {
        log("chkdsk-guard: BootExecute not found; leaving it alone");
        return None;
    };
    let fixed = without_forced_scan(&entries)?;
    let d = join_for_reg_add(&fixed);
    match ctx.api.run(
        "reg.exe",
        &[
            "add",
            KEY,
            "/v",
            VALUE,
            "/t",
            "REG_MULTI_SZ",
            "/d",
            &d,
            "/f",
        ],
        None,
    ) {
        Ok(o) if o.ok() => {
            let message = format!(
                "a boot-time disk check was scheduled for {drive} (chkdsk /r or /b); paguro \
                 removed it here so it will not race the paguro VM's tripwire (DESIGN.md sec. \
                 4.4). Start Windows natively once to run the check there, where it is harmless.{}",
                if dirty == Some(true) {
                    format!(
                        " ({drive} is also marked dirty; that flag is left as-is -- Windows \
                         gives no way to tell chkdsk's own scheduling from an unclean shutdown, \
                         and clearing it could suppress a real repair.)"
                    )
                } else {
                    String::new()
                }
            );
            log(&format!("chkdsk-guard: {message}"));
            let _ = ctx.api.report_event(&message);
            let n = Notice { message, dirty };
            save_notice(ctx.api, &n);
            Some(n)
        }
        Ok(o) => {
            log(&format!(
                "chkdsk-guard: reg add {VALUE}: {}",
                o.stderr.trim()
            ));
            None
        }
        Err(e) => {
            log(&format!("chkdsk-guard: reg add {VALUE}: {e}"));
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mock::MockApi;

    #[test]
    fn parses_reg_query_multi_sz() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\r\n    BootExecute    REG_MULTI_SZ    autocheck autochk *\\0\r\n\r\n";
        assert_eq!(parse(out), Some(vec![DEFAULT.to_string()]));
        let scheduled = "    BootExecute    REG_MULTI_SZ    autocheck autochk *\\0autocheck autochk /r \\??\\C:\\0";
        assert_eq!(
            parse(scheduled),
            Some(vec![
                DEFAULT.to_string(),
                "autocheck autochk /r \\??\\C:".to_string()
            ])
        );
        assert_eq!(parse("nothing here"), None);
    }

    #[test]
    fn detects_forced_scans_of_any_target() {
        assert!(!has_forced_scan(&[DEFAULT.to_string()]));
        assert!(has_forced_scan(&["autocheck autochk /r \\??\\C:".into()]));
        assert!(has_forced_scan(&["autocheck autochk /b *".into()]));
        assert!(has_forced_scan(&["autochk /r".into()]));
        // Case, and a flag that merely starts with r/b some other way, are
        // not mistaken for /r or /b (only a token, not a substring).
        assert!(!has_forced_scan(&["autocheck autochk /report".into()]));
        assert!(has_forced_scan(&["AUTOCHECK AUTOCHK /R \\??\\C:".into()]));
    }

    #[test]
    fn removes_only_the_forced_entries_and_keeps_others() {
        let entries = vec![
            DEFAULT.to_string(),
            "autocheck autochk /r \\??\\C:".to_string(),
            "some third-party boot program".to_string(),
        ];
        let fixed = without_forced_scan(&entries).unwrap();
        assert_eq!(
            fixed,
            vec![
                DEFAULT.to_string(),
                "some third-party boot program".to_string()
            ]
        );
        // The default replaced in place (no separate entry appended), the
        // common form when only /f (not /r or /b) was used and it was not
        // even present as a distinct forced-scan entry: a no-op.
        assert_eq!(without_forced_scan(&[DEFAULT.to_string()]), None);
        // The default missing entirely (replaced, not appended, by an
        // older chkdsk): restored.
        assert_eq!(
            without_forced_scan(&["autocheck autochk /r \\??\\C:".to_string()]),
            Some(vec![DEFAULT.to_string()])
        );
        assert_eq!(
            join_for_reg_add(&fixed),
            format!("{DEFAULT}\\0some third-party boot program")
        );
    }

    #[test]
    fn parses_dirty_bit() {
        assert_eq!(parse_dirty("Volume - C: is Dirty"), Some(true));
        assert_eq!(parse_dirty("Volume - C: is NOT Dirty"), Some(false));
        assert_eq!(parse_dirty("garbage"), None);
    }

    #[test]
    fn enforce_undoes_a_scheduled_scan_and_leaves_dirty_alone() {
        let m = MockApi::standard();
        m.set_runner(|prog, args| {
            Some(match prog {
                "fsutil.exe" => crate::api::Output {
                    status: 0,
                    stdout: "Volume - C: is Dirty\r\n".into(),
                    stderr: String::new(),
                },
                "reg.exe" if args.first() == Some(&"query") => crate::api::Output {
                    status: 0,
                    stdout: format!(
                        "    BootExecute    REG_MULTI_SZ    {DEFAULT}\\0autocheck autochk /r \\??\\C:\\0"
                    ),
                    stderr: String::new(),
                },
                "reg.exe" if args.first() == Some(&"add") => {
                    assert!(args.contains(&DEFAULT));
                    assert!(!args.iter().any(|a| a.contains("/r")));
                    crate::api::Output {
                        status: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    }
                }
                _ => panic!("unexpected: {prog} {args:?}"),
            })
        });
        let ctx = Ctx::new(&m);
        let n = enforce(&ctx, &|_| {}).expect("a notice was raised");
        assert_eq!(n.dirty, Some(true));
        assert!(n.message.contains("chkdsk /r or /b"));
        assert!(n.message.contains("left as-is"));
        assert_eq!(m.events.borrow().len(), 1);
        let saved: serde_json::Value =
            serde_json::from_slice(&m.read_file(&notice_path(&m), 1 << 16).unwrap().unwrap())
                .unwrap();
        assert_eq!(saved["chkdsk"]["dirty"], true);
    }

    #[test]
    fn enforce_is_quiet_when_nothing_is_scheduled() {
        let m = MockApi::standard();
        m.set_runner(|prog, _args| {
            Some(match prog {
                "fsutil.exe" => crate::api::Output {
                    status: 0,
                    stdout: "Volume - C: is NOT Dirty\r\n".into(),
                    stderr: String::new(),
                },
                "reg.exe" => crate::api::Output {
                    status: 0,
                    stdout: format!("    BootExecute    REG_MULTI_SZ    {DEFAULT}\\0"),
                    stderr: String::new(),
                },
                _ => panic!("unexpected: {prog}"),
            })
        });
        let ctx = Ctx::new(&m);
        assert_eq!(enforce(&ctx, &|_| {}), None);
        assert!(m.events.borrow().is_empty());
    }
}
