//! The in-session agent's frames (INTERFACES.md §11.3 "Files, programs,
//! drives and users", DESIGN.md §5d): opening files and programs on the
//! other side, and the user's known folders. The agent port carries these
//! control messages only; a program's I/O never travels on it.
//!
//! Every field is checked on the way in, as for the link's frames: SIDs
//! and uids against the identity mapping's rules, paths against the fixed
//! path mapping ([`crate::paths`]; a path that cannot cross is refused
//! here, before anything is started), arguments bounded and free of NUL.

use serde_json::{Value, json};

use crate::idmap::{FIRST_UID, mapped_sid};
use crate::paths::{Paths, distro_ok};

/// At most this many arguments, each at most [`MAX_ARG`] bytes: Windows'
/// command line is 32 767 characters in all.
pub const MAX_ARGS: usize = 256;
pub const MAX_ARG: usize = 32_767;

/// The known folders Linux's XDG directories are bound to (DESIGN.md §5d
/// "Shared user folders").
pub const KNOWN_FOLDERS: [&str; 6] = [
    "Desktop",
    "Documents",
    "Downloads",
    "Pictures",
    "Videos",
    "Music",
];

/// A Windows path the path mapping accepts (absolute, a drive letter, no
/// `..`, not UNC). The distribution is irrelevant to the check.
pub fn windows_path_ok(p: &str) -> bool {
    p.len() <= MAX_ARG
        && Paths {
            l_letter: 'L',
            distro: "x",
        }
        .to_linux(p)
        .is_ok()
}

/// A Linux path the path mapping accepts.
pub fn linux_path_ok(p: &str) -> bool {
    p.len() <= MAX_ARG
        && Paths {
            l_letter: 'L',
            distro: "x",
        }
        .to_windows(p)
        .is_ok()
}

fn args_ok(a: &[String]) -> bool {
    a.len() <= MAX_ARGS && a.iter().all(|s| s.len() <= MAX_ARG && !s.contains('\0'))
}

fn str_list(v: &Value, k: &str) -> Option<Vec<String>> {
    match v.get(k) {
        None => Some(Vec::new()),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string)).collect(),
        _ => None,
    }
}

/// host → guest: `ShellExecute` in the session of the user named by `sid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenInWindows {
    pub id: u64,
    pub sid: String,
    pub path: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
}

/// guest → host: the mapped Linux user's launcher (`gio launch`) in
/// `distro` (`None`: the running one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenInLinux {
    pub id: u64,
    pub uid: u32,
    pub path: String,
    pub distro: Option<String>,
    pub args: Vec<String>,
    pub cwd: Option<String>,
}

impl OpenInWindows {
    pub fn to_json(&self) -> Value {
        json!({"type": "open", "id": self.id, "sid": self.sid, "path": self.path, "args": self.args, "cwd": self.cwd})
    }
}

impl OpenInLinux {
    pub fn to_json(&self) -> Value {
        json!({"type": "open", "id": self.id, "uid": self.uid, "path": self.path, "distro": self.distro, "args": self.args, "cwd": self.cwd})
    }
}

/// Which way an `open` frame goes is in its fields: `sid` and a Windows
/// path, or `uid` and a Linux path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Open {
    InWindows(OpenInWindows),
    InLinux(OpenInLinux),
}

/// `None`: not an `open` frame. `Some(Err((id, reason)))`: refused, with
/// the id to answer (0 when even that is missing).
pub fn parse_open(v: &Value) -> Option<Result<Open, (u64, String)>> {
    if crate::kind(v) != Some("open") {
        return None;
    }
    let id = v.get("id").and_then(Value::as_u64).unwrap_or(0);
    let bad = |why: &str| Some(Err((id, format!("open: {why}"))));
    if id == 0 {
        return bad("no id");
    }
    let Some(path) = v.get("path").and_then(Value::as_str) else {
        return bad("no path");
    };
    let Some(args) = str_list(v, "args").filter(|a| args_ok(a)) else {
        return bad("bad arguments");
    };
    let cwd = v.get("cwd").and_then(Value::as_str).map(str::to_string);
    if let Some(sid) = v.get("sid").and_then(Value::as_str) {
        if !mapped_sid(sid) {
            return bad("not a mapped account");
        }
        if !windows_path_ok(path) || cwd.as_deref().is_some_and(|c| !windows_path_ok(c)) {
            return bad("a path that does not cross");
        }
        return Some(Ok(Open::InWindows(OpenInWindows {
            id,
            sid: sid.into(),
            path: path.into(),
            args,
            cwd,
        })));
    }
    let Some(uid) = v
        .get("uid")
        .and_then(Value::as_u64)
        .and_then(|u| u32::try_from(u).ok())
        .filter(|&u| u >= FIRST_UID)
    else {
        return bad("neither a mapped sid nor a mapped uid");
    };
    let distro = v.get("distro").and_then(Value::as_str).map(str::to_string);
    if distro.as_deref().is_some_and(|d| !distro_ok(d)) {
        return bad("not a distribution name");
    }
    if !linux_path_ok(path) || cwd.as_deref().is_some_and(|c| !linux_path_ok(c)) {
        return bad("a path that does not cross");
    }
    Some(Ok(Open::InLinux(OpenInLinux {
        id,
        uid,
        path: path.into(),
        distro,
        args,
        cwd,
    })))
}

/// Either way: the outcome of the `open` with this `id`.
pub fn open_result(id: u64, r: Result<(), &str>) -> Value {
    match r {
        Ok(()) => json!({"type": "open-result", "id": id, "ok": true}),
        Err(e) => json!({"type": "open-result", "id": id, "ok": false, "error": e}),
    }
}

pub fn parse_open_result(v: &Value) -> Option<(u64, Result<(), String>)> {
    if crate::kind(v) != Some("open-result") {
        return None;
    }
    let id = v.get("id").and_then(Value::as_u64)?;
    Some(if v.get("ok").and_then(Value::as_bool) == Some(true) {
        (id, Ok(()))
    } else {
        let e = v.get("error").and_then(Value::as_str).unwrap_or("refused");
        (id, Err(e.to_string()))
    })
}

/// guest → host: the user's known folders, as Windows resolves them
/// (`SHGetKnownFolderPath`: OneDrive or a redirected Documents included).
pub fn known_folders_frame(sid: &str, folders: &[(&str, &str)]) -> Value {
    let m: serde_json::Map<String, Value> = folders
        .iter()
        .map(|(k, p)| ((*k).to_string(), json!(p)))
        .collect();
    json!({"type": "known-folders", "sid": sid, "folders": m})
}

/// An account's SID and its known folders as (name, Linux path).
pub type KnownFolders = (String, Vec<(String, String)>);

/// The folders the host binds, each as its Linux path, for the account
/// `sid`. Unknown names are ignored; a folder whose path does not cross is
/// left out (a known folder outside the mapped volumes stays unset rather
/// than pointing somewhere empty, DESIGN.md §5d).
pub fn parse_known_folders(v: &Value) -> Option<Result<KnownFolders, String>> {
    if crate::kind(v) != Some("known-folders") {
        return None;
    }
    let Some(sid) = v
        .get("sid")
        .and_then(Value::as_str)
        .filter(|s| mapped_sid(s))
    else {
        return Some(Err("known-folders: not a mapped account".into()));
    };
    let Some(map) = v.get("folders").and_then(Value::as_object) else {
        return Some(Err("known-folders: no folders".into()));
    };
    let p = Paths {
        l_letter: 'L',
        distro: "x",
    };
    let mut out = Vec::new();
    for name in KNOWN_FOLDERS {
        let Some(w) = map.get(name).and_then(Value::as_str) else {
            continue;
        };
        // Only a Windows volume: a known folder on L: would bind Linux's
        // folder to itself.
        match p.to_linux(w) {
            Ok(l) if l.starts_with("/mnt/") && !l.starts_with(crate::paths::LINUX_L) => {
                out.push((name.to_string(), l));
            }
            _ => {}
        }
    }
    Some(Ok((sid.to_string(), out)))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    #[test]
    fn open_in_windows() {
        let o = OpenInWindows {
            id: 7,
            sid: SID.into(),
            path: r"C:\Users\anna\Desktop\Word.lnk".into(),
            args: vec![r"L:\debian\home\anna\a.docx".into()],
            cwd: Some(r"C:\Users\anna".into()),
        };
        assert_eq!(
            parse_open(&o.to_json()),
            Some(Ok(Open::InWindows(o.clone())))
        );
        let mut v = o.to_json();
        v["path"] = json!(r"\\evil\share\x.exe");
        assert!(matches!(parse_open(&v), Some(Err((7, _)))));
        let mut v = o.to_json();
        v["sid"] = json!("S-1-5-18");
        assert!(matches!(parse_open(&v), Some(Err((7, _)))));
        let mut v = o.to_json();
        v["args"] = json!(["a\u{0}b"]);
        assert!(matches!(parse_open(&v), Some(Err((7, _)))));
        let mut v = o.to_json();
        v["id"] = json!(0);
        assert!(matches!(parse_open(&v), Some(Err((0, _)))));
    }

    #[test]
    fn open_in_linux() {
        let o = OpenInLinux {
            id: 9,
            uid: 5000,
            path: "/home/anna/Desktop/gimp.desktop".into(),
            distro: Some("fedora".into()),
            args: vec![],
            cwd: None,
        };
        assert_eq!(parse_open(&o.to_json()), Some(Ok(Open::InLinux(o.clone()))));
        for (k, bad) in [
            ("uid", json!(0)),
            ("uid", json!(1000)),
            ("path", json!("/proc/1/exe")),
            ("distro", json!("../x")),
            ("cwd", json!("rel")),
        ] {
            let mut v = o.to_json();
            v[k] = bad;
            assert!(matches!(parse_open(&v), Some(Err((9, _)))), "{k}");
        }
        assert_eq!(parse_open(&json!({"type": "ssh-keys"})), None);
    }

    #[test]
    fn results() {
        assert_eq!(
            parse_open_result(&open_result(3, Ok(()))),
            Some((3, Ok(())))
        );
        assert_eq!(
            parse_open_result(&open_result(4, Err("not executable"))),
            Some((4, Err("not executable".into())))
        );
    }

    #[test]
    fn known_folders() {
        let f = known_folders_frame(
            SID,
            &[
                ("Desktop", r"C:\Users\anna\OneDrive\Desktop"),
                ("Documents", r"D:\Docs"),
                ("Downloads", r"\\nas\dl"),
                ("Music", r"L:\debian\home\anna\Music"),
                ("Favorites", r"C:\Users\anna\Favorites"),
            ],
        );
        let (sid, dirs) = parse_known_folders(&f).unwrap().unwrap();
        assert_eq!(sid, SID);
        assert_eq!(
            dirs,
            vec![
                (
                    "Desktop".to_string(),
                    "/mnt/c/Users/anna/OneDrive/Desktop".to_string()
                ),
                ("Documents".to_string(), "/mnt/d/Docs".to_string()),
            ]
        );
        let bad = known_folders_frame("S-1-5-18", &[]);
        assert!(matches!(parse_known_folders(&bad), Some(Err(_))));
    }
}
