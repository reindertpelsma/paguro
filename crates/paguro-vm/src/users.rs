//! The identity mapping on the Linux side (DESIGN.md §4.7): the service's
//! `accounts` frame in, Linux users created, renamed, locked and unlocked
//! to match, the map recorded, `accounts-ack` out.
//!
//! **`/etc/passwd` marks paguro's users itself**: their GECOS field is
//! `paguro <SID>`. So a sync that stopped halfway (a `useradd` that failed
//! after an earlier one succeeded) is safe to run again: a marked user is
//! never counted as someone else's name or uid, and an action already done
//! is recognised and skipped.

use std::fs;
use std::path::Path;
use std::process::Command;

use paguro_link::idmap::{self, Action, IdMap, WindowsAccount};
use serde_json::{Value, json};

type R<T> = Result<T, String>;

/// Where the map is recorded, next to the link's other state.
pub const IDMAP_FILE: &str = "idmap.json";

/// The GECOS marker of a user paguro made.
pub fn gecos(sid: &str) -> String {
    format!("paguro {sid}")
}

/// One `/etc/passwd` line's name, uid and GECOS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswdUser {
    pub name: String,
    pub uid: u32,
    pub gecos: String,
}

pub fn parse_passwd(text: &str) -> Vec<PasswdUser> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?.to_string();
            let uid = f.nth(1)?.parse().ok()?;
            let gecos = f.nth(1).unwrap_or("").to_string();
            Some(PasswdUser { name, uid, gecos })
        })
        .collect()
}

/// Applies one action to the system. A trait so tests see the commands
/// without running them.
pub trait Accounts {
    fn run(&mut self, argv: &[String]) -> R<()>;
}

pub struct SystemAccounts;

impl Accounts for SystemAccounts {
    fn run(&mut self, argv: &[String]) -> R<()> {
        let (cmd, args) = argv.split_first().ok_or("empty command")?;
        let out = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("{cmd}: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{}: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

/// The command for one action, or `None` when `passwd` shows it done.
///
/// - create: a home directory and a group of the same name; the login
///   shell is the system's default;
/// - rename: `usermod -l` only: the home directory stays where it is
///   (§4.7 "home directory untouched");
/// - lock: the password locked **and** the account expired, so key-based
///   SSH is refused too (`-L` alone does not stop it); unlock reverses
///   both.
pub fn command(
    action: &Action,
    sid_of: impl Fn(u32) -> String,
    passwd: &[PasswdUser],
) -> Option<Vec<String>> {
    let has = |name: &str, uid: u32| passwd.iter().any(|p| p.name == name && p.uid == uid);
    let v = |a: &[&str]| Some(a.iter().map(|s| s.to_string()).collect());
    match action {
        Action::Create { uid, linux_user } => {
            if has(linux_user, *uid) {
                return None;
            }
            let (u, c) = (uid.to_string(), gecos(&sid_of(*uid)));
            v(&[
                "useradd",
                "--create-home",
                "--user-group",
                "--uid",
                &u,
                "--comment",
                &c,
                "--",
                linux_user,
            ])
        }
        Action::Rename { uid, from, to } => {
            if has(to, *uid) {
                return None;
            }
            v(&["usermod", "--login", to, "--", from])
        }
        Action::Lock { linux_user, .. } => {
            v(&["usermod", "--lock", "--expiredate", "1", "--", linux_user])
        }
        Action::Unlock { linux_user, .. } => {
            v(&["usermod", "--unlock", "--expiredate", "", "--", linux_user])
        }
    }
}

/// The host's side of an `accounts` frame: sync the recorded map against
/// Windows' list, apply what changed, record the map once every action
/// succeeded, and reply with the mapping (or the error; the map is then
/// left as it was, and the next sync redoes what is missing).
pub fn handle_accounts(
    state_dir: &Path,
    passwd_path: &Path,
    sys: &mut dyn Accounts,
    req: &Value,
) -> Value {
    match sync(state_dir, passwd_path, sys, req) {
        Ok(map) => idmap::accounts_ack_frame(&map),
        Err(e) => json!({"type": "accounts-ack", "error": e}),
    }
}

fn sync(state_dir: &Path, passwd_path: &Path, sys: &mut dyn Accounts, req: &Value) -> R<IdMap> {
    let accounts: Vec<WindowsAccount> =
        idmap::parse_accounts(req).ok_or("not an accounts frame")??;
    let path = state_dir.join(IDMAP_FILE);
    let mut map = match fs::read_to_string(&path) {
        Ok(t) => {
            let v: Value =
                serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?;
            IdMap::from_json(&v)?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => IdMap::default(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let passwd_text =
        fs::read_to_string(passwd_path).map_err(|e| format!("{}: {e}", passwd_path.display()))?;
    let passwd = parse_passwd(&passwd_text);
    // Everyone paguro did not make is someone else's name and uid.
    let others: Vec<&PasswdUser> = passwd
        .iter()
        .filter(|p| !p.gecos.starts_with("paguro "))
        .collect();
    let names: Vec<&str> = others.iter().map(|p| p.name.as_str()).collect();
    let uids: Vec<u32> = others.iter().map(|p| p.uid).collect();

    let actions = map.sync(&accounts, &names, &uids)?;
    for a in &actions {
        let sid_of = |uid| map.by_uid(uid).map(|e| e.sid.clone()).unwrap_or_default();
        if let Some(argv) = command(a, sid_of, &passwd) {
            sys.run(&argv)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, format!("{:#}\n", map.to_json()))
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(map)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    const M: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    #[derive(Default)]
    struct Fake {
        ran: Vec<String>,
        fail_on: Option<&'static str>,
    }
    impl Accounts for Fake {
        fn run(&mut self, argv: &[String]) -> R<()> {
            let line = argv.join(" ");
            if self.fail_on.is_some_and(|f| line.contains(f)) {
                return Err(format!("{line}: failed"));
            }
            self.ran.push(line);
            Ok(())
        }
    }

    fn acct(rid: u32, name: &str) -> WindowsAccount {
        WindowsAccount {
            sid: format!("{M}-{rid}"),
            name: name.into(),
        }
    }

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("paguro-users-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn passwd_lines() {
        let p = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\nanna:x:5000:5000:paguro S-1-5-21-1-2-3-1001:/home/anna:/bin/bash\nbroken\n",
        );
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[1],
            PasswdUser {
                name: "anna".into(),
                uid: 5000,
                gecos: "paguro S-1-5-21-1-2-3-1001".into()
            }
        );
    }

    #[test]
    fn creates_records_and_replies() {
        let d = dir("create");
        let pw = d.join("passwd");
        fs::write(
            &pw,
            "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000:Bob:/home/bob:/bin/bash\n",
        )
        .unwrap();
        let mut sys = Fake::default();
        let req = idmap::accounts_frame(&[acct(1001, "Anna"), acct(1002, "Bob")]);
        let ack = handle_accounts(&d, &pw, &mut sys, &req);
        let users = idmap::parse_accounts_ack(&ack).unwrap().unwrap();
        assert_eq!(
            users,
            vec![
                (format!("{M}-1001"), 5000, "anna".into()),
                (format!("{M}-1002"), 5001, "bob2".into())
            ]
        );
        assert_eq!(
            sys.ran,
            [
                format!(
                    "useradd --create-home --user-group --uid 5000 --comment paguro {M}-1001 -- anna"
                ),
                format!(
                    "useradd --create-home --user-group --uid 5001 --comment paguro {M}-1002 -- bob2"
                ),
            ]
        );
        assert!(
            fs::read_to_string(d.join(IDMAP_FILE))
                .unwrap()
                .contains("\"linux_user\": \"bob2\"")
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_sync_is_redone_without_new_names() {
        let d = dir("redo");
        let pw = d.join("passwd");
        fs::write(&pw, "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        let req = idmap::accounts_frame(&[acct(1001, "Anna"), acct(1002, "Carol")]);
        // anna is made, carol fails: nothing recorded.
        let mut sys = Fake {
            fail_on: Some("carol"),
            ..Fake::default()
        };
        let ack = handle_accounts(&d, &pw, &mut sys, &req);
        assert!(matches!(idmap::parse_accounts_ack(&ack), Some(Err(_))));
        assert!(!d.join(IDMAP_FILE).exists());
        // The system now has anna, marked as paguro's.
        fs::write(&pw, format!("root:x:0:0:root:/root:/bin/bash\nanna:x:5000:5000:paguro {M}-1001:/home/anna:/bin/sh\n")).unwrap();
        let mut sys = Fake::default();
        let ack = handle_accounts(&d, &pw, &mut sys, &req);
        let users = idmap::parse_accounts_ack(&ack).unwrap().unwrap();
        // Same names and uids as the first attempt; anna not made twice.
        assert_eq!(users[0], (format!("{M}-1001"), 5000, "anna".into()));
        assert_eq!(users[1], (format!("{M}-1002"), 5001, "carol".into()));
        assert_eq!(sys.ran.len(), 1);
        assert!(sys.ran[0].ends_with("-- carol"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rename_and_lock_commands() {
        let pw = parse_passwd("");
        let sid = |_| String::new();
        let r = command(
            &Action::Rename {
                uid: 5000,
                from: "anna".into(),
                to: "anna_b".into(),
            },
            sid,
            &pw,
        )
        .unwrap();
        assert_eq!(r.join(" "), "usermod --login anna_b -- anna");
        let l = command(
            &Action::Lock {
                uid: 5000,
                linux_user: "anna".into(),
            },
            sid,
            &pw,
        )
        .unwrap();
        assert_eq!(l.join(" "), "usermod --lock --expiredate 1 -- anna");
        let u = command(
            &Action::Unlock {
                uid: 5000,
                linux_user: "anna".into(),
            },
            sid,
            &pw,
        )
        .unwrap();
        assert_eq!(u, ["usermod", "--unlock", "--expiredate", "", "--", "anna"]);
        // Already renamed: skipped.
        let done = parse_passwd("anna_b:x:5000:5000:paguro x:/home/anna:/bin/sh");
        assert!(
            command(
                &Action::Rename {
                    uid: 5000,
                    from: "anna".into(),
                    to: "anna_b".into()
                },
                sid,
                &done
            )
            .is_none()
        );
    }

    #[test]
    fn an_empty_listing_is_an_error_reply() {
        let d = dir("empty");
        let pw = d.join("passwd");
        fs::write(&pw, "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        let mut sys = Fake::default();
        let ack = handle_accounts(&d, &pw, &mut sys, &idmap::accounts_frame(&[]));
        assert!(matches!(idmap::parse_accounts_ack(&ack), Some(Err(_))));
        assert!(sys.ran.is_empty());
        let _ = fs::remove_dir_all(&d);
    }
}
