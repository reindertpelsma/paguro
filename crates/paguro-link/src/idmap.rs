//! The identity mapping, Windows SID → Linux uid (DESIGN.md §4.7 "Key on
//! the SID, never the username", §5d "Users on both sides").
//!
//! Pure bookkeeping: the recorded map, the Linux name derived from a
//! Windows account name, and what one sync against Windows' current account
//! list must do. Applying the actions (`useradd`, `usermod -l`,
//! `usermod -L`) is the caller's; so is reading the account list (the
//! service sends it) and the machine's existing Linux users.
//!
//! The rules, from §4.7:
//! - keyed on the SID; a renamed account renames the Linux user and leaves
//!   the home directory alone;
//! - a deleted account is **locked, never deleted**, and an account that
//!   reappears (a listing that missed it) is unlocked again: locking is the
//!   reversible choice;
//! - uids from a private range (5000+), never reused, even for locked
//!   entries;
//! - an empty listing is a failed listing, never "every account was
//!   deleted".

use serde_json::{Value, json};

/// The first uid paguro allocates (DESIGN.md §4.7).
pub const FIRST_UID: u32 = 5000;

/// Linux usernames: `[a-z_][a-z0-9_-]*`, at most 32 (`useradd`'s default
/// rule, without the trailing `$`).
pub const MAX_NAME: usize = 32;

/// One Windows account, as the service lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsAccount {
    pub sid: String,
    /// The account's name (the SAM name: the short, possibly truncated
    /// one for a Microsoft account).
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub sid: String,
    pub uid: u32,
    pub linux_user: String,
    /// The Windows name the Linux name was last derived from: a rename is
    /// a change of this, not of `linux_user`.
    pub windows_name: String,
    pub locked: bool,
    /// "Windows administrators are root in Linux" for this user's elevated
    /// sessions (§5d): off unless the user opts in.
    pub admin_is_root: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdMap {
    pub entries: Vec<Entry>,
}

/// What a sync asks of the Linux side, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Create { uid: u32, linux_user: String },
    Rename { uid: u32, from: String, to: String },
    Lock { uid: u32, linux_user: String },
    Unlock { uid: u32, linux_user: String },
}

/// A user account SID paguro maps: a machine or domain account
/// (`S-1-5-21-…`) with a RID of 1000 or more. The built-ins below 1000
/// (Administrator, Guest, DefaultAccount, WDAGUtilityAccount) are not
/// people.
pub fn mapped_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .get(3)
            .and_then(|r| r.parse::<u32>().ok())
            .is_some_and(|rid| rid >= 1000)
}

/// The Linux name for a Windows account name: lowercased, letters and
/// digits kept (accents stripped where the letter is Latin), everything
/// else one `_`, trimmed of `_` at the ends, a leading digit or `-`
/// prefixed with `u`, at most [`MAX_NAME`]. `None` when nothing usable
/// is left (a name in another script entirely): the caller then uses
/// `user<uid>`.
pub fn derive_name(windows_name: &str) -> Option<String> {
    let mut out = String::new();
    for c in windows_name.chars().flat_map(char::to_lowercase) {
        let c = fold_latin(c);
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if c == '-' || c == '.' {
            out.push('-');
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let t = out.trim_matches(|c| c == '_' || c == '-');
    if t.is_empty() {
        return None;
    }
    let mut s = if t.starts_with(|c: char| c.is_ascii_digit()) {
        format!("u{t}")
    } else {
        t.to_string()
    };
    s.truncate(MAX_NAME);
    Some(s.trim_end_matches(['_', '-']).to_string())
}

fn fold_latin(c: char) -> char {
    match c {
        'à'..='å' | 'ā' | 'ă' | 'ą' => 'a',
        'ç' | 'ć' | 'č' => 'c',
        'è'..='ë' | 'ē' | 'ę' | 'ě' => 'e',
        'ì'..='ï' | 'ī' => 'i',
        'ñ' | 'ń' | 'ň' => 'n',
        'ò'..='ö' | 'ø' | 'ō' | 'ő' => 'o',
        'ù'..='ü' | 'ū' | 'ů' | 'ű' => 'u',
        'ý' | 'ÿ' => 'y',
        'ś' | 'š' => 's',
        'ź' | 'ż' | 'ž' => 'z',
        'ł' => 'l',
        'ř' => 'r',
        'ť' => 't',
        'ď' => 'd',
        'ß' => 's',
        _ => c,
    }
}

/// `true` when `name` is a Linux username paguro may create or rename to.
pub fn linux_name_ok(name: &str) -> bool {
    crate::linux_user_ok(name)
}

impl IdMap {
    pub fn by_sid(&self, sid: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.sid == sid)
    }

    pub fn by_uid(&self, uid: u32) -> Option<&Entry> {
        self.entries.iter().find(|e| e.uid == uid)
    }

    /// One sync against Windows' account list. `taken_names` and
    /// `taken_uids` are the machine's Linux users that are not paguro's
    /// (from `/etc/passwd`); paguro's own entries are accounted for here.
    /// Updates the map and returns what the Linux side must do. Refuses an
    /// empty listing (see the module's rules).
    pub fn sync(
        &mut self,
        accounts: &[WindowsAccount],
        taken_names: &[&str],
        taken_uids: &[u32],
    ) -> Result<Vec<Action>, String> {
        let accounts: Vec<&WindowsAccount> =
            accounts.iter().filter(|a| mapped_sid(&a.sid)).collect();
        if accounts.is_empty() {
            return Err(
                "the Windows account list has no users: a failed listing, nothing changed".into(),
            );
        }
        let mut actions = Vec::new();

        // Deleted (or missed): lock. Reappeared: unlock.
        for e in &mut self.entries {
            let present = accounts.iter().any(|a| a.sid == e.sid);
            if !present && !e.locked {
                e.locked = true;
                actions.push(Action::Lock {
                    uid: e.uid,
                    linux_user: e.linux_user.clone(),
                });
            } else if present && e.locked {
                e.locked = false;
                actions.push(Action::Unlock {
                    uid: e.uid,
                    linux_user: e.linux_user.clone(),
                });
            }
        }

        // Renamed: follow, if the new name is free; otherwise keep the old
        // Linux name (the account still works; nothing is guessed).
        for a in &accounts {
            let Some(e) = self.by_sid(&a.sid) else {
                continue;
            };
            if e.windows_name == a.name {
                continue;
            }
            let (uid, from) = (e.uid, e.linux_user.clone());
            let base = derive_name(&a.name).unwrap_or_else(|| format!("user{uid}"));
            let to = self.free_name(&base, taken_names, Some(uid));
            if let Some(e) = self.entries.iter_mut().find(|e| e.sid == a.sid) {
                e.windows_name = a.name.clone();
                e.linux_user = to.clone();
            }
            if to != from {
                actions.push(Action::Rename { uid, from, to });
            }
        }

        // New: allocate.
        for a in &accounts {
            if self.by_sid(&a.sid).is_some() {
                continue;
            }
            let uid = self.next_uid(taken_uids);
            let base = derive_name(&a.name).unwrap_or_else(|| format!("user{uid}"));
            let linux_user = self.free_name(&base, taken_names, None);
            self.entries.push(Entry {
                sid: a.sid.clone(),
                uid,
                linux_user: linux_user.clone(),
                windows_name: a.name.clone(),
                locked: false,
                admin_is_root: false,
            });
            actions.push(Action::Create { uid, linux_user });
        }
        Ok(actions)
    }

    /// The lowest uid from [`FIRST_UID`] that no entry (locked ones
    /// included: a uid is never reused) and no other Linux user has.
    fn next_uid(&self, taken: &[u32]) -> u32 {
        let mut uid = FIRST_UID;
        while taken.contains(&uid) || self.by_uid(uid).is_some() {
            uid += 1;
        }
        uid
    }

    /// `base`, or `base2`, `base3`, … (shortened to fit): the first that
    /// neither another Linux user nor another entry has. `own` is the uid
    /// asking, whose current name does not count against it.
    fn free_name(&self, base: &str, taken: &[&str], own: Option<u32>) -> String {
        let used = |n: &str| {
            taken.contains(&n)
                || self
                    .entries
                    .iter()
                    .any(|e| e.linux_user == n && Some(e.uid) != own)
        };
        if !used(base) {
            return base.to_string();
        }
        (2u32..)
            .map(|k| {
                let suffix = k.to_string();
                let mut b = base.to_string();
                b.truncate(MAX_NAME - suffix.len());
                format!("{}{suffix}", b.trim_end_matches(['_', '-']))
            })
            .find(|n| !used(n))
            .unwrap_or_default()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": 1,
            "users": self.entries.iter().map(|e| json!({
                "sid": e.sid,
                "uid": e.uid,
                "linux_user": e.linux_user,
                "windows_name": e.windows_name,
                "locked": e.locked,
                "admin_is_root": e.admin_is_root,
            })).collect::<Vec<_>>(),
        })
    }

    /// Reads a recorded map, checking every field: a map that fails a
    /// check is refused whole (it decides who is who).
    pub fn from_json(v: &Value) -> Result<Self, String> {
        if v.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("idmap: not version 1".into());
        }
        let users = v
            .get("users")
            .and_then(Value::as_array)
            .ok_or("idmap: no users")?;
        let mut map = IdMap::default();
        for u in users {
            let s = |k: &str| {
                u.get(k)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or(format!("idmap: an entry has no {k}"))
            };
            let b = |k: &str| u.get(k).and_then(Value::as_bool).unwrap_or(false);
            let e = Entry {
                sid: s("sid")?,
                uid: u
                    .get("uid")
                    .and_then(Value::as_u64)
                    .and_then(|x| u32::try_from(x).ok())
                    .filter(|&x| x >= FIRST_UID)
                    .ok_or("idmap: an entry's uid is outside paguro's range")?,
                linux_user: s("linux_user")?,
                windows_name: s("windows_name")?,
                locked: b("locked"),
                admin_is_root: b("admin_is_root"),
            };
            if !mapped_sid(&e.sid) || !linux_name_ok(&e.linux_user) {
                return Err(format!("idmap: bad entry for {}", e.sid));
            }
            if map.by_sid(&e.sid).is_some()
                || map.by_uid(e.uid).is_some()
                || map.entries.iter().any(|x| x.linux_user == e.linux_user)
            {
                return Err(format!("idmap: {} appears twice", e.sid));
            }
            map.entries.push(e);
        }
        Ok(map)
    }
}

// ---- Agent-port frames (INTERFACES.md §11.3) -------------------------------

/// A Windows account name as a frame may carry it: 1-256 characters, no
/// control characters (it only ever reaches [`derive_name`] and the map).
pub fn windows_name_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 256 && !s.chars().any(char::is_control)
}

/// guest → host: Windows' enabled local accounts.
pub fn accounts_frame(accounts: &[WindowsAccount]) -> Value {
    json!({
        "type": "accounts",
        "accounts": accounts.iter().map(|a| json!({"sid": a.sid, "name": a.name})).collect::<Vec<_>>(),
    })
}

/// `None`: not an `accounts` frame. Entries that are not people
/// ([`mapped_sid`]) are dropped; a malformed one refuses the frame.
pub fn parse_accounts(v: &Value) -> Option<Result<Vec<WindowsAccount>, String>> {
    if crate::kind(v) != Some("accounts") {
        return None;
    }
    let Some(list) = v.get("accounts").and_then(Value::as_array) else {
        return Some(Err("accounts: no list".into()));
    };
    let mut out = Vec::new();
    for a in list {
        let sid = a.get("sid").and_then(Value::as_str).unwrap_or("");
        let name = a.get("name").and_then(Value::as_str).unwrap_or("");
        if sid.len() > 184 || !sid.starts_with("S-1-") || !windows_name_ok(name) {
            return Some(Err("accounts: a malformed entry".into()));
        }
        if mapped_sid(sid) {
            out.push(WindowsAccount {
                sid: sid.into(),
                name: name.into(),
            });
        }
    }
    Some(Ok(out))
}

/// host → guest: who each Windows account is on Linux (locked ones left
/// out), or the host's error.
pub fn accounts_ack_frame(map: &IdMap) -> Value {
    json!({
        "type": "accounts-ack",
        "users": map.entries.iter().filter(|e| !e.locked).map(|e| json!({
            "sid": e.sid, "uid": e.uid, "linux_user": e.linux_user,
        })).collect::<Vec<_>>(),
    })
}

/// One mapped account as the host reports it: (SID, uid, Linux user).
pub type Mapped = (String, u32, String);

/// `None`: not an `accounts-ack`. `Some(Ok)`: (sid, uid, linux_user) for
/// each mapped account, every field checked.
pub fn parse_accounts_ack(v: &Value) -> Option<Result<Vec<Mapped>, String>> {
    if crate::kind(v) != Some("accounts-ack") {
        return None;
    }
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Some(Err(e.to_string()));
    }
    let Some(list) = v.get("users").and_then(Value::as_array) else {
        return Some(Err("accounts-ack: no users".into()));
    };
    let mut out = Vec::new();
    for u in list {
        let sid = u.get("sid").and_then(Value::as_str).unwrap_or("");
        let user = u.get("linux_user").and_then(Value::as_str).unwrap_or("");
        let uid = u
            .get("uid")
            .and_then(Value::as_u64)
            .and_then(|x| u32::try_from(x).ok())
            .unwrap_or(0);
        if !mapped_sid(sid) || !linux_name_ok(user) || uid < FIRST_UID {
            return Some(Err("accounts-ack: a malformed entry".into()));
        }
        out.push((sid.to_string(), uid, user.to_string()));
    }
    Some(Ok(out))
}

/// The service's account listing (DESIGN.md §4.7): Windows' **enabled**
/// local accounts (Microsoft accounts are local accounts too), one line
/// `PAGURO-ACCOUNTS [json]` ([`parse_accounts_listing`]). A disabled
/// account is absent, so its Linux user is locked, like a deleted one.
/// Domain accounts are out of scope (personal devices, §8).
pub fn windows_accounts_ps1() -> String {
    r#"# paguro: the identity mapping's account list (DESIGN.md §4.7). Generated.
$ErrorActionPreference = 'Stop'
$a = @(Get-LocalUser | Where-Object Enabled | ForEach-Object { @{ sid = $_.SID.Value; name = $_.Name } })
'PAGURO-ACCOUNTS ' + (ConvertTo-Json -Compress -Depth 3 -InputObject $a)
"#
    .to_string()
}

/// What [`windows_accounts_ps1`] printed, as an `accounts` frame's list.
pub fn parse_accounts_listing(stdout: &str) -> Option<Result<Vec<WindowsAccount>, String>> {
    let j = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("PAGURO-ACCOUNTS "))?;
    let v: Value = serde_json::from_str(j).ok()?;
    // ConvertTo-Json of a one-element array still gives an array with
    // -InputObject; an object is accepted all the same.
    let list = match v {
        Value::Array(a) => a,
        o @ Value::Object(_) => vec![o],
        _ => return None,
    };
    parse_accounts(&json!({"type": "accounts", "accounts": list}))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    const M: &str = "S-1-5-21-1111111111-2222222222-3333333333";

    fn acct(rid: u32, name: &str) -> WindowsAccount {
        WindowsAccount {
            sid: format!("{M}-{rid}"),
            name: name.into(),
        }
    }

    #[test]
    fn which_sids_are_people() {
        assert!(mapped_sid(&format!("{M}-1001")));
        assert!(!mapped_sid(&format!("{M}-500")), "Administrator");
        assert!(!mapped_sid(&format!("{M}-503")), "DefaultAccount");
        assert!(!mapped_sid("S-1-5-18"));
        assert!(!mapped_sid("S-1-5-21-1-2-1001"));
        assert!(!mapped_sid(&format!("{M}-1001-5")));
        assert!(!mapped_sid(&format!("{M}-x")));
    }

    #[test]
    fn names() {
        assert_eq!(derive_name("Anna").as_deref(), Some("anna"));
        assert_eq!(derive_name("John Smith").as_deref(), Some("john_smith"));
        assert_eq!(derive_name("José Müller").as_deref(), Some("jose_muller"));
        assert_eq!(derive_name("anna.b").as_deref(), Some("anna-b"));
        assert_eq!(derive_name("  _Bob_ ").as_deref(), Some("bob"));
        assert_eq!(derive_name("2cool").as_deref(), Some("u2cool"));
        assert_eq!(derive_name("田中"), None);
        assert_eq!(derive_name("---"), None);
        let long = derive_name(&"a".repeat(40)).unwrap();
        assert_eq!(long.len(), MAX_NAME);
        for n in ["Anna", "John Smith", "José Müller", "2cool", "a$b'c\"d;e"] {
            assert!(linux_name_ok(&derive_name(n).unwrap()), "{n}");
        }
    }

    #[test]
    fn create_rename_lock_unlock() {
        let mut m = IdMap::default();
        let a = m
            .sync(
                &[
                    acct(1001, "Anna"),
                    acct(1002, "Bob"),
                    acct(500, "Administrator"),
                ],
                &["root", "bob"],
                &[5000],
            )
            .unwrap();
        assert_eq!(
            a,
            vec![
                Action::Create {
                    uid: 5001,
                    linux_user: "anna".into()
                },
                Action::Create {
                    uid: 5002,
                    linux_user: "bob2".into()
                },
            ]
        );

        // Renamed on Windows: the Linux user follows, the uid stays.
        let a = m
            .sync(
                &[acct(1001, "Anna B"), acct(1002, "Bob")],
                &["root", "bob"],
                &[5000],
            )
            .unwrap();
        assert_eq!(
            a,
            vec![Action::Rename {
                uid: 5001,
                from: "anna".into(),
                to: "anna_b".into()
            }]
        );

        // Deleted: locked, never removed; the uid is not reused.
        let a = m
            .sync(&[acct(1001, "Anna B"), acct(1003, "Carol")], &[], &[])
            .unwrap();
        assert_eq!(
            a,
            vec![
                Action::Lock {
                    uid: 5002,
                    linux_user: "bob2".into()
                },
                Action::Create {
                    uid: 5000,
                    linux_user: "carol".into()
                },
            ]
        );
        assert!(m.by_uid(5002).unwrap().locked);
        // Back again (a listing had missed it): unlocked.
        let a = m
            .sync(
                &[acct(1001, "Anna B"), acct(1002, "Bob"), acct(1003, "Carol")],
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(
            a,
            vec![Action::Unlock {
                uid: 5002,
                linux_user: "bob2".into()
            }]
        );
        // Idempotent.
        assert_eq!(
            m.sync(
                &[acct(1001, "Anna B"), acct(1002, "Bob"), acct(1003, "Carol")],
                &[],
                &[]
            )
            .unwrap(),
            vec![]
        );
    }

    #[test]
    fn an_empty_listing_changes_nothing() {
        let mut m = IdMap::default();
        m.sync(&[acct(1001, "Anna")], &[], &[]).unwrap();
        let before = m.clone();
        assert!(m.sync(&[], &[], &[]).is_err());
        // Only built-ins: the same thing.
        assert!(m.sync(&[acct(500, "Administrator")], &[], &[]).is_err());
        assert_eq!(m, before);
    }

    #[test]
    fn collisions_and_renames_into_taken_names() {
        let mut m = IdMap::default();
        m.sync(
            &[acct(1001, "Anna"), acct(1002, "anna"), acct(1003, "田中")],
            &[],
            &[],
        )
        .unwrap();
        let names: Vec<&str> = m.entries.iter().map(|e| e.linux_user.as_str()).collect();
        assert_eq!(names, ["anna", "anna2", "user5002"]);
        // Renamed to a name another entry has: suffixed, never shared.
        let a = m
            .sync(
                &[acct(1001, "Anna"), acct(1002, "Bob"), acct(1003, "Anna")],
                &[],
                &[],
            )
            .unwrap();
        assert!(
            a.contains(&Action::Rename {
                uid: 5002,
                from: "user5002".into(),
                to: "anna2".into()
            }),
            "anna2 was freed earlier in the same sync"
        );
        // A long name keeps its suffix within 32.
        let mut m = IdMap::default();
        let l = "x".repeat(40);
        m.sync(&[acct(1001, &l), acct(1002, &l)], &[], &[]).unwrap();
        assert_eq!(m.entries[1].linux_user, format!("{}2", "x".repeat(31)));
    }

    #[test]
    fn json_round_trip_and_refusals() {
        let mut m = IdMap::default();
        m.sync(&[acct(1001, "Anna"), acct(1002, "Bob")], &[], &[])
            .unwrap();
        m.entries[0].admin_is_root = true;
        assert_eq!(IdMap::from_json(&m.to_json()).unwrap(), m);

        let mut v = m.to_json();
        v["users"][1]["uid"] = json!(5000);
        assert!(IdMap::from_json(&v).is_err(), "a uid twice");
        let mut v = m.to_json();
        v["users"][0]["uid"] = json!(0);
        assert!(IdMap::from_json(&v).is_err(), "root is never mapped");
        let mut v = m.to_json();
        v["users"][0]["linux_user"] = json!("../etc");
        assert!(IdMap::from_json(&v).is_err());
        let mut v = m.to_json();
        v["users"][0]["sid"] = json!("S-1-5-18");
        assert!(IdMap::from_json(&v).is_err());
        assert!(IdMap::from_json(&json!({"version": 2, "users": []})).is_err());
    }

    #[test]
    fn frames() {
        let list = vec![acct(1001, "Anna"), acct(500, "Administrator")];
        let f = accounts_frame(&list);
        assert_eq!(parse_accounts(&f), Some(Ok(vec![acct(1001, "Anna")])));
        assert_eq!(parse_accounts(&json!({"type": "ssh-keys"})), None);
        let bad = accounts_frame(&[acct(1001, "a\nb")]);
        assert!(matches!(parse_accounts(&bad), Some(Err(_))));
        let bad = json!({"type": "accounts", "accounts": [{"sid": "x", "name": "a"}]});
        assert!(matches!(parse_accounts(&bad), Some(Err(_))));

        let mut m = IdMap::default();
        m.sync(&[acct(1001, "Anna"), acct(1002, "Bob")], &[], &[])
            .unwrap();
        m.entries[1].locked = true;
        let ack = parse_accounts_ack(&accounts_ack_frame(&m))
            .unwrap()
            .unwrap();
        assert_eq!(ack, vec![(format!("{M}-1001"), 5000, "anna".to_string())]);
        assert_eq!(
            parse_accounts_ack(&json!({"type": "accounts-ack", "error": "no"})),
            Some(Err("no".into()))
        );

        let out = format!(
            "junk\r\nPAGURO-ACCOUNTS [{{\"sid\":\"{M}-1001\",\"name\":\"Anna\"}},{{\"sid\":\"{M}-501\",\"name\":\"Guest\"}}]\r\n"
        );
        assert_eq!(
            parse_accounts_listing(&out),
            Some(Ok(vec![acct(1001, "Anna")]))
        );
        let one = format!("PAGURO-ACCOUNTS {{\"sid\":\"{M}-1001\",\"name\":\"Anna\"}}");
        assert_eq!(
            parse_accounts_listing(&one),
            Some(Ok(vec![acct(1001, "Anna")]))
        );
        assert!(windows_accounts_ps1().contains("Where-Object Enabled"));
    }
}
