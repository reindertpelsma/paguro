//! "The same path on both sides" (DESIGN.md §5d): the fixed, total mapping
//! between a Linux path in a distribution and a Windows path, used for
//! every path that crosses — a working directory, a forwarded file, a
//! program's arguments. Anything it cannot map is refused, never
//! approximated.
//!
//! | From | To |
//! |---|---|
//! | Linux `/mnt/c/X` (any NTFS volume `/mnt/v`) | `C:\X` (`V:\X`) |
//! | Linux `/mnt/l/d/X` (another distribution's files) | `L:\d\X` |
//! | Linux, any other `/X` in distribution *d* | `L:\d\X` |
//! | Windows `C:\X` | `/mnt/c/X` |
//! | Windows `L:\d\X` | `/X` in *d*; `/mnt/l/d/X` from another one |
//!
//! Names Windows cannot hold (`\ : * ? " < > |`, control characters) take
//! WSL's convention on the way to `L:`: the character becomes U+F000 + its
//! code, the table Samba's `catia` module is configured with
//! ([`catia_mappings`]), so a name looks the same through `L:` as through
//! WSL. A name ending in a dot or a space is refused instead: `catia` maps
//! characters, not positions, and Win32 strips a trailing dot, so such a
//! path would reach a different file.
//! Pure string work: whether a path is a special file (refused too) is the
//! caller's check, on the filesystem.

/// Why a path does not cross.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not absolute (`/…`, or `X:\…`).
    Relative,
    /// A `..` component: it cannot be resolved without the filesystem.
    DotDot,
    /// `/proc`, `/sys`, `/dev`: kernel interfaces, not files.
    KernelInterface,
    /// A UNC or device path (`\\server\…`, `\\?\…`).
    Unc,
    /// A name that cannot exist on that side (NUL, `/` in a Windows name,
    /// an escaped character in an NTFS name).
    BadName,
    /// The distribution name is not usable as a folder of `L:`.
    BadDistro,
}

/// The mapping's parameters: the drive letter `L:` has (configurable, moved
/// when taken) and the distribution the Linux side of this call is in.
#[derive(Clone, Copy, Debug)]
pub struct Paths<'a> {
    pub l_letter: char,
    pub distro: &'a str,
}

/// The Linux mount point of distributions' files, whatever `L:`'s letter.
pub const LINUX_L: &str = "/mnt/l";

const REFUSED_ROOTS: [&str; 3] = ["proc", "sys", "dev"];

/// The characters WSL maps into U+F000 + code on the way to Windows.
fn windows_illegal(c: char) -> bool {
    matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || ('\u{1}'..='\u{1f}').contains(&c)
}

/// A distribution's folder name: the same rules as a distribution name
/// everywhere else (letters, digits, `.`, `_`, `-`, not starting with `.`).
pub fn distro_ok(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 64
        && !d.starts_with('.')
        && d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Linux path components, `.` and empty ones dropped, `..` refused.
fn linux_components(p: &str) -> Result<Vec<&str>, Refused> {
    if !p.starts_with('/') {
        return Err(Refused::Relative);
    }
    let mut out = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(Refused::DotDot),
            c if c.contains('\0') => return Err(Refused::BadName),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// One Linux name as Windows sees it through `L:` (WSL's convention), or
/// refused when it ends in a dot or a space.
pub fn escape_name(name: &str) -> Result<String, Refused> {
    if name.ends_with(['.', ' ']) {
        return Err(Refused::BadName);
    }
    Ok(name
        .chars()
        .map(|c| {
            if windows_illegal(c) {
                char::from_u32(0xF000 + c as u32).unwrap_or(c)
            } else {
                c
            }
        })
        .collect())
}

/// Samba's `catia:mappings` for the `L:` share: the same table as
/// [`escape_name`] (the Unix character : the one Windows sees).
pub fn catia_mappings() -> String {
    (1u32..0x80)
        .filter_map(char::from_u32)
        .filter(|&c| windows_illegal(c))
        .map(|c| format!("0x{:02x}:0x{:04x}", c as u32, 0xF000 + c as u32))
        .collect::<Vec<_>>()
        .join(",")
}

/// The inverse of [`escape_name`]: U+F000 + code back to the character,
/// for exactly the characters the escape produces. A `/` cannot come back
/// (it is never escaped), so a name holding U+F02F is refused.
pub fn unescape_name(name: &str) -> Result<String, Refused> {
    name.chars()
        .map(|c| match c as u32 {
            0xF001..=0xF0FF => {
                let o = char::from_u32(c as u32 - 0xF000).ok_or(Refused::BadName)?;
                if windows_illegal(o) {
                    Ok(o)
                } else if o == '/' {
                    Err(Refused::BadName)
                } else {
                    Ok(c)
                }
            }
            _ => Ok(c),
        })
        .collect()
}

impl Paths<'_> {
    /// A Linux path in [`Paths::distro`] → the Windows path.
    pub fn to_windows(&self, p: &str) -> Result<String, Refused> {
        if !distro_ok(self.distro) {
            return Err(Refused::BadDistro);
        }
        let c = linux_components(p)?;
        if c.first().is_some_and(|r| REFUSED_ROOTS.contains(r)) {
            return Err(Refused::KernelInterface);
        }
        let l = self.l_letter.to_ascii_uppercase();
        match c.as_slice() {
            // /mnt/l/<d>/X: another distribution's files.
            ["mnt", "l", rest @ ..] => {
                let Some((d, rest)) = rest.split_first() else {
                    return Ok(format!("{l}:\\"));
                };
                if !distro_ok(d) {
                    return Err(Refused::BadDistro);
                }
                join_escaped(&format!("{l}:\\{d}"), rest)
            }
            // /mnt/<v>/X: an NTFS volume, names verbatim (they came from
            // NTFS, where the escapes cannot be).
            ["mnt", v, rest @ ..] if is_letter(v) => {
                if rest.iter().any(|n| n.chars().any(windows_illegal)) {
                    return Err(Refused::BadName);
                }
                let v = v.to_ascii_uppercase();
                Ok(format!("{v}:\\{}", rest.join("\\")))
            }
            rest => join_escaped(&format!("{l}:\\{}", self.distro), rest),
        }
    }

    /// A Windows path → the Linux path as seen from [`Paths::distro`].
    pub fn to_linux(&self, p: &str) -> Result<String, Refused> {
        if p.starts_with("\\\\") || p.starts_with("//") {
            return Err(Refused::Unc);
        }
        let mut chars = p.chars();
        let (Some(v), Some(':')) = (chars.next(), chars.next()) else {
            return Err(Refused::Relative);
        };
        if !v.is_ascii_alphabetic() {
            return Err(Refused::Relative);
        }
        let rest = chars.as_str();
        if !rest.is_empty() && !rest.starts_with(['\\', '/']) {
            return Err(Refused::Relative); // `C:foo`: relative to C:'s cwd
        }
        let mut names = Vec::new();
        for n in rest.split(['\\', '/']) {
            match n {
                "" | "." => {}
                ".." => return Err(Refused::DotDot),
                n if n.contains('\0') => return Err(Refused::BadName),
                n => names.push(n),
            }
        }
        let v = v.to_ascii_lowercase();
        if v == self.l_letter.to_ascii_lowercase() {
            let Some((d, rest)) = names.split_first() else {
                return Ok(LINUX_L.into());
            };
            if !distro_ok(d) {
                return Err(Refused::BadDistro);
            }
            let rest: Vec<String> = rest
                .iter()
                .map(|n| unescape_name(n))
                .collect::<Result<_, _>>()?;
            let base = if *d == self.distro {
                String::new()
            } else {
                format!("{LINUX_L}/{d}")
            };
            let s = format!("{base}/{}", rest.join("/"));
            return Ok(if s.len() > 1 {
                s.trim_end_matches('/').to_string()
            } else {
                s
            });
        }
        Ok(format!("/mnt/{v}/{}", names.join("/"))
            .trim_end_matches('/')
            .to_string())
    }
}

fn is_letter(s: &str) -> bool {
    s.len() == 1 && s.bytes().all(|b| b.is_ascii_lowercase())
}

fn join_escaped(base: &str, names: &[&str]) -> Result<String, Refused> {
    let names: Vec<String> = names
        .iter()
        .map(|n| escape_name(n))
        .collect::<Result<_, _>>()?;
    Ok(join(base, names.into_iter()))
}

fn join(base: &str, names: impl Iterator<Item = String>) -> String {
    let mut s = base.to_string();
    for n in names {
        s.push('\\');
        s.push_str(&n);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Paths<'static> = Paths {
        l_letter: 'L',
        distro: "debian",
    };

    #[test]
    fn linux_to_windows() {
        assert_eq!(
            P.to_windows("/mnt/c/Users/anna/x.txt"),
            Ok(r"C:\Users\anna\x.txt".into())
        );
        assert_eq!(P.to_windows("/mnt/c"), Ok(r"C:\".into()));
        assert_eq!(P.to_windows("/mnt/d/"), Ok(r"D:\".into()));
        assert_eq!(
            P.to_windows("/home/anna/src"),
            Ok(r"L:\debian\home\anna\src".into())
        );
        assert_eq!(P.to_windows("/"), Ok(r"L:\debian".into()));
        assert_eq!(
            P.to_windows("/mnt/l/fedora/etc"),
            Ok(r"L:\fedora\etc".into())
        );
        assert_eq!(P.to_windows("/mnt/l"), Ok(r"L:\".into()));
        assert_eq!(
            P.to_windows("//home/./anna//"),
            Ok(r"L:\debian\home\anna".into())
        );
        assert_eq!(
            P.to_windows("/run/user/1000/x"),
            Ok(r"L:\debian\run\user\1000\x".into())
        );
        // /mnt/<not a letter> is an ordinary directory in the distribution.
        assert_eq!(
            P.to_windows("/mnt/usb/x"),
            Ok(r"L:\debian\mnt\usb\x".into())
        );
        let m = Paths {
            l_letter: 'm',
            distro: "debian",
        };
        assert_eq!(m.to_windows("/etc"), Ok(r"M:\debian\etc".into()));
    }

    #[test]
    fn refusals() {
        for (p, r) in [
            ("home", Refused::Relative),
            ("/home/../etc", Refused::DotDot),
            ("/proc/1", Refused::KernelInterface),
            ("/sys", Refused::KernelInterface),
            ("/dev/null", Refused::KernelInterface),
            ("/mnt/l/../x", Refused::DotDot),
            ("/mnt/l/.hidden/x", Refused::BadDistro),
            ("/mnt/c/a:b", Refused::BadName),
        ] {
            assert_eq!(P.to_windows(p), Err(r), "{p}");
        }
        // /procfoo is not /proc.
        assert!(P.to_windows("/procfoo").is_ok());
        let bad = Paths {
            l_letter: 'L',
            distro: "a/b",
        };
        assert_eq!(bad.to_windows("/x"), Err(Refused::BadDistro));
        for (p, r) in [
            (r"\\server\share\x", Refused::Unc),
            (r"\\?\C:\x", Refused::Unc),
            (r"C:foo", Refused::Relative),
            (r"foo\bar", Refused::Relative),
            (r"C:\a\..\b", Refused::DotDot),
            (r"L:\..\x", Refused::DotDot),
            (r"L:\.x\y", Refused::BadDistro),
        ] {
            assert_eq!(P.to_linux(p), Err(r), "{p}");
        }
    }

    #[test]
    fn windows_to_linux() {
        assert_eq!(
            P.to_linux(r"C:\Users\anna\x.txt"),
            Ok("/mnt/c/Users/anna/x.txt".into())
        );
        assert_eq!(P.to_linux(r"c:/Users"), Ok("/mnt/c/Users".into()));
        assert_eq!(P.to_linux(r"C:\"), Ok("/mnt/c".into()));
        assert_eq!(P.to_linux(r"L:\debian\home\anna"), Ok("/home/anna".into()));
        assert_eq!(P.to_linux(r"L:\debian"), Ok("/".into()));
        assert_eq!(
            P.to_linux(r"l:\fedora\etc\"),
            Ok("/mnt/l/fedora/etc".into())
        );
        assert_eq!(P.to_linux(r"L:\"), Ok("/mnt/l".into()));
    }

    #[test]
    fn names_windows_cannot_hold() {
        assert_eq!(escape_name("a:b?.txt").unwrap(), "a\u{F03A}b\u{F03F}.txt");
        assert_eq!(escape_name("tab\tx").unwrap(), "tab\u{F009}x");
        assert_eq!(escape_name("normal name.txt").unwrap(), "normal name.txt");
        assert_eq!(escape_name("dots..."), Err(Refused::BadName));
        assert_eq!(escape_name("space "), Err(Refused::BadName));
        assert_eq!(P.to_windows("/tmp/x./y"), Err(Refused::BadName));
        // /mnt/c names came from NTFS: left alone.
        assert!(P.to_windows("/mnt/c/x.").is_ok());
        let m = catia_mappings();
        assert!(m.starts_with("0x01:0xf001,") && m.contains(",0x3a:0xf03a,"));
        assert!(m.ends_with(",0x7c:0xf07c"));
        assert_eq!(m.split(',').count(), 31 + 8);
        assert_eq!(
            P.to_windows("/tmp/a|b"),
            Ok("L:\\debian\\tmp\\a\u{F07C}b".into())
        );
        // Round trip through L:.
        for n in ["a:b", "q?*<>\"|\\", "plain", "é ü", ".hidden"] {
            assert_eq!(unescape_name(&escape_name(n).unwrap()).unwrap(), n, "{n:?}");
            let w = P.to_windows(&format!("/tmp/{n}")).unwrap();
            assert_eq!(P.to_linux(&w).unwrap(), format!("/tmp/{n}"), "{n:?}");
        }
        // A private-use character that is not an escape stays as it is;
        // one that would give back '/' is refused.
        assert_eq!(unescape_name("\u{F041}").unwrap(), "\u{F041}");
        assert_eq!(unescape_name("\u{F02F}"), Err(Refused::BadName));
    }

    #[test]
    fn every_mappable_path_round_trips() {
        for p in [
            "/mnt/c/Program Files/App",
            "/etc/fstab",
            "/mnt/l/fedora/usr/bin",
            "/",
            "/mnt/l",
            "/mnt/e",
        ] {
            let w = P.to_windows(p).unwrap();
            assert_eq!(P.to_linux(&w).unwrap(), p, "{p} -> {w}");
        }
    }
}
