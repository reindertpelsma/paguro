//! Session broker plumbing (DESIGN.md §4.7): a generated per-user
//! credential kept in the user's keyring (unlocked by the login password
//! through PAM — never a config file), and the FreeRDP command line that
//! signs in with it over the private link, as a full desktop or as
//! RemoteApp windows (§5b: Pro and better; Home gets the desktop).
//!
//! The keyring is reached through libsecret's `secret-tool`, with the
//! secret on stdin; FreeRDP gets it on stdin too (`/from-stdin:force`), so
//! it is on no command line on either side.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::net::GUEST_ADDR;

/// The keyring attributes the credential is stored under.
pub const SERVICE: &str = "paguro-vm";
/// Generated secrets: 24 random bytes, URL-safe base64 (32 characters).
const SECRET_BYTES: usize = 24;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(b: &[u8]) -> String {
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = c.iter().fold(0u32, |a, &x| (a << 8) | u32::from(x)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(B64.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// A fresh secret (getrandom).
pub fn generate() -> std::io::Result<String> {
    let mut b = [0u8; SECRET_BYTES];
    let mut done = 0;
    while done < b.len() {
        let rest = b.get_mut(done..).unwrap_or(&mut []);
        // SAFETY: a valid writable buffer.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        done += n as usize;
    }
    let s = encode(&b);
    zeroize::Zeroize::zeroize(&mut b);
    Ok(s)
}

/// `secret-tool` arguments for the credential of `account` (`rdp` or
/// `smb`) of Linux user `user`.
pub fn keyring_attrs(user: &str, account: &str) -> Vec<String> {
    vec![
        "service".into(),
        SERVICE.into(),
        "user".into(),
        user.into(),
        "account".into(),
        account.into(),
    ]
}

pub fn store(user: &str, account: &str, secret: &str) -> Result<(), String> {
    let mut c = Command::new("secret-tool")
        .arg("store")
        .arg(format!("--label=paguro: Windows VM ({account}) for {user}"))
        .args(keyring_attrs(user, account))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("secret-tool: {e}"))?;
    c.stdin
        .take()
        .ok_or("secret-tool: no stdin")?
        .write_all(secret.as_bytes())
        .map_err(|e| format!("secret-tool: {e}"))?;
    let st = c.wait().map_err(|e| format!("secret-tool: {e}"))?;
    st.success()
        .then_some(())
        .ok_or_else(|| format!("secret-tool store: {st}"))
}

pub fn lookup(user: &str, account: &str) -> Result<String, String> {
    let out = Command::new("secret-tool")
        .arg("lookup")
        .args(keyring_attrs(user, account))
        .output()
        .map_err(|e| format!("secret-tool: {e}"))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(format!("no {account} credential for {user} in the keyring"));
    }
    String::from_utf8(out.stdout).map_err(|_| "credential not UTF-8".into())
}

/// What to show: the whole desktop, or one application as RemoteApp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    Desktop,
    RemoteApp { program: String, name: String },
}

/// FreeRDP 3's command line (`xfreerdp3`, `wlfreerdp3`, or `sdl-freerdp3`);
/// the password follows on stdin. `home` is shared into Windows as a
/// redirected drive (§5b "the reverse direction").
pub fn freerdp_args(
    user: &str,
    view: &View,
    home: Option<&str>,
    cert_fingerprint: Option<&str>,
) -> Vec<String> {
    let mut a = vec![
        format!("/v:{GUEST_ADDR}"),
        format!("/u:{user}"),
        "/from-stdin:force".into(),
        "/network:lan".into(),
        "/gfx".into(),
        "+clipboard".into(),
        "/dynamic-resolution".into(),
        "/sound:sys:pulse".into(),
    ];
    // The link is host-only, but the certificate is still pinned when
    // known, not accepted blindly.
    a.push(match cert_fingerprint {
        Some(fp) => format!("/cert:fingerprint:sha256:{fp}"),
        None => "/cert:tofu".into(),
    });
    if let Some(h) = home {
        a.push(format!("/drive:home,{h}"));
    }
    if let View::RemoteApp { program, name } = view {
        a.push(format!("/app:program:{program},name:{name}"));
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| B64.contains(&c)));
        assert_eq!(encode(b"Man"), "TWFu");
        assert_eq!(encode(b"Ma"), "TWE");
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn rdp_args() {
        let a = freerdp_args("anna", &View::Desktop, Some("/home/anna"), None);
        assert!(a.contains(&"/v:169.254.244.2".to_string()));
        assert!(a.contains(&"/from-stdin:force".to_string()));
        assert!(a.contains(&"/drive:home,/home/anna".to_string()));
        assert!(!a.iter().any(|x| x.starts_with("/p:")));
        let r = freerdp_args(
            "anna",
            &View::RemoteApp {
                program: "||explorer".into(),
                name: "Explorer".into(),
            },
            None,
            Some("ab:cd"),
        );
        assert!(r.contains(&"/app:program:||explorer,name:Explorer".to_string()));
        assert!(r.contains(&"/cert:fingerprint:sha256:ab:cd".to_string()));
        assert_eq!(
            keyring_attrs("anna", "rdp").get(1).map(String::as_str),
            Some(SERVICE)
        );
    }
}
