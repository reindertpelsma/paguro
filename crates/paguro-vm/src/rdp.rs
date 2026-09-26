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

use crate::net::{GUEST_ADDR, HOST_ADDR};

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

/// Where Windows' RDP listens: its end of the private link.
pub fn default_addr() -> String {
    GUEST_ADDR.to_string()
}

/// FreeRDP 3's command line (`xfreerdp3`, `wlfreerdp3`, or `sdl-freerdp3`);
/// the password follows on stdin. `home` is shared into Windows as a
/// redirected drive (§5b "the reverse direction"). The certificate is always
/// pinned to the fingerprint Windows reported over the agent port (DESIGN.md
/// §5c "Peers are pinned"): there is no trust-on-first-use.
pub fn freerdp_args(
    addr: &str,
    user: &str,
    view: &View,
    home: Option<&str>,
    cert_fingerprint: &str,
) -> Vec<String> {
    let mut a = vec![
        format!("/v:{addr}"),
        format!("/u:{user}"),
        "/from-stdin:force".into(),
        "/network:lan".into(),
        "/gfx".into(),
        "+clipboard".into(),
        "/dynamic-resolution".into(),
        "/sound:sys:pulse".into(),
    ];
    a.push(format!("/cert:fingerprint:sha256:{cert_fingerprint}"));
    if let Some(h) = home {
        a.push(format!("/drive:home,{h}"));
    }
    if let View::RemoteApp { program, name } = view {
        a.push(format!("/app:program:{program},name:{name}"));
    }
    a
}

/// **Superseded for the product** by paguro's own RDP server (DESIGN.md §5c:
/// TermService cannot serve Windows Home or passwordless accounts); kept for
/// split-e2e.sh's RemoteApp phase, which proves the client side against
/// Windows' own server on the evaluation image.
///
/// PowerShell run in the guest after the link is provisioned (the adapter is
/// `paguro0`): RDP on, NLA required, RemoteApp for any program, reachable
/// only on the private link from the host. Additive only: this is the user's
/// own Windows, so their "Remote Desktop" rules are left alone (in the VM
/// nothing inbound reaches the internet adapter anyway, §5c), and the paguro
/// service puts `fDenyTSConnections` back to the user's own choice on native
/// boots (DESIGN.md §5c "The paguro service in the VM"). Prints the RDP
/// certificate's SHA-256 fingerprint as `paguro: rdp fingerprint <hex:..>`,
/// for the host to pin (it travels over the agent port in the product).
pub fn windows_setup() -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0
Set-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
# RemoteApp: any program, not only a published list.
$al = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList'
if (-not (Test-Path $al)) {{ New-Item -Path $al -Force | Out-Null }}
Set-ItemProperty -Path $al -Name fDisabledAllowList -Value 1
# Reachable on the private link only, and only from the host.
Get-NetFirewallRule -Name 'paguro-rdp-in' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'paguro-rdp-in' -DisplayName 'paguro: RDP on the private link' -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -InterfaceAlias 'paguro0' -RemoteAddress '{HOST_ADDR}' -Action Allow | Out-Null
Restart-Service TermService -Force -ErrorAction SilentlyContinue
$c = $null
for ($i = 0; $i -lt 30 -and -not $c; $i++) {{
    $c = Get-ChildItem 'Cert:\LocalMachine\Remote Desktop' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $c) {{ Start-Sleep 1 }}
}}
if (-not $c) {{ throw 'paguro: no RDP certificate' }}
$h = [Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)
'paguro: rdp fingerprint ' + (($h | ForEach-Object {{ $_.ToString('x2') }}) -join ':')
"#
    )
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
        let a = freerdp_args(
            &default_addr(),
            "anna",
            &View::Desktop,
            Some("/home/anna"),
            "ab:cd",
        );
        assert!(a.contains(&"/v:169.254.244.2".to_string()));
        assert!(a.contains(&"/from-stdin:force".to_string()));
        assert!(a.contains(&"/drive:home,/home/anna".to_string()));
        assert!(!a.iter().any(|x| x.starts_with("/p:")));
        assert!(
            !a.iter().any(|x| x.contains("tofu")),
            "never trust on first use"
        );
        let r = freerdp_args(
            "127.0.0.1:3390",
            "anna",
            &View::RemoteApp {
                program: "||explorer".into(),
                name: "Explorer".into(),
            },
            None,
            "ab:cd",
        );
        assert!(r.contains(&"/v:127.0.0.1:3390".to_string()));
        assert!(r.contains(&"/app:program:||explorer,name:Explorer".to_string()));
        assert!(r.contains(&"/cert:fingerprint:sha256:ab:cd".to_string()));
        assert_eq!(
            keyring_attrs("anna", "rdp").get(1).map(String::as_str),
            Some(SERVICE)
        );
    }

    #[test]
    fn windows_setup_is_link_only() {
        let w = windows_setup();
        assert!(w.contains("-InterfaceAlias 'paguro0' -RemoteAddress '169.254.244.1'"));
        assert!(w.contains("UserAuthentication -Value 1"), "NLA stays on");
        assert!(
            !w.contains("Disable-NetFirewallRule"),
            "the user's own rules are left alone"
        );
        assert!(w.contains("fDisabledAllowList -Value 1"));
        assert!(w.contains("paguro: rdp fingerprint"));
    }
}
