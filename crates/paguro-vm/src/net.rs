//! The private link `paguro0` (DESIGN.md §5c) and the two shares over it
//! (§5b Mode 1, §5c):
//!
//! ```text
//! Windows VM  169.254.244.2/30  ── paguro0 ──  169.254.244.1/30  netns "paguro"
//!   \\169.254.244.1\l   → L:\<distro>    Samba, bound to paguro0 only
//!   \\169.254.244.2\paguro-c  → /mnt/c   mounted from inside the netns
//! ```
//!
//! The host side of the link lives in its own network namespace, so the
//! Samba serving it can bind nothing else and a user's own `smbd` is
//! untouched; the kernel's SMB client mounts `/mnt/c` from inside the same
//! namespace (a CIFS socket belongs to the namespace of the mounting
//! task; the mount itself is visible everywhere). Authentication, not
//! encryption: a generated per-installation secret for a dedicated
//! account on each side, signing on (§5c).
//!
//! Everything here that decides something is text generation, tested
//! below; the glue shells out to iproute2 and Samba's own tools.

use std::path::Path;
use std::process::{Command, Stdio};

pub const NETNS: &str = "paguro";
pub const IFNAME: &str = "paguro0";
pub const HOST_ADDR: &str = "169.254.244.1";
pub const GUEST_ADDR: &str = "169.254.244.2";
pub const PREFIX: u8 = 30;
/// The share on the Linux side (`L:`, a folder per distribution) and on
/// the Windows side (C:, for `/mnt/c`).
pub const L_SHARE: &str = "l";
pub const C_SHARE: &str = "paguro-c";
/// The dedicated accounts, one per side.
pub const LINUX_SMB_USER: &str = "paguro";
pub const WINDOWS_SMB_USER: &str = "paguro-smb";
pub const SSH_PORT: u16 = 22;
pub const WINDOWS_SSH_FIREWALL_RULE: &str = "paguro-ssh-in";
/// The private link's whole subnet, for rules scoped by network rather
/// than by one address (outbound pinning, below).
pub const LINK_NET: &str = "169.254.244.0/30";
/// RDP's port (§5b), pinned to the link the same way SMB and SSH are.
pub const RDP_PORT: u16 = 3389;
pub const OUTBOUND_ALLOW_RULE: &str = "paguro-link-out-allow";
pub const OUTBOUND_BLOCK_RULE: &str = "paguro-link-out-block";
/// Where the Linux side's own SSH state lives (keys, `sshd_config`,
/// `authorized_keys`, `known_hosts`): one constant so `paguro-linux`'s CLI
/// and the agent-port handler below never disagree on the path.
pub const LINK_STATE_DIR: &str = "/etc/paguro/link";

/// `smb.conf` for the netns Samba: one share, the distributions' roots
/// under `root` (`/mnt/l`), bound to `paguro0` only.
pub fn smb_conf(root: &Path, state_dir: &Path) -> String {
    let s = state_dir.display();
    format!(
        "# paguro: the private link's Samba (DESIGN.md §5c). Generated.\n\
         [global]\n\
         \tworkgroup = PAGURO\n\
         \tnetbios name = PAGURO-LINUX\n\
         \tserver role = standalone server\n\
         \tinterfaces = {IFNAME}\n\
         \tbind interfaces only = yes\n\
         \tsmb ports = 445\n\
         \tserver min protocol = SMB3\n\
         \tserver signing = mandatory\n\
         \tsmb encrypt = off\n\
         \tmap to guest = never\n\
         \trestrict anonymous = 2\n\
         \tdisable netbios = yes\n\
         \tload printers = no\n\
         \tprinting = bsd\n\
         \tprintcap name = /dev/null\n\
         \tdisable spoolss = yes\n\
         \tpassdb backend = tdbsam:{s}/passdb.tdb\n\
         \tprivate dir = {s}/private\n\
         \tlock directory = {s}/lock\n\
         \tstate directory = {s}/state\n\
         \tcache directory = {s}/cache\n\
         \tpid directory = {s}\n\
         \tlog file = {s}/log.smbd\n\
         \tncalrpc dir = {s}/ncalrpc\n\
         [{L_SHARE}]\n\
         \tpath = {}\n\
         \tvalid users = {LINUX_SMB_USER}\n\
         \tread only = no\n\
         \tbrowseable = yes\n",
        root.display()
    )
}

/// PowerShell run once in the guest (by the agent; over SSH in the test):
/// the adapter with the link's MAC gets the static address and a Private
/// profile, the dedicated account and the C: share exist, SMB is allowed
/// on that adapter only, and `L:` maps to the host's share. Idempotent.
/// The secrets arrive as the script's two arguments, never in its text.
pub fn windows_provision_ps1(mac: &str) -> String {
    let mac_ps = mac.replace(':', "-").to_ascii_uppercase();
    format!(
        r#"# paguro: the private link, Windows side (DESIGN.md §5b, §5c). Generated.
param([Parameter(Mandatory)][string]$SmbSecret, [Parameter(Mandatory)][string]$HostSecret)
$ErrorActionPreference = 'Stop'
$a = Get-NetAdapter | Where-Object MacAddress -eq '{mac_ps}'
if (-not $a) {{ throw 'paguro: no adapter with MAC {mac_ps}' }}
Rename-NetAdapter -InputObject $a -NewName 'paguro0' -ErrorAction SilentlyContinue
$a = Get-NetAdapter -Name 'paguro0'
Set-NetIPInterface -InterfaceIndex $a.ifIndex -Dhcp Disabled
Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object IPAddress -ne '{GUEST_ADDR}' | Remove-NetIPAddress -Confirm:$false
if (-not (Get-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '{GUEST_ADDR}' -ErrorAction SilentlyContinue)) {{
    New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '{GUEST_ADDR}' -PrefixLength {PREFIX} | Out-Null
}}
# No gateway, no DNS: the link reaches the host and nothing else.
Set-DnsClient -InterfaceIndex $a.ifIndex -RegisterThisConnectionsAddress $false
Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
# A link without a gateway is an "unidentified network": its profile may
# take a moment to appear; the firewall rule below does not depend on it.
try {{
    Start-Sleep 2
    Set-NetConnectionProfile -InterfaceIndex $a.ifIndex -NetworkCategory Private
}} catch {{ "paguro: warning: network profile: $($_.Exception.Message)" }}
'paguro: address {GUEST_ADDR}/{PREFIX} on paguro0' 
# The dedicated account and the C: share.
$pw = ConvertTo-SecureString $SmbSecret -AsPlainText -Force
if (Get-LocalUser -Name '{WINDOWS_SMB_USER}' -ErrorAction SilentlyContinue) {{
    Set-LocalUser -Name '{WINDOWS_SMB_USER}' -Password $pw
}} else {{
    New-LocalUser -Name '{WINDOWS_SMB_USER}' -Password $pw -PasswordNeverExpires -UserMayNotChangePassword `
        -Description 'paguro: the private link (/mnt/c)' | Out-Null
}}
if (-not (Get-SmbShare -Name '{C_SHARE}' -ErrorAction SilentlyContinue)) {{
    New-SmbShare -Name '{C_SHARE}' -Path 'C:\' -FullAccess '{WINDOWS_SMB_USER}' | Out-Null
}}
'paguro: share {C_SHARE} for {WINDOWS_SMB_USER}' 
Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $false -Force
# SMB in on this adapter only.
Get-NetFirewallRule -Name 'paguro-smb-in' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name 'paguro-smb-in' -DisplayName 'paguro: SMB on the private link' -Direction Inbound `
    -Protocol TCP -LocalPort 445 -InterfaceAlias 'paguro0' -RemoteAddress '{HOST_ADDR}' -Action Allow | Out-Null
# L:, the host's distributions: the credential goes to Credential Manager
# (-SaveCredentials), never onto a command line.
# Not fatal: the host's Samba may not be up yet; a persistent mapping
# reconnects at the next logon.
try {{
    $l = Get-SmbMapping -LocalPath 'L:' -ErrorAction SilentlyContinue
    if (-not $l) {{
        New-SmbMapping -LocalPath 'L:' -RemotePath '\\{HOST_ADDR}\{L_SHARE}' -UserName '{LINUX_SMB_USER}' `
            -Password $HostSecret -Persistent $true -SaveCredentials | Out-Null
    }}
    'paguro: L: mapped'
}} catch {{ "paguro: warning: L: not mapped: $($_.Exception.Message)" }}
'paguro: private link ready'
"#
    )
}

/// PowerShell run once in the guest: the Windows side of "Shells, the same
/// command both ways" (DESIGN.md §5c). Idempotent, like
/// [`windows_provision_ps1`]. `linux_pubkey` is the Linux side's public key
/// line (`ssh-ed25519 AAAA... comment`); `admin` selects
/// `administrators_authorized_keys` (OpenSSH-on-Windows always consults this
/// one file for a member of Administrators, whichever admin account signs
/// in — never that account's own `authorized_keys`) or the plain per-user
/// file for a non-admin account. Nothing here is reachable except from the
/// private link: `ListenAddress` and the firewall rule both scope to it.
pub fn windows_ssh_provision_ps1(user: &str, linux_pubkey: &str, admin: bool) -> String {
    // Not a secret: embedded like the MAC, not passed as a parameter.
    // PowerShell's single-quoted strings escape `'` by doubling it.
    let linux_pubkey = linux_pubkey.trim().replace('\'', "''");
    let akey_path = if admin {
        r"$env:ProgramData\ssh\administrators_authorized_keys".to_string()
    } else {
        format!(r"$env:SystemDrive\Users\{user}\.ssh\authorized_keys")
    };
    format!(
        r#"# paguro: the private link, SSH Windows side (DESIGN.md §5c). Generated.
$ErrorActionPreference = 'Stop'
$LinuxPubKey = '{linux_pubkey}'
$cap = Get-WindowsCapability -Online -Name OpenSSH.Server*
if ($cap.State -ne 'Installed') {{ Add-WindowsCapability -Online -Name $cap.Name | Out-Null }}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue
$conf = "$env:ProgramData\ssh\sshd_config"
$body = Get-Content $conf -Raw -ErrorAction SilentlyContinue
if (-not $body) {{ $body = '' }}
$lines = @(
    'ListenAddress {GUEST_ADDR}',
    'Port {SSH_PORT}',
    'PubkeyAuthentication yes',
    'PasswordAuthentication no',
    'KbdInteractiveAuthentication no',
    "AllowUsers {user}"
)
foreach ($l in $lines) {{
    $key = ($l -split '\s+')[0]
    $body = ($body -split "`n" | Where-Object {{ $_ -notmatch "^\s*$key\s" }}) -join "`n"
    $body += "`n$l"
}}
Set-Content -Path $conf -Value $body -Encoding ascii
$akey = '{akey_path}'
New-Item -ItemType Directory -Force -Path (Split-Path $akey) | Out-Null
if (-not (Select-String -Path $akey -Pattern ([regex]::Escape($LinuxPubKey)) -ErrorAction SilentlyContinue)) {{
    Add-Content -Path $akey -Value $LinuxPubKey
}}
# OpenSSH refuses a world- or group-writable authorized-keys file.
icacls $akey /inheritance:r | Out-Null
icacls $akey /grant 'SYSTEM:F' 'Administrators:F' | Out-Null
Set-Service -Name sshd -Status Running
# Default shell: PowerShell, not cmd.exe.
$pwsh = (Get-Command powershell.exe).Source
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $pwsh
# In on this adapter only, key-only (PasswordAuthentication no above).
Get-NetFirewallRule -Name '{WINDOWS_SSH_FIREWALL_RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name '{WINDOWS_SSH_FIREWALL_RULE}' -DisplayName 'paguro: SSH on the private link' -Direction Inbound `
    -Protocol TCP -LocalPort {SSH_PORT} -InterfaceAlias 'paguro0' -RemoteAddress '{HOST_ADDR}' -Action Allow | Out-Null
'paguro: SSH ready on {GUEST_ADDR}:{SSH_PORT}'
"#
    )
}

/// Outbound pinning (DESIGN.md §5c "The control channel, and keeping the
/// link to itself"): SMB, SSH and RDP to the private link's subnet may
/// leave only through `paguro0`, hardened against a VPN or DHCP server
/// that pushes an overlapping or more specific route for
/// `169.254.244.0/30` out some other adapter. Windows Firewall has no
/// "every interface but this one" match, so the block rule lists every
/// *other* adapter by name, recomputed each run (adapters can change) —
/// a machine with only `paguro0` skips it: there is nowhere else to go.
/// Idempotent, like the other provisioning scripts here.
pub fn windows_outbound_pin_ps1() -> String {
    format!(
        r#"# paguro: outbound pinning (DESIGN.md §5c). Generated.
$ErrorActionPreference = 'Stop'
$ports = @(445, {SSH_PORT}, {RDP_PORT})
Get-NetFirewallRule -Name '{OUTBOUND_ALLOW_RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -Name '{OUTBOUND_BLOCK_RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name '{OUTBOUND_ALLOW_RULE}' `
    -DisplayName 'paguro: SMB/SSH/RDP to the link, out the private adapter' `
    -Direction Outbound -Protocol TCP -RemotePort $ports -RemoteAddress '{LINK_NET}' `
    -InterfaceAlias '{IFNAME}' -Action Allow | Out-Null
$others = @(Get-NetAdapter | Where-Object Name -ne '{IFNAME}' | ForEach-Object Name)
if ($others.Count -gt 0) {{
    New-NetFirewallRule -Name '{OUTBOUND_BLOCK_RULE}' `
        -DisplayName 'paguro: SMB/SSH/RDP to the link, blocked on every other adapter' `
        -Direction Outbound -Protocol TCP -RemotePort $ports -RemoteAddress '{LINK_NET}' `
        -InterfaceAlias $others -Action Block | Out-Null
}}
'paguro: SMB/SSH/RDP to {LINK_NET} pinned to {IFNAME}'
"#
    )
}

/// The CIFS mount options for `/mnt/c` (the password goes in through
/// `password=` in the mount data only; never on a command line).
pub fn cifs_options(user: &str, secret: &str, uid: u32, gid: u32) -> String {
    // A comma would end the option: Samba's convention doubles it.
    let pw = secret.replace(',', ",,");
    format!(
        "vers=3.1.1,sign,username={user},password={pw},uid={uid},gid={gid},\
         file_mode=0644,dir_mode=0755,noserverino,nosharesock,soft,echo_interval=10"
    )
}

pub fn cifs_source() -> String {
    format!("//{GUEST_ADDR}/{C_SHARE}")
}

/// One `authorized_keys` line for the host's own sshd (DESIGN.md §5c
/// "Shells, the same command both ways"): the Windows side's public key,
/// restricted to its one address — the mirror of the `from=` restriction
/// on Windows' own `authorized_keys`/`administrators_authorized_keys`.
pub fn authorized_keys_line(windows_pubkey: &str) -> String {
    format!("from=\"{GUEST_ADDR}\" {}", windows_pubkey.trim())
}

/// One `known_hosts` line pinning `pubkey` (a host key) to `addr`: used by
/// both directions so neither ever falls back to trust-on-first-use
/// (DESIGN.md §5c "The control channel, and keeping the link to itself";
/// the agent port is what delivers the other side's host key, INTERFACES
/// §11.3).
pub fn known_hosts_line(addr: &str, host_pubkey: &str) -> String {
    format!("{addr} {}", host_pubkey.trim())
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// The netns (created if absent) with its loopback up.
pub fn ensure_netns() -> Result<(), String> {
    if !Path::new("/run/netns").join(NETNS).exists() {
        run(Command::new("ip").args(["netns", "add", NETNS]))?;
    }
    run(Command::new("ip").args(["-n", NETNS, "link", "set", "lo", "up"]))
}

/// Move `ifname` (QEMU's tap, or the test VM's NIC) into the netns and
/// address it.
pub fn attach_link(ifname: &str) -> Result<(), String> {
    run(Command::new("ip").args(["link", "set", ifname, "netns", NETNS]))?;
    if ifname != IFNAME {
        run(Command::new("ip").args(["-n", NETNS, "link", "set", ifname, "name", IFNAME]))?;
    }
    let addr = format!("{HOST_ADDR}/{PREFIX}");
    run(Command::new("ip").args(["-n", NETNS, "addr", "replace", &addr, "dev", IFNAME]))?;
    run(Command::new("ip").args(["-n", NETNS, "link", "set", IFNAME, "up"]))
}

/// Run `f` on a thread that has joined the netns: sockets it opens
/// (a CIFS mount's included) belong to the private link.
pub fn in_netns<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    std::thread::spawn(move || {
        let p = Path::new("/run/netns").join(NETNS);
        let ns = std::fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        use std::os::fd::AsRawFd;
        // SAFETY: setns on a valid netns fd, this thread only.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(format!("setns: {}", std::io::Error::last_os_error()));
        }
        f()
    })
    .join()
    .map_err(|_| "netns thread panicked".to_string())?
}

/// Samba for `L:`: `smb.conf` under `state`, the share's account with
/// `secret` (on smbpasswd's stdin), and `smbd` started inside the netns
/// (a daemon: it detaches). `root` holds a folder per distribution.
pub fn start_samba(root: &Path, state: &Path, secret: &str) -> Result<(), String> {
    for d in ["private", "lock", "state", "cache", "ncalrpc"] {
        std::fs::create_dir_all(state.join(d)).map_err(|e| format!("{}: {e}", state.display()))?;
    }
    let conf = state.join("smb.conf");
    std::fs::write(&conf, smb_conf(root, state)).map_err(|e| format!("{}: {e}", conf.display()))?;
    let mut c = Command::new("smbpasswd")
        .arg("-c")
        .arg(&conf)
        .args(["-a", "-s", LINUX_SMB_USER])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("smbpasswd: {e}"))?;
    {
        use std::io::Write;
        let mut i = c.stdin.take().ok_or("smbpasswd: stdin")?;
        write!(i, "{secret}\n{secret}\n").map_err(|e| format!("smbpasswd: {e}"))?;
    }
    let st = c.wait().map_err(|e| format!("smbpasswd: {e}"))?;
    if !st.success() {
        return Err(format!("smbpasswd: {st}"));
    }
    let pidfile = state.join("smbd.pid");
    let _ = std::fs::remove_file(&pidfile);
    in_netns(move || run(Command::new("smbd").arg("-D").arg("-s").arg(&conf)))?;
    // smbd -D returns before it has set up; it may still give up (a
    // missing guest account, a port in use). Running means its pid file
    // names a live process a moment later.
    for _ in 0..SMBD_POLLS {
        std::thread::sleep(std::time::Duration::from_millis(SMBD_POLL_MS));
        if let Ok(p) = std::fs::read_to_string(&pidfile) {
            if Path::new("/proc").join(p.trim()).exists() {
                return Ok(());
            }
        }
    }
    Err(format!(
        "smbd did not stay up; see {}",
        state.join("log.smbd").display()
    ))
}

const SMBD_POLLS: u32 = 30;
const SMBD_POLL_MS: u64 = 200;

/// Mount `/mnt/c` (Mode 1) from inside the netns.
pub fn mount_c(target: &Path, secret: &str, uid: u32, gid: u32) -> Result<(), String> {
    let target = target.to_path_buf();
    let data = cifs_options(WINDOWS_SMB_USER, secret, uid, gid);
    in_netns(move || {
        std::fs::create_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
        paguro_initrd::sys::mount(&cifs_source(), &target, "cifs", 0, &data)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samba_binds_the_link_only() {
        let c = smb_conf(Path::new("/mnt/l"), Path::new("/run/paguro/samba"));
        assert!(c.contains("\tinterfaces = paguro0\n\tbind interfaces only = yes\n"));
        assert!(c.contains("server signing = mandatory"));
        assert!(c.contains("smb encrypt = off"));
        assert!(c.contains("map to guest = never"));
        assert!(c.contains("[l]\n\tpath = /mnt/l\n\tvalid users = paguro\n"));
        assert!(!c.contains("guest ok = yes"));
        assert!(c.contains("passdb backend = tdbsam:/run/paguro/samba/passdb.tdb"));
    }

    #[test]
    fn windows_side() {
        let s = windows_provision_ps1("02:70:67:00:00:02");
        assert!(s.contains("MacAddress -eq '02-70-67-00-00-02'"));
        assert!(s.contains("-IPAddress '169.254.244.2' -PrefixLength 30"));
        assert!(s.contains("-InterfaceAlias 'paguro0' -RemoteAddress '169.254.244.1'"));
        assert!(s.contains("New-SmbMapping -LocalPath 'L:' -RemotePath '\\\\169.254.244.1\\l'"));
        // secrets are parameters, not text
        assert!(s.starts_with("# paguro"));
        assert!(s.contains("param([Parameter(Mandatory)][string]$SmbSecret"));
    }

    #[test]
    fn ssh_windows_side_admin() {
        let s = windows_ssh_provision_ps1(
            "anna",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI abc paguro@host",
            true,
        );
        assert!(s.starts_with("# paguro"));
        assert!(s.contains("ListenAddress 169.254.244.2"));
        assert!(s.contains("Port 22"));
        assert!(s.contains("PasswordAuthentication no"));
        assert!(s.contains("KbdInteractiveAuthentication no"));
        assert!(s.contains("AllowUsers anna"));
        assert!(s.contains(r"administrators_authorized_keys"));
        assert!(!s.contains(r"Users\anna\.ssh\authorized_keys"));
        assert!(s.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI abc paguro@host"));
        assert!(s.contains("-InterfaceAlias 'paguro0' -RemoteAddress '169.254.244.1'"));
        assert!(s.contains("-LocalPort 22"));
        assert!(s.contains("DefaultShell"));
        // No secret handling needed: the key is public, so it may appear
        // as literal text (unlike the SMB script's two parameters).
    }

    #[test]
    fn ssh_windows_side_non_admin_and_quoting() {
        let s = windows_ssh_provision_ps1("bob", "ssh-ed25519 AAAA it's-fine bob@x", false);
        assert!(s.contains(r"Users\bob\.ssh\authorized_keys"));
        assert!(!s.contains("administrators_authorized_keys"));
        // A literal single quote in the key is escaped for PowerShell, not
        // left to break out of the quoted string.
        assert!(s.contains("it''s-fine"));
        assert!(!s.contains("$LinuxPubKey = 'ssh-ed25519 AAAA it's-fine"));
    }

    #[test]
    fn outbound_pinned_to_the_private_adapter() {
        let s = windows_outbound_pin_ps1();
        assert!(s.starts_with("# paguro"));
        assert!(s.contains("$ports = @(445, 22, 3389)"));
        assert!(s.contains("-RemoteAddress '169.254.244.0/30'"));
        assert!(s.contains("-InterfaceAlias 'paguro0' -Action Allow"));
        assert!(s.contains("Where-Object Name -ne 'paguro0'"));
        assert!(s.contains("-InterfaceAlias $others -Action Block"));
        // the block rule is skipped, not created empty, when there is
        // nowhere else the traffic could leave from
        assert!(s.contains("if ($others.Count -gt 0)"));
    }

    #[test]
    fn cifs() {
        let o = cifs_options("paguro-smb", "a,b", 1000, 1000);
        assert!(o.contains("password=a,,b,"));
        assert!(o.starts_with("vers=3.1.1,sign,"));
        assert_eq!(cifs_source(), "//169.254.244.2/paguro-c");
    }

    #[test]
    fn authorized_keys_restricted_by_address() {
        let l = authorized_keys_line(" ssh-ed25519 AAAA windows@host \n");
        assert_eq!(l, "from=\"169.254.244.2\" ssh-ed25519 AAAA windows@host");
    }

    #[test]
    fn known_hosts_pins_the_host_key() {
        let l = known_hosts_line(HOST_ADDR, " ssh-ed25519 AAAA \n");
        assert_eq!(l, "169.254.244.1 ssh-ed25519 AAAA");
    }
}
