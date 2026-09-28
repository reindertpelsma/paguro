//! `paguro-link`: what both ends of the private link must agree on
//! (DESIGN.md §5c, §5d; INTERFACES.md §11.3) — the addresses and names, the
//! Windows side's provisioning scripts, and the agent-port frames. The
//! Linux launcher (`paguro-vm`) and the paguro service in the VM
//! (`paguro-win`) both build on this crate, so the two sides cannot drift.
//!
//! Pure text and JSON; nothing here touches the system.

use serde_json::{Value, json};

/// The link adapter's name on both sides.
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
/// The VM's link adapter's MAC: how the service finds the adapter to
/// configure (QEMU gives it this address).
pub const LINK_MAC: &str = "02:70:67:00:00:02";

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

/// paguro's own sshd on Windows (DESIGN.md §5c "Shells"): a second,
/// independent instance, like the Linux side's. Windows' own `sshd` service,
/// its `sshd_config` and the global `DefaultShell` are never touched, so a
/// user's own OpenSSH Server keeps working natively, where the link address
/// does not exist.
pub const WINDOWS_SSHD_SERVICE: &str = "paguro-sshd";

/// PowerShell that sets `$ossh` to the folder holding `sshd.exe`: the
/// Win32-OpenSSH MSI's (Program Files) or Windows' own capability's
/// (System32), installing the capability only when neither exists.
/// Installing it creates Windows' own `sshd` service as Manual; paguro
/// leaves it that way.
const FIND_OPENSSH: &str = r#"$ossh = @("$env:ProgramFiles\OpenSSH", "$env:SystemRoot\System32\OpenSSH") |
    Where-Object { Test-Path "$_\sshd.exe" } | Select-Object -First 1
if (-not $ossh) {
    $cap = Get-WindowsCapability -Online -Name OpenSSH.Server*
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    $ossh = "$env:SystemRoot\System32\OpenSSH"
}"#;

/// The Windows side of "Shells, the same command both ways" (DESIGN.md
/// §5c), after the key exchange: paguro's own sshd ([`WINDOWS_SSHD_SERVICE`])
/// with its own configuration, host key and per-user authorized-keys files
/// under `%ProgramData%\paguro\link`, bound to the link address and allowed
/// in by a firewall rule scoped to the link. The service is Manual: the
/// paguro service (re)starts it on every VM boot, and natively nothing
/// starts it. Admins and non-admins alike use the per-user file (Windows'
/// `administrators_authorized_keys` special case lives only in Windows' own
/// configuration). Idempotent. `user` must pass [`windows_user_ok`] (its
/// short name is what Linux signs in as); `linux_pubkey` is the host's
/// client key, one line.
pub fn windows_ssh_provision_ps1(user: &str, linux_pubkey: &str) -> String {
    let short = user.rsplit('\\').next().unwrap_or(user);
    let who = ps_single_quoted(short);
    let key = ps_single_quoted(linux_pubkey.trim());
    format!(
        r#"# paguro: the private link, SSH Windows side (DESIGN.md §5c). Generated.
$ErrorActionPreference = 'Stop'
$User = {who}
$LinuxPubKey = {key}
{FIND_OPENSSH}
$link = "$env:ProgramData\paguro\link"
$akdir = "$link\authorized_keys"
New-Item -ItemType Directory -Force -Path $akdir | Out-Null
$ak = Join-Path $akdir $User
# Exactly the host's key for this user, from its one address, replaced
# rather than appended.
Set-Content -Path $ak -Value ('from="{HOST_ADDR}" ' + $LinuxPubKey) -Encoding ascii
# sshd refuses an authorized-keys file others can write.
icacls $ak /inheritance:r /grant '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
$conf = "$link\sshd_config"
@(
    '# paguro: the private link''s own sshd (DESIGN.md §5c). Generated.',
    '# Windows'' own sshd and its configuration are untouched.',
    'ListenAddress {GUEST_ADDR}',
    'Port {SSH_PORT}',
    'HostKey __PROGRAMDATA__/paguro/link/ssh_host_ed25519_key',
    'AuthorizedKeysFile __PROGRAMDATA__/paguro/link/authorized_keys/%u',
    "AllowUsers $User",
    'PubkeyAuthentication yes',
    'PasswordAuthentication no',
    'KbdInteractiveAuthentication no',
    'Subsystem sftp sftp-server.exe'
) | Set-Content -Path $conf -Encoding ascii
$bin = "`"$ossh\sshd.exe`" -f `"$conf`""
if (Get-Service -Name '{WINDOWS_SSHD_SERVICE}' -ErrorAction SilentlyContinue) {{
    sc.exe config {WINDOWS_SSHD_SERVICE} binPath= $bin start= demand | Out-Null
}} else {{
    New-Service -Name '{WINDOWS_SSHD_SERVICE}' -BinaryPathName $bin -StartupType Manual `
        -DisplayName 'paguro: SSH on the private link' | Out-Null
}}
# A restart, so a changed configuration takes effect.
Restart-Service -Name '{WINDOWS_SSHD_SERVICE}'
Get-NetFirewallRule -Name '{WINDOWS_SSH_FIREWALL_RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name '{WINDOWS_SSH_FIREWALL_RULE}' -DisplayName 'paguro: SSH on the private link' -Direction Inbound `
    -Protocol TCP -LocalPort {SSH_PORT} -InterfaceAlias '{IFNAME}' -RemoteAddress '{HOST_ADDR}' -Action Allow | Out-Null
'paguro: SSH ready on {GUEST_ADDR}:{SSH_PORT}'
"#
    )
}

/// A PowerShell single-quoted string literal (`'` doubled).
pub fn ps_single_quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
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

/// One `authorized_keys` line for the host's own sshd (DESIGN.md §5c
/// "Shells, the same command both ways"): the Windows side's public key,
/// restricted to its one address — the mirror of the `from=` restriction
/// in the per-user file of paguro's sshd on Windows
/// ([`windows_ssh_provision_ps1`]).
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

/// How the service runs a generated script with secrets: the script, whole,
/// on `powershell.exe`'s stdin, read before it is run (plain `-Command -`
/// executes stdin line by line, which breaks multi-line script blocks).
/// Nothing secret is ever on a command line.
pub const PS_STDIN_ARGS: [&str; 6] = [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    "[Console]::In.ReadToEnd() | Invoke-Expression",
];

/// A Windows account name the link's sshd can admit (`AllowUsers` is
/// space-separated and the scripts embed the name in quoted strings): an
/// optional `DOMAIN\` prefix, then `[A-Za-z0-9._-]`, at most 64.
pub fn windows_user_ok(s: &str) -> bool {
    let name = s.rsplit('\\').next().unwrap_or("");
    s.len() <= 64
        && !name.is_empty()
        && s.matches('\\').count() <= 1
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-\\".contains(&b))
}

/// The service's SSH preparation for one Windows user, before the key
/// exchange (DESIGN.md §5c "Shells"): `sshd.exe` present, paguro's own host
/// key (SYSTEM and Administrators only), and the user's link key in their
/// own profile, readable by them and SYSTEM only. Prints one line,
/// `PAGURO-SSH {json}` ([`parse_ssh_prepare`]), with both public keys and
/// the private key's path. Idempotent. `user` must pass
/// [`windows_user_ok`].
pub fn windows_ssh_prepare_ps1(user: &str) -> String {
    let who = ps_single_quoted(user);
    format!(
        r#"# paguro: SSH, the service's preparation for one user (DESIGN.md §5c). Generated.
$ErrorActionPreference = 'Stop'
$User = {who}
{FIND_OPENSSH}
$keygen = "$ossh\ssh-keygen.exe"
# paguro's own host key (its sshd is a separate instance; Windows' own
# host keys are not used or touched).
$link = "$env:ProgramData\paguro\link"
New-Item -ItemType Directory -Force -Path $link | Out-Null
$hk = "$link\ssh_host_ed25519_key"
if (-not (Test-Path $hk)) {{
    & $keygen -q -t ed25519 -N '""' -C "paguro-link@$env:COMPUTERNAME" -f $hk | Out-Null
}}
icacls $hk /inheritance:r /grant '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
$sid = (New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$prof = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid).LocalPath
if (-not $prof) {{ throw "paguro: $User has no profile yet" }}
$dir = Join-Path $prof '.ssh'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$key = Join-Path $dir 'paguro_link_ed25519'
if (-not (Test-Path $key)) {{
    & $keygen -q -t ed25519 -N '""' -C "paguro@$env:COMPUTERNAME" -f $key | Out-Null
}}
# OpenSSH refuses a private key others can read.
icacls $key /inheritance:r /grant "*${{sid}}:F" '*S-1-5-18:F' | Out-Null
'PAGURO-SSH ' + (@{{ user_pub = (Get-Content "$key.pub" -Raw).Trim(); host_pub = (Get-Content "$hk.pub" -Raw).Trim(); key = $key }} | ConvertTo-Json -Compress)
"#
    )
}

/// What [`windows_ssh_prepare_ps1`] reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshPrepared {
    pub user_pub: String,
    pub host_pub: String,
    pub key_path: String,
}

pub fn parse_ssh_prepare(stdout: &str) -> Option<SshPrepared> {
    let j = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("PAGURO-SSH "))?;
    let v: Value = serde_json::from_str(j).ok()?;
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(|x| x.trim().to_string())
    };
    let (user_pub, host_pub, key_path) = (s("user_pub")?, s("host_pub")?, s("key")?);
    (pubkey_ok(&user_pub) && pubkey_ok(&host_pub) && !key_path.is_empty()).then_some(SshPrepared {
        user_pub,
        host_pub,
        key_path,
    })
}

// ---- Agent-port frames (INTERFACES.md §11.3) -------------------------------
//
// Everything a frame carries that ends up in a script or a file is checked
// here first: secrets and user names against a fixed character set, keys
// as one `ssh-…` line. A frame that fails a check is refused, never
// "cleaned up".

/// guest → host: the service asks for the link's settings.
pub fn link_request() -> Value {
    json!({ "type": "link-request" })
}

pub fn is_link_request(v: &Value) -> bool {
    kind(v) == Some("link-request")
}

/// The per-installation secrets the service provisions the link with: the
/// password of Windows' dedicated SMB account (for `/mnt/c`), and the one
/// Windows uses for the host's share (`L:`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkConfig {
    pub smb_secret: String,
    pub host_secret: String,
}

/// host → guest.
pub fn link_frame(c: &LinkConfig) -> Value {
    json!({ "type": "link", "smb_secret": c.smb_secret, "host_secret": c.host_secret })
}

/// host → guest: the host could not supply the settings (the link is not
/// set up on this side); the service retries later.
pub fn link_error(error: &str) -> Value {
    json!({ "type": "link", "error": error })
}

/// `None`: not a `link` frame. `Some(Err)`: the host's error, or a frame
/// whose secrets fail [`secret_ok`].
pub fn parse_link(v: &Value) -> Option<Result<LinkConfig, String>> {
    if kind(v) != Some("link") {
        return None;
    }
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Some(Err(e.to_string()));
    }
    let get = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| secret_ok(s))
            .map(str::to_string)
            .ok_or_else(|| format!("link: {k} missing or not a usable secret"))
    };
    Some(get("smb_secret").and_then(|smb_secret| {
        Ok(LinkConfig {
            smb_secret,
            host_secret: get("host_secret")?,
        })
    }))
}

/// guest → host: the Windows side of the link is (or is not) in place.
pub fn link_ready(result: Result<(), &str>) -> Value {
    match result {
        Ok(()) => json!({ "type": "link-ready", "ok": true }),
        Err(e) => json!({ "type": "link-ready", "ok": false, "error": e }),
    }
}

pub fn parse_link_ready(v: &Value) -> Option<Result<(), String>> {
    (kind(v) == Some("link-ready")).then(|| {
        if v.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err(v
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("not ready")
                .to_string())
        }
    })
}

/// A secret generated by paguro: 24 to 128 characters of `[A-Za-z0-9_-]`.
/// Nothing else is accepted, so a secret can never break out of the
/// quoting it is embedded in.
pub fn secret_ok(s: &str) -> bool {
    (24..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What the service feeds `powershell.exe` on **stdin** (never on its
/// command line, where other processes could read it): the provisioning
/// script as a script block, invoked with the two secrets.
pub fn provision_invocation(c: &LinkConfig) -> String {
    format!(
        "& {{\n{}\n}} -SmbSecret {} -HostSecret {}\n",
        windows_provision_ps1(LINK_MAC),
        ps_single_quoted(&c.smb_secret),
        ps_single_quoted(&c.host_secret)
    )
}

/// guest → host: Windows' client key and its sshd host key.
/// guest → host: the Windows account Linux signs in as (short name, per
/// [`windows_user_ok`]), its link key and the link sshd's host key.
pub fn ssh_keys_frame(windows_user: &str, windows_user_pub: &str, windows_host_pub: &str) -> Value {
    json!({
        "type": "ssh-keys",
        "windows_user": windows_user,
        "windows_user_pub": windows_user_pub,
        "windows_host_pub": windows_host_pub,
    })
}

/// host → guest: the Linux account Windows signs in as, the host's client
/// key (for Windows' authorized keys) and its sshd host key (pinned in
/// Windows' `known_hosts`).
pub fn ssh_keys_ack_frame(linux_user: &str, linux_user_pub: &str, linux_host_pub: &str) -> Value {
    json!({
        "type": "ssh-keys-ack",
        "linux_user": linux_user,
        "linux_user_pub": linux_user_pub,
        "linux_host_pub": linux_host_pub,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshAck {
    pub linux_user: String,
    pub linux_user_pub: String,
    pub linux_host_pub: String,
}

/// `None`: not an `ssh-keys-ack`. `Some(Err)`: the host's error, or a
/// field that fails its check.
pub fn parse_ssh_keys_ack(v: &Value) -> Option<Result<SshAck, String>> {
    if kind(v) != Some("ssh-keys-ack") {
        return None;
    }
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Some(Err(e.to_string()));
    }
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let (user, upub, hpub) = (s("linux_user"), s("linux_user_pub"), s("linux_host_pub"));
    Some(if !linux_user_ok(&user) {
        Err(format!(
            "ssh-keys-ack: {user:?} is not a usable Linux user name"
        ))
    } else if !pubkey_ok(&upub) || !pubkey_ok(&hpub) {
        Err("ssh-keys-ack: a key is not one ssh-… line".into())
    } else {
        Ok(SshAck {
            linux_user: user,
            linux_user_pub: upub,
            linux_host_pub: hpub,
        })
    })
}

/// A portable Linux user name: `[a-z_][a-z0-9_-]*`, at most 32.
pub fn linux_user_ok(s: &str) -> bool {
    let mut b = s.bytes();
    s.len() <= 32
        && b.next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == b'_')
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// One OpenSSH public key line: `ssh-<type> <base64> [comment]`, printable
/// ASCII, no quotes or control characters.
pub fn pubkey_ok(s: &str) -> bool {
    let mut f = s.split(' ');
    s.len() <= 16 << 10
        && f.next()
            .is_some_and(|t| t.starts_with("ssh-") || t.starts_with("ecdsa-"))
        && f.next().is_some_and(|k| {
            !k.is_empty()
                && k.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+/=".contains(&c))
        })
        && s.bytes()
            .all(|c| (0x20..0x7f).contains(&c) && c != b'\'' && c != b'"')
}

fn kind(v: &Value) -> Option<&str> {
    v.get("type").and_then(Value::as_str)
}
#[cfg(test)]
mod tests {
    use super::*;

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
    fn ssh_windows_side() {
        let s = windows_ssh_provision_ps1(
            r"DESKTOP-1\anna",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI abc paguro@host",
        );
        assert!(s.starts_with("# paguro"));
        assert!(s.contains("$User = 'anna'"));
        assert!(s.contains("'ListenAddress 169.254.244.2'"));
        assert!(s.contains("'Port 22'"));
        assert!(s.contains("'PasswordAuthentication no'"));
        assert!(s.contains("'KbdInteractiveAuthentication no'"));
        assert!(s.contains(r#""AllowUsers $User""#));
        assert!(s.contains("AuthorizedKeysFile __PROGRAMDATA__/paguro/link/authorized_keys/%u"));
        assert!(
            s.contains("$LinuxPubKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI abc paguro@host'")
        );
        assert!(s.contains("-InterfaceAlias 'paguro0' -RemoteAddress '169.254.244.1'"));
        assert!(s.contains("-LocalPort 22"));
        assert!(s.contains(r#"('from="169.254.244.1" ' + $LinuxPubKey)"#));
        // A separate instance: Windows' own sshd, its configuration and
        // DefaultShell are left alone.
        assert!(s.contains("New-Service -Name 'paguro-sshd'"));
        assert!(s.contains("-StartupType Manual"));
        assert!(!s.contains("DefaultShell"));
        assert!(!s.contains(r"ssh\sshd_config"));
        assert!(!s.contains("administrators_authorized_keys\""));
        assert!(!s.contains("Set-Service -Name sshd"));
    }

    #[test]
    fn ssh_windows_side_quoting() {
        let s = windows_ssh_provision_ps1("bob", "ssh-ed25519 AAAA it's-fine bob@x");
        // A literal single quote in the key is escaped for PowerShell, not
        // left to break out of the quoted string.
        assert!(s.contains("it''s-fine"));
        assert!(!s.contains("$LinuxPubKey = 'ssh-ed25519 AAAA it's-fine"));
        // Paths PowerShell must expand are double-quoted.
        assert!(s.contains(r#"$link = "$env:ProgramData\paguro\link""#));
        assert!(!s.contains("'$env:"));
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
    fn authorized_keys_restricted_by_address() {
        let l = authorized_keys_line(" ssh-ed25519 AAAA windows@host \n");
        assert_eq!(l, "from=\"169.254.244.2\" ssh-ed25519 AAAA windows@host");
    }
    #[test]
    fn known_hosts_pins_the_host_key() {
        let l = known_hosts_line(HOST_ADDR, " ssh-ed25519 AAAA \n");
        assert_eq!(l, "169.254.244.1 ssh-ed25519 AAAA");
    }

    #[test]
    fn link_frames_round_trip() {
        let c = LinkConfig {
            smb_secret: "a".repeat(32),
            host_secret: "B-_9".repeat(8),
        };
        assert!(is_link_request(&link_request()));
        assert_eq!(parse_link(&link_frame(&c)), Some(Ok(c.clone())));
        assert_eq!(
            parse_link(&link_error("no state")),
            Some(Err("no state".into()))
        );
        assert_eq!(parse_link(&link_request()), None);
        assert_eq!(parse_link_ready(&link_ready(Ok(()))), Some(Ok(())));
        assert_eq!(
            parse_link_ready(&link_ready(Err("x"))),
            Some(Err("x".into()))
        );
    }

    #[test]
    fn secrets_that_could_break_quoting_are_refused() {
        for bad in [
            "short",
            "a'b".repeat(10).as_str(),
            &"a".repeat(129),
            &format!("{} x", "a".repeat(30)),
        ] {
            assert!(!secret_ok(bad), "{bad}");
            let f = json!({"type": "link", "smb_secret": bad, "host_secret": "a".repeat(32)});
            assert!(matches!(parse_link(&f), Some(Err(_))), "{bad}");
        }
    }

    #[test]
    fn secrets_go_in_the_invocation_not_the_script() {
        let c = LinkConfig {
            smb_secret: "s".repeat(32),
            host_secret: "h".repeat(32),
        };
        let inv = provision_invocation(&c);
        let script = windows_provision_ps1(LINK_MAC);
        assert!(!script.contains(&c.smb_secret));
        assert!(inv.starts_with("& {\n# paguro"));
        assert!(inv.ends_with(&format!(
            "}} -SmbSecret '{}' -HostSecret '{}'\n",
            c.smb_secret, c.host_secret
        )));
    }

    #[test]
    fn ssh_ack_is_checked() {
        let ok = ssh_keys_ack_frame(
            "alice",
            "ssh-ed25519 AAAA1+/= paguro@host",
            "ssh-ed25519 BBBB",
        );
        assert_eq!(
            parse_ssh_keys_ack(&ok),
            Some(Ok(SshAck {
                linux_user: "alice".into(),
                linux_user_pub: "ssh-ed25519 AAAA1+/= paguro@host".into(),
                linux_host_pub: "ssh-ed25519 BBBB".into()
            }))
        );
        for (u, k) in [
            ("Alice", "ssh-ed25519 AAAA"),
            ("a;b", "ssh-ed25519 AAAA"),
            ("alice", "ssh-ed25519 AA'AA"),
            ("alice", "ssh-ed25519 AAAA\nx"),
        ] {
            assert!(
                matches!(
                    parse_ssh_keys_ack(&ssh_keys_ack_frame(u, k, "ssh-ed25519 BBBB")),
                    Some(Err(_))
                ),
                "{u} {k}"
            );
        }
        assert_eq!(
            parse_ssh_keys_ack(&json!({"type": "ssh-keys-ack", "error": "no state"})),
            Some(Err("no state".into()))
        );
    }

    #[test]
    fn ssh_prepare() {
        assert!(windows_user_ok("anna") && windows_user_ok(r"DESKTOP-1\anna.b_c-d"));
        for bad in ["", "John Smith", "a$b", "a`b", r"a\b\c", r"DOM\", "a'b"] {
            assert!(!windows_user_ok(bad), "{bad}");
        }
        let s = windows_ssh_prepare_ps1(r"DESKTOP-1\anna");
        assert!(s.contains(r"$User = 'DESKTOP-1\anna'"));
        assert!(s.contains("icacls $key /inheritance:r"));
        let out = "noise\r\nPAGURO-SSH {\"user_pub\":\"ssh-ed25519 AAAA paguro@X\",\"host_pub\":\"ssh-ed25519 BBBB\",\"key\":\"C:\\\\Users\\\\anna\\\\.ssh\\\\paguro_link_ed25519\"}\r\n";
        assert_eq!(
            parse_ssh_prepare(out),
            Some(SshPrepared {
                user_pub: "ssh-ed25519 AAAA paguro@X".into(),
                host_pub: "ssh-ed25519 BBBB".into(),
                key_path: r"C:\Users\anna\.ssh\paguro_link_ed25519".into()
            })
        );
        assert_eq!(
            parse_ssh_prepare("PAGURO-SSH {\"user_pub\":\"x\",\"host_pub\":\"y\",\"key\":\"k\"}"),
            None
        );
        assert_eq!(parse_ssh_prepare("nothing"), None);
    }
}
