//! The VM's LAN adapter (DESIGN.md §5c "The VM's network: a tap and
//! nftables, no user-mode networking"): a tap with vhost-net in the host's
//! own namespace (never netns `paguro`, which stays the private link only,
//! §`net`), routed on a small private subnet, NATed and — opt-in — DMZ'd by
//! paguro's own `inet paguro` nftables table.
//!
//! As in `net.rs`: everything that decides something (the subnet, the
//! ruleset text, the DMZ port set) is pure and tested below; the glue shells
//! out to `ip`, `nft`, `iptables` (Docker's `DOCKER-USER` only) and
//! `firewall-cmd`.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

/// paguro's own nftables table (`inet paguro`, DESIGN.md §5c). One fixed
/// name: the table is created and deleted whole, per session, so it never
/// collides with — or needs to coexist inside — anyone else's.
pub const NFT_TABLE: &str = "paguro";

/// RFC 2544's benchmarking range: reserved for lab/test traffic, so it is
/// never a real LAN's subnet and never Docker's default bridge ranges
/// (172.17–31/16, which this deliberately avoids alongside the common
/// 192.168.0.0/16 and 10.0.0.0/8 home/corporate ranges).
pub const DEFAULT_SUBNET: &str = "198.19.249.0/24";

/// Windows' link-only services (DESIGN.md "the network: Windows keeps its
/// inbound services"): never DMZ'd, whatever the listening-port set says,
/// unless the user explicitly pins one of them to `windows`.
pub const NEVER_FORWARD: [u16; 5] = [22, 445, 3389, 5985, 5986];

pub const DEFAULT_LEASE_SECS: u32 = 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subnet {
    pub network: Ipv4Addr,
    pub prefix: u8,
    /// The host's address on the tap (`.1`).
    pub host: Ipv4Addr,
    /// The VM's address (`.2`), the DHCP server's one lease.
    pub guest: Ipv4Addr,
}

impl Subnet {
    /// `A.B.C.D/N`: a `/24` or wider (the guest needs `.1` and `.2` inside
    /// it, so anything narrower than `/30` is refused; a `/31` or `/32` has
    /// no room for a router address at all).
    pub fn parse(s: &str) -> Result<Subnet, String> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| format!("{s}: expected A.B.C.D/N"))?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| format!("{s}: bad address"))?;
        let prefix: u8 = prefix.parse().map_err(|_| format!("{s}: bad prefix"))?;
        if prefix > 30 {
            return Err(format!(
                "{s}: /{prefix} has no room for a router and a lease"
            ));
        }
        let bits = u32::from(addr);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = Ipv4Addr::from(bits & mask);
        let base = u32::from(network);
        Ok(Subnet {
            network,
            prefix,
            host: Ipv4Addr::from(base | 1),
            guest: Ipv4Addr::from(base | 2),
        })
    }

    pub fn mask(&self) -> Ipv4Addr {
        let bits = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        Ipv4Addr::from(bits)
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }

    pub fn host_cidr(&self) -> String {
        format!("{}/{}", self.host, self.prefix)
    }
}

/// A `--pin-port PORT:linux|windows` pin: forces one port to one side
/// regardless of what `ss` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pin {
    Linux,
    Windows,
}

/// `"aa:bb:cc:dd:ee:ff"` → the six bytes the DHCP lease is keyed to (the
/// VM's LAN adapter carries the host's own MAC, DESIGN.md §4.5).
pub fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("{s}: expected six ':'-separated hex bytes"));
    }
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).map_err(|_| format!("{s}: bad hex byte {p:?}"))?;
    }
    Ok(out)
}

pub fn parse_pin(s: &str) -> Result<(u16, Pin), String> {
    let (port, side) = s
        .split_once(':')
        .ok_or_else(|| format!("{s}: expected PORT:linux|windows"))?;
    let port: u16 = port.parse().map_err(|_| format!("{s}: bad port"))?;
    let side = match side {
        "linux" => Pin::Linux,
        "windows" => Pin::Windows,
        _ => return Err(format!("{s}: side must be linux or windows")),
    };
    Ok((port, side))
}

// ---------------------------------------------------------------------------
// The DMZ's port sets — pure, so the never-forward rule is checked without
// nftables at all.

#[derive(Clone, Debug, Default)]
pub struct DmzPins {
    pub linux: BTreeSet<u16>,
    pub windows: BTreeSet<u16>,
}

impl DmzPins {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u16, Pin)>) -> DmzPins {
        let mut p = DmzPins::default();
        for (port, side) in pairs {
            match side {
                Pin::Linux => {
                    p.windows.remove(&port);
                    p.linux.insert(port);
                }
                Pin::Windows => {
                    p.linux.remove(&port);
                    p.windows.insert(port);
                }
            }
        }
        p
    }
}

/// The ports that are never forwarded even though the default list says
/// so — every entry in [`NEVER_FORWARD`] **except** one the user explicitly
/// pinned to `windows`. This is the one escape hatch; nothing else moves
/// these five ports.
pub fn effective_never_forward(pins: &DmzPins) -> BTreeSet<u16> {
    NEVER_FORWARD
        .into_iter()
        .filter(|p| !pins.windows.contains(p))
        .collect()
}

/// Whether a single port would be DMZ'd, given who currently listens and
/// the pins — the same ladder the generated nftables ruleset encodes,
/// spelled out here so it can be checked without nft:
/// pinned windows → forward; pinned linux → never; the five link-only
/// ports → never (unless pinned windows, handled above); a port Linux
/// listens on → never; anything else → forward.
pub fn is_dmz_forwarded(port: u16, listening: &BTreeSet<u16>, pins: &DmzPins) -> bool {
    if pins.windows.contains(&port) {
        return true;
    }
    if pins.linux.contains(&port) {
        return false;
    }
    if NEVER_FORWARD.contains(&port) {
        return false;
    }
    !listening.contains(&port)
}

/// `ss -Hltn`/`-Hlun`'s `Local Address:Port` column → the set of ports
/// something on the host is already listening on. `H` (no header), `l`
/// (listening), `t`/`u` (tcp/udp), `n` (numeric — no `/etc/services` or PTR
/// lookups, which is what keeps this parseable and fast to re-run every few
/// seconds).
pub fn parse_ss_listen(output: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in output.lines() {
        let Some(local) = line.split_whitespace().nth(3) else {
            continue;
        };
        // "1.2.3.4:80", "[::]:80", "*:80" — the port is always the text
        // after the last ':'.
        if let Some((_, port)) = local.rsplit_once(':') {
            if let Ok(p) = port.parse::<u16>() {
                ports.insert(p);
            }
        }
    }
    ports
}

pub fn listening_ports() -> BTreeSet<u16> {
    let mut out = BTreeSet::new();
    for args in [["-Hltn"], ["-Hlun"]] {
        if let Ok(o) = Command::new("ss").args(args).output() {
            out.extend(parse_ss_listen(&String::from_utf8_lossy(&o.stdout)));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// nftables ruleset generation.

fn port_set(ports: &BTreeSet<u16>) -> String {
    let items = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {items} }}")
}

/// A named `inet_service` set's body: `nft` rejects an empty `elements =
/// { }` clause, so an empty set omits it (just `{ type inet_service; }`,
/// which still exists and can be matched against — just matches nothing).
fn set_body(ports: &BTreeSet<u16>) -> String {
    if ports.is_empty() {
        "{ type inet_service; }".to_string()
    } else {
        format!("{{ type inet_service; elements = {} }}", port_set(ports))
    }
}

pub struct NftInputs<'a> {
    pub tap: &'a str,
    pub wan: &'a str,
    pub subnet: &'a Subnet,
    pub dmz: bool,
    pub pins: &'a DmzPins,
    /// The initial contents of the dynamically-updated `linux_ports` set
    /// (kept current afterwards by [`linux_ports_update`]).
    pub listening: &'a BTreeSet<u16>,
}

/// The whole `table inet paguro { ... }`, loaded with one `nft -f`. Created
/// per session, deleted whole at teardown (`nft delete table inet paguro`).
pub fn nft_ruleset(i: &NftInputs) -> String {
    let mut s = format!(
        "# paguro: the VM's LAN (DESIGN.md \u{a7}5c). Generated; `nft -f` this file.\n\
         table inet {NFT_TABLE} {{\n\
         \tchain postrouting {{\n\
         \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
         \t\tip saddr {} oifname \"{}\" masquerade\n\
         \t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tiifname \"{}\" accept\n\
         \t\toifname \"{}\" accept\n\
         \t}}\n",
        i.subnet.cidr(),
        i.wan,
        i.tap,
        i.tap
    );
    if i.dmz {
        let never = effective_never_forward(i.pins);
        s.push_str(&format!(
            "\tset pinned_windows {}\n\
             \tset pinned_linux {}\n\
             \tset linux_ports {}\n\
             \tchain dmz {{\n\
             \t\ttype nat hook prerouting priority dstnat; policy accept;\n\
             \t\tiifname \"{}\" meta l4proto {{ tcp, udp }} th dport @pinned_windows dnat ip to {}\n\
             \t\tiifname \"{}\" meta l4proto {{ tcp, udp }} th dport @pinned_linux return\n\
             \t\tiifname \"{}\" meta l4proto {{ tcp, udp }} th dport {} return\n\
             \t\tiifname \"{}\" meta l4proto {{ tcp, udp }} th dport @linux_ports return\n\
             \t\tiifname \"{}\" ct state new meta l4proto {{ tcp, udp }} dnat ip to {}\n\
             \t}}\n",
            set_body(&i.pins.windows),
            set_body(&i.pins.linux),
            set_body(i.listening),
            i.wan,
            i.subnet.guest,
            i.wan,
            i.wan,
            port_set(&never),
            i.wan,
            i.wan,
            i.subnet.guest,
        ));
    }
    s.push_str("}\n");
    s
}

/// Just the DMZ's dynamic set, replaced atomically (one `nft -f`, so the
/// window between "empty" and "full" never exists): the poll loop's update.
pub fn linux_ports_update(listening: &BTreeSet<u16>) -> String {
    format!(
        "flush set inet {NFT_TABLE} linux_ports\n\
         add element inet {NFT_TABLE} linux_ports {}\n",
        port_set(listening)
    )
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

fn run_ignore(cmd: &mut Command) {
    let _ = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn nft_f(text: &str, tag: &str) -> Result<(), String> {
    let path = std::env::temp_dir().join(format!("paguro-nft-{tag}-{}.nft", std::process::id()));
    std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    let r = run(Command::new("nft").arg("-f").arg(&path));
    let _ = std::fs::remove_file(&path);
    r
}

pub fn nft_apply(ruleset: &str) -> Result<(), String> {
    nft_f(ruleset, "apply")
}

pub fn nft_update_linux_ports(listening: &BTreeSet<u16>) -> Result<(), String> {
    nft_f(&linux_ports_update(listening), "update")
}

/// Idempotent: no error if the table is already gone.
pub fn nft_delete_table() -> Result<(), String> {
    let out = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() || String::from_utf8_lossy(&out.stderr).contains("No such file") {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// sysctl, the tap, the default route.

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// Enables forwarding for the session; returns the previous value so it can
/// be restored (`restore_ip_forward`) even if it was already `1` (someone
/// else's requirement — we don't turn it back off under them).
pub fn set_ip_forward(enable: bool) -> Result<String, String> {
    let prev = std::fs::read_to_string(IP_FORWARD)
        .map_err(|e| format!("{IP_FORWARD}: {e}"))?
        .trim()
        .to_string();
    std::fs::write(IP_FORWARD, if enable { "1" } else { "0" })
        .map_err(|e| format!("{IP_FORWARD}: {e}"))?;
    Ok(prev)
}

pub fn restore_ip_forward(prev: &str) -> Result<(), String> {
    std::fs::write(IP_FORWARD, prev).map_err(|e| format!("{IP_FORWARD}: {e}"))
}

/// The interface the host currently routes its default route by (`ip route
/// show default`'s first `dev`) — what masquerade goes out of and what the
/// DMZ's inbound side watches. Parsed, not guessed: works over Wi-Fi and
/// Ethernet alike (DESIGN.md §5c "routed, not bridged").
pub fn default_route_iface() -> Result<String, String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("ip route show default: failed".into());
    }
    parse_default_route_iface(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| "no default route".into())
}

pub fn parse_default_route_iface(output: &str) -> Option<String> {
    let line = output.lines().next()?;
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .iter()
        .position(|w| *w == "dev")
        .and_then(|i| words.get(i + 1))
        .map(|s| s.to_string())
}

/// Address and bring up the tap QEMU already created (mirrors
/// `net::attach_link` for the private link): the interface exists in the
/// host's own namespace (never netns `paguro`) the moment QEMU opens it.
pub fn configure_tap(ifname: &str, subnet: &Subnet) -> Result<(), String> {
    run(Command::new("ip").args(["addr", "replace", &subnet.host_cidr(), "dev", ifname]))?;
    run(Command::new("ip").args(["link", "set", ifname, "up"]))
}

/// A safety net for the smoke test's `net-down` and for any tap QEMU left
/// behind: removing an interface that is already gone is not an error.
pub fn remove_tap_if_present(ifname: &str) {
    if Path::new("/sys/class/net").join(ifname).exists() {
        run_ignore(Command::new("ip").args(["link", "delete", ifname]));
    }
}

// ---------------------------------------------------------------------------
// Coexistence: Docker's DOCKER-USER chain, firewalld.

/// Docker (iptables or iptables-nft backend alike) always creates
/// `DOCKER-USER`, jumped to before its own rules — so an accept there is
/// honoured before Docker's FORWARD policy (often DROP) ever applies. This
/// is the fix for the classic libvirt-plus-Docker breakage (DESIGN.md
/// §5c "coexistence is a requirement").
pub fn docker_user_chain_exists() -> bool {
    Command::new("iptables")
        .args(["-nL", "DOCKER-USER"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn iptables_rule_exists(args: &[&str]) -> bool {
    let mut check = vec!["-C"];
    check.extend_from_slice(args.get(1..).unwrap_or(&[]));
    Command::new("iptables")
        .args(&check)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn add_docker_user_rule(tap: &str) -> Result<(), String> {
    for spec in [
        vec!["-I", "DOCKER-USER", "-i", tap, "-j", "ACCEPT"],
        vec!["-I", "DOCKER-USER", "-o", tap, "-j", "ACCEPT"],
    ] {
        if !iptables_rule_exists(&spec) {
            run(Command::new("iptables").args(&spec))?;
        }
    }
    Ok(())
}

pub fn remove_docker_user_rule(tap: &str) {
    for spec in [
        vec!["-D", "DOCKER-USER", "-i", tap, "-j", "ACCEPT"],
        vec!["-D", "DOCKER-USER", "-o", tap, "-j", "ACCEPT"],
    ] {
        run_ignore(Command::new("iptables").args(&spec));
    }
}

pub fn firewalld_running() -> bool {
    Command::new("firewall-cmd")
        .arg("--state")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Runtime-only (no `--permanent`): it must not survive past this session
/// even if teardown never runs.
pub fn add_firewalld_rule(tap: &str) -> Result<(), String> {
    for dir in ["-i", "-o"] {
        run(Command::new("firewall-cmd").args([
            "--direct",
            "--add-rule",
            "ipv4",
            "filter",
            "FORWARD",
            "0",
            dir,
            tap,
            "-j",
            "ACCEPT",
        ]))?;
    }
    Ok(())
}

pub fn remove_firewalld_rule(tap: &str) {
    for dir in ["-i", "-o"] {
        run_ignore(Command::new("firewall-cmd").args([
            "--direct",
            "--remove-rule",
            "ipv4",
            "filter",
            "FORWARD",
            "0",
            dir,
            tap,
            "-j",
            "ACCEPT",
        ]));
    }
}

/// UFW ships its own default-deny INPUT *and* FORWARD policy (`ufw status
/// verbose` calls the latter "routed"), enforced by rules UFW itself
/// manages — a `nft`/`iptables` accept added elsewhere races it exactly
/// like Docker's FORWARD DROP does, and for the tap's *inbound* side (DHCP,
/// DNS: both arrive as ordinary INPUT-chain traffic addressed to the host
/// itself) there is no other coexistence path at all. `ufw allow`/`ufw
/// route allow` are the supported way to add an exception UFW itself
/// honours; both are needed (the tap's INPUT traffic and its FORWARD
/// traffic are different UFW policies).
pub fn ufw_active() -> bool {
    let out = Command::new("ufw")
        .arg("status")
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).starts_with("Status: active"),
        Err(_) => false,
    }
}

pub fn add_ufw_rules(tap: &str) -> Result<(), String> {
    run(Command::new("ufw").args(["allow", "in", "on", tap]))?;
    run(Command::new("ufw").args(["route", "allow", "in", "on", tap]))?;
    run(Command::new("ufw").args(["route", "allow", "out", "on", tap]))?;
    Ok(())
}

pub fn remove_ufw_rules(tap: &str) {
    // `ufw`'s delete syntax puts `route` before `delete` for a routed rule
    // (`ufw route delete allow ...`), unlike a plain `ufw delete allow ...`
    // for the input rule — asymmetric, and easy to get backwards.
    run_ignore(Command::new("ufw").args(["delete", "allow", "in", "on", tap]));
    run_ignore(Command::new("ufw").args(["route", "delete", "allow", "in", "on", tap]));
    run_ignore(Command::new("ufw").args(["route", "delete", "allow", "out", "on", tap]));
}

/// What forwarding coexistence looks like right now, and what was done
/// about it — logged plainly so a blocked DMZ is never a silent mystery.
pub fn coexistence_setup(tap: &str) -> Vec<String> {
    let mut log = Vec::new();
    if docker_user_chain_exists() {
        match add_docker_user_rule(tap) {
            Ok(()) => log.push(format!(
                "coexistence: Docker's DOCKER-USER chain exists; added accept for {tap}"
            )),
            Err(e) => log.push(format!(
                "coexistence: Docker's DOCKER-USER chain exists but the accept rule failed \
                 ({e}); forwarding to/from {tap} may be blocked by Docker's FORWARD policy"
            )),
        }
    }
    if firewalld_running() {
        match add_firewalld_rule(tap) {
            Ok(()) => log.push(format!(
                "coexistence: firewalld is running; added a direct FORWARD accept for {tap}"
            )),
            Err(e) => log.push(format!(
                "coexistence: firewalld is running but the direct rule failed ({e}); \
                 forwarding to/from {tap} may be blocked by its zone/policy"
            )),
        }
    }
    if ufw_active() {
        match add_ufw_rules(tap) {
            Ok(()) => log.push(format!(
                "coexistence: ufw is active; allowed input and routed traffic for {tap} \
                 (its default-deny INPUT policy otherwise blocks the tap's own DHCP/DNS)"
            )),
            Err(e) => log.push(format!(
                "coexistence: ufw is active but the allow rules failed ({e}); DHCP/DNS on \
                 {tap} and forwarding through it may be blocked"
            )),
        }
    }
    if log.is_empty() {
        log.push("coexistence: no Docker DOCKER-USER chain, firewalld or ufw detected".to_string());
    }
    log
}

pub fn coexistence_teardown(tap: &str) {
    if docker_user_chain_exists() {
        remove_docker_user_rule(tap);
    }
    if firewalld_running() {
        remove_firewalld_rule(tap);
    }
    if ufw_active() {
        remove_ufw_rules(tap);
    }
}

// ---------------------------------------------------------------------------
// DNS: forward to the host's real resolver, layered simplest-first.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsMode {
    /// `systemd-resolved` is active: its stub listener now also answers on
    /// the tap's address (a drop-in, removed at teardown).
    ResolvedStub { drop_in: std::path::PathBuf },
    /// Neither: `dnsmasq` bound to the tap, forwarding to the host's own
    /// upstreams.
    Dnsmasq { pid: u32 },
    /// Nothing local at all: the DHCP lease's DNS servers are the host's
    /// own upstream resolvers directly (the guest asks them itself, same as
    /// slirp's DNS proxy never existed and Windows just used them raw).
    Static,
}

fn resolved_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The host's real upstream resolvers, `/etc/resolv.conf`'s `nameserver`
/// lines with `127.0.0.0/8` ones skipped (those are `systemd-resolved`'s or
/// some other local stub's own loopback listener, not reachable from the
/// tap, and never the intended upstream).
pub fn host_upstream_resolvers() -> Vec<Ipv4Addr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    parse_resolv_conf(&text)
}

pub fn parse_resolv_conf(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|l| l.strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse::<Ipv4Addr>().ok())
        .filter(|a| !a.octets().starts_with(&[127]))
        .collect()
}

const RESOLVED_DROPIN_DIR: &str = "/etc/systemd/resolved.conf.d";

/// Tier 1: a drop-in adding the tap address to `DNSStubListenerExtra`,
/// reloaded in (SIGHUP) — removed and reloaded out at teardown.
fn resolved_dropin_path(tap: &str) -> std::path::PathBuf {
    Path::new(RESOLVED_DROPIN_DIR).join(format!("paguro-{tap}.conf"))
}

fn reload_resolved() -> Result<(), String> {
    run(Command::new("systemctl").args(["reload-or-restart", "systemd-resolved"]))
}

/// Sets up whichever DNS tier applies, and what the DHCP lease should hand
/// out as option 6: the tap address itself when something local is now
/// forwarding (tiers 1-2), or the host's own upstreams directly (tier 3).
pub fn setup_dns(tap: &str, host_ip: Ipv4Addr) -> Result<(DnsMode, Vec<Ipv4Addr>), String> {
    if resolved_active() {
        let path = resolved_dropin_path(tap);
        std::fs::create_dir_all(RESOLVED_DROPIN_DIR).map_err(|e| e.to_string())?;
        std::fs::write(
            &path,
            format!("[Resolve]\nDNSStubListenerExtra={host_ip}\n"),
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        reload_resolved()?;
        return Ok((DnsMode::ResolvedStub { drop_in: path }, vec![host_ip]));
    }
    if which("dnsmasq") {
        let upstream = host_upstream_resolvers();
        let mut cmd = Command::new("dnsmasq");
        cmd.args([
            "--keep-in-foreground",
            "--no-daemon",
            "--bind-interfaces",
            &format!("--interface={tap}"),
            "--except-interface=lo",
            "--no-resolv",
            "--no-hosts",
            "--port=53",
            &format!("--listen-address={host_ip}"),
        ]);
        for a in &upstream {
            cmd.arg(format!("--server={a}"));
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("dnsmasq: {e}"))?;
        // dnsmasq stays attached to this fd (`--no-daemon`); teardown kills
        // it by pid.
        return Ok((DnsMode::Dnsmasq { pid: child.id() }, vec![host_ip]));
    }
    Ok((DnsMode::Static, host_upstream_resolvers()))
}

pub fn teardown_dns(mode: &DnsMode) {
    match mode {
        DnsMode::ResolvedStub { drop_in } => {
            let _ = std::fs::remove_file(drop_in);
            let _ = reload_resolved();
        }
        DnsMode::Dnsmasq { pid } => {
            // SAFETY: a plain SIGTERM to a pid we spawned ourselves.
            unsafe {
                libc::kill(*pid as libc::pid_t, libc::SIGTERM);
            }
        }
        DnsMode::Static => {}
    }
}

fn which(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// The whole session, as one RAII guard (`mem::HostLimit`'s pattern): built
// once before the boot loop, dropped once at the very end of `launch` —
// however it ends, so a tap, an `inet paguro` table, a flipped
// `ip_forward`, a Docker/firewalld rule or a DNS drop-in never outlives the
// session that made it.
pub struct LanSession {
    tap: String,
    ip_forward_prev: Option<String>,
    dns_mode: Option<DnsMode>,
    /// What the DHCP lease hands out as option 6 (see `setup_dns`).
    pub dns_servers: Vec<Ipv4Addr>,
    coexistence: bool,
    poll_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    poll_handle: Option<std::thread::JoinHandle<()>>,
}

impl LanSession {
    /// Everything that is per-session, not per-boot (a guest reboot gets a
    /// fresh tap and DHCP thread, set up by the caller around each QEMU;
    /// this is the table, the sysctl, the coexistence rules and DNS, which
    /// all outlive any one QEMU process).
    pub fn setup(
        tap: &str,
        wan: &str,
        subnet: &Subnet,
        dmz: bool,
        pins: DmzPins,
        log: &mut Vec<String>,
    ) -> Result<LanSession, String> {
        let prev = set_ip_forward(true)?;
        log.push(format!(
            "net: ip_forward was {prev}, set to 1 for the session (restored after)"
        ));
        let listening = listening_ports();
        let ruleset = nft_ruleset(&NftInputs {
            tap,
            wan,
            subnet,
            dmz,
            pins: &pins,
            listening: &listening,
        });
        nft_apply(&ruleset)?;
        log.push(format!(
            "net: nftables table inet {NFT_TABLE} loaded (tap {tap}, wan {wan}, dmz {})",
            if dmz { "on" } else { "off" }
        ));
        log.extend(coexistence_setup(tap));
        let (dns_mode, dns_servers) = setup_dns(tap, subnet.host)?;
        log.push(format!(
            "net: dns via {dns_mode:?}, servers {dns_servers:?}"
        ));
        let (poll_stop, poll_handle) = if dmz {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop2 = stop.clone();
            let handle = std::thread::spawn(move || {
                while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                    let ports = listening_ports();
                    let _ = nft_update_linux_ports(&ports);
                    for _ in 0..30 {
                        if stop2.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
            });
            (Some(stop), Some(handle))
        } else {
            (None, None)
        };
        Ok(LanSession {
            tap: tap.to_string(),
            ip_forward_prev: Some(prev),
            dns_mode: Some(dns_mode),
            dns_servers,
            coexistence: true,
            poll_stop,
            poll_handle,
        })
    }
}

impl Drop for LanSession {
    fn drop(&mut self) {
        if let Some(stop) = self.poll_stop.take() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(h) = self.poll_handle.take() {
            let _ = h.join();
        }
        if let Some(m) = self.dns_mode.take() {
            teardown_dns(&m);
        }
        if self.coexistence {
            coexistence_teardown(&self.tap);
        }
        let _ = nft_delete_table();
        if let Some(p) = self.ip_forward_prev.take() {
            let _ = restore_ip_forward(&p);
        }
        remove_tap_if_present(&self.tap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_parses_and_derives_router_and_lease() {
        let s = Subnet::parse("198.19.249.0/24").unwrap();
        assert_eq!(s.host, Ipv4Addr::new(198, 19, 249, 1));
        assert_eq!(s.guest, Ipv4Addr::new(198, 19, 249, 2));
        assert_eq!(s.mask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(s.cidr(), "198.19.249.0/24");
        // A host bit set in the input is normalised to the network address.
        let s2 = Subnet::parse("10.0.0.5/24").unwrap();
        assert_eq!(s2.network, Ipv4Addr::new(10, 0, 0, 0));
    }

    #[test]
    fn subnet_rejects_too_narrow() {
        assert!(Subnet::parse("198.19.249.0/31").is_err());
        assert!(Subnet::parse("198.19.249.0/32").is_err());
        assert!(Subnet::parse("not-an-ip/24").is_err());
    }

    #[test]
    fn parse_mac_ok_and_bad() {
        assert_eq!(
            parse_mac("a4:b1:c1:00:11:22").unwrap(),
            [0xa4, 0xb1, 0xc1, 0x00, 0x11, 0x22]
        );
        assert!(parse_mac("a4:b1:c1:00:11").is_err());
        assert!(parse_mac("zz:b1:c1:00:11:22").is_err());
        assert!(parse_mac("").is_err());
    }

    #[test]
    fn parse_pin_ok_and_bad() {
        assert_eq!(parse_pin("8080:linux").unwrap(), (8080, Pin::Linux));
        assert_eq!(parse_pin("3389:windows").unwrap(), (3389, Pin::Windows));
        assert!(parse_pin("abc:linux").is_err());
        assert!(parse_pin("80:elsewhere").is_err());
        assert!(parse_pin("80").is_err());
    }

    #[test]
    fn ss_parses_local_port_from_various_forms() {
        let out = "State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n\
                   LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n\
                   LISTEN 0 4096 *:8080 *:*\n\
                   LISTEN 0 128 [::]:22 [::]:*\n";
        let ports = parse_ss_listen(out);
        assert_eq!(ports, BTreeSet::from([631, 8080, 22]));
    }

    #[test]
    fn never_forward_default_blocks_all_five() {
        let pins = DmzPins::default();
        let listening = BTreeSet::new();
        for p in NEVER_FORWARD {
            assert!(!is_dmz_forwarded(p, &listening, &pins), "port {p}");
        }
    }

    #[test]
    fn pinning_windows_overrides_never_forward() {
        let pins = DmzPins::from_pairs([(3389, Pin::Windows)]);
        assert!(is_dmz_forwarded(3389, &BTreeSet::new(), &pins));
        // The other four are still blocked.
        assert!(!is_dmz_forwarded(22, &BTreeSet::new(), &pins));
        assert!(!is_dmz_forwarded(445, &BTreeSet::new(), &pins));
    }

    #[test]
    fn pinning_linux_blocks_even_if_not_listening() {
        let pins = DmzPins::from_pairs([(9000, Pin::Linux)]);
        assert!(!is_dmz_forwarded(9000, &BTreeSet::new(), &pins));
    }

    #[test]
    fn default_forwards_unlisted_nonspecial_ports() {
        let pins = DmzPins::default();
        let listening = BTreeSet::from([80, 443]);
        assert!(!is_dmz_forwarded(80, &listening, &pins));
        assert!(is_dmz_forwarded(8081, &listening, &pins));
    }

    #[test]
    fn re_pinning_a_port_replaces_the_earlier_side() {
        let pins = DmzPins::from_pairs([(9000, Pin::Windows), (9000, Pin::Linux)]);
        assert!(pins.linux.contains(&9000));
        assert!(!pins.windows.contains(&9000));
    }

    #[test]
    fn effective_never_forward_drops_only_pinned_windows_ports() {
        let pins = DmzPins::from_pairs([(445, Pin::Windows)]);
        let never = effective_never_forward(&pins);
        assert!(!never.contains(&445));
        assert!(never.contains(&22));
        assert!(never.contains(&3389));
    }

    fn subnet() -> Subnet {
        Subnet::parse(DEFAULT_SUBNET).unwrap()
    }

    #[test]
    fn ruleset_without_dmz_has_no_dnat_chain() {
        let s = subnet();
        let listening = BTreeSet::new();
        let pins = DmzPins::default();
        let text = nft_ruleset(&NftInputs {
            tap: "pgtap0",
            wan: "eth0",
            subnet: &s,
            dmz: false,
            pins: &pins,
            listening: &listening,
        });
        assert!(text.contains("table inet paguro"));
        assert!(text.contains("masquerade"));
        assert!(text.contains("iifname \"pgtap0\" accept"));
        assert!(text.contains("oifname \"pgtap0\" accept"));
        assert!(text.contains("ip saddr 198.19.249.0/24 oifname \"eth0\""));
        assert!(!text.contains("dnat"));
        assert!(!text.contains("chain dmz"));
    }

    #[test]
    fn ruleset_with_dmz_never_forwards_the_five_link_ports() {
        let s = subnet();
        let listening = BTreeSet::from([80]);
        let pins = DmzPins::default();
        let text = nft_ruleset(&NftInputs {
            tap: "pgtap0",
            wan: "eth0",
            subnet: &s,
            dmz: true,
            pins: &pins,
            listening: &listening,
        });
        assert!(text.contains("chain dmz"));
        assert!(text.contains("dnat ip to 198.19.249.2"));
        // The never-forward set is present verbatim.
        assert!(text.contains("{ 22, 445, 3389, 5985, 5986 }"));
        // The currently-listening set seeds `linux_ports`.
        assert!(text.contains("set linux_ports { type inet_service; elements = { 80 } }"));
    }

    #[test]
    fn ruleset_empty_pin_sets_omit_the_elements_clause() {
        // `nft -f` rejects `elements = { }` (an empty list) outright; an
        // empty set must be declared without one.
        let s = subnet();
        let listening = BTreeSet::new();
        let pins = DmzPins::default();
        let text = nft_ruleset(&NftInputs {
            tap: "pgtap0",
            wan: "eth0",
            subnet: &s,
            dmz: true,
            pins: &pins,
            listening: &listening,
        });
        assert!(text.contains("set pinned_windows { type inet_service; }"));
        assert!(text.contains("set pinned_linux { type inet_service; }"));
        assert!(!text.contains("elements = {  }"));
        assert!(!text.contains("elements = { }"));
    }

    #[test]
    fn ruleset_pinned_windows_port_is_absent_from_never_forward_set() {
        let s = subnet();
        let listening = BTreeSet::new();
        let pins = DmzPins::from_pairs([(3389, Pin::Windows)]);
        let text = nft_ruleset(&NftInputs {
            tap: "pgtap0",
            wan: "eth0",
            subnet: &s,
            dmz: true,
            pins: &pins,
            listening: &listening,
        });
        assert!(text.contains("set pinned_windows { type inet_service; elements = { 3389 } }"));
        assert!(!text.contains("{ 22, 445, 3389, 5985, 5986 }"));
        assert!(text.contains("{ 22, 445, 5985, 5986 }"));
    }

    #[test]
    fn linux_ports_update_is_a_flush_and_reload() {
        let text = linux_ports_update(&BTreeSet::from([53, 68]));
        assert_eq!(
            text,
            "flush set inet paguro linux_ports\n\
             add element inet paguro linux_ports { 53, 68 }\n"
        );
    }

    #[test]
    fn default_route_parses_dev() {
        assert_eq!(
            parse_default_route_iface("default via 192.168.1.1 dev wlan0 proto dhcp metric 600"),
            Some("wlan0".to_string())
        );
        assert_eq!(parse_default_route_iface(""), None);
        assert_eq!(parse_default_route_iface("default dev"), None);
    }

    #[test]
    fn resolv_conf_skips_loopback_and_keeps_upstreams() {
        let text = "nameserver 127.0.0.53\noptions edns0\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n";
        assert_eq!(
            parse_resolv_conf(text),
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)]
        );
    }
}
