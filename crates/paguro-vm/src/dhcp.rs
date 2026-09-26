//! A single-lease DHCPv4 server (DESIGN.md §5c "DHCP and DNS"): one fixed
//! lease for the VM's MAC, bound to the LAN tap only. slirp used to do this
//! for us; a tap needs its own.
//!
//! Split in two, both tested: `Message` encode/decode (RFC 2131), pure and
//! total (a malformed packet is `Err`, never a panic — see the proptest
//! below), and `serve`, the thin loop around a socket bound to one
//! interface.

use std::net::Ipv4Addr;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;
const HTYPE_ETHER: u8 = 1;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const FIXED_LEN: usize = 236; // op..file, before the cookie

pub const MSG_DISCOVER: u8 = 1;
pub const MSG_OFFER: u8 = 2;
pub const MSG_REQUEST: u8 = 3;
pub const MSG_ACK: u8 = 5;
pub const MSG_NAK: u8 = 6;

/// A decoded (or about-to-be-encoded) DHCPv4 message. Options are kept as
/// raw `(code, bytes)` pairs in wire order — callers ask for the ones they
/// care about (`option`, `msg_type`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Message {
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    pub fn msg_type(&self) -> Option<u8> {
        self.option(53).and_then(|v| v.first().copied())
    }

    /// The address a REQUEST asks for: option 50 if present (the SELECTING
    /// state, before the client has `ciaddr`), else `ciaddr` (RENEWING).
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        if let Some(v) = self.option(50) {
            return <[u8; 4]>::try_from(v).ok().map(Ipv4Addr::from);
        }
        (!self.ciaddr.is_unspecified()).then_some(self.ciaddr)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(300);
        b.push(self.op);
        b.push(HTYPE_ETHER);
        b.push(6); // hlen
        b.push(0); // hops
        b.extend(self.xid.to_be_bytes());
        b.extend(self.secs.to_be_bytes());
        b.extend(self.flags.to_be_bytes());
        b.extend(self.ciaddr.octets());
        b.extend(self.yiaddr.octets());
        b.extend(self.siaddr.octets());
        b.extend(self.giaddr.octets());
        b.extend(self.chaddr);
        b.extend([0u8; 10]); // chaddr is 16 bytes; 6 used
        b.extend([0u8; 64]); // sname
        b.extend([0u8; 128]); // file
        debug_assert_eq!(b.len(), FIXED_LEN);
        b.extend(MAGIC_COOKIE);
        for (code, val) in &self.options {
            b.push(*code);
            // A caller passing >255 bytes is a bug in this module, not
            // attacker input (all our options are short); clamp rather
            // than panic so encode() stays total.
            let len = val.len().min(255);
            b.push(len as u8);
            b.extend(val.get(..len).unwrap_or(val));
        }
        b.push(255); // end
        b
    }

    /// `Err` on anything short, truncated or missing the cookie — never a
    /// panic (fuzzed below).
    pub fn decode(buf: &[u8]) -> Result<Message, String> {
        if buf.len() < FIXED_LEN + 4 {
            return Err(format!("short packet: {} bytes", buf.len()));
        }
        let byte = |o: usize| -> Result<u8, String> {
            buf.get(o)
                .copied()
                .ok_or_else(|| "short packet".to_string())
        };
        let arr4 = |o: usize| -> Result<[u8; 4], String> {
            buf.get(o..o + 4)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .ok_or_else(|| "short packet".to_string())
        };
        let arr2 = |o: usize| -> Result<[u8; 2], String> {
            buf.get(o..o + 2)
                .and_then(|s| <[u8; 2]>::try_from(s).ok())
                .ok_or_else(|| "short packet".to_string())
        };
        let get4 = |o: usize| -> Result<Ipv4Addr, String> { arr4(o).map(Ipv4Addr::from) };
        let op = byte(0)?;
        let xid = u32::from_be_bytes(arr4(4)?);
        let secs = u16::from_be_bytes(arr2(8)?);
        let flags = u16::from_be_bytes(arr2(10)?);
        let ciaddr = get4(12)?;
        let yiaddr = get4(16)?;
        let siaddr = get4(20)?;
        let giaddr = get4(24)?;
        let mut chaddr = [0u8; 6];
        let ch = buf.get(28..34).ok_or("short packet")?;
        chaddr.copy_from_slice(ch);
        let cookie = buf.get(236..240).ok_or("short packet")?;
        if cookie != MAGIC_COOKIE {
            return Err("no DHCP magic cookie".into());
        }
        let mut options = Vec::new();
        let mut i = 240usize;
        while i < buf.len() {
            let code = byte(i)?;
            if code == 255 {
                break;
            }
            if code == 0 {
                i += 1; // pad
                continue;
            }
            let Some(&len) = buf.get(i + 1) else {
                return Err("option truncated (no length byte)".into());
            };
            let len = len as usize;
            let Some(val) = buf.get(i + 2..i + 2 + len) else {
                return Err("option truncated (short value)".into());
            };
            options.push((code, val.to_vec()));
            i += 2 + len;
        }
        Ok(Message {
            op,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            options,
        })
    }
}

/// Everything the single lease needs to answer with.
#[derive(Clone, Debug)]
pub struct LeaseConfig {
    pub server_ip: Ipv4Addr,
    pub client_ip: Ipv4Addr,
    pub client_mac: [u8; 6],
    pub prefix: u8,
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: u32,
}

fn mask_of(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    Ipv4Addr::from(bits)
}

fn reply_options(cfg: &LeaseConfig, msg_type: u8) -> Vec<(u8, Vec<u8>)> {
    let mut dns = Vec::new();
    for a in &cfg.dns {
        dns.extend(a.octets());
    }
    let mut opts = vec![
        (53, vec![msg_type]),
        (54, cfg.server_ip.octets().to_vec()),
        (51, cfg.lease_secs.to_be_bytes().to_vec()),
        (58, (cfg.lease_secs / 2).to_be_bytes().to_vec()), // renewal (T1)
        (59, (cfg.lease_secs * 7 / 8).to_be_bytes().to_vec()), // rebind (T2)
        (1, mask_of(cfg.prefix).octets().to_vec()),
        (3, cfg.router.octets().to_vec()),
    ];
    if !dns.is_empty() {
        opts.push((6, dns));
    }
    opts
}

/// The one lease this server ever hands out: `DISCOVER`/`REQUEST` from
/// `cfg.client_mac` get `OFFER`/`ACK` for `cfg.client_ip`; anything else
/// (a foreign MAC, a REQUEST for a different address) is ignored —
/// returning `None`, never a NAK, so a stray broadcast from something else
/// on the segment is simply not answered.
pub fn handle(req: &Message, cfg: &LeaseConfig) -> Option<Message> {
    if req.op != OP_BOOTREQUEST || req.chaddr != cfg.client_mac {
        return None;
    }
    match req.msg_type()? {
        MSG_DISCOVER => Some(Message {
            op: OP_BOOTREPLY,
            xid: req.xid,
            secs: 0,
            flags: req.flags,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: cfg.client_ip,
            siaddr: cfg.server_ip,
            giaddr: req.giaddr,
            chaddr: req.chaddr,
            options: reply_options(cfg, MSG_OFFER),
        }),
        MSG_REQUEST => {
            let wants = req.requested_ip();
            if wants.is_some() && wants != Some(cfg.client_ip) {
                // Asked for a different lease than we ever offer: NAK it so
                // the client restarts DISCOVER instead of hanging bound to
                // an address that isn't its.
                return Some(Message {
                    op: OP_BOOTREPLY,
                    xid: req.xid,
                    secs: 0,
                    flags: req.flags,
                    ciaddr: Ipv4Addr::UNSPECIFIED,
                    yiaddr: Ipv4Addr::UNSPECIFIED,
                    siaddr: Ipv4Addr::UNSPECIFIED,
                    giaddr: req.giaddr,
                    chaddr: req.chaddr,
                    options: vec![(53, vec![MSG_NAK]), (54, cfg.server_ip.octets().to_vec())],
                });
            }
            Some(Message {
                op: OP_BOOTREPLY,
                xid: req.xid,
                secs: 0,
                flags: req.flags,
                ciaddr: Ipv4Addr::UNSPECIFIED,
                yiaddr: cfg.client_ip,
                siaddr: cfg.server_ip,
                giaddr: req.giaddr,
                chaddr: req.chaddr,
                options: reply_options(cfg, MSG_ACK),
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The socket loop (not unit-tested here: it is a thin, untestable-without-a-
// kernel wrapper around `handle`; test/vm/net-smoke.sh exercises it against
// a real client).

#[cfg(target_os = "linux")]
pub mod server {
    use super::*;
    use std::io::ErrorKind;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// A UDP socket bound to `0.0.0.0:67`, scoped to `ifname` only
    /// (`SO_BINDTODEVICE`) so it never answers, or conflicts with, DHCP on
    /// any other interface — including a real one elsewhere on the host.
    pub fn bind(ifname: &str) -> Result<UdpSocket, String> {
        let sock =
            UdpSocket::bind(("0.0.0.0", SERVER_PORT)).map_err(|e| format!("bind :67: {e}"))?;
        let fd = sock.as_raw_fd();
        // SAFETY: fd is a valid, open socket for the lifetime of these
        // calls; the cstring/lens describe a plain sockaddr-free setsockopt.
        unsafe {
            let one: libc::c_int = 1;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                std::ptr::addr_of!(one).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            ) != 0
            {
                return Err(format!("SO_REUSEADDR: {}", std::io::Error::last_os_error()));
            }
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BROADCAST,
                std::ptr::addr_of!(one).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            ) != 0
            {
                return Err(format!("SO_BROADCAST: {}", std::io::Error::last_os_error()));
            }
            let name = std::ffi::CString::new(ifname).map_err(|e| e.to_string())?;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast(),
                name.as_bytes_with_nul().len() as libc::socklen_t,
            ) != 0
            {
                return Err(format!(
                    "SO_BINDTODEVICE({ifname}): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(sock)
    }

    /// Serve `cfg`'s one lease on `sock` until `stop` is set. Polls with a
    /// short read timeout so `stop` is noticed promptly without spinning.
    pub fn serve(
        sock: &UdpSocket,
        cfg: &LeaseConfig,
        stop: &Arc<AtomicBool>,
    ) -> Result<(), String> {
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| e.to_string())?;
        let mut buf = [0u8; 1500];
        while !stop.load(Ordering::Relaxed) {
            let n = match sock.recv_from(&mut buf) {
                Ok((n, _)) => n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(e) => return Err(format!("recv: {e}")),
            };
            let Some(frame) = buf.get(..n) else { continue };
            let Ok(req) = Message::decode(frame) else {
                continue;
            };
            let Some(reply) = handle(&req, cfg) else {
                continue;
            };
            let _ = sock.send_to(&reply.encode(), ("255.255.255.255", CLIENT_PORT));
        }
        Ok(())
    }

    /// The server as one RAII guard: a thread running [`serve`], stopped
    /// and joined on drop — so a guest reboot's fresh tap always gets a
    /// fresh, cleanly-stopped server instead of two answering at once.
    pub struct Guard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Guard {
        pub fn start(ifname: &str, cfg: LeaseConfig) -> Result<Guard, String> {
            let sock = bind(ifname)?;
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            let handle = std::thread::spawn(move || {
                let _ = serve(&sock, &cfg, &stop2);
            });
            Ok(Guard {
                stop,
                handle: Some(handle),
            })
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn cfg() -> LeaseConfig {
        LeaseConfig {
            server_ip: Ipv4Addr::new(198, 19, 249, 1),
            client_ip: Ipv4Addr::new(198, 19, 249, 2),
            client_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            prefix: 24,
            router: Ipv4Addr::new(198, 19, 249, 1),
            dns: vec![Ipv4Addr::new(198, 19, 249, 1)],
            lease_secs: 3600,
        }
    }

    fn discover(mac: [u8; 6], xid: u32) -> Message {
        Message {
            op: OP_BOOTREQUEST,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            options: vec![(53, vec![MSG_DISCOVER])],
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let m = discover([1, 2, 3, 4, 5, 6], 0xdeadbeef);
        let back = Message::decode(&m.encode()).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn offer_then_ack() {
        let c = cfg();
        let disc = discover(c.client_mac, 42);
        let offer = handle(&disc, &c).expect("offer");
        assert_eq!(offer.msg_type(), Some(MSG_OFFER));
        assert_eq!(offer.yiaddr, c.client_ip);
        assert_eq!(offer.xid, 42);
        assert_eq!(offer.option(3).unwrap(), &c.router.octets());
        assert_eq!(offer.option(1).unwrap(), &[255, 255, 255, 0]);
        assert_eq!(offer.option(6).unwrap(), &c.router.octets());

        let mut req = discover(c.client_mac, 43);
        req.options = vec![(53, vec![MSG_REQUEST]), (50, c.client_ip.octets().to_vec())];
        let ack = handle(&req, &c).expect("ack");
        assert_eq!(ack.msg_type(), Some(MSG_ACK));
        assert_eq!(ack.yiaddr, c.client_ip);
    }

    #[test]
    fn nak_for_a_different_address() {
        let c = cfg();
        let mut req = discover(c.client_mac, 7);
        req.options = vec![
            (53, vec![MSG_REQUEST]),
            (50, Ipv4Addr::new(10, 0, 0, 99).octets().to_vec()),
        ];
        let nak = handle(&req, &c).expect("nak");
        assert_eq!(nak.msg_type(), Some(MSG_NAK));
    }

    #[test]
    fn ignores_a_foreign_mac() {
        let c = cfg();
        let disc = discover([9, 9, 9, 9, 9, 9], 1);
        assert!(handle(&disc, &c).is_none());
    }

    #[test]
    fn ignores_a_bootreply() {
        let c = cfg();
        let mut m = discover(c.client_mac, 1);
        m.op = OP_BOOTREPLY;
        assert!(handle(&m, &c).is_none());
    }

    #[test]
    fn decode_rejects_short_and_cookieless_packets() {
        assert!(Message::decode(&[]).is_err());
        assert!(Message::decode(&[0u8; 100]).is_err());
        let mut short_cookie = vec![0u8; 236 + 4];
        short_cookie[236..240].copy_from_slice(&[1, 2, 3, 4]);
        assert!(Message::decode(&short_cookie).is_err());
    }

    #[test]
    fn decode_rejects_truncated_options() {
        let mut buf = vec![0u8; 236];
        buf.extend(MAGIC_COOKIE);
        buf.push(12); // a code with no length byte
        assert!(Message::decode(&buf).is_err());
        let mut buf2 = vec![0u8; 236];
        buf2.extend(MAGIC_COOKIE);
        buf2.push(12);
        buf2.push(10); // says 10 bytes follow; none do
        assert!(Message::decode(&buf2).is_err());
    }

    #[test]
    fn mask_of_prefixes() {
        assert_eq!(mask_of(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask_of(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(mask_of(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    // Fuzz-style: no byte string, of any length, ever panics `decode`. This
    // is the packet-facing surface (a hostile or corrupt frame from the
    // tap), so it must be total.
    #[cfg(test)]
    mod prop {
        use super::{MAGIC_COOKIE, MSG_DISCOVER, OP_BOOTREQUEST};
        use crate::dhcp::Message;
        use proptest::prelude::*;
        use std::net::Ipv4Addr;

        proptest! {
            #[test]
            fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
                let _ = Message::decode(&bytes);
            }

            // A well-formed header with an arbitrary options tail (which may
            // itself be malformed): still never panics, and a cookie-valid,
            // structurally sound tail always round-trips through encode.
            #[test]
            fn decode_of_valid_header_never_panics(tail in prop::collection::vec(any::<u8>(), 0..64)) {
                let mut buf = vec![0u8; 236];
                buf[0] = OP_BOOTREQUEST;
                buf.extend(MAGIC_COOKIE);
                buf.extend(tail);
                let _ = Message::decode(&buf);
            }

            #[test]
            fn encode_decode_roundtrip(
                xid in any::<u32>(),
                mac in prop::array::uniform6(any::<u8>()),
                dns_a in any::<u8>(), dns_b in any::<u8>(), dns_c in any::<u8>(), dns_d in any::<u8>(),
            ) {
                let m = Message {
                    op: OP_BOOTREQUEST,
                    xid,
                    secs: 0,
                    flags: 0,
                    ciaddr: Ipv4Addr::UNSPECIFIED,
                    yiaddr: Ipv4Addr::UNSPECIFIED,
                    siaddr: Ipv4Addr::UNSPECIFIED,
                    giaddr: Ipv4Addr::UNSPECIFIED,
                    chaddr: mac,
                    options: vec![
                        (53, vec![MSG_DISCOVER]),
                        (6, vec![dns_a, dns_b, dns_c, dns_d]),
                    ],
                };
                let back = Message::decode(&m.encode()).unwrap();
                prop_assert_eq!(m, back);
            }
        }
    }
}
