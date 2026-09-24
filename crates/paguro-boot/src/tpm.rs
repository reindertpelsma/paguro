//! The TPM conversation of the `tpm` and PIN-bypass rungs, and of the
//! provisioning `TPM2_Create` (DESIGN.md §6, "The TPM object itself").
//!
//! Marshalling and response parsing are `paguro_core::tpm`; this module adds
//! the hashing (names, cpHash/rpHash, session HMACs, policy digests) and the
//! command sequences:
//!
//! ```text
//! unseal   CreatePrimary(owner, SRK template)      password session
//!          Load(srk, private, public)              password session
//!          StartAuthSession(policy, unsalted, unbound, SHA-256)
//!          PolicyPCR(sha256, mask)
//!          [PolicyCounterTimer(Clock < deadline)]  PIN bypass only
//!          PolicyAuthValue
//!          Unseal(item)                            policy session, HMAC keyed by authValue
//!          FlushContext × n                        on every path
//! ```
//!
//! The session is an HMAC session, so `auth` never crosses the bus in clear;
//! the response HMAC is verified too. Parameter encryption is not implemented
//! yet (it needs AES-CFB in the loader) — the unsealed `D` is useless without
//! `B` and the passphrase, which never cross.

use hmac::{Hmac, Mac};
use paguro_core::bytes::Writer;
use paguro_core::tpm::{self as t, AuthCommand, TpmError};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::platform::{Platform, PlatformError};

/// Submissions of one command while the TPM answers "retry".
const MAX_ATTEMPTS: u32 = 8;

pub type Digest32 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmFail {
    Platform(PlatformError),
    /// A malformed response or a failed response HMAC.
    Protocol(TpmError),
    /// An error response code.
    Rc(u32),
    /// Our own marshalling ran out of buffer (a bug, not input).
    Marshal,
    /// The response HMAC did not verify.
    ResponseAuth,
    /// The loaded object's name differs from the one computed from its public area.
    NameMismatch,
    /// Unsealed data is not 32 bytes.
    BadPayload,
}

impl From<PlatformError> for TpmFail {
    fn from(e: PlatformError) -> Self {
        TpmFail::Platform(e)
    }
}

impl From<TpmError> for TpmFail {
    fn from(e: TpmError) -> Self {
        match e {
            TpmError::Rc(rc) => TpmFail::Rc(rc),
            other => TpmFail::Protocol(other),
        }
    }
}

impl From<paguro_core::bytes::Full> for TpmFail {
    fn from(_: paguro_core::bytes::Full) -> Self {
        TpmFail::Marshal
    }
}

impl TpmFail {
    pub fn class(&self) -> t::RcClass {
        match self {
            TpmFail::Rc(rc) => t::classify(*rc),
            _ => t::RcClass::Other,
        }
    }
}

fn sha256(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> Digest32 {
    // HMAC accepts keys of any length.
    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        return [0; 32];
    };
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// TPM2B values are compared and used as HMAC keys with trailing zero octets
/// removed (TPM 2.0 Part 1, §19.6.4.3).
fn trim_zeros(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    b.get(..end).unwrap_or(&[])
}

/// `TPM_ALG_SHA256 || SHA-256(publicArea)`.
pub fn object_name(public_area: &[u8]) -> [u8; 34] {
    let mut n = [0u8; 34];
    let (alg, digest) = n.split_at_mut(2);
    alg.copy_from_slice(&t::alg::SHA256.to_be_bytes());
    digest.copy_from_slice(&sha256(&[public_area]));
    n
}

fn pcr_selection_bytes(mask: u32) -> [u8; 10] {
    let mut b = [0u8; 10];
    let mut w = Writer::new(&mut b);
    // 10 bytes into 10 cannot fail.
    let _ = t::write_pcr_selection(&mut w, t::alg::SHA256, mask);
    b
}

/// The policy a seal's object carries, computed offline — exactly what the
/// TPM accumulates for the unseal sequence above.
///
/// `pcr_values`: SHA-256 values of the PCRs in `mask`, ascending.
pub fn policy_digest(mask: u32, pcr_values: &[Digest32], deadline: Option<u64>) -> Digest32 {
    let mut pcr_digest = Sha256::new();
    for v in pcr_values {
        pcr_digest.update(v);
    }
    let pcr_digest: Digest32 = pcr_digest.finalize().into();
    let mut d = sha256(&[
        &[0u8; 32],
        &t::cc::POLICY_PCR.to_be_bytes(),
        &pcr_selection_bytes(mask),
        &pcr_digest,
    ]);
    if let Some(deadline) = deadline {
        let args = sha256(&[
            &deadline.to_be_bytes(),
            &t::TIME_INFO_CLOCK_OFFSET.to_be_bytes(),
            &t::EO_UNSIGNED_LT.to_be_bytes(),
        ]);
        d = sha256(&[&d, &t::cc::POLICY_COUNTER_TIMER.to_be_bytes(), &args]);
    }
    sha256(&[&d, &t::cc::POLICY_AUTH_VALUE.to_be_bytes()])
}

/// SHA-256 PCR extend: `new = H(old || H(data))`.
pub fn extend(old: &Digest32, data: &[u8]) -> Digest32 {
    sha256(&[old, &sha256(&[data])])
}

/// PCR 12 after the load taint, from zero (INTERFACES.md §6).
pub fn pcr12_after_load_taint(ini: &[u8]) -> Digest32 {
    extend(&[0; 32], ini)
}

pub const MAX_OBJECT: usize = 1024;

/// A sealed object as returned by `TPM2_Create`, whole TPM2B values.
pub struct CreatedObject {
    pub private: [u8; MAX_OBJECT],
    pub private_len: usize,
    pub public: [u8; MAX_OBJECT],
    pub public_len: usize,
}

impl CreatedObject {
    pub const fn new() -> Self {
        CreatedObject {
            private: [0; MAX_OBJECT],
            private_len: 0,
            public: [0; MAX_OBJECT],
            public_len: 0,
        }
    }
    pub fn private(&self) -> &[u8] {
        self.private.get(..self.private_len).unwrap_or(&[])
    }
    pub fn public(&self) -> &[u8] {
        self.public.get(..self.public_len).unwrap_or(&[])
    }
}

impl Default for CreatedObject {
    fn default() -> Self {
        Self::new()
    }
}

/// Dictionary-attack state for the unlock list's "N TPM attempts left".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lockout {
    pub in_lockout: bool,
    pub counter: u32,
    pub max: u32,
}

impl Lockout {
    pub const fn attempts_left(&self) -> u32 {
        if self.in_lockout {
            0
        } else {
            self.max.saturating_sub(self.counter)
        }
    }
}

/// A TPM client over [`Platform::tpm_submit`].
pub struct Tpm<'p, P: Platform> {
    p: &'p mut P,
    cmd: [u8; t::MAX_COMMAND],
    resp: [u8; t::MAX_RESPONSE],
    params: [u8; 2048],
}

impl<'p, P: Platform> Tpm<'p, P> {
    pub fn new(p: &'p mut P) -> Self {
        Tpm {
            p,
            cmd: [0; t::MAX_COMMAND],
            resp: [0; t::MAX_RESPONSE],
            params: [0; 2048],
        }
    }

    /// Send the command in `self.cmd[..n]`; returns the response length.
    ///
    /// A `TPM_RC_RETRY`/`YIELDED`/`TESTING` response means the command was not
    /// executed and must be resubmitted unchanged (TPM 2.0 Part 1, §12.2.3):
    /// the reference implementation answers the first DA-protected
    /// authorisation after Startup with `TPM_RC_RETRY` while it records
    /// `daUsed` in NV. The identical bytes are sent again, a bounded number of
    /// times; the last response is returned either way.
    fn transact(&mut self, n: usize) -> Result<usize, TpmFail> {
        let cmd = self.cmd.get(..n).ok_or(TpmFail::Marshal)?;
        let mut attempts = 0;
        loop {
            let len = self.p.tpm_submit(cmd, &mut self.resp)?;
            if len > self.resp.len() {
                return Err(TpmFail::Protocol(TpmError::TooLarge));
            }
            attempts += 1;
            let code = self
                .resp
                .get(6..10)
                .filter(|_| len >= 10)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_be_bytes);
            match code {
                Some(rc) if attempts < MAX_ATTEMPTS && t::classify(rc) == t::RcClass::Retry => {}
                _ => return Ok(len),
            }
        }
    }

    /// Build + send a command whose params are `self.params[..pn]`.
    fn run(
        &mut self,
        code: u32,
        handles: &[u32],
        sessions: &[AuthCommand<'_>],
        pn: usize,
    ) -> Result<usize, TpmFail> {
        let params = self.params.get(..pn).ok_or(TpmFail::Marshal)?;
        let n = t::command(&mut self.cmd, code, handles, sessions, params)?;
        self.transact(n)
    }

    fn resp(&self, len: usize) -> &[u8] {
        self.resp.get(..len).unwrap_or(&[])
    }

    pub fn pcr_read(&mut self, mask: u32) -> Result<t::PcrValues, TpmFail> {
        let pn = t::params_pcr_read(&mut self.params, mask)?;
        let len = self.run(t::cc::PCR_READ, &[], &[], pn)?;
        let r = t::response(self.resp(len), false, 0)?;
        Ok(t::parse_pcr_read(r.params)?)
    }

    pub fn read_clock(&mut self) -> Result<t::TimeInfo, TpmFail> {
        let len = self.run(t::cc::READ_CLOCK, &[], &[], 0)?;
        let r = t::response(self.resp(len), false, 0)?;
        Ok(t::parse_read_clock(r.params)?)
    }

    fn properties(&mut self, first: u32, count: u32) -> Result<t::Properties, TpmFail> {
        let pn = t::params_get_properties(&mut self.params, first, count)?;
        let len = self.run(t::cc::GET_CAPABILITY, &[], &[], pn)?;
        let r = t::response(self.resp(len), false, 0)?;
        Ok(t::parse_get_properties(r.params)?)
    }

    pub fn lockout(&mut self) -> Result<Lockout, TpmFail> {
        let perm = self.properties(t::PT_PERMANENT, 1)?;
        let da = self.properties(t::PT_LOCKOUT_COUNTER, 2)?;
        Ok(Lockout {
            in_lockout: perm.get(t::PT_PERMANENT).unwrap_or(0) & t::PERMANENT_IN_LOCKOUT != 0,
            counter: da.get(t::PT_LOCKOUT_COUNTER).unwrap_or(0),
            max: da.get(t::PT_MAX_AUTH_FAIL).unwrap_or(0),
        })
    }

    pub fn flush(&mut self, handle: u32) -> Result<(), TpmFail> {
        let pn = t::params_flush(&mut self.params, handle)?;
        let len = self.run(t::cc::FLUSH_CONTEXT, &[], &[], pn)?;
        let r = t::response(self.resp(len), false, 0)?;
        Ok(t::parse_empty(r.params)?)
    }

    /// The deterministic storage parent. Returns its transient handle.
    pub fn create_primary_srk(&mut self) -> Result<u32, TpmFail> {
        let pn = t::params_create_primary_srk(&mut self.params)?;
        let len = self.run(
            t::cc::CREATE_PRIMARY,
            &[t::rh::OWNER],
            &[AuthCommand::PASSWORD],
            pn,
        )?;
        let r = t::response(self.resp(len), true, 1)?;
        t::parse_create_primary(r.params)?;
        r.handle.ok_or(TpmFail::Protocol(TpmError::Truncated))
    }

    pub fn load(&mut self, parent: u32, private: &[u8], public: &[u8]) -> Result<u32, TpmFail> {
        let pn = t::params_load(&mut self.params, private, public)?;
        let len = self.run(t::cc::LOAD, &[parent], &[AuthCommand::PASSWORD], pn)?;
        let r = t::response(self.resp(len), true, 1)?;
        let name = t::parse_load(r.params)?;
        let expect = object_name(public.get(2..).unwrap_or(&[]));
        if name != expect {
            return Err(TpmFail::NameMismatch);
        }
        r.handle.ok_or(TpmFail::Protocol(TpmError::Truncated))
    }

    /// Returns `(session handle, nonceTPM)`.
    fn start_policy_session(
        &mut self,
        nonce_caller: &[u8; 32],
    ) -> Result<(u32, [u8; 32], usize), TpmFail> {
        let pn = t::params_start_policy_session(&mut self.params, nonce_caller)?;
        let len = self.run(
            t::cc::START_AUTH_SESSION,
            &[t::rh::NULL, t::rh::NULL],
            &[],
            pn,
        )?;
        let r = t::response(self.resp(len), true, 0)?;
        let nonce = t::parse_start_auth_session(r.params)?;
        let mut out = [0u8; 32];
        let n = nonce.len().min(32);
        out.get_mut(..n)
            .ok_or(TpmFail::Marshal)?
            .copy_from_slice(nonce.get(..n).ok_or(TpmFail::Marshal)?);
        Ok((
            r.handle.ok_or(TpmFail::Protocol(TpmError::Truncated))?,
            out,
            n,
        ))
    }

    fn policy(&mut self, code: u32, session: u32, pn: usize) -> Result<(), TpmFail> {
        let len = self.run(code, &[session], &[], pn)?;
        let r = t::response(self.resp(len), false, 0)?;
        Ok(t::parse_empty(r.params)?)
    }

    /// The full unseal sequence. `deadline` selects the PIN-bypass policy.
    /// Transient objects are flushed on every path.
    pub fn unseal(
        &mut self,
        private: &[u8],
        public: &[u8],
        pcr_mask: u32,
        deadline: Option<u64>,
        auth: &[u8],
        out: &mut [u8; 32],
    ) -> Result<(), TpmFail> {
        let mut nonces = [0u8; 64];
        self.p.random(&mut nonces)?;
        let srk = self.create_primary_srk()?;
        let item = match self.load(srk, private, public) {
            Ok(h) => h,
            Err(e) => {
                let _ = self.flush(srk);
                return Err(e);
            }
        };
        let _ = self.flush(srk);
        let (n1, n2) = nonces.split_at(32);
        let (nc_start, nc_unseal) = (arr32(n1), arr32(n2));
        let (session, nonce_tpm, ntl) = match self.start_policy_session(&nc_start) {
            Ok(s) => s,
            Err(e) => {
                let _ = self.flush(item);
                return Err(e);
            }
        };
        let r = self.policy_and_unseal(
            session,
            item,
            public,
            pcr_mask,
            deadline,
            auth,
            nonce_tpm.get(..ntl).unwrap_or(&[]),
            &nc_unseal,
            out,
        );
        if r.is_err() {
            let _ = self.flush(session);
        }
        let _ = self.flush(item);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn policy_and_unseal(
        &mut self,
        session: u32,
        item: u32,
        public: &[u8],
        pcr_mask: u32,
        deadline: Option<u64>,
        auth: &[u8],
        nonce_tpm: &[u8],
        nonce_caller: &[u8; 32],
        out: &mut [u8; 32],
    ) -> Result<(), TpmFail> {
        let pn = t::params_policy_pcr(&mut self.params, t::alg::SHA256, pcr_mask)?;
        self.policy(t::cc::POLICY_PCR, session, pn)?;
        if let Some(d) = deadline {
            let pn = t::params_policy_clock_before(&mut self.params, d)?;
            self.policy(t::cc::POLICY_COUNTER_TIMER, session, pn)?;
        }
        self.policy(t::cc::POLICY_AUTH_VALUE, session, 0)?;

        // Unseal with an HMAC over cpHash, keyed by (empty sessionKey ||) authValue.
        let name = object_name(public.get(2..).unwrap_or(&[]));
        let cp = sha256(&[&t::cc::UNSEAL.to_be_bytes(), &name]);
        let key = trim_zeros(auth);
        let attrs = 0u8; // continueSession clear: the TPM flushes the session
        let hmac = hmac256(key, &[&cp, nonce_caller, nonce_tpm, &[attrs]]);
        let s = AuthCommand {
            handle: session,
            nonce: nonce_caller,
            attributes: attrs,
            hmac: &hmac,
        };
        let len = self.run(t::cc::UNSEAL, &[item], &[s], 0)?;
        let r = t::response(self.resp(len), false, 1)?;
        let ra = r.sessions.first().copied().unwrap_or_default();
        let rp = sha256(&[&0u32.to_be_bytes(), &t::cc::UNSEAL.to_be_bytes(), r.params]);
        let want = hmac256(key, &[&rp, ra.nonce, nonce_caller, &[ra.attributes]]);
        if !ct_eq(&want, ra.hmac) {
            return Err(TpmFail::ResponseAuth);
        }
        let data = t::parse_unseal(r.params)?;
        if data.len() != 32 {
            return Err(TpmFail::BadPayload);
        }
        out.copy_from_slice(data);
        self.resp.zeroize();
        Ok(())
    }

    /// `TPM2_Create` of a sealed object under the SRK (provisioning boot).
    pub fn create_sealed(
        &mut self,
        auth: &[u8; 32],
        data: &[u8; 32],
        policy: &Digest32,
        out: &mut CreatedObject,
    ) -> Result<(), TpmFail> {
        let srk = self.create_primary_srk()?;
        let r = self.create_under(srk, auth, data, policy, out);
        let _ = self.flush(srk);
        self.params.zeroize();
        self.cmd.zeroize();
        r
    }

    fn create_under(
        &mut self,
        srk: u32,
        auth: &[u8; 32],
        data: &[u8; 32],
        policy: &Digest32,
        out: &mut CreatedObject,
    ) -> Result<(), TpmFail> {
        let pn = t::params_create_sealed(&mut self.params, auth, data, policy)?;
        let len = self.run(t::cc::CREATE, &[srk], &[AuthCommand::PASSWORD], pn)?;
        let r = t::response(self.resp(len), false, 1)?;
        let c = t::parse_create(r.params)?;
        let pl = c.private.len();
        let ul = c.public.len();
        out.private
            .get_mut(..pl)
            .ok_or(TpmFail::Protocol(TpmError::Oversized))?
            .copy_from_slice(c.private);
        out.public
            .get_mut(..ul)
            .ok_or(TpmFail::Protocol(TpmError::Oversized))?
            .copy_from_slice(c.public);
        out.private_len = pl;
        out.public_len = ul;
        Ok(())
    }
}

fn arr32(b: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (d, s) in o.iter_mut().zip(b) {
        *d = *s;
    }
    o
}

/// Length-checked constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_trailing_zeros_only() {
        assert_eq!(trim_zeros(&[0, 1, 0, 0]), &[0, 1]);
        assert_eq!(trim_zeros(&[0, 0]), &[] as &[u8]);
        assert_eq!(trim_zeros(&[]), &[] as &[u8]);
    }

    #[test]
    fn policy_depends_on_every_input() {
        let v = [[1u8; 32]; 5];
        let a = policy_digest(0x1095, &v, None);
        assert_ne!(a, policy_digest(0x1095, &v, Some(5)));
        assert_ne!(a, policy_digest(0x1097, &v, None));
        let mut w = v;
        w[4][0] = 2;
        assert_ne!(a, policy_digest(0x1095, &w, None));
        assert_ne!(
            policy_digest(0x1095, &v, Some(5)),
            policy_digest(0x1095, &v, Some(6))
        );
    }

    #[test]
    fn extend_matches_definition() {
        let h = sha256(&[b"x"]);
        assert_eq!(extend(&[0; 32], b"x"), sha256(&[&[0u8; 32], &h]));
        assert_eq!(pcr12_after_load_taint(b"x"), extend(&[0; 32], b"x"));
    }

    #[test]
    fn ct_eq_and_lockout() {
        assert!(ct_eq(b"ab", b"ab"));
        assert!(!ct_eq(b"ab", b"ac"));
        assert!(!ct_eq(b"ab", b"a"));
        let l = Lockout {
            in_lockout: false,
            counter: 2,
            max: 5,
        };
        assert_eq!(l.attempts_left(), 3);
        assert_eq!(
            Lockout {
                in_lockout: true,
                ..l
            }
            .attempts_left(),
            0
        );
        assert_eq!(Lockout { counter: 9, ..l }.attempts_left(), 0);
    }

    #[test]
    fn fail_classification() {
        assert_eq!(TpmFail::Rc(t::rc::LOCKOUT).class(), t::RcClass::Lockout);
        assert_eq!(TpmFail::Marshal.class(), t::RcClass::Other);
        assert_eq!(TpmFail::from(TpmError::Rc(5)), TpmFail::Rc(5));
        assert_eq!(
            TpmFail::from(TpmError::Trailing),
            TpmFail::Protocol(TpmError::Trailing)
        );
        assert_eq!(object_name(b"")[..2], [0, 0x0b]);
    }
}
