//! The TPM conversation of the `tpm` and PIN-bypass rungs, and of the
//! provisioning `TPM2_Create` (DESIGN.md §6, "The TPM object itself").
//!
//! Marshalling and response parsing are `paguro_core::tpm`; this module adds
//! the hashing (names, cpHash/rpHash, session HMACs, policy digests), the
//! session salting and parameter encryption, and the command sequences:
//!
//! ```text
//! unseal   CreatePrimary(owner, SRK template)      password session
//!          Load(srk, private, public)              password session
//!          StartAuthSession(tpmKey = srk, policy, salted, AES-128-CFB)
//!          FlushContext(srk)
//!          PolicyPCR(sha256, mask)
//!          [PolicyCounterTimer(Clock < deadline)]  PIN bypass only
//!          PolicyAuthValue
//!          Unseal(item)                            policy session: HMAC keyed by
//!                                                  sessionKey || authValue,
//!                                                  response encrypted
//!          FlushContext × n                        on every path
//!
//! create   CreatePrimary(owner, SRK template)      password session
//!          StartAuthSession(tpmKey = srk, HMAC, salted, AES-128-CFB)
//!          Create(srk, sensitive, template)        HMAC session, sensitive encrypted
//!          FlushContext(srk)
//! ```
//!
//! **Salting** (TPM 2.0 Part 1 §19.6.13, Annex C.6.1): an ephemeral P-256
//! key agrees `Z` with the storage parent's public point (as `CreatePrimary`
//! returned it: on the curve, and the name must hash its public area);
//! `salt = KDFe(Z, "SECRET", Qe.x, Qs.x)` and
//! `sessionKey = KDFa(salt, "ATH", nonceTPM, nonceCaller)`. So the session
//! key never crosses the bus, and with it neither `D` (the Unseal response is
//! encrypted) nor a new object's `authValue` and data (the Create sensitive
//! is). A passive interposer learns nothing; an active one that substitutes
//! the parent's public key is out of scope, as it is for the whole TPM
//! (DESIGN.md §6). The response HMAC is verified before anything is
//! decrypted.

use core::mem::{offset_of, size_of};

use hmac::{Hmac, Mac};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint};
use paguro_core::bytes::Writer;
use paguro_core::tpm::{self as t, AuthCommand, EccPoint, TpmError, sa};
use paguro_crypto::tpm as st;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::platform::{Platform, PlatformError};

/// Submissions of one command while the TPM answers "retry".
const MAX_ATTEMPTS: u32 = 8;

/// Draws of 32 random bytes tried as the ephemeral salting scalar.
const EPHEMERAL_KEY_ATTEMPTS: usize = 4;

/// Capacity of the parameter area a command is marshalled into.
const PARAMS_LEN: usize = 2048;

/// Response header (TPM 2.0 Part 1 §18.3). Layout only: offsets are taken
/// with `offset_of!`, the bytes are never cast to it.
#[allow(dead_code)]
#[repr(C, packed)]
struct ResponseHeader {
    tag: u16,
    response_size: u32,
    response_code: u32,
}
const RESPONSE_CODE: core::ops::Range<usize> =
    field_range(offset_of!(ResponseHeader, response_code), size_of::<u32>());
const _: () = assert!(offset_of!(ResponseHeader, response_code) == 6);
const _: () = assert!(size_of::<ResponseHeader>() == t::HEADER_LEN);

/// `start..start + len`, for a field located with `offset_of!`.
const fn field_range(start: usize, len: usize) -> core::ops::Range<usize> {
    start..start + len
}

/// Size field in front of every TPM2B (TPM 2.0 Part 2 §10.4).
const TPM2B_SIZE_LEN: usize = size_of::<u16>();
/// `TPM_ALG_ID` (TPM 2.0 Part 2 §6.3).
const ALG_ID_LEN: usize = size_of::<u16>();
/// A SHA-256 `TPM2B_NAME` body: `nameAlg || digest` (TPM 2.0 Part 1 §16).
pub const NAME_LEN: usize = ALG_ID_LEN + t::SHA256_LEN;
/// `TPML_PCR_SELECTION` holding one `TPMS_PCR_SELECTION` of three octets
/// (PCRs 0–23), as `write_pcr_selection` emits it (TPM 2.0 Part 2 §10.9.7,
/// §10.6.2). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct PcrSelectionOne {
    count: u32,
    hash: u16,
    sizeof_select: u8,
    pcr_select: [u8; 3],
}
const PCR_SELECTION_LEN: usize = size_of::<PcrSelectionOne>();
const _: () = assert!(PCR_SELECTION_LEN == 10);

/// KDF labels (TPM 2.0 Part 1 §19.6.13, §19.6.8): the ECDH salt and the session key.
const LABEL_SALT: &[u8] = b"SECRET";
const LABEL_SESSION_KEY: &[u8] = b"ATH";

/// The sealed payload: one 32-byte key.
pub const PAYLOAD_LEN: usize = 32;

pub type Digest32 = [u8; t::SHA256_LEN];

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
    /// The storage parent's public point is not on P-256.
    BadParentKey,
    /// The random source gave no usable ephemeral key.
    Rng,
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
        return [0; t::SHA256_LEN];
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
pub fn object_name(public_area: &[u8]) -> [u8; NAME_LEN] {
    let mut n = [0u8; NAME_LEN];
    let (alg, digest) = n.split_at_mut(ALG_ID_LEN);
    alg.copy_from_slice(&t::alg::SHA256.to_be_bytes());
    digest.copy_from_slice(&sha256(&[public_area]));
    n
}

fn pcr_selection_bytes(mask: u32) -> [u8; PCR_SELECTION_LEN] {
    let mut b = [0u8; PCR_SELECTION_LEN];
    let mut w = Writer::new(&mut b);
    // PCR_SELECTION_LEN bytes into PCR_SELECTION_LEN cannot fail.
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
        &[0u8; t::SHA256_LEN],
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
    extend(&[0; t::SHA256_LEN], ini)
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
    params: [u8; PARAMS_LEN],
}

impl<'p, P: Platform> Tpm<'p, P> {
    pub fn new(p: &'p mut P) -> Self {
        Tpm {
            p,
            cmd: [0; t::MAX_COMMAND],
            resp: [0; t::MAX_RESPONSE],
            params: [0; PARAMS_LEN],
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
                .get(RESPONSE_CODE)
                .filter(|_| len >= RESPONSE_CODE.end)
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
        let da = self.properties(
            t::PT_LOCKOUT_COUNTER,
            t::PT_MAX_AUTH_FAIL - t::PT_LOCKOUT_COUNTER + 1,
        )?;
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

    /// The deterministic storage parent: its transient handle, the public
    /// point sessions are salted with, and its name (checked against the
    /// public area it came with).
    pub fn create_primary_srk(&mut self) -> Result<Srk, TpmFail> {
        let pn = t::params_create_primary_srk(&mut self.params)?;
        let len = self.run(
            t::cc::CREATE_PRIMARY,
            &[t::rh::OWNER],
            &[AuthCommand::PASSWORD],
            pn,
        )?;
        let r = t::response(self.resp(len), true, 1)?;
        let handle = r.handle.ok_or(TpmFail::Protocol(TpmError::Truncated))?;
        let srk = t::parse_create_primary(r.params).and_then(|p| {
            let name = object_name(p.public_area);
            if p.name == name {
                Ok(Srk {
                    handle,
                    point: p.point,
                    name,
                })
            } else {
                Err(TpmError::BadValue)
            }
        });
        match srk {
            Ok(s) => Ok(s),
            Err(e) => {
                let _ = self.flush(handle);
                Err(TpmFail::from(e).name_mismatch_if_value())
            }
        }
    }

    pub fn load(&mut self, parent: u32, private: &[u8], public: &[u8]) -> Result<u32, TpmFail> {
        let pn = t::params_load(&mut self.params, private, public)?;
        let len = self.run(t::cc::LOAD, &[parent], &[AuthCommand::PASSWORD], pn)?;
        let r = t::response(self.resp(len), true, 1)?;
        let name = t::parse_load(r.params)?;
        let expect = object_name(public.get(TPM2B_SIZE_LEN..).unwrap_or(&[]));
        if name != expect {
            return Err(TpmFail::NameMismatch);
        }
        r.handle.ok_or(TpmFail::Protocol(TpmError::Truncated))
    }

    /// `TPM2_StartAuthSession(tpmKey = srk, bind = NULL)`, salted by ECDH
    /// with the parent's point, AES-128-CFB, SHA-256.
    fn start_salted(&mut self, srk: &Srk, session_type: u8) -> Result<Session, TpmFail> {
        let qs = AffinePoint::from_coordinates(
            &FieldBytes::from(srk.point.x),
            &FieldBytes::from(srk.point.y),
        );
        let qs: AffinePoint = Option::from(qs).ok_or(TpmFail::BadParentKey)?;
        // An ephemeral scalar in [1, n): retried on the (2^-32) chance that
        // 32 random bytes are not one.
        let mut k = None;
        for _ in 0..EPHEMERAL_KEY_ATTEMPTS {
            let mut raw = [0u8; t::ECC_P256_LEN];
            self.p.random(&mut raw)?;
            let s: Option<NonZeroScalar> = NonZeroScalar::from_repr(FieldBytes::from(raw)).into();
            raw.zeroize();
            if s.is_some() {
                k = s;
                break;
            }
        }
        let mut k: NonZeroScalar = k.ok_or(TpmFail::Rng)?;
        let qe = (ProjectivePoint::GENERATOR * *k).to_affine();
        let mut shared = (ProjectivePoint::from(qs) * *k).to_affine();
        k.zeroize();
        let qe_point = EccPoint {
            x: qe.x().into(),
            y: qe.y().into(),
        };
        let mut z: [u8; t::ECC_P256_LEN] = shared.x().into();
        shared.zeroize();
        let mut salt = st::kdfe(&z, LABEL_SALT, &qe_point.x, &srk.point.x);
        z.zeroize();

        let mut nonce_caller = [0u8; t::SHA256_LEN];
        self.p.random(&mut nonce_caller)?;
        let pn = t::params_start_session(
            &mut self.params,
            &nonce_caller,
            Some(&qe_point),
            session_type,
        )?;
        let r = self.run(
            t::cc::START_AUTH_SESSION,
            &[srk.handle, t::rh::NULL],
            &[],
            pn,
        );
        let len = match r {
            Ok(l) => l,
            Err(e) => {
                salt.zeroize();
                return Err(e);
            }
        };
        let parsed = t::response(self.resp(len), true, 0).and_then(|r| {
            Ok((
                r.handle.ok_or(TpmError::Truncated)?,
                t::parse_start_auth_session(r.params)?,
            ))
        });
        let (handle, nonce_tpm) = match parsed {
            Ok(v) => v,
            Err(e) => {
                salt.zeroize();
                return Err(e.into());
            }
        };
        let mut s = Session {
            handle,
            nonce_tpm: [0; t::MAX_NONCE],
            nonce_len: nonce_tpm.len(),
            key: [0; t::SHA256_LEN],
        };
        s.nonce_tpm
            .get_mut(..s.nonce_len)
            .ok_or(TpmFail::Marshal)?
            .copy_from_slice(nonce_tpm);
        let mut key = [0u8; t::SHA256_LEN];
        st::kdfa(
            &salt,
            LABEL_SESSION_KEY,
            s.nonce_tpm(),
            &nonce_caller,
            &mut key,
        );
        s.key = key;
        key.zeroize();
        salt.zeroize();
        Ok(s)
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
        out: &mut [u8; PAYLOAD_LEN],
    ) -> Result<(), TpmFail> {
        let mut nc_unseal = [0u8; t::SHA256_LEN];
        self.p.random(&mut nc_unseal)?;
        let srk = self.create_primary_srk()?;
        let item = match self.load(srk.handle, private, public) {
            Ok(h) => h,
            Err(e) => {
                let _ = self.flush(srk.handle);
                return Err(e);
            }
        };
        let session = self.start_salted(&srk, t::SE_POLICY);
        let _ = self.flush(srk.handle);
        let mut session = match session {
            Ok(s) => s,
            Err(e) => {
                let _ = self.flush(item);
                return Err(e);
            }
        };
        let r = self.policy_and_unseal(
            &session, item, public, pcr_mask, deadline, auth, &nc_unseal, out,
        );
        if r.is_err() {
            let _ = self.flush(session.handle);
        }
        session.key.zeroize();
        let _ = self.flush(item);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn policy_and_unseal(
        &mut self,
        session: &Session,
        item: u32,
        public: &[u8],
        pcr_mask: u32,
        deadline: Option<u64>,
        auth: &[u8],
        nonce_caller: &[u8; t::SHA256_LEN],
        out: &mut [u8; PAYLOAD_LEN],
    ) -> Result<(), TpmFail> {
        let pn = t::params_policy_pcr(&mut self.params, t::alg::SHA256, pcr_mask)?;
        self.policy(t::cc::POLICY_PCR, session.handle, pn)?;
        if let Some(d) = deadline {
            let pn = t::params_policy_clock_before(&mut self.params, d)?;
            self.policy(t::cc::POLICY_COUNTER_TIMER, session.handle, pn)?;
        }
        self.policy(t::cc::POLICY_AUTH_VALUE, session.handle, 0)?;

        // Unseal: HMAC over cpHash keyed by sessionKey || authValue (the
        // policy has PolicyAuthValue); the response's data encrypted.
        let name = object_name(public.get(TPM2B_SIZE_LEN..).unwrap_or(&[]));
        let cp = sha256(&[&t::cc::UNSEAL.to_be_bytes(), &name]);
        let mut key = SessionValue::new(&session.key, trim_zeros(auth));
        // continueSession clear: the TPM flushes the session on success.
        let attrs = sa::ENCRYPT;
        let hmac = hmac256(
            key.get(),
            &[&cp, nonce_caller, session.nonce_tpm(), &[attrs]],
        );
        let s = AuthCommand {
            handle: session.handle,
            nonce: nonce_caller,
            attributes: attrs,
            hmac: &hmac,
        };
        let r = self.run(t::cc::UNSEAL, &[item], &[s], 0).and_then(|len| {
            let r = t::response(self.resp(len), false, 1)?;
            let ra = r.sessions.first().copied().unwrap_or_default();
            let rp = sha256(&[
                &t::rc::SUCCESS.to_be_bytes(),
                &t::cc::UNSEAL.to_be_bytes(),
                r.params,
            ]);
            let want = hmac256(key.get(), &[&rp, ra.nonce, nonce_caller, &[ra.attributes]]);
            if !ct_eq(&want, ra.hmac) {
                return Err(TpmFail::ResponseAuth);
            }
            let data = t::parse_unseal(r.params)?;
            if data.len() != PAYLOAD_LEN {
                return Err(TpmFail::BadPayload);
            }
            let mut kiv = st::cfb_key_iv(key.get(), ra.nonce, nonce_caller);
            out.copy_from_slice(data);
            st::cfb_decrypt(&kiv, out);
            kiv.zeroize();
            Ok(())
        });
        key.zeroize();
        self.resp.zeroize();
        r
    }

    /// `TPM2_Create` of a sealed object under the SRK (provisioning boot,
    /// and the Windows tool's PIN bypass).
    pub fn create_sealed(
        &mut self,
        auth: &[u8; PAYLOAD_LEN],
        data: &[u8; PAYLOAD_LEN],
        policy: &Digest32,
        out: &mut CreatedObject,
    ) -> Result<(), TpmFail> {
        let srk = self.create_primary_srk()?;
        let r = match self.start_salted(&srk, t::SE_HMAC) {
            Ok(mut session) => {
                let r = self.create_under(&srk, &session, auth, data, policy, out);
                if r.is_err() {
                    let _ = self.flush(session.handle);
                }
                session.key.zeroize();
                r
            }
            Err(e) => Err(e),
        };
        let _ = self.flush(srk.handle);
        self.params.zeroize();
        self.cmd.zeroize();
        r
    }

    fn create_under(
        &mut self,
        srk: &Srk,
        session: &Session,
        auth: &[u8; PAYLOAD_LEN],
        data: &[u8; PAYLOAD_LEN],
        policy: &Digest32,
        out: &mut CreatedObject,
    ) -> Result<(), TpmFail> {
        let mut nonce_caller = [0u8; t::SHA256_LEN];
        self.p.random(&mut nonce_caller)?;
        let pn = t::params_create_sealed(&mut self.params, auth, data, policy)?;
        // The SRK's authValue is empty: the session value is the key alone.
        let key = session.key;
        // Encrypt the first parameter's buffer: TPM2B_SENSITIVE_CREATE after
        // its size (Part 1 §21.1).
        let first = self
            .params
            .get(..TPM2B_SIZE_LEN)
            .and_then(|b| <[u8; TPM2B_SIZE_LEN]>::try_from(b).ok())
            .map(|b| usize::from(u16::from_be_bytes(b)))
            .ok_or(TpmFail::Marshal)?;
        let mut kiv = st::cfb_key_iv(&key, &nonce_caller, session.nonce_tpm());
        st::cfb_encrypt(
            &kiv,
            self.params
                .get_mut(TPM2B_SIZE_LEN..TPM2B_SIZE_LEN + first)
                .ok_or(TpmFail::Marshal)?,
        );
        kiv.zeroize();
        let params = self.params.get(..pn).ok_or(TpmFail::Marshal)?;
        let cp = sha256(&[&t::cc::CREATE.to_be_bytes(), &srk.name, params]);
        let attrs = sa::DECRYPT;
        let hmac = hmac256(&key, &[&cp, &nonce_caller, session.nonce_tpm(), &[attrs]]);
        let s = AuthCommand {
            handle: session.handle,
            nonce: &nonce_caller,
            attributes: attrs,
            hmac: &hmac,
        };
        let len = self.run(t::cc::CREATE, &[srk.handle], &[s], pn)?;
        let r = t::response(self.resp(len), false, 1)?;
        let ra = r.sessions.first().copied().unwrap_or_default();
        let rp = sha256(&[
            &t::rc::SUCCESS.to_be_bytes(),
            &t::cc::CREATE.to_be_bytes(),
            r.params,
        ]);
        let want = hmac256(&key, &[&rp, ra.nonce, &nonce_caller, &[ra.attributes]]);
        if !ct_eq(&want, ra.hmac) {
            return Err(TpmFail::ResponseAuth);
        }
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

/// The storage parent, as `CreatePrimary` returned it.
#[derive(Clone, Copy, Debug)]
pub struct Srk {
    pub handle: u32,
    pub point: EccPoint,
    pub name: [u8; NAME_LEN],
}

/// A salted session: its handle, the TPM's last nonce and the session key.
struct Session {
    handle: u32,
    nonce_tpm: [u8; t::MAX_NONCE],
    nonce_len: usize,
    key: [u8; t::SHA256_LEN],
}

impl Session {
    fn nonce_tpm(&self) -> &[u8] {
        self.nonce_tpm.get(..self.nonce_len).unwrap_or(&[])
    }
}

/// `sessionKey || authValue`: the HMAC key of an authorisation, and the
/// session value parameter encryption derives its key from.
struct SessionValue {
    b: [u8; t::SHA256_LEN + t::MAX_NONCE],
    n: usize,
}

impl SessionValue {
    fn new(key: &[u8; t::SHA256_LEN], auth: &[u8]) -> Self {
        let mut v = SessionValue {
            b: [0; t::SHA256_LEN + t::MAX_NONCE],
            n: 0,
        };
        let auth = auth.get(..auth.len().min(t::MAX_NONCE)).unwrap_or(&[]);
        let n = t::SHA256_LEN + auth.len();
        if let Some(d) = v.b.get_mut(..n) {
            let (a, b) = d.split_at_mut(t::SHA256_LEN);
            a.copy_from_slice(key);
            b.copy_from_slice(auth);
            v.n = n;
        }
        v
    }
    fn get(&self) -> &[u8] {
        self.b.get(..self.n).unwrap_or(&[])
    }
    fn zeroize(&mut self) {
        self.b.zeroize();
    }
}

impl TpmFail {
    /// A primary whose name does not hash its public area is a lying TPM.
    fn name_mismatch_if_value(self) -> Self {
        match self {
            TpmFail::Protocol(TpmError::BadValue) => TpmFail::NameMismatch,
            other => other,
        }
    }
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
