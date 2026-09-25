//! TPM 2.0 command marshalling and response parsing (TPM 2.0 Library Part 3),
//! for exactly the commands the loader sends.
//!
//! Commands are built into caller buffers; nothing allocates. Responses are
//! **external data** — a TPM, a firmware TCG2 implementation, or a bus
//! interposer produces them — so parsing is hardened like every other parser:
//! the response is capped at [`MAX_RESPONSE`], its header size must equal the
//! bytes received, every TPM2B/list size is bounded before use, and trailing
//! bytes anywhere are an error.
//!
//! Hashing (cpHash, policy digests, session HMACs), key agreement and
//! parameter encryption live in `paguro-boot` and `paguro-crypto`; this
//! module stays dependency-free.

use crate::bytes::{Full, Reader, Short, Writer};

pub const MAX_COMMAND: usize = 4096;
pub const MAX_RESPONSE: usize = 4096;
pub const HEADER_LEN: usize = 10;
pub const SHA256_LEN: usize = 32;
/// PCR_Read returns at most 8 digests per call (TPM 2.0 Part 2, `TPML_DIGEST`).
pub const MAX_PCR_DIGESTS: usize = 8;
pub const MAX_NONCE: usize = 64;
/// `TPM2B_SENSITIVE_DATA` payload cap (`MAX_SYM_DATA`).
pub const MAX_SENSITIVE_DATA: usize = 128;
pub const MAX_SESSIONS: usize = 3;
pub const MAX_PROPERTIES: usize = 64;

pub const ST_NO_SESSIONS: u16 = 0x8001;
pub const ST_SESSIONS: u16 = 0x8002;
pub const ST_CREATION: u16 = 0x8021;

pub mod cc {
    pub const CREATE_PRIMARY: u32 = 0x131;
    pub const CREATE: u32 = 0x153;
    pub const LOAD: u32 = 0x157;
    pub const UNSEAL: u32 = 0x15E;
    pub const FLUSH_CONTEXT: u32 = 0x165;
    pub const POLICY_AUTH_VALUE: u32 = 0x16B;
    pub const POLICY_COUNTER_TIMER: u32 = 0x16D;
    pub const START_AUTH_SESSION: u32 = 0x176;
    pub const GET_CAPABILITY: u32 = 0x17A;
    pub const PCR_READ: u32 = 0x17E;
    pub const POLICY_PCR: u32 = 0x17F;
    pub const READ_CLOCK: u32 = 0x181;
}

pub mod alg {
    pub const AES: u16 = 0x0006;
    pub const KEYEDHASH: u16 = 0x0008;
    pub const SHA256: u16 = 0x000B;
    pub const NULL: u16 = 0x0010;
    pub const ECC: u16 = 0x0023;
    pub const CFB: u16 = 0x0043;
    pub const ECC_NIST_P256: u16 = 0x0003;
}

pub mod rh {
    pub const OWNER: u32 = 0x4000_0001;
    pub const NULL: u32 = 0x4000_0007;
    /// `TPM_RS_PW`: the password session.
    pub const PW: u32 = 0x4000_0009;
}

pub mod attr {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const NO_DA: u32 = 1 << 10;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    /// The storage parent (TCG provisioning guidance SRK template).
    pub const SRK: u32 = FIXED_TPM
        | FIXED_PARENT
        | SENSITIVE_DATA_ORIGIN
        | USER_WITH_AUTH
        | NO_DA
        | RESTRICTED
        | DECRYPT;
    /// The sealed object (INTERFACES.md §4): `userWithAuth` and `noDA` clear,
    /// so only the policy authorises and dictionary-attack lockout applies.
    pub const SEALED: u32 = FIXED_TPM | FIXED_PARENT;
}

/// Session attributes.
pub mod sa {
    pub const CONTINUE_SESSION: u8 = 1;
    /// The first command parameter is encrypted (TPM 2.0 Part 1 §21).
    pub const DECRYPT: u8 = 0x20;
    /// The first response parameter is encrypted.
    pub const ENCRYPT: u8 = 0x40;
}

pub const SE_HMAC: u8 = 0x00;
pub const SE_POLICY: u8 = 0x01;
/// Bytes of one P-256 coordinate.
pub const ECC_P256_LEN: usize = 32;
pub const EO_UNSIGNED_LT: u16 = 0x0008;
/// Offset of `clockInfo.clock` inside `TPMS_TIME_INFO` (after `time` u64).
pub const TIME_INFO_CLOCK_OFFSET: u16 = 8;
pub const CAP_TPM_PROPERTIES: u32 = 6;
pub const PT_PERMANENT: u32 = 0x200;
pub const PT_LOCKOUT_COUNTER: u32 = 0x20E;
pub const PT_MAX_AUTH_FAIL: u32 = 0x20F;
pub const PT_LOCKOUT_INTERVAL: u32 = 0x210;
/// `TPMA_PERMANENT.inLockout`.
pub const PERMANENT_IN_LOCKOUT: u32 = 1 << 9;

/// Response codes the loader distinguishes.
pub mod rc {
    pub const SUCCESS: u32 = 0;
    pub const FMT1: u32 = 0x080;
    pub const AUTH_FAIL: u32 = FMT1 + 0x00E;
    pub const POLICY_FAIL: u32 = FMT1 + 0x01D;
    pub const BAD_AUTH: u32 = FMT1 + 0x022;
    pub const EXPIRED: u32 = FMT1 + 0x023;
    pub const VALUE: u32 = FMT1 + 0x004;
    pub const HANDLE: u32 = FMT1 + 0x00B;
    pub const INTEGRITY: u32 = FMT1 + 0x01F;
    pub const WARN: u32 = 0x900;
    pub const LOCKOUT: u32 = WARN + 0x021;
    pub const RETRY: u32 = WARN + 0x022;
    pub const TESTING: u32 = WARN + 0x00A;
    pub const YIELDED: u32 = WARN + 0x008;
    pub const PCR_CHANGED: u32 = WARN + 0x028;
    pub const VER1: u32 = 0x100;
    pub const POLICY: u32 = VER1 + 0x026;
    pub const INITIALIZE: u32 = VER1;
    pub const COMMAND_CODE: u32 = VER1 + 0x043;
    pub const AUTH_MISSING: u32 = VER1 + 0x025;
}

/// The error number of `code` with its handle/parameter/session index removed.
pub const fn rc_base(code: u32) -> u32 {
    if code & rc::FMT1 != 0 {
        code & (rc::FMT1 | 0x3F)
    } else {
        code
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcClass {
    /// Dictionary-attack lockout: grey the TPM row, keep the others.
    Lockout,
    /// Wrong PCRs or policy (firmware update, tamper, wrong PCR 12).
    PolicyFail,
    /// Wrong authValue: a genuinely wrong PIN; costs a DA attempt.
    AuthFail,
    /// Deadline passed (PIN bypass).
    Expired,
    /// Transient; the command may be retried.
    Retry,
    Other,
}

pub const fn classify(code: u32) -> RcClass {
    match rc_base(code) {
        rc::LOCKOUT => RcClass::Lockout,
        rc::POLICY_FAIL | rc::POLICY | rc::PCR_CHANGED => RcClass::PolicyFail,
        rc::AUTH_FAIL | rc::BAD_AUTH => RcClass::AuthFail,
        rc::EXPIRED => RcClass::Expired,
        rc::RETRY | rc::TESTING | rc::YIELDED => RcClass::Retry,
        _ => RcClass::Other,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmError {
    /// Longer than [`MAX_RESPONSE`].
    TooLarge,
    Truncated,
    BadTag,
    /// Header size field differs from the bytes received.
    SizeMismatch,
    /// Bytes left over after the last field.
    Trailing,
    /// A size or count exceeds its bound.
    Oversized,
    /// A field holds a value the command cannot have produced.
    BadValue,
    /// An error response.
    Rc(u32),
}

impl From<Short> for TpmError {
    fn from(_: Short) -> Self {
        TpmError::Truncated
    }
}

// ---------------------------------------------------------------------------
// Command marshalling
// ---------------------------------------------------------------------------

/// One command authorisation (`TPMS_AUTH_COMMAND`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthCommand<'a> {
    pub handle: u32,
    pub nonce: &'a [u8],
    pub attributes: u8,
    pub hmac: &'a [u8],
}

impl AuthCommand<'_> {
    /// The empty password session.
    pub const PASSWORD: AuthCommand<'static> = AuthCommand {
        handle: rh::PW,
        nonce: &[],
        attributes: sa::CONTINUE_SESSION,
        hmac: &[],
    };
}

fn tpm2b(w: &mut Writer<'_>, b: &[u8]) -> Result<(), Full> {
    w.u16_be(u16::try_from(b.len()).map_err(|_| Full)?)?;
    w.put(b)
}

/// Assemble a command: header, handles, optional auth area, parameters.
pub fn command(
    out: &mut [u8],
    code: u32,
    handles: &[u32],
    sessions: &[AuthCommand<'_>],
    params: &[u8],
) -> Result<usize, Full> {
    let cap = out.len().min(MAX_COMMAND);
    let mut w = Writer::new(out.get_mut(..cap).ok_or(Full)?);
    w.u16_be(if sessions.is_empty() {
        ST_NO_SESSIONS
    } else {
        ST_SESSIONS
    })?;
    w.u32_be(0)?;
    w.u32_be(code)?;
    for h in handles {
        w.u32_be(*h)?;
    }
    if !sessions.is_empty() {
        let at = w.len();
        w.u32_be(0)?;
        for s in sessions {
            w.u32_be(s.handle)?;
            tpm2b(&mut w, s.nonce)?;
            w.u8(s.attributes)?;
            tpm2b(&mut w, s.hmac)?;
        }
        let size = u32::try_from(w.len() - at - 4).map_err(|_| Full)?;
        w.patch(at, &size.to_be_bytes())?;
    }
    w.put(params)?;
    let size = u32::try_from(w.len()).map_err(|_| Full)?;
    w.patch(2, &size.to_be_bytes())?;
    Ok(w.len())
}

/// `TPML_PCR_SELECTION` with one bank and a 24-bit mask.
pub fn write_pcr_selection(w: &mut Writer<'_>, bank: u16, mask: u32) -> Result<(), Full> {
    w.u32_be(1)?;
    w.u16_be(bank)?;
    w.u8(3)?;
    w.put(&[mask as u8, (mask >> 8) as u8, (mask >> 16) as u8])
}

/// Parameters of `TPM2_PCR_Read`.
pub fn params_pcr_read(out: &mut [u8], mask: u32) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    write_pcr_selection(&mut w, alg::SHA256, mask)?;
    Ok(w.len())
}

/// `TPMT_PUBLIC` of the storage parent: the TCG ECC P-256 SRK template
/// (AES-128-CFB, empty authPolicy, empty unique). Deterministic, so every
/// `CreatePrimary` under the same owner seed yields the same key.
pub fn write_srk_public(w: &mut Writer<'_>) -> Result<(), Full> {
    w.u16_be(alg::ECC)?;
    w.u16_be(alg::SHA256)?;
    w.u32_be(attr::SRK)?;
    tpm2b(w, &[])?; // authPolicy
    w.u16_be(alg::AES)?;
    w.u16_be(128)?;
    w.u16_be(alg::CFB)?;
    w.u16_be(alg::NULL)?; // scheme
    w.u16_be(alg::ECC_NIST_P256)?;
    w.u16_be(alg::NULL)?; // kdf
    tpm2b(w, &[])?; // unique.x
    tpm2b(w, &[])?; // unique.y
    Ok(())
}

/// `TPMT_PUBLIC` of a sealed data object with `auth_policy`.
pub fn write_sealed_public(w: &mut Writer<'_>, auth_policy: &[u8; 32]) -> Result<(), Full> {
    w.u16_be(alg::KEYEDHASH)?;
    w.u16_be(alg::SHA256)?;
    w.u32_be(attr::SEALED)?;
    tpm2b(w, auth_policy)?;
    w.u16_be(alg::NULL)?; // keyedHash scheme
    tpm2b(w, &[])?; // unique
    Ok(())
}

fn write_tpm2b_with(
    w: &mut Writer<'_>,
    body: impl FnOnce(&mut Writer<'_>) -> Result<(), Full>,
) -> Result<(), Full> {
    let at = w.len();
    w.u16_be(0)?;
    body(w)?;
    let size = u16::try_from(w.len() - at - 2).map_err(|_| Full)?;
    w.patch(at, &size.to_be_bytes())
}

/// Parameters of `TPM2_CreatePrimary(owner, SRK template)`.
pub fn params_create_primary_srk(out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    write_tpm2b_with(&mut w, |w| {
        tpm2b(w, &[])?; // userAuth
        tpm2b(w, &[]) // data
    })?;
    write_tpm2b_with(&mut w, write_srk_public)?;
    tpm2b(&mut w, &[])?; // outsideInfo
    w.u32_be(0)?; // creationPCR: empty list
    Ok(w.len())
}

/// Parameters of `TPM2_Create` for a sealed object holding `data`, authorised
/// by `auth` under `auth_policy`.
pub fn params_create_sealed(
    out: &mut [u8],
    auth: &[u8],
    data: &[u8],
    auth_policy: &[u8; 32],
) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    write_tpm2b_with(&mut w, |w| {
        tpm2b(w, auth)?;
        tpm2b(w, data)
    })?;
    write_tpm2b_with(&mut w, |w| write_sealed_public(w, auth_policy))?;
    tpm2b(&mut w, &[])?;
    w.u32_be(0)?;
    Ok(w.len())
}

/// Parameters of `TPM2_Load`: `private` and `public` are whole TPM2B values
/// (size prefix included), as stored in a seal file.
pub fn params_load(out: &mut [u8], private: &[u8], public: &[u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.put(private)?;
    w.put(public)?;
    Ok(w.len())
}

/// A P-256 point as the TPM marshals it (`TPMS_ECC_POINT`, big-endian
/// coordinates). Not validated here: whoever does arithmetic on it checks
/// that it is on the curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EccPoint {
    pub x: [u8; ECC_P256_LEN],
    pub y: [u8; ECC_P256_LEN],
}

/// Parameters of an unbound SHA-256 `TPM2_StartAuthSession`
/// (`session_type` [`SE_HMAC`] or [`SE_POLICY`]). With `salt`, the
/// ephemeral public point the salt was agreed with (the `tpmKey` handle is
/// the caller's), and AES-128-CFB parameter encryption; without, an
/// unsalted session with no symmetric algorithm.
pub fn params_start_session(
    out: &mut [u8],
    nonce_caller: &[u8],
    salt: Option<&EccPoint>,
    session_type: u8,
) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    tpm2b(&mut w, nonce_caller)?;
    match salt {
        // encryptedSalt: a TPM2B_ENCRYPTED_SECRET holding a TPMS_ECC_POINT.
        Some(p) => write_tpm2b_with(&mut w, |w| {
            tpm2b(w, &p.x)?;
            tpm2b(w, &p.y)
        })?,
        None => tpm2b(&mut w, &[])?,
    }
    w.u8(session_type)?;
    if salt.is_some() {
        w.u16_be(alg::AES)?;
        w.u16_be(128)?;
        w.u16_be(alg::CFB)?;
    } else {
        w.u16_be(alg::NULL)?;
    }
    w.u16_be(alg::SHA256)?;
    Ok(w.len())
}

/// Parameters of an unsalted, unbound `TPM2_StartAuthSession` for a SHA-256
/// policy session without parameter encryption.
pub fn params_start_policy_session(out: &mut [u8], nonce_caller: &[u8]) -> Result<usize, Full> {
    params_start_session(out, nonce_caller, None, SE_POLICY)
}

/// Parameters of `TPM2_PolicyPCR` with an empty `pcrDigest` (the TPM uses its
/// current values).
pub fn params_policy_pcr(out: &mut [u8], bank: u16, mask: u32) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    tpm2b(&mut w, &[])?;
    write_pcr_selection(&mut w, bank, mask)?;
    Ok(w.len())
}

/// Parameters of `TPM2_PolicyCounterTimer(Clock < deadline)`.
pub fn params_policy_clock_before(out: &mut [u8], deadline_ms: u64) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    tpm2b(&mut w, &deadline_ms.to_be_bytes())?;
    w.u16_be(TIME_INFO_CLOCK_OFFSET)?;
    w.u16_be(EO_UNSIGNED_LT)?;
    Ok(w.len())
}

/// Parameters of `TPM2_GetCapability(TPM_PROPERTIES, first, count)`.
pub fn params_get_properties(out: &mut [u8], first: u32, count: u32) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.u32_be(CAP_TPM_PROPERTIES)?;
    w.u32_be(first)?;
    w.u32_be(count)?;
    Ok(w.len())
}

/// Parameters of `TPM2_FlushContext` (the handle is a parameter, not a handle).
pub fn params_flush(out: &mut [u8], handle: u32) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.u32_be(handle)?;
    Ok(w.len())
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// One response authorisation (`TPMS_AUTH_RESPONSE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AuthResponse<'a> {
    pub nonce: &'a [u8],
    pub attributes: u8,
    pub hmac: &'a [u8],
}

/// A successful response, split into its areas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    /// The response handle, when the command returns one.
    pub handle: Option<u32>,
    pub params: &'a [u8],
    pub sessions: [AuthResponse<'a>; MAX_SESSIONS],
    pub session_count: usize,
}

fn read_tpm2b<'a>(r: &mut Reader<'a>, max: usize) -> Result<&'a [u8], TpmError> {
    let n = usize::from(r.u16_be()?);
    if n > max {
        return Err(TpmError::Oversized);
    }
    Ok(r.take(n)?)
}

/// Split a response. `has_handle`: the command returns one handle.
/// `sessions`: how many authorisations the command carried (the response
/// must carry the same number).
pub fn response(resp: &[u8], has_handle: bool, sessions: usize) -> Result<Response<'_>, TpmError> {
    if resp.len() > MAX_RESPONSE {
        return Err(TpmError::TooLarge);
    }
    if sessions > MAX_SESSIONS {
        return Err(TpmError::Oversized);
    }
    let mut r = Reader::new(resp);
    let tag = r.u16_be()?;
    let size = r.u32_be()?;
    let code = r.u32_be()?;
    if size as usize != resp.len() {
        return Err(TpmError::SizeMismatch);
    }
    if code != rc::SUCCESS {
        // Error responses are a bare header.
        if tag != ST_NO_SESSIONS {
            return Err(TpmError::BadTag);
        }
        if !r.is_empty() {
            return Err(TpmError::Trailing);
        }
        return Err(TpmError::Rc(code));
    }
    let want_tag = if sessions == 0 {
        ST_NO_SESSIONS
    } else {
        ST_SESSIONS
    };
    if tag != want_tag {
        return Err(TpmError::BadTag);
    }
    let handle = if has_handle { Some(r.u32_be()?) } else { None };
    let params = if sessions == 0 {
        r.rest()
    } else {
        let n = r.u32_be()? as usize;
        if n > r.remaining() {
            return Err(TpmError::Oversized);
        }
        r.take(n)?
    };
    let mut out = Response {
        handle,
        params,
        sessions: [AuthResponse::default(); MAX_SESSIONS],
        session_count: sessions,
    };
    if sessions == 0 {
        return Ok(out);
    }
    for s in out.sessions.iter_mut().take(sessions) {
        s.nonce = read_tpm2b(&mut r, MAX_NONCE)?;
        s.attributes = r.u8()?;
        s.hmac = read_tpm2b(&mut r, MAX_NONCE)?;
    }
    if !r.is_empty() {
        return Err(TpmError::Trailing);
    }
    Ok(out)
}

fn done(r: &Reader<'_>) -> Result<(), TpmError> {
    if r.is_empty() {
        Ok(())
    } else {
        Err(TpmError::Trailing)
    }
}

/// SHA-256 PCR values as returned by `TPM2_PCR_Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcrValues {
    pub update_counter: u32,
    /// PCRs the TPM actually returned (it may drop unallocated ones).
    pub mask: u32,
    pub digests: [[u8; SHA256_LEN]; MAX_PCR_DIGESTS],
    pub count: usize,
}

impl PcrValues {
    /// The value of PCR `index`, if it was returned.
    pub fn get(&self, index: u32) -> Option<&[u8; SHA256_LEN]> {
        if index >= 24 || self.mask & (1 << index) == 0 {
            return None;
        }
        let pos = (self.mask & ((1u32 << index) - 1)).count_ones() as usize;
        self.digests.get(pos)
    }
}

/// Parse `TPM2_PCR_Read` parameters for a SHA-256 selection.
pub fn parse_pcr_read(params: &[u8]) -> Result<PcrValues, TpmError> {
    let mut r = Reader::new(params);
    let update_counter = r.u32_be()?;
    let banks = r.u32_be()?;
    if banks > 1 {
        return Err(TpmError::Oversized);
    }
    let mut mask = 0u32;
    if banks == 1 {
        if r.u16_be()? != alg::SHA256 {
            return Err(TpmError::BadValue);
        }
        let n = usize::from(r.u8()?);
        if n > 4 {
            return Err(TpmError::Oversized);
        }
        for (i, b) in r.take(n)?.iter().enumerate() {
            mask |= u32::from(*b) << (8 * i);
        }
        if mask >> 24 != 0 {
            return Err(TpmError::BadValue);
        }
    }
    let count = r.u32_be()? as usize;
    if count > MAX_PCR_DIGESTS {
        return Err(TpmError::Oversized);
    }
    if count != mask.count_ones() as usize {
        return Err(TpmError::BadValue);
    }
    let mut digests = [[0u8; SHA256_LEN]; MAX_PCR_DIGESTS];
    for d in digests.iter_mut().take(count) {
        let v = read_tpm2b(&mut r, 64)?;
        if v.len() != SHA256_LEN {
            return Err(TpmError::BadValue);
        }
        d.copy_from_slice(v);
    }
    done(&r)?;
    Ok(PcrValues {
        update_counter,
        mask,
        digests,
        count,
    })
}

fn skip_creation(r: &mut Reader<'_>) -> Result<(), TpmError> {
    read_tpm2b(r, 1024)?; // creationData
    read_tpm2b(r, 64)?; // creationHash
    if r.u16_be()? != ST_CREATION {
        return Err(TpmError::BadValue);
    }
    r.u32_be()?; // hierarchy
    read_tpm2b(r, 64)?; // ticket digest
    Ok(())
}

/// What `TPM2_CreatePrimary` returned for the storage parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Primary<'a> {
    /// `outPublic`'s `TPMT_PUBLIC` (without the TPM2B size): hashed for the
    /// name, which the caller compares with [`Primary::name`].
    pub public_area: &'a [u8],
    /// The parent's public point: session salts are agreed with it.
    pub point: EccPoint,
    pub name: &'a [u8],
}

/// Skip a `TPMT_SYM_DEF_OBJECT`, `TPMT_ECC_SCHEME` or `TPMT_KDF_SCHEME`:
/// an algorithm, and its details unless it is `TPM_ALG_NULL`. `details`
/// is how many u16 follow a non-null algorithm.
fn skip_alg(r: &mut Reader<'_>, details: usize) -> Result<u16, TpmError> {
    let a = r.u16_be()?;
    if a != alg::NULL {
        for _ in 0..details {
            r.u16_be()?;
        }
    }
    Ok(a)
}

/// A `TPMT_PUBLIC` that must be an ECC P-256 key: returns its point.
/// Anything else (another type or curve, coordinates of another size,
/// trailing bytes) is refused — the loader only ever asks for the SRK
/// template.
pub fn parse_ecc_public(area: &[u8]) -> Result<EccPoint, TpmError> {
    let mut r = Reader::new(area);
    if r.u16_be()? != alg::ECC {
        return Err(TpmError::BadValue);
    }
    r.u16_be()?; // nameAlg
    r.u32_be()?; // objectAttributes
    read_tpm2b(&mut r, 64)?; // authPolicy
    skip_alg(&mut r, 2)?; // symmetric: keyBits, mode
    skip_alg(&mut r, 1)?; // scheme: hashAlg
    if r.u16_be()? != alg::ECC_NIST_P256 {
        return Err(TpmError::BadValue);
    }
    skip_alg(&mut r, 1)?; // kdf: hashAlg
    let mut coord = || -> Result<[u8; ECC_P256_LEN], TpmError> {
        let c = read_tpm2b(&mut r, 2 * ECC_P256_LEN)?;
        c.try_into().map_err(|_| TpmError::BadValue)
    };
    let x = coord()?;
    let y = coord()?;
    done(&r)?;
    Ok(EccPoint { x, y })
}

/// `TPM2_CreatePrimary` parameters of the ECC storage parent.
pub fn parse_create_primary(params: &[u8]) -> Result<Primary<'_>, TpmError> {
    let mut r = Reader::new(params);
    let public_area = read_tpm2b(&mut r, 1024)?; // outPublic
    skip_creation(&mut r)?;
    let name = read_tpm2b(&mut r, 2 + 64)?;
    done(&r)?;
    Ok(Primary {
        public_area,
        point: parse_ecc_public(public_area)?,
        name,
    })
}

/// `TPM2_Create` output: whole TPM2B values (size prefix included), ready for
/// a seal file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Created<'a> {
    pub private: &'a [u8],
    pub public: &'a [u8],
}

pub fn parse_create(params: &[u8]) -> Result<Created<'_>, TpmError> {
    let mut r = Reader::new(params);
    let whole = |r: &mut Reader<'_>, max| -> Result<usize, TpmError> {
        let before = r.remaining();
        let v = read_tpm2b(r, max)?;
        if v.is_empty() {
            return Err(TpmError::BadValue);
        }
        Ok(before - r.remaining())
    };
    let start = params;
    let priv_len = whole(&mut r, 1024)?;
    let pub_len = whole(&mut r, 1024)?;
    skip_creation(&mut r)?;
    done(&r)?;
    let private = start.get(..priv_len).ok_or(TpmError::Truncated)?;
    let public = start
        .get(priv_len..priv_len + pub_len)
        .ok_or(TpmError::Truncated)?;
    Ok(Created { private, public })
}

/// `TPM2_Load` parameters: the loaded object's name.
pub fn parse_load(params: &[u8]) -> Result<&[u8], TpmError> {
    let mut r = Reader::new(params);
    let name = read_tpm2b(&mut r, 2 + 64)?;
    done(&r)?;
    Ok(name)
}

/// `TPM2_StartAuthSession` parameters: `nonceTPM`.
pub fn parse_start_auth_session(params: &[u8]) -> Result<&[u8], TpmError> {
    let mut r = Reader::new(params);
    let nonce = read_tpm2b(&mut r, MAX_NONCE)?;
    if nonce.len() < 16 {
        return Err(TpmError::BadValue);
    }
    done(&r)?;
    Ok(nonce)
}

/// `TPM2_Unseal` parameters: the sealed data.
pub fn parse_unseal(params: &[u8]) -> Result<&[u8], TpmError> {
    let mut r = Reader::new(params);
    let data = read_tpm2b(&mut r, MAX_SENSITIVE_DATA)?;
    done(&r)?;
    Ok(data)
}

/// Commands with no output parameters.
pub fn parse_empty(params: &[u8]) -> Result<(), TpmError> {
    done(&Reader::new(params))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeInfo {
    pub time: u64,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    /// `TPMS_CLOCK_INFO.safe`: the clock has not gone backwards. The PIN
    /// bypass is refused when clear (DESIGN.md §6).
    pub safe: bool,
}

pub fn parse_read_clock(params: &[u8]) -> Result<TimeInfo, TpmError> {
    let mut r = Reader::new(params);
    let t = TimeInfo {
        time: r.u64_be()?,
        clock: r.u64_be()?,
        reset_count: r.u32_be()?,
        restart_count: r.u32_be()?,
        safe: match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(TpmError::BadValue),
        },
    };
    done(&r)?;
    Ok(t)
}

/// `TPM2_GetCapability(TPM_PROPERTIES)` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Properties {
    pub more: bool,
    pub props: [(u32, u32); MAX_PROPERTIES],
    pub count: usize,
}

impl Properties {
    pub fn get(&self, prop: u32) -> Option<u32> {
        self.props
            .iter()
            .take(self.count)
            .find(|(p, _)| *p == prop)
            .map(|(_, v)| *v)
    }
}

pub fn parse_get_properties(params: &[u8]) -> Result<Properties, TpmError> {
    let mut r = Reader::new(params);
    let more = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(TpmError::BadValue),
    };
    if r.u32_be()? != CAP_TPM_PROPERTIES {
        return Err(TpmError::BadValue);
    }
    let count = r.u32_be()? as usize;
    if count > MAX_PROPERTIES {
        return Err(TpmError::Oversized);
    }
    let mut props = [(0u32, 0u32); MAX_PROPERTIES];
    for p in props.iter_mut().take(count) {
        *p = (r.u32_be()?, r.u32_be()?);
    }
    done(&r)?;
    Ok(Properties { more, props, count })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(tag: u16, code: u32, body: &[u8]) -> ([u8; 512], usize) {
        let mut b = [0u8; 512];
        let n = HEADER_LEN + body.len();
        b[..2].copy_from_slice(&tag.to_be_bytes());
        b[2..6].copy_from_slice(&(n as u32).to_be_bytes());
        b[6..10].copy_from_slice(&code.to_be_bytes());
        b[10..n].copy_from_slice(body);
        (b, n)
    }

    #[test]
    fn command_layout_known_answer() {
        // TPM2_PCR_Read(sha256: 0,2,4,7,12), no sessions.
        let mut p = [0u8; 32];
        let pn = params_pcr_read(&mut p, 0x1095).unwrap();
        let mut c = [0u8; 64];
        let n = command(&mut c, cc::PCR_READ, &[], &[], &p[..pn]).unwrap();
        assert_eq!(
            &c[..n],
            &[
                0x80, 0x01, 0, 0, 0, 20, 0, 0, 0x01, 0x7E, 0, 0, 0, 1, 0, 0x0B, 3, 0x95, 0x10, 0
            ]
        );
        // With a password session: auth area size 9.
        let n = command(
            &mut c,
            cc::UNSEAL,
            &[0x8000_0001],
            &[AuthCommand::PASSWORD],
            &[],
        )
        .unwrap();
        assert_eq!(
            &c[..n],
            &[
                0x80, 0x02, 0, 0, 0, 27, 0, 0, 0x01, 0x5E, 0x80, 0, 0, 1, 0, 0, 0, 9, 0x40, 0, 0,
                9, 0, 0, 1, 0, 0
            ]
        );
        assert_eq!(command(&mut c[..12], cc::UNSEAL, &[1], &[], &[]), Err(Full));
    }

    #[test]
    fn param_builders_have_expected_lengths() {
        let mut b = [0u8; 512];
        assert_eq!(
            params_create_primary_srk(&mut b),
            Ok(2 + 4 + 2 + 26 + 2 + 4)
        );
        assert_eq!(
            params_create_sealed(&mut b, &[1; 32], &[2; 32], &[3; 32]),
            Ok(2 + 68 + 2 + 46 + 2 + 4)
        );
        assert_eq!(
            params_start_policy_session(&mut b, &[0; 32]),
            Ok(34 + 2 + 1 + 2 + 2)
        );
        let p = EccPoint {
            x: [1; 32],
            y: [2; 32],
        };
        let n = params_start_session(&mut b, &[0; 32], Some(&p), SE_HMAC).unwrap();
        assert_eq!(n, 34 + 2 + 68 + 1 + 6 + 2);
        assert_eq!(&b[34..40], &[0, 68, 0, 32, 1, 1]);
        assert_eq!(&b[n - 9..n], &[SE_HMAC, 0, 6, 0, 128, 0, 0x43, 0, 0x0b]);
        assert_eq!(params_policy_pcr(&mut b, alg::SHA256, 0x1095), Ok(2 + 10));
        assert_eq!(params_policy_clock_before(&mut b, 5), Ok(10 + 4));
        assert_eq!(params_get_properties(&mut b, PT_PERMANENT, 16), Ok(12));
        assert_eq!(params_flush(&mut b, 0x8000_0000), Ok(4));
        assert_eq!(params_load(&mut b, &[0, 1, 1], &[0, 1, 2]), Ok(6));
        assert_eq!(params_create_primary_srk(&mut b[..10]), Err(Full));
    }

    #[test]
    fn rc_classification() {
        assert_eq!(classify(rc::LOCKOUT), RcClass::Lockout);
        // POLICY_FAIL reported against session 1 (bit 11 set, S=0x800).
        assert_eq!(classify(rc::POLICY_FAIL | 0x800), RcClass::PolicyFail);
        assert_eq!(classify(rc::POLICY), RcClass::PolicyFail);
        assert_eq!(classify(rc::PCR_CHANGED), RcClass::PolicyFail);
        assert_eq!(classify(rc::AUTH_FAIL | 0x900 & 0xF00), RcClass::AuthFail);
        assert_eq!(classify(rc::BAD_AUTH | 0x100), RcClass::AuthFail);
        assert_eq!(classify(rc::EXPIRED | 0x100), RcClass::Expired);
        assert_eq!(classify(rc::RETRY), RcClass::Retry);
        assert_eq!(classify(rc::TESTING), RcClass::Retry);
        assert_eq!(classify(rc::YIELDED), RcClass::Retry);
        assert_eq!(classify(rc::VALUE), RcClass::Other);
        assert_eq!(rc_base(0x98E), rc::AUTH_FAIL);
    }

    #[test]
    fn response_framing_errors() {
        let big = [0u8; MAX_RESPONSE + 1];
        assert_eq!(response(&big, false, 0), Err(TpmError::TooLarge));
        assert_eq!(response(&[0x80, 1, 0], false, 0), Err(TpmError::Truncated));
        let (b, n) = resp(ST_NO_SESSIONS, 0, &[]);
        assert_eq!(response(&b[..n], false, 4), Err(TpmError::Oversized));
        assert_eq!(response(&b[..n - 1], false, 0), Err(TpmError::Truncated));
        let mut x = b;
        x[5] = 11;
        assert_eq!(response(&x[..n], false, 0), Err(TpmError::SizeMismatch));
        let (b, n) = resp(ST_NO_SESSIONS, rc::LOCKOUT, &[]);
        assert_eq!(response(&b[..n], false, 1), Err(TpmError::Rc(rc::LOCKOUT)));
        let (b, n) = resp(ST_SESSIONS, rc::LOCKOUT, &[]);
        assert_eq!(response(&b[..n], false, 1), Err(TpmError::BadTag));
        let (b, n) = resp(ST_NO_SESSIONS, rc::LOCKOUT, &[0]);
        assert_eq!(response(&b[..n], false, 1), Err(TpmError::Trailing));
        let (b, n) = resp(ST_SESSIONS, 0, &[]);
        assert_eq!(response(&b[..n], false, 0), Err(TpmError::BadTag));
        let (b, n) = resp(ST_NO_SESSIONS, 0, &[1, 2, 3, 4, 9]);
        let r = response(&b[..n], true, 0).unwrap();
        assert_eq!((r.handle, r.params), (Some(0x0102_0304), &[9][..]));
        assert_eq!(response(&b[..n - 2], true, 0), Err(TpmError::SizeMismatch));
        let (b, n) = resp(ST_NO_SESSIONS, 0, &[1, 2]);
        assert_eq!(response(&b[..n], true, 0), Err(TpmError::Truncated));
    }

    #[test]
    fn response_with_sessions() {
        // params 2 bytes, one session: nonce 16, attrs, hmac 32
        let mut body = [0u8; 4 + 2 + 2 + 16 + 1 + 2 + 32];
        body[3] = 2;
        body[4..6].copy_from_slice(&[0xaa, 0xbb]);
        body[7] = 16;
        body[24] = 1;
        body[26] = 32;
        let (b, n) = resp(ST_SESSIONS, 0, &body);
        let r = response(&b[..n], false, 1).unwrap();
        assert_eq!(r.params, &[0xaa, 0xbb]);
        assert_eq!(r.session_count, 1);
        assert_eq!(
            (
                r.sessions[0].nonce.len(),
                r.sessions[0].attributes,
                r.sessions[0].hmac.len()
            ),
            (16, 1, 32)
        );
        // parameterSize larger than what remains
        let mut x = body;
        x[3] = 200;
        let (b, n) = resp(ST_SESSIONS, 0, &x);
        assert_eq!(response(&b[..n], false, 1), Err(TpmError::Oversized));
        // a nonce above MAX_NONCE
        let mut x = body;
        x[6] = 1;
        let (b, n) = resp(ST_SESSIONS, 0, &x);
        assert_eq!(response(&b[..n], false, 1), Err(TpmError::Oversized));
        // expecting two sessions, one present
        let (b, n) = resp(ST_SESSIONS, 0, &body);
        assert_eq!(response(&b[..n], false, 2), Err(TpmError::Truncated));
        // trailing after the sessions
        let mut y = [0u8; 60];
        y[..body.len()].copy_from_slice(&body);
        let (b, n) = resp(ST_SESSIONS, 0, &y[..body.len() + 1]);
        assert_eq!(response(&b[..n], false, 1), Err(TpmError::Trailing));
    }

    fn pcr_read_body(mask: [u8; 3], count: u32, dlen: u8) -> ([u8; 1024], usize) {
        let mut b = [0u8; 1024];
        let mut w = Writer::new(&mut b);
        w.u32_be(7).unwrap();
        w.u32_be(1).unwrap();
        w.u16_be(alg::SHA256).unwrap();
        w.u8(3).unwrap();
        w.put(&mask).unwrap();
        w.u32_be(count).unwrap();
        for i in 0..count {
            w.u16_be(u16::from(dlen)).unwrap();
            for _ in 0..dlen {
                w.u8(i as u8).unwrap();
            }
        }
        let n = w.len();
        (b, n)
    }

    #[test]
    fn pcr_read() {
        let (b, n) = pcr_read_body([0x95, 0x10, 0], 5, 32);
        let v = parse_pcr_read(&b[..n]).unwrap();
        assert_eq!((v.update_counter, v.mask, v.count), (7, 0x1095, 5));
        assert_eq!(v.get(0), Some(&[0; 32]));
        assert_eq!(v.get(7), Some(&[3; 32]));
        assert_eq!(v.get(12), Some(&[4; 32]));
        assert_eq!(v.get(1), None);
        assert_eq!(v.get(30), None);
        assert_eq!(parse_pcr_read(&b[..n - 1]), Err(TpmError::Truncated));
        let mut x = [0u8; 1025];
        x[..n].copy_from_slice(&b[..n]);
        assert_eq!(parse_pcr_read(&x[..n + 1]), Err(TpmError::Trailing));
        let (b, n) = pcr_read_body([0x95, 0x10, 0], 4, 32);
        assert_eq!(parse_pcr_read(&b[..n]), Err(TpmError::BadValue));
        let (b, n) = pcr_read_body([0xff, 0xff, 0], 16, 32);
        assert_eq!(parse_pcr_read(&b[..n]), Err(TpmError::Oversized));
        let (b, n) = pcr_read_body([1, 0, 0], 1, 20);
        assert_eq!(parse_pcr_read(&b[..n]), Err(TpmError::BadValue));
        let (b, n) = pcr_read_body([1, 0, 0], 1, 65);
        assert_eq!(parse_pcr_read(&b[..n]), Err(TpmError::Oversized));
        let mut x = b;
        x[10] = 5; // sizeofSelect beyond PCR_SELECT_MAX
        assert_eq!(parse_pcr_read(&x[..n]), Err(TpmError::Oversized));
        let mut x = b;
        x[9] = 0x04; // SHA-1 bank
        assert_eq!(parse_pcr_read(&x[..n]), Err(TpmError::BadValue));
        let mut x = b;
        x[7] = 2; // two banks
        assert_eq!(parse_pcr_read(&x[..n]), Err(TpmError::Oversized));
        // zero banks, zero digests: an empty (but valid) answer
        assert_eq!(
            parse_pcr_read(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).map(|v| v.count),
            Ok(0)
        );
        // bit above 23 in a 3-byte select is impossible; 4-byte select checked
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        s[8..10].copy_from_slice(&alg::SHA256.to_be_bytes());
        s[10] = 4;
        s[11..15].copy_from_slice(&[0, 0, 0, 1]);
        assert_eq!(parse_pcr_read(&s[..19]), Err(TpmError::BadValue));
    }

    #[test]
    fn creation_outputs() {
        let mut b = [0u8; 256];
        let mut w = Writer::new(&mut b);
        w.put(&[0, 3, 1, 2, 3]).unwrap(); // private
        w.put(&[0, 2, 4, 5]).unwrap(); // public
        w.put(&[0, 0]).unwrap(); // creationData
        w.put(&[0, 0]).unwrap(); // creationHash
        w.u16_be(ST_CREATION).unwrap();
        w.u32_be(rh::OWNER).unwrap();
        w.put(&[0, 0]).unwrap();
        let n = w.len();
        let c = parse_create(&b[..n]).unwrap();
        assert_eq!(
            (c.private, c.public),
            (&[0, 3, 1, 2, 3][..], &[0, 2, 4, 5][..])
        );
        assert_eq!(parse_create(&b[..n - 1]), Err(TpmError::Truncated));
        let mut x = b;
        x[13] = 0x22; // bad ticket tag
        assert_eq!(parse_create(&x[..n]), Err(TpmError::BadValue));
        let mut x = b;
        x[1] = 0; // empty private
        assert!(parse_create(&x[..n]).is_err());
        // CreatePrimary: outPublic (the SRK template, a point), creation…, name
        let mut area = [0u8; 256];
        let mut w = Writer::new(&mut area);
        write_srk_public(&mut w).unwrap();
        let empty_unique = w.len();
        let an = empty_unique + 64;
        let mut pub_area = [0u8; 256];
        pub_area[..empty_unique - 4].copy_from_slice(&area[..empty_unique - 4]);
        pub_area[empty_unique - 4..empty_unique - 2].copy_from_slice(&[0, 32]);
        pub_area[empty_unique - 2..empty_unique + 30].copy_from_slice(&[7; 32]);
        pub_area[empty_unique + 30..empty_unique + 32].copy_from_slice(&[0, 32]);
        pub_area[empty_unique + 32..an].copy_from_slice(&[8; 32]);
        let primary = |area: &[u8], b: &mut [u8; 256]| {
            let mut w = Writer::new(b);
            w.u16_be(area.len() as u16).unwrap();
            w.put(area).unwrap();
            w.put(&[0, 0, 0, 0]).unwrap();
            w.u16_be(ST_CREATION).unwrap();
            w.u32_be(rh::OWNER).unwrap();
            w.put(&[0, 0, 0, 3, 0, 0x0b, 9]).unwrap();
            w.len()
        };
        let n = primary(&pub_area[..an], &mut b);
        let p = parse_create_primary(&b[..n]).unwrap();
        assert_eq!(p.name, &[0, 0x0b, 9][..]);
        assert_eq!(p.public_area, &pub_area[..an]);
        assert_eq!((p.point.x, p.point.y), ([7; 32], [8; 32]));
        assert_eq!(parse_create_primary(&b[..n - 1]), Err(TpmError::Truncated));
        // The empty-unique template (what we send) is not a key.
        let n = primary(&area[..empty_unique], &mut b);
        assert_eq!(parse_create_primary(&b[..n]), Err(TpmError::BadValue));
        // An RSA key, another curve, a short coordinate, a trailing byte.
        let mut x = pub_area;
        x[1] = 0x01;
        assert_eq!(parse_ecc_public(&x[..an]), Err(TpmError::BadValue));
        let mut x = pub_area;
        x[empty_unique - 8..empty_unique - 6].copy_from_slice(&[0, 4]);
        assert_eq!(parse_ecc_public(&x[..an]), Err(TpmError::BadValue));
        let mut x = pub_area;
        x[empty_unique - 3] = 31;
        assert!(parse_ecc_public(&x[..an]).is_err());
        assert_eq!(
            parse_ecc_public(&pub_area[..an + 1]),
            Err(TpmError::Trailing)
        );
        assert_eq!(
            parse_ecc_public(&pub_area[..an - 1]),
            Err(TpmError::Truncated)
        );
    }

    #[test]
    fn small_outputs() {
        assert_eq!(parse_load(&[0, 2, 0, 0x0b]), Ok(&[0, 0x0b][..]));
        assert_eq!(parse_load(&[0, 2, 0, 0x0b, 0]), Err(TpmError::Trailing));
        assert_eq!(parse_load(&[0, 67]), Err(TpmError::Oversized));
        let mut s = [0u8; 18];
        s[1] = 16;
        assert_eq!(parse_start_auth_session(&s).map(<[u8]>::len), Ok(16));
        assert_eq!(
            parse_start_auth_session(&[0, 1, 0]),
            Err(TpmError::BadValue)
        );
        assert_eq!(parse_unseal(&[0, 2, 7, 8]), Ok(&[7, 8][..]));
        assert_eq!(parse_unseal(&[0, 129]), Err(TpmError::Oversized));
        assert_eq!(parse_empty(&[]), Ok(()));
        assert_eq!(parse_empty(&[0]), Err(TpmError::Trailing));

        let mut t = [0u8; 25];
        t[15] = 5;
        t[24] = 1;
        let ti = parse_read_clock(&t).unwrap();
        assert_eq!((ti.clock, ti.safe), (5, true));
        t[24] = 2;
        assert_eq!(parse_read_clock(&t), Err(TpmError::BadValue));
        assert_eq!(parse_read_clock(&t[..20]), Err(TpmError::Truncated));

        let mut p = [0u8; 9 + 16];
        p[4] = 6;
        p[8] = 2;
        p[9..13].copy_from_slice(&PT_LOCKOUT_COUNTER.to_be_bytes());
        p[16] = 3;
        p[17..21].copy_from_slice(&PT_MAX_AUTH_FAIL.to_be_bytes());
        p[24] = 32;
        let props = parse_get_properties(&p).unwrap();
        assert_eq!(props.get(PT_LOCKOUT_COUNTER), Some(3));
        assert_eq!(props.get(PT_MAX_AUTH_FAIL), Some(32));
        assert_eq!(props.get(PT_PERMANENT), None);
        assert!(!props.more);
        let mut x = p;
        x[0] = 2;
        assert_eq!(parse_get_properties(&x), Err(TpmError::BadValue));
        let mut x = p;
        x[4] = 5;
        assert_eq!(parse_get_properties(&x), Err(TpmError::BadValue));
        let mut x = p;
        x[7] = 65;
        assert_eq!(parse_get_properties(&x), Err(TpmError::Oversized));
        assert_eq!(parse_get_properties(&p[..20]), Err(TpmError::Truncated));
    }
}
