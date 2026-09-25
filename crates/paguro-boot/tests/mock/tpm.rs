//! A fake TPM 2.0 that speaks real TPM command bytes: it parses what the
//! loader marshals and answers with real response framing. It models the
//! parts of the TPM the loader's security rests on:
//!
//! - SHA-256 PCRs with extend;
//! - a deterministic SRK per owner seed;
//! - sealed objects whose private blob is bound to the seed and the public area;
//! - an ECC P-256 SRK whose public point salts sessions (ECDH, `KDFe`,
//!   `KDFa`), AES-128-CFB parameter encryption of the Create sensitive and
//!   the Unseal response, as TPM 2.0 Part 1 §19.6 and §21 define them;
//! - policy sessions that accumulate PolicyPCR / PolicyCounterTimer /
//!   PolicyAuthValue exactly as the TPM does, and an Unseal that checks the
//!   digest against the object's authPolicy and the command HMAC keyed by
//!   sessionKey || authValue, with a dictionary-attack counter and lockout;
//! - `TPMS_CLOCK_INFO` (clock + safe flag) and lockout properties.
//!
//! Fault injection (`corrupt`, `fail`) lets tests drive the loader's handling
//! of hostile or failing responses.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint};
use paguro_core::bytes::{Reader, Writer};
use paguro_core::tpm::{alg, attr, cc, rc};
use paguro_crypto::tpm as st;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn trim(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    &b[..end]
}

#[derive(Clone)]
enum Obj {
    Primary,
    Sealed {
        public: Vec<u8>,
        auth: Vec<u8>,
        policy: Vec<u8>,
        data: Vec<u8>,
    },
}

#[derive(Clone)]
struct Session {
    digest: [u8; 32],
    nonce_tpm: [u8; 32],
    auth_needed: bool,
    /// Empty for an unsalted session.
    key: Vec<u8>,
    /// AES-128-CFB parameter encryption was negotiated.
    aes: bool,
}

/// How to corrupt the next matching response.
#[derive(Clone, Copy, Debug)]
pub enum Corrupt {
    /// Flip a byte of the response HMAC (Unseal).
    ResponseHmac,
    /// Truncate the response by one byte (size field left as-is).
    Truncate,
    /// Replace the whole response with 7 garbage bytes.
    Garbage,
}

/// Well-formed but wrong answers (a lying or buggy TPM / interposer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quirk {
    /// `TPM2_Load` reports a name that is not the loaded public area's.
    WrongLoadName,
    /// `TPM2_Unseal` returns 31 bytes (correctly authenticated).
    ShortPayload,
    /// `TPM2_CreatePrimary` returns a public point that is not on the curve.
    OffCurveSrk,
    /// `TPM2_CreatePrimary` reports a name that is not its public area's.
    WrongPrimaryName,
    /// `TPM2_Unseal` returns `D` unencrypted (a TPM ignoring `encrypt`).
    PlainUnseal,
}

#[derive(Clone)]
pub struct FakeTpm {
    pub pcrs: [[u8; 32]; 24],
    pub seed: [u8; 32],
    pub clock: u64,
    pub safe: bool,
    pub lockout_counter: u32,
    pub max_tries: u32,
    pub in_lockout: bool,
    /// Every command code received, in order.
    pub commands: Vec<u32>,
    /// Inject `rc` for the next command with code `cc`.
    pub fail: Option<(u32, u32)>,
    pub corrupt: Option<(u32, Corrupt)>,
    pub quirk: Option<Quirk>,
    objects: HashMap<u32, Obj>,
    sessions: HashMap<u32, Session>,
    next_handle: u32,
    counter: u64,
}

impl FakeTpm {
    pub fn new(seed: u8) -> Self {
        FakeTpm {
            pcrs: [[0; 32]; 24],
            seed: [seed; 32],
            clock: 1_000_000,
            safe: true,
            lockout_counter: 0,
            max_tries: 3,
            in_lockout: false,
            commands: Vec::new(),
            fail: None,
            corrupt: None,
            quirk: None,
            objects: HashMap::new(),
            sessions: HashMap::new(),
            next_handle: 0,
            counter: 0,
        }
    }

    /// A power cycle: PCRs reset, transient objects and sessions gone.
    pub fn reboot(&mut self) {
        self.pcrs = [[0; 32]; 24];
        self.objects.clear();
        self.sessions.clear();
        self.commands.clear();
    }

    pub fn extend(&mut self, pcr: usize, digest: &[u8; 32]) {
        self.pcrs[pcr] = sha256(&[&self.pcrs[pcr], digest]);
    }

    pub fn count(&self, code: u32) -> usize {
        self.commands.iter().filter(|c| **c == code).count()
    }

    /// Handles still loaded (a leak check).
    pub fn live_handles(&self) -> usize {
        self.objects.len() + self.sessions.len()
    }

    fn nonce(&mut self) -> [u8; 32] {
        self.counter += 1;
        sha256(&[b"nonce", &self.counter.to_le_bytes(), &self.seed])
    }

    fn keystream(&self, public: &[u8], n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0u32;
        while out.len() < n {
            out.extend(sha256(&[&self.seed, public, &i.to_le_bytes()]));
            i += 1;
        }
        out.truncate(n);
        out
    }

    fn wrap(&self, public: &[u8], auth: &[u8], data: &[u8]) -> Vec<u8> {
        let mut plain = vec![auth.len() as u8];
        plain.extend(auth);
        plain.push(data.len() as u8);
        plain.extend(data);
        let ks = self.keystream(public, plain.len());
        let mut ct: Vec<u8> = plain.iter().zip(ks).map(|(a, b)| a ^ b).collect();
        ct.extend(hmac(&self.seed, &[public, &plain]));
        let mut blob = (ct.len() as u16).to_be_bytes().to_vec();
        blob.extend(ct);
        blob
    }

    fn unwrap(&self, public: &[u8], private: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if private.len() < 32 + 2 {
            return None;
        }
        let (ct, tag) = private.split_at(private.len() - 32);
        let ks = self.keystream(public, ct.len());
        let plain: Vec<u8> = ct.iter().zip(ks).map(|(a, b)| a ^ b).collect();
        if hmac(&self.seed, &[public, &plain]) != tag {
            return None;
        }
        let al = *plain.first()? as usize;
        let auth = plain.get(1..1 + al)?.to_vec();
        let dl = *plain.get(1 + al)? as usize;
        let data = plain.get(2 + al..2 + al + dl)?.to_vec();
        Some((auth, data))
    }

    fn srk_scalar(&self) -> NonZeroScalar {
        let raw = sha256(&[b"srk", &self.seed]);
        Option::from(NonZeroScalar::from_repr(FieldBytes::from(raw))).unwrap()
    }

    /// The SRK's `TPMT_PUBLIC`: the template with the point filled in.
    pub fn srk_public(&self) -> Vec<u8> {
        let q = (ProjectivePoint::GENERATOR * *self.srk_scalar()).to_affine();
        let mut b = [0u8; 256];
        let mut w = Writer::new(&mut b);
        paguro_core::tpm::write_srk_public(&mut w).unwrap();
        let n = w.len() - 4; // without the empty unique
        let mut v = b[..n].to_vec();
        let (mut x, y): ([u8; 32], [u8; 32]) = (q.x().into(), q.y().into());
        if self.quirk == Some(Quirk::OffCurveSrk) {
            x[31] ^= 1;
        }
        for c in [x, y] {
            v.extend([0, 32]);
            v.extend(c);
        }
        v
    }

    fn alloc(&mut self, base: u32) -> u32 {
        self.next_handle += 1;
        base + self.next_handle
    }

    /// Process one command; always returns a response (errors as RCs).
    pub fn submit(&mut self, cmd: &[u8]) -> Vec<u8> {
        let code = if cmd.len() >= 10 {
            u32::from_be_bytes(cmd[6..10].try_into().unwrap())
        } else {
            0
        };
        self.commands.push(code);
        let mut resp = match self.fail {
            Some((c, r)) if c == code => {
                self.fail = None;
                err(r)
            }
            _ => self.execute(cmd).unwrap_or_else(err),
        };
        if let Some((c, how)) = self.corrupt {
            if c == code {
                self.corrupt = None;
                match how {
                    Corrupt::ResponseHmac => {
                        let n = resp.len();
                        resp[n - 1] ^= 1;
                    }
                    Corrupt::Truncate => {
                        resp.pop();
                    }
                    Corrupt::Garbage => resp = vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 1],
                }
            }
        }
        resp
    }

    fn execute(&mut self, cmd: &[u8]) -> Result<Vec<u8>, u32> {
        let mut r = Reader::new(cmd);
        let tag = r.u16_be().map_err(|_| rc::VALUE)?;
        let size = r.u32_be().map_err(|_| rc::VALUE)?;
        let code = r.u32_be().map_err(|_| rc::VALUE)?;
        if size as usize != cmd.len() {
            return Err(rc::VALUE);
        }
        let n_handles = match code {
            cc::CREATE_PRIMARY
            | cc::CREATE
            | cc::LOAD
            | cc::POLICY_PCR
            | cc::POLICY_AUTH_VALUE
            | cc::POLICY_COUNTER_TIMER
            | cc::UNSEAL => 1,
            cc::START_AUTH_SESSION => 2,
            cc::FLUSH_CONTEXT | cc::READ_CLOCK | cc::GET_CAPABILITY | cc::PCR_READ => 0,
            _ => return Err(rc::COMMAND_CODE),
        };
        let mut handles = Vec::new();
        for _ in 0..n_handles {
            handles.push(r.u32_be().map_err(|_| rc::VALUE)?);
        }
        let mut sessions = Vec::new();
        if tag == 0x8002 {
            let asz = r.u32_be().map_err(|_| rc::VALUE)? as usize;
            let area = r.take(asz).map_err(|_| rc::VALUE)?;
            let mut a = Reader::new(area);
            while !a.is_empty() {
                let h = a.u32_be().map_err(|_| rc::VALUE)?;
                let nl = a.u16_be().map_err(|_| rc::VALUE)? as usize;
                let nonce = a.take(nl).map_err(|_| rc::VALUE)?.to_vec();
                let at = a.u8().map_err(|_| rc::VALUE)?;
                let hl = a.u16_be().map_err(|_| rc::VALUE)? as usize;
                let mac = a.take(hl).map_err(|_| rc::VALUE)?.to_vec();
                sessions.push((h, nonce, at, mac));
            }
        }
        let params = r.rest();
        let h0 = handles.first().copied().unwrap_or(0);
        let mut p = Reader::new(params);
        let tpm2b = |p: &mut Reader<'_>| -> Result<Vec<u8>, u32> {
            let n = p.u16_be().map_err(|_| rc::VALUE)? as usize;
            Ok(p.take(n).map_err(|_| rc::VALUE)?.to_vec())
        };
        match code {
            cc::PCR_READ => {
                let _count = p.u32_be().map_err(|_| rc::VALUE)?;
                let _hash = p.u16_be().map_err(|_| rc::VALUE)?;
                let sz = p.u8().map_err(|_| rc::VALUE)? as usize;
                let sel = p.take(sz).map_err(|_| rc::VALUE)?;
                let mut mask = 0u32;
                for (i, b) in sel.iter().enumerate() {
                    mask |= u32::from(*b) << (8 * i);
                }
                let mut body = 1u32.to_be_bytes().to_vec();
                body.extend(1u32.to_be_bytes());
                body.extend(alg::SHA256.to_be_bytes());
                body.push(3);
                body.extend([mask as u8, (mask >> 8) as u8, (mask >> 16) as u8]);
                body.extend(mask.count_ones().to_be_bytes());
                for i in 0..24 {
                    if mask & (1 << i) != 0 {
                        body.extend([0, 32]);
                        body.extend(self.pcrs[i]);
                    }
                }
                Ok(ok(None, &body, &[]))
            }
            cc::READ_CLOCK => {
                let mut body = 0u64.to_be_bytes().to_vec();
                body.extend(self.clock.to_be_bytes());
                body.extend(1u32.to_be_bytes());
                body.extend(0u32.to_be_bytes());
                body.push(u8::from(self.safe));
                Ok(ok(None, &body, &[]))
            }
            cc::GET_CAPABILITY => {
                let _cap = p.u32_be().map_err(|_| rc::VALUE)?;
                let first = p.u32_be().map_err(|_| rc::VALUE)?;
                let count = p.u32_be().map_err(|_| rc::VALUE)?;
                let all = [
                    (0x200u32, if self.in_lockout { 1 << 9 } else { 0 }),
                    (0x20E, self.lockout_counter),
                    (0x20F, self.max_tries),
                    (0x210, 7200),
                ];
                let props: Vec<_> = all
                    .iter()
                    .filter(|(k, _)| *k >= first)
                    .take(count as usize)
                    .collect();
                let mut body = vec![0u8];
                body.extend(6u32.to_be_bytes());
                body.extend((props.len() as u32).to_be_bytes());
                for (k, v) in props {
                    body.extend(k.to_be_bytes());
                    body.extend(v.to_be_bytes());
                }
                Ok(ok(None, &body, &[]))
            }
            cc::CREATE_PRIMARY => {
                if h0 != 0x4000_0001 || sessions.len() != 1 {
                    return Err(rc::AUTH_MISSING);
                }
                let h = self.alloc(0x8000_0000);
                self.objects.insert(h, Obj::Primary);
                // outPublic, creationData, creationHash, ticket, name
                let public = self.srk_public();
                let mut body = (public.len() as u16).to_be_bytes().to_vec();
                body.extend(&public);
                body.extend([0, 0, 0, 0]);
                body.extend(0x8021u16.to_be_bytes());
                body.extend(0x4000_0001u32.to_be_bytes());
                body.extend([0, 0]);
                let mut name = [&[0u8, 0x0b][..], &sha256(&[&public])].concat();
                if self.quirk == Some(Quirk::WrongPrimaryName) {
                    name[9] ^= 1;
                }
                body.extend((name.len() as u16).to_be_bytes());
                body.extend(name);
                Ok(ok(Some(h), &body, &pw_sessions(sessions.len())))
            }
            cc::CREATE => {
                if !matches!(self.objects.get(&h0), Some(Obj::Primary)) {
                    return Err(rc::HANDLE);
                }
                let (sh, nonce_caller, attrs, mac) =
                    sessions.first().cloned().ok_or(rc::AUTH_MISSING)?;
                let mut params = params.to_vec();
                let hmac_session = if sh == 0x4000_0009 {
                    None
                } else {
                    let sess = self.sessions.get(&sh).cloned().ok_or(rc::HANDLE)?;
                    let name = [&[0u8, 0x0b][..], &sha256(&[&self.srk_public()])].concat();
                    let cp = sha256(&[&cc::CREATE.to_be_bytes(), &name, &params]);
                    let want = hmac(&sess.key, &[&cp, &nonce_caller, &sess.nonce_tpm, &[attrs]]);
                    if want[..] != mac[..] {
                        return Err(rc::AUTH_FAIL | 0x900);
                    }
                    if attrs & 0x20 != 0 {
                        if !sess.aes {
                            return Err(rc::VALUE);
                        }
                        let n = u16::from_be_bytes([params[0], params[1]]) as usize;
                        let kiv = st::cfb_key_iv(&sess.key, &nonce_caller, &sess.nonce_tpm);
                        st::cfb_decrypt(&kiv, params.get_mut(2..2 + n).ok_or(rc::VALUE)?);
                    }
                    Some((sh, sess, nonce_caller, attrs))
                };
                let mut p = Reader::new(&params);
                let sens = tpm2b(&mut p)?;
                let mut s = Reader::new(&sens);
                let auth = tpm2b(&mut s)?;
                let data = tpm2b(&mut s)?;
                let public = tpm2b(&mut p)?;
                let mut pr = Reader::new(&public);
                let ty = pr.u16_be().map_err(|_| rc::VALUE)?;
                let _name_alg = pr.u16_be().map_err(|_| rc::VALUE)?;
                let attrs_obj = pr.u32_be().map_err(|_| rc::VALUE)?;
                if ty != alg::KEYEDHASH
                    || attrs_obj & attr::USER_WITH_AUTH != 0
                    || attrs_obj & attr::NO_DA != 0
                {
                    return Err(rc::VALUE);
                }
                let private = self.wrap(&public, trim(&auth), &data);
                let mut body = private;
                body.extend((public.len() as u16).to_be_bytes());
                body.extend(&public);
                body.extend([0, 0, 0, 0]);
                body.extend(0x8021u16.to_be_bytes());
                body.extend(0x4000_0001u32.to_be_bytes());
                body.extend([0, 0]);
                match hmac_session {
                    None => Ok(ok(None, &body, &pw_sessions(sessions.len()))),
                    Some((sh, sess, nonce_caller, attrs)) => {
                        let sess_bytes =
                            self.respond(sh, &sess, cc::CREATE, &body, &nonce_caller, attrs);
                        Ok(ok(None, &body, &sess_bytes))
                    }
                }
            }
            cc::LOAD => {
                if !matches!(self.objects.get(&h0), Some(Obj::Primary)) {
                    return Err(rc::HANDLE);
                }
                let private = tpm2b(&mut p)?;
                let public = tpm2b(&mut p)?;
                let (auth, data) = self.unwrap(&public, &private).ok_or(rc::INTEGRITY)?;
                let mut pr = Reader::new(&public);
                pr.take(8).map_err(|_| rc::VALUE)?;
                let policy = tpm2b(&mut pr)?;
                let h = self.alloc(0x8000_0000);
                self.objects.insert(
                    h,
                    Obj::Sealed {
                        public: public.clone(),
                        auth,
                        policy,
                        data,
                    },
                );
                let mut name = [&[0u8, 0x0b][..], &sha256(&[&public])].concat();
                if self.quirk == Some(Quirk::WrongLoadName) {
                    name[5] ^= 1;
                }
                let mut body = (name.len() as u16).to_be_bytes().to_vec();
                body.extend(name);
                Ok(ok(Some(h), &body, &pw_sessions(sessions.len())))
            }
            cc::START_AUTH_SESSION => {
                let nonce_caller = tpm2b(&mut p)?;
                let salt_blob = tpm2b(&mut p)?;
                let session_type = p.u8().map_err(|_| rc::VALUE)?;
                let sym = p.u16_be().map_err(|_| rc::VALUE)?;
                let aes = sym == alg::AES;
                if aes {
                    let bits = p.u16_be().map_err(|_| rc::VALUE)?;
                    let mode = p.u16_be().map_err(|_| rc::VALUE)?;
                    if bits != 128 || mode != alg::CFB {
                        return Err(rc::VALUE);
                    }
                } else if sym != alg::NULL {
                    return Err(rc::VALUE);
                }
                if p.u16_be().map_err(|_| rc::VALUE)? != alg::SHA256 || session_type > 1 {
                    return Err(rc::VALUE);
                }
                let salt = if h0 == 0x4000_0007 {
                    Vec::new()
                } else {
                    if !matches!(self.objects.get(&h0), Some(Obj::Primary)) {
                        return Err(rc::HANDLE);
                    }
                    let mut sr = Reader::new(&salt_blob);
                    let x = tpm2b(&mut sr)?;
                    let y = tpm2b(&mut sr)?;
                    let (x, y): ([u8; 32], [u8; 32]) = (
                        x.try_into().map_err(|_| rc::VALUE)?,
                        y.try_into().map_err(|_| rc::VALUE)?,
                    );
                    let qe: AffinePoint = Option::from(AffinePoint::from_coordinates(
                        &FieldBytes::from(x),
                        &FieldBytes::from(y),
                    ))
                    .ok_or(rc::VALUE)?;
                    let z: [u8; 32] = (ProjectivePoint::from(qe) * *self.srk_scalar())
                        .to_affine()
                        .x()
                        .into();
                    let q = (ProjectivePoint::GENERATOR * *self.srk_scalar()).to_affine();
                    let qx: [u8; 32] = q.x().into();
                    st::kdfe(&z, b"SECRET", &x, &qx).to_vec()
                };
                let h = self.alloc(0x0300_0000);
                let nonce_tpm = self.nonce();
                let key = if salt.is_empty() {
                    Vec::new()
                } else {
                    let mut k = [0u8; 32];
                    st::kdfa(&salt, b"ATH", &nonce_tpm, &nonce_caller, &mut k);
                    k.to_vec()
                };
                self.sessions.insert(
                    h,
                    Session {
                        digest: [0; 32],
                        nonce_tpm,
                        auth_needed: false,
                        key,
                        aes,
                    },
                );
                let mut body = vec![0, 32];
                body.extend(nonce_tpm);
                Ok(ok(Some(h), &body, &[]))
            }
            cc::POLICY_PCR => {
                let _digest = tpm2b(&mut p)?;
                let sel = &params[2..];
                let mut sr = Reader::new(sel);
                sr.take(7).map_err(|_| rc::VALUE)?;
                let b = sr.take(3).map_err(|_| rc::VALUE)?;
                let mask = u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16;
                let mut vals = Sha256::new();
                for i in 0..24 {
                    if mask & (1 << i) != 0 {
                        vals.update(self.pcrs[i]);
                    }
                }
                let vals: [u8; 32] = vals.finalize().into();
                let s = self.sessions.get_mut(&h0).ok_or(rc::HANDLE)?;
                s.digest = sha256(&[&s.digest, &cc::POLICY_PCR.to_be_bytes(), sel, &vals]);
                Ok(ok(None, &[], &[]))
            }
            cc::POLICY_COUNTER_TIMER => {
                let operand = tpm2b(&mut p)?;
                let offset = p.u16_be().map_err(|_| rc::VALUE)?;
                let op = p.u16_be().map_err(|_| rc::VALUE)?;
                if offset != 8 || op != 0x0008 || operand.len() != 8 {
                    return Err(rc::VALUE);
                }
                let deadline = u64::from_be_bytes(operand.clone().try_into().unwrap());
                if self.clock >= deadline {
                    return Err(rc::POLICY);
                }
                let args = sha256(&[&operand, &offset.to_be_bytes(), &op.to_be_bytes()]);
                let s = self.sessions.get_mut(&h0).ok_or(rc::HANDLE)?;
                s.digest = sha256(&[&s.digest, &cc::POLICY_COUNTER_TIMER.to_be_bytes(), &args]);
                Ok(ok(None, &[], &[]))
            }
            cc::POLICY_AUTH_VALUE => {
                let s = self.sessions.get_mut(&h0).ok_or(rc::HANDLE)?;
                s.digest = sha256(&[&s.digest, &cc::POLICY_AUTH_VALUE.to_be_bytes()]);
                s.auth_needed = true;
                Ok(ok(None, &[], &[]))
            }
            cc::UNSEAL => {
                let Some(Obj::Sealed {
                    public,
                    auth,
                    policy,
                    data,
                }) = self.objects.get(&h0).cloned()
                else {
                    return Err(rc::HANDLE);
                };
                let (sh, nonce_caller, attrs, mac) =
                    sessions.first().cloned().ok_or(rc::AUTH_MISSING)?;
                let sess = self.sessions.get(&sh).cloned().ok_or(rc::HANDLE)?;
                if self.in_lockout {
                    return Err(rc::LOCKOUT);
                }
                if sess.digest[..] != policy[..] {
                    return Err(rc::POLICY_FAIL | 0x900);
                }
                let name = [&[0u8, 0x0b][..], &sha256(&[&public])].concat();
                let cp = sha256(&[&cc::UNSEAL.to_be_bytes(), &name]);
                let mut key = sess.key.clone();
                if sess.auth_needed {
                    key.extend(trim(&auth));
                }
                let want = hmac(&key, &[&cp, &nonce_caller, &sess.nonce_tpm, &[attrs]]);
                if want[..] != mac[..] {
                    self.lockout_counter += 1;
                    if self.lockout_counter >= self.max_tries {
                        self.in_lockout = true;
                    }
                    return Err(rc::AUTH_FAIL | 0x900);
                }
                if attrs & 0x20 != 0 || (attrs & 0x40 != 0 && !sess.aes) {
                    // Unseal has no command parameter to decrypt.
                    return Err(rc::VALUE);
                }
                let mut data = if self.quirk == Some(Quirk::ShortPayload) {
                    data[..31].to_vec()
                } else {
                    data.clone()
                };
                let new_nonce = self.nonce();
                if attrs & 0x40 != 0 && self.quirk != Some(Quirk::PlainUnseal) {
                    let kiv = st::cfb_key_iv(&key, &new_nonce, &nonce_caller);
                    st::cfb_encrypt(&kiv, &mut data);
                }
                let mut body = (data.len() as u16).to_be_bytes().to_vec();
                body.extend(&data);
                let rp = sha256(&[&0u32.to_be_bytes(), &cc::UNSEAL.to_be_bytes(), &body]);
                let rmac = hmac(&key, &[&rp, &new_nonce, &nonce_caller, &[attrs]]);
                if attrs & 1 == 0 {
                    self.sessions.remove(&sh);
                }
                let mut sess_bytes = vec![0, 32];
                sess_bytes.extend(new_nonce);
                sess_bytes.push(attrs);
                sess_bytes.extend([0, 32]);
                sess_bytes.extend(rmac);
                Ok(ok(None, &body, &sess_bytes))
            }
            cc::FLUSH_CONTEXT => {
                let h = p.u32_be().map_err(|_| rc::VALUE)?;
                if self.objects.remove(&h).is_none() && self.sessions.remove(&h).is_none() {
                    return Err(rc::HANDLE);
                }
                Ok(ok(None, &[], &[]))
            }
            _ => Err(rc::COMMAND_CODE),
        }
    }
}

impl FakeTpm {
    /// The response auth of an HMAC session; the session goes unless
    /// `continueSession`.
    fn respond(
        &mut self,
        sh: u32,
        sess: &Session,
        code: u32,
        body: &[u8],
        nonce_caller: &[u8],
        attrs: u8,
    ) -> Vec<u8> {
        let new_nonce = self.nonce();
        let rp = sha256(&[&0u32.to_be_bytes(), &code.to_be_bytes(), body]);
        let rmac = hmac(&sess.key, &[&rp, &new_nonce, nonce_caller, &[attrs]]);
        if attrs & 1 == 0 {
            self.sessions.remove(&sh);
        } else if let Some(s) = self.sessions.get_mut(&sh) {
            s.nonce_tpm = new_nonce;
        }
        let mut v = vec![0, 32];
        v.extend(new_nonce);
        v.push(attrs);
        v.extend([0, 32]);
        v.extend(rmac);
        v
    }
}

fn err(code: u32) -> Vec<u8> {
    let mut v = 0x8001u16.to_be_bytes().to_vec();
    v.extend(10u32.to_be_bytes());
    v.extend(code.to_be_bytes());
    v
}

/// Response auth area for `n` password sessions.
fn pw_sessions(n: usize) -> Vec<u8> {
    [0u8, 0, 1, 0, 0].repeat(n)
}

fn ok(handle: Option<u32>, params: &[u8], sessions: &[u8]) -> Vec<u8> {
    let tag: u16 = if sessions.is_empty() { 0x8001 } else { 0x8002 };
    let mut v = tag.to_be_bytes().to_vec();
    v.extend([0; 4]);
    v.extend(0u32.to_be_bytes());
    if let Some(h) = handle {
        v.extend(h.to_be_bytes());
    }
    if !sessions.is_empty() {
        v.extend((params.len() as u32).to_be_bytes());
    }
    v.extend(params);
    v.extend(sessions);
    let n = v.len() as u32;
    v[2..6].copy_from_slice(&n.to_be_bytes());
    v
}
