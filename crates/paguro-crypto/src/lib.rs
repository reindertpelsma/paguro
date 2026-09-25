//! The key derivation chain of DESIGN.md §6 ("Every standing rung requires the
//! passphrase"), exactly as specified there.
//!
//! Convention: `HMAC(key, message)`; the secret is always the key. Every rung's
//! `env` carries its own label so no two rungs can collide, and `pass_hash` never
//! appears raw in two places.
//!
//! There is deliberately **no authentication tag** on the wrapped VMK and **no
//! convenience check** anywhere in this crate: a wrong passphrase yields a
//! plausible-looking VMK, and the first real check is the FVEK unwrap against
//! metadata on the raw volume. An early "incorrect password" is an offline
//! oracle by another name.
//!
//! Symmetric primitives only. (The loader's one asymmetric operation, the
//! ECDH that salts its TPM sessions, is in `paguro-boot`'s TPM client; it
//! verifies no signatures.)
#![no_std]
#![forbid(unsafe_code)]

pub mod bitlocker;
pub mod tpm;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Bytes of every key in the chain: one SHA-256 / HMAC-SHA-256 output.
pub const KEY_LEN: usize = 32;
pub type Key = [u8; KEY_LEN];
/// Bytes of the per-seal and stretch salts.
pub const SALT_LEN: usize = 16;

/// BitLocker's key-stretch iteration count (0x100000).
pub const STRETCH_ITERATIONS: u64 = 0x10_0000;

fn hmac(key: &[u8], parts: &[&[u8]]) -> Key {
    // HMAC accepts keys of any length; this cannot fail.
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// BitLocker's password hash input: `SHA256(SHA256(UTF-16LE(password)))`.
pub fn user_password_hash(password: &str) -> Key {
    let mut inner = Sha256::new();
    for unit in password.encode_utf16() {
        inner.update(unit.to_le_bytes());
    }
    Sha256::digest(inner.finalize()).into()
}

/// BitLocker's stretch-key algorithm. The loader needs it anyway for the
/// recovery-password protector, so paguro reuses it instead of adding PBKDF2.
///
/// Each round hashes `{ last[32], initial[32], salt[16], counter u64 LE }`, per
/// libbde's specification. Must be checked against libbde test vectors before
/// any real volume is touched (§11 Q10).
pub fn bitlocker_stretch(initial: &Key, salt: &[u8; SALT_LEN], iterations: u64) -> Key {
    let mut last = [0u8; KEY_LEN];
    for i in 0..iterations {
        let mut h = Sha256::new();
        h.update(last);
        h.update(initial);
        h.update(salt);
        h.update(i.to_le_bytes());
        last = h.finalize().into();
    }
    last
}

/// What the TPM compares as the object's `authValue`. Domain-separated so that
/// sniffing the authorisation never yields `pass_hash` itself.
pub fn tpm_auth(pass_hash: &Key) -> Key {
    hmac(pass_hash, &[b"paguro/tpm-auth"])
}

/// `env` for the `tpm` rung: `D` is what the TPM unsealed, `B` the
/// boot-services-only firmware secret.
pub fn env_tpm(b: &Key, d: &[u8]) -> Key {
    hmac(b, &[b"paguro/env/tpm", d])
}

/// `env` for the one-shot `setupTPM` rung; binds the whole `paguro.ini` so a
/// rolled-back configuration cannot unlock the one rung with no PCR 12 check.
pub fn env_setup(s: &Key, ini_sha256: &Key) -> Key {
    hmac(s, &[b"paguro/env/setup", ini_sha256])
}

/// `env` for the `passphrase` rung — a public constant, deliberately. The root
/// gate is what stands between an unprivileged ESP reader and brute force.
pub fn env_passphrase() -> Key {
    Sha256::digest(b"paguro/env/passphrase").into()
}

/// Folds in the encrypted FVEK blob: bytes that exist only on the raw volume.
pub fn root_gate(env: &Key, salt: &[u8; SALT_LEN], encrypted_fvek_blob: &[u8]) -> Key {
    hmac(env, &[b"paguro/rootgate", salt, encrypted_fvek_blob])
}

/// The final wrapping key for every standing rung.
pub fn final_key(root_gate: &Key, pass_hash: &Key) -> Key {
    let offline_gate = hmac(pass_hash, &[b"paguro/offlineGate"]);
    hmac(root_gate, &[b"paguro/final", &offline_gate])
}

/// The install-time bootstrap wrapping carried in `Boot####` OptionalData.
pub fn bootstrap_key(pass_hash: &Key, salt: &[u8; SALT_LEN]) -> Key {
    hmac(pass_hash, &[b"paguro/bootstrap", salt])
}

/// VMK = key XOR wrapped. A one-time pad: both are 32 bytes, and the per-seal
/// salt keeps it one-time across a BitLocker re-key.
pub fn xor32(a: &Key, b: &Key) -> Key {
    let mut out = [0u8; KEY_LEN];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn xor_wrap_roundtrips() {
        let vmk = [7u8; 32];
        let key = final_key(&root_gate(&env_passphrase(), &[1; 16], b"fvek"), &[9; 32]);
        let wrapped = xor32(&vmk, &key);
        assert_eq!(xor32(&wrapped, &key), vmk);
    }

    #[test]
    fn rungs_are_domain_separated() {
        let secret = [3u8; 32];
        // Same secret, empty D vs the ini hash of zeros: labels must separate them.
        assert_ne!(env_tpm(&secret, &[]), env_setup(&secret, &[0; 32]));
        assert_ne!(tpm_auth(&secret), final_key(&secret, &secret));
    }

    #[test]
    fn every_factor_changes_the_key() {
        let base = |b: u8, d: u8, fvek: u8, pw: u8| {
            final_key(
                &root_gate(&env_tpm(&[b; 32], &[d; 32]), &[0; 16], &[fvek; 8]),
                &[pw; 32],
            )
        };
        let k = base(1, 2, 3, 4);
        assert_ne!(k, base(9, 2, 3, 4), "B must matter");
        assert_ne!(k, base(1, 9, 3, 4), "D must matter");
        assert_ne!(k, base(1, 2, 9, 4), "the root gate must matter");
        assert_ne!(k, base(1, 2, 3, 9), "the passphrase must matter");
    }

    #[test]
    fn stretch_is_deterministic_and_salted() {
        let pw = user_password_hash("correct horse");
        let a = bitlocker_stretch(&pw, &[0; 16], 1000);
        assert_eq!(a, bitlocker_stretch(&pw, &[0; 16], 1000));
        assert_ne!(a, bitlocker_stretch(&pw, &[1; 16], 1000));
    }
}
