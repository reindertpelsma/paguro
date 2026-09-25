//! TPM 2.0 session cryptography, SHA-256 and AES-128 only (TPM 2.0 Library
//! Part 1): `KDFa` (§11.4.10.2), `KDFe` (§11.4.10.3) and the CFB parameter
//! encryption of §21.3. The key agreement that feeds `KDFe` (ECDH with the
//! storage parent) lives with the TPM client in `paguro-boot`.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Block};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// SHA-256 digest bytes: one KDF output block.
const SHA256_LEN: usize = 32;
/// The byte that ends the label in both KDFs (TPM 2.0 Part 1 §11.4.10).
const LABEL_TERMINATOR: u8 = 0x00;
/// `KDFe` produces its single block with counter 1.
const KDFE_COUNTER: u32 = 1;
/// AES-128: key bytes and block bytes (the CFB feedback register).
const AES128_KEY_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;
/// Output of [`cfb_key_iv`]: the AES-128 key, then the IV.
pub const CFB_KEY_IV_LEN: usize = AES128_KEY_LEN + AES_BLOCK_LEN;
/// The `KDFa` label for parameter encryption keys (Part 1 §21.3).
const CFB_LABEL: &[u8] = b"CFB";

/// `KDFa(SHA-256, key, label, contextU, contextV, 8·out.len())`: HMAC in
/// counter mode, `counter || label || 0x00 || contextU || contextV || bits`.
pub fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], out: &mut [u8]) {
    let bits = u32::try_from(out.len().saturating_mul(u8::BITS as usize)).unwrap_or(u32::MAX);
    for (i, chunk) in out.chunks_mut(SHA256_LEN).enumerate() {
        let counter = u32::try_from(i + 1).unwrap_or(u32::MAX);
        // HMAC accepts keys of any length; this cannot fail.
        let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
            return;
        };
        m.update(&counter.to_be_bytes());
        m.update(label);
        m.update(&[LABEL_TERMINATOR]);
        m.update(context_u);
        m.update(context_v);
        m.update(&bits.to_be_bytes());
        let mut block: [u8; SHA256_LEN] = m.finalize().into_bytes().into();
        let n = chunk.len();
        chunk.copy_from_slice(block.get(..n).unwrap_or(&[]));
        block.zeroize();
    }
}

/// `KDFe(SHA-256, Z, label, partyUInfo, partyVInfo, 256)`: one SHA-256 block,
/// `counter(1) || Z || label || 0x00 || partyUInfo || partyVInfo`. The salt of
/// an ECC-salted session is `KDFe(Z, "SECRET", Qe.x, Qs.x)` (Annex C.6.1).
pub fn kdfe(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8]) -> [u8; SHA256_LEN] {
    let mut h = Sha256::new();
    h.update(KDFE_COUNTER.to_be_bytes());
    h.update(z);
    h.update(label);
    h.update([LABEL_TERMINATOR]);
    h.update(party_u);
    h.update(party_v);
    h.finalize().into()
}

/// The AES-128 key and IV of one encrypted parameter:
/// `KDFa(sessionValue, "CFB", nonceNewer, nonceOlder, 256)`, key first.
/// `sessionValue` is the session key followed by the authValue in use.
pub fn cfb_key_iv(
    session_value: &[u8],
    nonce_newer: &[u8],
    nonce_older: &[u8],
) -> [u8; CFB_KEY_IV_LEN] {
    let mut out = [0u8; CFB_KEY_IV_LEN];
    kdfa(session_value, CFB_LABEL, nonce_newer, nonce_older, &mut out);
    out
}

fn cfb(key_iv: &[u8; CFB_KEY_IV_LEN], data: &mut [u8], decrypt: bool) {
    let (key, iv) = key_iv.split_at(AES128_KEY_LEN);
    let Ok(aes) = Aes128::new_from_slice(key) else {
        return;
    };
    let mut reg = Block::default();
    reg.copy_from_slice(iv);
    for chunk in data.chunks_mut(AES_BLOCK_LEN) {
        let mut ks = reg;
        aes.encrypt_block(&mut ks);
        let n = chunk.len();
        if decrypt {
            if let Some(r) = reg.get_mut(..n) {
                r.copy_from_slice(chunk);
            }
        }
        for (c, k) in chunk.iter_mut().zip(ks.iter()) {
            *c ^= k;
        }
        if !decrypt {
            if let Some(r) = reg.get_mut(..n) {
                r.copy_from_slice(chunk);
            }
        }
        ks.zeroize();
    }
    reg.zeroize();
}

/// AES-128-CFB (full-block feedback, as TPM parameter encryption uses it)
/// in place. A trailing partial block uses the leading keystream bytes.
pub fn cfb_encrypt(key_iv: &[u8; CFB_KEY_IV_LEN], data: &mut [u8]) {
    cfb(key_iv, data, false);
}

pub fn cfb_decrypt(key_iv: &[u8; CFB_KEY_IV_LEN], data: &mut [u8]) {
    cfb(key_iv, data, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let mut o = [0u8; N];
        for (i, b) in o.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }

    /// NIST SP 800-38A F.3.13 (CFB128-AES128.Encrypt), blocks 1–2, and the
    /// partial final block of the same stream.
    #[test]
    fn cfb_matches_sp800_38a() {
        let mut kiv = [0u8; 32];
        kiv[..16].copy_from_slice(&unhex::<16>("2b7e151628aed2a6abf7158809cf4f3c"));
        kiv[16..].copy_from_slice(&unhex::<16>("000102030405060708090a0b0c0d0e0f"));
        let plain: [u8; 32] =
            unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let want: [u8; 32] =
            unhex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
        let mut d = plain;
        cfb_encrypt(&kiv, &mut d);
        assert_eq!(d, want);
        cfb_decrypt(&kiv, &mut d);
        assert_eq!(d, plain);
        let mut part = plain;
        cfb_encrypt(&kiv, &mut part[..21]);
        assert_eq!(part[..21], want[..21]);
        cfb_decrypt(&kiv, &mut part[..21]);
        assert_eq!(part, plain);
    }

    #[test]
    fn kdfa_is_hmac_in_counter_mode() {
        let mut two = [0u8; 48];
        kdfa(b"k", b"ATH", b"u", b"v", &mut two);
        let block = |ctr: u32, bits: u32| -> [u8; 32] {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"k").unwrap();
            for p in [
                &ctr.to_be_bytes()[..],
                b"ATH\0",
                b"u",
                b"v",
                &bits.to_be_bytes(),
            ] {
                m.update(p);
            }
            m.finalize().into_bytes().into()
        };
        assert_eq!(two[..32], block(1, 384));
        assert_eq!(two[32..], block(2, 384)[..16]);
        let mut one = [0u8; 32];
        kdfa(b"k", b"ATH", b"u", b"v", &mut one);
        assert_eq!(one, block(1, 256));
        assert_ne!(cfb_key_iv(b"k", b"a", b"b"), cfb_key_iv(b"k", b"b", b"a"));
        let e = kdfe(b"z", b"SECRET", b"u", b"v");
        assert_eq!(
            e,
            <[u8; 32]>::from(Sha256::digest(b"\0\0\0\x01zSECRET\0uv"))
        );
    }
}
