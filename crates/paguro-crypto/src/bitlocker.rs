//! BitLocker's symmetric primitives: the AES-CCM key wrap (VMK, FVEK,
//! metadata validation) and XTS-AES over one data unit.
//!
//! Both are thin: CCM is RustCrypto's `ccm` over `aes`; XTS is the IEEE
//! 1619-2007 construction written out here (no ciphertext stealing: a BitLocker
//! data unit is a whole sector, 512 or 4096 bytes). The format around them —
//! where the nonce and tag sit in an FVE entry — is `paguro-core::bde`'s.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use ccm::aead::AeadInOut;
use ccm::aead::array::Array;
use ccm::consts::{U12, U16};

/// BitLocker's key wrap: AES-256-CCM, 12-byte nonce, 16-byte tag, no
/// associated data.
type Aes256Ccm = ccm::Ccm<Aes256, U16, U12>;

pub const CCM_NONCE_LEN: usize = 12;
pub const CCM_TAG_LEN: usize = 16;
/// AES-256 key bytes: the CCM wrapping key.
pub const CCM_KEY_LEN: usize = 32;

/// AES block bytes, and so XTS's tweak and the unit of its data.
const AES_BLOCK_LEN: usize = 16;
/// XTS keys (IEEE 1619-2007 §5.1): K1 ‖ K2, each an AES-128 or AES-256 key.
const AES128_KEY_LEN: usize = 16;
const AES256_KEY_LEN: usize = 32;
pub const XTS_128_KEY_LEN: usize = 2 * AES128_KEY_LEN;
pub const XTS_256_KEY_LEN: usize = 2 * AES256_KEY_LEN;
/// Multiplication by α in GF(2^128): the reduction byte for
/// x^128 + x^7 + x^2 + x + 1 (IEEE 1619-2007 §5.2), and the bit shifted out.
const GF128_REDUCTION: u8 = 0x87;
const CARRY_SHIFT: u32 = 7;

/// The CCM tag did not verify: wrong key, or the entry was altered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacError;

/// Decrypt `data` in place and verify `tag`. On failure `data` is left
/// unmodified-or-garbage and must not be used.
pub fn ccm_unwrap(
    key: &[u8; CCM_KEY_LEN],
    nonce: &[u8; CCM_NONCE_LEN],
    tag: &[u8; CCM_TAG_LEN],
    data: &mut [u8],
) -> Result<(), MacError> {
    let c = Aes256Ccm::new(&Array::from(*key));
    let r = c.decrypt_inout_detached(&Array::from(*nonce), &[], data.into(), &Array::from(*tag));
    if r.is_err() {
        // `ccm` zeroes nothing on failure; do it so a caller that ignores the
        // error still sees no candidate plaintext.
        data.fill(0);
        return Err(MacError);
    }
    Ok(())
}

/// Encrypt `data` in place and return the tag (the test writer's side).
pub fn ccm_wrap(
    key: &[u8; CCM_KEY_LEN],
    nonce: &[u8; CCM_NONCE_LEN],
    data: &mut [u8],
) -> [u8; CCM_TAG_LEN] {
    let c = Aes256Ccm::new(&Array::from(*key));
    match c.encrypt_inout_detached(&Array::from(*nonce), &[], data.into()) {
        Ok(t) => t.into(),
        // Only a message longer than 2^24 bytes (L = 3) fails; keys are tiny.
        Err(_) => [0; CCM_TAG_LEN],
    }
}

#[allow(clippy::large_enum_variant)] // no_std: no Box; the difference is 512 bytes
enum Keys {
    X128(Aes128, Aes128),
    X256(Aes256, Aes256),
}

/// XTS-AES-128 or -256 over whole data units; the tweak is the data unit's
/// index as a 128-bit little-endian integer (dm-crypt's `plain64`, BitLocker's
/// sector number from the volume start).
pub struct Xts {
    keys: Keys,
}

/// Why [`Xts`] refused a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XtsError {
    /// Not a 32- (XTS-AES-128) or 64-byte (XTS-AES-256) key.
    KeyLength,
    /// The data is not a whole number of 16-byte blocks, or is empty.
    DataLength,
}

fn mul_alpha(t: &mut [u8; AES_BLOCK_LEN]) {
    let mut carry = 0u8;
    for b in t.iter_mut() {
        let next = *b >> CARRY_SHIFT;
        *b = (*b << 1) | carry;
        carry = next;
    }
    if let Some(b) = t.first_mut() {
        *b ^= GF128_REDUCTION & 0u8.wrapping_sub(carry);
    }
}

fn xor_tweaks(first: [u8; AES_BLOCK_LEN], blocks: &mut [Block]) {
    let mut t = first;
    for b in blocks {
        for (x, y) in b.iter_mut().zip(t.iter()) {
            *x ^= y;
        }
        mul_alpha(&mut t);
    }
}

impl Xts {
    /// `key` = K1 ‖ K2 (data key, then tweak key), as BitLocker stores the
    /// FVEK and dm-crypt takes it.
    pub fn new(key: &[u8]) -> Result<Xts, XtsError> {
        let keys = match key.len() {
            XTS_128_KEY_LEN => {
                let (a, b) = key.split_at(AES128_KEY_LEN);
                Keys::X128(
                    Aes128::new_from_slice(a).map_err(|_| XtsError::KeyLength)?,
                    Aes128::new_from_slice(b).map_err(|_| XtsError::KeyLength)?,
                )
            }
            XTS_256_KEY_LEN => {
                let (a, b) = key.split_at(AES256_KEY_LEN);
                Keys::X256(
                    Aes256::new_from_slice(a).map_err(|_| XtsError::KeyLength)?,
                    Aes256::new_from_slice(b).map_err(|_| XtsError::KeyLength)?,
                )
            }
            _ => return Err(XtsError::KeyLength),
        };
        Ok(Xts { keys })
    }

    /// Bits of key: 128 or 256.
    pub fn key_bits(&self) -> u32 {
        match self.keys {
            Keys::X128(..) => (AES128_KEY_LEN * u8::BITS as usize) as u32,
            Keys::X256(..) => (AES256_KEY_LEN * u8::BITS as usize) as u32,
        }
    }

    fn first_tweak(&self, unit: u128) -> [u8; AES_BLOCK_LEN] {
        let mut t = Block::from(unit.to_le_bytes());
        match &self.keys {
            Keys::X128(_, k2) => k2.encrypt_block(&mut t),
            Keys::X256(_, k2) => k2.encrypt_block(&mut t),
        }
        t.into()
    }

    fn blocks(data: &mut [u8]) -> Result<&mut [Block], XtsError> {
        let (blocks, rest) = Block::slice_as_chunks_mut(data);
        if !rest.is_empty() || blocks.is_empty() {
            return Err(XtsError::DataLength);
        }
        Ok(blocks)
    }

    /// Decrypt one data unit in place.
    pub fn decrypt(&self, unit: u128, data: &mut [u8]) -> Result<(), XtsError> {
        let blocks = Self::blocks(data)?;
        let t = self.first_tweak(unit);
        xor_tweaks(t, blocks);
        match &self.keys {
            Keys::X128(k1, _) => k1.decrypt_blocks(blocks),
            Keys::X256(k1, _) => k1.decrypt_blocks(blocks),
        }
        xor_tweaks(t, blocks);
        Ok(())
    }

    /// Encrypt one data unit in place.
    pub fn encrypt(&self, unit: u128, data: &mut [u8]) -> Result<(), XtsError> {
        let blocks = Self::blocks(data)?;
        let t = self.first_tweak(unit);
        xor_tweaks(t, blocks);
        match &self.keys {
            Keys::X128(k1, _) => k1.encrypt_blocks(blocks),
            Keys::X256(k1, _) => k1.encrypt_blocks(blocks),
        }
        xor_tweaks(t, blocks);
        Ok(())
    }
}
