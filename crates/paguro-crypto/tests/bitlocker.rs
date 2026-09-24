//! BitLocker primitives against published vectors (INTERFACES.md §12.2):
//! IEEE 1619-2007 XTS-AES-128/-256 and Wycheproof AES-256-CCM (12-byte
//! nonce, 16-byte tag, the shape BitLocker's key wrap uses).
#![allow(clippy::indexing_slicing)]

use paguro_crypto::bitlocker::{MacError, Xts, XtsError, ccm_unwrap, ccm_wrap};
use proptest::prelude::*;

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn records(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().collect())
}

#[test]
fn xts_ieee1619_vectors() {
    let mut n = 0;
    for r in records(include_str!("data/xts_vectors.txt")) {
        let (cipher, key, tweak, pt, ct) = (r[0], hex(r[1]), hex(r[2]), hex(r[3]), hex(r[4]));
        let xts = Xts::new(&key).unwrap();
        assert_eq!(
            xts.key_bits(),
            if cipher == "aes-128-xts" { 128 } else { 256 }
        );
        let unit = u128::from_le_bytes(tweak.try_into().unwrap());
        let mut buf = pt.clone();
        xts.encrypt(unit, &mut buf).unwrap();
        assert_eq!(buf, ct, "encrypt, vector {n}");
        xts.decrypt(unit, &mut buf).unwrap();
        assert_eq!(buf, pt, "decrypt, vector {n}");
        n += 1;
    }
    assert!(n >= 14, "only {n} vectors");
}

#[test]
fn xts_refusals() {
    for len in [0, 16, 31, 48, 63, 65, 128] {
        assert_eq!(Xts::new(&vec![1; len]).err(), Some(XtsError::KeyLength));
    }
    let x = Xts::new(&[1; 32]).unwrap();
    assert_eq!(x.decrypt(0, &mut []), Err(XtsError::DataLength));
    assert_eq!(x.decrypt(0, &mut [0; 17]), Err(XtsError::DataLength));
    assert_eq!(x.encrypt(0, &mut [0; 15]), Err(XtsError::DataLength));
}

#[test]
fn ccm_wycheproof_vectors() {
    let (mut ok, mut bad) = (0, 0);
    for r in records(include_str!("data/ccm_vectors.txt")) {
        let (key, nonce, msg, ct, tag, result) =
            (hex(r[1]), hex(r[2]), hex(r[3]), hex(r[4]), hex(r[5]), r[6]);
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let tag: [u8; 16] = tag.try_into().unwrap();
        let mut buf = ct.clone();
        let res = ccm_unwrap(&key, &nonce, &tag, &mut buf);
        if result == "valid" {
            assert_eq!(res, Ok(()), "tc {}", r[0]);
            assert_eq!(buf, msg, "tc {}", r[0]);
            let mut again = msg.clone();
            assert_eq!(ccm_wrap(&key, &nonce, &mut again), tag, "tc {}", r[0]);
            assert_eq!(again, ct);
            ok += 1;
        } else {
            assert_eq!(res, Err(MacError), "tc {}", r[0]);
            assert!(buf.iter().all(|&b| b == 0), "no candidate plaintext");
            bad += 1;
        }
    }
    assert!(ok >= 5 && bad >= 5, "{ok} valid, {bad} invalid");
}

proptest! {
    #[test]
    fn xts_roundtrip_and_tweak_separation(
        key in proptest::collection::vec(any::<u8>(), 64),
        wide in any::<bool>(),
        unit in any::<u64>(),
        four_k in any::<bool>(),
        seed in any::<u8>(),
    ) {
        let key = if wide { &key[..] } else { &key[..32] };
        let x = Xts::new(key).unwrap();
        let len = if four_k { 4096 } else { 512 };
        let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(seed)).collect();
        let mut a = pt.clone();
        x.encrypt(u128::from(unit), &mut a).unwrap();
        let mut b = pt.clone();
        x.encrypt(u128::from(unit) + 1, &mut b).unwrap();
        prop_assert_ne!(&a, &b);
        x.decrypt(u128::from(unit), &mut a).unwrap();
        prop_assert_eq!(a, pt);
    }

    #[test]
    fn ccm_roundtrip_and_any_bit_flip_fails(
        key in any::<[u8; 32]>(),
        nonce in any::<[u8; 12]>(),
        msg in proptest::collection::vec(any::<u8>(), 1..80),
        flip in any::<usize>(),
    ) {
        let mut ct = msg.clone();
        let tag = ccm_wrap(&key, &nonce, &mut ct);
        let mut pt = ct.clone();
        prop_assert_eq!(ccm_unwrap(&key, &nonce, &tag, &mut pt), Ok(()));
        prop_assert_eq!(&pt, &msg);
        let bit = flip % ((ct.len() + 16) * 8);
        let (mut ct2, mut tag2) = (ct.clone(), tag);
        if bit / 8 < ct2.len() { ct2[bit / 8] ^= 1 << (bit % 8) } else { tag2[bit / 8 - ct2.len()] ^= 1 << (bit % 8) }
        prop_assert_eq!(ccm_unwrap(&key, &nonce, &tag2, &mut ct2), Err(MacError));
    }
}
