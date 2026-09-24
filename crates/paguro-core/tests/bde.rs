//! `paguro_core::bde` over synthetic metadata: every error variant, the
//! sector map against a model, and never-panic properties (INTERFACES.md
//! §12). Real Windows-made volumes are `paguro-boot/tests/bde.rs`.
#![allow(clippy::indexing_slicing)]

use paguro_core::bde::*;
use proptest::prelude::*;

const MB: u64 = 1 << 20;

fn entry(et: u16, vt: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ((8 + data.len()) as u16).to_le_bytes().to_vec();
    v.extend(et.to_le_bytes());
    v.extend(vt.to_le_bytes());
    v.extend(1u16.to_le_bytes());
    v.extend(data);
    v
}

fn ccm(ct_len: usize, fill: u8) -> Vec<u8> {
    let mut d = vec![fill; 12 + 16];
    d.extend(vec![fill ^ 0x5a; ct_len]);
    d
}

fn vmk(protection: u16, nested: &[u8]) -> Vec<u8> {
    let mut d = vec![protection as u8; 16];
    d.extend(0u64.to_le_bytes());
    d.extend(0u16.to_le_bytes());
    d.extend(protection.to_le_bytes());
    d.extend(nested);
    entry(entry::VMK, value::VMK, &d)
}

fn stretch() -> Vec<u8> {
    let mut d = 0x1001u32.to_le_bytes().to_vec();
    d.extend([7u8; 16]);
    entry(0, value::STRETCH_KEY, &d)
}

fn password() -> Vec<u8> {
    let mut n = stretch();
    n.extend(entry(0, value::AES_CCM, &ccm(44, 1)));
    vmk(0x2000, &n)
}

fn clear() -> Vec<u8> {
    let mut k = 0x2000u32.to_le_bytes().to_vec();
    k.extend([9u8; 32]);
    let mut n = entry(0, value::KEY, &k);
    n.extend(entry(0, value::AES_CCM, &ccm(44, 2)));
    vmk(0x0000, &n)
}

fn vhb(off: u64, len: u64) -> Vec<u8> {
    let mut d = off.to_le_bytes().to_vec();
    d.extend(len.to_le_bytes());
    entry(entry::VOLUME_HEADER_BLOCK, value::OFFSET_AND_SIZE, &d)
}

#[derive(Clone, Debug)]
struct V {
    bps: u16,
    size: u64,
    md: [u64; 3],
    reloc: u64,
    vh_sectors: u32,
    enc: u64,
    state: (u16, u16),
    conv: u32,
    cipher: u16,
    version: u16,
    val_version: u16,
    id: [u8; 16],
    entries: Vec<u8>,
}

impl V {
    fn new() -> V {
        let reloc = 17 * MB;
        let mut entries = entry(entry::DESCRIPTION, value::UNICODE, b"t\0e\0s\0t\0\0\0");
        entries.extend(password());
        entries.extend(clear());
        entries.extend(entry(entry::FVEK, value::AES_CCM, &ccm(44, 3)));
        entries.extend(vhb(reloc, 8192));
        V {
            bps: 512,
            size: 64 * MB,
            md: [16 * MB, 32 * MB, 48 * MB],
            reloc,
            vh_sectors: 16,
            enc: 64 * MB,
            state: (4, 4),
            conv: 0,
            cipher: 0x8004,
            version: 2,
            val_version: 2,
            id: GUID_NORMAL,
            entries,
        }
    }

    fn sector0(&self) -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        s[3..11].copy_from_slice(SIGNATURE);
        s[11..13].copy_from_slice(&self.bps.to_le_bytes());
        s[160..176].copy_from_slice(&self.id);
        for (i, m) in self.md.iter().enumerate() {
            s[176 + 8 * i..184 + 8 * i].copy_from_slice(&m.to_le_bytes());
        }
        s[510] = 0x55;
        s[511] = 0xaa;
        s
    }

    fn block(&self) -> Vec<u8> {
        let msize = (48 + self.entries.len()) as u32;
        let bsize = (64 + msize as usize).div_ceil(16) * 16;
        let mut b = SIGNATURE.to_vec();
        b.extend(((bsize / 16) as u16).to_le_bytes());
        b.extend(self.version.to_le_bytes());
        b.extend(self.state.0.to_le_bytes());
        b.extend(self.state.1.to_le_bytes());
        b.extend(self.enc.to_le_bytes());
        b.extend(self.conv.to_le_bytes());
        b.extend(self.vh_sectors.to_le_bytes());
        for m in self.md {
            b.extend(m.to_le_bytes());
        }
        b.extend(self.reloc.to_le_bytes());
        for v in [msize, 1, 48, msize] {
            b.extend(v.to_le_bytes());
        }
        b.extend([0xab; 16]);
        b.extend(5u32.to_le_bytes());
        b.extend(self.cipher.to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(0u64.to_le_bytes());
        b.extend(&self.entries);
        b.resize(bsize, 0);
        b
    }

    fn region(&self) -> Vec<u8> {
        let b = self.block();
        let mut r = b.clone();
        r.extend(((REGION_SIZE as usize - b.len()) as u16).to_le_bytes());
        r.extend(self.val_version.to_le_bytes());
        r.extend(crc32(&b).to_le_bytes());
        if self.val_version == 2 {
            r.extend(entry(0, value::AES_CCM, &ccm(44, 4)));
        }
        r.resize(REGION_SIZE as usize, 0);
        r
    }

    fn header(&self) -> VolumeHeader {
        parse_volume_header(&self.sector0()).unwrap()
    }
}

/// Parse `v` all the way to a layout.
fn full(v: &V) -> Result<Layout> {
    let hdr = parse_volume_header(&v.sector0())?;
    let r = v.region();
    let m = Metadata::parse(cross_check([&r, &r, &r], &hdr)?)?;
    Layout::new(&hdr, &m, v.size)
}

fn meta_err(v: &V) -> BdeError {
    let r = v.region();
    let hdr = v.header();
    match cross_check([&r, &r, &r], &hdr).and_then(Metadata::parse) {
        Ok(_) => panic!("accepted"),
        Err(e) => e,
    }
}

#[test]
fn crc32_check_value() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn a_well_formed_volume_parses() {
    let v = V::new();
    let hdr = v.header();
    assert_eq!(hdr.kind, HeaderKind::Standard);
    assert!(!hdr.eow);
    assert_eq!(hdr.bytes_per_sector, 512);
    let r = v.region();
    let b = cross_check([&r, &r, &r], &hdr).unwrap();
    assert_eq!(b.cipher, Cipher::XtsAes128);
    assert!(b.validation.is_some());
    let m = Metadata::parse(b).unwrap();
    let kinds: Vec<_> = m.protectors().map(|p| p.kind).collect();
    assert_eq!(kinds, [ProtectorKind::Password, ProtectorKind::ClearKey]);
    let pw = m.of_kind(ProtectorKind::Password).next().unwrap();
    assert_eq!(pw.salt, Some([7; 16]));
    assert_eq!(pw.wrapped_vmk.unwrap().ciphertext.len(), 44);
    let ck = m.of_kind(ProtectorKind::ClearKey).next().unwrap();
    assert_eq!(ck.clear_key, Some([9; 32]));
    assert_eq!(m.volume_header, (17 * MB, 8192));
    assert_eq!(m.description, Some(&b"t\0e\0s\0t\0\0\0"[..]));
    let l = Layout::new(&hdr, &m, v.size).unwrap();
    assert!(!l.partial);
    let h = l.fve_layout();
    assert_eq!(h.metadata_offsets, v.md);
    assert_eq!(h.region_size, 0x10000);
    assert_eq!(h.boot_sector_reloc_offset, 17 * MB);
    assert_eq!(h.boot_sector_reloc_sectors, 16);
    assert_eq!(h.encrypted_size, 64 * MB);
    assert_eq!(
        l.reserved_ranges(),
        [
            (0, 16),
            (17 * MB / 512, 16),
            (16 * MB / 512, 128),
            (32 * MB / 512, 128),
            (48 * MB / 512, 128)
        ]
    );
}

#[test]
fn to_go_and_used_space_only_are_identified() {
    let v = V::new();
    let mut s = v.sector0();
    s[3..11].copy_from_slice(TOGO_SIGNATURE);
    s[424..440].copy_from_slice(&GUID_NORMAL);
    for (i, m) in v.md.iter().enumerate() {
        s[440 + 8 * i..448 + 8 * i].copy_from_slice(&m.to_le_bytes());
    }
    let h = parse_volume_header(&s).unwrap();
    assert_eq!(h.kind, HeaderKind::ToGo);
    assert_eq!(h.metadata_offsets, v.md);
    // A Windows-formatted FAT32 without the identifier is just FAT32.
    s[424..440].fill(0);
    assert_eq!(parse_volume_header(&s), Err(BdeError::NotBitLocker));

    let mut e = V::new();
    e.id = GUID_EOW;
    assert!(e.header().eow);
    assert_eq!(full(&e), Err(BdeError::UsedSpaceOnly));
}

#[test]
fn volume_header_refusals() {
    let v = V::new();
    let good = v.sector0();
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut s = good.clone();
        f(&mut s);
        parse_volume_header(&s)
    };
    assert_eq!(
        with(&|s| s[3..11].copy_from_slice(b"NTFS    ")),
        Err(BdeError::NotBitLocker)
    );
    assert_eq!(
        parse_volume_header(&good[..100]),
        Err(BdeError::NotBitLocker)
    );
    assert_eq!(parse_volume_header(&[]), Err(BdeError::NotBitLocker));
    assert_eq!(
        with(&|s| {
            s[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
            s[160..176].fill(0);
        }),
        Err(BdeError::Vista)
    );
    assert_eq!(with(&|s| s[160] ^= 1), Err(BdeError::UnknownIdentifier));
    assert_eq!(with(&|s| s[511] = 0), Err(BdeError::BootSignature));
    assert_eq!(
        with(&|s| s[11..13].copy_from_slice(&1024u16.to_le_bytes())),
        Err(BdeError::SectorSize(1024))
    );
    assert_eq!(
        with(&|s| s[11..13].copy_from_slice(&0u16.to_le_bytes())),
        Err(BdeError::SectorSize(0))
    );
    assert_eq!(
        with(&|s| s[176..184].fill(0)),
        Err(BdeError::MetadataOffset)
    );
    assert_eq!(with(&|s| s[176] = 1), Err(BdeError::MetadataOffset));
    assert_eq!(
        with(&|s| {
            let a: [u8; 8] = s[176..184].try_into().unwrap();
            s[184..192].copy_from_slice(&a);
        }),
        Err(BdeError::MetadataOffset)
    );
}

#[test]
fn block_refusals() {
    let v = V::new();
    let hdr = v.header();
    let good = v.region();
    let one = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut r = good.clone();
        f(&mut r);
        parse_block(&r, 1, &hdr).map(|_| ())
    };
    let bsize = v.block().len();
    let fix_crc = |r: &mut Vec<u8>| {
        let c = crc32(&r[..bsize]);
        r[bsize + 4..bsize + 8].copy_from_slice(&c.to_le_bytes());
    };
    assert_eq!(one(&|_| {}), Ok(()));
    assert_eq!(one(&|r| r[0] = b'x'), Err(BdeError::BlockSignature(1)));
    assert_eq!(
        parse_block(&[], 2, &hdr).err(),
        Some(BdeError::BlockSignature(2))
    );
    assert_eq!(
        one(&|r| {
            r[10] = 1;
            fix_crc(r)
        }),
        Err(BdeError::BlockVersion(1))
    );
    assert_eq!(
        one(&|r| r[8..10].copy_from_slice(&2u16.to_le_bytes())),
        Err(BdeError::BlockSize)
    );
    assert_eq!(
        one(&|r| r[8..10].copy_from_slice(&0x1000u16.to_le_bytes())),
        Err(BdeError::BlockSize)
    );
    assert_eq!(
        parse_block(&good[..bsize + 4], 0, &hdr).err(),
        Some(BdeError::BlockSize)
    );
    assert_eq!(
        one(&|r| {
            r[40] ^= 0x10;
            fix_crc(r)
        }),
        Err(BdeError::BlockLocation)
    );
    assert_eq!(one(&|r| r[bsize + 2] = 3), Err(BdeError::Validation(1)));
    assert_eq!(
        one(&|r| r[bsize..bsize + 2].copy_from_slice(&4u16.to_le_bytes())),
        Err(BdeError::Validation(1))
    );
    assert_eq!(one(&|r| r[bsize + 8] = 0x20), Err(BdeError::Validation(1)));
    assert_eq!(one(&|r| r[bsize + 12] = 1), Err(BdeError::Validation(1)));
    assert_eq!(one(&|r| r[bsize - 20] ^= 1), Err(BdeError::Checksum(1)));
    assert_eq!(one(&|r| r[bsize + 4] ^= 1), Err(BdeError::Checksum(1)));
    for (at, val) in [(64usize, 0x7fff_ffffu32), (68, 2), (72, 40), (76, 1)] {
        assert_eq!(
            one(&|r| {
                r[at..at + 4].copy_from_slice(&val.to_le_bytes());
                fix_crc(r)
            }),
            Err(BdeError::MetadataHeader),
            "field at {at}"
        );
    }
    // Validation v1 (Windows 7): CRC only.
    let mut w7 = V::new();
    w7.val_version = 1;
    let r = w7.region();
    assert_eq!(parse_block(&r, 0, &hdr).unwrap().validation, None);
}

#[test]
fn copies_are_a_cross_check_not_a_vote() {
    let v = V::new();
    let hdr = v.header();
    let a = v.region();
    let mut w = v.clone();
    w.entries[4] = b'T'; // the description, "Test"
    let b = w.region(); // CRC-valid on its own
    assert!(parse_block(&b, 0, &hdr).is_ok());
    assert_eq!(
        cross_check([&a, &a, &b], &hdr).err(),
        Some(BdeError::CopiesDisagree)
    );
    assert_eq!(
        cross_check([&a, &b, &b], &hdr).err(),
        Some(BdeError::CopiesDisagree)
    );
    assert_eq!(
        cross_check([&b, &a, &a], &hdr).err(),
        Some(BdeError::CopiesDisagree)
    );
    // A copy that is merely damaged is named by its CRC.
    let mut c = a.clone();
    c[200] ^= 0xff;
    assert_eq!(
        cross_check([&a, &c, &a], &hdr).err(),
        Some(BdeError::Checksum(1))
    );
    assert_eq!(
        cross_check([&c, &a, &a], &hdr).err(),
        Some(BdeError::Checksum(0))
    );
    // Bytes past the validation entry are not part of the agreement.
    let mut d = a.clone();
    d[60000] = 1;
    assert!(cross_check([&a, &a, &d], &hdr).is_ok());
}

#[test]
fn entry_schema_refusals() {
    let base = V::new();
    let fvek = entry(entry::FVEK, value::AES_CCM, &ccm(44, 3));
    let with = |extra: &[u8], drop_fvek: bool, drop_vhb: bool| {
        let mut v = base.clone();
        let mut e = entry(entry::DESCRIPTION, value::UNICODE, b"x\0");
        e.extend(password());
        if !drop_fvek {
            e.extend(&fvek);
        }
        if !drop_vhb {
            e.extend(vhb(v.reloc, 8192));
        }
        e.extend(extra);
        v.entries = e;
        meta_err(&v)
    };
    assert_eq!(with(&[], true, false), BdeError::MissingFvek);
    assert_eq!(with(&[], false, true), BdeError::MissingVolumeHeader);
    assert_eq!(with(&fvek, false, false), BdeError::DuplicateFvek);
    assert_eq!(
        with(&vhb(1, 2), false, false),
        BdeError::DuplicateVolumeHeader
    );
    assert_eq!(
        with(
            &entry(entry::VMK, value::AES_CCM, &ccm(44, 0)),
            false,
            false
        ),
        BdeError::Schema {
            entry_type: 2,
            value_type: 5
        }
    );
    assert_eq!(
        with(&entry(entry::FVEK, value::KEY, &[0; 36]), false, false),
        BdeError::Schema {
            entry_type: 3,
            value_type: 1
        }
    );
    assert_eq!(
        with(
            &entry(entry::VOLUME_HEADER_BLOCK, value::KEY, &[0; 16]),
            false,
            false
        ),
        BdeError::Schema {
            entry_type: 0xf,
            value_type: 1
        }
    );
    assert_eq!(
        with(
            &entry(entry::DESCRIPTION, value::KEY, &[0; 4]),
            false,
            false
        ),
        BdeError::Schema {
            entry_type: 7,
            value_type: 1
        }
    );
    assert_eq!(with(&[4, 0, 0, 0], false, false), BdeError::EntryTooSmall);
    assert_eq!(
        with(&[200, 0, 0, 0, 0, 0, 0, 0], false, false),
        BdeError::EntryOverruns
    );
    assert_eq!(with(&[9], false, false), BdeError::EntryOverruns);
    assert_eq!(with(&[0, 0, 1, 0], false, false), BdeError::TrailingGarbage);
    // A zero terminator followed by zeros is fine; unknown entries skipped.
    let mut v = base.clone();
    v.entries.extend(entry(0x55, 0x66, &[1, 2, 3]));
    v.entries.extend([0; 6]);
    assert!(full(&v).is_ok());
    // Floods.
    let flood: Vec<u8> = (0..MAX_ENTRIES).flat_map(|_| entry(0x55, 0, &[])).collect();
    assert_eq!(with(&flood, false, false), BdeError::TooManyEntries);
    let vmks: Vec<u8> = (0..MAX_PROTECTORS).flat_map(|_| password()).collect();
    assert_eq!(with(&vmks, false, false), BdeError::TooManyProtectors);
}

#[test]
fn protector_schema_refusals() {
    let base = V::new();
    let with = |p: Vec<u8>| {
        let mut v = base.clone();
        let mut e = p;
        e.extend(entry(entry::FVEK, value::AES_CCM, &ccm(44, 3)));
        e.extend(vhb(v.reloc, 8192));
        v.entries = e;
        meta_err(&v)
    };
    let ccm_e = entry(0, value::AES_CCM, &ccm(44, 1));
    // Password: exactly one stretch key and one wrapped VMK.
    assert_eq!(with(vmk(0x2000, &ccm_e)), BdeError::BadVmk);
    let mut two = stretch();
    two.extend(&ccm_e);
    two.extend(&ccm_e);
    assert_eq!(with(vmk(0x0800, &two)), BdeError::BadVmk);
    // Clear key: a key and a wrapped VMK.
    assert_eq!(with(vmk(0x0000, &ccm_e)), BdeError::BadVmk);
    let mut short_key = entry(0, value::KEY, &[0; 4 + 16]);
    short_key.extend(&ccm_e);
    assert_eq!(with(vmk(0x0000, &short_key)), BdeError::BadKey);
    assert_eq!(
        with(vmk(0x0000, &entry(0, value::KEY, &[0; 3]))),
        BdeError::BadKey
    );
    // Startup key: a wrapped VMK.
    assert_eq!(with(vmk(0x0200, &[])), BdeError::BadVmk);
    let mut st = entry(0, value::STRETCH_KEY, &[0; 10]);
    st.extend(&ccm_e);
    assert_eq!(with(vmk(0x2000, &st)), BdeError::BadStretchKey);
    let mut n = stretch();
    n.extend(entry(0, value::AES_CCM, &[0; 20]));
    assert_eq!(with(vmk(0x2000, &n)), BdeError::BadCcm);
    let mut n = stretch();
    n.extend(entry(0, value::AES_CCM, &ccm(MAX_WRAPPED + 1, 0)));
    assert_eq!(with(vmk(0x2000, &n)), BdeError::BadCcm);
    assert_eq!(with(vmk(0x2000, &[1, 2, 3])), BdeError::EntryOverruns);
    assert_eq!(
        with(entry(entry::VMK, value::VMK, &[0; 20])),
        BdeError::BadVmk
    );
    // Kinds the loader never acts on are listed, unconstrained, and inert.
    let mut v = base.clone();
    v.entries.extend(vmk(0x0100, &entry(0, 6, &[1; 40])));
    v.entries.extend(vmk(0x0500, &ccm_e));
    v.entries.extend(vmk(0x1000, &[]));
    v.entries.extend(vmk(0x4242, &ccm_e));
    let r = v.region();
    let m = Metadata::parse(cross_check([&r, &r, &r], &v.header()).unwrap()).unwrap();
    let odd: Vec<_> = m
        .protectors()
        .skip(2)
        .map(|p| (p.kind, p.wrapped_vmk, p.kind.usable()))
        .collect();
    assert_eq!(
        odd,
        [
            (ProtectorKind::Tpm, None, false),
            (ProtectorKind::TpmPin, None, false),
            (ProtectorKind::SmartCard, None, false),
            (ProtectorKind::Other(0x4242), None, false)
        ]
    );
}

#[test]
fn key_entries() {
    let mut k = 0x8004u32.to_le_bytes().to_vec();
    k.extend([1; 32]);
    let e = entry(0, value::KEY, &k);
    let p = parse_key(&e).unwrap();
    assert_eq!((p.method, p.key), (0x8004, &[1u8; 32][..]));
    assert_eq!(parse_key(&[]).err(), Some(BdeError::BadKey));
    let mut long = e.clone();
    long.push(0);
    assert_eq!(
        parse_key(&long).err(),
        Some(BdeError::BadKey),
        "size must be exact"
    );
    let mut vt = e.clone();
    vt[4] = 5;
    assert_eq!(parse_key(&vt).err(), Some(BdeError::BadKey));
    assert_eq!(
        parse_key(&entry(0, value::KEY, &[1, 2, 3, 4])).err(),
        Some(BdeError::BadKey)
    );
    assert_eq!(
        parse_key(&[3, 0, 0, 0]).err(),
        Some(BdeError::EntryTooSmall)
    );
}

fn bek(id: [u8; 16], keys: usize) -> Vec<u8> {
    let mut ek = id.to_vec();
    ek.extend(0u64.to_le_bytes());
    ek.extend(entry(0, value::UNICODE, b"E\0\0\0"));
    for _ in 0..keys {
        let mut k = 0x2002u32.to_le_bytes().to_vec();
        k.extend([0x42; 32]);
        ek.extend(entry(0, value::KEY, &k));
    }
    let body = entry(entry::STARTUP_KEY, value::EXTERNAL_KEY, &ek);
    let total = (48 + body.len()) as u32;
    let mut f = Vec::new();
    for v in [total, 1, 48, total] {
        f.extend(v.to_le_bytes());
    }
    f.extend([0; 32]);
    f.extend(body);
    f
}

#[test]
fn startup_key_files() {
    let f = bek([5; 16], 1);
    assert_eq!(
        parse_startup_key(&f),
        Ok(StartupKey {
            id: [5; 16],
            key: [0x42; 32]
        })
    );
    assert_eq!(
        parse_startup_key(&bek([5; 16], 0)),
        Err(BdeError::BadStartupKey)
    );
    assert_eq!(
        parse_startup_key(&bek([5; 16], 2)),
        Err(BdeError::BadStartupKey)
    );
    assert_eq!(
        parse_startup_key(&f[..f.len() - 1]),
        Err(BdeError::BadStartupKey)
    );
    assert_eq!(parse_startup_key(&[]), Err(BdeError::BadStartupKey));
    let mut v = f.clone();
    v[4] = 2;
    assert_eq!(parse_startup_key(&v), Err(BdeError::BadStartupKey));
}

#[test]
fn layout_refusals() {
    let base = V::new();
    let err = |f: &dyn Fn(&mut V)| {
        let mut v = base.clone();
        f(&mut v);
        full(&v).err()
    };
    let set_vhb = |v: &mut V, off: u64, len: u64| {
        let n = v.entries.len();
        v.entries.truncate(n - 24);
        v.entries.extend(vhb(off, len));
    };
    assert_eq!(err(&|_| {}), None);
    assert_eq!(err(&|v| v.reloc += 4096), Some(BdeError::Relocation));
    assert_eq!(err(&|v| v.vh_sectors = 8), Some(BdeError::Relocation));
    assert_eq!(
        err(&|v| {
            v.vh_sectors = 0;
            set_vhb(v, v.reloc, 0)
        }),
        Some(BdeError::Relocation)
    );
    assert_eq!(
        err(&|v| {
            v.reloc = 100;
            set_vhb(v, 100, 8192)
        }),
        Some(BdeError::Relocation)
    );
    assert_eq!(
        err(&|v| {
            v.reloc = 64 * MB - 4096;
            set_vhb(v, v.reloc, 8192)
        }),
        Some(BdeError::Relocation)
    );
    assert_eq!(
        err(&|v| {
            v.reloc = 16 * MB + 4096;
            set_vhb(v, v.reloc, 8192)
        }),
        Some(BdeError::Overlap)
    );
    assert_eq!(
        err(&|v| {
            v.reloc = 4096;
            set_vhb(v, 4096, 8192)
        }),
        Some(BdeError::Overlap)
    );
    assert_eq!(err(&|v| v.md[1] = 16 * MB + 512), Some(BdeError::Overlap));
    assert_eq!(err(&|v| v.md[2] = 64 * MB), Some(BdeError::MetadataOffset));
    assert_eq!(err(&|v| v.md[0] = 4096), Some(BdeError::Overlap));
    assert_eq!(err(&|v| v.enc = 65 * MB), Some(BdeError::EncryptedSize));
    assert_eq!(err(&|v| v.enc = 100), Some(BdeError::EncryptedSize));
    assert_eq!(
        err(&|v| v.state = (1, 1)),
        Some(BdeError::State {
            current: 1,
            next: 1
        })
    );
    assert_eq!(
        err(&|v| v.state = (4, 1)),
        Some(BdeError::State {
            current: 4,
            next: 1
        })
    );
    assert_eq!(
        err(&|v| {
            v.state = (5, 4);
            v.conv = 4096
        }),
        Some(BdeError::State {
            current: 5,
            next: 4
        })
    );
    for c in [0x8000, 0x8001, 0x8002, 0x8003, 0x9999] {
        assert_eq!(err(&|v| v.cipher = c), Some(BdeError::UnsupportedCipher(c)));
    }
    // A hand-built header is re-checked (found by fuzzing: an unaligned
    // offset made a zero-length run).
    let v = base.clone();
    let r = v.region();
    let m = Metadata::parse(cross_check([&r, &r, &r], &v.header()).unwrap()).unwrap();
    let mut h = v.header();
    h.metadata_offsets[1] = i64::MAX as u64;
    assert_eq!(Layout::new(&h, &m, v.size).err(), Some(BdeError::MetadataOffset));
    let mut h = v.header();
    h.bytes_per_sector = 1024;
    assert_eq!(Layout::new(&h, &m, v.size).err(), Some(BdeError::SectorSize(1024)));
    // Paused and running conversions are read; the boundary is encrypted_size.
    for st in [(5, 4), (2, 4)] {
        let mut v = base.clone();
        v.state = st;
        v.enc = 40 * MB;
        let l = full(&v).unwrap();
        assert!(l.partial);
        assert_eq!(l.encrypted_size, 40 * MB);
    }
    let mut v = base.clone();
    v.cipher = 0x8005;
    assert_eq!(full(&v).unwrap().cipher, Cipher::XtsAes256);
    // A trailing partial sector is not part of the view.
    let mut v = base.clone();
    v.bps = 4096;
    v.vh_sectors = 2;
    v.size = 64 * MB + 512;
    assert_eq!(full(&v).unwrap().units(), 64 * MB / 4096);
}

/// The map, by brute force: what each unit of the decrypted view is.
fn model(l: &Layout, unit: u64) -> Source {
    let bps = u64::from(l.bytes_per_sector);
    let off = unit * bps;
    if off < l.reloc_len {
        let p = l.reloc_offset + off;
        return Source::Disk {
            unit: p / bps,
            encrypted: p < l.encrypted_size,
        };
    }
    let hidden = [
        (l.reloc_offset, l.reloc_len),
        (l.metadata_offsets[0], REGION_SIZE),
        (l.metadata_offsets[1], REGION_SIZE),
        (l.metadata_offsets[2], REGION_SIZE),
    ];
    if hidden.iter().any(|&(o, n)| off >= o && off < o + n) {
        return Source::Zero;
    }
    Source::Disk {
        unit,
        encrypted: off < l.encrypted_size,
    }
}

fn layout_strategy() -> impl Strategy<Value = (V, u64)> {
    (
        any::<bool>(),
        0u64..8,
        0u64..1024,
        any::<[u16; 4]>(),
        1u64..=1024,
    )
        .prop_filter_map("valid layout", |(four_k, size_mb, enc_frac, pos, _)| {
            let mut v = V::new();
            if four_k {
                v.bps = 4096;
                v.vh_sectors = 2;
            }
            v.size = (size_mb + 1) * MB;
            let slot = |p: u16| (u64::from(p) * v.size / 65536) & !0xfff;
            v.md = [slot(pos[0]), slot(pos[1]), slot(pos[2])];
            v.reloc = slot(pos[3]);
            let n = v.entries.len();
            v.entries.truncate(n - 24);
            v.entries.extend(vhb(v.reloc, 8192));
            v.enc = (v.size * enc_frac / 1024) & !0xfff;
            if v.enc < v.size {
                v.state = (5, 4);
            }
            full(&v).ok().map(|_| (v.clone(), v.size))
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn map_matches_the_model((v, _) in layout_strategy(), probes in proptest::collection::vec(any::<u64>(), 64)) {
        let l = full(&v).unwrap();
        let units = l.units();
        prop_assert_eq!(l.map(units), None);
        for p in probes {
            let u = p % units;
            let (src, run) = l.map(u).unwrap();
            prop_assert_eq!(src, model(&l, u));
            prop_assert!(run >= 1 && u + run <= units);
            // The run continues in step (it may end early at a boundary
            // where nothing changes, e.g. two adjacent hidden regions).
            for i in [0, run / 2, run - 1] {
                let want = match src {
                    Source::Zero => Source::Zero,
                    Source::Disk { unit, encrypted } => Source::Disk { unit: unit + i, encrypted },
                };
                prop_assert_eq!(model(&l, u + i), want);
            }
        }
    }

    #[test]
    fn mutated_metadata_never_panics(flips in proptest::collection::vec((0usize..2048, any::<u8>()), 1..8), which in 0usize..3) {
        let v = V::new();
        let hdr = v.header();
        let good = v.region();
        let mut bad = good.clone();
        for (at, x) in flips {
            bad[at] ^= x;
        }
        let agreed = parse_block(&good, 0, &hdr).unwrap().agreed.len();
        let mut copies = [&good[..], &good[..], &good[..]];
        copies[which] = &bad;
        if let Ok(b) = cross_check(copies, &hdr) {
            prop_assert_eq!(&bad[..agreed], &good[..agreed], "only an unchanged copy is accepted");
            if let Ok(m) = Metadata::parse(b) {
                let _ = Layout::new(&hdr, &m, v.size);
            }
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic(b in proptest::collection::vec(any::<u8>(), 0..1200)) {
        let hdr = V::new().header();
        let _ = parse_volume_header(&b);
        let _ = parse_block(&b, 0, &hdr);
        let _ = parse_key(&b);
        let _ = parse_startup_key(&b);
        let _ = Ccm::parse(&b);
        for e in Entries::new(&b, MAX_ENTRIES) {
            let _ = e;
        }
    }
}
