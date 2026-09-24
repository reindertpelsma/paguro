//! Property tests for the loader-facing formats: `parse(serialize(x)) == x`
//! for every valid `x`, and no parser panics on arbitrary bytes
//! (INTERFACES.md §12, "property").
#![allow(clippy::indexing_slicing)]

use paguro_core::bootstrap;
use paguro_core::config::{self, Config, Efi, Entry, MAX_ENTRIES};
use paguro_core::disk;
use paguro_core::gpt;
use paguro_core::guid::Guid;
use paguro_core::handoff::{self, FveLayout, Fvek, Handoff, ImageId, Pcrs, Rung, Volume};
use paguro_core::seal::{self, Kind, Seal, Sealed};
use paguro_core::tpm;
use proptest::prelude::*;

fn name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,32}"
}

fn path() -> impl Strategy<Value = String> {
    proptest::collection::vec("[A-Za-z0-9 #._-]{0,20}[A-Za-z0-9]", 1..6)
        .prop_map(|c| format!("\\{}", c.join("\\")))
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..max)
}

/// A TPM2B value (size-prefixed, non-empty) as a seal file stores it.
fn tpm2b(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..max).prop_map(|v| {
        let mut out = (v.len() as u16).to_be_bytes().to_vec();
        out.extend(v);
        out
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn guid_text_roundtrip(g in any::<[u8; 16]>()) {
        let g = Guid(g);
        let text = g.to_text();
        prop_assert_eq!(Guid::parse(std::str::from_utf8(&text).unwrap()), Ok(g));
    }

    #[test]
    fn config_roundtrip(
        ents in proptest::collection::vec(
            (name(), any::<[u8; 16]>(), path(), proptest::option::of(path()), path(), 0u8..3),
            1..=16,
        ),
        flags in any::<[bool; 3]>(),
        def in any::<prop::sample::Index>(),
    ) {
        let mut seen: Vec<&String> = Vec::new();
        let mut entries = [Entry::EMPTY; MAX_ENTRIES];
        let mut n = 0;
        for (nm, vol, root, efi_disk, efi, kind) in &ents {
            if seen.contains(&nm) {
                continue;
            }
            seen.push(nm);
            // 0: root + disk, 1: efi_file only, 2: root + efi_file.
            entries[n] = Entry {
                name: nm,
                volume: Guid(*vol),
                root: (*kind != 1).then_some(root.as_str()),
                efi: if *kind == 0 {
                    Efi::Disk { disk: efi_disk.as_deref().unwrap_or(root), path: efi }
                } else {
                    Efi::File(efi)
                },
            };
            n += 1;
        }
        let cfg = Config {
            default: def.index(n),
            entries,
            entry_count: n,
            tpm: flags[0],
            setup_tpm: flags[1],
            passphrase: flags[2],
        };
        let mut buf = vec![0u8; 16 * 1024];
        let len = config::write(&cfg, &mut buf).unwrap();
        prop_assert_eq!(config::parse(&buf[..len]).unwrap(), cfg);
    }

    #[test]
    fn config_never_panics(b in bytes(4096)) {
        let _ = config::parse(&b);
    }

    #[test]
    fn config_never_panics_on_near_valid(lines in proptest::collection::vec(
        prop_oneof![
            Just("[Paguro]".to_string()),
            Just("[Boot.a]".to_string()),
            Just("[TPM]".to_string()),
            "[A-Za-z.]{0,12}".prop_map(|s| format!("[{s}]")),
            "(version|default|volume|root|efi_disk|efi|efi_file|enabled)=[ -~]{0,40}",
        ],
        0..40,
    )) {
        let _ = config::parse(lines.join("\n").as_bytes());
    }

    #[test]
    fn seal_roundtrip(
        kind_i in 0usize..4,
        deadline in any::<u64>(),
        wrapped in any::<[u8; 32]>(),
        salt in any::<[u8; 16]>(),
        public in tpm2b(500),
        private in tpm2b(500),
    ) {
        let kind = Kind::ALL[kind_i];
        let s = Seal {
            kind,
            deadline: (kind == Kind::PinBypass).then_some(deadline),
            pcrs: kind.has_tpm_object().then_some(seal::Pcrs::V1),
            wrapped_vmk: &wrapped,
            salt: &salt,
            sealed: kind.has_tpm_object().then_some(Sealed { public: &public, private: &private }),
        };
        let mut buf = [0u8; seal::MAX_FILE];
        let n = seal::write(&s, &mut buf).unwrap();
        prop_assert_eq!(seal::read(kind, &buf[..n]), Ok(s));
    }

    #[test]
    fn seal_never_panics(b in bytes(1200), kind_i in 0usize..4) {
        let _ = seal::read(Kind::ALL[kind_i], &b);
        let _ = seal::read_body(Kind::ALL[kind_i], &b);
    }

    #[test]
    fn bootstrap_roundtrip(
        volume in any::<[u8; 16]>(),
        salt in any::<[u8; 16]>(),
        wrapped in any::<[u8; 32]>(),
        desc in "[ -~]{0,40}",
        p in path(),
    ) {
        let od = bootstrap::write_optional_data(&Guid(volume), &salt, &wrapped);
        let mut buf = [0u8; 1024];
        let n = bootstrap::write_load_option(1, &desc, &p, &od, &mut buf).unwrap();
        let bs = bootstrap::parse(&buf[..n]).unwrap();
        prop_assert_eq!((bs.volume, bs.salt, bs.wrapped_vmk), (Guid(volume), &salt, &wrapped));
    }

    #[test]
    fn bootstrap_never_panics(b in bytes(1024)) {
        let _ = bootstrap::parse(&b);
        if let Ok(lo) = bootstrap::parse_load_option(&b) {
            let _ = lo.is_windows_boot_manager();
        }
    }

    #[test]
    fn gpt_roundtrip(
        parts in proptest::collection::vec((any::<[u8; 16]>(), 1u64..1000), 1..20),
        disk_guid in any::<[u8; 16]>(),
    ) {
        let disk_blocks = 1u64 << 20;
        let mut entries = Vec::new();
        let mut lba = 34u64;
        for (id, len) in &parts {
            entries.push(gpt::Entry {
                type_guid: paguro_core::guid::GPT_BASIC_DATA,
                unique_guid: Guid(*id),
                first_lba: lba,
                last_lba: lba + len - 1,
                attributes: 0,
                name: [0; 36],
            });
            lba += len;
        }
        let mut h = [0u8; 512];
        let mut a = [0u8; gpt::MAX_ENTRY_ARRAY];
        gpt::build::write(&Guid(disk_guid), disk_blocks, 512, &entries, 128, &mut h, &mut a).unwrap();
        let hdr = gpt::Header::parse(&h, disk_blocks).unwrap();
        prop_assert_eq!(hdr.disk_guid, Guid(disk_guid));
        let es = hdr.entries(&a).unwrap();
        for (i, e) in entries.iter().enumerate() {
            prop_assert_eq!(es.get(i as u32).unwrap(), *e);
        }
    }

    #[test]
    fn gpt_never_panics(h in bytes(600), a in bytes(2048), blocks in any::<u64>()) {
        let mut blk = [0u8; 512];
        let n = h.len().min(512);
        blk[..n].copy_from_slice(&h[..n]);
        if let Ok(hdr) = gpt::Header::parse(&blk, blocks) {
            let _ = hdr.entries(&a);
        }
    }

    #[test]
    fn handoff_roundtrip(
        guid in any::<[u8; 16]>(),
        lba in any::<u64>(),
        sectors in any::<u64>(),
        vmk in proptest::option::of(any::<[u8; 32]>()),
        fvek in proptest::option::of((any::<u16>(), proptest::collection::vec(any::<u8>(), 1..=64))),
        layout in proptest::option::of(any::<([u64; 3], u64, u64, u32, u64)>()),
        b in any::<[u8; 32]>(),
        mask in 1u32..(1 << 24),
        config_bytes in proptest::option::of(bytes(2000)),
        name in name(),
        root in proptest::option::of((any::<u64>(), any::<u16>())),
        efi in proptest::option::of((any::<bool>(), any::<u64>(), any::<u16>())),
        state in 0u32..16,
        rung in 1u8..=8,
        prov in proptest::option::of((any::<[u8; 32]>(), any::<[u8; 16]>(), tpm2b(300), tpm2b(300))),
    ) {
        let pcrv = vec![0x5au8; mask.count_ones() as usize * 32];
        let root = root.map(|(r, s)| ImageId { name: &name, mft_record: r, mft_seq: s });
        // A second file: never the root's record; an efi disk only beside a root.
        let efi = efi
            .filter(|(_, r, _)| root.is_none_or(|x| x.mft_record != *r))
            .map(|(disk, r, s)| (disk && root.is_some(), ImageId { name: &name, mft_record: r, mft_seq: s }));
        let efi_disk = efi.filter(|e| e.0).map(|e| e.1);
        let efi_file = efi.filter(|e| !e.0).map(|e| e.1);
        let provision = prov.as_ref().map(|(w, s, public, private)| Seal {
            kind: Kind::Tpm,
            deadline: None,
            pcrs: Some(seal::Pcrs::V1),
            wrapped_vmk: w,
            salt: s,
            sealed: Some(Sealed { public, private }),
        });
        let h = Handoff {
            volume: Volume { partition: Guid(guid), first_lba: lba, sectors },
            vmk: vmk.as_ref(),
            fvek: fvek.as_ref().map(|(c, k)| Fvek { cipher: *c, key: k }),
            fve_layout: layout.map(|(m, r, o, s, e)| FveLayout {
                metadata_offsets: m,
                region_size: r,
                boot_sector_reloc_offset: o,
                boot_sector_reloc_sectors: s,
                encrypted_size: e,
            }),
            b: &b,
            pcrs: Pcrs { mask, values: &pcrv },
            config: config_bytes.as_deref(),
            root,
            efi_disk,
            efi_file,
            state,
            rung: Rung::from_u8(rung).unwrap(),
            provision,
        };
        let mut buf = vec![0u8; handoff::MAX_LEN];
        let n = handoff::encode(&h, &mut buf).unwrap();
        prop_assert_eq!(handoff::decode(&buf[..n]), Ok(h));
    }

    #[test]
    fn disk_detect_is_total(len in any::<u64>(), tail in bytes(512)) {
        let mut t = [0u8; 512];
        t[..tail.len()].copy_from_slice(&tail);
        let p = disk::detect(len, &t);
        prop_assert!(p.len <= len);
        if p.format == disk::Format::Vhd {
            prop_assert_eq!(p.len + 512, len);
        }
    }

    #[test]
    fn disk_classify_never_panics(len in any::<u64>(), head in bytes(2048), gpt_sig in any::<bool>()) {
        let mut h = head;
        if gpt_sig && h.len() >= 520 {
            h[512..520].copy_from_slice(gpt::SIGNATURE);
        }
        if let Ok(fs) = disk::classify(len, &h) {
            let (at, n) = fs.range();
            prop_assert!(at.saturating_add(n) <= len);
        }
    }

    #[test]
    fn fat32_superfloppy_accepted(total in 70_000u32..4_000_000, extra in 0u64..4096) {
        let s = disk::build::fat32_boot_sector(total);
        let len = u64::from(total) * 512 + extra;
        let fs = disk::classify(len, &s).unwrap();
        prop_assert_eq!(fs.range(), (0, u64::from(total) * 512));
    }

    #[test]
    fn handoff_never_panics(b in bytes(4096)) {
        let _ = handoff::decode(&b);
    }

    #[test]
    fn handoff_never_panics_with_header(recs in bytes(2048), count in any::<u16>()) {
        let mut b = handoff::MAGIC.to_vec();
        b.extend(((16 + recs.len()) as u32).to_le_bytes());
        b.extend(count.to_le_bytes());
        b.extend([0, 0]);
        b.extend(&recs);
        let _ = handoff::decode(&b);
    }

    #[test]
    fn tpm_responses_never_panic(b in bytes(1200), has_handle in any::<bool>(), sessions in 0usize..4) {
        let _ = tpm::response(&b, has_handle, sessions);
        let _ = tpm::parse_pcr_read(&b);
        let _ = tpm::parse_create_primary(&b);
        let _ = tpm::parse_create(&b);
        let _ = tpm::parse_load(&b);
        let _ = tpm::parse_start_auth_session(&b);
        let _ = tpm::parse_unseal(&b);
        let _ = tpm::parse_read_clock(&b);
        let _ = tpm::parse_get_properties(&b);
    }

    #[test]
    fn tpm_well_framed_responses_never_panic(body in bytes(600), code in any::<u32>(), tag in any::<u16>()) {
        let mut b = tag.to_be_bytes().to_vec();
        b.extend(((10 + body.len()) as u32).to_be_bytes());
        b.extend(code.to_be_bytes());
        b.extend(&body);
        for s in 0..=3 {
            let _ = tpm::response(&b, s % 2 == 0, s);
        }
    }

    #[test]
    fn pcr_read_roundtrip(pcrs in proptest::collection::vec(0u32..24, 1..=8), seed in any::<u8>()) {
        let mask = pcrs.iter().fold(0u32, |m, p| m | 1 << p);
        let n = mask.count_ones() as usize;
        let mut p = vec![0, 0, 0, 9, 0, 0, 0, 1, 0, 0x0b, 3, mask as u8, (mask >> 8) as u8, (mask >> 16) as u8];
        p.extend((n as u32).to_be_bytes());
        for i in 0..n {
            p.extend([0, 32]);
            p.extend([seed.wrapping_add(i as u8); 32]);
        }
        let v = tpm::parse_pcr_read(&p).unwrap();
        prop_assert_eq!(v.mask, mask);
        let mut i = 0u8;
        for pcr in 0..24 {
            if mask & (1 << pcr) != 0 {
                prop_assert_eq!(v.get(pcr), Some(&[seed.wrapping_add(i); 32]));
                i += 1;
            } else {
                prop_assert_eq!(v.get(pcr), None);
            }
        }
    }
}
