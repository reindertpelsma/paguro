//! Mock boots: the whole stage machine over an in-memory platform
//! (INTERFACES.md §12, "mock boot").
#![allow(clippy::indexing_slicing)]

mod mock;

use mock::*;
use paguro_boot::platform::{Grey, Input, Notice, Row, Screen, VolumeFormat};
use paguro_boot::{BootError, Outcome};
use paguro_core::bootstrap;
use paguro_core::config::Efi;
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, Guid, PAGURO_VENDOR};
use paguro_core::handoff::{Rung, state};
use paguro_core::seal::{self, Kind};
use paguro_core::tpm::cc;
use paguro_crypto as kdf;

fn unlock_menus(m: &Mock) -> Vec<paguro_boot::platform::UnlockMenu> {
    m.screens
        .iter()
        .filter_map(|s| match s {
            Screen::Unlock(menu) => Some(*menu),
            _ => None,
        })
        .collect()
}

fn pin(w: &mut World, pw: &str) {
    w.m.input(Input::Select(Row::PasswordOrPin)).secret(pw);
}

// ---------------------------------------------------------------------------
// The happy path and the ratchet

#[test]
fn happy_path_tpm_rung() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));

    // Load taint, then boot taint — computed, and equal to what the TPM holds.
    let ini_digest = sha256(&[&w.ini]);
    assert_eq!(w.m.extends(), vec![ini_digest, boot_taint()]);
    let load = extend(&[0; 32], &ini_digest);
    assert_eq!(load, paguro_boot::tpm::pcr12_after_load_taint(&w.ini));
    assert_eq!(w.m.pcr12(), extend(&load, &boot_taint()));
    assert!(w.m.logged(&format!("pcr12={} (load taint)", hex(&load))));
    assert!(w.m.logged("stage1 ok (verified)"));

    let h = w.m.decoded();
    assert_eq!(h.rung, Rung::Tpm);
    assert_eq!(h.vmk, Some(&VMK));
    assert_eq!(h.fvek.unwrap().key, &FVEK[..]);
    assert!(h.fve_layout.is_some());
    assert_eq!(h.b, &B);
    assert_eq!(h.config, Some(&w.ini[..]));
    assert_eq!(h.state, 0);
    assert_eq!(h.volume.partition, VOLUME);
    assert_eq!((h.volume.first_lba, h.volume.sectors), (64, 256));
    let root = h.root.unwrap();
    assert_eq!(root.name, "debian");
    assert_eq!((root.mft_record, root.mft_seq), (1234, 7));
    assert_eq!(h.efi_file, None);
    assert_eq!(h.efi_disk, None, "efi_disk defaults to root: not forwarded");
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        (saw.name.as_str(), saw.volume, saw.root.as_deref()),
        ("debian", VOLUME, Some("\\paguro\\debian.vhd"))
    );
    assert_eq!(
        saw.efi,
        format!(
            "{:?}",
            Efi::Disk {
                disk: "\\paguro\\debian.vhd",
                path: paguro_core::config::DEFAULT_EFI
            }
        ),
        "efi_disk defaults to root, efi to the removable-media path"
    );
    assert_eq!(h.pcrs.mask, 0x95);
    let t = w.m.tpm.as_ref().unwrap();
    assert_eq!(&h.pcrs.values[..32], &t.pcrs[0]);
    assert_eq!(&h.pcrs.values[96..], &t.pcrs[7]);
    assert!(h.provision.is_none());
    assert_eq!(
        w.m.events.last(),
        Some(&Event::Start(b"chain-device-path".to_vec()))
    );
    // Every TPM object and session was flushed.
    assert_eq!(t.live_handles(), 0);
    // The event log tags carry the paguro GUID.
    let Event::Extend(_, _, ev) =
        w.m.events
            .iter()
            .find(|e| matches!(e, Event::Extend(..)))
            .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(&ev[..16], &paguro_core::guid::PCR12_EVENT_TAG.0);
    assert_eq!(&ev[16..], b"paguro/load-taint/v1");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn secure_boot_off_skips_the_hash_check_but_not_the_ratchet() {
    let mut w = World::new();
    w.m.secure_boot = false;
    w.m.put_var("PaguroConfigHash", PAGURO_VENDOR, 7, &[0xee; 32]); // wrong, and ignored
    w.with_tpm_seal(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
    assert!(w.m.logged("stage1 skipped (secure boot off)"));
    assert!(!w.m.screens.contains(&Screen::ConfigInvalid));
    assert_eq!(w.m.extends()[0], sha256(&[&w.ini]));
    let h = w.m.decoded();
    assert_eq!(h.state, state::CONFIG_UNVERIFIED);
    assert_eq!(h.config, Some(&w.ini[..]));
    assert!(unlock_menus(&w.m)[0].unattested);
}

#[test]
fn secure_boot_off_tampered_ini_cannot_unseal() {
    // The ratchet, not the hash, protects the TPM rung when SB is off.
    let mut w = World::new();
    w.m.secure_boot = false;
    w.with_tpm_seal(PIN);
    let mut evil = w.ini.clone();
    evil.extend(b"# tampered\n");
    w.set_ini(evil, false);
    pin(&mut w, PIN);
    w.m.input(Input::Select(Row::RecoveryKey));
    let out = w.run();
    assert_eq!(out, Outcome::Halted(BootError::UserAbort));
    assert!(w.m.logged("rung tpm failed"));
    assert!(!w.m.logged("rung tpm: unsealed"));
    // Policy failure is reported to Windows.
    assert_eq!(
        w.m.var("PaguroTpmBroken").map(|v| v.1.clone()),
        Some(vec![1])
    );
}

#[test]
fn hash_mismatch_with_secure_boot_enters_recovery() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.put_var("PaguroConfigHash", PAGURO_VENDOR, 7, &[0xee; 32]);
    w.v.recovery = Some((RECOVERY_KEY, VMK));
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    assert_eq!(w.m.screens[0], Screen::ConfigInvalid);
    assert!(w.m.logged("stage1 hash mismatch"));
    // Capped first: the only extend is the boot taint, from zero.
    assert_eq!(w.m.extends(), vec![boot_taint()]);
    assert_eq!(w.m.pcr12(), extend(&[0; 32], &boot_taint()));
    let menu = unlock_menus(&w.m)[0];
    assert_eq!(menu.tpm, Err(Grey::RecoveryMode));
    assert!(menu.unattested);
    let h = w.m.decoded();
    assert_eq!(h.state, state::RECOVERY_PATH | state::CONFIG_UNVERIFIED);
    assert_eq!(h.config, None);
    assert_eq!(h.rung, Rung::RecoveryKey);
    // Stage 4 was steered by the on-screen choice (the only entry in
    // \paguro\, taken silently), never by the configuration.
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        (saw.name.as_str(), saw.root.as_deref()),
        ("debian", Some("\\paguro\\debian.vhd"))
    );
    assert!(w.m.logged("1 entries in \\paguro\\, 1 disk(s)"));
    assert!(
        w.m.browsed.is_empty(),
        "one file in \\paguro: nothing asked"
    );
    // The TPM was never asked to unseal.
    assert_eq!(w.m.tpm.as_ref().unwrap().count(cc::UNSEAL), 0);
}

pub const RECOVERY_PW: &str = "000011-000022-000033-000044-000055-000066-000077-720885";
pub const RECOVERY_KEY: [u8; 16] = [1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0xff, 0xff];

#[test]
fn hash_mismatch_start_windows_sets_bootnext_and_resets() {
    let mut w = World::new();
    w.m.put_var("PaguroConfigHash", PAGURO_VENDOR, 7, &[0xee; 32]);
    w.m.input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::StartWindows);
    assert_eq!(w.m.var("BootNext").map(|v| v.1.clone()), Some(vec![0, 0]));
    assert_eq!(w.m.events.last(), Some(&Event::Reset));
    assert!(
        w.m.extends().is_empty(),
        "nothing measured on the way to Windows"
    );
    assert!(w.m.handoff.is_none());
}

#[test]
fn recovery_never_tokenises_the_ini() {
    // A hostile file: if parsed it would fail (ConfigInvalid) and name a
    // volume that does not exist. Recovery must hash it and nothing else.
    let mut w = World::new();
    let hostile = b"[Paguro]\nversion=1\ndefault=x\n[Boot.x]\nvolume=deadbeef-0000-0000-0000-000000000000\nbogus line\n".to_vec();
    w.set_ini(hostile, false);
    w.v.recovery = Some((RECOVERY_KEY, VMK));
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    assert!(
        !w.m.log.iter().any(|l| l.contains("stage2")),
        "{:?}",
        w.m.log
    );
    assert_eq!(
        w.m.screens
            .iter()
            .filter(|s| **s == Screen::ConfigInvalid)
            .count(),
        1
    );
    assert!(!w.m.screens.contains(&Screen::Notice(Notice::VolumeMissing)));
    assert_eq!(w.v.opened.unwrap().0.guid, VOLUME, "found by enumeration");
    assert_eq!(w.m.decoded().config, None);
}

#[test]
fn hash_variable_missing_goes_straight_to_recovery() {
    for bad in [None, Some(vec![0u8; 31]), Some(vec![0u8; 33])] {
        let mut w = World::new();
        w.m.vars
            .remove(&("PaguroConfigHash".to_string(), PAGURO_VENDOR));
        if let Some(v) = bad {
            w.m.put_var("PaguroConfigHash", PAGURO_VENDOR, 7, &v);
        }
        w.with_passphrase_seal("pw");
        w.m.input(Input::Select(Row::RecoveryPassphrase))
            .secret("pw");
        assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
        assert!(w.m.logged("stage1 hash variable missing"));
        assert!(!w.m.screens.contains(&Screen::ConfigInvalid));
        assert_eq!(w.m.extends(), vec![boot_taint()]);
        assert_eq!(
            w.m.decoded().state,
            state::RECOVERY_PATH | state::CONFIG_UNVERIFIED
        );
    }
}

#[test]
fn missing_tpm_seal_extends_the_sentinel() {
    let mut w = World::new();
    w.with_passphrase_seal("pw");
    w.m.input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    // Sentinel at load time, never the ini; and only once.
    assert_eq!(w.m.extends(), vec![boot_taint()]);
    assert!(w.m.logged("(no tpm_seal.bin)"));
    assert_eq!(unlock_menus(&w.m)[0].tpm, Err(Grey::Unavailable));
    assert_eq!(w.m.decoded().config, Some(&w.ini[..]));
}

#[test]
fn deleting_the_seal_cannot_skip_the_ratchet() {
    // With the seal present PCR 12 = load taint; without, it is poisoned
    // and differs from anything a seal could name.
    let mut a = World::new();
    a.with_tpm_seal(PIN);
    pin(&mut a, PIN);
    a.run();
    let mut b = World::new();
    b.with_tpm_seal(PIN);
    b.m.files.remove(&seal_file(&VOLUME, Kind::Tpm));
    b.run();
    assert_ne!(a.m.extends()[0], b.m.extends()[0]);
    assert_eq!(b.m.extends()[0], boot_taint());
}

#[test]
fn pcr12_not_zero_is_refused() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.tpm().pcrs[12] = [1; 32];
    w.m.input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::StartWindows);
    assert!(w.m.screens.contains(&Screen::Notice(Notice::Pcr12NotZero)));
    assert!(w.m.logged("PCR 12 not zero"));
    assert!(w.m.extends().is_empty());
    assert_eq!(w.m.tpm.as_ref().unwrap().count(cc::UNSEAL), 0);

    // "Recover" from the refusal caps and continues without the TPM row.
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.tpm().pcrs[12] = [1; 32];
    w.v.recovery = Some((RECOVERY_KEY, VMK));
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    assert_eq!(w.m.extends(), vec![boot_taint()]);
    assert_eq!(
        w.m.decoded().state & state::RECOVERY_PATH,
        state::RECOVERY_PATH
    );
}

#[test]
fn ui_section_is_applied_after_stage2_and_dropped_by_recovery() {
    use paguro_core::config::{Keyboard, Ui, UiMode, UiTheme};
    let with_ui = |w: &mut World| {
        let mut ini = w.ini.clone();
        ini.extend_from_slice(b"\n[UI]\ntheme = light-contrast\nmode = text\nkeyboard = de\n");
        w.set_ini(ini, true);
    };
    let light = Ui {
        theme: UiTheme::LightContrast,
        mode: UiMode::Text,
        keyboard: Keyboard::De,
    };
    // Applied once the file has verified and parsed.
    let mut w = World::new();
    with_ui(&mut w);
    w.with_tpm_seal(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
    assert_eq!(w.m.ui, vec![light]);
    assert!(w.m.logged("paguro: ui light-contrast text de"));

    // Absent: nothing to apply, the platform keeps dark / auto.
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
    assert!(w.m.ui.is_empty());

    // Voluntary recovery after the file applied: back to the defaults.
    let mut w = World::new();
    with_ui(&mut w);
    w.with_tpm_seal(PIN).with_passphrase_seal("pw");
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert_eq!(w.m.ui, vec![light, Ui::DEFAULT]);

    // A file that fails verification is never parsed, so never applied.
    let mut w = World::new();
    with_ui(&mut w);
    let mut tampered = w.ini.clone();
    tampered.extend_from_slice(b"\n");
    w.set_ini(tampered, false);
    w.m.input(Input::StartWindows);
    let _ = w.run();
    assert!(w.m.ui.is_empty(), "recovery never reads [UI]");
}

#[test]
fn voluntary_recovery_caps_after_the_load_taint() {
    let mut w = World::new();
    w.with_tpm_seal(PIN).with_passphrase_seal("pw");
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert_eq!(w.m.extends(), vec![sha256(&[&w.ini]), boot_taint()]);
    let menus = unlock_menus(&w.m);
    assert!(menus[0].tpm.is_ok());
    assert_eq!(menus[1].tpm, Err(Grey::RecoveryMode));
    let h = w.m.decoded();
    assert_eq!(h.state, state::RECOVERY_PATH | state::CONFIG_UNVERIFIED);
    assert_eq!(h.config, None);
}

#[test]
fn config_that_hashes_but_does_not_parse() {
    let mut w = World::new();
    w.set_ini(b"[Paguro]\nversion = 2\n".to_vec(), true);
    w.m.input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::StartWindows);
    assert!(w.m.logged("stage2 config refused: UnsupportedVersion"));
    assert_eq!(w.m.screens[0], Screen::ConfigInvalid);
    assert!(
        w.m.extends().is_empty(),
        "nothing extended for a refused config"
    );

    let mut w = World::new();
    w.set_ini(b"[Paguro]\nversion = 2\n".to_vec(), true);
    w.with_passphrase_seal("pw");
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert_eq!(w.m.extends(), vec![boot_taint()]);
}

#[test]
fn oversized_config_is_never_hashed_or_parsed() {
    let mut w = World::new();
    w.set_ini(vec![b'#'; 65537], true);
    w.with_passphrase_seal("pw");
    w.m.input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert!(w.m.logged("over 64 KiB"));
    assert_eq!(
        w.m.decoded().state & state::RECOVERY_PATH,
        state::RECOVERY_PATH
    );
    // A file of exactly 64 KiB is accepted by stage 1 (and then refused by the parser).
    let mut w = World::new();
    let mut max = b"[Paguro]\n".to_vec();
    max.resize(65536, b'#');
    w.set_ini(max, true);
    w.run();
    assert!(w.m.logged("stage1 ok"));
}

// ---------------------------------------------------------------------------
// Bootstrap and provisioning

fn bootstrap_world(pw: &str) -> World {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.m.vars
        .remove(&("PaguroConfigHash".to_string(), PAGURO_VENDOR));
    w.m.vars.remove(&("PaguroB".to_string(), PAGURO_VENDOR));
    let salt = [0x99; 16];
    let ph = pass_hash(pw, &salt);
    let wrapped = kdf::xor32(&kdf::bootstrap_key(&ph, &salt), &VMK);
    let od = bootstrap::write_optional_data(&VOLUME, &salt, &wrapped);
    let mut lo = [0u8; 512];
    let n =
        bootstrap::write_load_option(1, "paguro setup", "\\EFI\\paguro\\paguro.efi", &od, &mut lo)
            .unwrap();
    w.m.put_var("Boot0005", EFI_GLOBAL_VARIABLE, 7, &lo[..n]);
    w.m.put_var("BootCurrent", EFI_GLOBAL_VARIABLE, 6, &[5, 0]);
    w
}

#[test]
fn bootstrap_entry_is_deleted_first() {
    let mut w = bootstrap_world(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Bootstrap));
    assert_eq!(w.m.events[0], Event::DeleteVar("Boot0005".into()));
    assert!(w.m.var("Boot0005").is_none());
    assert!(w.m.logged("bootstrap entry Boot0005 deleted"));
    assert!(unlock_menus(&w.m)[0].first_boot);
}

#[test]
fn bootstrap_entry_deleted_even_when_the_boot_fails() {
    let mut w = bootstrap_world(PIN);
    w.m.disks.clear();
    w.m.input(Input::Recover);
    assert_eq!(w.run(), Outcome::Halted(BootError::NoVolume));
    assert_eq!(w.m.events[0], Event::DeleteVar("Boot0005".into()));
    // The payload's volume is missing: the same choice as a configured one.
    assert!(w.m.screens.contains(&Screen::Notice(Notice::VolumeMissing)));
    assert!(w.m.logged(&format!("configured volume {VOLUME} not found")));
}

#[test]
fn a_non_bootstrap_boot_current_is_left_alone() {
    let mut w = World::new();
    w.m.put_var("BootCurrent", EFI_GLOBAL_VARIABLE, 6, &[0, 0]); // Windows' entry
    w.with_tpm_seal(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
    assert!(w.m.var("Boot0000").is_some());
    assert!(!w.m.events.iter().any(|e| matches!(e, Event::DeleteVar(_))));
}

#[test]
fn malformed_bootstrap_payload_is_deleted_but_not_used() {
    let mut w = bootstrap_world(PIN);
    let mut lo = [0u8; 512];
    let n = bootstrap::write_load_option(1, "x", "\\p", b"PGRBST\x00\x01short", &mut lo).unwrap();
    w.m.put_var("Boot0005", EFI_GLOBAL_VARIABLE, 7, &lo[..n]);
    w.v.recovery = Some((RECOVERY_KEY, VMK));
    w.m.input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    assert_eq!(w.m.events[0], Event::DeleteVar("Boot0005".into()));
    assert!(w.m.logged("malformed bootstrap entry"));
}

#[test]
fn bootstrap_provisions_a_seal_that_unseals_next_boot() {
    let mut w = bootstrap_world(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Bootstrap));
    // B created boot-services-only, before any rung.
    let (battrs, b) = w.m.var("PaguroB").cloned().unwrap();
    assert_eq!(battrs, paguro_boot::platform::attrs::NV_BS);
    assert!(w.m.logged("created B"));
    // First boot caps (no .ini): the provisioning seal names the load taint
    // of the configuration the loader authored, not today's PCR 12.
    assert_eq!(w.m.extends(), vec![boot_taint()]);

    let h = w.m.decoded();
    assert_eq!(h.rung, Rung::Bootstrap);
    assert_eq!(h.state, state::CONFIG_UNVERIFIED);
    let ini = h.config.expect("authored config").to_vec();
    let cfg = paguro_core::config::parse(&ini).unwrap();
    let e = cfg.default_entry().unwrap();
    assert_eq!(e.volume, VOLUME, "the bootstrap payload's volume");
    assert_eq!(e.root, Some("\\paguro\\debian.vhd"));
    assert_eq!(e.efi_disk(), e.root);
    let prov = h.provision.expect("provisioned seal");
    assert_eq!(prov.pcrs, Some(seal::Pcrs::V1));
    assert!(w.m.logged(&format!(
        "sealed for pcr12={}",
        hex(&paguro_boot::tpm::pcr12_after_load_taint(&ini))
    )));

    // What the initrd would write: tpm_seal.bin = magic || PROVISION body,
    // paguro.ini = CONFIG, PaguroConfigHash = SHA-256(CONFIG).
    let mut body = vec![0u8; seal::MAX_FILE];
    let n = seal::write(&prov, &mut body).unwrap();
    let seal_file = body[..n].to_vec();

    // Next boot, same TPM (power-cycled), same B.
    let mut tpm = w.m.tpm.take().unwrap();
    tpm.reboot();
    firmware_pcrs(&mut tpm);
    let mut next = World::new();
    next.m.tpm = Some(tpm);
    next.m.put_var("PaguroB", PAGURO_VENDOR, 3, &b);
    next.set_ini(ini, true);
    next.m
        .files
        .insert(mock::seal_file(&VOLUME, Kind::Tpm), seal_file);
    pin(&mut next, PIN);
    assert_eq!(next.run(), Outcome::Started(Rung::Tpm));
    assert_eq!(next.m.decoded().vmk, Some(&VMK));
}

#[test]
fn provisioning_skipped_when_pcr12_was_dirty() {
    let mut w = bootstrap_world(PIN);
    w.m.tpm().pcrs[12] = [3; 32];
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Bootstrap));
    let h = w.m.decoded();
    assert!(h.provision.is_none());
    assert!(h.config.is_some(), "the configuration is still authored");
    assert!(w.m.logged("PCR 12 dirty"));
}

#[test]
fn provisioning_survives_a_failing_create() {
    let mut w = bootstrap_world(PIN);
    w.m.tpm().fail = Some((cc::CREATE, paguro_core::tpm::rc::VALUE));
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Bootstrap));
    assert!(w.m.decoded().provision.is_none());
    assert!(w.m.logged("TPM2_Create failed"));
}

// ---------------------------------------------------------------------------
// Rungs and escalation

#[test]
fn free_protectors_before_the_tpm() {
    let mut w = World::new();
    w.with_tpm_seal(PIN).with_setup_seal(PIN);
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::SetupTpm));
    assert_eq!(
        w.m.tpm.as_ref().unwrap().count(cc::UNSEAL),
        0,
        "no DA attempt spent"
    );
    // S is one-shot: deleted before the handoff is published.
    let del =
        w.m.events
            .iter()
            .position(|e| *e == Event::DeleteVar("PaguroSetup".into()))
            .unwrap();
    let publ =
        w.m.events
            .iter()
            .position(|e| *e == Event::Publish)
            .unwrap();
    assert!(del < publ);
    assert!(w.m.var("PaguroSetup").is_none());
    assert_eq!(w.m.decoded().rung, Rung::SetupTpm);
}

#[test]
fn setup_rung_binds_the_configuration() {
    // A setupTPM staged for one ini does not open with another.
    let mut w = World::new();
    w.with_setup_seal(PIN);
    let other = ini_text(&VOLUME, false);
    w.set_ini(other, true);
    pin(&mut w, PIN);
    let out = w.run();
    assert_eq!(out, Outcome::Halted(BootError::UserAbort));
    assert!(w.m.screens.contains(&Screen::Incorrect));
}

#[test]
fn wrong_pin_costs_one_attempt_then_the_right_one_works() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    pin(&mut w, "wrong");
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
    assert!(w.m.screens.contains(&Screen::Incorrect));
    let t = w.m.tpm.as_ref().unwrap();
    assert_eq!(t.lockout_counter, 1);
    let menus = unlock_menus(&w.m);
    assert_eq!(menus[0].tpm, Ok(Some(3)));
    assert_eq!(menus[1].tpm, Ok(Some(2)));
    assert_eq!(t.live_handles(), 0, "failed unseal flushed everything");
}

#[test]
fn lockout_greys_the_tpm_row_and_keeps_the_others() {
    let mut w = World::new();
    w.with_tpm_seal(PIN).with_passphrase_seal("pw");
    w.m.tpm().in_lockout = true;
    w.m.input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    let menu = unlock_menus(&w.m)[0];
    assert_eq!(menu.tpm, Err(Grey::Locked));
    assert!(menu.password_or_pin && menu.recovery_passphrase && menu.recovery_key);
}

#[test]
fn reaching_lockout_shows_the_locked_screen() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.tpm().max_tries = 1;
    pin(&mut w, "wrong");
    pin(&mut w, PIN); // TPM now in lockout: no further TPM attempt
    w.m.input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::StartWindows);
    assert_eq!(w.m.tpm.as_ref().unwrap().count(cc::UNSEAL), 2);
    assert!(w.m.screens.contains(&Screen::TpmLocked));
    assert_eq!(unlock_menus(&w.m).last().unwrap().tpm, Err(Grey::Locked));
}

#[test]
fn policy_failure_sets_tpm_broken_and_offers_the_rest() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.tpm().pcrs[7] = [0x77; 32]; // e.g. a dbx update since sealing
    w.v.recovery = Some((RECOVERY_KEY, VMK));
    pin(&mut w, PIN);
    w.m.input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    let (attrs, v) = w.m.var("PaguroTpmBroken").cloned().unwrap();
    assert_eq!(
        (attrs, v),
        (paguro_boot::platform::attrs::NV_BS_RT, vec![1])
    );
    assert_eq!(unlock_menus(&w.m)[1].tpm, Err(Grey::Unavailable));
    assert_eq!(
        w.m.tpm.as_ref().unwrap().lockout_counter,
        0,
        "policy failures cost no attempt"
    );
}

#[test]
fn a_confirmed_tpm_unlock_clears_a_stale_tpm_broken_flag() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.put_var(
        "PaguroTpmBroken",
        paguro_core::guid::PAGURO_VENDOR,
        paguro_boot::platform::attrs::NV_BS_RT,
        &[1],
    );
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
    assert!(w.m.var("PaguroTpmBroken").is_none());
}

#[test]
fn a_wrong_key_from_the_tpm_does_not_clear_the_flag() {
    // The unseal succeeds but the derived VMK fails the FVEK unwrap: nothing
    // is confirmed, so the flag stays.
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.v.vmk = [0x55; 32];
    w.v.recovery = Some((RECOVERY_KEY, [0x55; 32]));
    w.m.put_var(
        "PaguroTpmBroken",
        paguro_core::guid::PAGURO_VENDOR,
        paguro_boot::platform::attrs::NV_BS_RT,
        &[1],
    );
    pin(&mut w, PIN);
    w.m.input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    assert!(w.m.var("PaguroTpmBroken").is_some());
}

#[test]
fn pin_bypass_needs_no_prompt() {
    let mut w = World::new();
    w.with_tpm_seal(PIN).with_bypass_seal(2_000_000);
    assert_eq!(w.run(), Outcome::Started(Rung::PinBypass));
    assert!(w.m.screens.is_empty(), "{:?}", w.m.screens);
    assert_eq!(w.m.decoded().rung, Rung::PinBypass);
    assert_eq!(w.m.tpm.as_ref().unwrap().count(cc::POLICY_COUNTER_TIMER), 1);
}

#[test]
fn pin_bypass_refused_when_expired_or_unsafe() {
    for (clock, safe, msg) in [
        (3_000_000u64, true, "pin bypass expired"),
        (1_000_000, false, "TPM clock not safe"),
    ] {
        let mut w = World::new();
        w.with_tpm_seal(PIN).with_bypass_seal(2_000_000);
        w.m.tpm().clock = clock;
        w.m.tpm().safe = safe;
        pin(&mut w, PIN);
        assert_eq!(w.run(), Outcome::Started(Rung::Tpm), "{msg}");
        assert!(w.m.logged(msg));
    }
    // Expiry enforced by the TPM even if the loader's pre-check is fooled.
    let mut w = World::new();
    w.with_tpm_seal(PIN).with_bypass_seal(2_000_000);
    w.m.tpm().fail = Some((cc::READ_CLOCK, 0x101));
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Tpm));
}

#[test]
fn clear_key_unlocks_silently() {
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(w.m.screens.is_empty());
    assert_eq!(w.m.decoded().vmk, Some(&VMK));
}

#[test]
fn unencrypted_volume_has_no_rung_and_no_vmk() {
    let mut w = World::new();
    w.m.disks = vec![disk(&[(VOLUME, NTFS)])];
    assert_eq!(w.run(), Outcome::Started(Rung::Unencrypted));
    let h = w.m.decoded();
    assert_eq!((h.vmk, h.fvek, h.rung), (None, None, Rung::Unencrypted));
    assert!(w.m.screens.is_empty());
}

#[test]
fn a_tpm_seal_over_plaintext_is_refused() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.disks = vec![disk(&[(VOLUME, NTFS)])];
    assert_eq!(w.run(), Outcome::Halted(BootError::SealOverPlaintext));
    assert!(
        w.m.screens
            .contains(&Screen::Notice(Notice::SealOverPlaintext))
    );
    assert!(w.m.handoff.is_none());
}

#[test]
fn handoff_contents_per_rung() {
    // (rung, state flags, config present, provision present)
    let cases: Vec<(Rung, u32, bool, bool, World)> = vec![
        {
            let mut w = World::new();
            w.with_tpm_seal(PIN);
            pin(&mut w, PIN);
            (Rung::Tpm, 0, true, false, w)
        },
        {
            let mut w = World::new();
            w.with_setup_seal(PIN);
            pin(&mut w, PIN);
            (Rung::SetupTpm, 0, true, false, w)
        },
        {
            let mut w = World::new();
            w.with_passphrase_seal("pw");
            w.m.input(Input::Select(Row::RecoveryPassphrase))
                .secret("pw");
            (Rung::Passphrase, 0, true, false, w)
        },
        {
            let mut w = World::new();
            w.v.recovery = Some((RECOVERY_KEY, VMK));
            w.m.input(Input::Select(Row::RecoveryKey))
                .secret(RECOVERY_PW);
            (Rung::RecoveryKey, 0, true, false, w)
        },
        {
            let mut w = World::new();
            w.with_tpm_seal(PIN).with_bypass_seal(2_000_000);
            (Rung::PinBypass, 0, true, false, w)
        },
        {
            let mut w = bootstrap_world(PIN);
            pin(&mut w, PIN);
            (Rung::Bootstrap, state::CONFIG_UNVERIFIED, true, true, w)
        },
        {
            let mut w = World::new();
            w.v.clear_key = Some(VMK);
            (Rung::ClearKey, 0, true, false, w)
        },
        {
            let mut w = World::new();
            w.m.disks = vec![disk(&[(VOLUME, NTFS)])];
            (Rung::Unencrypted, 0, true, false, w)
        },
    ];
    for (rung, flags, config, provision, mut w) in cases {
        assert_eq!(w.run(), Outcome::Started(rung), "{rung:?}");
        let h = w.m.decoded();
        assert_eq!(h.rung, rung);
        assert_eq!(h.state, flags, "{rung:?}");
        assert_eq!(h.config.is_some(), config, "{rung:?}");
        assert_eq!(h.provision.is_some(), provision, "{rung:?}");
        assert_eq!(h.vmk.is_some(), rung != Rung::Unencrypted, "{rung:?}");
        assert_eq!(h.b.len(), 32);
        assert_eq!(h.root.unwrap().name, "debian");
        assert_eq!(h.efi_disk, None);
        // The published blob never outlives publication in the loader's buffer
        // (checked indirectly: it decodes, and B matches the variable).
        assert_eq!(h.b, &w.m.var("PaguroB").unwrap().1[..]);
    }
}

#[test]
fn hibernation_and_dirty_degrade_to_read_only() {
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    w.v.flags = state::HIBERNATED | state::DIRTY;
    w.m.input(Input::Continue).input(Input::Continue);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(
        w.m.screens,
        vec![
            Screen::Notice(Notice::Hibernated),
            Screen::Notice(Notice::Dirty)
        ]
    );
    assert_eq!(w.m.decoded().state, state::HIBERNATED | state::DIRTY);

    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    w.v.flags = state::HIBERNATED;
    w.m.input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::StartWindows);
    assert!(w.m.handoff.is_none());
}

// ---------------------------------------------------------------------------
// Volumes

#[test]
fn configured_volume_missing_offers_recovery() {
    let mut w = World::new();
    let other = Guid([0x77; 16]);
    w.m.disks = vec![disk(&[(other, BITLOCKER)])];
    w.v.clear_key = Some(VMK);
    w.m.input(Input::Recover);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(w.m.screens.contains(&Screen::Notice(Notice::VolumeMissing)));
    assert_eq!(w.v.opened.unwrap().0.guid, other);
    assert_eq!(w.m.extends().last(), Some(&boot_taint()));
    assert_eq!(
        w.m.decoded().state & state::RECOVERY_PATH,
        state::RECOVERY_PATH
    );
}

#[test]
fn several_candidates_ask_which_volume() {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    let (a, b) = (Guid([0xa1; 16]), Guid([0xb2; 16]));
    w.m.disks = vec![
        disk(&[(a, BITLOCKER)]),
        disk(&[(Guid([0xcc; 16]), b"FAT32   "), (b, NTFS)]),
    ];
    w.m.input(Input::Choose(1));
    assert_eq!(w.run(), Outcome::Started(Rung::Unencrypted));
    let list =
        w.m.screens
            .iter()
            .find_map(|s| match s {
                Screen::SelectVolume(v) => Some(*v),
                _ => None,
            })
            .expect("the volume list was shown");
    let rows: Vec<_> = list
        .as_slice()
        .iter()
        .map(|v| (v.disk, v.partition, v.bytes, v.format))
        .collect();
    assert_eq!(
        rows,
        vec![
            (0, 1, 256 * 512, VolumeFormat::BitLocker),
            (1, 2, 256 * 512, VolumeFormat::Ntfs)
        ],
        "disk, 1-based partition number, size and format; the FAT32 is not a candidate"
    );
    assert_eq!(w.v.opened.unwrap().0.guid, b);
    assert_eq!(w.v.opened.unwrap().0.disk, 1);
}

#[test]
fn no_volume_at_all() {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.m.disks = vec![disk(&[(Guid([1; 16]), b"FAT32   ")])];
    assert_eq!(w.run(), Outcome::Halted(BootError::NoVolume));
    assert!(w.m.screens.contains(&Screen::NoInstallation));
}

#[test]
fn damaged_gpt_disks_are_skipped() {
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    let mut bad = disk(&[(VOLUME, BITLOCKER)]);
    bad.data[512 + 20] ^= 0xff; // header CRC now wrong
    w.m.disks = vec![bad, disk(&[(VOLUME, BITLOCKER)])];
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(w.v.opened.unwrap().0.disk, 1);
    assert!(w.m.logged("disk 0: no valid GPT"));
}

// ---------------------------------------------------------------------------
// Secrets, errors, hostile TPM

#[test]
fn b_is_reused_when_present_and_recreated_when_malformed() {
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    w.run();
    assert!(
        !w.m.events
            .iter()
            .any(|e| matches!(e, Event::SetVar(n, ..) if n == "PaguroB"))
    );
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    w.m.put_var("PaguroB", PAGURO_VENDOR, 3, &[1; 31]);
    w.run();
    let (_, b) = w.m.var("PaguroB").cloned().unwrap();
    assert_eq!(b.len(), 32);
    assert_eq!(w.m.decoded().b, &b[..]);
}

#[test]
fn no_rng_halts_before_any_rung() {
    let mut w = World::new();
    w.m.vars.remove(&("PaguroB".to_string(), PAGURO_VENDOR));
    w.m.rng_fails = true;
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Halted(BootError::Rng));
    assert_eq!(w.v.tries, 0);
}

#[test]
fn no_tpm_means_no_measurements_and_no_tpm_row() {
    let mut w = World::new();
    w.m.tpm = None;
    w.with_passphrase_seal("pw");
    pin(&mut w, "pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert!(w.m.extends().is_empty());
    assert_eq!(unlock_menus(&w.m)[0].tpm, Err(Grey::Unavailable));
    assert_eq!(w.m.decoded().pcrs.values, &[0u8; 128][..]);
}

#[test]
fn escape_everywhere_ends_in_user_abort_or_windows() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    assert_eq!(w.run(), Outcome::Halted(BootError::UserAbort));
    assert_eq!(w.m.screens.last(), Some(&Screen::CannotUnlock));

    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.input(Input::Escape).input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::StartWindows);
}

#[test]
fn start_windows_without_an_entry() {
    let mut w = World::new();
    w.m.vars
        .remove(&("Boot0000".to_string(), EFI_GLOBAL_VARIABLE));
    w.m.input(Input::StartWindows);
    assert_eq!(w.run(), Outcome::Halted(BootError::NoWindowsEntry));
    assert!(!w.m.events.contains(&Event::Reset));
}

#[test]
fn malformed_seal_files_are_ignored() {
    let mut w = World::new();
    w.m.files.insert(
        seal_file(&VOLUME, Kind::Tpm),
        b"PGRTPM\x00\x01garbage".to_vec(),
    );
    w.m.files
        .insert(seal_file(&VOLUME, Kind::Passphrase), vec![0; 5000]);
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(w.m.logged("tpm_seal.bin refused"));
    assert!(w.m.logged("passphrase_seal.bin unreadable"));
    // The ratchet decision uses presence: a malformed seal still gets the load taint.
    assert_eq!(w.m.extends()[0], sha256(&[&w.ini]));
}

#[test]
fn hostile_tpm_responses_grey_the_row_and_nothing_else() {
    use mock::tpm::Corrupt;
    for (code, how) in [
        (cc::UNSEAL, Corrupt::ResponseHmac),
        (cc::UNSEAL, Corrupt::Truncate),
        (cc::LOAD, Corrupt::Garbage),
        (cc::CREATE_PRIMARY, Corrupt::Truncate),
        (cc::START_AUTH_SESSION, Corrupt::Garbage),
    ] {
        let mut w = World::new();
        w.with_tpm_seal(PIN);
        w.v.recovery = Some((RECOVERY_KEY, VMK));
        w.m.tpm().corrupt = Some((code, how));
        pin(&mut w, PIN);
        w.m.input(Input::Select(Row::RecoveryKey))
            .secret(RECOVERY_PW);
        assert_eq!(
            w.run(),
            Outcome::Started(Rung::RecoveryKey),
            "{code:#x} {how:?}"
        );
        assert!(w.m.logged("rung tpm failed"), "{code:#x}");
        assert_eq!(unlock_menus(&w.m)[1].tpm, Err(Grey::Unavailable));
    }
}

#[test]
fn response_hmac_is_verified() {
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.tpm().corrupt = Some((cc::UNSEAL, mock::tpm::Corrupt::ResponseHmac));
    pin(&mut w, PIN);
    w.run();
    assert!(w.m.logged("ResponseAuth"));
}

#[test]
fn stage4_stub_halts_after_the_unseal() {
    // The production Volume: stage 3 reaches the TPM, stage 4 is not written.
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    pin(&mut w, PIN);
    let mut bufs = Box::new(paguro_boot::Buffers::new());
    let out = paguro_boot::run(
        &mut w.m,
        &mut paguro_boot::Unimplemented,
        &mut bufs,
        &PARAMS,
    );
    assert_eq!(
        out,
        Outcome::Halted(BootError::NotImplemented("stage 3: FVE metadata"))
    );
    assert!(w.m.logged("rung tpm: unsealed"));
    assert_eq!(
        w.m.screens.last(),
        Some(&Screen::Notice(Notice::NotImplemented))
    );
    assert!(w.m.handoff.is_none());
    // The buffers hold no secrets afterwards.
    assert!(bufs.secret.iter().all(|b| *b == 0));
    assert!(bufs.handoff.iter().all(|b| *b == 0));
}

#[test]
fn chain_failure_is_reported() {
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    w.m.start_fails = true;
    assert_eq!(
        w.run(),
        Outcome::Halted(BootError::Platform(paguro_boot::PlatformError::Device(26)))
    );
    assert!(w.m.handoff.is_some(), "published before the chain attempt");
}

#[test]
fn a_lying_tpm_is_caught() {
    use mock::tpm::Quirk;
    for (quirk, msg) in [
        (Quirk::WrongLoadName, "NameMismatch"),
        (Quirk::ShortPayload, "BadPayload"),
    ] {
        let mut w = World::new();
        w.with_tpm_seal(PIN);
        w.m.tpm().quirk = Some(quirk);
        w.v.recovery = Some((RECOVERY_KEY, VMK));
        pin(&mut w, PIN);
        w.m.input(Input::Select(Row::RecoveryKey))
            .secret(RECOVERY_PW);
        assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey), "{quirk:?}");
        assert!(w.m.logged(msg), "{quirk:?}: {:?}", w.m.log);
        assert!(!w.m.logged("rung tpm: unsealed"));
    }
}

#[test]
fn a_partition_that_is_neither_bitlocker_nor_ntfs() {
    let mut w = World::new();
    w.m.disks = vec![disk(&[(VOLUME, b"EXFAT   ")])];
    assert_eq!(w.run(), Outcome::Halted(BootError::NotAVolume));
}

#[test]
fn a_failed_measurement_halts_the_boot() {
    // Load taint that cannot land.
    let mut w = World::new();
    w.with_tpm_seal(PIN);
    w.m.extend_fails = true;
    let out = w.run();
    assert!(matches!(out, Outcome::Halted(BootError::Tpm(_))), "{out:?}");
    assert!(w.m.screens.is_empty(), "no prompt without the ratchet");
    // A recovery cap that cannot land: recovery refuses to continue.
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.m.extend_fails = true;
    let out = w.run();
    assert!(matches!(out, Outcome::Halted(BootError::Tpm(_))), "{out:?}");
    assert!(w.m.screens.is_empty());
}

#[test]
fn a_maximal_configuration_is_forwarded_whole() {
    // A 64 KiB paguro.ini (INTERFACES §3.1) fits in CONFIG (§8: 96 KiB cap,
    // u32 record lengths) beside every other record.
    let mut w = World::new();
    let mut ini = ini_text(&VOLUME, true);
    ini.extend(vec![b'#'; paguro_core::ini::MAX_LEN - 1 - ini.len()]);
    ini.push(b'\n');
    assert_eq!(ini.len(), paguro_core::ini::MAX_LEN);
    let expected = ini.clone();
    w.set_ini(ini, true);
    w.v.clear_key = Some(VMK);
    w.run();
    let h = w.m.handoff.as_ref().expect("handoff built");
    let d = paguro_core::handoff::decode(h).expect("decodes");
    assert_eq!(d.config, Some(&expected[..]));
}

// ---------------------------------------------------------------------------
// Boot entries: per-entry volumes, per-volume seals

const OTHER: Guid = Guid([0x6d; 16]);

/// A configuration with `entries` as `(name, volume, extra lines)`.
fn entries_ini(default: &str, entries: &[(&str, Guid, &str)]) -> Vec<u8> {
    let mut s = format!("[Paguro]\nversion = 1\ndefault = {default}\n");
    for (name, vol, extra) in entries {
        s.push_str(&format!(
            "\n[Boot.{name}]\nvolume = {vol}\nroot = \\paguro\\{name}.vhd\n{extra}"
        ));
    }
    s.push_str("\n[Passphrase]\nenabled = 1\n");
    s.into_bytes()
}

#[test]
fn an_entry_on_a_second_disks_volume_is_found() {
    let mut w = World::new();
    w.m.disks = vec![disk(&[(VOLUME, BITLOCKER)]), disk(&[(OTHER, BITLOCKER)])];
    w.set_ini(
        entries_ini("arch", &[("debian", VOLUME, ""), ("arch", OTHER, "")]),
        true,
    );
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let (part, _) = w.v.opened.unwrap();
    assert_eq!((part.guid, part.disk), (OTHER, 1));
    assert!(w.m.logged(&format!("volume {OTHER} (BitLocker) on disk 1")));
    assert!(
        !w.m.screens
            .iter()
            .any(|s| matches!(s, Screen::SelectVolume(_)))
    );
    let h = w.m.decoded();
    assert_eq!(h.volume.partition, OTHER);
    assert_eq!(h.root.unwrap().name, "arch");
    assert_eq!(w.v.saw_entry.clone().unwrap().volume, OTHER);
}

#[test]
fn seals_are_read_from_the_volume_directory() {
    let mut w = World::new();
    w.m.disks = vec![disk(&[(VOLUME, BITLOCKER)]), disk(&[(OTHER, BITLOCKER)])];
    w.set_ini(entries_ini("arch", &[("arch", OTHER, "")]), true);
    w.with_passphrase_seal("pw");
    // Move the seal into the entry's volume directory.
    let f =
        w.m.files
            .remove(&seal_file(&VOLUME, Kind::Passphrase))
            .unwrap();
    w.m.files.insert(seal_file(&OTHER, Kind::Passphrase), f);
    assert!(
        seal_file(&OTHER, Kind::Passphrase).starts_with("6d6d6d6d-6d6d-6d6d-6d6d-6d6d6d6d6d6d\\")
    );
    w.m.input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert_eq!(w.m.decoded().volume.partition, OTHER);
}

#[test]
fn seals_for_a_different_volume_are_ignored() {
    // Seals exist for VOLUME (and at the old flat path), but the entry names
    // OTHER: none of them is offered, and the ratchet sees no tpm_seal.bin.
    let mut w = World::new();
    w.m.disks = vec![disk(&[(VOLUME, BITLOCKER)]), disk(&[(OTHER, BITLOCKER)])];
    w.set_ini(entries_ini("arch", &[("arch", OTHER, "")]), true);
    w.with_tpm_seal(PIN).with_passphrase_seal("pw");
    let flat = w.m.files[&seal_file(&VOLUME, Kind::Passphrase)].clone();
    w.m.files.insert(Kind::Passphrase.file_name().into(), flat);
    w.v.recovery = Some((RECOVERY_KEY, VMK));
    w.m.input(Input::Select(Row::RecoveryKey))
        .secret(RECOVERY_PW);
    assert_eq!(w.run(), Outcome::Started(Rung::RecoveryKey));
    assert_eq!(
        w.m.extends(),
        vec![boot_taint()],
        "sentinel, not the load taint"
    );
    assert!(w.m.logged("(no tpm_seal.bin)"));
    let menu = unlock_menus(&w.m)[0];
    assert!(!menu.recovery_passphrase);
    assert!(!menu.password_or_pin);
    assert_eq!(menu.tpm, Err(Grey::Unavailable));
}

#[test]
fn recovery_reads_the_enumerated_volumes_seals() {
    // The configured volume is gone; recovery picks OTHER by enumeration and
    // offers OTHER's passphrase seal, not VOLUME's.
    let mut w = World::new();
    w.m.disks = vec![disk(&[(OTHER, BITLOCKER)])];
    w.with_passphrase_seal("pw");
    let f = w.m.files[&seal_file(&VOLUME, Kind::Passphrase)].clone();
    w.m.files.insert(seal_file(&OTHER, Kind::Passphrase), f);
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryPassphrase))
        .secret("pw");
    assert_eq!(w.run(), Outcome::Started(Rung::Passphrase));
    assert_eq!(w.v.opened.unwrap().0.guid, OTHER);
    // And without OTHER's seal there is nothing to offer.
    let mut w = World::new();
    w.m.disks = vec![disk(&[(OTHER, BITLOCKER)])];
    w.with_passphrase_seal("pw");
    w.m.input(Input::Recover);
    w.run();
    assert!(!unlock_menus(&w.m)[0].recovery_passphrase);
}

#[test]
fn the_default_entry_is_the_one_booted() {
    let mut w = World::new();
    w.set_ini(
        entries_ini(
            "second",
            &[
                ("first", VOLUME, ""),
                (
                    "second",
                    VOLUME,
                    "efi = \\EFI\\systemd\\systemd-bootx64.efi\n",
                ),
            ],
        ),
        true,
    );
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(w.m.logged("stage2 ok (2 entries, default second)"));
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(saw.name, "second");
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\second.vhd"));
    assert!(saw.efi.contains("systemd-bootx64.efi"), "{}", saw.efi);
    let h = w.m.decoded();
    assert_eq!(h.root.unwrap().name, "second");
    assert_eq!(h.efi_disk, None);
}

#[test]
fn a_separate_efi_disk_is_forwarded_and_a_defaulted_one_is_not() {
    // Separate: both IMAGE records, same entry name, different files.
    let mut w = World::new();
    w.set_ini(
        entries_ini(
            "debian",
            &[("debian", VOLUME, "efi_disk = \\paguro\\esp.vhd\n")],
        ),
        true,
    );
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        (
            saw.root.as_deref(),
            saw.efi.contains("\\\\paguro\\\\esp.vhd")
        ),
        (Some("\\paguro\\debian.vhd"), true),
        "{}",
        saw.efi
    );
    let h = w.m.decoded();
    let root = h.root.unwrap();
    assert_eq!((root.mft_record, root.mft_seq), (1234, 7));
    let e = h.efi_disk.expect("separate efi disk forwarded");
    assert_eq!((e.name, e.mft_record, e.mft_seq), ("debian", 4321, 3));

    // Written out but equal to root: the same as absent.
    let mut w = World::new();
    w.set_ini(
        entries_ini(
            "debian",
            &[("debian", VOLUME, "efi_disk = \\paguro\\debian.vhd\n")],
        ),
        true,
    );
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(w.m.decoded().efi_disk, None);

    // The volume layer resolving both paths to one file is not forwarded twice.
    let mut w = World::new();
    w.set_ini(
        entries_ini(
            "debian",
            &[("debian", VOLUME, "efi_disk = \\paguro\\link.vhd\n")],
        ),
        true,
    );
    w.v.clear_key = Some(VMK);
    w.v.efi_disk = (1234, 7);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(w.m.decoded().efi_disk, None);
}

#[test]
fn first_boot_unlocks_the_bootstrap_payloads_volume() {
    // Two BitLocker volumes: no question asked, the payload names VOLUME, and
    // the authored configuration (and so its seal) names it too.
    let mut w = bootstrap_world(PIN);
    w.m.disks = vec![disk(&[(OTHER, BITLOCKER)]), disk(&[(VOLUME, BITLOCKER)])];
    w.v.efi_disk_path = Some("\\paguro\\esp.vhd");
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Bootstrap));
    assert!(
        !w.m.screens
            .iter()
            .any(|s| matches!(s, Screen::SelectVolume { .. }))
    );
    assert_eq!(w.v.opened.unwrap().0.guid, VOLUME);
    assert_eq!(w.v.locate_saw_config, Some(false));
    let h = w.m.decoded();
    let cfg = paguro_core::config::parse(h.config.unwrap()).unwrap();
    let e = cfg.default_entry().unwrap();
    assert_eq!((e.name, e.volume), ("debian", VOLUME));
    assert_eq!(
        e.efi,
        Efi::Disk {
            disk: "\\paguro\\esp.vhd",
            path: paguro_core::config::DEFAULT_EFI
        }
    );
    assert!(h.provision.is_some());
    assert_eq!(h.efi_disk.map(|e| e.mft_record), Some(4321));
}

// ---------------------------------------------------------------------------
// efi_file: a UEFI image directly on NTFS

#[test]
fn an_efi_file_entry_is_started_from_a_buffer() {
    let mut w = World::new();
    w.set_ini(
        entries_ini("debian", &[])
            .into_iter()
            .chain(
                format!("\n[Boot.debian]\nvolume = {VOLUME}\nefi_file = \\paguro\\rescue.efi\n")
                    .into_bytes(),
            )
            .collect(),
        true,
    );
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(saw.root, None);
    assert_eq!(saw.efi, format!("{:?}", Efi::File("\\paguro\\rescue.efi")));
    // LoadImage(SourceBuffer) with the bytes stage 4 read; no device path.
    assert_eq!(
        w.m.events.last(),
        Some(&Event::StartBuffer(b"MZ-fake-uki".to_vec()))
    );
    assert!(!w.m.events.iter().any(|e| matches!(e, Event::Start(_))));
    let h = w.m.decoded();
    assert_eq!(h.root, None, "no root: none forwarded");
    assert_eq!(h.efi_disk, None);
    let f = h.efi_file.expect("efi file forwarded");
    assert_eq!((f.name, f.mft_record, f.mft_seq), ("debian", 777, 1));
}

#[test]
fn an_efi_file_beside_a_root_forwards_both() {
    let mut w = World::new();
    w.set_ini(
        entries_ini(
            "debian",
            &[("debian", VOLUME, "efi_file = \\paguro\\uki.efi\n")],
        ),
        true,
    );
    w.v.clear_key = Some(VMK);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let h = w.m.decoded();
    assert_eq!(h.root.map(|r| r.mft_record), Some(1234));
    assert_eq!(h.efi_file.map(|r| r.mft_record), Some(777));
    assert_eq!(h.efi_disk, None);
}

#[test]
fn an_efi_file_entry_reaches_the_stage4_stub_with_its_target() {
    // Stage 4 is not written: the stub is reached with the configured entry,
    // and nothing is published or started.
    let mut w = World::new();
    w.set_ini(
        format!(
            "[Paguro]\nversion = 1\ndefault = rescue\n\n[Boot.rescue]\nvolume = {VOLUME}\nefi_file = \\paguro\\rescue.efi\n"
        )
        .into_bytes(),
        true,
    );
    w.v.clear_key = Some(VMK);
    w.v.stub_stage4 = true;
    assert_eq!(
        w.run(),
        Outcome::Halted(BootError::NotImplemented("stage 4: NTFS + image"))
    );
    let saw = w.v.saw_entry.clone().expect("stage 4 was asked");
    assert_eq!(
        (saw.name.as_str(), saw.volume, saw.root),
        ("rescue", VOLUME, None)
    );
    assert_eq!(saw.efi, format!("{:?}", Efi::File("\\paguro\\rescue.efi")));
    assert!(w.m.handoff.is_none());
    assert!(
        !w.m.events
            .iter()
            .any(|e| matches!(e, Event::Start(_) | Event::StartBuffer(_)))
    );
    // The production stub refuses the buffer read too.
    let mut m = Mock::new();
    let mut stub = paguro_boot::Unimplemented;
    let r = paguro_boot::Volume::<Mock>::efi_image(&mut stub, &mut m).map(<[u8]>::to_vec);
    assert_eq!(
        r.err(),
        Some(BootError::NotImplemented("stage 4: efi_file read"))
    );
}

#[test]
fn first_boot_can_author_an_efi_file_entry() {
    let mut w = bootstrap_world(PIN);
    w.v.efi_file_path = Some("\\paguro\\rescue.efi");
    pin(&mut w, PIN);
    assert_eq!(w.run(), Outcome::Started(Rung::Bootstrap));
    let h = w.m.decoded();
    let cfg = paguro_core::config::parse(h.config.unwrap()).unwrap();
    let e = cfg.default_entry().unwrap();
    assert_eq!((e.root, e.efi), (None, Efi::File("\\paguro\\rescue.efi")));
    assert_eq!(h.root, None);
    assert!(h.efi_file.is_some());
    assert!(matches!(w.m.events.last(), Some(Event::StartBuffer(_))));
}

// ---------------------------------------------------------------------------
// Recovery: what to boot — the browser (INTERFACES.md §13.4)

use paguro_boot::platform::Level;

/// No configuration (recovery), one BitLocker volume with a clear key.
fn recovery_world() -> World {
    let mut w = World::new();
    w.m.files.remove("paguro.ini");
    w.v.clear_key = Some(VMK);
    w
}

fn browsed(m: &Mock) -> Vec<(String, Vec<String>, usize)> {
    m.browsed.clone()
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The root-hint browsers shown: path and entries.
fn root_lists(m: &Mock) -> Vec<(String, Vec<String>)> {
    m.browsed
        .iter()
        .zip(&m.browsed_levels)
        .filter(|(_, l)| **l == Level::Root)
        .map(|((p, n, _), _)| (p.clone(), n.clone()))
        .collect()
}

fn efi_disk(disk: &str, path: &str) -> String {
    format!("{:?}", Efi::Disk { disk, path })
}

const DEFAULT: &str = paguro_core::config::DEFAULT_EFI;

#[test]
fn the_browser_starts_in_paguro_sorted_and_filtered() {
    let mut w = recovery_world();
    w.v.dir(
        "\\paguro",
        &[
            "debian.vhd",
            "notes.txt",
            "Old/",
            "arch.VHDX",
            "rescue.efi",
            "$Extend/",
        ],
    );
    w.m.input(Input::Entry(2)).input(Input::UseDefault);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(
        browsed(&w.m),
        vec![(
            "\\paguro".into(),
            names(&["Old", "arch.VHDX", "debian.vhd", "rescue.efi"]),
            0
        )],
        "folders first, case-insensitive; only disks and UEFI images"
    );
    assert!(w.m.screens.contains(&Screen::Browse(Level::Volume)));
    // A disk is its own root and, here, starts its default image.
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(saw.name, "debian");
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\debian.vhd"));
    assert_eq!(saw.efi, efi_disk("\\paguro\\debian.vhd", DEFAULT));
    let h = w.m.decoded();
    assert_eq!(h.root.unwrap().name, "debian");
    assert_eq!(h.config, None);
    assert_eq!(h.state & state::RECOVERY_PATH, state::RECOVERY_PATH);
    assert_eq!(
        w.m.events.last(),
        Some(&Event::Start(b"chain-device-path".to_vec()))
    );
}

#[test]
fn folders_open_and_parent_returns_to_the_folder_left() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["a/", "b/", "x.vhd", "y.vhd"])
        .dir("\\paguro\\b", &["inner/", "rescue.efi"])
        .dir("\\paguro\\b\\inner", &[])
        .dir("\\", &["paguro/", "Users/"]);
    w.m.input(Input::Entry(1)) // b
        .input(Input::Entry(0)) // inner (empty)
        .input(Input::Parent) // back to b, on "inner"
        .input(Input::Parent) // back to \paguro, on "b"
        .input(Input::Parent) // the volume root, on "paguro"
        .input(Input::Parent) // at the root: stays
        .input(Input::Entry(0)) // paguro
        .input(Input::Entry(1)) // b
        .input(Input::Entry(1)) // rescue.efi → root hint
        .input(Input::Entry(3)); // y.vhd (after the folders a, b)
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let b: Vec<_> = browsed(&w.m).into_iter().map(|(p, _, s)| (p, s)).collect();
    assert_eq!(
        b,
        vec![
            ("\\paguro".to_string(), 0),
            ("\\paguro\\b".into(), 0),
            ("\\paguro\\b\\inner".into(), 0),
            ("\\paguro\\b".into(), 0),
            ("\\paguro".into(), 1),
            ("\\".into(), 0),
            ("\\".into(), 0),
            ("\\paguro".into(), 0),
            ("\\paguro\\b".into(), 0),
            ("\\paguro".into(), 0),
        ]
    );
    assert_eq!(
        root_lists(&w.m),
        vec![("\\paguro".into(), names(&["a", "b", "x.vhd", "y.vhd"]))],
        "the root-hint browser: folders and disks, no UEFI images"
    );
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        saw.efi,
        format!("{:?}", Efi::File("\\paguro\\b\\rescue.efi"))
    );
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\y.vhd"));
    let h = w.m.decoded();
    assert_eq!(h.efi_file.unwrap().name, "rescue");
    assert_eq!(h.root.unwrap().mft_record, 1234);
}

#[test]
fn an_efi_file_takes_the_only_disk_in_paguro_as_its_root() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["tools/", "debian.vhd"])
        .dir("\\paguro\\tools", &["rescue.efi"]);
    w.m.input(Input::Entry(0)).input(Input::Entry(0));
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(root_lists(&w.m).is_empty(), "one candidate: no list");
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\debian.vhd")
    );
    assert_eq!(
        w.m.events.last(),
        Some(&Event::StartBuffer(b"MZ-fake-uki".to_vec()))
    );
}

#[test]
fn no_root_leaves_the_hint_empty_and_no_disk_means_none() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["a.vhd", "rescue.efi", "b.vhd"]);
    w.m.input(Input::Entry(2)).input(Input::NoRoot);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(w.m.decoded().root, None, "the initrd asks");

    let mut w = recovery_world();
    w.v.dir("\\paguro", &["rescue.efi"]);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(
        browsed(&w.m).is_empty(),
        "a lone UEFI image is taken silently"
    );
    assert_eq!(w.m.decoded().root, None);
}

#[test]
fn escape_from_the_root_browser_returns_to_the_first_one() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["rescue.efi", "a.vhd", "b.vhd"]);
    w.m.input(Input::Entry(2))
        .input(Input::Escape)
        .input(Input::Entry(1))
        .input(Input::UseDefault);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let b: Vec<_> = browsed(&w.m).into_iter().map(|(p, _, s)| (p, s)).collect();
    assert_eq!(
        b,
        vec![
            ("\\paguro".to_string(), 0),
            ("\\paguro".into(), 0),
            ("\\paguro".into(), 2),
        ],
        "back on the UEFI image that led to the root question"
    );
    assert_eq!(root_lists(&w.m).len(), 1);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\b.vhd")
    );
}

#[test]
fn the_root_browser_walks_folders_and_takes_typed_paths() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["rescue.efi", "a.vhd", "b.vhd", "vms/"])
        .dir("\\paguro\\vms", &["deep.vhdx", "other.efi"]);
    w.m.input(Input::Entry(3)) // rescue.efi (vms, a, b, rescue)
        .input(Input::Entry(0)) // vms
        .input(Input::Entry(0)); // deep.vhdx
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(
        root_lists(&w.m),
        vec![
            ("\\paguro".into(), names(&["vms", "a.vhd", "b.vhd"])),
            ("\\paguro\\vms".into(), names(&["deep.vhdx"])),
        ]
    );
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\vms\\deep.vhdx")
    );

    let mut w = recovery_world();
    w.v.dir("\\paguro", &["rescue.efi", "a.vhd", "b.vhd"]);
    w.m.input(Input::Entry(2)).input(Input::TypePath);
    w.m.secret("\\Linux\\root.img");
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\Linux\\root.img")
    );
}

#[test]
fn a_disk_can_start_an_image_browsed_on_its_efi_partition() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["debian.vhd", "arch.vhd"])
        .esp_dir("\\paguro\\debian.vhd", "\\", &["EFI/", "startup.nsh"])
        .esp_dir(
            "\\paguro\\debian.vhd",
            "\\EFI",
            &["BOOT/", "systemd/", "Linux/"],
        )
        .esp_dir(
            "\\paguro\\debian.vhd",
            "\\EFI\\systemd",
            &["systemd-bootx64.efi", "notes.txt"],
        );
    w.m.input(Input::Entry(1)) // debian.vhd
        .input(Input::BrowseDisk)
        .input(Input::Entry(0)) // EFI
        .input(Input::Entry(2)) // systemd (BOOT, Linux, systemd)
        .input(Input::Entry(0)); // systemd-bootx64.efi
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let b = browsed(&w.m);
    assert_eq!(
        b[1],
        ("\\".into(), names(&["EFI"]), 0),
        "only folders and UEFI images"
    );
    assert_eq!(b[2].1, names(&["BOOT", "Linux", "systemd"]));
    assert_eq!(b[3].1, names(&["systemd-bootx64.efi"]));
    assert!(w.m.screens.contains(&Screen::Browse(Level::EfiPartition)));
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(
        saw.efi,
        efi_disk(
            "\\paguro\\debian.vhd",
            "\\EFI\\systemd\\systemd-bootx64.efi"
        )
    );
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\debian.vhd"));
    assert!(w.m.logged(
        "recovery target \\paguro\\debian.vhd efi \\EFI\\systemd\\systemd-bootx64.efi (root \\paguro\\debian.vhd)"
    ));
    // Stage 4 was asked for that image, and started it by device path.
    assert_eq!(
        w.m.events.last(),
        Some(&Event::Start(
            b"chain-device-path:\\EFI\\systemd\\systemd-bootx64.efi".to_vec()
        ))
    );
    let h = w.m.decoded();
    assert_eq!(h.root.unwrap().name, "debian");
    assert_eq!(
        h.efi_disk, None,
        "the efi disk is the root: not forwarded twice"
    );
}

#[test]
fn the_efi_partition_browser_backs_out_step_by_step() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["a.vhd", "b.vhd"])
        .esp_dir("\\paguro\\b.vhd", "\\", &["EFI/"])
        .esp_dir("\\paguro\\b.vhd", "\\EFI", &["BOOT/"]);
    w.m.input(Input::Entry(1))
        .input(Input::BrowseDisk)
        .input(Input::Entry(0)) // \EFI
        .input(Input::Parent) // \ , on EFI
        .input(Input::Escape) // back to the disk screen
        .input(Input::Escape) // back to the volume browser
        .input(Input::Entry(0)) // a.vhd
        .input(Input::UseDefault);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    let b: Vec<_> = browsed(&w.m).into_iter().map(|(p, _, s)| (p, s)).collect();
    assert_eq!(
        b,
        vec![
            ("\\paguro".to_string(), 0),
            ("\\".into(), 0),
            ("\\EFI".into(), 0),
            ("\\".into(), 0),
            ("\\paguro".into(), 1),
        ]
    );
    let disk_screens =
        w.m.screens
            .iter()
            .filter(|s| matches!(s, Screen::DiskStart { .. }))
            .count();
    assert_eq!(disk_screens, 3, "b, b again after the browser, then a");
    assert_eq!(
        w.v.saw_entry.clone().unwrap().efi,
        efi_disk("\\paguro\\a.vhd", DEFAULT)
    );
}

#[test]
fn a_disk_without_an_efi_partition_says_so() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["plain.img", "other.img"]);
    w.m.input(Input::Entry(1))
        .input(Input::BrowseDisk)
        .input(Input::UseDefault);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(w.m.screens.contains(&Screen::NoEfiPartition));
    assert!(w.m.logged("no EFI partition on \\paguro\\plain.img"));
}

#[test]
fn typed_paths_on_both_levels() {
    // On the volume: a UEFI image anywhere.
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["debian.vhd", "arch.vhd"]);
    w.m.input(Input::TypePath).secret("\\boot\\Rescue.EFI");
    w.m.input(Input::Entry(0));
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(w.m.screens.contains(&Screen::EnterPath(Level::Volume)));
    let saw = w.v.saw_entry.clone().unwrap();
    assert_eq!(saw.name, "Rescue");
    assert_eq!(saw.efi, format!("{:?}", Efi::File("\\boot\\Rescue.EFI")));
    assert_eq!(saw.root.as_deref(), Some("\\paguro\\arch.vhd"));

    // On the disk's EFI partition.
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["debian.vhd", "arch.vhd"]);
    w.m.input(Input::Entry(1)).input(Input::TypePath);
    w.m.secret("\\EFI\\debian\\shimx64.efi");
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(
        w.m.screens
            .contains(&Screen::EnterPath(Level::EfiPartition))
    );
    assert_eq!(
        w.v.saw_entry.clone().unwrap().efi,
        efi_disk("\\paguro\\debian.vhd", "\\EFI\\debian\\shimx64.efi")
    );
}

#[test]
fn a_bad_typed_path_is_refused_and_the_browser_returns() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &[]);
    w.m.input(Input::TypePath).secret("\\a*b.vhd");
    w.m.input(Input::TypePath).secret("\\a\\..\\b.vhd");
    w.m.input(Input::TypePath).secret("\\paguro\\debian.vhd");
    w.m.input(Input::UseDefault);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert_eq!(
        w.m.screens
            .iter()
            .filter(|s| **s == Screen::PathRefused)
            .count(),
        2
    );
    assert_eq!(browsed(&w.m).len(), 3);
    assert_eq!(
        w.v.saw_entry.clone().unwrap().root.as_deref(),
        Some("\\paguro\\debian.vhd")
    );
}

#[test]
fn typed_paths_take_slashes_and_ignore_drive_letters() {
    for typed in [
        "C:\\paguro\\debian.vhd",
        "d:/paguro/debian.vhd",
        "paguro/debian.vhd",
    ] {
        let mut w = recovery_world();
        w.v.dir("\\paguro", &[]);
        w.m.input(Input::TypePath).secret(typed);
        w.m.input(Input::UseDefault);
        assert_eq!(w.run(), Outcome::Started(Rung::ClearKey), "{typed}");
        assert_eq!(
            w.v.saw_entry.clone().unwrap().root.as_deref(),
            Some("\\paguro\\debian.vhd"),
            "{typed}"
        );
        assert_eq!(
            w.m.logged("drive letter ignored"),
            typed.contains(':'),
            "{typed}"
        );
    }
}

#[test]
fn paths_stay_within_the_bounds() {
    // 255-character folder names: the fifth level would exceed 1024 bytes,
    // so it is refused and the browser stays where it was.
    let long = |c: char| c.to_string().repeat(255);
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["x.vhd", "y.vhd"]);
    let mut path = String::new();
    let mut parent = "\\".to_string();
    for c in ['a', 'b', 'c', 'd', 'e'] {
        w.v.dir(&parent, &[&format!("{}/", long(c))]);
        path = format!("{path}\\{}", long(c));
        parent = path.clone();
    }
    w.m.input(Input::Parent);
    for _ in 0..5 {
        w.m.input(Input::Entry(0));
    }
    let out = w.run();
    assert_eq!(out, Outcome::Halted(BootError::UserAbort));
    assert!(w.m.screens.contains(&Screen::PathRefused));
    let last = browsed(&w.m).last().unwrap().0.clone();
    assert_eq!(last.len(), 4 * 256, "still in the fourth level");
}

#[test]
fn escape_from_the_browser_ends_the_boot() {
    let mut w = recovery_world();
    w.v.dir("\\paguro", &["a.vhd", "b.vhd"]);
    w.m.input(Input::Escape);
    assert_eq!(w.run(), Outcome::Halted(BootError::UserAbort));
    assert!(w.m.handoff.is_none());
}

#[test]
fn a_normal_boot_never_browses() {
    let mut w = World::new();
    w.v.clear_key = Some(VMK);
    w.v.dir("\\paguro", &["x.vhd", "y.vhd"]);
    assert_eq!(w.run(), Outcome::Started(Rung::ClearKey));
    assert!(browsed(&w.m).is_empty());
    assert!(w.v.listed.is_empty());
}

#[test]
fn production_stub_refuses_the_listings() {
    use paguro_boot::Volume;
    use paguro_boot::platform::DirListing;
    let mut m = Mock::new();
    let mut d = Box::new(DirListing::new());
    assert!(matches!(
        paguro_boot::Unimplemented.list_dir(&mut m, "\\paguro", &mut d),
        Err(BootError::NotImplemented(_))
    ));
    assert!(matches!(
        paguro_boot::Unimplemented.list_efi_dir(&mut m, "\\a.vhd", "\\", &mut d),
        Err(BootError::NotImplemented(_))
    ));
}
