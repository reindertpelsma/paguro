//! The Windows side's TPM work against a real TPM 2.0 (swtpm), checked by
//! the loader's own unseal: the PIN bypass `restart-linux` writes must open
//! the Windows-made BitLocker fixture through `paguro_boot::tpm::Tpm::unseal`
//! exactly as the loader calls it, and the pre-flight's prediction must
//! follow the PCRs and the TCG log. Skipped when swtpm is not installed.
#![cfg(unix)]
#![allow(clippy::indexing_slicing)]

mod common;

use common::*;
use paguro_boot::tpm::Tpm;
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, PAGURO_VENDOR};
use paguro_core::recorded::{self, Recorded};
use paguro_core::seal::{self, Kind};
use paguro_core::tcglog::{EV_EFI_VARIABLE_AUTHORITY, EV_EFI_VARIABLE_DRIVER_CONFIG};
use paguro_win::api::attr;
use paguro_win::mock::{ESP_PATH, MockApi, MockFile};
use sha2::{Digest, Sha256};

fn esp_file(name: &str) -> String {
    format!("{ESP_PATH}EFI\\paguro\\{name}")
}

fn log(dbx: [u8; 32]) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    let n = paguro_core::tcglog::write(
        &[
            (7, EV_EFI_VARIABLE_DRIVER_CONFIG, [1; 32], b"SecureBoot"),
            (7, EV_EFI_VARIABLE_DRIVER_CONFIG, dbx, b"dbx"),
            (
                7,
                EV_EFI_VARIABLE_AUTHORITY,
                [3; 32],
                b"Windows Production PCA",
            ),
        ],
        &mut b,
    )
    .unwrap();
    b.truncate(n);
    b
}

/// An installed machine on BitLocker with a TPM, whose last Linux boot
/// recorded exactly this machine's state, and PCR 12 as the loader leaves it.
fn machine() -> Option<(MockApi, std::rc::Rc<std::cell::RefCell<Swtpm>>)> {
    let t = swtpm()?;
    let m = MockApi::standard();
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    attach(&m, &t);
    with_bitlocker(&m);
    install_esp(&m);
    let mut f = MockFile::zeros(64 << 20);
    f.write_at(64 << 20, &paguro_win::mock::fixed_vhd_footer(64 << 20));
    m.put_mock_file("C:\\paguro\\debian.vhd", f);
    ok(
        &m,
        &[
            "config",
            "set",
            "--entry",
            "debian",
            "--root",
            "C:\\paguro\\debian.vhd",
        ],
    );
    *m.log.borrow_mut() = log([2; 32]);
    let pcrs = paguro_win::tpmwin::pcr_read(&m, 0x95).unwrap();
    let h = |n: &str| -> [u8; 32] { Sha256::digest(m.file(&esp_file(n)).unwrap()).into() };
    let rec = Recorded {
        pcrs: [
            *pcrs.get(0).unwrap(),
            *pcrs.get(2).unwrap(),
            *pcrs.get(4).unwrap(),
            *pcrs.get(7).unwrap(),
        ],
        secure_boot_config: paguro_win::preflight::secure_boot_config(&log([2; 32])).unwrap(),
        shim_sha256: h("shimx64.efi"),
        loader_sha256: h("paguro.efi"),
    };
    let mut b = [0u8; recorded::LEN];
    recorded::write(&rec, &mut b).unwrap();
    m.put_file(
        &esp_file(&format!("{}\\recorded.bin", paguro_win::mock::C_GUID)),
        &b,
    );
    let ini = m.file(&esp_file("paguro.ini")).unwrap();
    t.borrow_mut().pcr_extend(12, &Sha256::digest(&ini).into());
    Some((m, t))
}

fn tpm_check(d: &serde_json::Value) -> serde_json::Value {
    d["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "tpm")
        .unwrap()
        .clone()
}

#[test]
fn restart_linux_writes_a_bypass_the_loader_unseals() {
    let Some((m, t)) = machine() else { return };
    let r = run(&m, &["restart-linux"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(tpm_check(&r.json["data"])["state"], "ok");
    assert!(
        r.json["data"]["pin_bypass"]["file"].is_string(),
        "{}",
        r.json["data"]["pin_bypass"]
    );
    let file = m
        .file(&esp_file(&format!(
            "{}\\tpm_pin_bypass_seal.bin",
            paguro_win::mock::C_GUID
        )))
        .unwrap();
    let s = seal::read(Kind::PinBypass, &file).unwrap();
    let sealed = s.sealed.unwrap();
    // Exactly the loader's call (paguro-boot machine.rs try_pin_bypass).
    let mut d = [0u8; 32];
    let mut lp = LoaderTpm(t.clone());
    Tpm::new(&mut lp)
        .unseal(
            sealed.private,
            sealed.public,
            s.pcrs.unwrap().mask,
            s.deadline,
            &[],
            &mut d,
        )
        .unwrap();
    let vmk = paguro_crypto::xor32(&d, s.wrapped_vmk);
    assert!(
        vmk_opens_fixture(&vmk),
        "the bypass must yield the volume's VMK"
    );
    assert!(!r.stdout.contains(&paguro_win::out::to_hex(&vmk)));
    // After a PCR the policy names moves, it opens nothing.
    t.borrow_mut().pcr_extend(7, &[0x55; 32]);
    let mut lp = LoaderTpm(t.clone());
    assert!(
        Tpm::new(&mut lp)
            .unseal(
                sealed.private,
                sealed.public,
                s.pcrs.unwrap().mask,
                s.deadline,
                &[],
                &mut d
            )
            .is_err()
    );
}

#[test]
fn an_expired_bypass_opens_nothing() {
    let Some((m, t)) = machine() else { return };
    let ini = m.file(&esp_file("paguro.ini")).unwrap();
    let pcrs = paguro_win::tpmwin::pcr_read(&m, 0x95).unwrap();
    let rec = Recorded {
        pcrs: [
            *pcrs.get(0).unwrap(),
            *pcrs.get(2).unwrap(),
            *pcrs.get(4).unwrap(),
            *pcrs.get(7).unwrap(),
        ],
        ..Recorded::default()
    };
    let (file, _) = paguro_win::tpmwin::create_pin_bypass(&m, &rec, &ini, &[7; 32], 0).unwrap();
    let s = seal::read(Kind::PinBypass, &file).unwrap();
    let sealed = s.sealed.unwrap();
    let mut d = [0u8; 32];
    let mut lp = LoaderTpm(t.clone());
    assert!(
        Tpm::new(&mut lp)
            .unseal(
                sealed.private,
                sealed.public,
                s.pcrs.unwrap().mask,
                s.deadline,
                &[],
                &mut d
            )
            .is_err()
    );
    // The same with an hour left opens.
    let (file, _) =
        paguro_win::tpmwin::create_pin_bypass(&m, &rec, &ini, &[7; 32], 3_600_000).unwrap();
    let s = seal::read(Kind::PinBypass, &file).unwrap();
    let sealed = s.sealed.unwrap();
    let mut lp = LoaderTpm(t);
    Tpm::new(&mut lp)
        .unseal(
            sealed.private,
            sealed.public,
            s.pcrs.unwrap().mask,
            s.deadline,
            &[],
            &mut d,
        )
        .unwrap();
    assert_eq!(paguro_crypto::xor32(&d, s.wrapped_vmk), [7; 32]);
}

#[test]
fn preflight_predicts_a_dbx_update_and_a_firmware_change() {
    let Some((m, t)) = machine() else { return };
    let d = ok(&m, &["preflight"]);
    assert_eq!(tpm_check(&d)["state"], "ok");
    assert_eq!(d["action"]["action"], "restart");
    // Windows Update ships a dbx: the driver-config prefix moves.
    *m.log.borrow_mut() = log([9; 32]);
    let d = ok(&m, &["preflight"]);
    assert_eq!(d["action"]["reason"], "secure_boot_databases");
    // …and restart-linux stages setupTPM instead of writing a bypass.
    *m.stdin.borrow_mut() = b"pw\n".to_vec();
    let r = run(&m, &["--passphrase-stdin", "restart-linux"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.json["data"]["staged"].is_object());
    assert!(r.json["data"]["pin_bypass"].is_null());
    assert!(m.var("PaguroSetup", &PAGURO_VENDOR).is_some());
    // A firmware update moves PCR 0.
    *m.log.borrow_mut() = log([2; 32]);
    t.borrow_mut().pcr_extend(0, &[1; 32]);
    let d = ok(&m, &["preflight"]);
    assert_eq!(d["action"]["reason"], "firmware");
}
