//! Property tests over whole mock boots: whatever the ESP, the variables, the
//! disks, the TPM's answers and the user's keystrokes, the stage machine
//! terminates without panicking, and its security invariants hold.
#![allow(clippy::indexing_slicing)]

mod mock;

use mock::*;
use paguro_boot::platform::{Input, Row};
use paguro_boot::{Buffers, Outcome};
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, PAGURO_VENDOR};
use paguro_core::handoff::state;
use paguro_core::seal::Kind;
use proptest::prelude::*;

fn input() -> impl Strategy<Value = (Input, Option<Vec<u8>>)> {
    prop_oneof![
        Just((Input::Select(Row::PasswordOrPin), None)),
        Just((Input::Select(Row::RecoveryPassphrase), None)),
        Just((Input::Select(Row::RecoveryKey), None)),
        Just((Input::StartWindows, None)),
        Just((Input::Recover, None)),
        Just((Input::Continue, None)),
        Just((Input::Escape, None)),
        any::<u8>().prop_map(|i| (Input::Choose(i), None)),
        proptest::collection::vec(any::<u8>(), 0..300)
            .prop_map(|s| (Input::Secret(s.len()), Some(s))),
        Just((Input::Secret(PIN.len()), Some(PIN.as_bytes().to_vec()))),
    ]
}

fn blob(max: usize) -> impl Strategy<Value = Option<Vec<u8>>> {
    proptest::option::of(proptest::collection::vec(any::<u8>(), 0..max))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn hostile_environment_never_panics(
        ini in blob(600),
        seals in proptest::array::uniform4(blob(700)),
        hash in blob(40),
        b in blob(40),
        s in blob(40),
        boot_current in blob(3),
        boot_var in blob(300),
        sb in any::<bool>(),
        tpm in any::<bool>(),
        pcr12 in any::<bool>(),
        disk_noise in proptest::collection::vec((0usize..4096 * 512, any::<u8>()), 0..8),
        script in proptest::collection::vec(input(), 0..8),
    ) {
        let mut w = World::new();
        w.with_tpm_seal(PIN);
        match ini { Some(i) => w.set_ini(i, false), None => { w.m.files.remove("paguro.ini"); } }
        for (kind, f) in Kind::ALL.iter().zip(seals) {
            if let Some(f) = f { w.m.files.insert(kind.file_name().into(), f); }
        }
        let mut set = |name: &str, vendor, v: Option<Vec<u8>>| match v {
            Some(v) => w.m.put_var(name, vendor, 7, &v),
            None => { w.m.vars.remove(&(name.to_string(), vendor)); }
        };
        set("PaguroConfigHash", PAGURO_VENDOR, hash);
        set("PaguroB", PAGURO_VENDOR, b);
        set("PaguroSetup", PAGURO_VENDOR, s);
        set("BootCurrent", EFI_GLOBAL_VARIABLE, boot_current);
        set("Boot0001", EFI_GLOBAL_VARIABLE, boot_var);
        w.m.secure_boot = sb;
        if !tpm { w.m.tpm = None; } else if pcr12 { w.m.tpm().pcrs[12] = [9; 32]; }
        for (at, v) in disk_noise { w.m.disks[0].data[at] = v; }
        w.m.script = script.into_iter().collect();
        w.v.recovery = Some((RECOVERY_KEY_BYTES, VMK));
        let out = w.run();
        // Invariants whatever happened:
        if let Some(h) = w.m.handoff.as_ref() {
            let h = paguro_core::handoff::decode(h).expect("the loader only publishes valid handoffs");
            prop_assert!(matches!(out, Outcome::Started(_) | Outcome::Halted(_)));
            if h.state & state::RECOVERY_PATH != 0 {
                prop_assert!(h.config.is_none(), "recovery never forwards the configuration");
            }
            // A published VMK is the right one.
            if let Some(v) = h.vmk { prop_assert_eq!(v, &VMK); }
        }
        if let Some(t) = w.m.tpm.as_ref() {
            // If anything was measured, the last word before a key is the cap.
            if w.m.handoff.is_some() {
                prop_assert_eq!(w.m.extends().last().copied(), Some(boot_taint()));
            }
            prop_assert_eq!(t.live_handles(), 0, "no TPM handle leaks");
        }
    }

    #[test]
    fn arbitrary_tpm_responses_never_panic(
        responses in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 0..30),
        script in proptest::collection::vec(input(), 0..6),
    ) {
        let mut w = World::new();
        w.with_tpm_seal(PIN).with_bypass_seal(2_000_000);
        w.m.raw_tpm = responses.into_iter().collect();
        w.m.script = script.into_iter().collect();
        let mut bufs = Box::new(Buffers::new());
        let _ = paguro_boot::run(&mut w.m, &mut w.v, &mut bufs, &PARAMS);
    }
}

const RECOVERY_KEY_BYTES: [u8; 16] = [1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0xff, 0xff];
