//! `%ProgramData%\paguro\<volume-guid>\tpm-auth.bin` (INTERFACES.md §8.4):
//! the salted, stretched passphrase hash (`paguro_core::tpm_auth`) the `tpm`
//! rung mixes into its TPM object's `authValue` and into `derive_vmk`'s
//! wrapping key — `keys::pass_hash`'s own output, never the raw password
//! hash.
//!
//! Written whenever [`crate::cmd::transition::stage`] re-prepares the
//! loader's seal material from a freshly typed passphrase, so
//! `paguro-initrd` can re-seal the `tpm` rung after `PaguroTpmBroken`
//! without asking for a PIN of its own (`crates/paguro-initrd/src/reseal.rs`).
//! Read by Linux through the read-only ntfs3 mount it already has open.
//!
//! **ACL**: SYSTEM full control; Administrators read and delete (so
//! uninstall's ordinary recursive cleanup of `%ProgramData%\paguro` still
//! works) but not write — nobody else, not inherited. `C:` is
//! BitLocker-encrypted at rest, so a stolen, powered-off machine cannot read
//! this file at all; letting even an unlocked machine's Administrators only
//! *read* it costs a live-admin reader the same 2^20-round
//! (`paguro_crypto::STRETCH_ITERATIONS`) stretch an offline attacker already
//! pays against `tpm_seal.bin`'s own salt, so the file buys no cheaper
//! dictionary attack than the seal it sits beside already exposes.
//!
//! Deleted by uninstall as part of the ordinary `remove_tree_or_later` sweep
//! of `%ProgramData%\paguro` (`crates/paguro-win/src/cmd/uninstall.rs`) —
//! this module needs no special-cased removal step, only the ACL above
//! letting that sweep succeed.

use paguro_core::guid::Guid;

use crate::api::join;
use crate::ctx::Ctx;
use crate::out::{CmdError, guid_text};

pub use paguro_core::tpm_auth::FILE_NAME;

/// SYSTEM: full control. Administrators: read and delete, not write. Nobody
/// else; the DACL is protected (`P`), so nothing is inherited from
/// `%ProgramData%\paguro`.
pub const SDDL: &str = "O:SYD:P(A;;FA;;;SY)(A;;FRSD;;;BA)";

/// `%ProgramData%\paguro\<volume-guid>`.
pub fn dir(ctx: &Ctx<'_>, volume: &Guid) -> String {
    join(&ctx.data_dir(), &guid_text(volume))
}

/// `%ProgramData%\paguro\<volume-guid>\tpm-auth.bin`.
pub fn path(ctx: &Ctx<'_>, volume: &Guid) -> String {
    join(&dir(ctx, volume), FILE_NAME)
}

/// Write the file for `volume`: `salt` and `ph` (`keys::pass_hash`'s
/// output) — exactly what a future `tpm`-rung boot re-derives from the same
/// passphrase and the same salt.
pub fn write(ctx: &Ctx<'_>, volume: &Guid, salt: &[u8; 16], ph: &[u8; 32]) -> Result<(), CmdError> {
    ctx.api.create_dir_all(&dir(ctx, volume))?;
    let a = paguro_core::tpm_auth::TpmAuth {
        salt: *salt,
        value: *ph,
    };
    let mut buf = [0u8; paguro_core::tpm_auth::LEN];
    let n = paguro_core::tpm_auth::write(&a, &mut buf)
        .map_err(|_| CmdError::internal("tpm-auth.bin: does not fit"))?;
    ctx.api
        .write_protected_file(&path(ctx, volume), buf.get(..n).unwrap_or(&[]), SDDL)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockApi;
    use zeroize::Zeroizing;

    fn ctx(api: &MockApi) -> Ctx<'_> {
        Ctx::new(api)
    }

    #[test]
    fn write_lands_at_the_documented_path_with_the_documented_acl() {
        let m = MockApi::demo();
        let c = ctx(&m);
        let volume = Guid([0x42; 16]);
        let salt = [7u8; 16];
        let ph = [9u8; 32];
        write(&c, &volume, &salt, &ph).unwrap();

        let p = path(&c, &volume);
        assert_eq!(p, format!("{}\\{}", dir(&c, &volume), FILE_NAME));
        let files = m.files.borrow();
        let f = files.get(&p.to_lowercase()).expect("file written");
        assert_eq!(f.acl.as_deref(), Some(SDDL));
        let got = f.all().unwrap();
        let parsed = paguro_core::tpm_auth::parse(&got).unwrap();
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.value, ph);
    }

    /// Uninstall needs no special case for this file: its restrictive ACL
    /// still lets `cmd::setup::remove_tree_or_later`'s ordinary recursive
    /// sweep of `%ProgramData%\paguro` (`cmd::uninstall`'s last step) remove
    /// it and its per-volume directory.
    #[test]
    fn removed_by_the_ordinary_uninstall_sweep() {
        let m = MockApi::demo();
        let c = ctx(&m);
        let volume = Guid([0x55; 16]);
        write(&c, &volume, &[1; 16], &[2; 32]).unwrap();
        assert!(
            m.files
                .borrow()
                .contains_key(&path(&c, &volume).to_lowercase())
        );

        crate::cmd::setup::remove_tree_or_later(&m, &c.data_dir()).unwrap();

        assert!(
            !m.files
                .borrow()
                .contains_key(&path(&c, &volume).to_lowercase())
        );
        assert!(!m.dirs.borrow().contains(&dir(&c, &volume).to_lowercase()));
    }

    /// The value `write` stores is exactly what the loader's own derivation
    /// (`paguro-boot`'s `Machine::stretch`, i.e. `paguro_crypto::bitlocker_stretch`
    /// over `paguro_crypto::user_password_hash`) produces for the same PIN
    /// and salt — the cross-check the loader and `paguro-win` share, since
    /// both call the identical `paguro-crypto` functions
    /// (`crates/paguro-boot/src/machine.rs`'s `Machine::stretch` uses
    /// `paguro_crypto::STRETCH_ITERATIONS` by default, exactly as
    /// `keys::pass_hash` hardcodes it).
    #[test]
    fn stored_value_matches_the_loaders_derivation() {
        let m = MockApi::demo();
        let c = ctx(&m);
        let volume = Guid([0x11; 16]);
        let salt = [3u8; 16];
        let pin = "correct horse battery staple";

        let ph = crate::keys::pass_hash(pin, &salt);
        write(&c, &volume, &salt, &ph).unwrap();

        let want = Zeroizing::new(paguro_crypto::bitlocker_stretch(
            &paguro_crypto::user_password_hash(pin),
            &salt,
            paguro_crypto::STRETCH_ITERATIONS,
        ));
        assert_eq!(*ph, *want, "keys::pass_hash must be the same derivation");

        let files = m.files.borrow();
        let got = files
            .get(&path(&c, &volume).to_lowercase())
            .unwrap()
            .all()
            .unwrap();
        let parsed = paguro_core::tpm_auth::parse(&got).unwrap();
        assert_eq!(
            parsed.value, *want,
            "the file must hold exactly what a tpm-rung boot re-derives"
        );
    }
}
