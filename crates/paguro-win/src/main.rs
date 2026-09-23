//! `paguro-win` — the Windows transition app and repair hook.
//!
//! - **Restart into Linux** (§4.6): pre-flight, write the PIN bypass, set
//!   `BootNext`, restart. A *restart*, never a shutdown, so Fast Startup never
//!   leaves a hibernated volume behind.
//! - **Repair hook** (§7): restore the ESP after feature updates, stage a
//!   one-shot `setupTPM` when the TPM path broke, re-run the bootstrap after an
//!   NVRAM clear.
//!
//! The decision logic is pure and lives in [`preflight`], so it is tested on any
//! host. The Win32 calls (`SetFirmwareEnvironmentVariableEx`, TBS, `manage-bde`)
//! are Windows-only and not written yet.

#[cfg_attr(not(test), allow(dead_code))]
mod preflight;

fn main() {
    if cfg!(windows) {
        eprintln!("paguro-win: not implemented yet");
    } else {
        eprintln!(
            "paguro-win only runs on Windows; `cargo test -p paguro-win` runs its logic anywhere"
        );
    }
    std::process::exit(2);
}
