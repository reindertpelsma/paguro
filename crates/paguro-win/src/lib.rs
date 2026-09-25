//! `paguro-win` — the Windows side, terminal first (INTERFACES.md §11).
//!
//! - [`api::WinApi`] is every OS touchpoint; [`mock::MockApi`] implements it
//!   in memory so all command logic is tested on any host, and
//!   `real::RealApi` (Windows only) implements it with Win32.
//! - [`cli`] is the `paguro` command line; [`out`] the versioned `--json`
//!   envelope and exit codes the PowerShell module (`windows/PaguroTools`)
//!   and the future GUI build on.
//! - Formats are never implemented here: `paguro.ini`, seals, load options,
//!   signature lists, SMBIOS, the TCG log, BitLocker metadata and the TPM
//!   client all come from `paguro-core`, `paguro-crypto` and `paguro-boot`.
// `unsafe` is confined to `real` (Win32 calls); everything else is safe Rust.
#![deny(unsafe_code)]

pub mod api;
pub mod bootent;
pub mod cfgfile;
pub mod cli;
pub mod cmd;
pub mod ctx;
pub mod esp;
pub mod fltmsg;
pub mod hw;
pub mod journal;
pub mod keys;
pub mod mock;
pub mod out;
pub mod preflight;
pub mod rpc;
#[cfg(windows)]
pub mod real;
pub mod tpmwin;
