//! The four stages of §4.1, as functions that do not exist yet.
//!
//! Each returns [`Error::NotImplemented`] so the skeleton builds and the order is
//! fixed in code before any of it is written. Fill them in *in order*; a later
//! stage must never be reachable while an earlier one is unimplemented.

#[derive(Debug)]
pub enum Error {
    NotImplemented(&'static str),
    ConfigHashMismatch,
    ConfigParse(paguro_core::ini::IniError),
}

/// Stage 1: bounded read, SHA-256, compare with `paguro-config-hash`.
fn verify_config() -> Result<(), Error> {
    Err(Error::NotImplemented(
        "stage 1: verify paguro.ini against firmware hash",
    ))
}

/// Stage 2: parse, then the load taint.
fn load_taint() -> Result<(), Error> {
    Err(Error::NotImplemented("stage 2: parse + extend PCR 12"))
}

/// Stage 3: FVE metadata, rungs, VMK; then the boot taint.
fn unlock() -> Result<(), Error> {
    Err(Error::NotImplemented("stage 3: rungs + boot taint"))
}

/// Stage 4: NTFS, image map, handoff, `LoadImage`.
fn chainload() -> Result<(), Error> {
    Err(Error::NotImplemented("stage 4: locate image, load UKI"))
}

pub fn run() -> Result<(), Error> {
    verify_config()?;
    load_taint()?;
    unlock()?;
    chainload()
}
