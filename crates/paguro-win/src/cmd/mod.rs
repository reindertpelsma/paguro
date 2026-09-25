//! One module per command group; each function is a whole command over
//! [`crate::ctx::Ctx`], returning a [`crate::out::CmdResult`].

pub mod checks;
pub mod config;
pub mod disk;
pub mod distro;
pub mod efi;
pub mod esp;
pub mod hw;
pub mod install;
pub mod mok;
pub mod protection;
pub mod secureboot;
pub mod service;
pub mod setup;
pub mod status;
pub mod transition;
pub mod uninstall;
