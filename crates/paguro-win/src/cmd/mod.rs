//! One module per command group; each function is a whole command over
//! [`crate::ctx::Ctx`], returning a [`crate::out::CmdResult`].

pub mod config;
pub mod disk;
pub mod efi;
pub mod esp;
pub mod hw;
pub mod install;
pub mod mok;
pub mod status;
pub mod transition;
pub mod uninstall;
