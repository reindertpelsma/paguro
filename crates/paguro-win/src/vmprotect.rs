//! DESIGN.md §4.4's "hold the protected handle" and "refuse access to the
//! image files themselves", the service's half (INTERFACES.md §11.1: "the
//! service re-sends `PROTECT` for every image listed in `paguro.ini` at
//! start"). In the paguro VM only, before arming (`crate::arming`): for
//! every `paguro.ini` entry with a root image on a mounted volume, open it
//! and pin its clusters (`WinApi::pin_file`), then send `PROTECT` for it on
//! `\PaguroPort`. The pins are returned to the caller, which keeps them for
//! the life of the service: closing one would let NTFS move the file again.
//!
//! Order matters. The pin comes first: once `PROTECT` is in the table, an
//! open from a process the filter does not exempt is refused, and the
//! service is exempt only while it holds the port -- which it never does
//! across a sleep. Arming comes after: the filter's `Protected` count is
//! what `crate::arming` waits for, so every image is protected before the
//! driver ever reports itself ready. Neither the open nor the pin reads the
//! image's own clusters (only its MFT record, which is not claimed), so
//! none of this can trip the tripwire that is still on at this point.

use std::time::Duration;

use paguro_core::guid::Guid;

use crate::api::{ErrorKind, PinnedFile, WinApi};
use crate::arming::Backoff;
use crate::cfgfile;
use crate::ctx::Ctx;
use crate::fltmsg::DENY_ALL;

const RETRY_START: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// `\\?\Volume{GUID}\` -> the GUID in memory layout, as the driver's
/// `FltGetVolumeGuidName` names the same volume (`PG_MESSAGE.Volume`).
pub fn volume_guid(guid_path: &str) -> Option<[u8; 16]> {
    let open = guid_path.find('{')?;
    let close = open + guid_path.get(open..)?.find('}')?;
    Guid::parse(guid_path.get(open + 1..close)?)
        .ok()
        .map(|g| g.0)
}

/// The Windows paths of every root image `paguro.ini` lists, on volumes
/// mounted here. An entry whose volume is absent is logged and skipped:
/// nothing on it can be reached from this Windows either.
pub fn images(api: &dyn WinApi, log: &dyn Fn(&str)) -> Result<Vec<String>, String> {
    let ctx = Ctx::new(api);
    let esp = ctx.esp().map_err(|e| format!("the ESP: {}", e.message))?;
    let found = cfgfile::read(api, &esp)
        .map_err(|e| format!("paguro.ini: {}", e.message))?
        .ok_or("no paguro.ini on the ESP")?;
    let config = found.parsed.map_err(|e| format!("paguro.ini: {e}"))?;
    let mut out = Vec::new();
    for e in &config.entries {
        let Some(root) = &e.root else { continue };
        match cfgfile::windows_path(api, &e.volume, root) {
            Ok(Some(p)) => {
                if !out.iter().any(|o: &String| o.eq_ignore_ascii_case(&p)) {
                    out.push(p);
                }
            }
            Ok(None) => log(&format!("{}: its volume is not mounted here", e.name)),
            Err(err) => log(&format!("{}: {}", e.name, err.message)),
        }
    }
    Ok(out)
}

/// One image: pin it, then `PROTECT` it. `Ok(None)`: it does not exist
/// (nothing to protect, not an error to retry).
fn protect_one(api: &dyn WinApi, path: &str) -> Result<Option<PinnedFile>, String> {
    let pin = match api.pin_file(path) {
        Ok(p) => p,
        Err(e) if e.kind == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    let volume = volume_guid(&pin.volume_guid_path)
        .ok_or_else(|| format!("{path}: no GUID in {:?}", pin.volume_guid_path))?;
    let mut port = api
        .open_filter_port()
        .map_err(|e| format!("\\PaguroPort: {e}"))?
        .ok_or("\\PaguroPort not present yet")?;
    port.protect(volume, pin.file_id, DENY_ALL)
        .map_err(|e| format!("{path}: PROTECT: {e}"))?;
    Ok(Some(pin))
}

/// Protects every image [`images`] lists, retrying with backoff until each
/// is either protected or known not to exist. Returns the pins, which the
/// caller must keep alive. Blocks: run it off the service's own thread.
///
/// An empty list is retried too (the ESP not readable yet, or no entry
/// with a root): with nothing protected, `crate::arming` would wait
/// forever on the filter anyway, and the tripwire stays on -- the safe
/// side (DESIGN.md §4.4).
pub fn run(api: &dyn WinApi, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) -> Vec<PinnedFile> {
    let mut pins: Vec<(String, PinnedFile)> = Vec::new();
    let mut backoff = Backoff::new(RETRY_START, RETRY_MAX);
    loop {
        match images(api, log) {
            Ok(list) if list.is_empty() => log("paguro.ini lists no image to protect"),
            Ok(list) => {
                let mut pending = false;
                for path in &list {
                    if pins.iter().any(|(p, _)| p.eq_ignore_ascii_case(path)) {
                        continue;
                    }
                    match protect_one(api, path) {
                        Ok(Some(pin)) => {
                            log(&format!("protected {path}"));
                            pins.push((path.clone(), pin));
                        }
                        Ok(None) => log(&format!("{path}: does not exist; skipped")),
                        Err(e) => {
                            log(&e);
                            pending = true;
                        }
                    }
                }
                if !pending && !pins.is_empty() {
                    return pins.into_iter().map(|(_, p)| p).collect();
                }
            }
            Err(e) => log(&e),
        }
        sleep(backoff.wait());
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::FilterStatus;
    use crate::mock::{C_VOLUME_PATH, MockApi};
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::Ordering;

    fn logging(sink: &RefCell<Vec<String>>) -> impl Fn(&str) + '_ {
        move |m: &str| sink.borrow_mut().push(m.to_string())
    }

    #[test]
    fn volume_guid_is_memory_layout() {
        let g = volume_guid("\\\\?\\Volume{aaaaaaaa-0000-0000-0000-000000000002}\\").unwrap();
        assert_eq!(&g[..4], &[0xaa; 4]);
        assert_eq!(g[15], 2);
        let g = volume_guid("\\\\?\\Volume{01020304-0506-0708-090a-0b0c0d0e0f10}\\").unwrap();
        assert_eq!(g, [4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(volume_guid("C:\\"), None);
        assert_eq!(volume_guid("\\\\?\\Volume{nope}\\"), None);
    }

    #[test]
    fn images_come_from_paguro_ini() {
        let m = MockApi::demo();
        let logs = RefCell::new(Vec::new());
        assert_eq!(
            images(&m, &logging(&logs)).unwrap(),
            vec!["C:\\paguro\\debian.vhd".to_string()]
        );
    }

    #[test]
    fn pins_then_protects_every_image() {
        let m = MockApi::demo();
        let status = std::rc::Rc::new(Cell::new(FilterStatus::default()));
        *m.filter_port.borrow_mut() = Some(status.clone());
        let logs = RefCell::new(Vec::new());
        let pins = run(&m, &|_| panic!("no retry needed"), &logging(&logs));
        assert_eq!(pins.len(), 1);
        assert_eq!(status.get().protected, 1);
        let sent = m.filter_protects.borrow().clone();
        let facts = m.file_facts("C:\\paguro\\debian.vhd").unwrap().unwrap();
        assert_eq!(
            sent,
            vec![(volume_guid(C_VOLUME_PATH).unwrap(), facts.file_id, DENY_ALL)]
        );
        assert_eq!(m.pins_held.load(Ordering::SeqCst), 1);
        drop(pins);
        assert_eq!(m.pins_held.load(Ordering::SeqCst), 0, "dropping unpins");
    }

    #[test]
    fn waits_for_the_filter_port() {
        let m = MockApi::demo();
        let status = std::rc::Rc::new(Cell::new(FilterStatus::default()));
        let ticks = Cell::new(0);
        let sleep = |_d: Duration| {
            ticks.set(ticks.get() + 1);
            if ticks.get() == 3 {
                *m.filter_port.borrow_mut() = Some(status.clone());
            }
        };
        let logs = RefCell::new(Vec::new());
        let pins = run(&m, &sleep, &logging(&logs));
        assert_eq!(ticks.get(), 3);
        assert_eq!(pins.len(), 1);
        assert_eq!(status.get().protected, 1);
        // The failed attempts' pins were dropped, not leaked.
        assert_eq!(m.pins_held.load(Ordering::SeqCst), 1);
        assert!(logs.borrow().iter().any(|l| l.contains("not present yet")));
    }

    #[test]
    fn a_missing_image_is_skipped_and_empty_retries() {
        let m = MockApi::demo();
        *m.filter_port.borrow_mut() = Some(std::rc::Rc::new(Cell::new(FilterStatus::default())));
        let _ = m.remove_file("C:\\paguro\\debian.vhd");
        let ticks = Cell::new(0);
        let sleep = |_d: Duration| {
            ticks.set(ticks.get() + 1);
            if ticks.get() == 2 {
                m.put_file("C:\\paguro\\debian.vhd", b"image");
            }
        };
        let logs = RefCell::new(Vec::new());
        let pins = run(&m, &sleep, &logging(&logs));
        assert_eq!(pins.len(), 1);
        assert!(logs.borrow().iter().any(|l| l.contains("does not exist")));
    }
}
