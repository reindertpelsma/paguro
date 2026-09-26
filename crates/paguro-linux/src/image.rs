//! `paguro image attach|detach|grow` (INTERFACES.md §10.2 "Control device
//! `/dev/paguro`", §10.3 "Device-mapper tables", §11.3 "Image lifecycle
//! over this channel").
//!
//! The owner's order, exactly as specified:
//! - **Protect** (Windows gives Linux a new image): the minifilter protects
//!   the file and flushes the volume, then reports its identity; the module
//!   claims it from its **own** NTFS parse, never from what was reported
//!   ([`attach`] — identity here comes from ntfs3's own `name_to_handle_at`
//!   on an already-mounted, already-protected file, the same discovery
//!   `pgctl ident` and the initrd use).
//! - **Release** (Linux gives an image back): Linux checks the device is
//!   unused and unmounted, and removes it; the module releases the claim's
//!   ranges; **only then** is Windows told to unprotect ([`detach`]).
//! - **Grow**: Windows extends the file with the existing part still
//!   protected, protects the new part, flushes, and reports; the module
//!   re-derives the extents and accepts only an append ([`grow`]).
//!
//! Frames travel the guest-agent virtio-serial channel (`org.paguro.agent.0`,
//! `paguro_vm::qemu::AGENT_PORT`) with the same `u32`-length-prefixed-JSON
//! framing every other agent-port message uses
//! (`paguro_vm::session::agent_frame`/`agent_frames`). [`AgentChannel`] is
//! the transport, pluggable so tests can capture what would be sent without
//! a live guest.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use paguro_initrd::dm::{DevInfo, Dm};
use paguro_initrd::pg::{self, Ctl};
use paguro_initrd::plan::Target;
use paguro_initrd::sys;
use serde_json::{Value, json};

/// A claimed file's ntfs3 identity: MFT record number and sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Identity {
    pub mft_record: u64,
    pub mft_seq: u16,
}

/// What names a file in an agent-port frame: enough for the guest to find
/// it again, and for a log line to mean something. The Windows side is not
/// part of this crate (INTERFACES.md §11.3 is DRAFT there); this is the
/// Linux-side encoding of its half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
    /// The path as Windows would show it (informational only: identity is
    /// never trusted from a reported path or extents, only from the
    /// module's own NTFS parse — INTERFACES.md §11.3 "Protect").
    pub windows_path: String,
}

/// `PG_CLAIM`'s outcome ([`ImageBackend::claim`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaimResult {
    pub claim_id: u32,
    pub sectors: u64,
    pub state: u32,
}

/// `PG_GROW`'s outcome ([`ImageBackend::grow`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct GrowResult {
    pub sectors: u64,
    pub state: u32,
    /// `0`: accepted. Anything else: refused (`PG_ERR_NOT_APPEND` when the
    /// growth was not an append; the old extents stay writable unless the
    /// old map itself no longer parses).
    pub error: i32,
}

/// Whether a view A device may be removed.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Presence {
    /// No such device (already gone, or never created this boot).
    #[default]
    Absent,
    /// Exists, not open anywhere: safe to remove.
    Idle,
    /// Exists and is open (mounted or otherwise held); `String` is a human
    /// reason. Detach must refuse.
    Busy(String),
}

pub use pg::{CLAIM_CHECKED, CLAIM_READONLY, CLAIM_REFUSED};

/// The `/dev/paguro` + device-mapper operations [`attach`], [`detach`] and
/// [`grow`] need, behind a trait so the ordering can be unit-tested without
/// a live kernel module. [`KernelBackend`] is the real thing.
pub trait ImageBackend {
    fn identity(&self, file: &Path) -> Result<Identity, String>;
    fn fiemap(&self, file: &Path) -> Result<Vec<(u64, u64)>, String>;
    fn claim(&mut self, volume_id: u32, format: u32, id: Identity) -> Result<ClaimResult, String>;
    fn crosscheck(&mut self, claim_id: u32, ranges: &[(u64, u64)]) -> Result<u32, String>;
    fn grow(&mut self, claim_id: u32) -> Result<GrowResult, String>;
    fn release(&mut self, claim_id: u32) -> Result<(), String>;
    fn dm_create(&mut self, name: &str, claim_id: u32, sectors: u64) -> Result<PathBuf, String>;
    fn dm_reload(&mut self, name: &str, claim_id: u32, sectors: u64) -> Result<(), String>;
    fn dm_remove(&mut self, name: &str) -> Result<(), String>;
    /// Whether `name` may be detached right now.
    fn presence(&self, name: &str) -> Result<Presence, String>;
}

/// The dm-mapper name a `name` argument becomes
/// (`shell::view_a_path`'s convention: `paguro-<name>`).
pub fn dm_name(name: &str) -> String {
    format!("paguro-{name}")
}

/// Result of a successful [`attach`].
#[derive(Clone, Debug)]
pub struct Attached {
    pub claim_id: u32,
    pub device: PathBuf,
    pub sectors: u64,
}

/// `paguro image attach <file>`: claim it by its own ntfs3-reported
/// identity, cross-check that against the module's own parse (mandatory,
/// INTERFACES.md §10.1a), and load view A. A disagreeing cross-check
/// releases the claim and refuses — no view A, ever.
pub fn attach<B: ImageBackend>(
    backend: &mut B,
    volume_id: u32,
    file: &Path,
    name: &str,
    format: u32,
) -> Result<Attached, String> {
    let id = backend.identity(file)?;
    let claim = backend.claim(volume_id, format, id)?;
    let ranges = backend.fiemap(file)?;
    let state = match backend.crosscheck(claim.claim_id, &ranges) {
        Ok(s) => s,
        Err(e) => {
            let _ = backend.release(claim.claim_id);
            return Err(e);
        }
    };
    if state & CLAIM_CHECKED == 0 || state & CLAIM_REFUSED != 0 {
        let _ = backend.release(claim.claim_id);
        return Err(format!(
            "{}: ntfs3's FIEMAP disagrees with the module's own NTFS parse; no view A, ever",
            file.display()
        ));
    }
    let device = backend.dm_create(&dm_name(name), claim.claim_id, claim.sectors)?;
    Ok(Attached {
        claim_id: claim.claim_id,
        device,
        sectors: claim.sectors,
    })
}

/// `paguro image detach <name>`: refuse while the view A device is open
/// (mounted or otherwise held); else remove it, release the claim, and —
/// **only once that has succeeded** — send `image-released` so Windows can
/// unprotect the file (INTERFACES.md §11.3 "Release": Windows is told
/// last).
pub fn detach<B: ImageBackend, C: AgentChannel>(
    backend: &mut B,
    channel: &mut C,
    name: &str,
    claim_id: u32,
    file: &FileRef,
) -> Result<(), String> {
    let dm = dm_name(name);
    match backend.presence(&dm)? {
        Presence::Busy(reason) => {
            return Err(format!("refusing to detach {dm}: {reason}"));
        }
        Presence::Idle => backend.dm_remove(&dm)?,
        Presence::Absent => {}
    }
    backend.release(claim_id)?;
    channel.send(&frames::image_released(file))?;
    Ok(())
}

/// What [`grow`] is growing: the dm/claim name, the claim id, where the
/// file is reachable on Linux right now (for the post-grow re-cross-check),
/// and its channel-facing [`FileRef`]. A struct rather than four more
/// arguments to `grow` itself.
#[derive(Clone, Copy)]
pub struct GrowTarget<'a> {
    pub name: &'a str,
    pub claim_id: u32,
    pub local_path: &'a Path,
    pub file: &'a FileRef,
}

/// `paguro image grow <name> --by SIZE`: ask Windows to grow the file,
/// wait for its `image-grown` report, then `PG_GROW` (accepted only if the
/// growth was an append). `PG_GROW` clears the claim's cross-checked state
/// (INTERFACES.md §10.1a: "`paguro-image` loads only after a passing
/// `PG_CROSSCHECK`; `PG_GROW` clears it") — a fresh `PG_CROSSCHECK` against
/// `target.local_path` (the file, reachable the same way `attach` reached
/// it: an already-mounted, read-only ntfs3 view) is required before view
/// A's table can be reloaded at the new length, exactly as
/// `kernel/dm-paguro/test/vm-test.body`'s growth test proves at the module
/// level. The result is always acknowledged back to the guest.
pub fn grow<B: ImageBackend, C: AgentChannel>(
    backend: &mut B,
    channel: &mut C,
    target: &GrowTarget<'_>,
    by_sectors: u64,
    deadline: Instant,
) -> Result<GrowResult, String> {
    let GrowTarget {
        name,
        claim_id,
        local_path,
        file,
    } = *target;
    channel.send(&frames::image_grow_request(file, by_sectors))?;
    loop {
        let Some(f) = channel.recv(deadline)? else {
            return Err(format!(
                "{}: no image-grown report within the deadline",
                file.windows_path
            ));
        };
        if frames::field(&f, "type") != "image-grown" {
            continue;
        }
        break;
    }
    let g = backend.grow(claim_id)?;
    if g.error != 0 {
        channel.send(&frames::image_grow_ack(file, false, Some(g.error)))?;
        return Err(format!(
            "{}: PG_GROW refused (error {}) — not an append",
            file.windows_path, g.error
        ));
    }
    let ranges = backend.fiemap(local_path)?;
    let state = backend.crosscheck(claim_id, &ranges)?;
    if state & CLAIM_CHECKED == 0 || state & CLAIM_REFUSED != 0 {
        channel.send(&frames::image_grow_ack(file, false, None))?;
        return Err(format!(
            "{}: post-grow cross-check disagreed; view A not reloaded",
            file.windows_path
        ));
    }
    backend.dm_reload(&dm_name(name), claim_id, g.sectors)?;
    channel.send(&frames::image_grow_ack(file, true, None))?;
    Ok(g)
}

/// Frame definitions (INTERFACES.md §11.3 "Image lifecycle over this
/// channel"). Every frame carries `"file"` (a [`FileRef`]'s wire form, see
/// [`FileRef`]'s docs on why identity itself never travels the channel).
pub mod frames {
    use super::*;

    fn file_value(f: &FileRef) -> Value {
        json!({ "path": f.windows_path })
    }

    pub fn file_ref_of(v: &Value) -> Option<FileRef> {
        Some(FileRef {
            windows_path: v.get("file")?.get("path")?.as_str()?.to_string(),
        })
    }

    pub fn field<'a>(v: &'a Value, key: &str) -> &'a str {
        v.get(key).and_then(Value::as_str).unwrap_or_default()
    }

    /// guest → host: Windows protected and flushed a new file; here is its
    /// path (identity is *derived*, never taken from this frame).
    pub fn image_protected(file: &FileRef) -> Value {
        json!({ "type": "image-protected", "file": file_value(file) })
    }

    /// host → guest: Linux has released the claim; safe to unprotect.
    pub fn image_released(file: &FileRef) -> Value {
        json!({ "type": "image-released", "file": file_value(file) })
    }

    /// host → guest: please grow this file by `by_sectors` (512-byte
    /// sectors), keeping the existing part protected.
    pub fn image_grow_request(file: &FileRef, by_sectors: u64) -> Value {
        json!({ "type": "image-grow-request", "file": file_value(file), "by_sectors": by_sectors })
    }

    /// guest → host: Windows finished growing (and re-protecting) the file.
    pub fn image_grown(file: &FileRef) -> Value {
        json!({ "type": "image-grown", "file": file_value(file) })
    }

    /// host → guest: the result of `PG_GROW` (and, if accepted, of
    /// reloading view A at the new length).
    pub fn image_grow_ack(file: &FileRef, ok: bool, error: Option<i32>) -> Value {
        match error {
            Some(e) => {
                json!({ "type": "image-grow-ack", "file": file_value(file), "ok": ok, "error": e })
            }
            None => json!({ "type": "image-grow-ack", "file": file_value(file), "ok": ok }),
        }
    }
}

/// A frame transport: `u32`-length-prefixed JSON, exactly
/// `paguro_vm::session::agent_frame`/`agent_frames`'s wire format (the same
/// channel the driver's arming and the `ssh-keys` handshake use).
/// Pluggable so tests can capture what would be sent, and feed canned
/// replies, without a live guest.
pub trait AgentChannel {
    fn send(&mut self, v: &Value) -> Result<(), String>;
    /// Best-effort receive of the next frame before `deadline`; `Ok(None)`
    /// means nothing arrived in time, not an error.
    fn recv(&mut self, deadline: Instant) -> Result<Option<Value>, String>;
}

/// The real transport: a `UnixStream` connected to the running
/// `paguro-vm` session's `agent.sock` (the same socket
/// `paguro_vm::session` connects to for the driver's arming and the
/// `ssh-keys` handshake).
pub struct UnixAgentChannel {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl UnixAgentChannel {
    pub fn connect(path: &Path) -> Result<Self, String> {
        let stream = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(UnixAgentChannel {
            stream,
            buf: Vec::new(),
        })
    }
}

impl AgentChannel for UnixAgentChannel {
    fn send(&mut self, v: &Value) -> Result<(), String> {
        self.stream
            .write_all(&paguro_vm::session::agent_frame(v))
            .map_err(|e| format!("agent channel: send: {e}"))
    }

    fn recv(&mut self, deadline: Instant) -> Result<Option<Value>, String> {
        loop {
            let framed = paguro_vm::session::agent_frames(&mut self.buf);
            if let Some(v) = framed.into_iter().next() {
                return Ok(Some(v));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            self.stream
                .set_read_timeout(Some(remaining.min(Duration::from_millis(500))))
                .map_err(|e| format!("agent channel: set_read_timeout: {e}"))?;
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err("agent channel: closed".into()),
                Ok(n) => self.buf.extend_from_slice(chunk.get(..n).unwrap_or(&chunk)),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => return Err(format!("agent channel: recv: {e}")),
            }
        }
    }
}

/// No live guest to tell: every frame is silently dropped. Release
/// (INTERFACES.md §11.3) still requires the module to have actually
/// released the claim first — [`detach`] enforces that regardless of
/// whether a guest is reachable — but *telling* Windows is opportunistic:
/// if Windows is not currently running as a VM (there is no live
/// `org.paguro.agent.0`), there is nothing to tell, and that is fine. The
/// CLI falls back to this when [`UnixAgentChannel::connect`] fails.
#[derive(Default)]
pub struct NullChannel;

impl AgentChannel for NullChannel {
    fn send(&mut self, _v: &Value) -> Result<(), String> {
        Ok(())
    }
    fn recv(&mut self, _deadline: Instant) -> Result<Option<Value>, String> {
        Ok(None)
    }
}

/// A recording, scriptable [`AgentChannel`] for tests: every [`send`] is
/// captured in order, and [`recv`] hands back canned frames from a queue
/// (never blocking).
#[derive(Default)]
pub struct FakeChannel {
    pub sent: Vec<Value>,
    pub inbox: VecDeque<Value>,
}

impl FakeChannel {
    pub fn with_inbox(frames: impl IntoIterator<Item = Value>) -> Self {
        FakeChannel {
            sent: Vec::new(),
            inbox: frames.into_iter().collect(),
        }
    }
}

impl AgentChannel for FakeChannel {
    fn send(&mut self, v: &Value) -> Result<(), String> {
        self.sent.push(v.clone());
        Ok(())
    }

    fn recv(&mut self, _deadline: Instant) -> Result<Option<Value>, String> {
        Ok(self.inbox.pop_front())
    }
}

/// `PG_STATUS`'s sole registered volume, or an error naming what to pass
/// explicitly (`--volume`) when there is more than one or none: the CLI
/// does not itself run `PG_VOLUME_ADD` (that needs the raw/plain device
/// numbers and BitLocker's reserved ranges, which only the initrd's
/// handoff currently derives) — it assumes the volume holding the Windows
/// files this host boots from is already registered, which is the case for
/// every boot that reached a shell.
pub fn sole_volume_id(ctl: &Ctl) -> Result<u32, String> {
    let status = ctl.status()?;
    let mut found = None;
    for v in status.volume.iter() {
        if v.id == 0 {
            continue;
        }
        if found.is_some() {
            return Err("more than one volume registered; pass --volume <id>".into());
        }
        found = Some(v.id);
    }
    found.ok_or_else(|| "no volume registered; pass --volume <id>".into())
}

/// The real backend: `/dev/paguro` (`paguro_initrd::pg::Ctl`) and
/// device-mapper (`paguro_initrd::dm::Dm`).
pub struct KernelBackend {
    pub ctl: Ctl,
    pub dm: Dm,
}

impl KernelBackend {
    pub fn open() -> Result<Self, String> {
        Ok(KernelBackend {
            ctl: Ctl::open()?,
            dm: Dm::open()?,
        })
    }
}

/// `/proc/self/mountinfo`'s 3rd field ("maj:min") matching `major:minor`,
/// if any — the mount point (5th field) for a friendlier refusal than a
/// bare open count.
fn mount_point_of(major: u32, minor: u32) -> Option<String> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let want = format!("{major}:{minor}");
    for line in info.lines() {
        let mut fields = line.split_whitespace();
        let _id = fields.next()?;
        let _parent = fields.next()?;
        let devt = fields.next()?;
        if devt == want {
            let _root = fields.next()?;
            let mount_point = fields.next()?;
            return Some(mount_point.to_string());
        }
    }
    None
}

impl ImageBackend for KernelBackend {
    fn identity(&self, file: &Path) -> Result<Identity, String> {
        let (mft_record, mft_seq) = sys::file_identity(file)?;
        Ok(Identity {
            mft_record,
            mft_seq,
        })
    }

    fn fiemap(&self, file: &Path) -> Result<Vec<(u64, u64)>, String> {
        let f = std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
        sys::fiemap(&f)
    }

    fn claim(&mut self, volume_id: u32, format: u32, id: Identity) -> Result<ClaimResult, String> {
        let mut c = pg::Claim {
            volume_id,
            format,
            mft_record: id.mft_record,
            mft_seq: id.mft_seq,
            ..Default::default()
        };
        self.ctl.claim(&mut c)?;
        Ok(ClaimResult {
            claim_id: c.claim_id,
            sectors: c.sectors,
            state: c.state,
        })
    }

    fn crosscheck(&mut self, claim_id: u32, ranges: &[(u64, u64)]) -> Result<u32, String> {
        self.ctl.crosscheck(claim_id, ranges)
    }

    fn grow(&mut self, claim_id: u32) -> Result<GrowResult, String> {
        let g = self.ctl.grow(claim_id)?;
        Ok(GrowResult {
            sectors: g.sectors,
            state: g.state,
            error: g.error,
        })
    }

    fn release(&mut self, claim_id: u32) -> Result<(), String> {
        self.ctl.release(claim_id)
    }

    fn dm_create(&mut self, name: &str, claim_id: u32, sectors: u64) -> Result<PathBuf, String> {
        let target = Target {
            start: 0,
            len: sectors,
            kind: "paguro-image",
            params: claim_id.to_string(),
        };
        self.dm.setup(name, &[target], 0)?;
        Ok(Path::new("/dev/mapper").join(name))
    }

    fn dm_reload(&mut self, name: &str, claim_id: u32, sectors: u64) -> Result<(), String> {
        let target = Target {
            start: 0,
            len: sectors,
            kind: "paguro-image",
            params: claim_id.to_string(),
        };
        self.dm.reload(name, &[target], 0)
    }

    fn dm_remove(&mut self, name: &str) -> Result<(), String> {
        self.dm.remove(name)
    }

    fn presence(&self, name: &str) -> Result<Presence, String> {
        match self.dm.info(name)? {
            None => Ok(Presence::Absent),
            Some(DevInfo {
                open_count,
                major,
                minor,
                ..
            }) if open_count > 0 => {
                let where_ = mount_point_of(major, minor)
                    .map(|m| format!("mounted at {m}"))
                    .unwrap_or_else(|| format!("open count {open_count}"));
                Ok(Presence::Busy(where_))
            }
            Some(_) => Ok(Presence::Idle),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A fake [`ImageBackend`] that records every call (for order
    /// assertions) and can be scripted to fail at a chosen step.
    #[derive(Default)]
    struct FakeBackend {
        log: Rc<RefCell<Vec<String>>>,
        identity: Identity,
        claim: ClaimResult,
        crosscheck_state: u32,
        grow_result: GrowResult,
        fail_release: bool,
        fail_dm_remove: bool,
        fail_crosscheck: bool,
        presence: Presence,
    }

    impl ImageBackend for FakeBackend {
        fn identity(&self, _file: &Path) -> Result<Identity, String> {
            self.log.borrow_mut().push("identity".into());
            Ok(self.identity)
        }
        fn fiemap(&self, _file: &Path) -> Result<Vec<(u64, u64)>, String> {
            self.log.borrow_mut().push("fiemap".into());
            Ok(vec![(10, 5)])
        }
        fn claim(
            &mut self,
            _volume_id: u32,
            _format: u32,
            _id: Identity,
        ) -> Result<ClaimResult, String> {
            self.log.borrow_mut().push("claim".into());
            Ok(self.claim)
        }
        fn crosscheck(&mut self, _claim_id: u32, _ranges: &[(u64, u64)]) -> Result<u32, String> {
            self.log.borrow_mut().push("crosscheck".into());
            if self.fail_crosscheck {
                return Err("crosscheck failed".into());
            }
            Ok(self.crosscheck_state)
        }
        fn grow(&mut self, _claim_id: u32) -> Result<GrowResult, String> {
            self.log.borrow_mut().push("grow".into());
            Ok(self.grow_result)
        }
        fn release(&mut self, _claim_id: u32) -> Result<(), String> {
            self.log.borrow_mut().push("release".into());
            if self.fail_release {
                return Err("release failed".into());
            }
            Ok(())
        }
        fn dm_create(
            &mut self,
            name: &str,
            _claim_id: u32,
            _sectors: u64,
        ) -> Result<PathBuf, String> {
            self.log.borrow_mut().push("dm_create".into());
            Ok(Path::new("/dev/mapper").join(name))
        }
        fn dm_reload(&mut self, _name: &str, _claim_id: u32, _sectors: u64) -> Result<(), String> {
            self.log.borrow_mut().push("dm_reload".into());
            Ok(())
        }
        fn dm_remove(&mut self, name: &str) -> Result<(), String> {
            self.log.borrow_mut().push(format!("dm_remove {name}"));
            if self.fail_dm_remove {
                return Err("dm_remove failed".into());
            }
            Ok(())
        }
        fn presence(&self, _name: &str) -> Result<Presence, String> {
            self.log.borrow_mut().push("presence".into());
            Ok(self.presence.clone())
        }
    }

    fn file() -> FileRef {
        FileRef {
            windows_path: r"\paguro\debian.vhd".into(),
        }
    }

    // ---- attach --------------------------------------------------------

    #[test]
    fn attach_creates_view_a_when_crosscheck_agrees() {
        let mut b = FakeBackend {
            claim: ClaimResult {
                claim_id: 7,
                sectors: 1024,
                state: 0,
            },
            crosscheck_state: CLAIM_CHECKED,
            ..Default::default()
        };
        let out = attach(
            &mut b,
            1,
            Path::new("/mnt/c/paguro/debian.vhd"),
            "debian",
            0,
        )
        .unwrap();
        assert_eq!(out.claim_id, 7);
        assert_eq!(out.sectors, 1024);
        assert_eq!(out.device, Path::new("/dev/mapper/paguro-debian"));
        assert_eq!(
            *b.log.borrow(),
            vec!["identity", "claim", "fiemap", "crosscheck", "dm_create"]
        );
    }

    #[test]
    fn attach_releases_and_refuses_when_crosscheck_disagrees() {
        let mut b = FakeBackend {
            claim: ClaimResult {
                claim_id: 7,
                ..Default::default()
            },
            crosscheck_state: CLAIM_REFUSED,
            ..Default::default()
        };
        let err = attach(&mut b, 1, Path::new("/mnt/c/x.vhd"), "x", 0).unwrap_err();
        assert!(err.contains("disagrees"));
        // Released, and never reaches dm_create: no view A for a refused claim, ever.
        assert_eq!(
            *b.log.borrow(),
            vec!["identity", "claim", "fiemap", "crosscheck", "release"]
        );
    }

    #[test]
    fn attach_releases_when_crosscheck_itself_errors() {
        let mut b = FakeBackend {
            fail_crosscheck: true,
            ..Default::default()
        };
        assert!(attach(&mut b, 1, Path::new("/mnt/c/x.vhd"), "x", 0).is_err());
        assert!(b.log.borrow().contains(&"release".to_string()));
        assert!(!b.log.borrow().contains(&"dm_create".to_string()));
    }

    // ---- detach: the ordering invariants --------------------------------

    #[test]
    fn detach_refuses_while_busy_and_touches_nothing_else() {
        let mut b = FakeBackend {
            presence: Presence::Busy("mounted at /mnt/x".into()),
            ..Default::default()
        };
        let mut ch = FakeChannel::default();
        let err = detach(&mut b, &mut ch, "debian", 7, &file()).unwrap_err();
        assert!(err.contains("mounted at /mnt/x"));
        assert_eq!(*b.log.borrow(), vec!["presence"]);
        assert!(ch.sent.is_empty(), "Windows must not be told anything");
    }

    #[test]
    fn detach_removes_releases_then_tells_windows_last() {
        let mut b = FakeBackend {
            presence: Presence::Idle,
            ..Default::default()
        };
        let mut ch = FakeChannel::default();
        detach(&mut b, &mut ch, "debian", 7, &file()).unwrap();
        assert_eq!(
            *b.log.borrow(),
            vec!["presence", "dm_remove paguro-debian", "release"]
        );
        assert_eq!(ch.sent.len(), 1);
        assert_eq!(frames::field(&ch.sent[0], "type"), "image-released");
        assert_eq!(
            frames::file_ref_of(&ch.sent[0]).unwrap().windows_path,
            file().windows_path
        );
    }

    #[test]
    fn detach_skips_dm_remove_when_already_absent() {
        let mut b = FakeBackend {
            presence: Presence::Absent,
            ..Default::default()
        };
        let mut ch = FakeChannel::default();
        detach(&mut b, &mut ch, "debian", 7, &file()).unwrap();
        assert_eq!(*b.log.borrow(), vec!["presence", "release"]);
        assert_eq!(ch.sent.len(), 1);
    }

    #[test]
    fn detach_does_not_tell_windows_if_release_fails() {
        let mut b = FakeBackend {
            presence: Presence::Idle,
            fail_release: true,
            ..Default::default()
        };
        let mut ch = FakeChannel::default();
        assert!(detach(&mut b, &mut ch, "debian", 7, &file()).is_err());
        assert!(
            ch.sent.is_empty(),
            "the module must actually release before Windows is told"
        );
    }

    #[test]
    fn detach_does_not_tell_windows_if_dm_remove_fails() {
        let mut b = FakeBackend {
            presence: Presence::Idle,
            fail_dm_remove: true,
            ..Default::default()
        };
        let mut ch = FakeChannel::default();
        assert!(detach(&mut b, &mut ch, "debian", 7, &file()).is_err());
        assert!(ch.sent.is_empty());
        assert!(!b.log.borrow().contains(&"release".to_string()));
    }

    // ---- grow: request first, append-only accepted, refused acked -------

    #[test]
    fn grow_requests_then_accepts_an_append_and_reloads() {
        let mut b = FakeBackend {
            grow_result: GrowResult {
                sectors: 2048,
                state: 0,
                error: 0,
            },
            crosscheck_state: CLAIM_CHECKED,
            ..Default::default()
        };
        let mut ch = FakeChannel::with_inbox([frames::image_grown(&file())]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let path = Path::new("/mnt/c/paguro/debian.vhd");
        let g = grow(
            &mut b,
            &mut ch,
            &GrowTarget {
                name: "debian",
                claim_id: 7,
                local_path: path,
                file: &file(),
            },
            512,
            deadline,
        )
        .unwrap();
        assert_eq!(g.sectors, 2048);
        assert_eq!(
            *b.log.borrow(),
            vec!["grow", "fiemap", "crosscheck", "dm_reload"]
        );
        assert_eq!(ch.sent.len(), 2);
        assert_eq!(frames::field(&ch.sent[0], "type"), "image-grow-request");
        assert_eq!(ch.sent[0]["by_sectors"], 512);
        assert_eq!(frames::field(&ch.sent[1], "type"), "image-grow-ack");
        assert_eq!(ch.sent[1]["ok"], true);
    }

    #[test]
    fn grow_refuses_a_non_append_and_never_reloads() {
        let mut b = FakeBackend {
            grow_result: GrowResult {
                sectors: 1024,
                state: pg::CLAIM_READONLY,
                error: 106, // PG_ERR_NOT_APPEND
            },
            ..Default::default()
        };
        let mut ch = FakeChannel::with_inbox([frames::image_grown(&file())]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let path = Path::new("/mnt/c/paguro/debian.vhd");
        let err = grow(
            &mut b,
            &mut ch,
            &GrowTarget {
                name: "debian",
                claim_id: 7,
                local_path: path,
                file: &file(),
            },
            512,
            deadline,
        )
        .unwrap_err();
        assert!(err.contains("not an append"));
        assert_eq!(*b.log.borrow(), vec!["grow"]);
        assert_eq!(frames::field(&ch.sent[1], "type"), "image-grow-ack");
        assert_eq!(ch.sent[1]["ok"], false);
        assert_eq!(ch.sent[1]["error"], 106);
    }

    #[test]
    fn grow_never_reloads_when_the_post_grow_crosscheck_disagrees() {
        // PG_GROW clears CLAIM_CHECKED (INTERFACES.md §10.1a); a disagreeing
        // re-cross-check must refuse the reload, not just accept it because
        // PG_GROW itself reported success.
        let mut b = FakeBackend {
            grow_result: GrowResult {
                sectors: 2048,
                state: 0,
                error: 0,
            },
            crosscheck_state: CLAIM_REFUSED,
            ..Default::default()
        };
        let mut ch = FakeChannel::with_inbox([frames::image_grown(&file())]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let path = Path::new("/mnt/c/paguro/debian.vhd");
        let err = grow(
            &mut b,
            &mut ch,
            &GrowTarget {
                name: "debian",
                claim_id: 7,
                local_path: path,
                file: &file(),
            },
            512,
            deadline,
        )
        .unwrap_err();
        assert!(err.contains("cross-check disagreed"));
        assert_eq!(*b.log.borrow(), vec!["grow", "fiemap", "crosscheck"]);
        assert_eq!(
            frames::field(ch.sent.last().unwrap(), "type"),
            "image-grow-ack"
        );
        assert_eq!(ch.sent.last().unwrap()["ok"], false);
    }

    #[test]
    fn grow_ignores_unrelated_frames_before_the_report() {
        let mut b = FakeBackend {
            crosscheck_state: CLAIM_CHECKED,
            ..Default::default()
        };
        let mut ch = FakeChannel::with_inbox([
            json!({"type": "driver", "state": "ok"}),
            json!({"type": "ssh-keys", "windows_user_pub": "x"}),
            frames::image_grown(&file()),
        ]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let path = Path::new("/mnt/c/paguro/debian.vhd");
        assert!(
            grow(
                &mut b,
                &mut ch,
                &GrowTarget {
                    name: "debian",
                    claim_id: 7,
                    local_path: path,
                    file: &file(),
                },
                512,
                deadline,
            )
            .is_ok()
        );
    }

    #[test]
    fn grow_times_out_without_a_report() {
        let mut b = FakeBackend::default();
        let mut ch = FakeChannel::default(); // never answers
        let deadline = Instant::now(); // already past
        let path = Path::new("/mnt/c/paguro/debian.vhd");
        let err = grow(
            &mut b,
            &mut ch,
            &GrowTarget {
                name: "debian",
                claim_id: 7,
                local_path: path,
                file: &file(),
            },
            512,
            deadline,
        )
        .unwrap_err();
        assert!(err.contains("deadline"));
        assert!(
            b.log.borrow().is_empty(),
            "PG_GROW never called without a report"
        );
    }

    // ---- frames ---------------------------------------------------------

    #[test]
    fn frame_round_trip_through_the_wire_format() {
        let f = file();
        for v in [
            frames::image_protected(&f),
            frames::image_released(&f),
            frames::image_grow_request(&f, 4096),
            frames::image_grown(&f),
            frames::image_grow_ack(&f, true, None),
            frames::image_grow_ack(&f, false, Some(106)),
        ] {
            let bytes = paguro_vm::session::agent_frame(&v);
            let mut buf = bytes;
            let framed = paguro_vm::session::agent_frames(&mut buf);
            assert_eq!(framed.len(), 1);
            assert_eq!(framed[0], v);
            assert_eq!(frames::file_ref_of(&framed[0]).unwrap(), f);
        }
    }

    #[test]
    fn fake_channel_hands_back_frames_in_order() {
        let mut ch = FakeChannel::with_inbox([json!({"a": 1}), json!({"a": 2})]);
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(ch.recv(deadline).unwrap(), Some(json!({"a": 1})));
        assert_eq!(ch.recv(deadline).unwrap(), Some(json!({"a": 2})));
        assert_eq!(ch.recv(deadline).unwrap(), None);
    }
}
