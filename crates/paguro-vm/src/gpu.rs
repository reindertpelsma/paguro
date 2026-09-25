//! GPU backends for the Windows VM (INTERFACES.md §11.9).
//!
//! The launcher knows no GPU technology. A backend is a small provider it
//! asks, in order; the first available one is used, the launcher logs why
//! the others were not, and a backend failing at start falls back to the
//! next, so a GPU problem never stops Windows from starting. Only `none`
//! exists today: a plain display device, no acceleration.

/// What [`GpuBackend::probe`] and [`GpuBackend::health`] report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    Available,
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    Ok,
    Degraded(String),
}

/// A guest-side driver a backend needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestRequirement {
    pub driver: String,
    pub min_version: Option<String>,
}

/// What a backend is told about the VM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmInfo {
    pub memory_mib: u64,
    pub name: String,
}

/// The contract, per backend (INTERFACES.md §11.9).
pub trait GpuBackend {
    fn name(&self) -> &'static str;
    fn probe(&self) -> Probe;
    fn qemu_args(&self, vm: &VmInfo) -> Vec<String>;
    fn guest_requirements(&self) -> Vec<GuestRequirement>;
    fn health(&self) -> Health;
}

/// Always available: QEMU's standard VGA (Windows' inbox basic display
/// driver, over the UEFI GOP).
pub struct NoneBackend;

/// Video memory of the plain display device: enough for 4K at 32 bpp.
const NONE_VGAMEM_MB: u32 = 64;

impl GpuBackend for NoneBackend {
    fn name(&self) -> &'static str {
        "none"
    }
    fn probe(&self) -> Probe {
        Probe::Available
    }
    fn qemu_args(&self, _vm: &VmInfo) -> Vec<String> {
        vec![
            "-device".into(),
            format!("VGA,id=video0,vgamem_mb={NONE_VGAMEM_MB}"),
        ]
    }
    fn guest_requirements(&self) -> Vec<GuestRequirement> {
        Vec::new()
    }
    fn health(&self) -> Health {
        Health::Ok
    }
}

/// The backends in preference order (kayfabe, Helios, … once they exist;
/// `none` last, always).
pub fn registry() -> Vec<Box<dyn GpuBackend>> {
    vec![Box::new(NoneBackend)]
}

/// The order to try at start: every available backend, preferred first,
/// and a log line for each one skipped.
pub fn candidates(backends: &[Box<dyn GpuBackend>]) -> (Vec<usize>, Vec<String>) {
    let mut use_ = Vec::new();
    let mut log = Vec::new();
    for (i, b) in backends.iter().enumerate() {
        match b.probe() {
            Probe::Available => use_.push(i),
            Probe::Unavailable(why) => log.push(format!("gpu: {} unavailable: {why}", b.name())),
        }
    }
    (use_, log)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    struct Fake(&'static str, Probe);
    impl GpuBackend for Fake {
        fn name(&self) -> &'static str {
            self.0
        }
        fn probe(&self) -> Probe {
            self.1.clone()
        }
        fn qemu_args(&self, _: &VmInfo) -> Vec<String> {
            vec![self.0.into()]
        }
        fn guest_requirements(&self) -> Vec<GuestRequirement> {
            vec![GuestRequirement {
                driver: "nvidia".into(),
                min_version: Some("580".into()),
            }]
        }
        fn health(&self) -> Health {
            Health::Degraded("test".into())
        }
    }

    #[test]
    fn falls_through_to_none() {
        let b: Vec<Box<dyn GpuBackend>> = vec![
            Box::new(Fake("kayfabe", Probe::Unavailable("no NVIDIA GPU".into()))),
            Box::new(Fake("helios", Probe::Available)),
            Box::new(NoneBackend),
        ];
        let (order, log) = candidates(&b);
        assert_eq!(order, [1, 2]);
        assert_eq!(log, ["gpu: kayfabe unavailable: no NVIDIA GPU"]);
        assert_eq!(b[2].name(), "none");
        assert_eq!(b[2].health(), Health::Ok);
        assert!(b[2].guest_requirements().is_empty());
        assert_eq!(b[1].guest_requirements()[0].driver, "nvidia");
        assert_eq!(b[1].health(), Health::Degraded("test".into()));
        let a = b[2].qemu_args(&VmInfo::default());
        assert_eq!(a[0], "-device");
        assert!(a[1].starts_with("VGA,"));
        assert_eq!(b[1].qemu_args(&VmInfo::default()), ["helios"]);
    }

    #[test]
    fn registry_ends_with_none() {
        let r = registry();
        assert_eq!(r.last().map(|b| b.name()), Some("none"));
        assert_eq!(candidates(&r).0, [r.len() - 1]);
    }
}
