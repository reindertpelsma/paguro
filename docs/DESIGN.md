# paguro — dual-boot Linux from inside NTFS, no repartitioning

*Paguroidea: the hermit crabs. They occupy a shell they did not build, leave its
structure unaltered, and can move out without damaging it. The metaphor is the
design's two hard invariants, and it names the failure mode being guarded
against.*


Design captured 2026-09-21, revised 2026-09-25. This document argues the design;
[`INTERFACES.md`](INTERFACES.md) fixes the exact formats and contracts. Status:
**being built against INTERFACES.md** — the loader runs all four stages, BitLocker
included, under OVMF and AAVMF with a software TPM in CI, and the kernel module's
core runs in a throwaway VM; none of it has yet met real firmware or a real
Windows guest. *Architecturally mature, experimentally unproven.* The next
increase in confidence comes from trying hard to destroy a sacrificial NTFS
volume and failing (§11).

> **Your existing Windows, both ways.** Install Linux like an application, use
> the Windows you already have from inside it as a VM, and keep a completely
> ordinary native Windows boot for whatever needs bare metal — with nothing
> repartitioned and nothing reinstalled.

What that gives, in the order it matters to people:

- **Space shared with Windows, not carved from it.** Linux lives in image files
  on the Windows volume and draws from the same free space: no partition sized up
  front, no starving one side to feed the other, and an image grows when it needs
  to (§2, §5.6).
- **As many distributions as you like**, each a file: trying one is creating a
  file, removing it is deleting one (§2).
- **Your Windows, both ways** — the same installation boots natively and runs as
  a VM on the Linux desktop (§1b, §5b).
- **Windows can reach Linux, even on a single-disk laptop**: the image is a file
  WSL2 mounts, which a Linux partition on the Windows disk never is (§1).
- **Your WSL2 distributions on the metal**, as they are (§8b).
- **BitLocker keeps working** without recovery-key prompts, because Windows' boot
  path is never touched (§6).

What install adds, all of it additive and all of it removed by a supported
uninstall (§6b): files in `\EFI\paguro\` on the ESP, paguro's firmware variables,
a boot entry and one enrolled MOK certificate, the Linux image file(s) on C:, a
Windows minifilter, and a transition app. The partition table and Windows'
BitLocker configuration are never touched.

---

## 1. Motivation

Classic dual boot requires shrinking NTFS, adding partitions and installing a
bootloader Windows will later fight with. The file container's first benefit is
that **ordinary people can complete the install** — and the barrier is the whole
ritual, not one step of it:

| Normal Linux install | paguro |
|---|---|
| download an ISO | run an installer in Windows |
| find a USB stick | reboot |
| flash it | |
| find the boot-menu key | |
| boot a live environment | |
| navigate a partitioner, get the ESP right | |
| hope Secure Boot cooperates | |

Windows' shrink being blocked by unmovable files — MFT extents, pagefile,
hiberfil, VSS shadow copies — is real, and is step six. The other six are where
curious people bounce off. This is what Wubi was popular for.

**One pool of space, and as many distributions as it holds.** The reservation is
dynamic, not fixed (§5.6): ~15 GB that grows, drawn from the same free space
Windows uses, rather than 200 GB committed forever to one side of a partition
boundary. For someone who only *sometimes* wants Linux, that is the difference
between trying it and not — and a second or third distribution is another file,
not another round with a partitioner (§2).

What it sells is **predictability and reversibility**. It does not sell
invisibility: a machine carrying a driver, an EFI binary and a boot entry is not
invisible to IT, and §8 excludes managed devices anyway.

*"Linux inside NTFS without repartitioning"* is the **mechanism**; the product is
that the two environments stop being separate installations.

**The machinery runs only when Linux runs.** Windows boots natively with the
module absent, the loader unused and nothing enforcing anything — so using Linux
occasionally means being exposed occasionally, and there is no path where light
use makes the dangerous part more dangerous.

**Dual boot does not disappear because VMs get good.** Institutional reality
(IT expects Windows), residual VM quirks, and the fact that people want 100%
Windows compatibility rather than 90% mean the native boot keeps mattering
regardless of how good GPU virtualisation becomes.

**But the VM has to be good enough to be the daily path**, or the design inverts
into the worst case: an intricate mechanism exercised rarely and therefore never
tested, guarding a boot the user relies on constantly. That makes GPU sharing a
headline requirement rather than a nice-to-have — see **§1b**, which comes before
the disk design for that reason.

### Why not just a dedicated partition

A partition is the technically robust answer — an LBA range neither filesystem
can touch — and for a user who wants nothing else it is simpler. paguro chooses
an image file for what a partition cannot give:

- **one pool of space** shared with Windows, and as many distributions as it
  holds without carving the disk up (§2);
- **Windows can reach Linux.** On a single-disk laptop — most laptops — a Linux
  partition is invisible to Windows: Windows has no ext4 driver, Hyper-V passes
  through whole disks but not partitions, and `wsl --mount` attaches whole disks,
  so it cannot take the disk Windows is running from. An image file on C: is just
  a file, which WSL2 mounts (§8b) — and the same holds the other way, so a WSL2
  distribution runs on the metal as it is;
- **installability and reversibility** (above): nothing repartitioned, and
  uninstall is deleting files.

### The storage path, and what killed Wubi

Wubi is the obvious precedent, and precisely what killed it is what this design
is built around.

**The root cause was the I/O path.** From WubiUEFI's own initramfs patch, the
image is loop-mounted *on top of a mounted NTFS volume*:

```text
ext4 -> loop -> file I/O -> NTFS driver (ntfs-3g / FUSE)
     -> block device
```

That single fact explains both technical deaths. **Flush and FUA never reached
hardware** — a barrier became an `fsync` on a file, through a filesystem driver,
through FUSE — so ext4's journal assumed durability the stack did not provide and
a power cut left it unrepairable. And **every I/O crossed the NTFS driver**,
twice through userspace in the ntfs-3g era, with fragmentation costing real seeks
because the file was read *through* a filesystem.

paguro's path has no filesystem in it:

```text
ext4 -> gather (the image's extents, a range remap)
     -> dm-crypt (the volume, BitLocker's own layout)
     -> block device
```

Barriers propagate to hardware exactly as for a partition, and fragmentation is a
table lookup in the gather. That is not a mitigation of Wubi's problem — it is
the absence of its cause. Cost is a LUKS-encrypted partition plus a linear remap:
the same `dm-crypt` target, over the volume instead of over a partition (§4.3).

**WubiUEFI is the useful data point:** the community *did* fix the boot half, and
kept it working for years. It explicitly did not fix the storage half, because
that meant redesigning it. paguro's entire design is the storage half.

**And "an image on NTFS is unsafe" is simply false** — WSL2 runs `ext4.vhdx` for
millions of users daily, as Microsoft's own shipping product. Note what that
claim does and does not answer: WSL2's path is `guest → virtual disk → Hyper-V →
Windows file I/O → NTFS`, so Windows owns the filesystem throughout and there is
no ownership question. It refutes the general claim; it does not refute "sector
mapping needs enforcement", which is what §4.3 exists for.

**Wubi's other two causes, and how paguro answers them.** Canonical dropped Wubi
because carrying it was not worth the trouble, and UEFI broke it. paguro is
UEFI-native, and NTFS's on-disk format has been effectively frozen since NTFS
3.1. What remains is upkeep: paguro spans two operating systems and a
hypervisor, so it has more surfaces that can drift than Wubi had. The design is
built so that drift is **caught early, fails soft and is repaired from
Windows**:

| Drift | What happens | Built in |
|---|---|---|
| a Windows feature update wipes the ESP | Windows boots as always; the next start of the paguro service restores the loader and seals | the repair hook (§7) |
| firmware, `dbx` or Secure Boot database updates | the pre-flight notices before "Restart into Linux" and re-stages the seal; if it lands later, the loader says so and Windows fixes it in one click | pre-flight, `setupTPM`, `PaguroTpmBroken` (§4.6, §6) |
| a kernel update the module does not build against | the update fails loudly and the previous kernel stays the default; no unbootable entry is ever written | the DKMS initramfs guard (INTERFACES §11.6) |
| anything else in the Linux path | Linux declines to start, the data intact, the recovery key and Windows both still work | the core invariant (§3) |

**Windows is never the thing that breaks**: its boot path, BitLocker
configuration and partition table are untouched, and uninstall is a handful of
deletions (§6b). The pieces most likely to move are stock components maintained
by others (shim, systemd-boot or GRUB, the distribution's kernel and
initramfs, device-mapper, ntfs3), and the parts that are ours — the formats, the
loader, the kernel module's core — are small, versioned and exercised on every
change against OVMF, AAVMF, several kernels and both architectures.

Upkeep is still a commitment someone has to make, as for any software that
touches boot. But the failure it guards against is "Linux waits for a repair
that Windows can do", not a stranded machine.

---

### Closest prior art

Each part has precedent, much of it small community work on GitHub; nothing
found combines the parts.

**Linux from an image file**

| Project | Shares | Lacks |
|---|---|---|
| **Ventoy `vtoyboot`** (386★, 2025) | boots an *installed* Linux natively from a **fixed-size VHD**, including from a local disk — the closest thing to paguro's boot and storage half, and the same fixed-VHD choice | no BitLocker; no Windows running meanwhile, so no enforcement; must be re-run after kernel updates |
| **Ventoy** core | `vtoydm` maps a fragmented file's extents with a `dm-linear` table — paguro's view A mechanism | removable-media multiboot |
| **WubiUEFI** (1.2k★) | Linux in a file inside NTFS, no repartitioning, UEFI via shim | loop-over-NTFS I/O path, no BitLocker, no enforcement; last release June 2024 (22.04.4) |
| `nikp123/ntfs-rootfs`; the "Windows and Linux in one partition" gist | Linux root directly on NTFS via `ntfs3`, no partitioning | a shared filesystem, not an image: filename conflicts, `chkdsk` deleting Linux files, explicitly not recommended |

**The same Windows, natively and as a VM**

| Project | Shares | Lacks |
|---|---|---|
| **`qt1/mapped-windows-vdisk`** (2019) | builds the VM's disk with `dmsetup` from a copied GPT and ESP plus a link to the real Windows partition — paguro's view B sandwich, found independently | partition-based dual boot, unencrypted, manual; no protection of anything but the other partitions |
| `lejenome` dual-boot-to-VM; `0xf4b1/qemu-kvm-windows`; `npip99/dual-boot-to-vm` | one Windows installation booted natively and in KVM, via a linear-RAID or partition-passthrough disk | Windows on its own partition; activation and BitLocker unaddressed |
| **Parallels / VMware Fusion "Boot Camp VM"** | the closest commercial analogue | macOS host; reactivation friction; gone with Apple Silicon |

**The rest**

| Project | Shares | Lacks |
|---|---|---|
| **WinBoat + Helios**, WinApps, Cassowary, dockur | RemoteApp windows; paravirtual GPU without VFIO | a *freshly provisioned* Windows, not the user's own |
| `dislocker`, `cryptsetup bitlk` | BitLocker unlock outside Windows | userspace only; **no pre-boot (EFI-stage) implementation found** |
| booting a WSL2 `ext4.vhdx` on bare metal | — | **nothing found**; the known paths mount it or re-virtualise it |

What appears new is the combination: an EFI-stage BitLocker unlock, a kernel
module that polices the image's extents against a *concurrently running* OS
rather than only mapping them, and one already-encrypted, already-activated
Windows installation reachable natively and as a VM without changing its boot
path. The pieces paguro shares with `vtoyboot` and `mapped-windows-vdisk` are
evidence the mechanisms are sound, not only that the idea is taken.

### The solvable counterweight

**A partition puts its risk in one bounded operation at install time**, which
fails visibly and recoverably. This design puts risk in an enforcement path
instead. That is a worse place for risk to live *unless the path can be shown
correct*, which is why §11 Q1–Q3 are go/no-go gates rather than items on a
list.

**And if the GPU backend never arrives**, the proposition collapses back to the
mechanism — an elaborate way to occasionally boot Linux — and a partition wins.
That is the other gate, and §1b is where it is argued.

---

## 1a. What people actually complain about

§1 argues from first principles. This section is the evidence, and it exists
because the complaints are unusually consistent: survey the dual-boot writing of
the last two years and **almost every mechanical grievance is a consequence of
the two things paguro does not do — repartition, and install a bootloader.**

Surveyed: the articles and threads listed under *Sources* below. The table
names the complaint, not how often it came up — a handful of articles is a
sample, not a statistic.

| Complaint | paguro |
|---|---|
| **Windows updates overwrite GRUB / boot entries** | Microsoft's bootloader is never replaced and `bootmgfw.efi` is never touched; there is nothing to overwrite. A wiped ESP is repaired from a running Windows, and §4.6's transition re-creates the entry as its *normal* operation |
| **Partitioning risk — "a mistake deletes your Windows partition"** | no repartitioning at all |
| Rebooting is friction; Linux ends up unused | **not solved by the storage half** — §1b is the answer, and it is the unproven one |
| **Fast Startup locks NTFS; Windows partition won't mount** | *restart* performs a full shutdown, so the transition path never produces a hybrid-hibernated volume (§4.6). The universal advice — "disable Fast Startup" — becomes unnecessary rather than mandatory |
| **Secure Boot / SBAT breakage** | GRUB was the August 2024 revocation's target; paguro's own chain has no GRUB, and a stock image's GRUB is its distribution's to update. The shim ecosystem is still shared — but §4.6's pre-flight **detects the change before the reboot and stages the fix automatically**, so the cost is a PIN prompt in Windows instead of a machine that won't start. The residual is that we ship an update, which is ordinary maintenance |
| **BitLocker demands its recovery key** | Microsoft's boot path is untouched, so PCR 4 and 7 do not move and **Windows never prompts.** §6 |
| Storage split is permanent, resizing later is risky | §5.6 — the image grows on demand |
| Clock skew (UTC vs local time) | **solved at install.** Linux copies Windows' timezone and uses a local-time RTC, so the two agree and Windows is not modified. NTP still runs, which also covers a DST change while the machine is off |

*Sources:*
[How-To Geek](https://www.howtogeek.com/dont-need-to-dual-boot-anymore-theres-a-better-way/),
[Yahoo Tech](https://tech.yahoo.com/computing/articles/dual-booting-linux-no-longer-160013039.html),
[XDA: why I stopped dual booting](https://www.xda-developers.com/why-i-stopped-dual-booting-windows-and-linux-on-my-pc/),
[XDA: 5 pitfalls](https://www.xda-developers.com/5-pitfalls-of-dual-booting-windows-and-linux-that-i-wasnt-prepared-for/),
[It's FOSS](https://itsfoss.com/dual-boot-issues/),
[MakeUseOf: Fast Startup](https://www.makeuseof.com/stop-chasing-faster-boot-times-disable-windows-fast-startup/),
[Corsair](https://www.corsair.com/us/en/explorer/diy-builder/storage/what-is-dual-booting-and-is-it-worth-it/),
Linux Mint forums ([343070](https://forums.linuxmint.com/viewtopic.php?t=343070),
[416387](https://forums.linuxmint.com/viewtopic.php?t=416387)).

**The BitLocker row is the most legible benefit in the document and the easiest to
demonstrate.** Installing any conventional Linux bootloader changes the measured
boot state, Windows notices, and the user is asked for 48 digits they have never
seen. One of the surveyed authors quit dual-booting over exactly that, quoting the
PCR mismatch. No approach other than a second physical drive can make this
promise.

### The objection worth taking seriously

Two of the most mainstream pieces argue the whole category is obsolete — *"dual-
booting still works, but it solves a problem most people don't really have
anymore"* — and recommend WSL2 or a VM instead.

**It is an argument against the market, not against the mechanism** — and it lands
on the half this document already flags as unproven. If WSL2 is sufficient, none
of §4 is justified and §11's kill criterion should fire.

**The rebuttal is revealed preference.** If WSL2 were sufficient, people would have
stopped installing Linux natively. They have not, in numbers that are still
measured in millions. WSL2 gives you Linux **tools inside Windows**; it does not
give you a Linux **desktop** — a different window manager, a different workflow, a
machine that is not running Windows' interface. That is a categorical gap, not a
maturity gap, and no amount of WSL2 improvement closes it.

**And nobody is incentivised to close the other half.** Each mechanism that breaks
dual boot is individually defensible: the SBAT update revoked genuinely vulnerable
GRUB builds, `bcdboot` rewrites the ESP because Windows assumes it is alone, and
BitLocker demanding a key on a PCR change is correct behaviour. There is no malice
to appeal to and no reason to expect improvement — which is worse for the user than
malice would be.

**paguro's answer is that it does not need the cooperation.** It modifies nothing
on Windows' boot path, so there is nothing for Windows to take back. And WSL2 is
not a competitor here (§8b): the same image file is a WSL2 disk inside Windows,
and a WSL2 distribution runs as a container on the booted Linux — so the
mainstream recommendation becomes the first rung, and someone who never climbs
past it has lost nothing.

### What paguro is actually for

The competing options differ on four axes, and only one row has all four:

| | Existing Windows kept | Linux native | Bare-metal Windows | No repartition |
|---|---|---|---|---|
| WSL2 / Linux VM on Windows | ✓ | ✗ | ✓ | ✓ |
| Wipe, install Linux, Windows in a VM | **✗** | ✓ | **✗** | n/a |
| Traditional dual boot | ✓ | ✓ | ✓ | **✗** |
| Second physical drive | ✓ | ✓ | ✓ | ✓ — *if the machine takes one* |
| **paguro** | ✓ | ✓ | ✓ | ✓ |

> **paguro is for people who keep the Windows they already have.** Because the
> machine cannot take a second drive; because the OEM install carries vendor
> drivers, utilities and a licence that a clean install loses; or simply because
> they are not willing to make major modifications to a working computer.

If you are willing to reinstall, the answer has always been *install Linux and run
a Windows VM*, and paguro adds only risk. What that costs in practice is
reinstalling and relicensing every application, losing kernel-anti-cheat titles
and anything that detects virtualisation, OEM activation trouble from the changed
hardware, and — if native Windows is kept as well — paying 30–60 GB twice.

The second-drive row is the real incumbent, and it is the advice both XDA and the
Linux Mint thread land on. **Its limit is laptops**, which is most of the market.

So the differentiator is the one the document opens with — **your existing
Windows, both ways** — and it is also why the WSL2 objection does not land: a case
built on *booting Linux* has no answer to "don't boot, use a VM", while a case
built on *not rebuilding your Windows* is untouched by it.

---

## 1b. GPU sharing — the other half of the point

The disk design says nothing about GPUs, but without a usable GPU in the guest
none of it is worth doing: a Windows VM that cannot render is not a substitute
for the native boot, and the native boot is what this design exists to avoid
needing daily.

### Which approach, by hardware

| Host GPU | Windows guest | What it costs |
|---|---|---|
| **NVIDIA** | **kayfabe** — emulated GPU, guest loads the real unmodified driver | nothing to the shared Windows install |
| AMD / Intel | **Helios** — WDDM miniport forwarding Vulkan over Venus | a test-signed display driver in the shared install; see below |
| NVIDIA, by choice | **Helios** works here too, for anyone who prefers it to kayfabe | the same driver cost, and the VM runs Helios's driver instead of the native NVIDIA one — losing what kayfabe keeps (CUDA, NVENC, the vendor's own driver) |
| any, *Linux* guest | DRM native context (AMD/Intel, Mesa 25.0+), nvkvm-pv (NVIDIA) | n/a — different problem, listed for orientation |

### Neither backend is available today

Stated plainly, because the rest of this section reads as though a working
Windows GPU path existed:

| Project | What its own material establishes |
|---|---|
| nvkvm-pv | working NVIDIA forwarding for **Linux** guests, with CUDA/Vulkan/display results. Explicitly excludes Windows guests and warns against treating it as a hardened security boundary |
| kayfabe | research-stage emulated NVIDIA device running an unmodified driver. Reports incorrect LLM/PyTorch output and large-kernel performance **22–81× off native**; no graphics/Vulkan/display; Windows is the objective, not a result |
| Helios | further along than a casual reading suggests — substantial D3D11/D3D12 functionality and extensive validation. Still carries live correctness defects on its own roadmap (a Steel Nomad Vulkan freeze, D3D12 presentation ordering) and an explicit production-readiness warning |

So kayfabe is the **preferred destination, not a justified dependency**. Keep the
graphics backend replaceable, and require separate demonstrations of desktop
rendering, application compatibility, CUDA, encoding and recovery — *"the stock
driver loads"* substitutes for none of those.

**Build order:** kayfabe to its milestone → per-window projection (§1b) → this
storage design. Each is independently falsifiable, and none of the GPU work being
unfinished is evidence against the storage architecture.

**And the first paguro artifact is not paguro.** It is a deliberately narrow
torture harness: a virtual NTFS disk, a file with nasty runlists and
attribute-list extension records, a Windows VM, and a block layer that rejects
exactly the mutations the module would reject. Then defrag, `chkdsk`, allocation
pressure, file growth, Windows Update, crashes at every write boundary and forced
power loss — against the criteria and the kill condition in §11 Q1–Q3.

Do not write the rest until that survives.

**Helios is not wrong; it is wrong *when kayfabe is available*.** On non-NVIDIA
hardware it may be the only path to a usable GPU in a Windows guest, and then its
costs are the price of entry rather than an avoidable mistake. The argument below
is about which to choose when there is a choice — not a claim that AMD and Intel
users should go without.

### VFIO is excluded by construction

Linux is running the user's desktop on that GPU and cannot hand it away. So the
field is narrowed before any comparison starts: **kayfabe, Helios, or no GPU in
the guest.** This is forced by the architecture, not a preference.

### The deciding property is driver fidelity

> **kayfabe runs the stock NVIDIA Windows driver. Helios reimplements the
> graphics stack.**

That is the difference that decides it, and it decides it in kayfabe's favour
independently of anything about this design: the vendor driver means real CUDA,
NVENC and the full D3D feature set, against an implementation whose own roadmap
still lists correctness defects.

**Test-signing is the second difference, and it is where paguro's shape matters.**
Helios needs a WDDM miniport signed into the guest — which was rational for
winboat-org, whose Windows is a throwaway container image. Here the same image is
the user's native boot, so anything installed into it persists into bare metal
(§12).

The cost is real but narrower than "structurally wrong". Helios's *current*
deployment uses development certificates and modifies the DriverStore, and **a
DriverStore entry for an unsigned display driver plus relaxed code integrity is
what EDR posture telemetry reports** — §8's tiering moves against it. But
development signing is a property of today's deployment, not of the graphics
architecture, and §12 already describes scoping boot configuration to VM boots. An
attestation-signed Helios would keep an ordinary DriverStore entry and would not
move the tier.

What remains structural is smaller: Helios requires *some* persistent driver in
the shared installation and kayfabe requires none.

Capability compounds it. Venus measured on an RTX 4070: ~99–100% of native
compute, 87–93% on transfers, but **every cooperative-matrix path reads 0.00** —
tensor cores unreachable — with no Vulkan Video, no mesh shaders, and no CUDA.
No Vulkan Video means **no NVENC**, which matters directly below.

### Display transport

§5b mode 1 makes this a design question rather than a detail:

| Path | Transport | For |
|---|---|---|
| RemoteApp over RDP | FreeRDP + RAIL, frames encoded inside the guest | Office, Explorer, LOB apps — GPU barely matters |
| **Per-window zero-copy** | RAIL for control, dma-buf per window for pixels | the interesting one — see below |
| Direct framebuffer | host compositor presents guest VRAM full-screen | CAD viewports, video editing, games |
| Native boot | §4.6 `BootNext` | anti-cheat, firmware work |

Path 3 is where kayfabe plainly earns its keep: the guest's rendered frame
already lives in host-accessible memory, so the compositor presents it without a
readback-encode-decode round trip. RDP is the wrong transport for a high-refresh
viewport regardless of encoder quality.

Path 1 carries an open question worth measuring rather than assuming: Windows'
RDP server can hardware-encode H.264/AVC444, but whether **client** SKUs expose
that the way Server does is unverified. If they do, a guest with a real NVIDIA
driver makes the transport cheap as a side effect. If not, encode stays on the
CPU.

### Per-window zero-copy projection

The most interesting independently useful idea here — and worth being precise
that it is **independent**. It makes the *GPU* approach better than the
alternatives; it says nothing about the storage architecture, needs none of it,
and would work identically against an ordinary Linux install with an ordinary
Windows VM. That separability is a staging strength, not a weakness: it ships and
fails on its own schedule. It is not evidence for §2–§5.

**Keep RAIL as the control plane, replace only the graphics path.** RAIL already
carries window create/destroy/move/resize/z-order, icons, input, clipboard and
audio — that is what turns menus, toolbars and frameless popups into genuine host
windows rather than a rectangle-in-a-rectangle. What it *also* carries is
bitmaps, with an encode step. Substitute a per-window dma-buf for that and keep
everything else:

```text
DwmDxGetWindowSharedSurface -> shared handle
  -> D3DKMTQueryResourceInfo / D3DKMTOpenResource
  -> D3DKMT_HANDLE (allocation)
  -> host allocation -> dma-buf
  -> host compositor imports directly
```

Both calls are documented in the WDK, and `D3D11_RESOURCE_MISC_SHARED_DISPLAYABLE`
confirms the design intent — such a texture is meant to be handed to a display
path. WinApps or WinBoat keeps working unchanged as launcher and shell
integration; only the pixels change route.

**A forwarding architecture is a particularly good fit**, because the *host*
already owns the allocation. The defensible claim is that this route may be
unusually effective here — **not** that competing architectures are structurally
incapable of per-window sharing. Intel documented a dma-buf-based local display
mechanism for GVT-g, which is neither this proposal nor an SR-IOV result, but is
enough to retire the universal claim.

**Caveats that will bite:**

- **`DwmDxGetWindowSharedSurface` is worse than "thinly documented".** Microsoft
  states it is intended for a graphics driver or runtime rather than
  applications, that the documentation is valid **for Windows 7 only**, and that
  its existence or behaviour is not guaranteed on other versions. It also sits
  next to an undocumented `user32` twin. A current-Windows proof of concept is
  therefore mandatory before treating surface acquisition as available at all.
- **Host-owned allocation is not the same as safely displayable without copy.**
  Exportability, image layout, producer completion, consumer release and resource
  lifetime all have to line up — Linux's dma-buf documentation treats sharing and
  synchronisation as coupled for exactly this reason.
- **Resize recreates the surface**, so the allocation changes. Re-resolve on
  every `updateId` change — the protocol already signals it.
- **Layered and transparent windows** may have no straightforward redirection
  surface. Fall back to the RDP bitmap path per-window rather than globally.
- The **second-GPU case** is already solved by the same logic the present path
  uses: native scanout when the display is on the same GPU, readback when it is
  not.

Note RAIL seamless windows are genuinely usable today — people do daily work in
them. This is not fixing something broken; it is removing an encode and decode
from a path that does not need them.

### WinApps / WinBoat as the integration layer

WinBoat is FreeRDP 3.x driving Windows RemoteApp against `127.0.0.1`, plus a Go
guest agent for app enumeration — architecturally the same family as WinApps.
Verified from source: `getFreeRDP.ts` requires xfreerdp v3.x, `winboat.ts`
launches `/app:program:…` with `/cert:ignore +clipboard /sound:sys:pulse
/microphone:sys:pulse /floatbar /compression /sec:tls`. Either project can serve
§5b mode 1's window integration unchanged, and either is the natural host for the
zero-copy substitution above.

**File sharing runs in two directions and they are not symmetric:**

| Direction | Mechanism | Status |
|---|---|---|
| host → guest (Linux files in Windows) | FreeRDP `/drive:` redirection, or dockur's in-container Samba (`\\host.lan\Data`) | WinBoat/WinApps already do this |
| **guest → host** (Windows C: at `/mnt/c`) | Windows shares over the point-to-point virtio link, `mount.cifs` on the host | **neither project does this** — ours to build and secure |

§5b mode 1 depends on the second row, so it is an addition rather than something
to lift. Easy enough mechanically; the security work is ours (bind to the
host-only link, credentials from the keyring per §4.7).

**Licensing is where the shared installation differs most.** A WinBoat-style
VM is a *second* Windows installation, so it needs its own licence beyond the
evaluation period. A laptop's OEM key in the firmware (`/sys/firmware/acpi/
tables/MSDM`) can activate such a VM only if the native installation is not also
in use — the licence covers one instance per device. paguro's VM is **the same
installation on the same device**, never running at the same time as the native
boot, which is what the Windows licence terms describe ("one instance … on one
device, whether that device is physical or virtual"). No second licence, and
the same for self-built desktops, whose digital licence is tied to the hardware
rather than stored in firmware. (Our reading of the licence terms; to be
confirmed against the current Windows 11 text before release.)

**Activation still has to survive the move between hardware and VM.** Windows
ties its activation to a hardware hash; a VM that looks like different hardware
can show *not activated* while it runs. The VM therefore presents the host's own
identity where QEMU can: the firmware's SMBIOS tables (`-smbios` from the host's
values), the OEM licence table (`-acpitable file=…/MSDM`), the system disk's
serial number and the network adapter's MAC address (§11 Q32).

**Helios** is winboat-org's separate GPU effort (§The deciding property above).
Note also that Venus's missing Vulkan Video means it cannot help the RDP encode.

With kayfabe providing full GPU capability in the VM (CUDA, NVENC, tensor cores,
certified driver identity), the native boot becomes a rarely-exercised fallback:
anti-cheat games and firmware work. That is the ideal configuration for a design
this intricate — **the complicated path is the one used daily and therefore
tested constantly; the simple path is the fallback.**

Kayfabe also needs **zero guest-side driver changes**, which suits a *shared*
installation best; Helios needs a display driver in an image that also boots
natively — acceptable once attestation-signed, costly while it is test-signed.

---

## 2. Disk layout

Unchanged from stock Windows. Nothing is added to the partition table.

```text
p1  ESP   (FAT32)  -- Windows Boot Manager, untouched,
                     PRIMARY boot path
p2  MSR   (16 MB)
p3  C:    (NTFS)   -- Windows system volume
      \-- one or more image files, anywhere on the
          volume; non-sparse, uncompressed,
          each growing on demand (sec.5.6)
p4  Windows Recovery
```

The Linux installation lives entirely inside an image file on C:, which is where
it inherits BitLocker protection for free. The image is a **fixed VHD** — raw
payload plus a 512-byte footer — so the same file is a bare-metal root for paguro
and a disk WSL2 can mount (§8b). This document calls the default one `linux.vhd`.

**One pool of space, as many distributions as it holds.** §4.3 watches no NTFS
metadata at runtime, so nothing ties an image to a particular directory, and
`paguro.ini` can list **several** `[Boot.*]` entries, even on different NTFS
volumes and disks.

That is the headline capability, and a partition layout cannot offer it at all:

| | Partitioned dual boot | paguro |
|---|---|---|
| space, Windows vs Linux | fixed at creation, each starving the other | **one pool** — every image draws from NTFS free space and grows on demand |
| second distro | another partition, carved from somewhere | another image file, another `[Boot.*]` entry |
| trying one out | repartition, then repartition back | create a file, delete a file |
| Windows reaching Linux | not on the disk Windows runs from | the image is a file WSL2 mounts |

Several distributions contending for one pool of free space is awkward enough
with partitions that most people keep exactly one. Here it is a file each.

**Sized dynamically, not reserved.** Start at ~15 GB and grow as needed (§5.6).
The space is fungible with Windows', draws from the same free pool, needs no
adjacency, and returns instantly on removal. A partition can only grow into free
space immediately after it, and can only give space back if the geometry
cooperates.

**File requirements for images paguro boots** — the paguro host and stock
distribution images (verified at setup and at every boot). WSL2 distribution
disks are dynamic VHDX and follow different rules (§8b):
- a **fixed VHD** or a **raw** disk file, detected by content — never a dynamic
  VHD/VHDX, whose block allocation table raw mapping cannot follow
- fully allocated, **not sparse** (`FILE_ATTRIBUTE_SPARSE_FILE` clear)
- **not NTFS-compressed** (`FILE_ATTRIBUTE_COMPRESSED` clear)

Sparse or compressed files have extent maps that raw LBA writes would corrupt.
Fragmentation is not a requirement: the extent list only feeds a range table
(§4.3).

### Inside an image

Each `[Boot.*]` entry in `paguro.ini` names two things (INTERFACES §3.2): the
**root**, a disk file the kernel module claims and hands to Linux, and the **next
UEFI image**, either on the FAT32 of a disk file (`efi_disk`, by default the root)
or as a plain `.efi` file on NTFS (`efi_file`). Two shapes cover the cases:

```text
stock distribution image              the paguro host
GPT (nested -- Windows never          root:  fixed VHD, one bare ext4,
     looks inside the file)                  no partition table
  p1  FAT32 ESP -> its own shim +     next:  a UKI as an efi_file
      GRUB, systemd-boot or a UKI            on NTFS
  p2  ext4 / btrfs / LVM / LUKS
```

A distribution image is an ordinary GPT disk — §4.3 already presents the file as
one — and its ESP is found by partition type (`C12A7328-…`); a disk that is one
bare FAT32 ("superfloppy") works too. The loader reads **only FAT32, and only
through the firmware's own driver** (§4.2); everything beyond the ESP is read by
the next image with its own filesystem code. Size the ESP generously: the image
grows on demand, so the "/boot is full" problem of 512 MB partitions cannot
arise.

**The root is a hint the loader never opens**: it resolves the file's identity
and forwards it, and whatever filesystem is on it is Linux's to mount.

---

## 3. Core invariant

> **The physical disk is written only after some component has proven the
> image's extent map is exactly what Linux believes it is.**

Everything else follows from this. The worst failure is **"Linux refuses to
start"** or **"the image is orphaned with its contents intact"** — never **"the
disk is corrupted"** (§4.3).

A second invariant:

> **The extent map is never persisted. It is re-derived from NTFS metadata at
> every boot, by every consumer.**

This neutralises the entire class of "defrag moved the file between sessions"
bugs. Nothing ever depends on a stale map.

**This section and §5 are the heart of the design.** Everything about TPM
policies, PCR selection and key derivation in §6 has to be got right, but it is
well-trodden ground with known answers. Not corrupting a disk that two
operating systems believe they own is the part that is actually hard, and the
part where a mistake is unrecoverable rather than merely inconvenient.

---

## 3a. The architecture on one page

**This is what the document specifies**, and every later section elaborates one
box of it. Where anything else disagrees with this page, this page is right and
the other text is a defect. §11's open questions each map to something here.

```text
NATIVE WINDOWS BOOT -- completely ordinary
  firmware default, Microsoft's bootloader,
  Secure Boot on, partition table unchanged,
  paguro absent

LINUX BOOT
  own Boot#### entry -> a distribution's signed
  shim (redistributed) -> paguro.efi, signed with
  the machine MOK key, enrolled once at install.
  paguro.efi never writes to disk; reaches Windows
  only by BootNext + reset, never by chainloading
    stage 1  read paguro.ini, SHA-256, compare to
             PaguroConfigHash (Secure Boot on)
    stage 2  parse; LOAD TAINT: PCR 12 <- H(whole .ini)
    stage 3  FVE parse, rungs, obtain VMK;
             BOOT TAINT: PCR 12 <- sentinel
    stage 4  NTFS; the chosen [Boot.*] entry's
             disks; gates; publish efi_disk as a
             READ-ONLY BlockIo, firmware FAT binds;
             LoadImage the next image: UKI,
             systemd-boot, or shim + GRUB as shipped
  -> hands the initrd (TLV table): volume, VMK,
    FVEK + layout, B, PCR values, verified .ini,
    image identities, gate state, rung

KEYS (sec.6)
  every standing rung needs the passphrase;
  tpm = TPM(PCR 0/2/4/7/12) + B + passphrase
  setupTPM = one-shot, staged by Windows
  passphrase = opt-in; recovery = FVE's own
  PIN bypass: TPM-clock-bound, written by a
    logged-in Windows on "Restart into Linux"
  .ini ratcheted whole into PCR 12; crypto
    material and PCR selection live in the
    per-volume *_seal.bin files

LINUX KERNEL MODULE -- the only component that
can corrupt anything. DKMS source in the image's
paguro package, with the initramfs hook
  NTFS parsed by the module at load, and again at
  each growth event -- same parser, same bounds.
    nothing in userspace can supply the map.
    ntfs3 FIEMAP is a cross-check that can only
    SUBTRACT: disagree -> no view A, ever.
  asserts before r/w: dirty bit, hibernation,
    unreplayed journal, allocated == sum(extents).
    any failure -> READ-ONLY
  view A's content asserted before anything
    mounts (GPT / bare ext4 / ISO 9660), reading
    past the first extent: fail -> no view A
  runtime enforcement is A RANGE TEST, nothing else:
    read  in the set -> EIO    this is what stops
    write in the set -> EIO    defrag -- no copy,
    else             -> pass   so no runlist record
                               is ever logged
  NO CIPHER AND NO KEY IN THE MODULE
  the module's unit is A PROTECTED VIEW OVER A BLOCK
    DEVICE. everything above it -- synthetic GPT,
    dm-crypt segments, which partitions the guest
    sees -- is stock device-mapper driven by userspace
  view A  one image's extents, gathered. NOT SINGULAR:
          several images may be mapped at once
  view B  C: as ciphertext -> the VM; extents EIO
  view C  C: as plaintext  -> Linux mounts NTFS
  B and C are PARTITIONS, carry the SAME protections,
  and are MUTUALLY EXCLUSIVE -- never both
  dm-linear sandwiches B's GPT -- untrusted,
  enforcement is beneath it
  worst case: image orphaned into found.000,
    CONTENTS INTACT. anything worse is a defect

WINDOWS VM
  no TPM.  FVE metadata substituted with an
  ExternalKey VMK entry; {GUID}.BEK on a synthetic
  removable, hot-unplugged after boot.
  Guest does its own crypto with the real FVEK.

WINDOWS MINIFILTER -- quality of experience,
not correctness
  pins clusters, denies sharing, refuses unload;
  not trusted; defrag skips cleanly instead of
  meeting EIO

GROWTH  append-only, through whichever side holds C:
        (the VM driver, or ntfs3 natively);
        module re-derives and verifies itself
SHRINK  offline, two phases, narrow before truncate
INSTALL  from Windows, through WSL2: the distribution's
         own installer in a container, writing a
         fixed VHD; never against the real disk
UNINSTALL  additive install => six deletions,
           one reboot
```

---

## 4. Components

### 4.1 Custom UEFI bootloader (`paguro.efi`)

**Signed with this machine's own key, trusted through shim.** paguro needs no
Microsoft signature and has no project certificate (INTERFACES §2.1, §11.6):

- **The first image is a distribution's Microsoft-signed shim, redistributed
  unchanged** with its MokManager. Every such shim trusts, besides its vendor's
  key, anything signed by a key in `MokList`. Our `Boot####` entry points at the
  shim, and the shim's second stage is `paguro.efi`. `paguro.efi` carries the
  `.sbat` section shim requires, and its generation is bumped when a security fix
  must revoke older builds. The installer picks the shim build whose signing CA
  is in this machine's `db` (the 2011 UEFI CA or its 2023 successor).
- **One MOK key per machine**, generated by `paguro install`. It signs
  `paguro.efi`, every DKMS build of the kernel module, and locally built UKIs.
  The Windows tool queues it for enrolment by writing shim's `MokNew`/`MokAuth`
  variables, so the next boot shows MokManager **once**; no later install,
  distribution or kernel update asks again.
- **`db` is the fallback**, for machines that ship with the third-party UEFI CA
  disabled (Secured-core PCs), where no distribution shim loads: enable that CA
  in firmware setup, or enrol our certificate in `db` directly. Both need
  firmware setup and both move Windows' PCR 7, so the Windows tool first
  suspends BitLocker for exactly one reboot and Windows re-seals by itself.

Our trust is the machine key, not the shim vendor's: when SBAT or `dbx` revokes a
shim, the repair hook installs the distribution's replacement and nothing else
changes (§7). Where the private key lives, and what guards it, is §6 (The machine
MOK key).

Sits in `\EFI\paguro\` on the ESP, **alongside** Windows Boot Manager. **Does
not replace `bootx64.efi`. Does not install a boot menu by default. Windows
remains the default.**

**It never writes to the disk.** Every file it needs written — the configuration,
the seal files — is written by the initrd from values the loader forwards. That
is what keeps the loader's bugs confined to confidentiality and bootability rather
than letting them reach the disk.

It does write **firmware variables**, all small and deliberate, none on a block
device (INTERFACES §5): deleting the bootstrap `Boot####` entry, creating
`PaguroB` on the first boot (and deleting it on an uninstall boot, §6b),
deleting the one-shot `PaguroSetup`, setting and clearing `PaguroTpmBroken`, and
setting `BootNext` to reach Windows (§6). Stated
as firmware operations so the disk rule stays absolute rather than approximate.
It also calls `TPM2_Create` on a provisioning boot, because only it stands at
the right PCR values (§6 Bootstrap).

#### The execution contract: four stages

Everything in the design rests on this ordering, so it is stated as a contract
rather than a sequence of steps.

There are **two taints**, and they mark different boundaries.

```text
-- STAGE 1 - must be correct; nothing protects it --
   read paguro.ini and PaguroConfigHash (64 KB cap)
   SHA-256 over the whole file
   Secure Boot on: compare against PaguroConfigHash
     (a firmware variable; no key involved)
   Secure Boot off: no comparison; the handoff
     marks the configuration unverified

-- STAGE 2 - behind stage 1; small --
   parse the file
   > LOAD TAINT: extend PCR 12 with H(paguro.ini)
     the WHOLE file -- crypto material is in .bin
     files beside it, so there is nothing to exclude

-- STAGE 3 - the VMK is still obtainable here --
   parse FVE metadata
   enumerate and merge protectors
   prompt, try the rungs, obtain the VMK
   > BOOT TAINT: extend PCR 12 with a fixed sentinel

-- STAGE 4 - the TPM will not re-authorise;
             the VMK is still in memory --
   parse NTFS through the decrypted view
   read the gates: hibernation, dirty bit
     (forwarded; Linux degrades to read-only)
   resolve the entry's root to its identity
     (never opened), and efi_disk or efi_file
   efi_disk: detect fixed VHD or raw, validate
     the extent map, find its FAT32; publish the
     disk as a READ-ONLY BlockIo, ConnectController,
     LoadImage the next image by device path
   efi_file: read it whole, LoadImage(SourceBuffer)
```

> **What the boot taint does and does not do.** Extending a PCR prevents a
> **future unseal**; it does not erase the VMK already in the loader's memory. An
> exploit in stage 4 need not ask the TPM for anything. What protects stage 4 is
> narrower and holds on its own: **crafting NTFS structures requires the VMK**,
> so an attacker able to feed the parser chosen input already has the key.
> Without it, ciphertext corruption yields uncontrolled garbage — a crash, not
> chosen execution. The boot taint is a re-authorisation control, not memory
> isolation.

| Taint | When | Prevents |
|---|---|---|
| **Load** | after parsing, before any protector is tried | a modified configuration ever yielding the key |
| **Boot** | the moment the VMK is obtained | anything later in this boot — the next image, Linux userspace, an exploited parser — obtaining it again |

**Where review goes first:** stage 3, where an exploit runs while the VMK is still
obtainable. Every parser is hardened (§6), but these three come first:

- **FVE metadata** — plaintext on disk, rewritable by anyone with physical access
- **protector enumeration and merge** — FVE-sourced entries are never signed
- **recovery-key handling** — the protector entry it consumes is FVE-sourced

With the theme compiled in (§Theme) and the configuration behind its hash,
BitLocker's formats are the only substantial attacker-authored data the loader
parses before a key exists. The rest is small and bounded, each with a fuzz
target: the physical disk's GPT (primary header only), the seal files and the
bootstrap payload (fixed layouts), a display's 128-byte EDID block, and escape
sequences from a serial console.

**The boot taint lands on a natural boundary rather than an arbitrary one.**
Reading NTFS *requires* the key, so NTFS necessarily follows it — which puts the
loader's largest parser where the TPM will no longer re-authorise and where
crafting input needs the VMK. That falls out of the data dependency, not from a
decision.

**When there is no `tpm_seal.bin`:** apply the **boot taint at load time** and
skip the load taint. Extending the sentinel *poisons* PCR 12, so an attacker who
deletes the seal hoping to skip the ratchet finds the PCR unusable for any policy
for the rest of the boot.

**Stage 1 contains no parser and no cryptography beyond SHA-256** — the hash
covers the *whole* file, so there is nothing to locate and nothing to tokenise
before verification. Read, hash, compare.

**The comparison runs only under Secure Boot.** With Secure Boot off the loader
itself can be substituted, so a check inside it would protect nothing; the load
taint still binds the TPM rung either way, and the handoff marks the
configuration unverified so every prompt says so (INTERFACES §3.3).

That is the strongest form this stage can take: with no key involved there is no
signature format to parse, no ASN.1, and no verification code that could be made
to return the wrong answer. The one thing stage 1 must get right is a bounded read
and a constant-time-irrelevant memcmp.

**And there is no embedded public key**, because nothing in `paguro.efi`
verifies a signature. The theme is compiled into the binary (§Theme), and PE
verification of the next image belongs to the platform: `LoadImage` runs Secure
Boot verification against `db`, and shim's `MokList` is reached through shim's
own hooks (§4.2, Verifying the next image). The binary carries SHA-256, AES-XTS,
AES-CCM (the FVEK unwrap), HMAC, and one elliptic-curve operation: the ECDH
that salts TPM sessions so `D` never crosses the TPM bus in clear. **No
signature verification** — the one asymmetric step is key agreement.

**Stage 2's parser is second line, not first**, and should still be small:
when the first line is three primitives, a soft second line behind them is how
the thing actually fails.

#### The safety gates — degrade, don't refuse

- **`hiberfil.sys` holds an active hibernation image** — read the header
  signature; existence alone means nothing, since Fast Startup keeps the file
  permanently.
- **The NTFS dirty bit is set** — `$Volume` (MFT record 3),
  `$VOLUME_INFORMATION`, flag `0x0001`.

Both are cheap, because the loader parses NTFS anyway.

**Degrading to read-only is better than refusing, and equally safe** — the user
boots, retrieves their files, and *then*
fixes Windows, rather than being told to go fix Windows with no way to reach
anything first. Neither condition can cause divergence when nothing is written,
and hibernation is safe read-only too: Windows' cached state only makes what
Linux reads *stale*, which is a correctness matter for the reader rather than a
corruption risk.

The loader passes the condition to the initrd, which builds the views
accordingly (§4.3) — read-only, and **no VM**, since repairing NTFS can require
moving the image and the module would refuse.

**Neither condition means the disk is bad, and the messages must say so.** Fast
Startup makes hibernation the **common** path — *every* normal Windows shutdown
leaves an active image — so booting paguro from the firmware menu lands here
routinely. The dirty bit is rarer and equally benign. Someone told their
filesystem *"needs repair"* after an ordinary shutdown will go looking for a
failing drive.

| Condition | Frequency | Register |
|---|---|---|
| hibernation image | **after every Fast Startup shutdown** | *"Windows saved a session. This is normal."* |
| dirty bit | occasional | *"Windows didn't shut down cleanly last time."* |

**A second, independent reason Windows stays the default boot entry.** Without
that, read-only would be the *normal* experience rather than a degraded one —
and it is why **"Restart into Linux" from Windows is the recommended route**:
Restart bypasses Fast Startup and produces a clean volume by construction. §4.6
exists for that reason, not as a convenience.

**Never clear an active hibernation image.** That discards whatever Windows had
open. Refusing is correct; read-only is the accommodation.

**Neither gate excludes `autochk`.** A boot-time check can be *scheduled* —
`chkdsk /f` on a volume it cannot lock writes the `BootExecute` value — and then
runs regardless; a clean volume establishes only that no *unclean-shutdown*
check is pending. Inside the VM, `autochk` meets §4.3's range test like anything
else; it is not excluded by a gate.

#### Ordering of the unseal

**Load-bearing, not incidental.** The unseal happens before any further image is
loaded, so PCR 4 at that moment covers shim + `paguro.efi` and nothing else.
**Kernel updates therefore cannot break the seal** — the next image is measured
after the key is already in hand. Deferring the unseal until after the kernel is
loaded would make every `kernel-install` a seal-invalidating event, with §7's
repair hook papering over a self-inflicted wound on every update.

#### Recovery — a path that does not read the configuration

When the hash does not match — or, under Secure Boot, the hash variable is
missing — the configuration is unusable: it cannot be
repaired in place, because the loader never writes to the disk. An **in-loader
editor cannot solve this** — editing changes the file, and proceeding on a
mismatch means parsing attacker-authorable bytes in stage 2, which is exactly
what the hash check exists to prevent. Recomputing the hash over whatever is
there would make the check ornamental.

So recovery works around the configuration instead of through it:

```text
Recover Linux
  > cap PCR 12 immediately     (see below)
    choose and unlock the volume
    browse to the disk or UEFI image, boot it
  then: Linux repairs it -- it can write both
        the file and the firmware variable
```

**Cap on entry, always.** Entering recovery extends the boot-taint sentinel
before anything else, so the TPM cannot release a key for the remainder of that
boot. This matters most for *voluntary* recovery from an otherwise healthy boot,
where the load taint was computed correctly and the TPM would otherwise still be
able to unseal. The general rule: **any path that parses unverified input caps
first.**

**Recovery never parses `paguro.ini`.** Volumes come from enumeration, paths
from an on-screen browser over the unlocked NTFS and the chosen disk's FAT32
(INTERFACES §13.4), and display and keyboard settings from compiled-in defaults
(dark, auto, US layout, each changeable on screen); keys come from the `.bin`
protector files and the volume's own FVE metadata, all self-validating. A
malicious configuration therefore cannot steer where recovery looks or what it
loads, and the prompt **states that it is unattested**.

**Recovery behaves identically whether Secure Boot is on or off.** Every major
distribution ships a shim-signed live image, so an attacker reaches the same
position *with* Secure Boot on; gating on it would buy nothing and cost a branch.

So: **one recovery path, always enumerating.** Enumeration finds volumes, but
unlocking one still requires the owner's secret; an attacker who starts recovery
reaches a prompt and stops, and PCR 12 was capped on entry.

#### The configuration is cache-like, not load-bearing

Recovery never needs the configuration, which is what makes it survivable when
the configuration is the thing that broke. **Config-independent is not
secret-independent**, which is what makes the mode safe to offer at all.

Two consequences worth stating, because both would otherwise be engineered
around:

- **No redundant copies of the configuration.** A design treating it as
  load-bearing would keep a backup on the ESP or inside the image. Unnecessary,
  and a second copy is a second thing to keep hashed and synchronised.
- **§7's repair of the ESP restores access from a running Windows.** A feature
  update that wipes the ESP removes the loader and seal files until the hook
  restores them; Windows keeps booting, the recovery key still works, and nothing
  needs external media.

#### Screens

Design rules first, because they determine the set:

1. **The happy path shows nothing.** Firmware logo → Linux. A loader that
   announces itself every boot becomes noise, and noise is what people stop
   reading.
2. **Esc always reaches the picker**, from every screen, so paguro can never
   strand anyone. Not a direct Windows boot: there is no portable way to invoke
   the *firmware's* boot menu — `OsIndications` with
   `EFI_OS_INDICATIONS_BOOT_TO_FW_UI` reaches firmware *setup*, not the picker,
   and some vendors conflate the two. So `Esc` shows **our** picker, which
   enumerates ESPs and lists Windows Boot Manager alongside anything else
   bootable, plus a **Firmware settings** entry that sets `OsIndications` and
   resets.
3. **The name appears on every screen.** An unexplained PIN prompt is alarming;
   an attributed one is not.
4. **Error codes live behind `D`**, never in the message. The message says what
   to do.
5. **Scale follows the framebuffer height**, checked to fit from 800×600 to
   3840×2160, or 4K makes an 8×16 font unreadable.
6. **Any prompt shown while the configuration is unverified** — recovery mode, or
   a missing configuration hash — **states that it is unattested.**
7. **Every screen works on every console** (INTERFACES §13.2a): graphics on each
   display at its own preferred mode, never one canvas spread across two; the
   same screens as text on serial consoles and where there is no GOP; input from
   keyboard, serial and pointer at once, with nothing requiring the pointer. F2
   cycles the light, dark and high-contrast variants, F3 toggles text and
   graphics, F4 and F5 choose the keyboard layout and language for this boot.

Sixteen screens in total, but **five primitives**:

| Primitive | Used by |
|---|---|
| progress bar | progress |
| **list** | unlock options · picker · volume selection · NTFS browser · FAT32 browser · keyboard layout · language |
| secret entry | password/PIN · recovery key grid |
| message + actions | the whole failure family — nine texts, one frame |
| detail table | details |

Everything else — the title band, `Esc` to the picker, codes behind `D` — is
frame, written once.

**Progress** — only after 500 ms, so most machines never see it. Stages:
`Unlocking volume` → `Reading filesystem` → `Verifying image` → `Starting Linux`.

**Unlock prompt** — a short list, not a single field. The reason is the **TPM
attempt cost**: someone typing a passphrase must not burn dictionary-attack
attempts against a mechanism it was never going to satisfy.

```text
                     paguro

   Unlock Linux

 > Password or PIN            3 TPM attempts left
   Recovery passphrase        no attempt limit
   Recovery key               48 digits

   ^ v select   Enter continue   Esc other options
```

**Label by cost, not by mechanism.** "TPM PIN" and "protector passphrase" read as
two different secrets, but the PIN *is* the Linux password — for most users the
same string. Naming them by mechanism invites *"which one do I have?"*, the
question a list is supposed to avoid. The attempt limit is what actually differs.

**Show only rows that exist.** Most users have no standing passphrase protector
and see two. `Details` explains what each is tried against.

**Try free protectors before the TPM, within any row.** A *correct* password then
never costs an attempt, whichever row was chosen — the counter moves only on a
genuinely wrong guess.

**Two grey-out reasons, two texts:**

```text
 [x] Password or PIN    unavailable until restart
                      -- recovery mode
 [x] Password or PIN    TPM locked for 2 hours
                      -- use another option
```

One is fixed by rebooting, the other by waiting or choosing another row. A shared
"unavailable" would send people down the wrong path.

**A TPM failure never removes the other options.** Lockout, policy mismatch, a
missing TPM — all of them grey one row and leave the rest working. The same list
appears in recovery mode, minus the TPM row, since entering recovery caps
PCR 12.

**First boot** adds one line that sets expectations: *"From now on this replaces
your Linux login password — and restarting into Linux from Windows skips it."*

**Cannot unlock** — the highest-value screen in the set, because most people do
not know their Windows is fine:

```text
   Cannot unlock Linux

   Windows will almost certainly start normally.
   Try that first -- you probably do not need
   your recovery key.

   Enter   Start Windows
   R       I need Linux now -- enter recovery key
   D       Details
```

Only after `R` does the 48-digit grid appear, in 8 groups with auto-advance and
`aka.ms/myrecoverykey` on screen.

**Refusal** — one layout, several texts, all actionable. The hibernation case is
the model because the detail people get wrong is that *Shut down does not count*:

```text
   Windows saved a session -- starting Linux read-only

   This is normal after shutting Windows down.
   Your disk is fine. Linux will start, but cannot
   write until Windows resumes once.

 > Continue read-only        get to your files
   Restart into Windows      then restart into Linux

   ^ v  select   Enter  continue   D  Details
```

**Framing matters more than layout here.** Fast Startup makes this the *common*
path — every normal Windows shutdown leaves a hibernation image — so this screen
is routine, not an error. Nothing in it may read as disk trouble, and it must not
say *"Linux cannot start"*. The second option is the route to a writable Linux,
and naming it *"Restart into Linux"* teaches the intended path at the moment it
is relevant.

Same frame, same non-alarming register, for: **dirty bit** (*"Windows didn't shut
down cleanly last time"* — also benign), image missing, image not allocated,
unsupported cipher, conversion in progress — and two more that need their own text because
the action differs:

```text
   Too many incorrect attempts

   The TPM has locked itself for 2 hours to prevent guessing.
   Waiting will restore it -- nothing is damaged.
   Your other unlock options still work.

   Enter   Try another option
   Esc     Other boot options
```

The TPM row is greyed; everything else remains available. This screen must not
offer another TPM attempt, and must not read as a dead end.

```text
   No Linux installation found

   Searched this volume and found no Linux image.

   To fix   Start Windows and run the paguro repair tool
```

Reached when recovery ran and located no image. `Enter` opens the browser below
rather than ending there.

**Locating what to boot by hand: a browser, not a text field.** NTFS paths are
long enough that a typo becomes a support call, and a firmware keyboard types
with a US layout whatever is printed on the keys (§Theme). A lone candidate is
**taken silently**, so most users see none of this.

```text
   Select what to start

   \paguro\

   old\                                   folder
 > debian.vhd                    214 GB   disk
   rescue.efi                    112 MB   UEFI image

   ^ v select   Enter open   <- up   Esc back
```

It starts at `\paguro\` and lists folders first, then disks (`.vhd`, `.vhdx`, `.img`, `.raw`)
and UEFI images. A **disk** becomes the root and the `efi_disk`: the loader finds
its FAT32 by content (the GPT's one ESP, or a superfloppy) and offers its default
`\EFI\BOOT\BOOT<arch>.EFI`, or a second browser over that FAT32 to pick
systemd-boot, a specific UKI or the distribution's shim. A **UEFI image** becomes
the `efi_file`, and the root hint is the only disk in `\paguro\`, a choice among
several, or none — Linux then asks. A typed path is the fallback on both levels.

Both browsers reuse the list primitive. The chosen image still goes through
`LoadImage`, so Secure Boot verifies it exactly as on the normal path — browsing
changes what you point at, never what is allowed to run.

**Configuration is not valid** — deliberately distinct from drift, because the
meaning and the remedy differ. "Refuse" without a route out is what makes people
reach for an editor, so it offers one:

```text
   Configuration is not valid

   paguro.ini has changed since it was installed,
   or is damaged. Linux cannot start from it.

   If you did not change it, this may indicate
   tampering.

   Enter   Start Windows
   R       Recover Linux -- needs a password or key
   D       Details
```

**Recovery looks like everything else**, since the theme is part of the binary
(§Theme).

**Volume selection**, only when recovery finds more than one BitLocker volume:

```text
   Which volume holds your Linux installation?

 > Disk 0, partition 3    931 GB   BitLocker, unlocked
   Disk 1, partition 2    1.8 TB   BitLocker, locked
```

**Picker** — hidden, shown on a keypress during progress. §4.1's no-menu rule is
about not appearing every boot, not about never existing:

```text
   Choose what to start

 > Debian                                default
   Rescue
   Linux (recovery)
   ----------------------------------------------
   Windows Boot Manager
   ----------------------------------------------
   Other boot files
   \EFI\ubuntu\shimx64.efi            ESP, disk 0
   ----------------------------------------------
   Firmware settings
```

The last entry sets `OsIndications` and resets — the only portable way to reach
firmware UI from an EFI application.

The "Linux" rows are the `[Boot.*]` entries of `paguro.ini`, and nothing else:
several kernels, boot counting and rollback are systemd-boot's job behind an
entry (§4.2). Every entry's disks and UEFI image live **inside its NTFS volume**,
read through the unlock — so the configuration cannot redirect the next image to
unencrypted media.

Making paguro the **default** boot entry is opt-in and carries a warning: today a
paguro bug costs Linux, as default it costs booting at all. It also requires Fast
Startup off, since every boot then lands here and §4.1's hibernation gate would
make Linux read-only — §4.6's "Restart bypasses Fast Startup" only helps on the transition
path, which a default-paguro user is not taking.

**Details** — reached with `D`. It reports the **whole chain**, not just the
failure, because the useful question in support is usually *which step stopped*:

```text
   paguro 0.1.0

   Config       [ok] hash matches firmware
   PCR 12       [ok] extended  (load taint)
   TPM          [ok] 2.0 present
   Protectors   tpm (a3f2...)   setupTPM absent
                recovery present
   Unseal       [x] TPM_RC_POLICY_FAIL
                  PCR 4  expected 7a3f...  got 91bc...
   Volume       [ok] C:  BitLocker XTS-AES-256,
                  fully encrypted
   Image        [ok] \linux.vhd   214 GB, 3 extents

   Firmware     American Megatrends 2.22
                Secure Boot  enabled

   Q  show as QR code        Esc  Back
```

The `expected / got` line is what a support person needs, and it distinguishes a
firmware update from tampering.

**`Q` renders it as a QR code.** The loader never writes, so there is no log file
to send — a QR the user photographs solves it with no rule broken and no
transcription errors. It is the difference between a usable bug report and a
blurry photograph of a screen.

### 4.2 The next image — a UKI, systemd-boot, or the distribution's own shim + GRUB

After stage 3 the loader holds the key, and stage 4 turns a disk file inside NTFS
inside BitLocker into the one thing every UEFI boot loader already reads: **a
read-only disk.**

```text
physical BlockIo -> BitLocker decrypt -> NTFS parse
  -> the disk file's extent map (VHD footer stripped)
  -> EFI_BLOCK_IO_PROTOCOL, read-only, own device path
  -> ConnectController: the firmware's own partition
     and FAT drivers bind it
  -> LoadImage(the next image) by device path
```

The next image is whatever the entry names (`efi`, by default the removable-media
path `\EFI\BOOT\BOOT<arch>.EFI`):

| Next image | Works because |
|---|---|
| a UKI | kernel, initrd and command line in one signed PE; it needs nothing but itself |
| systemd-boot | it enumerates `/EFI/Linux` and `/loader/entries` off the `DeviceHandle` it inherits: several kernels, boot counting, rollback, `bootctl set-default`, invisible at `timeout 0` |
| **the distribution's own shim + GRUB** | GRUB's `efidisk` driver uses every `BlockIo` handle, so the image is an ordinary disk to it, and its own ext4/btrfs/LVM/LUKS modules read `/boot` inside it. **No GRUB module of ours** |

**That last row makes stock distribution images bootable unchanged at the
boot-loader level.** Everything above the disk is maintained by the distribution;
paguro supplies the storage and gets out of the way. What a stock image still
needs is one package, `paguro` — the kernel module as DKMS source and the
initramfs hook that reads the handoff and builds the views (§4.3) — because a stock
initramfs cannot find a root inside a VHD inside NTFS on its own.

**The disk is read-only for everyone.** `WriteBlocks` returns
`EFI_WRITE_PROTECTED`, so the loader's never-writes rule holds whoever asks. GRUB's
`save_env` and `recordfail` meet that error; that GRUB carries on regardless is
to be confirmed per distribution (§11 Q27).

*Security footnote, for anyone weighing TPM and Secure Boot:* a UKI's command line
is part of the signed PE, so it cannot be requested at boot, which closes
`init=/bin/sh` and `rd.break`. A GRUB whose menu edits the command line does not.
Under TPM+PIN that costs nothing — whoever reaches the menu has already typed the
PIN — and §6 covers the failure path a UKI does **not** close either. The opt-in
TPM-only profile has no PIN in front, so it requires a UKI (§6).

#### Where the next image lives — a FAT32 inside the disk, or directly on NTFS

Each entry picks one (INTERFACES §3.2):

- **`efi_disk`, the default:** the FAT32 of a disk file, found by content — the
  GPT's one ESP, or a disk that is one bare FAT32. The next image gets a real
  `DeviceHandle`, and the distribution updates its boot loader and kernels inside
  the image whenever it likes.
- **`efi_file`, the secondary mode:** a `.efi` stored as a plain file on NTFS,
  read whole and started with `LoadImage(SourceBuffer)` — **never jumped to**:
  `LoadImage` runs Secure Boot verification, and executing a buffer directly would
  be a Secure Boot bypass. It gives up the `DeviceHandle` (no systemd-stub
  credentials or add-ons, no systemd-boot behind it), and replacing the file needs
  an NTFS write, which Linux makes through view C while the VM is off. Its use is
  images Windows can manage without opening a VHD: the paguro host's UKI, a
  rescue or installer UKI dropped onto C:.

The question worth arguing is why the loader's own reading **stops at FAT32**
rather than reaching the image's ext4 root. BitLocker is neutral between them —
the synthetic `BlockIo` decrypts inside its own `ReadBlocks`, invisibly to whatever
consumes it, and an ext4 parser would read through exactly the same layer. It is
an engineering-cost decision, and it goes three ways for FAT32.

**1. FAT32 costs no filesystem code at all.** The loader already owns every layer
beneath the question, and at the last one it installs a `BlockIo` with a device
path and calls `ConnectController()`. The firmware's **own** partition driver
parses the nested GPT and its **own** FAT driver binds the ESP, yielding a real
`EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, and the next image loads through the stock
`LoadImage()` path. It is the pattern `EFI_RAM_DISK_PROTOCOL` uses — unusable here
only because it wants the whole image resident in RAM. No firmware has an ext4
driver; that route means writing one, on top of a BitLocker reader and an NTFS
reader that are already the two largest components of the application. Where the
image's own boot loader is GRUB, reading ext4 is GRUB's job, maintained by the
distribution that ships it.

**2. UKI tooling assumes a FAT ESP.** `ukify`, `kernel-install`, `bootctl`,
`sbctl` and `dracut --uefi` check for vfat and for partition type GUID
`C12A7328-…`; `bootctl` errors out otherwise. Give the nested GPT a
correctly-typed ESP and all of it works unmodified. On ext4 it is path overrides
and `SYSTEMD_RELAX_ESP_CHECKS=1` in perpetuity, re-fought at each distro upgrade.

**3. ext4 drift is an attested remote-brick failure mode.** ext4 keeps gaining
INCOMPAT flags and read-only bootloader parsers keep dying on them: GRUB vs
`64bit`, vs `metadata_csum_seed` (Fedora 34 machines that would not boot), vs
`orphan_file` (default-on since e2fsprogs 1.47). A routine `tune2fs`, `resize2fs`
or distro upgrade flips a flag and the machine stops booting. GRUB at least has
distro packaging to push a fix through; this would be a signed binary on a
stranger's ESP, behind Secure Boot, on a machine we cannot reach. FAT32 has
gained no features since 1996.

**What ext4 would buy, and why it is defusable:** one filesystem, no sync step
between `/boot` and the root, no "/boot is full". That last pain comes from a
512 MB partition nobody can resize — here the image grows on demand, so a
generous ESP removes it outright.

A FAT driver is mandatory in the UEFI specification, so the one question was
whether firmware binds its drivers to a handle *we* installed rather than one it
enumerated. **OVMF and AAVMF do**: stage 4 publishes the disk and chains through
the firmware's FAT on x86_64 and aarch64 in CI. Real firmware is §11 Q11.

**Three tiers, and the design never depends on the top one:**

| Tier | Cost | Yields | State |
|---|---|---|---|
| 1. `ConnectController()` binds the firmware's partition + FAT drivers | no FS code | real `DeviceHandle`, systemd-boot and shim + GRUB behind it | **built**; binds under OVMF and AAVMF |
| 2. own FAT32 reader + own `SimpleFileSystem` on top | ~500 lines | the same, no firmware dependency | not built: a firmware that does not bind is a **clean refusal** with a *cannot start* screen. The read-only FAT32 directory reader it needs already exists, for the recovery browser |
| 3. `LoadImage()` from a memory buffer | nothing beyond reading the file | boots; no `DeviceHandle` | **built**, as `efi_file` |

`LoadImage()` accepts a `SourceBuffer`, not only a file path, and still verifies
against Secure Boot — it invokes the Security Architectural Protocol regardless of
source, which is how shim-chainloading works. Read-only FAT32 is boot sector →
FAT → cluster chain: no journal, no extent trees, no checksums, no feature flags.

**That asymmetry is the whole argument.** Firmware cooperation is an optimisation,
never a dependency of the design: an `efi_file` boots without it today, and tier 2
removes it for `efi_disk`. ext4 has no equivalent bottom tier — there, the parser
*is* the design.

#### Verifying the next image

**No image hash in the configuration, and no accept-any-signer mode.** The next
image goes through `LoadImage` and is verified like any other EFI image.

**An "accept any signer" mode is not implementable**, which is why none exists:
under Secure Boot, loading an image signed by an unenrolled key means loading and
relocating the PE ourselves — and a signed binary that loads unsigned code **is**
a Secure Boot bypass, the pattern that gets bootloaders revoked through `dbx`.

**Which store verifies which image** (INTERFACES §2.1, §3.2):

| Next image | Verified by |
|---|---|
| the distribution's own shim, then its GRUB and kernel | firmware `LoadImage` against `db` (Microsoft's third-party UEFI CA), then that shim with the distribution's key. paguro, itself started by a shim, `LoadImage`s a second shim: it needs that CA in `db` and a shim that tolerates an existing `SHIM_LOCK` protocol (§11 Q28) |
| a distribution-signed UKI or systemd-boot | the same chain |
| a **locally built** UKI | the machine MOK key, which signs it on every kernel install — so no further enrolment. Firmware `LoadImage` checks `db` only, so `MokList` is reached through shim's `LoadImage` hook in recent shim, or `SHIM_LOCK->Verify()` before loading the PE ourselves (§11 Q29) |

**No image hash either**: the distribution rewrites its boot files on every kernel
update, so a pinned hash would force a reseal per update. Pinning the *location* in
the ratcheted `.ini` is what closes redirection, and the image lives inside the
encrypted volume, where writing it already requires the VMK.

#### Theme — compiled in, extensible at build time

Colours, fonts, images, layout and every string are built into `paguro.efi`. A
theme is a directory — `theme.toml` for colours, sizes and per-screen layout,
PNG images, TTF fonts, one strings file per language — that the build validates
and turns into pre-decoded pixels, pre-rasterised glyphs and a layout table
(INTERFACES §13.1). A theme that fails validation fails the build. **The loader
binary contains no PNG, TOML or font parser**, so it parses no display data an
attacker can author.

That matters more here than it would elsewhere: the TPM measures the bootloader
*binary*, not the data it consumes, so a display-parser bug would be a
**measured-boot bypass** — attacker code running under the identity PCR 4 already
attested, in a process about to receive the volume key. A boot screen is sixteen
screens of text and a colour palette; it is not worth a parser in that position.

**Variants and modes are enums over compiled-in data.** Every build carries `dark`
(the default), `light`, and a high-contrast version of each, cycled with F2;
`paguro.ini`'s `[UI]` section may pick the starting variant and the mode — `auto`
(graphics on every display, the same screens as text on each serial console),
`graphics`, or `text`. Recovery reads no `.ini`, so it starts in `dark` / `auto`.

**Languages:** `en`, `nl`, `de`, `fr` and `es`, all compiled into every build —
Latin fonts are small — with the starting one chosen at install from Windows'
display language and F5 changing it for one boot. The strings table is shared
with the Windows app, so a language is added once for both. Scripts that need
large fonts (CJK runs to megabytes) are what per-region builds are for.

**Keyboard layout matters more than language.** Firmware keyboard drivers report
keys as a US layout would, whatever is printed on them — BitLocker's own pre-boot
PIN has the same limitation. A passphrase set in Windows on a German or French
keyboard would not unlock. `[UI] keyboard` selects a compiled-in remap table from
what the firmware reports (plus Shift and AltGr) to what the chosen layout
produces; the installer takes the layout from Windows' active input language, and
the passphrase screen names it. Dead keys are not supported at boot, so the
Windows app refuses them when the passphrase is set. Recovery starts in `us`, and
F4 changes it.

**Changing the look means shipping a binary**, so PCR 4 moves and every machine
reseals through the repair hook (§7). That is the right discipline rather than a
cost: a cosmetic change to the one screen that asks for the user's passphrase
should be a security-relevant update.

### 4.3 Linux kernel module — the single enforcement point

Runs from the image's own initramfs. It ships in the image's `paguro` package as
**DKMS source**, built on the machine against whatever kernel is installed and
signed with the machine key; the initramfs hook refuses to build an initramfs
without it, so a kernel it cannot build against fails its install loudly and the
previous kernel stays the default (INTERFACES §11.6). **It owns the protected
views and the invariant**, and nothing else — which is what makes the invariant
enforceable and the module small.

#### What the module exposes, and what it does not

Its unit is **a protected view over a block device**, not a disk, a volume or a
partition. Given an underlying device and a set of ranges it must protect, it
exposes:

| View | Contents | Live when |
|---|---|---|
| **A** | one image's extents, gathered contiguous — a Linux root | always, and **one per image** |
| **B** | the volume as **ciphertext**, protected ranges erroring | VM running |
| **C** | the volume as **plaintext**, protected ranges erroring | VM **off** (§5b) |

**B and C are the same device at two layers** and are mutually exclusive. **A is
not singular** — several images can be mapped at once, each with its own range
set, which is what makes multiple distributions on one volume a file each rather
than a partition each (§2).

> **Everything above this is userspace.** The synthetic GPT, which partitions the
> VM is shown, the scratch ESP and MSR, the `dm-crypt` segments — all built with
> stock device-mapper by ordinary tools. The module contributes a block device and
> a comparison.

That boundary is why a **second NTFS volume costs nothing**: it is another
instance of the same thing, and which volumes appear in the guest's synthetic disk
is a userspace policy question rather than a module design decision. Cheap to
allow now, expensive to retrofit into a structure that assumed one.

#### View B is a synthesised disk, not the physical one

Passing the physical disk through with the image's sectors excluded leaves a
hole: **`diskpart` in the guest writes the real GPT.** The image would be
protected; the partition table would not.

Synthesising it closes that structurally — the guest scribbles on our table and
the real one is never touched.

**The module does not build the table**, and does not know what is in it. It
exports a protected block device; stock `dm-linear` concatenates that with
synthetic GPT segments into the disk the guest sees:

```text
/dev/mapper/paguro-vmdisk = dm-linear concat of
   [ primary GPT + 1 MiB align  2048 sectors, scratch ]
   [ synthetic ESP   FAT32 loop image -- BCD lives here ]
   [ MSR             16 MB sparse, loop device ]
   [ C:              the module's exported partition ]
   [ backup GPT      scratch loop device ]
```

That looks like it weakens this defence and does not: **enforcement lives beneath
the partition table.** Guest writes to the GPT segments land on scratch loop
devices; guest writes to C: land on the module's device, where the range test
applies. `diskpart` scribbles on a table made of two
loop devices, and a malformed or hostile GPT changes what the guest *believes*
about the disk without making a single protected write succeed.

So GPT synthesis is **untrusted by construction**, and it costs no new code
anywhere: the bytes are generated once in userspace, and the composition is stock
in-tree `dm-linear`.

*(QEMU cannot compose a GPT over block devices natively — `fat:rw:dir`
synthesizes an MBR for virtual FAT and has no general equivalent — and no other
hypervisor does either. The [device-mapper
sandwich](https://forum.level1techs.com/t/solved-how-to-pass-through-lvm-ntfs-partition-to-windows-kvm/205738)
is the established technique, and it is the better answer anyway — stock kernel
code instead of a userspace assembler.)*

```text
synthetic GPT
  p1  ESP  -- ours. The BCD lives here, and the
             testsigning BCD if sec.12 applies
  p2  MSR  -- empty 16 MB, for fidelity;
             not read at boot
  p3  C:   -- the real volume as ciphertext, the
             image's extents returning EIO
```

**Preserve the C: partition GUID** — the BCD resolves the OS volume by it, so the
synthetic table must carry the real one through or Windows will not find its own
disk. The disk GUID likewise, since Windows records disk identity.

**WinRE is deliberately absent, and that is a safety feature.** *"Reset this PC"*
boots into WinRE to do its work, and a reset performed from inside the VM would
**reinstall Windows over the shared installation** — about the most destructive
thing a user could do from in there. Without the partition the option simply
fails, and recovery happens where it belongs, from a native boot.

Every other partition on the disk — data volumes, OEM recovery — is invisible to
the guest. Less exposure, and nothing there for it to damage.

Offsets become **volume-relative** rather than disk-relative, which shortens the
exclusion arithmetic. The image still lives inside the volume, so its extents are
still in the guest's view and still protected.

**One thing to test:** Windows records disk and volume identity. A *subset*
layout under the real GUIDs may read as "the layout changed" — most likely
nothing happens, but a drive-letter reassignment or `MountedDevices` update would
land in the shared registry.

`A ⊂ C`, which is the source of C's extra rules. Mutual exclusion between B and C
is enforced here rather than by convention, because one component owns both.

**Exclusion means I/O error, not zero-fill.** Reads of A's extents from view B
return `EIO`. Not a gap, and not `dm-zero`.

Zero-fill is the tempting alternative — `chkdsk /r` inside the guest would then
see no unreadable sectors — but that cost is the smaller one, because
**zero-fill is what turns a rejected relocation into a destroyed filesystem**:

```text
defrag allocates targets     allowed -- legitimate free space
copies source clusters       reads view B -> ZEROS
updates MFT runlist          module rejects
crash, dirty volume
native boot, LFS redo        applies the committed transaction
                             the image now points at zeros
```

With `EIO` the sequence never starts. **Windows cannot log an intent to move
clusters it cannot read**, and the reason is an ordering fact rather than a
recovery behaviour:

> `FSCTL_MOVE_FILE` allocates the target, **copies**, and only then rewrites the
> mapping pairs. The runlist record is written *after* the copy succeeds. If the
> copy cannot succeed, **that record never exists.**

Nothing to roll back and nothing to redo — which is a stronger guarantee than
*"the log rolls it back"*, and it does not depend on NTFS recovering correctly
from anything.

The allocation step may still log a `$Bitmap` change that commits. That is
harmless: claiming and later releasing free clusters elsewhere says nothing about
the image's runlist.

§5.7 already depends on these semantics: BitLocker conversion is *"mediated, not
merely detected"* precisely because it **takes I/O errors on excluded ranges** and
cannot complete. One semantics, used consistently.

##### Why the journal cannot be protected instead

The obvious alternative is to stop the replay at its source — refuse the
`$LogFile` writes that would commit the transaction. It does not work, and the
reason is timing rather than difficulty:

> NTFS logs the redo/undo record, modifies the page **in memory**, and commits
> when the commit record flushes. The MFT write the module rejects is the **lazy
> page flush**, which happens long afterwards. By the time there is anything to
> reject, the transaction is already durable.

Filtering proactively would mean an **LFS record parser** — an undocumented
format, in the write path, inside the few hundred lines that must be correct. That
would be the largest addition to the trusted core, to cover a case
that erroring reads close at the source.

##### What erroring reads do not cover

**A write error is a different conversation from a read error.** NTFS's response
to a failing *read* cannot be relocation — it has no data to relocate, and
substituting a fresh cluster would be silent data loss rather than recovery. But a
failing *write* leaves NTFS holding the data in memory, where dynamic bad-cluster
remapping is at least coherent: allocate a replacement, write there, rewrite the
runlist, file the original in `$BadClus`. **No read of the image occurs anywhere
in that sequence**, so nothing above stops it.

Three things bound it, and none of them is certainty:

- **It needs a write into the image**, which nothing legitimate does — and the
  minifilter denies the handle in the first place.
- **The historical remapping behaviour was specified for fault-tolerant volumes**,
  where a mirror supplies good data. On a plain volume a modern NTFS most likely
  fails the write and marks the volume dirty, leaving reallocation to the drive.
- **It is independent of the read-error choice.** Writes into the image are
  refused whatever reads return, so this path is not a consequence of `EIO`.

**This is unverified, and §11 tests it before anything is built.** If NTFS does
remap on write failure, the fix is likely an error *class* rather than more
machinery: NTFS remaps on a device error and does not remap on write-protect, so
returning something in the read-only class may close it outright.

**`chkdsk /r` is the firmer version of the same concern** — it reads every
cluster, cannot read ours, and its remediation is to mark them bad and take them
out of the file. That is a runlist change with no successful read. It is also
explicit, user-initiated, and what the minifilter exists to prevent reaching.

**And a guest writing LFS records directly** never reads the image at all.
`$LogFile` lives in view B, so a compromised Windows can author a committed record
that native recovery replays on a boot where nothing is enforcing.

That case is **detected, not prevented**: the next Linux boot re-derives the map,
the mandatory structural assertion (below) fails on a runlist that moved without
its data, and view A is never created. And that
is the right level for it. A Windows that is hand-authoring NTFS journal
structures is compromised, and the guarantee worth having there is *Linux refuses
to start*, not *Linux is protected* — §6's LUKS tier is the only thing in the
design that claims the latter.

#### One parse, at load, and a range test thereafter

**Blocking *reads* of the image's extents collapses most of this component.** A
guest cannot log an intent to move clusters it cannot copy (§View B), so nothing
legitimate ever attempts to rewrite the image's runlist — which means there is
nothing to watch for at write time.

```text
module load
  1. parse NTFS: locate the image, decode its runlist
         -> ground truth LBA ranges
  2. assert  dirty bit clear
             no hibernation
             no unreplayed journal
             allocated size == sum(extent lengths)
  3. any assertion fails -> read-only, or refuse
  4. export the ranges

runtime
  read  intersecting the set -> EIO
  write intersecting the set -> EIO
  everything else            -> pass through
```

> **That is the whole enforcement path: a range test.** No NTFS parsing on
> I/O — only at claim and at each growth event, where the module re-derives
> the extents itself (§5.6) — no `$Bitmap` tracking, no re-decoding the runlist on writes — and
> therefore **no cryptography in the module at all**, since decrypt-to-inspect
> existed only to read metadata it no longer inspects.

**This is why enforcement lives here and not in QEMU or a minifilter.** A
minifilter sees the operations it registers for on the filesystem stack. A block
device sees **every access, with no path around it** — the difference between
*"we have not established that our layer can mediate this"* and *complete
mediation by construction*.

##### Why the metadata watch is unnecessary

A metadata watch — re-decoding the runlist and checking `$Bitmap` on every write
— looks necessary and is not. With reads erroring, the operations that could
still change the allocation are only **unlink and truncate**, which need no read —
and which no legitimate Windows service performs, because they are deliberate
data loss.

**And deletion is survivable anyway, because the module gates LBAs and not
files.** It does not know the image exists:

```text
clusters freed in $Bitmap
Windows allocates them to some new file
Windows writes   -> REJECTED, still in the range set
```

The new file fails; **the image's data is never overwritten.** At the next Linux
boot the map does not resolve and Linux declines to start, with every cluster
intact — ordinary undelete territory. A `$Bitmap` watch would protect metadata
consistency, which matters for Windows' health rather than for Linux's data.

##### Nothing in userspace can supply the map

The module reads the disk itself. There is no ioctl that accepts ranges, and this
is the property the trust model rests on.

The kernel's own **`ntfs3`** still provides a second opinion, sequenced so it can
never become an input:

```text
module parses, exports view C only
userspace mounts C read-only (recovery suppressed),
    FIEMAPs the image, feeds the result back
        as a CLAIM TO BE CHECKED
module compares against its own derivation
    agree    -> export view A
    disagree -> refuse. no view A, ever
```

> **Userspace input can only subtract, never add.** Two independent
> implementations must fail identically to get through, and a compromised
> userspace can cause a refusal and nothing else.

That matters because a *derivation* bug is a different failure from Windows
moving the file: a misparsed delta-encoded offset can name sectors NTFS
legitimately allocated elsewhere, and no amount of protecting the image helps.
Checking before view A exists means a wrong map produces *"Linux does not boot"*,
never *"Linux wrote into Windows' files"*.

##### Ambiguous map means read-only, never read-write

A pending journal entry means the on-disk runlist may not be final. The **old**
runlist still points at the live data, so reading is safe — writing is not:
writes would land on clusters a later redo may detach from the file, and they
would be silently lost.

So dirty bit, hibernation or unreplayed journal all degrade to **read-only**. No
writes lost, nothing corrupted, and the remedy is a reboot into Windows to let
NTFS settle.

##### The remaining parser, and its discipline

One NTFS parse, at load, on structures an untrusted guest may have written. It
deserves the same treatment as the FVE parser (§6) — decode one runlist from a
known record, fixed bounds, no allocation derived from content, reject rather
than tolerate. Roughly 100 lines, run **once**, before anything is exported,
rather than on every write.

#### How the views are built: decrypt once, gate at whichever layer is exposed

The volume is decrypted **once**, by `dm-crypt`, with the segment layout
BitLocker's own format dictates. Everything else is a range test applied above or
below that.

```text
raw partition
  |
  +-- [range test] --> view B    ciphertext to the guest;
  |                              image extents EIO
  |                              (FVE regions substituted
  |                              above, in the sandwich)
  |
  +-- dm-crypt --> decrypted volume
                     |
                     +-- [range test] --> view C   NTFS mount
                     |
                     +-- gather -------> view A   Linux root
```

**B and C are mutually exclusive, so exactly one range test is live at a time** —
below the cipher while the guest holds the volume, above it while Linux mounts
NTFS. View A's gather is always live, since it is the root device, and is bounded
separately (below).

##### The decrypted volume is a handful of segments, not one target

A BitLocker volume cannot be covered by a single `crypt` target, because parts of
it are **not ciphertext**:

| Segment | Target |
|---|---|
| the first sectors (`[0, reloc_len)`) | `crypt` over the **relocated copy**, with `iv_offset` = the relocated sector — the copy is ciphertext, tweaked by where it physically lives |
| the relocated copy's own home | `zero` |
| the three FVE metadata regions, and Windows 10+'s extra region | `zero` — never decrypted |
| the data areas up to `encrypted_size` | `crypt`, physical-sector tweaks |
| beyond `encrypted_size` (a paused conversion) | `linear` — still plaintext on disk |

On 4 KiB-sector volumes every `crypt` segment carries `sector_size:4096
iv_large_sectors`, with `iv_offset` still counted in 512-byte sectors. The
`encrypted_size` boundary can fall inside any of these, so the builder splits
segments there. The table is tested unit for unit against the loader's own
decrypted-view map (`paguro-core::bde`), and the FVEK reaches dm-crypt through a
kernel `logon` key that is invalidated once the table loads — it never appears
in a table line.

That is the table `cryptsetup bitlk` builds, and its size is fixed by BitLocker's
layout rather than by how fragmented anything is. **O(1) segments regardless of
the image's extent count**, which is the property that matters.

**The layout costs nothing extra to obtain.** Recovering the FVEK already required
parsing FVE metadata (§6), and that parse yields the region offsets and the
relocation. Building this table is a by-product of work the design does anyway.

**No conflict with the guest.** View B's metadata substitution is a range redirect
on the **ciphertext** side, serving a static buffer to a guest that does its own
crypto. View C's segments are on the **plaintext** side. They never meet.

##### Why not one crypt target per extent

The alternative — `dm-crypt` directly over the image's extents, one target each
with its own `iv_offset` — is mechanically correct: `dm-crypt` computes the tweak
as `iv_offset + (sector − target_start)`, so per-target offsets do yield
physical-sector tweaks across a fragmented file.

It does not scale. **Every target instantiates a full `crypt_config`** — cipher
transforms per CPU, its own `page_pool` and request mempools, two workqueues, and
a `dmcrypt_write` kthread. At fifty extents that is noise; at several thousand it
is thousands of kthreads and reserved mempools, and a table load that repeats
per-CPU key setup once per target. An image grown incrementally on an aged volume
gets there.

Decrypting the volume once and **gathering** the extents above the cipher avoids
the whole question: the crypt layer never learns that the image is fragmented.

##### One origin constant, in one place

BitLocker's IV sector is relative to the **encrypted region's origin**, not to the
block device's start. In the per-extent design that constant appeared on every
target, and a mapping could be right while the tweaks were wrong — a silent
failure, since XTS produces output for any tweak. Here it appears **once**, in the
segment table, which is the same place `cryptsetup bitlk` puts it.

Prove it anyway:

> **Mandatory post-construction assertion.** The module checks view A's content
> immediately after the stack is built, **before anything mounts**, and reads
> **past the first extent**, because extents gathered in the wrong order must fail
> too. What it checks follows the content (INTERFACES §3.2): for a GPT, the
> primary header's CRC, the backup header at the last LBA and each partition's
> first-sector signature where known; for a bare ext4, the superblock magic and
> the backup superblock in block group 1 agreeing on UUID and block count; for
> ISO 9660, the primary volume descriptor and a volume size equal to the payload.
> A wrong origin, a wrong relocation or a wrong order all fail it.

An assertion, not a unit test — a mis-derived map must not be able to reach a
filesystem. Same posture as refusing on disagreement between the three FVE
metadata copies rather than picking one.

**And it is what makes re-deriving the map at every boot safe** (§3). A
relocation performed by native Windows copied the data with it, so the
structures are where they belong and the fresh map is correct. A runlist that
changed *without* the data moving fails the assertion, and Linux declines to
start rather than mounting whatever is now there.

##### The module holds no key and runs no cipher

Gating is a range test on LBAs, which needs no plaintext. The one NTFS parse
happens at load, through the decrypted volume the initrd has already built —
after which the module has no reason to hold a key and does not.

> **No cipher, no key, nothing in the request path but a comparison.**

##### The gather is where containment lives

View A is the image's extents, gathered from the decrypted volume into a
contiguous device. **It is bounded by construction**: it maps only the verified
extents, and every request is translated through that table and refused if it
falls outside it — the same comparison, applied the other way round. (The range
test that bounds `ntfs3` on view C would refuse *all* of view A's traffic, which
is exactly why view A has its own.)

> **This is neither file encryption nor ordinary volume encryption.** It is the
> volume's cipher, at the volume's sector numbering, with the file's extents
> selected out by the gather. Nothing here invents a key or a tweak schedule; it
> reproduces BitLocker's, exactly, or it refuses.

#### Views B and C carry identical protections

Worth stating because the naming invites the opposite assumption — view C is "for
Linux", so it sounds like the safe one.

It is not. **`ntfs3` mounting read-write is exactly as capable of allocating over
the image's clusters as Windows is**, and a Linux-side defragment or repair pass
is exactly as capable of relocating the file. So C carries the same range test as
B — the same extents, the same `EIO` on read and write.

The only asymmetry is the layer: B is gated on the **ciphertext** side so the
guest does its own crypto and sees itself truthfully as encrypted (§6); C is gated
on the **plaintext** side so Linux can mount the filesystem. **The protection is
identical; only where it sits differs.**

#### What this makes unnecessary

If relocation cannot happen there is nothing to buffer against it: **no overlay,
no operation log, no replay, no commit point.** Guest writes are live from the
first one, no session can be discarded, and enforcement never needs the guest's
cooperation.

**QEMU is not trusted.** It is handed view B and can do nothing outside it.
A QEMU bug is no longer a corruption vector, which removes a very large body of
code from the trusted computing base.

#### The Windows driver's role is unchanged by any of this

| Layer | Responsible for |
|---|---|
| Windows minifilter (§4.4) | **that Windows boots and behaves well** — defrag skips the file cleanly rather than taking an I/O error on it |
| this module | **that the disk survives** — erroring reads and rejected writes, with or without the minifilter present |

**Correctness lives here and nowhere else.** The journal hazard above might look
like it promotes the minifilter to a safety component — prevent the *attempt*,
since a committed transaction can be replayed where we are absent. It does not,
because **erroring reads already prevent the attempt from producing a record**.
The chain only existed while exclusion served zeros.

That matters beyond this one case: a design in which the guest must cooperate for
the host's data to survive is one where unloading a driver is a corruption
primitive. The minifilter can be absent, stale, or defeated, and the guarantee is
the same.

##### The worst case, stated concretely

> **The image orphaned into `found.000`, with its contents intact.**

A damaged directory entry is something `chkdsk` repairs by relinking the file
rather than by rewriting it, so the runlist and the clusters survive. The user
loses the *path*, not the data, and recovery is moving one file back and pointing
`paguro.ini` at it.

Anything worse than that — a runlist that changes, clusters freed under a live
mapping, contents replaced — is a **defect, not a degraded mode**, and §11 Q1-Q3 are
the test that decides whether the design reaches this bound.

**Every corruption risk becomes a crash risk.** That also softens §11 Q17: if
attestation signing turns out unavailable, the fallback costs user experience
rather than safety.

#### Read-only degradation

**NTFS health gates Linux writability.** If the volume is dirty, hibernated, or
has an unreplayed journal, the views are built read-only. (A failed map
derivation, an `ntfs3` disagreement or a failed structural assertion is different:
there is then **no view A at all**, §4.3.)

| View | When NTFS needs repair |
|---|---|
| **A** — Linux root | **read-only** |
| **C** — Windows volume for Linux to mount | **read-only** |
| **B** — the Windows VM | **not offered** |

**The VM is not the repair path.** Booting Linux read-only, starting the VM and
letting Windows run `chkdsk` does not work, because **repairing NTFS can require
moving files, including the image**, and the
module refuses exactly those writes. The repair tool and the enforcement layer
would be in direct conflict, producing a repair that cannot complete and may be
retried every boot. View B would also have to be writable, putting `autochk`
into the same conflict.

```text
NTFS needs repair
  -> Linux boots read-only   (retrieve your files)
  -> no VM
  -> advice: reboot into Windows
```

**Repair happens under native Windows, and is safe there for the reason the
whole design turns on:** nothing is running that depends on the image's LBAs,
so moving it is free. paguro simply is not in the way. The next Linux boot
derives a fresh map.

The loader's message says the same thing, so the advice does not change depending
on where the user reads it.

**Enforce it as a read-only *device*, not a read-only *mount*.** ext4 replays its
journal under `ro` unless `noload` is given, and a mount option is convention
where a `dm` target is enforcement.

It also fixes the ordering: **you cannot `fsck` the inner filesystem until the
outer one is clean.** Repair in containment order.

**The failure path should not drop to a shell — but the PIN is what makes this
safe, not the audit.** The PIN is entered *before* the unseal, so an attacker who
induces a disk-construction failure cannot reach a shell at all, and that is
enforced by the TPM rather than by discipline. *"No code path in this initrd ever
drops to a shell"* is a property that erodes silently across distro updates.

So with a PIN this is **not** required, and §The TPM-only profile argues it should
be actively avoided: the shell sits *behind* the PIN, which makes it a repair tool
for the legitimate user rather than a hole. It becomes an obligation only in the
opt-in TPM-only configuration, where nothing is in front of it.

#### Residual

**`$LogFile` does not roll a rejected change back — LFS redo rolls committed
transactions *forward*.** A rejected write leaves the on-disk page at an older LSN
than its log record, which is exactly the condition under which recovery reapplies
it, on a native boot with nothing enforcing. That is why reads return `EIO`: a
relocation's runlist record is never written, because the copy it follows fails.

What remains is a write rejected after its transaction committed for some other
reason. The bound there is the structural assertion at the next Linux boot: view A
is never created, and the worst outcome is the image orphaned but intact. *"NTFS
recovers cleanly"* is still an empirical claim, tested in §11 Q3.

Linux's *own* derivation of the map being wrong is a separate failure, covered by
the `ntfs3` cross-check (§11 Q4).

### 4.4 Windows-side driver — kernel mode, mandatory

**A minifilter. There is no user-mode variant**, because clean refusals must cover
the whole session — including volume dismount and shutdown — which a user-mode
process cannot guarantee (§5.1).

**Its role is quality of experience, not correctness** — §4.3 enforces the
invariant at the block layer regardless of whether this driver is present or
working. What it adds is that Windows gets a *clean skip* instead of a surprise
I/O failure and a half-written metadata change:

- **refuse to unload** (`FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP`,
  `STATUS_FLT_DO_NOT_DETACH`) for the life of the session
- **hold the protected handle** with `MARK_HANDLE_PROTECT_CLUSTERS`, so defrag
  skips the image instead of meeting `EIO`
- **refuse access to the image files themselves**, not only their clusters:
  opens by path or by file ID from anything but the paguro service, delete,
  rename, hard links, size and allocation changes, non-paging writes, and the
  FSCTLs that would move, sparsify, compress, trim or duplicate their extents.
  Nothing in the guest — an indexer, antivirus, backup, a user double-clicking
  the `.vhd` — ever reads those sectors and meets `EIO`; it gets a clean
  *access denied* instead. This also blocks `rm /mnt/c/linux.vhd` over SMB
  (§5b), a path sector exclusion never touches, since it travels through
  Windows' filesystem layer
- **reject incompatible volume-wide transformations** cleanly (§5.7), so the
  conversion never starts rather than failing partway against rejected writes

The three FSCTLs themselves are user-mode-accessible (`FSCTL_GET_RETRIEVAL_POINTERS`,
`FSCTL_MARK_HANDLE` + `MARK_HANDLE_PROTECT_CLUSTERS`, both needing
`SE_MANAGE_VOLUME_NAME`), so privilege was never the reason for kernel mode —
lifetime is.

**Load boot-start, and abort the VM if it does not load.**

`FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP` is stronger than it sounds:
Microsoft documents that with it set, **mandatory unload requests fail and the
`FilterUnloadCallback` is not even called**. Non-mandatory unloads are separately
refused with `STATUS_FLT_DO_NOT_DETACH`. So the driver genuinely cannot be
unloaded — but two paths still need explicit handling: **instance teardown on
volume dismount** (a different mechanism; the filter stays loaded while losing
its instance) and **shutdown**. Neither is a correctness hole any more — losing
the driver means Windows stops getting clean errors, not that the disk becomes
writable outside its ranges.

Boot-start still matters — the earlier the driver attaches, the fewer operations
Windows attempts that the module has to reject messily — with one ordering
caveat: **the pin cannot happen at `DriverEntry`**, because the filter manager
attaches the instance when C: mounts. Pin, verify, then report; pinning needs no
host channel, so nothing early depends on virtio being up.

#### Until the driver arms: the tripwire

Before the driver has its protections in place, a refusal must not reach
Windows at all. §11 Q1's measurement is why: a boot-time `chkdsk /r` (autochk,
which runs before any driver loads) read the image's clusters, got the
refusal, and set out to *"replace bad clusters"* in `linux.img`. That would
move them into `$BadClus` and point the file at fresh clusters, through MFT
writes view B allows. So until the driver arms, the first refused request
stops the VM **before Windows can see it**:

```text
launcher   QEMU started paused (-S)
           dmsetup message <view B> 0 tripwire <QEMU pid>
           cont
guest      ... a request touching a claim, before arming
module     SIGKILL to QEMU; an interrupt on every CPU, waited for;
           only then the request is failed
           (no QEMU thread can run another user or guest instruction by
           then, so nothing reads the error)
driver     protections in place -> asks to be armed (agent port)
launcher   tripwire off -> {"type":"armed","ok":true}
driver     armed only on that ack; from now on refusals are EIO, as ever
```

- **Every boot starts under the tripwire.** `-action reboot=shutdown`: a guest
  reboot ends QEMU, and the launcher starts the next one paused and sets the
  tripwire before it runs. That is also how every boot gets the `.BEK`
  stick again.
- **It is set by name, in the kernel, and kills synchronously.** No userspace
  hop sits in the disk path. There is no timeout on the driver either: a
  Windows without the driver runs, and only an access to the image stops it.
- **The driver loads before any channel to the host exists** (boot-start,
  attached when C: mounts). So what depends on the host's ack is its *armed*
  state, not its load. Until the ack arrives the tripwire stays on, which is
  the safe side.
- **When it fires, the user is told why:** *"Windows read or wrote the Linux
  image before paguro's driver had armed … usually a disk check scheduled in
  Windows: start Windows natively once to let it finish there, where it is
  harmless."* The launcher also writes `tripped.json` for the front ends. A
  scheduled `/r` would otherwise stop every VM boot at the same point.
- **Risk to verify on real machines:** third-party antivirus with boot-time
  scanners reading files before the driver attaches would stop every VM boot.
  The message makes it obvious, and native boot is unaffected.
- **Measured end to end (2026-09-26, `test/vm/split-e2e.sh` with
  `PAGURO_Q1_CHKDSK=1`):** `chkdsk C: /r` scheduled in the session, then a
  reboot. The new QEMU was started paused and the tripwire set. autochk's
  first read of the image stopped it, and Windows was told of no refusal in
  that boot (0 I/O errors reported). Afterwards the image's extents, its NTFS
  map and every protected sector were unchanged.
- **Side effect: one Automatic Repair screen.** A VM stopped *while Windows
  boots* leaves a failed boot recorded on C:, which the VM and native Windows
  share. So the next boot, native or VM, opens Automatic Repair. Its log
  reports "Number of root causes = 0", and **Continue** boots normally (native
  Windows up in 65 s, volume clean, image unchanged). The launcher's message
  says so. Stopping a Windows that has *finished* booting records nothing
  (the Q3 kill runs).
- **Prevention, so users rarely meet it:** in a VM session the paguro service
  refuses to let a bad-sector scan of C: be scheduled. It watches the
  `BootExecute` autochk entry and the dirty bit for `/r`/`/b` on C:, removes
  them, and tells the user to run the check natively, where it is harmless.
  The tripwire stays the safety net for whatever else reads the image early.

*Cost:* this makes the driver a hard dependency for the VM to run at all. A
Windows update that blocks or breaks it means no VM until fixed, so §7 must treat
driver load failure as a first-class condition with a real remediation path, not
a log line.

**On a native boot the driver is present and inert.** The VM and the native boot
share one Windows installation, and so one service configuration: whatever loads
in the VM is also configured to load natively. The driver therefore decides at
`DriverEntry` which boot it is in, from a marker only the paguro VM carries — an
SMBIOS type 11 OEM string that QEMU sets (`-smbios type=11,value=paguro-vm/1`),
read with `ExGetSystemFirmwareTable('RSMB')`:

| Boot | Driver |
|---|---|
| paguro VM | registers the filter, refuses unload, pins and protects as above |
| native | **registers nothing**: no filter, no instances, no port. `DriverEntry` returns success with an unload routine, so it can be stopped and unloaded like any legacy driver, and it never touches I/O |
| native, test-signed build | does not load at all: test signing is on only in the VM's synthetic ESP (§12), so Code Integrity refuses it — one event-log entry per boot, nothing else |

Natively there is nothing to protect: Linux is not running, and anything
native Windows does to an image — defrag moving it included — is harmless,
because the next Linux boot re-derives the map (§3). A forged marker on a native
boot only switches clean refusals on for the image files, which costs nothing.

**Signing.** Attestation signing (§11) is preferred: it loads under Secure Boot
and HVCI, creates an ordinary DriverStore entry, and does not move the machine
between §8's EDR tiers. Failing that, §12's synthetic ESP scopes test-signing to
VM boots — workable, at the cost of the tier. Note the hardware-ID PnP trick in
§12 does **not** apply here: minifilters are primitive drivers, not device-bound,
so their load lifecycle needs its own design rather than an inherited one.

The driver is not proof of privilege over the guest — the host owns the
hypervisor, guest RAM and the virtual disk, and is strictly more privileged by
construction. What it adds is *clean in-guest refusals across the session* — a
quality-of-experience property, since §4.3 holds with or without it.

### 4.5 QEMU integration

- presents the **synthesised disk** (§4.3): scratch GPT, synthetic ESP, MSR, and
  view B — C: as ciphertext with the image's extents returning `EIO`
- presents the **`.BEK` on a synthetic removable**, hot-unplugged after boot, and
  the substituted FVE metadata through view B (§6 The VM boot)
- presents a **virtio device** as the driver's confirmation channel
- presents **no TPM** (§6)
- presents **the host's identity, so Windows stays activated without a
  watermark** (§1b, §11 Q32), by default:
  - the host's **whole SMBIOS table** (`/sys/firmware/dmi/tables/DMI` →
    `-smbios file=…`), with paguro's type-11 marker appended — the same
    manufacturer, model, board, serial and system UUID the native boot sees,
    **and QEMU's own `-uuid` set to that same UUID**: community reports on OEM
    licences find Windows checks the UUID, and a VM whose type-1 UUID differs
    from the machine UUID (libvirt's `smbios mode='host'` alone) does not stay
    activated;
  - the firmware's licence tables: **MSDM** (the OEM key, `-acpitable
    file=/sys/firmware/acpi/tables/MSDM`) and **SLIC** where present;
  - **`-cpu host`**, the real CPU model and features;
  - the system disk's **serial number** on the virtual disk, and the host
    network adapter's **MAC address** on the VM's NAT adapter (never a bridged
    one, where the duplicate MAC would clash on the LAN).
  The hypervisor CPUID bit stays set (§11 Q32).
- configures `werror=report,rerror=report`, so `EIO` reaches the guest as an
  error rather than pausing the VM (§11 Q8)
- **stops the VM** if no driver has reported within ~60 s (§4.4) — a
  quality-of-experience gate, since §4.3 enforces regardless

#### Memory: giving Windows' unused RAM back to Linux (later)

The Windows VM should behave like WSL2 in reverse — hold memory while it uses
it, return it when it does not — without Windows seeing a balloon eat its RAM.
The pieces, cheapest first:

1. **Discarded guest memory costs nothing already.** KVM guest RAM is ordinary
   anonymous memory in QEMU: once a range is discarded (`MADV_DONTNEED`), reads
   map the shared zero page and the first write allocates a fresh page — for the
   guest's own writes through the EPT and for QEMU's DMA alike. No custom KVM
   code is needed for the "read-only zero page, allocate on write" behaviour.
2. **Getting Windows' free memory discarded**: free-page reporting through the
   virtio balloon where the Windows driver supports it; otherwise KSM with
   `use_zero_pages`, which merges the pages Windows' zero-page thread has
   already cleared.
3. **Windows' standby list is the real prize** — SysMain and the cache fill RAM
   with reclaimable pages. Under host memory pressure (PSI), the guest agent asks
   Windows to purge its standby list (the documented-in-practice
   `SystemMemoryListInformation` call RAMMap uses); the freed pages are zeroed
   and returned by (2). Windows keeps its cache whenever the host is not short.
   **Graded, not all at once**: the same call can purge only the
   *low-priority* standby pages (prefetched and least recently useful) first,
   and the whole list only if pressure continues — the nearest thing to cache
   ballooning Windows offers, since its cache is invisible to a plain balloon;
   `SetSystemFileCacheSize` can additionally cap the cache while the host stays
   tight.
4. **The balloon** stays the last resort, and host memory limits (a cgroup for
   the VM) keep the worst case bounded.

**One pool for both systems: lent memory may only hold cache; given memory is
ballooned.** Under one kernel, memory has three states — used, free, and
*cache*, which anyone may reclaim at once. A VM boundary loses the third: when
a guest touches a page it had reported free, the host must produce a page on
the spot, and if it cannot, the guest stalls and, in the end, is killed with
its QEMU process. The rule that restores the guarantee:

| Memory the guest… | Host may use it for | Guest touches it again |
|---|---|---|
| **reported free** (free-page reporting, or KSM's zero pages for Windows) | **clean page cache only** | the host drops cache — always possible, no I/O |
| **gave up through the balloon** | anything, including process memory | cannot: it is the balloon's until deflated |

**Enforced by accounting, not per page.** Linux cannot tag individual pages
"cache only", and does not need to: it is enough that the host's
non-reclaimable memory (process memory, unreclaimable kernel memory, dirty
pages) never exceeds

    RAM − the VM's size + what the balloon holds

because then at every moment there is at least as much clean, droppable cache
as memory the guest could take back. A host daemon keeps it so: it applies
`memory.high` to Linux's own workloads before the bound, and when Linux needs
more working memory it **inflates the balloon** instead — which raises the
bound by exactly what the guest gave up. Dirty memory is bounded
(`vm.dirty_bytes`) so reclaim never waits on writeback. Swap and an
`oom_score_adj` of −1000 for QEMU remain the backstop for anything the
accounting misses; the guest is never the OOM victim.

**For a Windows guest**, whose balloon consumes its standby cache first, the
guest agent reports the standby size so the host knows how much it can take
through the balloon cheaply; free pages Windows zeroes come back through KSM.
What stays out of reach is one shared cache for files (virtio-fs without DAX on
Windows), so file data may be cached on both sides.

### 4.6 Windows-side transition app

A "**Restart into Linux**" action that:

1. sets a one-shot next-boot entry (`BootNext` EFI variable, or
   `bcdedit /set {fwbootmgr} bootsequence`)
2. issues a **restart**

**Restart always performs a full shutdown, regardless of Fast Startup.** This is
why the design does not disable Fast Startup — the transition path produces a
clean volume every time, and the user keeps the feature for daily use.

Mirror on the Linux side: a "Reboot into Windows" that sets `BootNext`, so
neither direction requires a firmware menu.

**And no PIN prompt on the way in.** The user is logged into Windows, so the
transition also writes `tpm_pin_bypass_seal.bin` — a TPM-clock-bound seal that
lets the next boot unlock without asking (§6 The PIN bypass).

#### The pre-flight check — the reason this beats a boot menu

Before setting `BootNext`, the app verifies everything the next boot depends on,
**repairs what it can and prompts for what it cannot**:

```text
shim, MokManager and paguro.efi in \EFI\paguro\,
  hashes match install; shim not revoked by SBAT/dbx
Boot#### entry exists and is well-formed
paguro.ini present; PaguroConfigHash matches it
  (its absence means NVRAM was cleared, and
  PaguroB -- unreadable from any OS -- with it)
the entry's disk files present, fixed VHD or raw,
  not sparse/compressed
the machine MOK key in MokList
PCR 0/2/7 match the last Linux boot   <- see below
```

> **This moves diagnosis from the worst environment to the best one.** A boot
> menu tells you something is broken *at boot* — minimal shell, no network, no
> browser, no tools, and a user who now needs another computer and a USB stick.
> The same fault surfaces here in a full Windows session, before anything has
> failed, with a button that fixes it.

**And it is self-healing rather than a recovery mode.** Feature updates run
`bcdboot`, which rewrites the ESP and can demote or remove our entry (§7). Because
the transition *creates the entry and sets `BootNext` as its normal operation*, a
wiped boot order is repaired by the thing the user was doing anyway. A boot-menu
design cannot do this: a wiped menu is precisely when the tool that would fix it
is unreachable.

**Nothing here needs external media.** That is the property dual-boot users
actually fear losing — every article in §1a that describes a broken bootloader
describes a live-USB rescue session. Windows always boots, so the repair always
has a desktop to run on.

#### Predicting a TPM failure instead of discovering one

**PCRs 0 and 2 are extended by firmware before any OS loader runs**, so they hold
identical values in both boot paths. Linux records them each boot (§6) to a file
on NTFS; Windows reads the current values through TBS and compares.

**PCR 7 is not path-independent, and comparing its value directly does not work.**
It receives an `EV_EFI_VARIABLE_AUTHORITY` event naming the certificate that
verified each loaded image — the Windows Production PCA on one path, the Microsoft
UEFI CA and the MOK on ours. A raw `PCR_Read` from a booted Windows therefore never
equals what `paguro.efi` recorded, and a pre-flight built on that comparison would
report permanent mismatch.

**So compare the event log, not the register.** The `EV_EFI_VARIABLE_DRIVER_CONFIG`
entries — `PK`, `KEK`, `db`, `dbx` — *are* path-independent; only the trailing
authority events differ. Reading the TCG log through TBS and comparing that prefix
predicts the case that actually matters, because `dbx` updates are §7's routine
cause of seal breakage.

| Signal | Predictable from Windows? |
|---|---|
| PCR 0, 2 | **yes** — firmware-extended, path-independent |
| PCR 7 | **not by value.** Compare the event log's variable-config prefix instead |
| PCR 12 | **yes** — computed from `paguro.ini`, which Windows can hash |
| PCR 4 | not directly — but it only moves if shim or `paguro.efi` changed, both of which the pre-flight checks by hash |

**Dropping PCR 7 from the pre-flight entirely is a valid simplification**, at the
cost of not predicting `dbx` updates — the most frequent cause. What Linux recorded
remains ground truth either way; Windows is only guessing ahead of it.

So a `dbx` update, a firmware update or a MOK enrolment is detected **before** the
reboot, and the app stages a one-shot `setupTPM` with a PIN prompt in Windows
rather than letting the user meet a failed unseal in the bootloader.

> **The recorded file is advisory, never authoritative.** It lives on NTFS where
> anything on Windows can edit it. That is acceptable because PCR values are not
> secret and the worst a forged mismatch achieves is a `setupTPM` staging, which
> still requires the PIN. It must never be an *input* to a security decision —
> only to a prediction.

#### The TPM-failure handshake, from the other direction

When the loader does reach a failed unseal — a firmware change between the
pre-flight and the boot, or a user who booted from the firmware menu — it sets a
runtime EFI variable and says so on screen:

```text
paguro.efi   unseal fails its policy -> set
             PaguroTpmBroken, offer "Start Windows"
Windows app  sees the flag, explains what changed,
             prompts for the PIN, stages setupTPM,
             clears the flag, reboots
next boot    comes up on setupTPM, re-seals, deletes it
```

**The flag means "the standing seal no longer matches this machine"**, and
whoever makes it match again clears it (INTERFACES §5): the Windows tool when it
stages `setupTPM`; the initrd after a boot on another rung has re-sealed against
this boot's PCR values; the loader when a TPM unlock succeeds **and its key opens
the volume** — a successful unseal alone is not enough. A merely successful boot
clears nothing, and a failed `setupTPM` boot sets it again. The loader reads it
before writing, so an ordinary boot writes nothing to NVRAM.

**Every other rung stays available throughout** — the optional passphrase
protector and the volume's own recovery key are untouched by a TPM fault, so this
is the *convenient* path rather than the only one (§6, Unlocking: escalation, not
selection).

**Entry points in Windows, and what is actually possible:**

| Surface | Feasible? |
|---|---|
| Start menu / desktop / taskbar shortcut | Yes — ordinary shortcut plus the elevated helper below |
| Shift+Restart → "Use a device" | **Works today, zero code.** WinRE lists firmware boot entries and ours is one. Reachable from the lock screen. |
| Power flyout (Shut down / Restart / Sleep) | No supported extension point |
| Lock screen tile | Only via a **custom credential provider** — a genuine extension point, but a COM DLL loaded into LogonUI where a crash bricks the logon screen. High risk for a convenience feature. |

**It needs admin.** Setting EFI variables requires `SE_SYSTEM_ENVIRONMENT_NAME`,
so a shortcut launched as a normal user cannot do it — a small elevated service
that the UI signals.

**Linux stays reachable without logging into Windows.** Because install creates a
real `Boot####` entry, the firmware boot menu lists it; that boot uses the
standing seal and asks for the PIN. There is no hard dependency on reaching a
Windows desktop first (§6 A standing seal).

### 4.7 Identity sync and session broker

One userspace script on the Linux side. Windows is the **system of record**; the
sync is one-way.

**Key on the SID, never the username.** Windows accounts can be renamed while
the SID is stable, and a username-keyed sync reads a rename as delete-then-create
— orphaning or locking out a live Linux home directory. Windows names also carry
spaces, uppercase and unicode, and Microsoft-account users get a truncated
5-character local name unrelated to their display name. So the mapping is
`SID → uid`, recorded in a file, with sanitisation and a collision policy for the
derived Linux username. Allocate uids from a private range (5000+) to stay clear
of distro allocations.

| Windows event | Linux action |
|---|---|
| account created | create user, allocate uid, record SID |
| account renamed | rename Linux user, **home directory untouched** |
| account deleted | **lock the account. Never delete data.** |
| password changed | re-prompt for the SMB/RDP credential |

**Lock, never delete — and the justification matters.** Deleting a Windows
account does not delete its profile directory either, so locking is *parity with
Windows' own behaviour*, the same principle §6 applies to encryption. It is also
the only reversible option: "clean up the orphaned home" is exactly the tidiness
feature someone adds later, and a sync script will eventually misread the account
list during a transient failure and fire it on a false positive.

**Credentials.** The Windows session auto-unlocks to the logged-in Linux user, so
a per-user secret must be stored somewhere. It goes in the **keyring, unlocked by
the Linux login password via PAM** — not in a config file. WinApps' default is
plaintext in `~/.config/winapps/winapps.conf`; copying that would make the Linux
path weaker than the Windows one, which §6 forbids. Provision a generated
per-user credential rather than reusing the user's real Windows password.

**One interactive session, total.** Windows client SKUs permit a single
interactive session — connecting over RDP disconnects the console session. This
design is therefore single-user-at-a-time by construction, and two Linux users
with fast user switching will fight over the VM. Consistent with the
personal-device scope in §8, but it is a declared limit, not an oversight.

---

## 5. The ownership protocol

**No ownership state machine is needed.** Because the module refuses every access
to the image's extents at the block layer (§4.3), relocation cannot happen while
Linux runs, so there is nothing to buffer, log, replay or promote.

### 5.1 The property

> **While Linux runs, no other writer can reach the image's sectors, and the map
> of those sectors was verified before any view existed.**

A *timing-based* approach — a user-mode pinner plus a liveness heartbeat — cannot
establish this, and the counterexample shows why:

```text
t0  pin held; guest writes reach the physical disk
t1  the pinner dies; Windows closes its handle
t2  before heartbeat expiry, NTFS relocates the file
    and persists the metadata
t3  the host notices the missing heartbeat and stops
    future direct writes
```

At t3, nothing can un-write t2. `MARK_HANDLE_PROTECT_CLUSTERS` blocks
defragmentation only *until the handle closes*.

**A block-layer refusal has no window.** Reads and writes to the image's extents
fail for the whole session regardless of what runs in the guest, and a relocation
that cannot copy never produces a runlist record (§4.3).

### 5.2 Layering

| Layer | Prevents | Failure mode |
|---|---|---|
| Windows minifilter (§4.4) | the operation being attempted | a clean Windows refusal |
| **kernel module (§4.3)** | **any access to the image's extents** | **`EIO`; the disk is untouched** |

The first is quality of experience; the second is the correctness boundary, and
it also covers direct access (`\\.\PhysicalDrive`) that no filesystem filter
could catch.

### 5.3 What still has to be established

Two things, both in §11:

- **The map must be right before view A exists** (§11 Q4). A derivation bug is a
  different failure from Windows moving the file; the `ntfs3` cross-check and the
  structural assertion (§4.3) are what catch it.
- **Volume-wide transformations** (§5.7) are *mediated* — they take `EIO` and
  cannot complete — but a conversion refused partway leaves Windows with a
  partially converted volume. Visible and self-reported, not silent; not nothing.

### 5.4 Crash recovery

> After an arbitrary crash, can the machine take its untouched native Windows
> boot path with no hidden dependency on unfinished Linux-side recovery?

**Yes, trivially.** There is no overlay to merge, no log to replay and no commit
to interrupt. The disk at any instant holds exactly the guest's own completed
writes, minus the ones that were refused, and native Windows recovers from that
with its own journal as it would from any power loss.

### 5.5 The trusted core — one module

After everything that came out of review, **exactly one component we write can
corrupt anything:**

| Component | Can corrupt? |
|---|---|
| **Linux kernel module** (§4.3) | **yes — the entire critical path** |
| Windows minifilter (§4.4) | no — defence in depth and clean errors; not trusted |
| QEMU | no — handed a view it cannot escape |
| `paguro.efi` | no — never writes to disk |

**"We write" is doing real work in that sentence.** The design also depends on
`dm-crypt`, the block layer, ext4 and — when C: is mounted read-write — `ntfs3`,
any of which could corrupt a volume through a bug of their own. That is the
ordinary condition of building on a kernel, and it is not what this claim is
about: it is about how much *novel* code sits on the critical path.

**`ntfs3` is the most junior of those dependencies**, merged in 5.15 and younger
than everything else in the list. Its read-write use is confined to native-mode
growth and mode 2 (§5b), both non-default, and that placement is deliberate rather
than incidental — **VM-mode growth stays the default path** precisely because it
keeps the user's Windows volume out of a 2021-vintage driver's write path.

That is an unusual position for something spanning two operating systems and a
hypervisor, and it is what makes the rest of this section achievable rather than
aspirational.

#### What must be hand-written and reviewed

| Line by line | Normal process |
|---|---|
| **range enforcement** — filtering every request against protected ranges: clipping, discard, write-zeroes, boundary arithmetic | the `paguro.ini` parser |
| **the load-time NTFS parse** — one runlist from a known MFT record, plus the state assertions, run once before anything is exported | installer, progress UI, identity sync |
| **view construction** (A, B, C) and mutual exclusion | SMB/WinApps integration |

**A few hundred lines**: a range test, one parse that runs once, and the plumbing
to export the views — no runlist decoder in the write path, no `$Bitmap` tracking,
no cryptography (§4.3). Small enough that a person can hold it, which is the only
condition under which line-by-line review means anything.

**The FVE metadata substitution does not live here.** The three substituted
regions are `dm-linear` segments in the userspace sandwich, pointing at a loop
device holding the buffer the initrd authored (§6 The VM boot). The module's only
part is the range test beneath. A wrong buffer means the VM does not boot — loud,
not corrupting.

#### The release bar

> **Not "no bugs" — no bug class that produces unrecoverable corruption.**

Disk corruption is the worst outcome this project can have. A crash and a restart
is acceptable; an unrecoverable disk is not, and one incident ends the project.
That bar is narrower than general correctness and, unlike general
correctness, it is mechanically checkable.

#### Why it is testable in a way most storage software is not

**The critical module is pure logic over inputs.** Synthetic NTFS images,
injected request streams, loop devices — no Windows, no GPU, no real disk, no
hardware. So the one component that can corrupt is the one that can be tested
**cheaply, exhaustively, and on every push in CI**.

That inverts the usual arrangement, and it is the opposite of kayfabe, where
verifying anything needs real hardware and a human watching.

A **1:10 implementation-to-test ratio** is therefore realistic: thousands of lines
of tests around a few hundred lines of enforcement.

| Contract | Test |
|---|---|
| (map, request stream) → filtered stream | exhaustive synthetic ranges: straddling, zero-length, discard, write-zeroes, off-by-one at every boundary |
| (runlist, image) → map | crafted runlists, attribute lists, sparse/compressed rejection, the `ntfs3` cross-check disagreeing |
| crash at any point | truncate an injected history at every boundary, apply, assert recoverable |
| view exclusivity | assert B and C are never simultaneously live |

**Every test asserts both NTFS *and* the image are recoverable.** Checking only
the outer filesystem is the easy mistake.

What CI cannot cover, and what therefore needs hardware: `bootmgr` behaviour,
real power-cut timing, and the Windows driver's interaction. Those are §11's
bench items — a small, enumerable set, rather than the bulk of the verification.

**Write the executable model before the implementation.** Then review asks *"does
this code implement this model?"* — which humans answer reliably — instead of
*"can I think of a case that breaks this?"*, which is how ordering bugs survive
review.

**What this does not contain:** key handling. A §6 bug costs confidentiality, not
integrity, and lives in `paguro.efi` and the initrd rather than in this module.

### 5.6 Growth and shrink

**Dynamic sizing is the main advantage over a partition, so it is v1.** A
preallocated image that cannot grow is exactly as fixed as a partition, and the
advantage exists only on paper. **15 GB that grows** is a materially different
product from **200 GB reserved forever**.

#### Growth happens through whichever side holds C:

Extending the file needs NTFS write access, and §5b makes view B and view C
mutually exclusive — so exactly one of the two is available at any moment, and
each has its own path:

```text
VM MODE -- the guest holds C:
  Linux needs space
    -> request over virtio to the guest
    -> the Windows driver extends the image
    -> Windows flushes

NATIVE MODE -- Linux has C: mounted read-write via ntfs3
  Linux needs space
    -> ntfs3 extends the image directly
    -> no guest involved, no virtio round trip
```

Both then converge:

```text
  module observes the writes complete durably
  module re-parses the runlist (the only NTFS
         parse after load) and verifies the new
         extents ITSELF
  module extends the exclusion set   <- first
  module extends view A's mapping    <- then
  -> Linux grows the nested GPT if there is one,
     resize2fs online
```

**Append-only is what makes either path safe.** Existing extents must be
unchanged; runs beyond the current end are permitted. The module checks this
against the on-disk runlist it re-derives, never against what the extender
reported — so a Windows driver that lies and an `ntfs3` that misbehaves are the
same case, handled the same way.

**And the exclusion applies to Linux too.** When Linux has C: mounted read-write,
`ntfs3` is as capable of relocating the image as Windows is. Its writes go through
view C, which carries the same range set — so the protection that keeps the guest
honest keeps Linux honest, with no second mechanism. The minifilter's Windows-side
role has an exact counterpart here, and it is the same block layer providing it.

**Ordering carries the safety in both directions**: the exclusion is extended
before the mapping, so there is no instant in which two writers can reach the
same sectors.

| Crash point | Result |
|---|---|
| during the allocation write | NTFS journal rolls back; the module never saw a completed write and extended nothing |
| after allocation is durable, before Linux uses it | extra space allocated to the image, unused |
| after Linux uses it | the allocation was already durable, so NTFS owns it |

The asymmetry holds: **the image may end up with unused capacity, never with
Linux depending on space NTFS can reclaim.**

#### Shrink is offline, and ext4 is why

`resize2fs` supports online growth but **not** online shrink, and view A is the
root filesystem — it cannot be unmounted while Linux runs. A filesystem
constraint, not a design one.

```text
phase 1 -- Linux maintenance boot, root not mounted from A
    resize2fs smaller, shrink the nested partition,
    record the new length
phase 2 -- native Windows
    truncate the image file (and rewrite the VHD footer)
next Linux boot
    derives the shorter map at load
```

**Shrink before truncating**: Linux stops using the tail in phase 1, so by the
time native Windows frees those clusters nothing maps them — the module is not
running under native Windows, and does not need to be.

**The rare direction, acceptably so.** The common operations are **grow** (live)
and **remove** (delete the file; everything returns to NTFS at once). Partial
shrink is the uncommon middle.

*Footnote:* btrfs supports online shrink. If shrinkability matters that is a real
reason to choose it for the inner filesystem; the design does not care which it
is, only that the nested partition and the block device agree.

### 5.7 Volume-wide transformations

Pinning answers *"which sectors hold this file"*. It says nothing about *"how
must those sectors be interpreted"*, and the second can change while the first
does not.

The concrete case is **BitLocker conversion**. Turning BitLocker off is a
supported operation on the running OS volume and relocates nothing.

**Mediated, not merely detected.** Conversion writes every sector, so it hits
excluded ranges and takes I/O errors there. It cannot complete, and Windows
tracks conversion progress itself — so the failure is visible and self-reported
rather than producing metadata that describes a transformation the sectors never
underwent.

**Requiring the user to perform encryption changes from a native Windows boot
remains the supported answer.** The block layer makes the unsupported path fail
safely; it does not make it pleasant.

---

## 5b. Access to Windows data

Reading and writing the user's Windows data is half the point of dual boot.
There are two modes and they are **mutually exclusive by construction** — the
module enforces exactly one at a time.

**Both land at `/mnt/c`.** Whether Windows' files arrive over SMB from the running
VM or from a native `ntfs3` mount, the path is the same, and so is what the user
can do with them — including growing the image (§5.6). The mode is an
implementation detail of how the bytes get there, not something a user should have
to hold in their head.

**Switching modes has a deliberate gap.** Starting the VM means unmounting
`/mnt/c` first; stopping it means the SMB share goes away before the native mount
can be taken. There is a window during Windows' boot in which `/mnt/c` is simply
not there — and that is correct rather than unfortunate. The alternative is a path
that sometimes points at a stale mount while the other writer owns the volume,
which is the failure this whole section exists to prevent.

> **Never both.** If the VM is running, Linux cannot mount C:. If Linux has C:
> mounted, the VM will not start. Enforced in the module, not by convention — one
> component owns both views.

### Edition limit: RemoteApp needs a Pro-or-better host

**Windows Home cannot act as a Remote Desktop host**, so the RemoteApp path below
does not exist on Home installations. Since this design uses the *user's existing*
Windows rather than an installer-chosen edition, that is a large fraction of the
target audience, not an edge case.

| Edition | Window integration |
|---|---|
| Pro / Enterprise / Education | RemoteApp per-window, as described below |
| **Home** | full-desktop VM window only, until the per-window projection in §1b exists |

The SMB file-sharing half works on Home regardless — it needs file sharing, not
RDP hosting. Only the seamless-window experience is affected.

**Per-window projection does not fix this.** It keeps **RAIL for the control
plane** and replaces only the pixel
transport — and RAIL is an extension of RDP, which Home cannot host. Replacing
encoded frames with shared buffers does not supply the missing server.

Seamless windows on Home would need a **separate control protocol** — our own
guest agent reporting window create/destroy/move/resize/z-order — which is
additional architecture, not the stated *"keep the integration, replace only the
pixels"* design. Until that exists, Home gets a full-desktop VM window.

### Mode 1 — SMB from the running VM (default)

The Windows VM starts with the Linux session. WinApps runs against it, Windows
shares its own volumes back over the point-to-point virtio link, and C: appears
at `/mnt/c`.

**This is strictly better than mounting NTFS directly, because Windows keeps
exclusive ownership of its own journal.** The two-drivers-one-volume problem does
not get managed — it does not exist. No dirty bit interaction, no torn metadata
reads, and ACLs, alternate data streams, file locking, VSS and indexing all keep
working because the real NTFS implementation is the one serving the files.
FreeRDP drive redirection covers the reverse direction, putting the Linux home
into Windows as a network drive.

| Concern | Resolution |
|---|---|
| `rm /mnt/c/linux.vhd` over SMB | the minifilter holds the handle with `dwShareMode = 0` (§4.4) — sharing violation |
| mount blocking boot if the VM is slow or fails | `x-systemd.automount`, never a hard `_netdev` entry in fstab |
| credentials for the share | per-user generated secret in the keyring (§4.7), not a config file |
| share reachable off-box | bind to the host-only virtio link; not routable |
| throughput | SMB over virtio, not NVMe-direct. Fine for Documents/Downloads; a large build tree on `/mnt/c` will hurt |

Note the VM's uptime becomes Linux's uptime, so Windows Update reboots happen
inside a running Linux session. Starting the VM at login should be a setting,
not a given — it costs RAM and CPU whether or not Windows is used that session.

### Mode 2 — direct NTFS mount from Linux (the escape hatch)

The escape hatch, and it matters precisely when the VM will not boot — which is
when the user most needs their files. Off by default, and **the Rule 3 warning
below must be shown at the point of use**, not buried in documentation.

#### The kernel module is the single arbiter

It owns the views (§4.3), so exclusivity is enforced in one place rather than by
convention. **`A ⊂ C`** — the image lives inside the volume Linux is mounting —
and that containment is the entire source of C:'s extra rules.

#### Rule 1 — the VM must be off, read-only included

Mode 1 inverts this — there the VM must be *on*. That is the whole reason the two
modes are exclusive rather than complementary.

Not relaxed for `ro`. If QEMU is up, no view-C mount may exist: the guest holds
the volume mounted with live cached `$MFT` state, and anything Linux writes
underneath diverges immediately. Keying the rule on *"is QEMU running"* leaves
nothing to reason about.

A volume being mutated by the Windows guest also gives a Linux reader torn reads
and a page cache full of stale metadata; read-only protects the disk but not the
reader. Read-write is two independent NTFS drivers with two independent journals
on one volume.

Applies to **every** Windows volume, not only C:. Enforced by the module
refusing to instantiate view B while any view-C mount is held, and the reverse.

#### Rule 2 — the image must not be reachable through the mount

C: only. The stake is not corruption in the abstract, it is Linux **deleting its
own root device**: `rm`, truncate, or anything that relocates the file through
the NTFS layer destroys the dm table the running system is executing from, while
NTFS's cached allocation state goes stale against raw writes it cannot see.

Mode 1 handles this at the Windows end via `dwShareMode = 0` (§4.4). In mode 2
Windows is not running, so the enforcement has to be local.

**It is the minifilter's job, on the Linux side, and for the same reason.** The
module already makes every access to the image's sectors through view C fail, so
nothing here is needed for correctness. What is needed is that nobody *meets*
those failures: a file manager generating a thumbnail, a backup tool, `du`, a
desktop indexer or `grep -r` walking `/mnt/c` would otherwise get `EIO` and a log
full of I/O errors, which reads as a failing disk. Same argument as §4.4: clean
refusals up front, the range test underneath.

**What ntfs3 can do to the image** (read from the source, mainline v7.3-rc4):
it never moves existing data clusters, has no defrag or move-extent ioctl, never
marks clusters bad and does not react to I/O errors beyond passing them up.
Clusters are freed only by an operation on *that file* — truncate, a
`fallocate` collapse (allowed on ordinary files), or unlinking the last link.
So the guard only has to stop operations on the image's inode. One volume-wide
effect remains: metadata **readahead** through the block device's page cache can
touch clusters next to metadata, including the image's (below).

Two layers, keyed to the image's inode — never its path, because ntfs3
resolves the 8.3 short name and supports hard links:

| Layer | Mechanism | Covers |
|---|---|---|
| **inode guard** (primary) | a **BPF-LSM** program keyed on `(dev, ino)`: `file_open`, `path_truncate`, `inode_setattr`, `inode_unlink`, `inode_rename`, `inode_link`, `inode_setxattr`/`removexattr`, `inode_file_setattr`, `file_permission` → `EACCES` (`EBUSY` for unlink/rename/link). Every data access needs an fd, so `file_open` alone covers read, mmap, `fallocate`, `open_by_handle_at` | everything, on the inode |
| **tripwire** | the module's range test: readahead (`REQ_RAHEAD`) hits are expected and failed quietly; any other hit is counted and logged as a guard failure | the correctness floor |

The BPF link is pinned, and the program also denies unlinking its own pin and
unmounting that bpffs, so **only a reboot removes it**. The paguro host sets
`lsm=…,bpf` on its signed command line (Debian enables `CONFIG_BPF_LSM` but not
in the default list). The growth service is the one cgroup the program allows.
No bind mount: it could be unmounted, and it would not behave as one
filesystem.

**Acceptance test:** mount view C read-write, then walk the whole volume —
`find`, `du`, `tar` to `/dev/null`, a thumbnailer, `rm -rf` of the image's
parent directory. **Zero `EIO`s in the kernel log**, clean `EBUSY`/`EACCES` to
the callers, and the image intact.

A guard rail, not a security boundary — the user is already root in their own
OS. It exists so the catastrophic case requires deliberate effort, and so the
ordinary case never shows an I/O error.

#### Rule 3 — the dirty bit cuts both ways

A read-write ntfs3 mount marks the volume dirty and clears it on clean unmount.
An unclean Linux shutdown therefore leaves C: dirty, and **§4.1's gate then boots
Linux read-only** until Windows has run `chkdsk`.

Correct fail-safe behaviour, but the user experiences it as *"Linux went read-only
after I force-powered-off."* It must be surfaced in the UI, not only on the boot
screen. The resulting `chkdsk` may relocate the image — safe, because it runs
under native Windows and the next Linux boot re-derives the map.

Windows hibernation is covered the same way: with a hibernation image present
Linux boots read-only and no view C is offered read-write, so the classic
mount-a-hibernated-volume corruption path cannot be reached.

#### Other Windows volumes

Rule 1 only, unless they hold paguro images, in which case they get the same
range protection as C: (§4.3 — a second volume is another instance of the same
view). Otherwise they are ordinary NTFS volumes that happen to belong to the other
OS.

If separately BitLocker-protected, each needs its own unlock. Note that
auto-unlock keys for data volumes are stored in the **system volume's registry**
and are not reachable from paguro's seal (§6), so the user must supply a
password or recovery key for those.

---

## 5c. One machine, one set of paths

Whichever system is on the metal, the other one's files, shells and network
should be where the user expects them. **The same path names the same file in
every topology** — Windows native with WSL, Linux native with the Windows VM,
images or a dedicated disk, one distribution or several.

### The paths

| From | Windows' files | Linux distribution *d*'s files |
|---|---|---|
| any Linux (WSL, bare metal, a container) | `/mnt/c`, `/mnt/d`, … — one per NTFS volume | `/mnt/l/d` |
| Windows (native or the VM) | `C:\`, `D:\`, … | **`L:\d`** — one drive, a folder per distribution |

`L:` is the default letter, configurable, and moved to the next free one if
taken; every distribution paguro knows — images, WSL distributions made
bootable, a dedicated disk — appears as a folder. WSL's own
`\\wsl.localhost\d` keeps working for WSL-registered distributions; `L:` is the
path that also works when Windows is the VM.

### Who serves what, per topology

The same idea both ways round: **a small host distribution runs the other
distributions as privileged containers and serves their roots**.

| Topology | `/mnt/c` in Linux | `L:\` in Windows |
|---|---|---|
| **Windows native** | WSL's own drive mounting (9P, or virtiofs where WSL uses it) — no SMB | Samba in paguro's **WSL helper distribution**, which attaches every paguro image and a dedicated disk into the WSL VM (`wsl --mount --vhd --bare`, `wsl --mount \\.\PhysicalDriveN`) and exports each root |
| **Linux native, VM running** | SMB from the VM over the host-only link (§5b Mode 1) | Samba on the Linux host, over the same link, exporting every distribution's root |
| **Linux native, VM off** | `ntfs3` on view C (§5b Mode 2) | — (Windows is not running) |

- **The same disk mounted twice is safe only inside one kernel.** WSL2 runs all
  distributions in one VM, so the helper mounting a disk a WSL distribution is
  already using yields the same superblock — the kernel shares it. Across
  kernels it is never safe, and never happens: a disk is either in the WSL VM or
  in the bare-metal host (or its Windows VM), not both.
- **SMB is used only where it wins**: Windows reading Linux's roots, where WSL's
  9P is the slow path, and Linux reading C: when Windows is a VM. Linux reading
  C: from inside Windows (WSL) uses WSL's own mount.
- **A dedicated disk** is the same row: attached whole into the WSL VM (opened
  with the VMK-derived LUKS slot, §8d) or mounted by the bare-metal host.

### The private link

Every paguro share travels on a link nothing else uses, so it can neither
conflict with nor be reached from the user's own network or their own Samba:

- **Windows VM ↔ Linux host**: a dedicated host-only virtio-net adapter
  (`paguro0`, 169.254.244.0/30), separate from the VM's LAN adapter. The host's
  Samba runs **in its own network namespace** attached to that link, so it can
  never bind anything else and a user's own `smbd` is untouched. Windows' SMB
  server cannot be bound per interface, so it is scoped by firewall rules to
  that adapter and serves a paguro-only share to a paguro-only local account.
- **Windows ↔ WSL helper**: the WSL VM's own address in NAT mode. In mirrored
  networking mode the WSL VM shares Windows' addresses and port 445 is taken by
  Windows' own server, so the helper's Samba listens on another port, which
  Windows' SMB client supports from Windows 11 24H2; older builds fall back to
  NAT mode for the helper.
- **Authentication, not encryption**: a random per-installation secret for a
  dedicated SMB account, kept in Windows' Credential Manager and the Linux
  keyring (§4.7); SMB signing on, SMB encryption off — the link never leaves the
  machine. Nothing is exposed as a guest share.
- **Built and proven** (the split end-to-end test in `test/vm/`): Samba in netns
  `paguro` bound to `paguro0` only, `/mnt/c` mounted from inside the netns, and
  `L:` mapped in Windows over the link. **Keep this model**: it is what makes
  every service below link-only.
- **Everything paguro serves on the link is link-only by construction, never
  by configuration the user could change**: a listener on Linux exists only
  inside netns `paguro`; one on Windows is bound to `169.254.244.2` where the
  service allows it and firewall-scoped to the private adapter where it does
  not (SMB). None of them is ever reachable from the LAN (see the DMZ rule
  below).

### The control channel, and keeping the link to itself

**The agent port is paguro's RPC between the two sides, not a network:**
virtio-serial `org.paguro.agent.0` between the Windows VM and its launcher,
and Hyper-V sockets between Windows and the WSL VM when Windows is on the
metal. Everything that bootstraps trust travels there and nowhere else:

- arming (§4.4);
- the SSH public keys and host keys for each direction;
- the SMB secret;
- the RDP certificate's fingerprint;
- later, any other provisioning.

A device between one VM and its launcher cannot be reached from any network.

**The link carries the internal protocols, and only the link.** SMB, SSH and
RDP between the two sides run on `paguro0`. The VM's internet adapter has no
paguro listener on either side, and nothing of ours is reachable from
LAN/Wi-Fi/VPN. Hardened against pushed or overlapping routes (a VPN or DHCP
server that pushes `169.254.0.0/16`, or a LAN that reuses the range):

- **Linux side:** the link lives in netns `paguro`, whose routing table no
  VPN or DHCP client touches.
- **Windows side:** listeners are bound to `169.254.244.2` where the service
  allows it, and firewall-scoped by **interface**, not by address.
- **Outbound pinning:** a Windows firewall rule allows SMB, SSH and RDP to
  `169.254.244.0/30` to leave **only** through the private adapter. A
  pushed route can never carry a credential to someone else.
- **Peers are pinned, never trusted on first use:** SSH `known_hosts`
  entries and RDP's `/cert:fingerprint:` both come from the agent port.

**No encryption on the link, authentication everywhere.** The link never
leaves the machine, so SMB signing without encryption stays (§The private
link). Every connection is authenticated: SMB with the per-installation
secret, SSH by key, RDP as below.

**RDP's credential is the user's own Windows password, kept only in the Linux
keyring** (§4.7). A paguro-issued token in its place was considered and
rejected. RDP authenticates local accounts by password (NLA), so accepting
anything else means code inside LSASS (an authentication package, or an
MSV1_0 sub-authentication DLL). Windows 11's LSA protection refuses LSASS
plugins not signed through Microsoft's program, so that would stop working on
exactly the machines paguro targets. A credential provider runs in LogonUI, not
LSASS, but still has to hand Windows a password. Within that limit, the
password is:

- stored only in the Linux keyring, unlocked by the Linux login (PAM);
- re-prompted when Windows' password changes;
- sent only by FreeRDP, only over the pinned link, to the pinned certificate.

*Alternative kept open:* log the user's session in at VM boot and attach RDP
to it with no password. It is not the default, because RemoteApp and
client-edition session rules make it fragile.

### Shells, the same command both ways

`paguro` is the same command on both sides, and forwards to the other side
when the target lives there. `paguro shell <target>` and `paguro distro enter
<d>` work from either side, whichever is booted:

| Target | From Windows native | From the Windows VM | From Linux (metal) |
|---|---|---|---|
| `windows` | a local shell | a local shell | into the running VM (or an offer to start it) |
| the running Linux host | — | **into the host**, over the link | a local shell |
| a distribution *d* | `wsl -d` for WSL distributions; into its container in the WSL helper for paguro images | **forwarded to the host**: the host's `paguro distro enter d` | into *d*'s container on the host |

From the Windows VM, **Linux's images are never touched directly**: they are
claimed by the host and refused to Windows at the block layer (§4.3), so
"enter" is always the host doing it on Windows' behalf.

**The channels:**

- **Windows VM ↔ Linux host: SSH over the private link, both directions.**
  This is standard tooling that users already have: PowerShell over OpenSSH,
  `scp`, and editors' remote modes.
  - **Linux → Windows:** Windows' OpenSSH server, `ListenAddress
    169.254.244.2` only, firewall-scoped to the private adapter, key-only.
    The default shell is PowerShell.
  - **Windows → Linux:** the listener must exist only on the link, but an
    `sshd` *running* in netns `paguro` would start shells cut off from the
    network. So a **systemd socket unit with
    `NetworkNamespacePath=/run/netns/paguro`** listens on `169.254.244.1:22`
    and hands each connection to `sshd -i` in the host's own namespace. The
    socket lives only on the link, and the shells are ordinary.
  - **Keys:** a unique key pair per installation and direction, generated by
    paguro. The private halves are readable only by the owning account (the
    Linux user, and on Windows the user's profile, SYSTEM-only for the
    service's own). Each side's `authorized_keys` holds exactly the other's
    public key, restricted with `from="169.254.244.x"`. No passwords.
- **Windows native ↔ WSL: unchanged.** `wsl.exe` and the WSL helper's own
  channel (Hyper-V sockets). Nothing listens on a network.
- *Superseded:* the earlier plan of vsock with a paguro agent PTY for the VM.
  SSH over the link gives the same isolation (link-only listeners, key-only,
  from-restricted) with standard clients on both ends.

### The paguro service in the VM

The same `paguro service` runs on every Windows boot. **Natively** it does
none of the following (the SMBIOS marker `paguro-vm/1` is absent, §4.4).
**In the VM** it:

1. arms the driver: sends the report on the agent port, waits for the host's
   ack, and only then marks the minifilter armed (§4.4, INTERFACES §11.3);
2. provisions the link: the static address on the private adapter, the SMB
   share and account, the firewall scoping, and the `L:` mapping;
3. provisions SSH: OpenSSH server bound to the link, the host's public key in
   `authorized_keys`, and the Windows key for reaching Linux;
4. provisions RDP for RemoteApp: RDP with NLA, RemoteApp for any program, an
   inbound rule on the private link from the host only, and the certificate's
   fingerprint sent over the agent port for the host to pin. It records the
   user's own RDP on/off setting and puts it back on native boots, because the
   VM and native Windows share one registry;
5. keeps (2)–(4) correct on every VM boot, and **removes nothing that
   native Windows needs**. The link adapter only exists in the VM, so its
   rules are inert natively.

### Adding WSL distributions for bare metal
### Adding WSL distributions for bare metal

A WSL distribution becomes bootable by being **registered with the paguro host
distribution**, which runs it as a privileged container on the metal (§8b). The
Windows app writes that registration into the host image (it is a VHD WSL can
attach), not into `paguro.ini`, which stays the bootloader's configuration.

### The VM's network: a tap and nftables, no user-mode networking

The VM's LAN adapter is a **tap device with vhost-net, NATed by nftables** on
the host, not QEMU's user-mode network (slirp). slirp is a userspace TCP stack,
slow for SMB and bulk transfers and awkward for inbound forwarding. A tap runs
at kernel speed and makes the DMZ below a plain DNAT.

- **Where things live:** the LAN tap is in the **host's own namespace**,
  because it needs the host's routes. Netns `paguro` keeps **only** the private
  link (`paguro0`, §The private link). The two adapters, and their purposes,
  never mix.
- **Routed, not bridged:** a small private subnet on the tap, with
  masquerading out of whatever interface the host routes by. That works on
  Wi-Fi, where bridging does not.
- **paguro's own nftables table** (`inet paguro`): masquerade, forward-accept
  for the tap, and the DMZ's DNAT set. Created per session, deleted after.
  `net.ipv4.ip_forward` is enabled for the session and restored. IPv6 starts
  as none and comes later as NAT66 if needed.
- **DHCP and DNS,** which slirp used to provide: a single-lease DHCP server in
  the launcher, and DNS forwarded to the host's resolver on the tap address
  (systemd-resolved's `DNSStubListenerExtra` where present, dnsmasq
  otherwise). Windows needs no special configuration.
- **Coexistence is a requirement, not a detail:** Docker sets the FORWARD
  policy to DROP, and a drop in any base chain wins over our accept, which is
  the classic libvirt-plus-Docker breakage. So the launcher detects Docker and
  firewalld and adds its accept where they will honour it (`DOCKER-USER`,
  firewalld's policy/zone). A preflight check says so plainly when it cannot.

### The network: Windows keeps its inbound services

When Linux is on the metal and Windows is the VM, **inbound LAN connections go
to Linux if Linux listens on that port, and to the Windows VM otherwise** —
Windows remains reachable for what it serves natively (RDP, a game server, a
sync client's port), like a DMZ host behind the Linux one:

- nftables DNAT on the LAN interface for new inbound connections whose port is
  not in the set of Linux's listening sockets; the set is kept current from the
  kernel's socket diagnostics, plus ports the user pins to either side;
- **never forwarded, whatever the set says:** the ports of paguro's link-only
  services on Windows (445 SMB, 22 SSH, 5985/5986 WinRM) and 3389 RDP unless the
  user pins it to Windows. The DMZ must not turn the private link's services
  into LAN services;
- replies and Linux's own outbound traffic are untouched (conntrack); the VM's
  outbound traffic is NATed through the host;
- the VM's LAN adapter carries the host's MAC (§4.5), so the network sees one
  machine, as it does when Windows is booted natively; Windows' firewall still
  applies to what reaches it.

## 6. Encryption model

**What this section guarantees:** a stolen, powered-off machine yields nothing
better than an offline dictionary attack on the user's passphrase; Windows'
own BitLocker configuration is never modified; and every failure of the TPM path
has a recovery that needs no external media and, almost always, no 48-digit key.

§3 and §5 are where a mistake destroys a disk. Here a mistake weakens a lock —
which is why this section can lean on well-trodden primitives, and why it has to
be exact about which ones.

### Both BitLocker states are primary

Which one a machine is in depends on its **provenance**, not on anything the user
chose:

| Machine | C: |
|---|---|
| shipped with Windows 11, or clean-installed on 24H2 | **encrypted** — Device Encryption enables itself, Home included |
| upgraded from Windows 10 | **usually not encrypted** |

Windows 10's end of support in October 2025 made the second group large and
recent, so **both are primary test configurations.** BitLocker support is a
release requirement; the unencrypted case is supported alongside it, not instead
of it.

**Unencrypted C:** the loader reads NTFS directly, no seal is written, and the
ladder below does not apply. Linux inherits no encryption, and the only way to
encrypt it is the LUKS tier (§LUKS inside the image) — whose role is therefore
mainstream on these machines rather than niche. The TPM is still present
(Windows 11 requires one), so the distribution can bind LUKS to it with
`systemd-cryptenroll`.

**Encrypted C:**

- **Most users have never seen their recovery key.** It was escrowed to their
  Microsoft account automatically. So the bootstrap does not depend on it, and
  the *"Windows will almost certainly start normally"* screen (§4.1) matters —
  someone who does not know their drive is encrypted is the typical case.
- **The PIN is the Linux password, asked earlier rather than additionally.**
  Device Encryption is TPM-only; this design uses TPM+PIN for the Linux path
  (below), but the PIN *is* the user's Linux password, entered before the volume
  decrypts instead of at the login screen. Total prompts are unchanged, and
  restarting from Windows skips it (§The PIN bypass).

  **Obligation:** changing the Linux password must update the seal, or the two
  diverge silently. It is a local operation (§Changing the PIN), so a PAM hook
  covers it — and it must **fail loudly**.

  **Single-user only.** Pre-boot authentication happens before any user database
  is readable, so the loader cannot know who is typing. Several seals with
  different PINs are possible, but a wrong guess then costs one lockout attempt
  per seal, and asking *who you are* first leaks the user list. **Multi-user
  takes parity with Windows: a shared machine PIN pre-boot, then per-user login.**
- **Clear-key volumes need no special handling.** Device Encryption on a local
  account sits with a clear-key protector until a Microsoft or Entra account signs
  in. That is exactly the state where escalation unlocks silently. When the clear
  key later goes away, §7 must provision the seal at that moment, or the machine
  starts asking for a password one day for no visible reason.

Detected at setup and by the repair hook:

```text
manage-bde -status C:
manage-bde -protectors -get C:
```

**Disk encryption is Windows' decision.** The user enables or disables BitLocker
with Windows tools; the hook detects the change and provisions accordingly.
Enabling it encrypts the Linux install for free, because the image lives inside
C:.

### What the TPM and Secure Boot each do

| | Protects | Against |
|---|---|---|
| **TPM** | *confidentiality* — a secret is withheld unless the boot state matches | a stolen laptop |
| **Secure Boot** | *integrity of execution* — unsigned code does not run | someone substituting the code you meant to run |

> **Secure Boot does exactly one thing in this design: it prevents unsigned code
> from executing** — shim and `paguro.efi` at the firmware boundary, and the next
> image after them. No parser, no protector and no recovery path is gated on it.
> Every major distribution ships a shim-signed live image, so an attacker reaches
> a root shell on this machine *with* Secure Boot on; conditioning anything on its
> state would buy nothing. The one check that runs only under Secure Boot is the
> configuration hash, because without Secure Boot the loader that compares it can
> itself be replaced (§paguro.ini).
>
> **Secure Boot and the firmware-held config hash are evil-maid protection. The
> TPM taints are the security.**

**The TPM carries the theft case alone**, which is the case the overwhelming
majority of users face.

**Secure Boot is nonetheless required — for compatibility, not protection.**
Turning it off moves PCR 7, which is in BitLocker's **default** profile, so
Windows demands its recovery key on the next boot; and anti-cheat (Vanguard,
Faceit) refuses to run. A machine with Secure Boot off is already broken in ways
its owner notices long before Linux gets a vote.

**Its one contribution is that the prompt asking for your secret is the one you
installed.** Even that has a limit: an attacker with firmware access clears the
supervisor password, enrols their own key, boots a pixel-perfect prompt, captures
the passphrase and restores the genuine loader. The comforting *"cannot unlock
automatically — this is normal after a firmware update"* screen is exactly what
such a keylogger would show. **No display-based mitigation works** — anything the
genuine loader can display without input, an attacker who can run the genuine
loader can learn.

So the prompt is **unattested against an attacker with firmware access**, and the
design does not pretend otherwise. What limits the damage is that a captured
passphrase is **not sufficient** (§Every standing rung requires the passphrase).

**Clearing the TPM is loud.** It destroys BitLocker's own protector too, so
Windows demands its recovery key and the owner learns of the tamper.

### Parity, not superiority

An attacker takes the weakest available path; a Linux path stronger than Windows
buys nothing, and a weaker one degrades the device.

| Windows configuration | Linux path |
|---|---|
| BitLocker off | unencrypted, unless the LUKS tier is chosen |
| TPM-only | **TPM+PIN**, the PIN being the Linux password |
| TPM+PIN | TPM+PIN, **same PIN** |

#### Why TPM-only on Windows still means TPM+PIN on Linux

**Parity is about the attacker's weakest path end to end, not about matching
protector types.** Windows TPM-only is safe because the attacker meets a login
screen after the unseal. Linux TPM-only is not, for a reason specific to this
design: **the initrd must hold the key to do its job** — it reads NTFS and builds
the views (§4.3). An induced failure that reaches a shell reaches the key, and
failures are easy to induce by corrupting a few bytes of NTFS metadata.

The UKI closes `init=/bin/sh` and `rd.break`, because its command line is signed.
It does not close an initrd's emergency shell. **The PIN does**: it is entered
before the unseal, so an attacker who induces a failure never reaches a shell.
That is enforced by the TPM rather than by an audit of every failure path.

**So with a PIN the shell should stay** — it sits behind authentication and is
the legitimate user's repair tool. Hardening it away is an obligation only in the
opt-in TPM-only profile (below).

**And the requirement is arithmetic, not policy**: the passphrase is an operand
of the key derivation, so it cannot decay into a setting someone defaults off.

### Reading a BitLocker volume — the largest block of new code

Unsealing is the small part. *Reading* a BitLocker volume from the loader means:

- **Relocated sectors.** On in-place-converted volumes BitLocker moves the NTFS
  boot sector and writes its own header in its place; the FVE metadata describes
  the relocation. A reader that decrypts from sector 0 gets garbage and cannot
  tell.
- **Cipher variants.** AES-XTS-128/256 since Windows 10 1511; older volumes use
  AES-CBC with the Elephant diffuser, which is refused (§8b).
- **Partially converted volumes.** A paused conversion leaves the sectors past
  `encrypted_size` plaintext, and the reader serves them as such; a region caught
  mid-conversion is refused.
- **Used-space-only encryption** — Device Encryption's default — reports its own
  conversion state. The reader identifies it and refuses it until it is classified
  correctly (§11 Q25).
- **Three metadata copies, compared, never outvoted**, and after unlock the
  metadata's own VMK-wrapped hash checked, so nothing unauthenticated — the layout
  included — is used.

References exist in Linux userspace — `cryptsetup`'s `bitlk` (LGPL), `dislocker`
(GPLv2), and libbde's format specification — and they are the test oracles: the
loader's decryption equals dislocker's, libbde's and cryptsetup's on
Windows-made volumes and on generated ones (512 and 4096-byte sectors,
XTS-128/256, every supported protector, partly encrypted).

### The Linux-side seal

BitLocker permits one TPM protector, and it belongs to Windows. paguro's seal is
created **outside** BitLocker's protector API, against the PCR values present when
`paguro.efi` runs, and **it does not seal the VMK** — it seals `D`, one of three
inputs to the key that unwraps it.

**PCR selection: 0, 2, 4, 7, and 12.**

| Attacker move | Caught by |
|---|---|
| malicious DXE driver or option ROM | PCR 0 / 2 |
| an EFI application chainloading `paguro.efi` | PCR 4 — its own measurement lands first |
| substituted `paguro.efi` | PCR 4 |
| Secure Boot disabled, or a key added to `db` | PCR 7 |
| tampered `paguro.ini` | PCR 12 (§The ratchet) |

PCR 4 is measured whether or not Secure Boot validates, so it alone would catch a
substituted loader; PCR 7 is included to match Windows' own profile.

**What the policy does not catch:**

- **A CMOS clear that removes a supervisor password.** Vendors preserve
  `PK`/`KEK`/`db`/`dbx` and the `SecureBoot` value across a settings reset, so
  PCR 7 does not move. PCR 1 does, and PCR 1 is in neither profile.
- **A MOK enrolment**, on newer shim, which measures the MOK list into PCR 14
  precisely so that enrolment does not break BitLocker.

That is the standard limit of TPM+PIN against firmware access, and BitLocker is
exposed to it identically. It is closed for the key material that matters by the
next section, not by PCR selection.

**PCR 11 differs between the paths.** `bootmgr` extends it after unsealing;
in the Linux path `bootmgr` never runs. Seal against what *this* path measures.

#### Every standing rung requires the passphrase

> **No standing rung that paguro creates releases the VMK on the strength of stolen
> machine state alone. The passphrase is an input to every derivation, so the best
> any attacker can reach is an offline dictionary attack.** (The volume's own
> recovery key is BitLocker's rung, not ours, and equally strong.)

Two mechanisms are exempt, both bounded, both created by a live authenticated
Windows session — which already holds the key:

| | Why it is not a hole |
|---|---|
| `setupTPM` | staged by Windows from the VMK its own protector yields. One boot, then gone |
| the PIN bypass | written by a **logged-in** Windows session, sealed to the same PCRs as the TPM rung, expired by the TPM clock |

The property that survives both: **nothing an attacker can steal from a
powered-off machine is sufficient.**

**Convention: `HMAC(key, message)`; the secret is always the key.**

```text
-- eagerly, before any rung is attempted --
if B absent:  B = secure_random(32)
              store NV | BOOTSERVICE_ACCESS
else:         B = read()

-- per attempt --
pass_hash = bitlocker_stretch(password)

env  = tpm       : HMAC(B, "paguro/env/tpm"
                          || TPM2_Unseal(auth))
       setupTPM  : HMAC(S, "paguro/env/setup"
                          || H(paguro.ini))
       passphrase: "paguro/env/passphrase"
                   # a public constant, deliberately

       where auth = HMAC(pass_hash, "paguro/tpm-auth")

root_gate = HMAC(env, "paguro/rootgate"
                      || salt || encrypted_FVEK_blob)

key  = HMAC(root_gate, "paguro/final"
            || HMAC(pass_hash, "paguro/offlineGate"))
       # TPM-only profile: key = root_gate

VMK  = key XOR wrapped_vmk       # no authentication tag
```

`D` is the sealed payload, `B` a standing firmware secret (the variable
`PaguroB`), `S` the one-shot `setupTPM` secret (`PaguroSetup`), `salt` 16 random
bytes stored beside each wrapped VMK. The labels are part of the interface, with
test vectors (INTERFACES §7).

**XOR, not a cipher.** HMAC-SHA256 yields 32 bytes and the VMK is 32 bytes, so
this is a one-time pad; `salt` keeps it one-time across a BitLocker re-key.

**`bitlocker_stretch`, not PBKDF2.** The loader needs BitLocker's stretch-key
algorithm anyway, for the recovery-password protector, and it runs 0x100000
SHA-256 iterations.

| Factor | Closes |
|---|---|
| `pass_hash` in the key | **TPM bus sniffing** — the LPC/SPI interposer attack that defeats BitLocker TPM-only in minutes. A sniffed `D` opens nothing. Also TPM implementation flaws and any authorisation bypass |
| `B` in the key | **any operating system**: `B` is boot-services-only, so a compromised Windows or Linux can never read it. **Not a physical attacker**: turning Secure Boot off, dumping `B` (or reading the SPI flash directly) and turning it back on restores PCR 7 and leaves `B` known. A firmware supervisor password stops the toggle, nothing stops an SPI read |
| `H(paguro.ini)` in `setupTPM` | a staged transition cannot be unlocked with a rolled-back configuration, though it opens no seal and so gets no PCR 12 check (the passphrase rung attests nothing by design, below) |
| the root gate | an unprivileged reader of the ESP cannot run a dictionary attack, because the FVEK blob lives only on the raw volume |

| Separation | Without it |
|---|---|
| `auth = HMAC(pass_hash, "paguro/tpm-auth")` | sniffing the TPM authorisation yields `pass_hash`, an operand of the final key |
| `HMAC(pass_hash, "paguro/offlineGate")` | `pass_hash` appears raw in two places |
| per-rung `"paguro/env/..."` labels | `env_tpm` with an empty `D` equals `env_setup` |
| `"paguro/rootgate"`, `"paguro/final"` | chained HMACs become ambiguous |

**The root gate binds the encrypted FVEK blob, not a protector entry**, because
the FVEK exists on every BitLocker volume and changes only on a re-key, while a
TPM protector entry is rewritten whenever BitLocker suspends and resumes. It also
hands the loader its attempt order: nothing can test a candidate key except the
FVEK unwrap, so every free and password-derived rung is tried before a TPM
dictionary attempt is spent.

##### No authentication tag, and no convenience check

The VMK is 32 bytes of uniform randomness, so **every wrong passphrase yields a
plausible-looking result.** The first real check is the FVEK unwrap, whose MAC
lives on the raw volume. That closes the threat that actually exists: an
**unprivileged process reading the mounted ESP**, for which a tagged wrapping
would be an offline oracle against a secret normally behind shadow-file
permissions.

> **Do not add a convenience check.** A helpful early *"incorrect password"* and
> an offline oracle are the same object.

##### The TPM object itself

- **Policy is a conjunction**: `TPM2_PolicyPCR` **and** `TPM2_PolicyAuthValue`,
  with `USERWITHAUTH` clear — otherwise an authValue-only path satisfies
  authorisation without the PCRs.
- **`TPMA_OBJECT_noDA` must be clear.** The reason the PIN is an `authValue` rather
  than a hash we compare is that the TPM's dictionary-attack lockout then applies.
  `noDA` switches that off silently.
- **Salted HMAC session, not a password session**, with parameter encryption:
  the session is salted with the SRK's public key (P-256 ECDH), so neither
  `auth` nor `D` crosses the bus in clear. This is load-bearing: `B` is
  readable by a physical attacker, so `D` staying out of a bus sniffer's reach
  is what keeps a phished passphrase useless. An active interposer that
  substitutes the SRK's public key is outside it, as for any TPM use.
- **Nothing lives in the TPM.** The sealed object is a file, and its parent is
  re-created from the TCG-standard storage-key template on each use, so Windows
  and Linux reproduce the same parent without an NV handle (INTERFACES §4; §11
  Q12 asks whether an existing persistent SRK may stand in).

##### Where `B` lives

`PaguroB`, a **boot-services-only** UEFI variable — `NV | BOOTSERVICE_ACCESS`, no
`RUNTIME_ACCESS` — so no operating system can read it at all. That is the whole
of what it protects against: operating systems. Someone with the machine in hand
can read it (the factor table above), which is why the passphrase and `D` carry
the physical case. That matters
because Linux's `efivarfs` makes runtime variables world-readable (`0644`), while
Windows gates them behind `SE_SYSTEM_ENVIRONMENT_NAME`.

**No OS can create one either**, so `paguro.efi` does, on the first boot, from
`EFI_RNG_PROTOCOL`. Firmware bugs exist, so this is verified per machine (§11
Q13); the fallback is a runtime variable plus `efivarfs` mounted `0700`.

**Why firmware and not a TPM NV index:** Windows cannot create NV indices from
user mode (the driver's command allow-list blocks it), and keeping `B` out of the
TPM means a TPM cleared from `tpm.msc` does not also destroy `B`.

### The ladder

| Rung | Factors | Standing? |
|---|---|---|
| `tpm` | TPM (PCR-bound) + `B` + passphrase | yes — the default path |
| `setupTPM` | `S` + passphrase | **no — exactly one boot** |
| `passphrase` | passphrase only | yes. **Opt-in, default off** |
| recovery | the 48-digit key | yes, from the volume's own FVE metadata |

The **PIN bypass** is not a rung: it skips the prompt on a boot the TPM rung
would have unlocked anyway (§The PIN bypass).

**`setupTPM` is a transition, not a fallback.** Its one job is *Windows hands
Linux something for exactly one boot*, and three flows use it:

| Flow | Why Windows stages it |
|---|---|
| install | no seal can exist before `paguro.efi` has run (§Bootstrap) |
| PIN changed from Windows | a new PIN means a fresh `D`, wrapped VMK and `auth` at the loader's PCR values; staging keeps that on the Linux side, and does not depend on `TPM2_Create` being reachable from Windows (§11 Q12b) |
| TPM path broken — `dbx`, MOK enrolment, firmware update | nothing is left for a Linux boot to arrive through |

**So the standing answer to "the TPM broke" is: boot Windows.** §4.6's pre-flight
usually notices *before* the reboot and stages it without the user meeting a
failed unseal.

| Firmware secret | Variable | Attributes | Lifetime | Written by |
|---|---|---|---|---|
| `B` | `PaguroB` | `NV \| BOOTSERVICE_ACCESS` | standing | `paguro.efi` |
| `S` | `PaguroSetup` | `NV \| BOOTSERVICE_ACCESS \| RUNTIME_ACCESS` | one boot — the loader deletes it before handoff | Windows |

`B` must be unreadable by any OS; `S` must be *writable* by Windows. One variable
cannot be both.

**`setupTPM` gets no deadline**, because **a fallback cannot depend on the thing
it is a fallback for** — it exists for boots where the TPM path does not work.

#### Is `setupTPM` a TPM bypass?

It confers nothing. **An attacker with Windows admin already holds the VMK**:
`manage-bde -protectors -get C:` reveals the recovery password, and the volume is
unlocked while they are there. And it is loud — staging one with a different PIN
makes the owner's PIN stop working at the next boot.

Requiring Windows to prove possession of a secret from a previous Linux boot was
considered and rejected: the case that needs `setupTPM` most is the one where
Linux boots have stopped succeeding.

#### The passphrase rung, and why it defaults to off

**It attests nothing, by design.** No PCR is checked and `env` is a public
constant, so a tampered configuration takes effect on this rung. Binding the
configuration into it would defend nothing, because **the attack is phishing, and
phishing does not need the unlock to succeed** — a substituted loader captures the
passphrase and shows an error. BitLocker's password protector does not attest the
boot chain either.

**It defaults to off because it is the one standing rung a phished passphrase
opens by itself.** With it off, a phished passphrase still needs `D`, which only
the TPM releases, and only to the genuine loader at the original PCR values. A
physical attacker can learn `B` (SPI read) and phish the passphrase, but cannot
run their own code at the loader's PCR 4, so `D` stays in the TPM. **That makes
TPM parameter encryption load-bearing**: without a salted session with
response encryption, `D` crosses the TPM bus in clear during a genuine boot and
a bus sniffer completes the set. (The root gate still stops an *unprivileged*
attacker; the physical attacker has the raw volume.)

**Leaving it off is nearly free, because Windows is the repair channel.** The
image lives inside C:, so paguro's VMK *is* Windows' VMK — and Windows' own
protector is untouched by an NVRAM clear, for the same reason the clear was
silent: PCR 7 did not move.

```text
firmware cleared, Linux will not start
  -> boot Windows       BitLocker opens normally
  -> paguro tool        obtains the VMK via Windows'
                        own protector, re-runs the
                        bootstrap (sec.7)
  -> restart into Linux fresh B, fresh seals
```

No recovery key and no data loss; the user needs only their Linux passphrase —
the factor no attacker and no firmware reset can supply. **Native Windows staying
boring is the recovery channel as well as the safety property.**

The dependency this names: **Linux's recoverability assumes Windows is present
and bootable.** Uninstall, growth and the VM assume it already. Someone who wants
Linux to stand alone is exactly who should enable the `passphrase` rung, and the
installer should say so in those words.

### The PIN bypass

*"Restart into Linux"* is clicked from a **logged-in Windows session**. Asking for
the PIN seconds later has no security content, and this removes it without
weakening the ladder:

```text
Windows, on transition
    read the TPM clock
    write tpm_pin_bypass_seal.bin
        deadline | wrapped VMK | sealed object
        sealed to PCR 0/2/4/7/12 with
        PolicyCounterTimer(clock < deadline),
        empty authValue
    set BootNext, reboot

paguro.efi
    unseal D -> VMK = wrapped VMK XOR D, no prompt
initrd
    delete the file
```

**It cannot be reached in any state where the TPM rung would fail**, because it is
sealed to the same PCRs; and being sealed to **PCR 12**, it cannot steer anything.
**It skips a prompt and does nothing else.**

**The TPM clock, not the RTC.** `GetTime()` is settable by anyone with firmware
access — exactly the attacker a deadline bounds. The TPM clock is monotonic and
`TPM2_PolicyCounterTimer` lets the **TPM** enforce the deadline, which is what
makes the file inert at rest: after expiry it opens nothing, whatever copies
exist.

> **Refuse when `TPMS_CLOCK_INFO.safe` is not set.** The TPM persists its clock
> lazily, so after an unexpected power loss it can have moved backwards, and
> `safe` reports exactly that.

**If Windows cannot create the sealed object** (§11 Q12b), Linux pre-seals a
`tpmTimeSecret` each boot (policy PCR 0/2/4/7/12, no `authValue`) and leaves it on
the encrypted volume for Windows, which then writes
`deadline | VMK XOR HMAC(tpmTimeSecret, created_tpm_time)`. The timestamp
authenticates itself as a derivation input — but the loader must **also compare it
explicitly**, since a stale entry still yields a valid key. Binding PCR 12 rotates
the secret on every configuration change for free.

### What lives where

```text
ESP  \EFI\paguro\
  shim<arch>.efi, mm<arch>.efi   a distribution's signed
                                 shim + MokManager, unchanged
  paguro.efi
  paguro.ini                configuration only
                            ratcheted WHOLE
  <volume-guid>\            one per NTFS volume unlocked
    tpm_seal.bin            PCR selection | wrapped VMK
                            | salt | sealed obj
    setuptpm_seal.bin       wrapped VMK | salt
    passphrase_seal.bin     wrapped VMK | salt
    tpm_pin_bypass_seal.bin deadline | PCR selection
                            | wrapped VMK | salt | sealed obj

firmware
  PaguroB           32 bytes, NV | BOOTSERVICE_ACCESS
  PaguroConfigHash  32 bytes, SHA-256 of paguro.ini
  PaguroSetup       S: one-shot, runtime, Windows-written
  PaguroTpmBroken   1 byte, runtime: the seal no longer
                    matches (set by the loader)

paguro.ini
  [Paguro]      version, the default entry
  [Boot.<name>] volume; root; efi_disk + efi,
                or efi_file
  [UI]          variant, mode, keyboard layout
  [TPM] [SetupTPM] [Passphrase]   enabled = 0 | 1
```

> **One rule: the `.ini` is configuration; crypto material is in `.bin` files.**

**The PCR selection is crypto material too**, so it lives in each seal file rather
than in the `.ini`: a wrong value fails the policy digest instead of needing a
parser to trust it. Seals sit in a directory per volume, so entries on different
NTFS volumes, even on different disks, each unlock with their own.

That rule is what makes the ratchet simple. PCR 12 is extended with
`H(paguro.ini)` — the whole file, no exclusions — which is non-circular only
because the TPM object, whose policy names PCR 12, is not inside the file.

**The blobs are inert at rest**, which is why the unencrypted ESP is the right
place: a sealed object is encrypted under the TPM's storage seed, and a wrapped
VMK needs the passphrase. **A stale `tpm_seal.bin` is useless on its own** — a PIN
change moves the derived key, so wrapped VMK and sealed object only work as a matched pair,
and using an old pair requires the machine anyway.

**No TPM → no `tpm_seal.bin`.** The loader falls through to whatever BitLocker
holds, which is parity: a TPM-less BitLocker volume already demands a secret at
every Windows boot.

### `paguro.ini` and its hash in firmware

One text file, **no signature**. Integrity is a SHA-256 of the whole file held in
the runtime variable `PaguroConfigHash`, which both Linux (root) and Windows
(admin) can rewrite, and **compared only under Secure Boot**: with Secure Boot
off the loader itself can be substituted, so the comparison would protect
nothing, while the ratchet below binds the TPM rung either way.

**Hashing the whole file keeps the parser out of stage 1**: read, hash, compare,
then tokenise. And **no key is involved** — a signature would put a verifier in
stage 1 and a private key in the hands of every writer of the file. The firmware
variable replaces a secret with a privilege the platform already enforces.

| | Blocked by the hash? |
|---|---|
| drive pulled, edited elsewhere | **yes** — no NVRAM write without the machine |
| live USB with root on this machine | no — it can write `efivarfs` |
| rollback to an older file and hash | no — nor would a signature |

The live-USB case is narrower than it looks: a changed `.ini` moves PCR 12, so the
TPM rung fails regardless, and protector material is self-validating. What remains
is feeding the parser — pre-key, in a process holding nothing — and the parser is
hardened for exactly that reason.

**Rollback** is closed by neither a signature (an old file carries a valid one)
nor the ratchet (an old file produces its own matching PCR 12). Only a
**monotonic TPM NV counter** bound into the seal policy closes it (§11 Q12).

**Hash variable absent under Secure Boot** — NVRAM cleared — means `B` is gone
too, so the TPM rung is dead regardless: the loader goes straight to recovery,
which offers exactly the rungs that do not need `B`, says the boot is unattested,
and points at §7's repair.

**Grammar**, frozen (INTERFACES §3.1): `[section]`, `key=value`, `#comment`; no
includes, continuations, escapes or interpolation. Capped at 64 KB, read into a
buffer one byte larger so the last byte is a permanent NUL. Unknown keys in a
known section and duplicate keys are errors, so typos are loud.

**Writes**: write `paguro.ini.new`, update the hash, rename; keep `paguro.ini.bak`
for the *writer's* rollback during a rename. **The loader never reads `.bak`** —
the hash covers only the primary, and a primary that hashes correctly but fails to
parse goes to the *Configuration is not valid* screen. The file's header comment
says it is not hand-editable and names the one command that edits it.

### The ratchet and the two taints

```text
PCR 12  <- extend with SHA-256(paguro.ini)   LOAD TAINT
PCR 12  <- extend with a fixed sentinel      BOOT TAINT
```

**PCR 12 is always extended before any rung is tried** — with `H(paguro.ini)` when
`tpm_seal.bin` exists, and with the sentinel otherwise, which poisons PCR 12 for
the rest of the boot. Deleting a seal file therefore cannot skip the ratchet. (On
the very first boot there is no `.ini` and no seal, so it is the sentinel.)

**The boot taint** is extended the moment a key exists, whichever rung supplied
it — `bootmgr`'s PCR 11 pattern — so nothing later in the boot can unseal again.

> **The taints do the security work.** A tampered `.ini` produces a PCR 12 the
> sealed object's policy does not match; the unseal fails and the tampered value
> never acts on a key. That is enforced by the TPM, not by a check in our code —
> and it is why the configuration needs no signature.

**Changing configuration forces a reseal**, and should: that is the class of
change the ratchet exists to catch. **Adding or removing a protector does not**,
because protectors are files.

**PCR 12 is computed, never read.** The loader verifies PCR 12 is all zeros before
its first extend and refuses otherwise, so the value to seal against is
deterministic and a machine where firmware already touched PCR 12 is detected
rather than silently mis-sealed.

**During a PCR-policy rotation** — a firmware update, say — an old and a new seal
may coexist until the new one has succeeded once.

### Protector material is self-validating

| Wrong | Fails at |
|---|---|
| sealed object | `TPM2_Unseal` |
| wrapped VMK | the FVEK unwrap's AES-CCM MAC |
| PCR selection | the policy digest |
| salt | the derived key, then the same MAC |

An attacker can forge protector files freely; they cannot make one succeed.
FVE-sourced protectors — which Windows owns and nobody signs — are merged under
the same rule, **bounded in count and restricted to known types**, so a flood of
entries is a nuisance rather than a compromise.

### Bootstrap: how the first boot gets a key

The seal can only be made where the PCR values are known, and they are only
reliably known by being there: PCR 4 during setup measures Windows' boot chain,
not `paguro.efi`, and `TPM2_Create` may not be reachable from Windows at all. So
the first boot bootstraps from the passphrase and seals itself.

```text
installer (Windows)
    obtain the VMK via Windows' own protector
    prompt for a passphrase -> pass_hash
    PaguroBootstrap (firmware variable)
      <- volume GUID || salt || VMK XOR
         HMAC(pass_hash, "paguro/bootstrap" || salt)
    set BootNext, reboot
    -- no paguro.ini is written --

first boot (paguro.efi)
    delete the Boot#### entry -- first action
    no .ini: unlock the payload's volume,
      take \paguro\'s only disk or UEFI image
    prompt, unwrap the VMK
    B <- EFI_RNG_PROTOCOL, store as PaguroB
    D <- EFI_RNG_PROTOCOL
    author the first paguro.ini
    TPM2_Create  sealed = D
      policy PCR 0/2/4/7/12 AND AuthValue,
        PCR 12 computed from that .ini's load taint
      auth   HMAC(pass_hash, "paguro/tpm-auth")
    write nothing; forward the .ini and the seal

first boot (initrd)
    write paguro.ini and tpm_seal.bin
    set PaguroConfigHash
```

**The first boot never parses unverified bytes**: there is no `.ini` to read, and
the one it forwards is the one it authored. **The bootstrap wrapping is
single-factor, and that is sound only because there is no oracle** — `B` cannot
come from Windows, residue may outlive deletion, and none of it can be tested
against a guess.

**The loader seals; the initrd writes files.** `paguro.efi` already carries
`StartAuthSession`, `PolicyPCR`, `PolicyAuthValue`, `Load` and `Unseal`, so
`Create` is one more command — and doing it there means the initrd needs no TPM
work at install and **`pass_hash` never crosses into Linux**. PCR values are
still forwarded, as on every boot, for later re-seals.

**If the first boot never happens**, the Windows task tears the bootstrap down on
its next start; `paguro.efi` deletes it as its first action, found through
`BootCurrent`, even when its payload is malformed. Setup says plainly
that the install is not finished until Linux has booted once.

**Fallback: the BitLocker recovery key**, which the loader can use unaided. Not the
default — hunting for it mid-install is enough friction to make people abandon.

#### What crosses the handoff

A header and typed records, each bounded; an unknown or duplicated record is
refused (INTERFACES §8):

| Record | Carries | Why Linux needs it |
|---|---|---|
| `VOLUME` | the NTFS partition: GUID, first LBA, length | which device to build the views over |
| `VMK`, `FVEK`, `FVE_LAYOUT` | the keys, and the metadata regions, boot-sector relocation and `encrypted_size` (absent on an unencrypted volume) | the decrypted volume's segment table (§4.3) and the module's reserved ranges |
| `B` | 32 bytes | re-sealing without a reboot |
| `PCRS` | PCR 0/2/4/7 as the loader read them | the same |
| `CONFIG` | the verified `paguro.ini` bytes | everything else Linux reads from the configuration |
| `IMAGE` | the chosen entry's root, and its `efi_disk` or `efi_file`: role, name, MFT record and sequence number | the files to claim — identities, never locations; the module derives the extents itself |
| `STATE` | hibernation, dirty bit, configuration unverified, recovery path | read-only views, and what the screens say |
| `RUNG` | which rung unlocked | re-sealing after a non-TPM rung, clearing `PaguroTpmBroken` |
| `PROVISION` | new sealed object, wrapped VMK, salt | only on a provisioning boot |

The FVEK and layout build the decrypted volume (§4.3), so booting Linux needs no
second FVE parse. (Authoring the VM's substituted metadata does need one; it runs
in userspace, and a wrong result only stops the VM booting.) `pass_hash` never
crosses.

**Mechanism:** `EfiRuntimeServicesData` pages (never `EfiBootServicesData`, which
the kernel reclaims), located through a configuration table, read once by a small
handoff driver and zeroed — how that driver reaches the initrd is still open
(§11 Q31). **Not** the enforcement module, which never holds key
material. **Never** on the kernel command line, in a persistent variable,
in diagnostics or in a file.

### Changing the PIN, and firmware updates

| Changed from | Mechanism | Takes effect |
|---|---|---|
| **Linux** | trial session computes the policy digest from the PCR values the loader recorded; seal a fresh `D'` with the new `auth`; rewrite `tpm_seal.bin` | immediately |
| **Windows** | stage a one-shot `setupTPM` | the next Linux boot |

Linux never needs to read a PCR: by the time userspace runs PCR 4 carries the
next image and PCR 12 is capped, but sealing a *fresh* `D'` against the
**recorded** digest sidesteps recovering anything. The initrd records the
loader's PCR values **every boot**, so they are never stale; they are public,
and tampering with them costs at most one failed unseal.

**Firmware updates**: §4.6's pre-flight compares the firmware-extended PCRs and the
`dbx` portion of the event log against the recorded values, and stages `setupTPM`
before the reboot. If the change lands between pre-flight and boot, the loader
sets `PaguroTpmBroken` and offers *Start Windows*; the Windows app picks the flag
up and stages the same thing.

### Unlocking: escalation, not selection

| Rung | Behaviour |
|---|---|
| nothing | try every input-free path silently — the PIN bypass, a clear key |
| one secret | a **short list labelled by attempt cost** (§4.1). Within any row, free protectors before the TPM |
| recovery key | always offered, never required first |

**A TPM failure never removes the other rungs**; lockout or a policy mismatch
greys one row.

**Always offer "Start Windows" before the recovery key** — most people who reach a
BitLocker prompt do not realise their Windows is fine.

> **"Start Windows" sets `BootNext` and resets. It never chainloads.** Loading
> `bootmgfw.efi` from `paguro.efi` leaves shim's and our authority events in
> **PCR 7**, which *is* in BitLocker's default profile (PCR 4 is not), so Windows
> would demand the recovery key — caused by the escape hatch meant to avoid it.
> **`paguro.efi` never chainloads anything on Windows' boot path.**

### Every parser is hardened; review goes scarcest-first

> **The taints are containment for a bug that got through, never a licence to
> have one.** Secure Boot's premise is that everything up to the loaded image is
> trustworthy code, which puts every parser in `paguro.efi` in scope.

| Parser | Stage | Exposure |
|---|---|---|
| `paguro.ini` | 2 | behind the whole-file hash |
| **FVE metadata** | **3** | **plaintext on disk, rewritable with physical access, and the key is still obtainable — the one that matters** |
| **protector merge** | **3** | FVE-sourced entries are unsigned; bound the count, restrict the types |
| `.bin` protector files | 3 | fixed binary layouts, no parser to speak of |
| NTFS | 4 | follows the boot taint; crafting input needs the VMK |
| PE verification | 4 | shim's |

**Recovery never parses `paguro.ini`.** It hashes it, and reads only the `.bin`
files and FVE metadata — so a known-bad configuration is never tokenised on the
one path that is about to receive a typed secret.

**Containment for the FVE parser**, which has good structural bounds and should
use them: bound every read to the three metadata regions named in the
fixed-location header; walk the TLV list against a hard schema and skip unknown
types by declared length; fixed arrays, capped counts, no allocation derived from
content; and **treat the three copies as a cross-check** — structural
disagreement is a reason to refuse, not to pick one.

### The TPM-only profile

Opt-in, never default, and the opt-in screen shows this list.

With no PIN the loader unseals unconditionally and hands the key to the initrd,
so an induced failure could otherwise reach a shell with the volume open. **The
shell stays available — as WinRE does — but arriving there costs the key:**

```text
any shell in the initrd (emergency, rescue, debug, panic)
    1. close every view and the decrypted volume
       (dm remove: dm-crypt wipes the key it held)
    2. wipe the handoff copy, B and anything unsealed from memory
    3. cap PCR 12 (already capped by the loader's boot taint;
       extended again so nothing depends on that alone)
    4. then the shell
to reopen: the recovery key or a passphrase protector, typed in that shell
```

After `switch_root` a shell is the operating system's own login, authenticated
by it as usual. The **recovery entry is gated the same way** — it is a
legitimately signed permissive path, so signature checking cannot distinguish
it.

| Obligation | Enforced by |
|---|---|
| a UKI as the next image, never an editable boot menu | the entry's `efi` or `efi_file` names a UKI |
| `lockdown=confidentiality` | signed kernel command line |
| SysRq disabled, no KDB/KGDB | kernel build config |
| IOMMU forced, Thunderbolt security | signed kernel command line |
| no listening network services | the profile's unit set |

Distros enable lockdown in `integrity` mode under Secure Boot, not
`confidentiality`, so it must be set explicitly. **None of this applies to the
default TPM+PIN configuration.**

### Configurations that must be refused

**A TPM seal over an unencrypted volume.** The chained image is then a plaintext
file anyone can swap, so attesting `paguro.efi` attests nothing. The general
rule: **refuse any configuration whose security properties are illusory** — a UI
reading "TPM protected" over a swappable plaintext image is worse than one
honestly reading "unprotected".

### LUKS inside the image

**Windows is trusted everywhere in this design** — it holds the VMK, hosts the
repair channel, runs the minifilter and can read the image offline. A LUKS
passphrase entered in the Linux boot, which Windows never sees, is the only
construction here that makes Linux's data opaque to a compromised Windows. On an
unencrypted C: it is also the only way to encrypt Linux at all.

```text
image
  +-- nested ESP (FAT32, plaintext)
  |     <- the loader finds the next image here, unchanged
  \-- LUKS container
        \-- ext4 root
```

The bootloader needs no change; `cryptsetup` opens LUKS on view A. **It is the
distribution's business** — symmetric with *disk encryption is Windows'
decision* — so it costs documentation rather than code.

Costs: a LUKS root **cannot be mounted by WSL2** without `cryptsetup` inside WSL
and a passphrase at every start, so the installer should say this tier trades
away the WSL interop; and **double XTS** when BitLocker is also on (§11 Q15).

### The VM boot

A BitLocker-protected C: **cannot TPM-unseal inside the VM**: OVMF measures a
different chain, and Windows' sealed blob is bound to the physical TPM's storage
seed. Left alone, every VM boot lands on the recovery prompt.

| Approach | Why not |
|---|---|
| suspend BitLocker | writes the VMK in the clear; weakens native boot |
| `manage-bde -off` | hours of rewrite, removes protection |
| present C: decrypted | the guest believes it is unencrypted; *"turn on BitLocker"* becomes a double-encryption path |
| add a real protector with `manage-bde` | modifies Windows' BitLocker configuration, which the design never does |
| vTPM | Windows would see a different chip and re-provision every boot, in both directions, in one shared registry |
| TPM passthrough | `TPM2_Clear` from the guest destroys both seals; the guest pollutes host PCRs |

**The design: substitute the FVE metadata, unlock with a synthetic startup key.**
The VM's disk sandwich (§4.3) splices the volume's three FVE metadata regions,
as `dm-linear` segments over a loop device, from a **static buffer**
carrying one extra VMK entry of **ExternalKey** type, and QEMU presents the
matching `.BEK` on a synthetic removable device, hot-unplugged once the guest has
booted. **Nothing is written to the user's volume.**

```text
substituted metadata
    + VMK entry, id = G, type ExternalKey
      containing AES-CCM(K_ext, VMK)
synthetic removable
    {G}.BEK -- FVE header + external key entry
              (0x0009), holding K_ext
```

The initrd builds the buffer — a userspace FVE parse and re-serialisation, where a
wrong result only means the VM does not boot. The module is not involved.

**The guest does its own crypto with the real FVEK**, so
what lands on disk is byte-identical to a native boot's writes, and the guest's
view of itself is truthful: *protected, startup key.*

**The format is not officially published, but it is verifiable.** libbde's
specification is thorough; the `.BEK` header is essentially the FVE metadata
header, so authoring both is one piece of knowledge; and libbde and dislocker give
a **CI oracle** — synthesised metadata plus `.BEK` in, correct VMK out. The `.BEK`
must be on *removable* media, because `bootmgr` only searches there; the open
question is that automatic search at boot (§11 Q9).

**Guest writes to BitLocker's own regions are absorbed, never passed through**
(§11 Q24). The substituted set is every sector BitLocker owns, not only the
three metadata blocks: the volume header with its metadata pointers, the
relocated boot sectors, the three metadata regions, and the further region
Windows 10+ keeps beside them. All of it is served from the per-session
substitute, and guest writes to it land in a per-session overlay: the guest
reads back what it wrote, and **nothing reaches the disk**.

| Guest action | Result |
|---|---|
| suspend for an update, add a clear key | works in the session; the next VM boot starts from the real metadata again — as the suspend's reboot count would have |
| add or remove a protector, change the PIN | appears to work and is **not kept**; the host notices the write and says so: *BitLocker changes belong in native Windows* |
| **relocate metadata** | the new blocks are ordinary NTFS-allocated sectors and land harmlessly; the pointers to them live in the volume header, which is in the absorbed set — so native Windows keeps its old, intact metadata |

That makes the bound hold for FVE metadata too: **nothing the guest does to
BitLocker's structures can change what native Windows boots from.** The cost is
that BitLocker management is a native-boot activity, which it already was
(no TPM in the VM).

Why absorb rather than `EIO`: the writer is `fvevol.sys`, below NTFS, and how
it reacts to a failed metadata write — retry, volume offline, bugcheck — is
unknown; absorbing keeps the guest stable and is equally safe for the disk.
`EIO` stays available as a test mode. **The minifilter cannot help here**: it
sits above the filesystem and `fvevol.sys` below it.

**The VM gets no TPM.** Windows Hello, Credential Guard and in-guest BitLocker
management are unavailable in VM sessions; they were never going to work against
a different TPM.

### The machine MOK key

One key pair per machine, generated at install, signs everything paguro-side that
shim must accept: `paguro.efi`, every DKMS build of the kernel module, and locally
built UKIs (§4.1). **It is needed on both sides** — by the Windows tool for every
later `paguro install`, since a new distribution needs its module and UKI signed,
and by each Linux image for its own kernel updates — so each holds a copy
(INTERFACES §11.6):

| Copy | Where | Opt-in protection |
|---|---|---|
| Windows | `C:\ProgramData\paguro\mok\`: admin-only, inside the BitLocker volume | wrapped by the boot passphrase, or TPM-sealed |
| each Linux image | `/etc/paguro/mok/`: root-only, inside the image | wrapped by the boot passphrase, or sealed to PCR 11 as systemd-stub extends it, a value Windows never reproduces |
| Linux at runtime | root's kernel keyring, written to a `0600` file on `tmpfs` only while `sign-file` or `sbsign` runs | — |

**Never on the ESP.** A private key wrapped by the boot passphrase is an offline
guessing oracle for that passphrase — it can always be checked against the public
certificate — so it must only be readable by whoever can already read the
encrypted volume. On the ESP any unprivileged Linux process could run the
dictionary attack the root gate exists to prevent. For the same reason the wrap
uses its own KDF, Argon2id with its own label (`paguro/mok-wrap`), which makes
the oracle expensive rather than merely present.

**What each option protects, stated at its strength.** The passphrase wrap
protects the key at rest, and against a compromised Windows until the passphrase
is typed into it — which installing another distribution asks for. The Windows
TPM seal protects only against the disk being read elsewhere: any admin process
in a running Windows can unseal it. The PCR 11 seal keeps the Linux copy from a
Windows reading the image offline. None of them outranks the rest of the design:
PCR 11 covers the measured UKI, not the mutable root, so a compromised Windows can
still modify Linux userspace inside the image. Privileged compromise of either OS
is machine compromise (§8); the LUKS tier is the answer for anyone who needs
otherwise.

### A standing seal, not a one-shot one

Sealing only at each transition would make **Linux unbootable whenever Windows
is** — precisely when a second OS is most valuable. The standing seal keeps Linux
bootable from the firmware menu; the PIN bypass adds convenience on top without
becoming a dependency.

---

## 6b. Uninstall — six deletions and a reboot

§1 sells reversibility, and reversibility is one of the reasons the simpler
partitioned design was rejected — so it is specified here and verified by an
acceptance test, not asserted.

**The property that makes reversal tractable: install is purely additive.**

| Item | Added or modified |
|---|---|
| `\EFI\paguro\` on the ESP: shim, MokManager, `paguro.efi`, `paguro.ini`, the `*_seal.bin` files | added |
| `PaguroB`, `PaguroConfigHash`, `PaguroSetup`, `PaguroTpmBroken` in firmware | added |
| the machine key's certificate in `MokList`; its private key on C: | added |
| the image file(s) on C:, wherever `paguro.ini` names them | added |
| the minifilter | added |
| transition app, scheduled task | added |
| `Boot####` entry | added |
| `BootOrder` | **modified** — our entry inserted; removing it leaves the rest untouched |

Nothing existing is overwritten. There is not even a BitLocker protector to
remove — the extra VMK entry exists only in the view QEMU hands the guest (§6).

That matters because the standard demands on an uninstall protocol — an ownership
record of prior values, a rule for preserving later legitimate changes — **assume
the installer overwrote something.** It doesn't. So uninstall is *delete what is
present*: idempotent, re-runnable, and safe against partial installs by
construction.

> **Rule, not description:** install may only add. Anything that would require
> modifying existing state needs a different approach, because it would cost the
> property that makes reversal trivial.

What remains to specify is smaller than it first appeared, but not nothing:

| Needed | Why |
|---|---|
| **an ordering** for revocation and removal | the driver must stop enforcing before the image is deleted; the boot entry must go before the loader |
| **the driver's two-phase removal** | a minifilter that refuses to unload (§4.4, by design) needs a reboot with its service disabled before it can be removed |
| **resumability** | interrupted removal must be re-runnable — which the additive property already makes safe, but the tool must actually be written that way |

Partial-state cases, most of which the additive property answers on its own:

| Case | Answer |
|---|---|
| install only partly completed | remove what is present; each step is independent |
| Linux no longer boots | none of the removal steps are Linux-side |
| driver loaded and refusing to unload | the two-phase reboot above |
| user changed BitLocker configuration after install | nothing to restore — we never changed it |
| removal itself interrupted | re-run it |

**Order of operations, as a starting point** (not yet a specification):

```text
1. Windows  -- remove the scheduled task and
              transition app
2. firmware -- remove the Boot#### entry,
              restore BootOrder
3. ESP      -- remove \EFI\paguro\;
              delete PaguroConfigHash, PaguroSetup,
              PaguroTpmBroken and the MOK private key
4. driver   -- mark for removal, reboot
5. driver   -- remove from the DriverStore
6. disk     -- delete the image file(s)
```

Step 4 is the only thing that cannot be done live, which makes uninstall a
two-phase operation with one reboot — hence a resumable tool rather than a
script.

**`PaguroB` cannot be deleted from any operating system**, because it is
boot-services-only (§6), and **a `MokList` entry is removed only through
MokManager.** Uninstall therefore offers one final boot through our shim, before
step 3 removes it: the Windows tool queues the machine certificate in shim's
`MokDel`, MokManager asks once to confirm, and `paguro.efi`, finding a one-shot
runtime uninstall request, deletes `PaguroB` and resets straight back to Windows.
Skipped, `PaguroB` stays behind as 32 inert bytes and the certificate as a trust
anchor for a private key that no longer exists; the uninstaller says so.

The surface is six deletions and a reboot, and the additive property means none of
them can leave the machine in a state worse than "partly removed".

#### Uninstall is an acceptance test, not polish

Reversibility is one of the reasons the simpler partitioned design was rejected
(§1), so it has to be **verified rather than asserted**:

```text
fresh Windows image
  -> install paguro
  -> use it
  -> update both operating systems
  -> grow the image
  -> induce one failed boot
  -> uninstall
  -> diff machine state against the pre-install snapshot
```

The criterion is **not** "Windows still boots". Everything attributable to paguro
must be gone:

| Surface | Checked |
|---|---|
| `Boot####` entries and `BootOrder` | ours removed, others untouched |
| ESP contents | `\EFI\paguro\` gone, nothing else changed |
| DriverStore | the minifilter, and its service registration |
| services and scheduled tasks | transition app, repair hook |
| BitLocker protectors | **none added** under §6, so none to remove — assert that |
| BCD | unmodified |
| Secure Boot state, `MokList` | as found: the machine certificate removed if the final boot ran |
| TPM objects | **none persisted** — the parent is re-created each boot and sealed objects are files — assert that |
| firmware variables | `PaguroConfigHash`, `PaguroSetup`, `PaguroTpmBroken` gone; `PaguroB` gone if the final uninstall boot ran, otherwise documented as 32 inert bytes |
| image files | deleted, space returned |
| registry | `MountedDevices` and anything else touched |

Running this **after** both operating systems have updated is the part that
matters — an uninstaller that only works against the machine state it was written
for is not an uninstaller.

---

## 7. Drift and the repair hook

A scheduled task at Windows startup. Records build number and ESP file hashes;
reconciles when they differ.

| Drift | Cause |
|---|---|
| `\EFI\paguro\` removed, ESP rewritten | feature updates run `bcdboot` |
| **our shim revoked** | an SBAT or `dbx` update revokes that distribution's shim build. Install the distribution's replacement; our trust is the machine key, so nothing else changes |
| a `*_seal.bin` removed from the ESP | same. **Convenience, not access**: the TPM rung is lost until repaired, but recovery and the other rungs still work |
| boot order reset, entry demoted | same |
| Fast Startup re-enabled | feature updates reset it |
| TPM seal broken | firmware update changes PCR 0 |
| **TPM seal broken, Secure Boot untouched** | a **`dbx` revocation update** — shipped through Windows Update, so a *routine* cause. PCR 7 moves; the pre-flight (§4.6) usually predicts it, the hook stages a one-shot `setupTPM`, and the next Linux boot re-seals |
| **TPM seal broken after a MOK change** | the machine key is enrolled once, at install (§4.1); a rotation or another tool's key changes `MokList`, which shim measures into PCR 7 or 14 depending on version. Same handling |
| **`PaguroB` missing from firmware** | NVRAM cleared — dead CMOS battery, board replacement, firmware recovery, or a supervisor-password reset. **The `tpm` rung is dead** and `PaguroConfigHash` is gone with it; repair is one Windows boot re-running the bootstrap (below), and the hook should offer it unprompted |
| BitLocker state changed | user action or policy |
| **clear key removed, protection activated** | the user signed in with a Microsoft or Entra account — **provision the seal now**, or boot silently becomes boot-with-a-prompt for no visible reason (§6) |
| **Linux password changed without the seal following** | PAM hook failed — must be surfaced, not logged |
| an image relocated | native defrag — harmless; the next Linux boot re-derives the map |

**Auto-repair silently:** re-copy shim, MokManager and the already signed
`paguro.efi`, re-create the UEFI boot entry, restore boot order — all
byte-identical restorations from saved copies, needing no key.

**Windows does not re-seal; it stages.** Sealing needs PCR values only the loader
can read, and `TPM2_Create` may not be reachable from Windows user mode at all.
So the task stages a one-shot `setupTPM` and the next Linux boot re-seals. That
boot unlocks through `setupTPM`, which is exactly its job.

**The one exception is `B`, and the repair is to re-run the bootstrap.** When
NVRAM has been cleared, `PaguroSetup`, `PaguroConfigHash` and usually `MokList`
are gone with `PaguroB`, so the cleanest repair is exactly what the installer
does:

```text
obtain the VMK via Windows' own BitLocker protector
    (unaffected -- PCR 7 did not move)
MokList lost: queue the machine key in MokNew again
prompt for the Linux passphrase -> pass_hash
PaguroBootstrap (firmware variable)
  <- volume GUID || salt || VMK XOR
     HMAC(pass_hash, "paguro/bootstrap" || salt)
BootNext, reboot
```

from which §6's bootstrap proceeds unchanged: `paguro.efi` generates a fresh `B`,
seals, and the initrd rewrites the seal files and the hash. **No new mechanism** — recovery from
a firmware reset is the install path run a second time, which is why it is worth
keeping that path warm rather than treating it as one-shot setup code.

Windows touches key material in three places, all from a logged-in session that
already holds the VMK: this bootstrap, `setupTPM` staging, and the PIN bypass. It
is also what makes the `passphrase` rung optional rather than necessary.

**Report, never act:** BitLocker configuration changes; anything touching the
image files. Enabling or disabling encryption is a multi-hour volume operation
never to be started on a user's behalf.

**Verify `paguro.efi` by hash recorded at install**, not merely "is it
signed." A signed-but-different binary is what tampering and partial updates look
like.

Fast Startup state is **reported, not fought** — the transition app makes it
irrelevant.

---

## 8. Scope and limits

**This is for personally-owned machines.**

| Endpoint software | VM boot visible? |
|---|---|
| Plain AV (Defender consumer, ESET, Sophos, university agents) | No — they scan files and processes, not boot posture |
| Defender for Endpoint / CrowdStrike / SentinelOne | Yes — posture telemetry includes Secure Boot and code integrity |
| Intune / compliance-gated access | Yes, and enforced |

Users can check their own tier:
```text
dsregcmd /status         # Intune / Entra enrollment?
Get-Service -Name Sense  # Defender for Endpoint?
Get-Service | ? Name -match 'csagent|SentinelAgent'
```

On a genuinely managed corporate device, running the managed image as a guest
under your own hypervisor is a policy question before a technical one.
**Engineering around an employer's security monitoring is out of scope.**

Note the native boot is unaffected in every tier — stock kernel, Secure Boot on,
nothing loaded. Only the VM session would report differently, and only where full
EDR is deployed.

### Antivirus and EDR

The storage path does not depend on antivirus behaving: the module's range test
holds whatever runs in Windows. What antivirus can cause is noise, slowness, or
a paguro binary being blocked — and the last one is the real risk.

| Where | Risk | Answer |
|---|---|---|
| **paguro's own Windows binaries** | **high.** The service writes firmware variables and boot entries, queues MOK enrolments, and reads the BitLocker recovery password — the behaviour of a bootkit, or of ransomware that abuses BitLocker. EDR heuristics are built to flag exactly that | code-signed binaries (Azure Trusted Signing or an EV certificate) so reputation accrues; false-positive submissions to Microsoft and the major vendors before release; open source and reproducible builds so vendors can look; every sensitive action logged in plain words, and none taken silently |
| native Windows, the image files | medium: on-access and scheduled scans of multi-GB files written by another OS — slow, and a lock held by a scanner at shutdown | a **Defender exclusion** for the image paths, added by the installer with the user's consent and shown in the UI; third-party AV gets the same instructions |
| VM, the image files | low: the minifilter refuses the scanner's opens, so it logs *access denied* and moves on; no `EIO` reaches it | our altitude above antivirus filters (FSFilter Top), so the refusal comes before the scanner sees the file — a Microsoft-assigned altitude is required anyway |
| the minifilter | medium: an unknown kernel driver, and while it is test-signed a guest booted with test signing, which EDR products treat as a risk signal | attestation signing (§12); until then test signing is confined to the VM's synthetic ESP, so the native boot never runs in test mode |
| the ESP | low: firmware scanners (Defender's UEFI scanner, ESET) flag *known* bootkits; a distribution's shim is common, `paguro.efi` is new | the same code-signing and submission path; the machine-MOK signature and SBAT data are visible to any scanner |
| raw disk access for verification | low: some products block `\\.\PhysicalDrive` handles | the service documents the exclusion it needs and degrades to a clear error |

---

## 8b. Installation scope and the WSL on-ramp

### v1 is deliberately narrow

**Every eliminated permutation is worth something when the unacceptable failure
is destroyed user data.** The supported configuration for a first release:

| | v1 |
|---|---|
| Windows | 11, a tested set of builds |
| **edition** | **Pro or better for seamless windows.** Home installs and runs, but cannot host RemoteApp, so Windows applications appear in a full-desktop window rather than as individual ones (§5b) |
| firmware | UEFI, Secure Boot on |
| TPM | 2.0 present |
| **WSL2** | **required** — the install runs there (below) |
| BitLocker | **off**, or XTS-AES encrypted, fully or with a paused conversion — **not** CBC+Elephant, not a region mid-conversion; used-space-only once §11 Q25 is answered, refused until then (§6) |
| disk | single, GPT, with `C:` on it |
| distros | one or two, each installed by its own installer through an adapter (below) |
| GPU | whichever backend reaches its milestone first |
| machines | personally owned (§8) |

Everything outside that is refused at install with a reason, not attempted and
hoped for. Widening happens after the storage gate (§11) has survived, one axis
at a time.

### Install from Windows, through WSL2, with the distribution's own installer

`paguro install <distro>` runs in Windows, and **no distribution installer ever
runs against the real disk, and no ISO is ever booted** (INTERFACES §11.4). A
stock installer on bare metal would see the physical disk with Windows on it, and
a stock live initramfs cannot find its media inside a VHD inside NTFS, or behind
BitLocker. Inside WSL2 the only disk an installer can see is the one we attach:

```text
paguro install <distro>                  (Windows, admin)
  export the host's hardware             PCI/USB/ACPI/DMI IDs
  create a fixed VHD                     diskpart; works on Home
  wsl --mount --vhd --bare               the only extra disk in WSL2
  the distribution's ISO, verified       SHA256SUMS and its signature
  its live system as a container         systemd-nspawn, the VHD its
                                         only real disk, WSLg for the GUI
  its own installer, writing a paguro-ready system
  wsl --unmount; the bootstrap Boot#### entry (§6)
```

**The installer writes the right system itself; there is no step after it.** Its
copy source is an overlay holding only paguro's own packages as real packages —
`paguro` (the kernel module and the initramfs hook) and the Windows VM stack — so
its own initramfs step picks the hook up; its boot loader is configured through
the distribution's own settings never to write `Boot####` entries and to install
to the removable-media path. **paguro picks no drivers and no firmware**: the
hardware export becomes a synthetic sysfs, inside the installer's container only,
so the installer's own detection (Ubuntu's third-party drivers, Debian's firmware
checks) chooses them for the real machine rather than for Hyper-V's synthetic one.

**What the supported list bounds is adapters, not builds**: per distribution,
where its installer reads its source, its boot-loader settings, and a hook if the
package list alone does not reach the initramfs step. A distribution without an
adapter falls back to a scripted bootstrap (debootstrap, `dnf --installroot`,
pacstrap) into the same VHD. Stock images mean stock initramfs code, which is why
the default profile does not rely on *"this initrd has no path that drops to a
shell"* (§6: the PIN is in front of it), and the opt-in TPM-only profile carries
that obligation explicitly.

**The loader has no ISO support.** ISOs are opened in WSL2 at install time; a
Linux that wants one later mounts it from a claimed file with `isofs`.

### One mode: paguro boots distro images

**There is one thing paguro boots — a full Linux install in an image file**, with
its own disk layout, boot loader, kernel, drivers and firmware. That image is a
normal distribution plus one package; paguro supplies the storage and the first
boot loader and gets out of the way.

**paguro does not maintain an operating system.** A paguro-built host running
rootfs images as containers, with our own driver layer and compositor, would put
kernel, drivers, firmware, wifi and hardware support on this project in
perpetuity — §8c's stated long-term risk, adopted deliberately. **A Debian image
carries all of it instead.**

#### Your WSL2 distributions, on the metal

A WSL2 distribution is a rootfs in a VHDX. The paguro host runs it **as a
privileged container**, fullscreen or in a window, so the distribution a user
already lives in under Windows runs natively with the real GPU and full I/O —
and is still there, unchanged, the next time they are in Windows.

```text
paguro boots       the paguro host (fixed VHD, bare ext4, UKI on NTFS)
the host runs      the user's WSL2 ext4.vhdx as a privileged container
```

**The disk is used as is — no conversion.** WSL2's `ext4.vhdx` is a *dynamic*
VHDX (1 TB virtual by default), so it cannot be a raw extent map like the
host's image. It is handled in layers, each doing one job:

| Layer | Job |
|---|---|
| the module | claims the `.vhdx` file like any image (§4.3): its extents are protected in views B and C, whatever runs |
| file exposure | the claimed file appears to Linux as a regular file that can grow (INTERFACES §10.5) |
| `qemu-storage-daemon` | reads and writes the VHDX format — BAT, log replay, allocation on write — and exports a block device |
| the container | mounts the ext4 on it |

Growth is the design's ordinary growth path: ntfs3 extends the file when Windows
is not running; in VM mode the guest extends it and the host claims the new
extents before verifying them against the flushed MFT (INTERFACES §11.3). The
VHDX format stays qemu's job; paguro writes no VHDX code.

**Requirements:** the distribution is shut down in Windows (`wsl --shutdown`,
and no hibernation), and the file is not NTFS-sparse — paguro turns WSL's
optional sparse mode off for the distributions it runs
(`wsl --manage <distro> --set-sparse false`).

**Performance** is WSL2's class, not native: every I/O goes through the VHDX
layer. Anyone who needs full speed installs a stock distribution image instead
(below), which boots directly.

**Fixed VHD is the format for images paguro boots**, because WSL cannot mount a
raw `.img` — it wants `.vhd`/`.vhdx`. A fixed VHD is raw plus a 512-byte footer,
so the payload is contiguous from offset 0 and the extent map is the file's
extents minus the last sector. The same file is a WSL2 disk and a bare-metal
root, with no conversion in either direction, and it still grows by extending
the file and rewriting the footer.

##### Namespaces, and what the boundary is not

Shared network and IPC so the container's applications reach the host's network
and display without plumbing; separate pid, uts and mnt. The host's `/` appears at
`/mnt/parent`, and a shell on the host is immediately reachable.

> **This is a packaging boundary, not a security boundary** — exactly as WSL2 is
> not one. A privileged container sharing pid and mnt can see and signal the
> host's processes. For one user's own machine that is correct; it must not be
> mistaken for isolation.

##### Two choices that should be made explicitly

**Nested session or shared socket.** The container can receive a fullscreen
surface and run its own compositor inside it — preserving the distribution's
desktop environment — or its applications can connect straight to the host's
compositor, which is simpler and cheaper. Both work; the design should pick one
rather than leave it to whoever implements first.

**Where network configuration lives.** The host owns wifi and clock setup, which
is right at install time. A user whose container *is* their daily environment will
look for network settings there — so either the container reaches the host's
`NetworkManager` over the shared bus, or switching to the host's panel is a
documented step rather than a discovered one.

#### The host image is a shipped default, not an architecture

paguro ships a **Debian-based image** so that installing paguro does not mean
installing a distribution. It carries firmware, drivers, a compositor and the
Windows VM, which keeps container images small and makes WinApps entries inside
one into shortcuts to a VM the host already runs.

**It is replaceable.** A user who installs their own Ubuntu into an image gets the
same machine; nothing above the block layer depends on which distribution is in
it. Multi-image support (§2) means both can exist at once, and `paguro install`
adds a third.

> **A trade worth recording: the host is not immutable.** A read-only,
> dm-verity host whose root hash sits in the signed UKI would make the OS as
> trusted as the UKI. A Debian install is not that, and the design accepts the
> loss in exchange for *"Debian maintains the OS"* — the measured boot path ends
> at the UKI (§6, The machine MOK key).

### WSL mode — the on-ramp, before any of this exists

For users who do not want the VM, run the **same image** under WSL2:
a `--privileged` container inside WSL2, GPU via `/dev/dxg` and the NVIDIA
container toolkit's WSL support, and WSLg's Wayland socket bind-mounted in so
GUI apps composite natively.

**WSL mode requires none of §4.1–§4.5.** No bootloader, no BitLocker reader, no
kernel module. It is a disk and a container.
That makes it **independently shippable, and shippable first** — it validates the
distro, rootfs and container work with zero disk risk, long before
`paguro.efi` exists. Treat it as the staging plan, not only a feature.

Three caveats:

- **The image format is fixed VHD**, because WSL cannot mount a raw `.img`. Raw
  plus a 512-byte footer, so one file is both a WSL2 disk and a bare-metal root
  with no conversion — see §One mode. Confirm the footer geometry and that growth
  by extend-and-rewrite behaves (§11 Q23).
- **GPU parity between modes is not guaranteed.** WSL2 is D3D12-on-`dxgkrnl` with
  Mesa's d3d12 driver for GL/Vulkan; the VM path under kayfabe is the real NVIDIA
  stack. An application can work in one mode and fail in the other.
- **"No driver versioning issues" is optimistic, not wrong.** The Windows driver
  is the only driver, which removes the usual mismatch — but the container's CUDA
  runtime must still be within what that driver supports.

Modes are mutually exclusive for the same reason as §5b: WSL writes to the image
through Windows' filesystem layer while the VM path writes raw sectors beneath it.
Never both.

**So the on-ramp has two rungs plus a consequence:**

| | Machinery |
|---|---|
| WSL2 container, inside Windows | none — ships before `paguro.efi` exists |
| paguro boots a distro image | bootloader + module; the Windows VM and GPU sharing are separable |
| *that image runs WSL2 containers* | **none.** A userspace capability of any Linux (above) |

The first rung validates the image and the container work with zero disk risk. The
third is not a rung at all — it falls out of the second, which is why §1a's
*"use WSL2 instead"* objection needs no rebuttal.

**And a LUKS root rules out WSL mode outright** (§6, the compromised-Windows
tier). WSL would need `cryptsetup` inside WSL2, a passphrase at every start, and
`dm-crypt` in Microsoft's kernel — and paguro's ladder cannot supply the key,
since WSL2 never sees the loader's handoff. Someone choosing that tier is choosing
against the on-ramp, which the installer should say rather than let them discover.

---

## 8d. Later: a dedicated Linux disk

On machines with a second internal disk, Linux can have the whole disk instead
of an image — the partitioned layout at full native speed, **without any of the
image machinery**, and still with paguro's Windows integration. Planned next to
the image install, not replacing it.

| | Image on NTFS | Dedicated disk |
|---|---|---|
| Linux storage | fixed VHD in NTFS | the whole second disk, the distribution's own layout |
| paguro kernel module, view C guard, minifilter | needed | **not needed** — Linux never lives inside Windows' filesystem |
| installer | distribution ISO in a WSL2 container | the same, with the second disk attached whole (`wsl --mount` accepts non-system disks) |
| encryption | BitLocker, inherited | **LUKS2 on the Linux disk when Windows uses BitLocker**: TPM + PIN, a VMK-derived slot for Windows, and the BitLocker recovery password |
| Windows VM | view B: synthetic GPT, image extents refused | the **whole Windows disk** passed to QEMU; FVE substitution only if BitLocker is on (the VM still has no TPM) |
| Fast Startup / hibernation | gates Linux read-write | irrelevant to booting Linux; the VM still requires a clean Windows volume, and the app says how to get one |

**Encryption follows Windows.** The dedicated disk mirrors what the user
already chose for Windows:

| Windows | Linux disk |
|---|---|
| BitLocker with a TPM protector | LUKS2, with the TPM + PIN slot below |
| BitLocker without a TPM (password or USB key) | LUKS2 without a TPM slot: the Linux passphrase |
| BitLocker off | **no LUKS by default.** Offered, not recommended: most people who leave Windows unencrypted do not want Linux encrypted on the same machine |

**Encryption: ordinary LUKS2, three keyslots, each labelled.** When Windows
uses BitLocker with a TPM, the Linux disk is standard LUKS2 with:

| Keyslot | Opened by | Purpose |
|---|---|---|
| **TPM + PIN** (`systemd-cryptenroll --tpm2-with-pin`) | the daily Linux boot | sealed to the PCRs of a direct boot of that disk; no paguro loader in this path, so the measurements are the distribution's own |
| **derived from the Windows VMK**: `HMAC(VMK, "paguro/luks")`, as a hex passphrase | Windows, through its own BitLocker protector | WSL2 opens the disk from Windows without asking; changes only when BitLocker re-keys |
| **the BitLocker recovery password** (48 digits) | a person | Microsoft's recovery procedure opens Linux too — printed, in the Microsoft account, or in Active Directory; ~128 bits of entropy make the offline guessing a LUKS header allows useless |

Whoever holds Windows' key can therefore open Linux — parity with the rest of
the design, where Windows is trusted (§6).

**Every paguro keyslot says what it is.** LUKS2 keyslots have no names, so each
gets a LUKS2 token of type `paguro` naming its purpose, shown by
`cryptsetup luksDump` and by the Windows app, and the recovery prompt says it
in words. For the recovery slot:

> *This is your Microsoft BitLocker recovery key — the 48-digit key of your
> Windows installation. Find it at aka.ms/myrecoverykey.*

and for the other two, what depends on them: *"Lets Windows open this Linux disk
(WSL). Managed by paguro — removing it stops Windows from opening Linux."* /
*"Your Linux PIN."* The tokens say **removing a paguro keyslot is discouraged**;
the Windows tool re-creates a missing one, and replaces the recovery slot when
the recovery password is rotated in Windows, using the VMK-derived slot to
authorise the change.

**The PIN bypass, for the LUKS disk too.** *Restart into Linux* from a
logged-in Windows skips the PIN here as it does for images (§6), with the same
security. LUKS has no native time-limited TPM unlock — `systemd-cryptenroll`
binds PCRs and a PIN, not a TPM clock deadline — so paguro adds the one missing
piece as a **LUKS2 token plugin** (`libcryptsetup-token-paguro-bypass.so`, a
small C library on libcryptsetup's documented token API). `systemd-cryptsetup`
tries tokens before it prompts, so the bypass needs no script in the boot path:

```text
Windows, on "Restart into Linux" (logged in)
    K <- random 32 bytes
    add a LUKS keyslot for K       (authorised by the VMK-derived slot, via WSL)
    seal K: PolicyPCR(the TPM + PIN slot's PCRs, as recorded by the
            last Linux boot) AND PolicyCounterTimer(clock < deadline)
    store the sealed object + deadline in a LUKS2 token "paguro-bypass"
    BootNext = the Linux disk, restart

Linux initrd
    systemd-cryptsetup -> the plugin unseals K -> unlocked, no prompt
    after unlock: remove the bypass keyslot and its token
```

It is exactly as strong as paguro's own bypass: created only by a logged-in
Windows, sealed to the same PCRs as the standing TPM + PIN slot, refused when
`TPMS_CLOCK_INFO.safe` is clear, expired by the TPM clock whatever copies
exist, and one-shot — the initrd removes it after use, and the Windows service
removes any stale one at its next start.

**No key ever enters the TPM.** A LUKS keyslot encrypts the volume key with a
key derived from a passphrase; `systemd-cryptenroll` seals a random secret that
*is* that passphrase, and the bypass seals `K` the same way — as paguro seals
`D` and never the VMK. Unsealing yields a way to open one keyslot, not the key
that encrypts the disk.

**The ratchet has to be configured; LUKS supplies the parts.** Getting a shell
in a LUKS initrd before unlock is trivial (`init=/bin/sh` from the boot menu,
the emergency shell), much as WinRE is on a Windows laptop, and Secure Boot does
not stop it. What makes such a shell worthless is the same pattern paguro's
loader uses — seal against a PCR that is extended once the key exists, and
extend it before any shell:

| Part | Provided by | paguro's configuration |
|---|---|---|
| measure the volume key into PCR 15 after unlock | `systemd-cryptsetup`, `tpm2-measure-pcr=yes` in crypttab | set |
| refuse unseal once PCR 15 moved | binding PCR 15 **to its zero value** at enrolment (`--tpm2-pcrs=7+15:sha256=00…0`) | set; not a distribution default |
| cap before any shell | **not built in** | a unit ordered before `emergency`, `rescue` and `debug-shell` in the initrd (and initramfs-tools' panic hook) extends PCR 15 with a sentinel **and wipes whatever was already unsealed** — keyring entries, files under `/run`, a pending bypass keyslot and token — WinRE's pattern, and paguro's "cap on entry" (§4.1) |
| an edited command line cannot unseal | PCRs 8/9 (GRUB) or 11/12 (systemd-stub) | bound for the bypass slot, which has no PIN during its window |

**GRUB or UKI.** Which PCRs cover the command line depends on the boot chain:

| Chain | What is measured | Standing TPM + PIN slot | PIN-less bypass |
|---|---|---|---|
| **UKI** (systemd-stub, optionally behind systemd-boot) | the kernel, initrd and command line in one signed image (PCR 11), extra command line and credentials (PCR 12) | PCR 7 + 15 (zero) | bound to PCR 11/12 — **the recommended chain for TPM** |
| **GRUB** with its TPM measurements | every command GRUB executes, including anything typed at the GRUB shell or in an edited menu entry (PCR 8), and every file it loads plus the kernel command line (PCR 9) | PCR 7 + 15 (zero) | bound to PCR 8/9 **as the last Linux boot recorded them**; a kernel or `grub.cfg` update changes them, and the bypass then simply fails and the PIN is asked for |

The standing slot needs no command-line binding: a shell before unlock still
has no PIN, and the TPM's lockout limits guessing. Only PIN-less paths need it.
Whether a distribution's signed GRUB performs these measurements is checked at
install, and the bypass is offered only where they are present.

**How robust TPM + PIN is on LUKS, stated plainly.** BitLocker's TPM path was
designed as a whole — the PCR 7/11 profile, `bootmgr` ratcheting PCR 11, WinRE
capping, the PIN mixed into the key. LUKS provides the parts, but its defaults
bind PCR 7 alone, leave PCR 15 unbound, give the emergency shell no cap and the
PIN no offline gate, and many distributions do not enable TPM unlock at all.
LUKS users traditionally rely on the passphrase, whose Argon2id keyslot is a
strong offline gate by itself. paguro therefore treats the **passphrase and the
recovery key as the robust baseline** of the dedicated disk and TPM + PIN as a
convenience layered on top, with the gaps above closed by configuration.

**The user chooses, once, and each choice is done completely.** The question
is asked only when Windows uses BitLocker; with BitLocker off, Linux is
unprotected by paguro and the distribution's own installer keeps its usual
encryption option. When paguro sets the protection up, the installer adapter
pre-creates the LUKS volume and **hides the installer's own encryption
settings**, so the user is never asked twice. The same choices apply to
images on NTFS, where BitLocker already covers the data and the choice only
decides how Linux unlocks:

| Choice | Offered when | What paguro guarantees |
|---|---|---|
| **TPM + PIN** — recommended | Windows' BitLocker uses a TPM | matched to BitLocker: the PIN mixed into the key (`HMAC(D, stretch(PIN))`), PCR 7 + 15 (zero), the volume key measured into PCR 15, the shell cap. **PIN bypass** (*Restart into Linux* skips the PIN) is a checkbox, on by default |
| **Passphrase** | always | an offline-gate keyslot only (Argon2id on LUKS; the passphrase rung on NTFS), no TPM. Recommended when BitLocker has no TPM protector, or for anyone who would rather not rely on the TPM for Linux |
| **TPM only** | **only when Windows itself is TPM-only** | unlocks without input and relies on the Linux login screen; the §6 TPM-only obligations and the same initrd protections as TPM + PIN (a shell costs the key) |
| **Unprotected** (by paguro) | dedicated disk only | paguro sets up no LUKS, and **the distribution installer's own encryption option reappears**, so the user can encrypt Linux independently of Windows — a LUKS paguro does not manage and adds no keyslots to. **The VMK is not stored on the disk**, so starting the Windows VM asks for a BitLocker unlock (recovery key or password) each time |

**TPM only is capped at Windows' own level.** Linux holds the VMK — in the
handoff for images, on the LUKS volume for a dedicated disk — so a Linux that
unlocks with less than Windows does lowers Windows' protection to that level:
a TPM + PIN BitLocker user who picked TPM-only for Linux would leave Windows'
key reachable through the Linux path without a PIN. So TPM-only is offered only
where Windows is TPM-only already (§6: never weaker than Windows).

**Every choice where paguro manages LUKS adds the same two extra keyslots** —
alongside a typed passphrase too, not only alongside TPM + PIN: the BitLocker
recovery password (a person can always get in the Microsoft way) and the
VMK-derived slot (Windows and WSL open Linux without asking). And the VMK itself
is kept inside the LUKS volume, root-only and sealed to PCR 11 like the MOK key
(§6), so the Windows VM on the dedicated disk starts without a prompt.

PCR 15 bound to zero also closes the published *fake volume* attack (swap in a
LUKS volume with the same UUID whose `init` then asks the TPM): the fake
volume's key moves PCR 15 before its `init` runs, so nothing unseals.

**One limit of stock LUKS, stated plainly:** `systemd-cryptenroll`'s PIN is
only the TPM `authValue`; the sealed secret is the keyslot passphrase itself.
A TPM whose storage is compromised — the faulTPM attack on AMD fTPMs — releases
the secret without the PIN, so there is no offline gate behind it. paguro's own
seal mixes the stretched PIN into the final key for exactly that reason (§6);
for the dedicated disk the stock mechanism is used as it is, and the gap is
documented. (The token plugin could carry paguro's derivation for the standing
slot too, if that trade is ever wanted.)

**Booting it** stays one click from either side: *Restart into Linux* in
Windows, or the entry in `paguro.efi`'s picker, sets `BootNext` to the Linux
disk's own boot entry and resets — never a chainload — so the TPM sees exactly
the direct boot its seal expects, a few seconds later, just as "Start Windows"
does. Firmware's boot menu reaches it too. The NTFS volume is never read on this
path, so Windows' hibernation state cannot matter.

**The Windows VM with the whole disk** needs its own safety rules: WinRE must
still not be reachable (*Reset this PC* from the VM would reinstall the shared
Windows), so the recovery partition is hidden from the guest by the same kind
of dm-linear view, and Linux must not mount the Windows volume while the VM
runs (§5b Rule 1) — enforced by a userspace lock, since the module is not in
this path.

## 8c. Platform drift — what is actually exposed

Wubi died because the platform moved. Worth being specific about which surfaces
here can move, since the intuitive answer is wrong.

| Surface | Stability |
|---|---|
| **NTFS on-disk format** | effectively frozen since NTFS 3.1. Runlists, `$MFT`, `$Bitmap` — what the storage core depends on, and Microsoft's incentive not to break it is about as strong as incentives get |
| **FVE metadata format** | **has moved** — Vista→7, and again for XTS in Windows 10 1511. Twice in fifteen years. This is §6's territory, and it has a **CI oracle** (§6, libbde round-trip) so a change surfaces as a failing test |
| testsigning | not going anywhere — it is the driver development path for every hardware vendor on the platform |
| driver signing | attestation signing is **available today**: EV certificate plus a Hardware Dev Center submission. An administrative cost, not an adoption threshold |
| driver blocklist | targets **exploitable** drivers (the BYOVD problem), not legitimate signed ones — so writing the minifilter well doubles as keeping it signable |

So "stops booting after a Windows update" narrows to three vectors, none of them
NTFS: a feature update wiping the ESP (§7, and recovery does not read the
configuration anyway), a blocklist entry (avoided by being signed and not
exploitable), and an FVE format change (caught in CI).

**What that leaves is maintenance, not drift.** Three components across two
operating systems and a hypervisor is a standing cost regardless of how stable
the formats are, and it is the risk that survives every technical answer.

---

## 9. Rejected alternatives

| Rejected | Why |
|---|---|
| **UWF Read-Only Media** | Enterprise/Education/IoT only — excludes Home and Pro, i.e. most users; and the block-layer module makes a guest-side write filter unnecessary. |
| **User-mode pinner** | §5's t0–t3 counterexample shows a liveness check cannot establish the safety property: relocation can persist between handle close and heartbeat expiry. The issue is handle *lifetime*, not privilege. §4.4 is kernel-only. |
| **A metadata watch in the module** | Re-decoding the runlist and `$Bitmap` on every write is unnecessary once reads of the image return `EIO` — a relocation cannot copy, so it never logs a runlist change (§4.3). |
| **Zero-fill for protected reads** | Turns a rejected relocation into a destroyed filesystem after native log replay (§4.3). |
| **One `dm-crypt` target per extent** | A full `crypt_config` each; thousands of extents means thousands of kthreads. Decrypt the volume once and gather instead (§4.3). |
| **A signed `paguro.ini`** | Needs a verifier in stage 1 and a private key every writer holds; the whole-file hash in firmware plus the PCR 12 ratchet do the job without either (§6). |
| **A project certificate, or a Microsoft-signed `paguro.efi`** | Unnecessary: every distribution's signed shim trusts `MokList`, so one machine key, enrolled once, signs everything paguro-side, and a revoked shim is replaced without touching our trust (§4.1). |
| **ISO support in the loader** | A third on-disk format parsed with the key in memory, for images a stock live initramfs could not boot from NTFS anyway. ISOs are opened in WSL2 at install (§8b). |
| **External theme files** | A parser of attacker-authored data in the loader; compiled in instead (§4.2). |
| **A paguro-maintained host OS** | Puts kernel, drivers and hardware support on this project forever (§8b). |
| **Disabling code integrity at runtime to load a driver** | The mechanism does not exist. `testsigning` is read by `winload.efi` at boot; there is no supported runtime toggle. Live relaxation means patching `g_CiOptions` via a vulnerable signed driver — BYOVD, the exact pattern EDR is built to detect. See §12. |
| **Replacing `bootx64.efi` / installing a boot menu** | Windows updates fight it; the machine stops looking stock. Transition from inside Windows instead. |
| **Forcing Fast Startup off** | A permanent cost to the user's daily Windows for an occasional benefit. Restart bypasses it anyway. |
| **Loading the driver from a secondary disk with nothing on C:** | Windows has no such mechanism for full Windows — PnP matches only the DriverStore, and `$WinPEDriver$`/`drvload` are WinPE-only. The driver installs normally into the DriverStore, and §11 Q18 covers its load lifecycle. |
| **Secure Boot off to permit unsigned drivers** | Does not work. Kernel-mode code signing is **independent** of Secure Boot on x64. Only test-signing, F8, or a kernel debugger allow it. |
| **One-shot seal as the *only* unlock** | Couples Linux's bootability to Windows working. The PIN bypass is one-shot, but it sits on top of a standing seal (§6). |
| **Removing the initrd shell under TPM+PIN** | The shell sits behind the PIN, so it is the legitimate user's repair tool; hardening it away buys nothing (§6). |
| **An ext4 reader in the loader, for a UKI on the root** | Requires filesystem code that FAT32 does not — firmware supplies FAT for free via a synthetic `BlockIo` + `ConnectController()`, and a distribution's GRUB behind it reads ext4 with its own modules. Also fights every UKI tool's vfat/type-GUID check, and inherits ext4's record of new INCOMPAT flags bricking read-only bootloader parsers. See §4.2. |
| **Hosting the UKI on the real ESP (thin bootloader)** | Tempting — it would delete the NTFS and BitLocker readers from `paguro.efi`. Rejected: Windows ESPs are often exactly 100 MB and a UKI with a cryptsetup/dm/ntfs3 initrd is 50–150 MB, and **filling the ESP breaks Windows feature-update staging**. **Consequence: the bootloader keeps its NTFS and BitLocker readers.** |
| **`ntfsfix` to clear the dirty bit and continue** | Not chkdsk. Clearing the flag suppresses the repair that would have caught real inconsistency, and resetting `$LogFile` discards uncommitted transactions. Refuse instead. |

---

## 11. Open questions — verify before building

Every entry maps to §3a. Ordered by what blocks what; numbers are stable, so a
later question sits with the ones it belongs to rather than in numeric order.

### The storage gate — build the torture harness before anything else

1. **Does NTFS relocate a cluster when a write to it fails?** (§4.3) **The
   architecture-deciding question, and it outranks everything below.** Blocking
   reads stops a relocation from ever being logged, because the copy must precede
   the runlist rewrite — but a *write* failure leaves NTFS holding the data, where
   dynamic bad-cluster remapping would rewrite the runlist with no read at all.

   ```text
   write into the image from inside the guest
     -> let the lazy flush take EIO on a protected extent
     -> dump $BadClus and the runlist
     -> repeat with the error reported as a device error
        and as a write-protect / read-only error
   ```

   > **If NTFS remaps on write failure, the fix is likely the error class rather
   > than more machinery** — remapping is a response to a failing *device*, not to
   > a read-only one. Settle which error the protected ranges should return before
   > building anything on top of the range test.

   Also measure what `chkdsk /r` does to a file whose clusters return errors: it
   reads every cluster, cannot read ours, and its remediation is to mark them bad
   and take them out of the file. Explicit and user-initiated, but it is the
   firmest version of the same concern.

2. **Does a relocation's copy always read from disk?** (§4.3) The ordering claim
   assumes the copy reaches our range test. Untested: a copy satisfied from the
   guest's **cache** when the file's pages are already resident (clean or dirty);
   chunked moves, where early chunks commit before a later one fails; and whether
   a failed flush of dirty in-range pages aborts the move or proceeds. Any of
   these turns a refused relocation into a completed one.

3. **Does NTFS recover cleanly if a metadata write is rejected anyway?** (§4.3)
   The design aims never to reject one — the runlist record should not exist. This
   is the backstop for the paths where one happens regardless.

   ```text
   attempted relocation -> rejected write -> arbitrary interruption
     -> native Windows boots -> chkdsk clean or deterministic repair
     -> the image's contents intact
   ```

   **Check the log, not just the outcome.** NTFS is write-ahead, so a transaction
   commits before the MFT page is lazily flushed; a rejected flush leaves the page
   at an older LSN than the record, which is the condition under which recovery
   **reapplies** it. A run that leaves the runlist intact while a record did get
   written is a latent version of the same defect.

   > **Kill criterion.** If NTFS can reach an unrecoverable intermediate state
   > after a rejected write, **stop.** Do not add another protocol layer on top —
   > that failure means the enforcement approach is wrong, not incomplete.

   **Measured, 2026-09-26 (Q1–Q3, first pass — not closed).**
   `test/vm/split-e2e.sh` with `PAGURO_Q1=1`, which runs `test/vm/q1-probe.ps1`:
   Windows 11 Enterprise 24H2 (build 26100) as a VM on view B, AHCI, the module's
   refusals reaching the guest as `EIO`. The minifilter was loaded, but no PROTECT
   was issued, so these are the raw paths it normally closes. There were two runs:
   one ended with a clean shutdown, the other with `kill -9` of QEMU, Q3's
   interruption.

   | Probe (into the claimed image) | Windows' answer |
   |---|---|
   | buffered `WriteFile` + `FlushFileBuffers` | write accepted into the cache; the flush fails with 1117 (`ERROR_IO_DEVICE`) |
   | write-through / unbuffered write | fails with 1117 (one run failed at the unbuffered open) |
   | buffered write left to the lazy writer | accepted; nothing logged by NTFS before the session ended |
   | `FSCTL_MOVE_FILE`, 16 clusters and 1, after the writes above | fails with 1117, both runs |
   | `defrag C: /D /U` | still running after 600 s; about 2,400 refused I/Os in run 1 |

   Afterwards, in both runs:
   - **In the guest:** the image's extents were identical (`0:570657+16384`),
     the volume was never marked dirty, and the only events were `disk 153`
     (I/O retried). There was no NTFS event, so no delayed-write failure,
     corruption or check-needed was ever reported.
   - **From Linux on the raw partition:** every BitLocker-owned range and the
     image's extents were byte-identical.
   - **Native boot of the same disk:** not dirty, `chkdsk /scan` found no
     problems, 0 KB in bad sectors, and the image's extents were unchanged.

   On this build, a refused write is not remapped. No bad cluster was recorded
   and the runlist never moved, so Q1's feared dynamic remapping did not occur.
   A relocation fails at its copy, so Q2's ordering held, including with dirty
   pages cached. A hard stop after both left nothing for recovery to reapply,
   so Q3 held.

   **`chkdsk /r` in the session: it tried to take the image's clusters out of
   the file.** Measured by `PAGURO_Q1_CHKDSK=1` in two runs with the same
   result: `chkdsk C: /r` scheduled in the VM, then a reboot into autochk
   (about 9.5 min). Its own log, from `System Volume Information\Chkdsk`:

   ```text
   Stage 4: Looking for bad clusters in user file data ...
   Read failure with status 0xc0000185 at offset 0x8b521000 for 0x10000 bytes.
   A disk read error occurredc0000185
   The disk does not have enough space to replace bad clusters
   detected in file 2585C of name \paguro\linux.img.
   ...
   Windows has scanned the file system and found no problems.
   0 KB in bad sectors.
   ```

   Afterwards the image's size, extents and NTFS extent map were unchanged,
   read from both Windows and Linux (`pgctl fiemap` against the claim-time map).
   The volume was not dirty, and native Windows scanned clean. **But the outcome
   rests on autochk declining with "not enough space"** on a volume with 10 GB
   free, for a reason not yet understood. The **intent** was the one this
   question feared: replace the clusters it cannot read, which moves them into
   `$BadClus` and rewrites the runlist through MFT writes view B allows. **Treat
   `chkdsk /r` in a session as an open corruption path until the refusal is
   understood or closed by design.** Candidates (none decided):
   - refuse view B writes to the image's own FILE record(s), with the installer
     giving that record a cluster of its own;
   - have the minifilter refuse `/r`-style scans in the session;
   - find which error class makes autochk report the clusters rather than
     replace them.

   **Not yet covered:**
   - other error classes (a write-protect or medium error instead of `EIO`), and
     virtio-blk / virtio-scsi instead of AHCI;
   - why autochk declined the replacement (see above), and `chkdsk /r` on a
     volume where it would not;
   - the lazy writer's own flush attempt observed directly, and an interruption
     at other points (for example mid-defrag);
   - older builds and ReFS;
   - Q2's clean-cache case, which cannot arise while reads of the image fail
     from boot. It could arise if pages were cached before the session.

4. **Does `ntfs3` give a usable extent map without writing?** (§4.3) `FIEMAP` on
   a read-only, recovery-suppressed mount of the decrypted volume, cross-checked
   against the module's own decoder. Confirm `ro` genuinely suppresses recovery,
   and that `ro,noload` prevents ext4 journal replay on view A.

5. **Does `MARK_HANDLE_PROTECT_CLUSTERS` hold for the whole session**, and does
   nothing in early Windows startup touch the file before the driver attaches?
   Note `autochk` is **not** excluded by the dirty-bit gate — a scheduled check
   runs regardless.

6. **Non-sparse enforcement** — confirm `fsutil file createnew` + `setvaliddata`
   produces a file with no sparse or compressed attributes, and that Windows
   never sets them later.

7. **Does Windows notice the subset GPT?** (§4.3) View B presents ESP + MSR + C:
   under the real GUIDs, with WinRE and any data partitions absent. Confirm it
   does not reassign drive letters or update `MountedDevices` in the shared
   registry.

8. **What error policy does QEMU need?** (§4.5) `EIO` reaches the guest as a
   device error only with `werror=report,rerror=report`; the defaults pause or
   report ENOSPC instead, which would stall the VM rather than failing the
   operation. One configuration line, load-bearing for the whole of §4.3.

### The boot path

9. **Does `bootmgr` find a `.BEK` on QEMU's synthetic removable?** (§6) The file
   format is well-exercised by recovery-key-on-USB users; the open part is
   specifically the automatic search at boot. One boot settles it. A "no" leaves
   the VM without an automatic unlock: the fallback is the recovery password typed
   at the guest's BitLocker prompt on every VM boot — workable, and bad enough that
   this is effectively a gate on the VM path.
10. **Does the substituted VMK entry round-trip through libbde?** (§6) The oracle
   harness exists: generated BitLocker volumes with every supported protector,
   startup key included, are decrypted by libbde and dislocker in CI, and the
   loader already parses `.BEK` files. What remains is the substituted
   ExternalKey entry itself — synthesised metadata plus `.BEK` in, correct VMK
   out — so a format change is a failing test rather than a field failure.
11. **Does `ConnectController()` bind firmware's Partition and FAT drivers to an
   application-installed synthetic `BlockIo` handle?** (§4.2) **Answered for
   OVMF and AAVMF: yes** — tier 1 binds, and stage 4 chains through it end to end
   in CI on x86_64 and aarch64. Real firmware is still to test; one that does not
   bind is a clean refusal until tier 2 (~500 lines) exists. Also confirm the FAT
   driver's small random-read pattern survives per-sector AES-XTS on real
   hardware, or add a block cache.
12. **Can a persistent SRK stand in for the re-created parent?** (§6) The parent
    is created from the TCG-standard template on each use and never persisted, so
    Windows and Linux reproduce it without an NV handle (INTERFACES §4). Where a
    persistent SRK already exists, loading under it is cheaper; whether both OSes
    can rely on it, with Windows holding `ownerAuth`, is the same class of
    question as `NV_DefineSpace`, which turned out blocked. The same experiment
    should say whether Linux can define a **monotonic NV counter**, the only
    construction that closes configuration rollback (§6).

12b. **Can Windows create a sealed object with `TPM2_PolicyCounterTimer`?** (§6,
    the PIN bypass) Decides whether the TPM enforces the deadline directly or the
    `tpmTimeSecret` fallback is needed. Same allow-list question as `NV_DefineSpace`,
    and `TPM2_ReadClock` reachability rides along with it — a no-auth read, so
    probably permitted, and answerable in the same afternoon as Q14.
13. **Do boot-services-only UEFI variables behave as specified, on real
    firmware?** (§6, `PaguroB`) Three things to confirm per machine: that the variable
    **persists** across reboot; that it is genuinely **absent at runtime** in both
    Windows and Linux rather than merely undocumented; and that writing one from an
    EFI application does not require Setup Mode. A "no" on any of them drops `B`
    to a runtime-accessible variable plus `efivarfs` mounted `0700`, which is
    weaker and distro-dependent — so this is worth settling on the same trip that
    answers Q9, not later.
14. **Is the TCG event log readable through TBS from Windows user mode?** (§4.6)
    The pre-flight compares the log's `EV_EFI_VARIABLE_DRIVER_CONFIG` entries
    rather than PCR 7's value, because PCR 7 carries authority events that differ
    between the Windows and Linux boot paths. Confirm the log is reachable and
    that those entries are identical across both. A "no" costs `dbx` prediction,
    not the design — the TPM-failure handshake still recovers, one reboot later.

15. **What does double XTS cost?** (§6, LUKS tier) BitLocker's cipher plus a LUKS
    cipher is two AES passes per block. With AES-NI each runs at several GB/s, so
    on NVMe this may or may not become the bottleneck. Measure before offering
    the tier, not after.
16. **How much NVRAM residue does a deleted `Boot####` entry leave?** (§Bootstrap)
    The wrapped VMK there is unverifiable without an oracle, so residue is not
    load-bearing — but confirm that, rather than assume it, on firmware that
    compacts its variable store lazily.
26. **Does the chosen shim start a MOK-signed second stage named in its load
    options?** (§4.1) Shim builds differ; a build that ignores them gets
    `paguro.efi` under its default second-stage name instead. Confirm per shim
    the installer ships, x64 and aa64.
27. **Does GRUB carry on when its writes fail?** (§4.2) `save_env` and
    `recordfail` meet `EFI_WRITE_PROTECTED` on the published disk. Confirm per
    supported distribution that GRUB boots regardless, rather than stopping at a
    prompt.
28. **Does a distribution's shim start from under ours?** (§4.2) paguro, itself
    started by shim, `LoadImage`s the distribution's shim, which verifies GRUB and
    the kernel with the distribution's key. It needs Microsoft's third-party UEFI
    CA in `db` and a shim that tolerates an existing `SHIM_LOCK` protocol.
29. **How are MOK-signed next images accepted after `paguro.efi`?** (§4.2)
    Firmware `LoadImage` checks `db` only, so a locally signed UKI needs shim's
    `LoadImage` hook (recent shim) or `SHIM_LOCK->Verify()` followed by loading the
    PE ourselves — sound only because verification ran first. Decide which, per
    shim version.

### Deploying the driver

17. **Is attestation signing available for a filesystem minifilter?** EV
    certificate plus a Hardware Dev Center submission, no HLK run. Administrative
    cost rather than an adoption threshold (§8c) — but confirm it covers this
    driver class.
18. **What is the minifilter's load lifecycle?** Primitive drivers are not
    device-bound, so §12's hardware-ID trick does not apply. Needs its own design:
    when it loads, what happens if absent, how the host distinguishes "not yet
    loaded" from "refused to load".
19. **Can it load boot-start and pin at C: mount?** (§4.4) Earlier attachment
    means fewer guest operations rejected messily. Not a correctness matter since
    §4.3 enforces regardless.
20. **Does it meet HVCI code-compatibility requirements?** Page-aligned sections,
    no W^X, no dynamic code — build-time properties, but verify with the HLK test.

### The GPU half

21. **Does `DwmDxGetWindowSharedSurface` exist and behave on current Windows?**
    (§1b) Documented for Windows 7 only, for driver/runtime use rather than
    applications, with no guarantee elsewhere. A current-Windows proof of concept
    is mandatory before per-window projection can be planned around.
22. **Is the GPU backend at its milestone, not its promise?** (§1b) Require
    separate demonstrations of desktop rendering, application compatibility,
    CUDA, encoding and recovery. *"The stock driver loads"* substitutes for none
    of them.

### Blocking nothing, worth knowing early

23. **Does a fixed VHD satisfy both consumers?** (§8b) `wsl --mount --vhd`
    against one, and paguro's extent mapping against the same file. Confirm the
    footer geometry, and that growth by extend-and-rewrite-footer keeps both
    working.
30. **Can the WSL2 kernel host a distribution's installer?** (§8b) It must mount
    ISO 9660 and squashfs (fallback: `squashfuse`, `bsdtar`); partition nodes the
    installer creates on the VHD must appear inside its container; and the
    installer's GUI must work over WSLg.

### Design gaps to close before building

24. **Does the guest touch BitLocker's regions the way §6 assumes?** (§6) The
    policy is decided — absorb every write to BitLocker-owned sectors, pass
    none through. What needs measuring, in the Windows VM with every write
    recorded (`dm-log-writes`): which sectors suspend/resume, adding and
    removing protectors, a PIN change, a cumulative and a feature update,
    volume shrink and extend, `chkdsk` and `defrag` write; whether any of them
    moves metadata (a write to BitLocker structures outside the substituted
    set would show it); and how `fvevol.sys` behaves under absorb versus `EIO`.

25. **Used-space-only encryption.** Device Encryption's default. Those volumes
    report a distinct conversion state; the loader identifies it and refuses the
    volume until the unused regions are classified correctly. §8b's v1 matrix
    admits them on the strength of this answer.

31. **How does Linux read the handoff?** (§6, INTERFACES §8.2) A small module or
    early init code reads the configuration table once and zeroes it; what it
    exposes to the initrd — for example a read-once `/dev/paguro-handoff` — is
    still to be decided. It must stay out of the enforcement module, which holds
    no key material.

32. **Does an OEM licence accept being run in a VM?** The precise case to find
    out. A retail or digital licence moved between identical-looking machines
    is ordinary; an OEM licence (the key in the firmware's MSDM table,
    activated against the device's hardware hash) is meant for bare metal, and
    running the *same* installation virtualised is unusual for it. Whether
    Windows or Microsoft's activation service rejects it — by the hash, by
    detecting the hypervisor, or not at all — is not documented by Microsoft; **community reports say it works** when the
    VM carries the SLIC/MSDM tables, SMBIOS types 0 and 1 from the host and the
    host's board UUID, including the *same* installation booted on bare metal
    and in the VM (sources in §4.5's notes) — the configuration §4.5 now uses
    by default. To confirm on our own hardware: on an OEM laptop,
    switching native ↔ VM many times: activated in the VM with no watermark?
    still activated natively? Order of attempts, least first: `-cpu host`,
    the host's SMBIOS and MSDM (§4.5); then disk serial and MAC; then hiding
    the hypervisor CPUID bit, which is the likely lever if detection is the
    trigger but costs Hyper-V enlightenments and VBS in the VM. If nothing
    works, the VM runs with the watermark and nothing else is affected, and the
    docs say so for OEM machines. Digitally licensed desktops are the control.

---

## 12. Driver signing

This section is about the Windows side. **The Linux side is settled by one key**:
the kernel module is built by DKMS on the machine and signed with the machine MOK
key, as are `paguro.efi` and locally built UKIs (§4.1, §6 The machine MOK key).

§4.4's minifilter is mandatory, so this section is live: **attestation signing is
the plan**, and the rest documents the fallback and what **not** to do.

**Conditional load via hardware ID** is how Windows loads a *device* driver only
when its device is present — QEMU presents a PCI device, the INF matches it, and
on native boot nothing loads. It works for a virtio-style device driver; it does
**not** apply to a minifilter, which is a primitive driver rather than a
device-bound one (§11 Q18).

**Synthetic ESP for test-signing, if attestation is unavailable.** Compose a small
FAT32 image into the VM's disk containing `bootmgfw.efi` and a BCD with
`testsigning on`, instead of mapping the real ESP. `testsigning` is a boot flag,
not persisted to the OS volume, so native boots stay clean.

Requires Secure Boot **off in the VM's OVMF** — Windows ignores `testsigning`
under a Secure Boot policy. Native keeps Secure Boot on.

**Code-integrity enforcement cannot be disabled at runtime.** `bcdedit /set
testsigning on` is read by `winload.efi` at boot; there is no supported registry
value that turns DSE off for a running kernel. Doing it live means patching
`g_CiOptions` in kernel memory through a vulnerable signed driver — BYOVD, which
is precisely what PatchGuard and every EDR product exists to catch. Any scheme
of the form *"detect VM, disable signing, load driver, revert"* is built on a
mechanism that does not exist. The relaxation must be configured **before Windows
starts**, which is what the synthetic ESP above does — and that is strictly
better, because nothing is ever edited and there is no crash window to reason
about.

**HVCI does not block test-signed drivers.** Microsoft's documentation states
the opposite: *"if you have Memory Integrity / HVCI (Hypervisor Code Integrity)
enabled, you must test-sign the binary using any self-created test cert. An
unsigned binary isn't supported."* Under testsigning mode a self-signed driver
loads with Memory Integrity on. **No overlay registry dance, no two-phase VM
boot, no HVCI state machine** — Secure Boot off in OVMF plus `testsigning on` in
the synthetic ESP's BCD is sufficient.

What HVCI *does* add is **code-compatibility** requirements on the binary:
page-aligned sections, no W^X, no dynamic code generation. These are build-time
properties, satisfied deliberately at compile and link time, not a runtime
blocker. Build for them from the start rather than discovering them late.

**BitLocker can block `bcdedit /set testsigning`, not only Secure Boot** — the
docs call this out, and this design has BitLocker on by definition. It does not
bite us: the VM's BCD is authored offline into the synthetic ESP, never set with
`bcdedit` on a running machine. Recorded because it looks like a blocker and
is not.

**Test-signing shows a "Test Mode" watermark** on the guest desktop. Cosmetic,
but the user sees it every session.

**virtio needs none of this.** Red Hat's virtio-win drivers are WHQL-signed and
load on stock Windows.

Preference order: **attestation signing** (fully clean) → **synthetic ESP**
(scopes test-signing to VM boots) → **never** global test-signing, and **never**
a runtime CI patch.

If attestation signing is unavailable (§11 Q17) there is no user-mode fallback,
and the synthetic-ESP route becomes the shipping path at the cost of §8's EDR
tier — which makes Q17 a deployment gate rather than a preference.
