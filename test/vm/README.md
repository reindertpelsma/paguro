# test/vm: Windows as a VM through the paguro disk stack

`paguro-vm` (the launcher, `crates/paguro-vm`) boots the machine's own
Windows installation — BitLocker and all — as a VM (DESIGN.md §4.3, §4.5,
§5b, §5c, §6 "The VM boot"). These tests prove it on a real Windows 11
volume without loading anything into the host's kernel.

| Script | What |
|---|---|
| `fve-oracle.sh` | §11 Q10: the substituted FVE metadata (one extra External Key VMK entry) and its `.BEK`, applied to generated BitLocker volumes (`test/fixtures/bde/make.sh`), are opened by **libbde** (`bdemount -s`) and **dislocker** (`dislocker-file -f`) to exactly the expected plaintext; the volume's own recovery password still opens it |
| `split-e2e.sh` | the whole path, below |
| `q1-probe.ps1` | §11 Q1–Q3 from inside the guest (`split-e2e.sh` with `PAGURO_Q1=1`; `PAGURO_Q1_KILL=1` ends the session with `kill -9`): writes into the image in every form, `FSCTL_MOVE_FILE` of it, the optimiser, with extents, dirty bit, bad-sector count and events before and after; a native scan afterwards |
| `q1-chkdsk.ps1` | after `PAGURO_Q1_CHKDSK=1` schedules `chkdsk C: /r` and reboots the guest into it: autochk's own log (copied out of `System Volume Information` with backup semantics) and the image as NTFS then maps it |
| `q24.py` | §11 Q24's instrument: which sectors the guest wrote where, from the disk's `dm-log-writes` log (QEMU `blklogwrites`) |
| `net-smoke.sh` | §5c: the VM's LAN (no Windows) — a throwaway busybox guest with a tap exactly as `--net tap` configures it, `paguro-vm net-up`/`net-down` (the same `lan.rs`/`dhcp.rs` production code) standing in for `launch`'s network setup. See `crates/paguro-vm/README.md`'s "The VM's network" section |

## `split-e2e.sh`

The paguro host stack must run under a kernel that may load `dm-paguro`,
so it runs in a throwaway Linux VM ("L2", the host's own kernel, a busybox
initramfs built by `lib.sh`); Windows runs in a second VM that
`paguro-vm launch` starts on the host, its disk L2's
`/dev/mapper/paguro-vmdisk` exported over NBD (nbdkit):

```text
host                                       L2 (Linux)
paguro-vm launch --nbd ... ──── NBD ────── nbdkit /dev/mapper/paguro-vmdisk
  OVMF, no TPM, host SMBIOS/UUID/MAC,        dm-linear: GPT | ESP | MSR | C: | GPT
  .BEK on usb-storage (unplugged once read)    C: = view B (dm-paguro) except the
  blklogwrites → writes.log (Q24)                   FVE buffer (absorbs writes)
  paguro0 (stream socket) ───────────────── eth1 → netns paguro, 169.254.244.1/30
                                               Samba (L:), /mnt/c (CIFS, in the netns)
```

1. **L2**: `paguro-vm unlock --volume-add` (stand-in for the initrd: the
   VMK from the recovery password, the decrypted volume, `PG_VOLUME_ADD`
   with BitLocker's ranges reserved), `pgctl claim` of a file on C:,
   `paguro-vm prepare`; checks view B's `EIO` over the claimed extents,
   B/C exclusion, and that the guest is served the substitute.
2. **Windows** boots from it (Q9: bootmgr finds the `.BEK` on the
   removable stick); guest checks: protection on with the session's
   External Key, testsigning from the synthetic ESP's BCD, PaguroFlt
   loaded and attached, the SMBIOS marker, the host's UUID and MAC, three
   partitions (no WinRE), no TPM.
3. **The private link**: Samba in netns `paguro` serves `L:`; the
   generated provisioning script sets up Windows' side; `/mnt/c` is
   mounted from inside the netns (Mode 1).
4. **BitLocker in the guest** (suspend, resume, add and delete a
   protector) and the view B probe from inside Windows, each a phase of the
   write log.
5. After shutdown: `q24.py` over the log; L2 hashes every BitLocker-owned
   range and the image's extents on the raw partition before and after
   (unchanged), reports what the guest wrote to the FVE buffer (absorbed),
   tears down, and loads view C now that B is gone.
6. **Native boot** of the same disk (TPM, no marker): BitLocker unseals,
   protection on, no External Key, PaguroFlt not loaded (test-signed,
   testsigning off natively), the file written in the VM is there.

Inputs (never committed; see `test/winvm/README.md` for the evaluation
image): a copy of the winvm image with BitLocker enabled on C:
(`manage-bde -on C: -RecoveryPassword`, full encryption, C: shrunk first
to keep the copy small), its recovery password, its native OVMF variables
and swtpm state, the virtio-win NetKVM driver and the test-signed
minifilter installed, testsigning **off** in the native BCD, and a 64 MiB
file `C:\paguro\linux.img` to claim. Samba for L2 comes from an extracted
`samba` package (`PAGURO_SAMBA_ROOT`); without it the L: step fails.
Everything large lives under `$PAGURO_VM_WORK` (`/data/paguro-work/vm/run`).

## `nested-e2e.sh`

The whole product topology in one Linux VM, with Windows one level deeper. On
this lab's cloud VM (Windows three levels down) it does not reach a usable
desktop: enlightened, Windows booted in about 15 minutes and froze after
logon; with `--no-hv-enlightenments` it was still booting after 55 minutes.
Use `split-e2e.sh` for anything that needs the guest.
