# paguro — interfaces

This document fixes every boundary between components: file formats, firmware
variables, the loader→initrd handoff, the kernel module's control surface, and
the Windows-side contracts. [`DESIGN.md`](DESIGN.md) says *why*; this says
*exactly what*. Where the two disagree, fix one of them in the same commit.

Every component can be built in parallel once these are stable. Each interface
has a **reference implementation in `paguro-core`** (Rust, `no_std`), and every
parser of external data has a fuzz target (§12).

Status markers: **FROZEN** (v1, changes need a version bump), **DRAFT** (may
change before the first release), **OPEN** (a decision still to be made; the
design question is named).

---

## 0. Conventions

- **Integers are little-endian** in every paguro-defined format. External
  formats keep their own (VHD footer is big-endian, TPM marshalling is
  big-endian).
- **Every paguro format starts with an 8-byte magic whose last two bytes are the
  version** (`PGRxxx\0\x01` = v1). Unknown version → refuse, never guess.
- **Every format has a hard maximum size**, checked before the first byte is
  interpreted. No length read from input sizes an allocation.
- **Trailing bytes are an error**, not ignored.
- **Parsers return a typed error and no partial result.** A malformed input is
  refused whole.
- **Labels** in key derivation are ASCII, prefixed `paguro/`, and never reused
  between purposes.
- Sector = 512 bytes. NTFS cluster size comes from the boot sector and is never
  assumed.

### 0.1 Architectures

x86_64 and aarch64. All code is architecture-neutral; where a name depends on
the architecture it follows the UEFI convention (`<arch>` = `x64` | `aa64`:
`BOOTX64.EFI` / `BOOTAA64.EFI`, `shimx64.efi` / `shimaa64.efi`). Every paguro
format is little-endian regardless of host. CI runs the Rust and C tests on
aarch64 under qemu-user and boots the aarch64 loader under AAVMF.

## 1. Identifiers

| Name | Value |
|---|---|
| paguro vendor GUID (firmware variables) | `c648880d-36be-4eaf-8a1b-6f3a9c2926c9` |
| handoff configuration-table GUID | `290e97f6-3835-4ea1-a6f5-847ccbc33a0a` |
| paguro TCG event tag GUID (PCR 12 events) | `23fc424e-17ab-4b60-bf91-2bd392852091` |
| ESP directory | `\EFI\paguro\` |
| device-mapper target names | `paguro-image`, `paguro-volume` |
| control device | `/dev/paguro` (misc) |

## 2. ESP files — FROZEN layout, DRAFT contents

```text
\EFI\paguro\
  shim<arch>.efi, mm<arch>.efi   a distribution's Microsoft-signed shim and
                                 MokManager, redistributed unchanged (§2.1)
  paguro.efi                 the loader
  paguro.ini                 configuration only (§3)
  <volume-guid>\             one directory per NTFS volume paguro unlocks
    tpm_seal.bin             §4
    setuptpm_seal.bin        §4
    passphrase_seal.bin      §4
    tpm_pin_bypass_seal.bin  §4
```

The loader **reads** these files and never writes any of them. The initrd and
the Windows tool are the only writers.

### 2.1 Getting started under Secure Boot without a Microsoft signature — DRAFT

paguro has no Microsoft-signed binary and does not need one. Every shim a
distribution ships is signed by Microsoft's third-party UEFI CA and trusts, in
addition to its own vendor key, **anything signed by a key in `MokList`**. So:

- **We redistribute a distribution's signed shim unchanged** (shim is BSD
  licensed; distributions publish the signed binaries), with its MokManager.
  `paguro.efi` is signed with the machine MOK key (§11.6), which that shim
  accepts once the key is enrolled. Our own `Boot####` entry points at the
  shim; the shim's second stage is `paguro.efi`, named in the entry's load
  options (shim's second-stage argument) or, if a shim build ignores them,
  installed under shim's default second-stage name next to it.
- **SBAT:** shim refuses a second stage without a `.sbat` section. `paguro.efi`
  carries one (`crates/paguro-efi/sbat.csv`); its `paguro` generation is bumped
  when a security fix must revoke older builds.
- **Which shim:** one whose SBAT generation is current and, per machine, signed
  by a CA present in `db`. Microsoft's UEFI CA 2011 expired in June 2026;
  newer shims are signed by the UEFI CA 2023, which only boots where Windows
  Update has added that certificate to `db`. The installer reads `db` and picks
  the matching build (x64 and aa64).
- **When the first image cannot be a Microsoft-signed shim.** Some machines
  (Secured-core / Copilot+ PCs) ship with the third-party UEFI CA disabled,
  so no distribution shim loads. The fallbacks both change `db`, and a `db`
  change moves Windows' PCR 7:
  1. enable "Allow Microsoft third-party UEFI CA" in firmware setup (one
     toggle; adds that CA to `db`), then the normal shim path;
  2. enrol our certificate in `db` directly: firmware setup's "enroll
     signature/image" where offered, or Setup Mode. Last resort: per-vendor
     menus, and removing Microsoft's CAs by mistake breaks GPU option ROMs.

  Either way **the Windows tool first suspends BitLocker for exactly one
  reboot** (`manage-bde -protectors -disable C: -RebootCount 1`), so the next
  Windows boot does not ask for the recovery key and re-seals to the new
  PCR 7 by itself. Then it guides the firmware step.
 if that distribution's shim is
  revoked by SBAT or `dbx`, paguro follows the distribution's replacement; the
  repair hook installs it. Nothing else changes, because our trust is the MOK
  key, not the shim vendor's.
- **To verify (§11):** the chosen shim loads a MOK-signed second stage named in
  load options; and how `paguro.efi` then gets **MOK-signed next images**
  (locally signed UKIs) accepted — firmware `LoadImage` checks `db` only, so
  this relies on shim's `LoadImage` hook / loader protocol in recent shim, or
  on `SHIM_LOCK->Verify` plus loading the PE ourselves. Distribution-signed
  GRUB is unaffected: it is started through the distribution's own shim, which
  is `db`-verified (§3.2).

## 3. `paguro.ini`

### 3.1 Grammar — FROZEN

`[section]`, `key=value`, `#comment`. Whitespace around names and values is
stripped. No includes, continuations, escapes, quoting or interpolation. UTF-8,
LF or CRLF. **Maximum 65 536 bytes**, read into a buffer one byte larger.
`#` starts a comment only at the start of a line (no inline comments). A key
before any section header is an error. Duplicate keys within a known section are
an error. Unknown sections are ignored; unknown keys in a known section are an
error (so typos are loud). Booleans are exactly `0` or `1`. In `[Boot.*]`,
`volume` is required, and exactly one of `root` or `efi_file` at least:
`root` is required unless `efi_file` is set; `efi_file` excludes `efi_disk`
and `efi`.

Reference: `paguro-core::ini` (grammar) and `paguro-core::config` (schema).

### 3.2 Schema v1 — DRAFT

**The `.ini` is the bootloader's configuration and nothing else.** Each boot
entry says two things: where the Linux root disk is (a hint forwarded to
Linux), and where the next UEFI image is. Additional disks, mounts and
Linux-side policy are Linux's configuration, not the loader's.

```ini
# paguro configuration. Not hand-editable: use `paguro config`.
[Paguro]
version = 1
# a [Boot.*] name
default = debian

[Boot.debian]
# GPT partition GUID of the NTFS volume holding this entry's files;
# may be on any disk
volume   = 6c0a0000-0000-4000-8000-000000000000
# the Linux root disk: claimed by the module, handed to Linux as its root
root     = \paguro\debian.vhd
# the disk holding the next UEFI image; optional, default = root
efi_disk = \paguro\debian.vhd
# the UEFI image on efi_disk's FAT32; optional,
# default = the removable-media path for this architecture
efi      = \EFI\BOOT\BOOTX64.EFI

[Boot.rescue]
volume   = 6c0a0000-0000-4000-8000-000000000000
# a UEFI image stored directly on the NTFS volume; excludes efi_disk and efi,
# and root becomes optional
efi_file = \paguro\rescue.efi

[TPM]
enabled = 1

[SetupTPM]
enabled = 1

[Passphrase]
# opt-in, DESIGN §6
enabled = 0
```

| Key | Type | Bounds |
|---|---|---|
| `version` | integer | must be `1` |
| `default` | entry name | must name a present `[Boot.*]` |
| entry name | `[A-Za-z0-9_-]{1,32}` | ≤ 16 entries |
| `volume` | GPT partition GUID | canonical 36-char form |
| `root`, `efi_disk`, `efi_file` | NTFS path on `volume` | ≤ 32 components, each ≤ 255 UTF-16 units, total ≤ 1024 bytes |
| `efi` | FAT path | same bounds |

**Disk format is detected, not configured.** A file whose last 512 bytes are a
valid fixed-VHD footer (cookie, disk type 2, checksum, `current_size` = file
length − 512) is a VHD and its payload is everything before the footer;
anything else is a raw disk. The loader finds the FAT32 on `efi_disk` by
content:

| Payload starts with | UEFI image is read from |
|---|---|
| a GPT | the one partition of type ESP (`C12A7328-…`); zero or several → refuse |
| a FAT32 boot sector | the whole payload (a "superfloppy" FAT32 disk) |
| anything else | refuse |

**`root` is a hint the loader forwards, not a disk it opens.** The loader
resolves the path to the file's identity (MFT record and sequence number) and
puts it in the handoff; it never reads the root's contents. Linux's module
claims the file and exposes it as a block device, and whatever filesystem is on
it is Linux's to mount: ext4, ISO 9660 (`isofs`), squashfs, LUKS. The loader
only interprets `efi_disk`'s contents, and only to find the next UEFI image.

**A root disk need not be partitioned.** `root` may hold a GPT, or a bare
filesystem (ext4 directly on the payload — the same shape as a WSL distribution
disk). The paguro host uses exactly that: its UKI as an `efi_file` on NTFS, its
root a VHD with one ext4 and nothing else. Its kernel updates replace the UKI
through view C (write new, rename), which the host does while the VM is off.

**The structural assertion follows the content** (DESIGN §4.3: checked by the
module on view A before anything mounts — in Linux, not in the loader — and it must catch extents gathered in the wrong
order, so it reads past the first extent):

| Root content | Assertion |
|---|---|
| GPT | primary header CRC, the backup header at the last LBA, and each partition's first sector signature where known (FAT, ext4) |
| bare ext4 | superblock magic `0xEF53` at byte 1 080, and the backup superblock in block group 1 agreeing on UUID and block count |
| ISO 9660 | primary volume descriptor, and the volume space size equal to the payload length |


The loader publishes **the whole disk** (`efi_disk`'s payload) as a
**read-only** `EFI_BLOCK_IO_PROTOCOL` with a device path, whose reads resolve
through the extent map and BitLocker, then calls `ConnectController` so the
firmware's partition and FAT drivers bind it (DESIGN §4.2 tier 1; own FAT
`SimpleFileSystem` as the fallback, tier 2). The UEFI image is loaded by device
path, so it inherits a `DeviceHandle`. `WriteBlocks` returns
`EFI_WRITE_PROTECTED`: the loader never writes to disk, whoever asks.

**What `efi` may point at:**

| Next image | Works because |
|---|---|
| a UKI | it needs nothing but itself (also from `efi_file`) |
| systemd-boot | it enumerates `/EFI/Linux` off its `DeviceHandle` |
| **the distribution's own shim + GRUB** | GRUB's `efidisk` driver uses every `BlockIo` handle, so the image is an ordinary disk to it: its own ext4/btrfs/LVM/LUKS modules read `/boot` inside the image. **No GRUB module of ours** |

The third row is what makes stock distribution images bootable unchanged at the
boot-loader level. What a stock image still needs, stated plainly:

- **one package in the image** (`paguro`, §11.6): `dm-paguro` as DKMS source,
  built on the machine against whatever kernel is installed, and the
  initramfs-tools/dracut hook that reads the handoff and builds the views. A
  stock initramfs cannot find a root inside a VHD inside NTFS on its own;
- **GRUB's writes fail**: `save_env`/`recordfail` meet a write-protected disk
  and GRUB carries on (to be confirmed per distribution, §11);
- **nested shim**: paguro, itself loaded by shim, `LoadImage`s the
  distribution's Microsoft-signed shim, which then verifies GRUB and the kernel
  with the distribution's own key. Needs the Microsoft third-party UEFI CA in
  `db` and a shim that tolerates an existing `SHIM_LOCK` protocol (to be
  confirmed, §11).

**Decisions, argued:**

- **One volume per entry, any disk.** `volume` moved from `[Paguro]` into each
  entry, so entries may live on different NTFS volumes and different disks.
  The loader unlocks only the chosen entry's volume, with that volume's seals
  (`\EFI\paguro\<volume-guid>\`). `root` and `efi_disk` share the entry's
  volume: two volumes for one boot would mean two unlocks before the kernel.
- **A UEFI image directly on NTFS is allowed, as the secondary mode
  (`efi_file`).** Reading it costs little: the loader already reads NTFS files
  by path (the image, `hiberfil.sys`, `$Volume`). It is loaded with
  `LoadImage(SourceBuffer)`, **never jumped to**: `LoadImage` runs Secure Boot
  verification, and executing a buffer directly would be a Secure Boot bypass.
  What it gives up, and why it is not the default:
  - **no `DeviceHandle`**, so no systemd-stub credentials or add-ons and no
    systemd-boot behind it;
  - **kernel updates need NTFS writes**: Linux can only write the file through
    view C, which is exclusive with the VM and puts every kernel update through
    the NTFS dirty-bit path. A UKI inside the image's own ESP updates any time.

  Its use is images Windows manages: the paguro rescue or installer UKI, which
  the Windows tool can drop onto C: without touching the inside of a VHD.
- **No discovery inside the ESP.** Multiple kernels, boot counting and rollback
  are systemd-boot's job: point `efi` at systemd-boot and it enumerates
  `/EFI/Linux` and `/loader/entries` off the `DeviceHandle` we gave it. The
  loader's own picker chooses between `[Boot.*]` entries and nothing else.
- **No `format` or `expose` keys.** Format is detected (above). How Linux
  presents a disk (block device or file, the WSL tier) is Linux's policy.

PCR selection is **not** in the `.ini`: it lives in each seal file (§4), where a
wrong value fails the policy digest instead of needing a parser to trust it.

### 3.3 Integrity — FROZEN

- Firmware variable `PaguroConfigHash` (§5) holds `SHA-256(paguro.ini)`.
- **The comparison runs only when Secure Boot is enabled.** With Secure Boot
  off, the loader itself can be substituted, so the hash would protect nothing;
  the PCR 12 ratchet (§6) still binds the TPM rung either way.
- Mismatch (Secure Boot on) → the configuration is unusable: the loader enters
  recovery (DESIGN §4.1), which never parses the `.ini`.
- Writers: write `paguro.ini.new`, set the variable, rename. The loader never
  reads `.new` or `.bak`.

## 4. Seal files — DRAFT (v1)

All seal files share one header and differ in body. Reference:
`paguro-core::seal`. Maximum file size 4096 bytes.

```text
header   magic[8]      "PGRTPM\0\x01" | "PGRSTP\0\x01" | "PGRPAS\0\x01" | "PGRBYP\0\x01"
body
  tpm         pcr_bank u16 | pcr_mask u32 | wrapped_vmk[32] | salt[16] | sealed
  setuptpm    wrapped_vmk[32] | salt[16]
  passphrase  wrapped_vmk[32] | salt[16]
  pin bypass  deadline u64 | pcr_bank u16 | pcr_mask u32
              | wrapped_vmk[32] | salt[16] | sealed

sealed       len u16 | TPM2B_PUBLIC | TPM2B_PRIVATE     (len ≤ 1024;
             the two TPM2B values in TPM marshalling, big-endian sizes,
             and they must exactly fill len)
```

- `pcr_bank` is a `TPM_ALG_ID`; v1 accepts only `0x000B` (SHA-256).
- `pcr_mask` bit *n* = PCR *n*; v1 requires exactly `{0,2,4,7,12}`.
- `deadline` is TPM `Clock` in milliseconds (DESIGN §6, PIN bypass).
- **Parent key**: the TCG-standard ECC P-256 storage key template, created with
  `TPM2_CreatePrimary` under the owner hierarchy on each use and never
  persisted. Deterministic, so Windows and Linux reproduce the same parent
  without an NV handle. (**OPEN**, DESIGN §11 Q12: if a persistent SRK is
  present, use it instead.)
- **Object policy**: `PolicyPCR(bank, mask)` ∧ `PolicyAuthValue`; bypass adds
  `PolicyCounterTimer(Clock < deadline)`. `userWithAuth` clear, `noDA` clear.

The files are self-validating (DESIGN §6): no field is trusted, a wrong value
fails at the TPM or at the FVEK unwrap.

## 5. Firmware variables — FROZEN

Vendor GUID from §1.

| Name | Size | Attributes | Written by | Read by |
|---|---|---|---|---|
| `PaguroB` | 32 | NV \| BS | loader, first boot | loader |
| `PaguroConfigHash` | 32 | NV \| BS \| RT | initrd, Windows tool | loader (Secure Boot only) |
| `PaguroSetup` (`S`) | 32 | NV \| BS \| RT | Windows tool | loader, which deletes it before handoff |
| `PaguroTpmBroken` | 1 | NV \| BS \| RT | loader | Windows tool |

Plus the standard `BootNext` / `Boot####` (the bootstrap entry, §9).

**`PaguroTpmBroken` lifecycle.** It means "the standing TPM seal does not match
this machine any more", and whoever makes it match again clears it:

| Event | Who | Flag |
|---|---|---|
| TPM rung fails its policy (PCRs moved) | loader | set |
| Windows sees the flag, stages `setupTPM`, reboots into Linux | Windows tool | cleared when staging |
| a boot on another rung (passphrase, recovery) whose initrd re-seals against this boot's PCR values (handoff `PCRS`) and writes the new `tpm_seal.bin` | initrd | cleared after the file is written |
| a boot whose TPM rung succeeds **and its key opens the volume** (the FVEK unwrap confirms it; a successful unseal alone does not) | loader | cleared, read first so a normal boot writes nothing |

A successful boot alone does not clear it: only a seal that matches again
does. If the `setupTPM` boot itself fails, the loader sets it again.

Any size mismatch → the variable is treated as absent.

## 6. Measurements (PCR 12) — FROZEN

Using `EFI_TCG2_PROTOCOL.HashLogExtendEvent`, event type `EV_EVENT_TAG`
(`0x06`), tagged with the paguro event GUID. The digest is the SHA-256 of the
data hashed:

| Event | Data hashed | Digest |
|---|---|---|
| load taint | the whole verified `paguro.ini` | `SHA-256(paguro.ini)` |
| boot taint | ASCII `paguro/boot-taint/v1` | fixed |

Seals are made against the value after the load taint,
`PCR12 = SHA-256(0³² ‖ SHA-256(paguro.ini))`, computed rather than read. The
loader refuses if PCR 12 is not all zeros before its first extend (DESIGN §6).

## 7. Key derivation — FROZEN

Exactly as DESIGN §6 and `paguro-crypto`. The labels are part of the
interface:

```text
paguro/tpm-auth  paguro/env/tpm  paguro/env/setup  paguro/env/passphrase
paguro/rootgate  paguro/final    paguro/offlineGate  paguro/bootstrap
```

Test vectors live in `crates/paguro-crypto/tests/vectors.rs` and must be
reproduced by any second implementation (the Windows tool).

## 8. Loader → initrd handoff — DRAFT

**Transport:** one `EfiRuntimeServicesData` allocation, published as a UEFI
configuration table under the handoff GUID. Read once by the Linux handoff
driver, copied to kernel memory, and the original zeroed. Never on the command
line, in a variable or in a file.

**Format:** header then TLV records. Maximum 96 KiB (room for a maximal `CONFIG`). Reference:
`paguro-core::handoff`.

```text
header   magic "PGRHOF\0\x01" | total_len u32 | record_count u16 | reserved u16
record   type u16 | len u32 | value[len]        (no padding)
```

| Type | Name | Value | Occurs |
|---|---|---|---|
| 1 | `VOLUME` | partition GUID[16] \| first_lba u64 \| sectors u64 (512-byte units) | 1 |
| 2 | `VMK` | 32 bytes | 0–1 (absent = unencrypted volume) |
| 3 | `FVEK` | cipher u16 \| key len u16 \| key | 0–1 |
| 4 | `FVE_LAYOUT` | metadata offsets u64×3 \| region size u64 \| boot-sector reloc offset u64, sectors u32 \| encrypted_size u64 | 0–1 |
| 5 | `B` | 32 bytes | 1 |
| 6 | `PCRS` | mask u32 \| n×32-byte SHA-256 values (no TPM: mask `0x95`, zero values) | 1 |
| 7 | `CONFIG` | the verified `paguro.ini` bytes | 0–1 |
| 8 | `IMAGE` | role u8 (1 = root, 2 = efi disk, 3 = efi file) \| name len u8 \| name \| mft_record u64 \| mft_seq u16 | 0–2: the chosen entry's `root`, and its `efi_disk` or `efi_file` when different from `root` |
| 9 | `STATE` | flags u32: 1 = hibernation image, 2 = dirty bit, 4 = config unverified (also: Secure Boot off, first boot), 8 = recovery path | 1 |
| 10 | `RUNG` | u8: 1 tpm, 2 setuptpm, 3 passphrase, 4 recovery, 5 pin bypass, 6 bootstrap, 7 clear key (BitLocker suspended), 8 unencrypted volume | 1 |
| 11 | `PROVISION` | sealed object, wrapped VMK, salt (as the tpm seal body), sealed against the load taint of the `CONFIG` the loader authored on this boot | 0–1 |

Unknown type → refuse. Duplicate of a type that occurs at most once → refuse.

`IMAGE` gives the file's identity; it never gives its location. Only the chosen
entry's files are forwarded; the whole verified configuration travels in
`CONFIG` for anything else Linux needs. The kernel
module reads the extents itself (§10).

### 8.1 Decisions recorded from the first implementation

- **Passphrase stretch salt:** each seal file's own `salt`; the bootstrap payload
  its own.
- **PIN bypass:** `VMK = wrapped_vmk XOR D`; `authValue` empty; the `salt` field
  is present but unused. Policy order `PolicyPCR`, `PolicyCounterTimer`,
  `PolicyAuthValue`. The Windows writer must match.
- **TPM objects:** parent = SRK template, empty unique, AES-128-CFB symmetric;
  sealed object `fixedTPM | fixedParent`; policy order `PolicyPCR`,
  `PolicyAuthValue`.
- **Event log:** `TCG_PCClientTaggedEvent`, tag id = first 4 bytes of the paguro
  event GUID, data = GUID ‖ label (`paguro/load-taint/v1`,
  `paguro/boot-taint/v1`).
- **Provisioning boot:** the loader authors the first `paguro.ini`, seals against
  its load taint, and forwards both (`CONFIG`, `PROVISION`); the initrd writes
  them.
- **Bootstrap entry:** found through `BootCurrent`; only that `Boot####` is
  deleted, also when its payload is malformed.
- **Hash variable missing with Secure Boot on:** straight to recovery.
- **GPT:** primary header only; entry array ≤ 16 KiB.

### 8.2 Handoff driver — OPEN

How Linux reads the table (a small module or early init code) and what it
exposes to the initrd (e.g. a read-once `/dev/paguro-handoff`).

## 9. Bootstrap boot entry — DRAFT

The installer's one-shot `Boot####` entry points at `paguro.efi`; its
`OptionalData`:

```text
magic "PGRBST\0\x01" | volume GUID[16] | salt[16] | wrapped_vmk[32]
wrapped_vmk = VMK XOR HMAC(pass_hash, "paguro/bootstrap" || salt)
```

The loader deletes the entry as its first action (DESIGN §6 Bootstrap).

## 10. Kernel module — DRAFT

The module is two pieces, deliberately separated for review:

| Piece | Files | Kernel APIs | Reviewed as |
|---|---|---|---|
| **core** | `pg_range.c`, `pg_ntfs.c` | none: plain C over byte buffers and a read callback | the trusted core; small enough to hand-write; compiled into userspace for tests and fuzzing |
| **glue** | `dm-paguro-main.c`, `pg_ctl.c` | device-mapper, misc device, block I/O | boring; exercised in a VM |

### 10.1 What the core computes

Given a read-sector callback over the **plaintext** NTFS volume and a file
identity `(mft_record, mft_seq)`:

1. Boot sector: validate `NTFS    ` OEM id, bytes/sector ∈ {512, 4096},
   sectors/cluster power of two, cluster ≤ 2 MiB, MFT record size, `$MFT` LCN in
   range.
2. `$MFT` record 0: apply update-sequence fixups, decode its `$DATA` runlist —
   the map from record number to disk.
3. The file's record: fixups, in-use, not a directory, sequence number equals
   `mft_seq`, base record (not an extension).
4. Attributes: bounded walk. Refuse `$ATTRIBUTE_LIST` beyond 64 extension
   records. Unnamed `$DATA` must be non-resident, not compressed, not sparse,
   not encrypted.
5. Runlist(s): decode, concatenate across extension records in VCN order, no
   gaps, no sparse runs; `allocated_size == Σ run lengths × cluster size`.
6. Output: extents in sectors, file order (for view A) and normalised (for the
   range test). Capacity fixed at build time (`PG_MAX_EXTENTS`, 65 536).
7. Volume assertions (record 3 `$Volume` dirty flag) are a separate call.

Every step has a typed error. The Rust reference is `paguro-core::ntfs`; the C
is differential-tested against it (§12).

### 10.1a Decisions recorded from the first implementation

- **Growth:** extents are coalesced, so the old list must be a prefix of the new
  one except that its last extent may be extended in place (NTFS extends the
  last run when the new clusters are adjacent).
- **Extra refusals:** `$MFT` with an `$ATTRIBUTE_LIST`; initialized size short
  of the file size; a file size not a multiple of the sector size; record
  numbers < 24 or ≥ 2³²; record layouts other than NTFS 3.1. The 64-record
  limit counts `$DATA` segments outside the base record.
- **Cross-check is mandatory:** `paguro-image` loads only after a passing
  `PG_CROSSCHECK`; `PG_GROW` clears it.
- **Dirty volume:** claims are read-only, view B is refused, views A and C load
  read-only.
- **Every re-read** (claim, grow) must see the geometry `PG_VOLUME_ADD` saw.
- Core files: `pg_range.c`, `pg_claim.c`, `pg_ntfs.c` (which also holds the
  GPT + FAT ESP payload check). Requires Linux ≥ 6.9.

### 10.2 Control device `/dev/paguro` — DRAFT

`ioctl`s with fixed-size structs, `_IOWR('p', n, ...)`, defined in
`kernel/dm-paguro/paguro_uapi.h`; each carries an `error` out-field
(`PG_ERR_*`), devices as major/minor. Userspace passes
**identities and devices, never extents**.

| ioctl | In | Effect |
|---|---|---|
| `PG_VOLUME_ADD` | raw (ciphertext) dev_t, plaintext dev_t, volume GUID, reserved ranges (≤ 8) | registers a volume; parses its boot sector. Reserved ranges are BitLocker's non-data regions from the handoff `FVE_LAYOUT`: sectors `[0, reloc_len)`, the relocated boot-sector copy, the three metadata regions. **Subtract-only**: they can make a claim fail, never make one succeed |
| `PG_CLAIM` | volume id, mft_record, mft_seq, format | core derives extents; refuses intersection with any other claim **or any reserved range**; returns claim id |
| `PG_GROW` | claim id | re-derives; accepted only if the old extents are an exact prefix of the new (append-only); otherwise the claim becomes read-only |
| `PG_CROSSCHECK` | claim id, extent list from ntfs3 FIEMAP | compares only; mismatch → claim is refused, never amended |
| `PG_RELEASE` | claim id | only when no view uses it |
| `PG_VOLUME_REMOVE` | volume id | only when it has no claims or views |
| `PG_STATUS` | — | counts, refused I/O, per-claim state |

### 10.3 Device-mapper tables

```text
view A   0 <len> paguro-image  <claim_id>
views B/C 0 <len> paguro-volume <volume_id> <b|c>
```

- `paguro-image` maps the claim's gathered extents; length = VHD payload for
  `format=vhd`. Before first use it asserts the payload's structure (GPT with a
  FAT ESP, DESIGN §4.3).
- `paguro-volume` passes I/O through to the raw (B) or plaintext (C) device and
  returns `EIO` for any request intersecting any claim on that volume.
- **B and C on one volume are mutually exclusive**; the module refuses the
  second table load.
- Growth: after `PG_GROW` succeeds, userspace reloads the `paguro-image` table
  with a larger length. The module refuses a length beyond the claim.

### 10.4 View C guard (Linux-side minifilter) — DRAFT

Quality of experience, not correctness (DESIGN §5b Rule 2). While view C is
mounted, for every claimed image on that volume:

- a BPF-LSM program keyed on `(dev, ino)` → claim id denies `file_open`,
  `path_truncate`, `inode_setattr`, `inode_unlink`, `inode_rename`,
  `inode_link`, `inode_setxattr`, `inode_removexattr`, `inode_file_setattr`,
  `file_permission` with `EACCES` (`EBUSY` for unlink/rename/link), except for
  the growth service's cgroup. Its link is pinned; it also denies removing its
  own pin and unmounting that bpffs. Requires `lsm=…,bpf`.
- the image carries the NTFS `SYSTEM` attribute; view C is mounted
  `sys_immutable,ads=0` and never `discard`.
- `paguro-volume` fails `REQ_RAHEAD` bios on claimed extents quietly and counts
  every other hit as a guard failure (`PG_STATUS`).

Test: every operation on the image (by path, 8.3 alias, hard link, file handle,
ADS name) is refused with `EACCES`/`EPERM`/`EBUSY`, never `EIO`; a volume-wide
stress (walk, fill to ENOSPC, mass create/delete, `fstrim`, remount, dirty
`$LogFile`) causes zero non-readahead hits in `PG_STATUS`; only a reboot removes
the guard.

### 10.5 File exposure (`expose=file`) — OPEN

Single-file filesystem `paguro-img` over a `paguro-image` device (see the WSL
tier discussion). Not part of v1's trusted core.

## 11. Windows side — DRAFT

### 11.1 Minifilter ↔ service

Filter communication port `\PaguroPort`, admin-only. Messages are fixed-size
structs, versioned:

| Message | Direction | Content |
|---|---|---|
| `PROTECT` | service → filter | volume GUID, file id (128-bit), deny flags |
| `UNPROTECT` | service → filter | volume GUID, file id |
| `EVENT` | filter → service | a denied operation: file id, operation, process |

The filter keeps no state across reboots; the service re-sends `PROTECT` for
every image listed in `paguro.ini` at start. The filter is not a correctness
component (DESIGN §4.4).

### 11.2 `paguro` CLI (Windows)

| Command | Effect |
|---|---|
| `paguro install <distro>` | build the image through WSL2 (§11.4), write `.ini`, set `PaguroConfigHash`, create the bootstrap entry |
| `paguro restart-linux` | pre-flight, write the PIN-bypass seal, `BootNext`, restart |
| `paguro stage-setup` | stage `setupTPM` (`S` + `setuptpm_seal.bin`) |
| `paguro repair` | re-install ESP files, re-stage if needed (DESIGN §7) |
| `paguro uninstall` | DESIGN §6b |
| `paguro config ...` | the only editor of `paguro.ini` |

### 11.4 Installing a distribution: the distribution's ISO, in a WSL2 container — DRAFT

**WSL2 is a requirement** (Windows 10 2004+ / 11, any edition). **No
distribution installer ever runs against the real disk, and no ISO is ever
booted.** A stock installer on bare metal would see the physical disk with
Windows on it; a stock live initramfs cannot find its media inside a VHD inside
NTFS, or behind BitLocker, without our driver injected into it. Building the
image from Windows removes both problems, and inside WSL2 the only disk an
installer can see is the one we attach.

```text
paguro install <distro>              (Windows, admin)
  1. export the host hardware                     (§11.5)
  2. create the file      fixed VHD, diskpart `create vdisk type=fixed`
                          (works on Home; no Hyper-V module)
  3. wsl --mount --vhd --bare   the VHD is the only extra disk in WSL2
  4. the distribution's own live system, as a privileged container in WSL2:
       download the ISO, verify SHA256SUMS and its signature
       mount the ISO at /cdrom, its squashfs as the rootfs (overlay on top)
       systemd-nspawn -b with only mnt, pid, uts and ipc namespaces and no
         seccomp or capability filters: the live system's own systemd,
         dbus, udisks and snapd run as on a live boot
         /dev/sdX (the VHD) the only real disk it is given
         WSLg sockets bound in, so the installer's GUI shows on Windows
       run the distribution's installer; the adapter makes it write a
         paguro-ready system itself (below), so there is no step after it
  5. wsl --unmount
  6. write paguro.ini, PaguroConfigHash, the bootstrap Boot#### entry
```

- The `paguro` package reaches the target like any package the installer
  copies, so the driver is in the image from its first boot — no injection
  problem.
- The same path makes an existing WSL distribution bootable: its rootfs is the
  source in step 4.
- **Why the ISO and not a bootstrap tool.** The install is the distribution's
  own: its installer, its package selection and defaults, the bits it ships,
  offline if the ISO is local. The live system already contains every tool the
  installer needs; we only give it a container instead of a machine.
- **The installer writes the right system itself; no post-install chroot.**
  Every installer copies a filesystem and then generates the initramfs, so the
  adapter puts paguro's pieces where that copy and that generation pick them
  up:
  - **the copy source is an overlay**, not the bare squashfs. Our layer holds
    **only paguro's own packages**, installed as real packages (registered with
    dpkg/rpm, so the target upgrades them): `paguro` (§11.6) and the Windows
    VM stack (QEMU, OVMF, our VM
    integration). **No firmware and no drivers from us**: choosing those is the
    installer's job (§11.5). Installers copy from the squashfs *file*, not from
    the running root (Calamares `unpackfs`, Ubuntu's layered squashfs via
    `curtin`, Anaconda from the live base device), so the adapter points the
    installer's source at the overlay mount rather than relying on the
    container's root;
  - **the installer's own initramfs step** (`update-initramfs`, `dracut`) then
    includes our hook, because the package is already in the target;
  - **the bootloader through the distribution's own settings, which stay
    correct afterwards:** Debian/Ubuntu `grub2/update_nvram=false` and
    `grub2/force_efi_extra_removable=true` (debconf); the equivalent per
    distribution. The image's GRUB must never write `Boot####` entries: the
    firmware cannot see the nested ESP, and `paguro.efi` is what starts it.
    No wrapper binaries in the target.
- **The adapter is data plus hooks per distribution**: where its installer
  reads its source, its bootloader settings, and a hook before its initramfs
  step if the package list alone does not reach it (Calamares module order,
  Ubuntu autoinstall `packages`, Anaconda kickstart `%packages` from our
  repository).
- **To verify first** (§11): that the WSL2 kernel mounts ISO 9660 and squashfs
  (fallback: `squashfuse`, `bsdtar`), that partition nodes created by the
  installer appear inside the container, and that the GUI works over WSLg.
- **The scripted path stays** as the fallback for distributions without an
  adapter: debootstrap / `dnf --installroot` / pacstrap into the VHD, then the
  same chroot step.
- The same flow makes an existing WSL distribution bootable: its rootfs is the
  source instead of an installer.

The loader has no ISO support: ISOs are opened in WSL2 at install time, and
Linux can still mount one from a claimed file with `isofs`.

### 11.5 Host hardware export — DRAFT

Inside WSL2 the installer's hardware detection sees Hyper-V's synthetic
devices, not the machine. **paguro does not pick drivers or firmware**; it makes
the installer's own detection see the real machine, by exporting it from
Windows.

**Collected on Windows** (SetupAPI, present devices only; SMBIOS through
`GetSystemFirmwareTable`; CPUID), written to `host-hardware.json` and kept in
the image at `/etc/paguro/host-hardware.json`:

```json
{ "version": 1,
  "cpu":     { "vendor": "GenuineIntel", "family": 6, "model": 170, "stepping": 4 },
  "dmi":     { "sys_vendor": "…", "product_name": "…", "board_vendor": "…",
               "board_name": "…", "bios_vendor": "…", "bios_version": "…" },
  "pci":     [ { "vendor": "10de", "device": "28a0", "subvendor": "1043",
                 "subdevice": "1f3a", "class": "030000" } ],
  "usb":     [ { "vendor": "8087", "product": "0033", "class": "e0" } ],
  "acpi":    [ "PNP0C50", "INT33D2" ],
  "storage": [ { "bus": "nvme", "model": "…", "size": 1024209543168 } ] }
```

**Presented to the installer as a synthetic sysfs**, generated from the export
at `/run/paguro/hostsys`: one directory per device with the `modalias`,
`vendor`, `device`, `subsystem_*` and `class` files a real `/sys` has, plus
`class/dmi/id/*`. Detection tools are pointed at it where they support a root
(Ubuntu's `ubuntu-drivers` honours `UBUNTU_DRIVERS_SYS_DIR`); where a tool only
reads `/sys`, the adapter bind-mounts the synthetic devices over the paths that
tool reads, inside the installer's container only. The container's own `/sys`
stays real, so udev, systemd and the installer's disk handling are untouched.

The CPU needs nothing: WSL2 passes CPUID through, so `/proc/cpuinfo` already
names the real processor and microcode selection works as is.

What this reaches, by installer: Ubuntu's "install third-party drivers"
(NVIDIA and other proprietary drivers, chosen by modalias); Debian's
`isenkram`/firmware checks; Calamares' driver modules. Installers that install
all firmware unconditionally (Fedora's `linux-firmware`) need nothing.

### 11.6 The `paguro` package: source, built on the machine — DRAFT

**We ship source, never binaries per kernel.** The package carries
`dm-paguro` as a DKMS module and depends on the distribution's compiler and its
kernel-headers package for the installed kernel flavour (`linux-headers-*`,
`kernel-devel`, `linux-headers`). DKMS builds it in the target during the
install and again on every kernel install, so custom and self-built kernels
work whenever their headers are present. What we maintain is **source
compatibility across kernel versions** (`#if LINUX_VERSION_CODE` in the glue
only — the core has no kernel dependency), checked in CI against the kernels
of every supported distribution plus mainline and `linux-next`.

The per-distribution part is packaging, not builds: one `deb`, one `rpm`, one
Arch package, each a thin wrapper around the same source and hooks.

**A kernel update must never produce an unbootable entry.** The initramfs hook
**fails the initramfs build** if `dm-paguro.ko` is missing for that kernel, so a
DKMS build failure fails the kernel package's install loudly and the previous
kernel stays the default, instead of an initramfs that cannot find its root.
Ordering: DKMS runs before initramfs generation (`/etc/kernel/postinst.d/dkms`
before `initramfs-tools`; dracut and `kernel-install` plugins likewise).

**Secure Boot: one machine key, enrolled once.** There is no paguro project
certificate. `paguro install` generates a **self-signed MOK key pair for this
machine**, and everything paguro-side is signed with it:

| Signed with the machine key | When |
|---|---|
| `paguro.efi` | at install, and on each paguro update (by Linux, below) |
| `dm-paguro.ko` | by DKMS, on every kernel install, for any distribution |
| locally built UKIs (`ukify`) | on each kernel install, where the distribution does not sign its own |

The chain is firmware `db` → a Microsoft-signed shim on the real ESP (a
distribution's `shim-signed`, redistributed unchanged) → `MokList` → the machine
key. Distribution-signed GRUB and kernels keep verifying through the
distribution's own shim (§3.2).

- **Enrolment, once:** WSL2 has no efivarfs, so `mokutil` cannot run at install.
  The Windows tool writes shim's `MokNew`/`MokAuth` variables itself
  (`SetFirmwareEnvironmentVariable`) and shows the one-time password; the next
  boot shows MokManager once. After that no install, distribution or kernel
  update ever asks again. With Secure Boot off, nothing is enrolled.
- **Where the private key lives.** It is needed on both sides: by the Windows
  tool for every later `paguro install` (a new distribution needs its DKMS
  module and UKI signed), and by each Linux image for its kernel updates.

  | Copy | Location | Default | Opt-in |
  |---|---|---|---|
  | Windows | `C:\ProgramData\paguro\mok\` — admin-only ACL, inside the BitLocker volume | plain file | **wrapped by the boot passphrase**, or **TPM-sealed** |
  | each Linux image | `/etc/paguro/mok/`, root-only, inside the image | plain file | wrapped by the boot passphrase, or sealed to PCR 11 |
  | Linux at runtime | the kernel keyring (root's `@u`) after unlock | — | — |

  **Never on the ESP.** A key wrapped by the boot passphrase is an offline
  guessing oracle for that passphrase — the private key can always be checked
  against the public certificate, tag or no tag — so it must only be readable
  by whoever could already read the encrypted volume. On C: or inside the
  image, reading it needs admin or the VMK; on the ESP any unprivileged Linux
  process could run the dictionary attack the root gate exists to prevent
  (DESIGN §6).

  **The passphrase wrap uses its own KDF, not the loader's.** The loader is
  bound to `bitlocker_stretch` for BitLocker compatibility; this key is not, so
  it uses Argon2id with its own salt and label (`paguro/mok-wrap`), which
  makes the oracle expensive rather than merely present.

  **What each option protects, stated plainly:**
  - *passphrase wrap:* the key at rest, and against a compromised Windows
    **unless the passphrase is typed into it** — which `paguro install` of a new
    distribution asks for;
  - *TPM seal for the Windows app:* only against the disk being read
    elsewhere. Any admin process in a running Windows can unseal it, so it is a
    convenience equal to "Windows holds the key";
  - *PCR 11 seal in Linux:* against Windows reading the image offline (DESIGN
    §6); the Linux side's default once opted in.

  **Linux signs through the keyring.** After unlock the key material sits in
  root's keyring; the DKMS and `ukify` signing hooks write it to a `0600` file
  on a `tmpfs` only for the duration of `sign-file`/`sbsign`, then remove it.
- The repair hook (DESIGN §7) restores the **already signed** `paguro.efi`
  from a copy kept on the ESP; it needs no key.

### 11.3 Guest agent (VM mode growth) — OPEN

virtio-serial channel `org.paguro.agent.0`; length-prefixed messages; the host
never trusts a reported extent without claiming it first and verifying it
against the on-disk MFT after a guest volume flush.

## 13. Loader UI and theme — DRAFT

### 13.1 Compiled in, extensible at build time

The loader parses no display data at run time (DESIGN §4.2 "Theme — compiled
in"): a display-parser bug would run under the identity PCR 4 attests, in the
process about to receive the volume key. **Extensibility lives at build time
instead.** A theme is a directory:

```text
themes/<name>/
  theme.toml      colours, fonts and sizes, spacing, and per-screen layout:
                  which element goes where (anchors, margins, alignment,
                  max widths), which images appear, options such as
                  show-logo / show-hints / bullet character
  images/*.png    logo, background, icons (any size; scaled variants chosen
                  per resolution)
  fonts/*.ttf     rasterised at build time for the sizes the theme uses
  strings/<lang>.toml   every user-visible string
```

`build.rs` (host `std`, free to use PNG, TOML and TTF crates) validates the
theme and emits Rust statics: pre-decoded pixels, pre-rasterised glyph alpha
maps, a layout table and the strings. **The loader binary contains no PNG,
TOML or font parser.** Choosing a theme or language is a build option
(`PAGURO_THEME`, `PAGURO_LANG`), which rides on the per-region builds DESIGN
§4.2 already plans. A theme that fails validation fails the build.

Changing the look means shipping a binary, so PCR 4 moves and machines re-seal
through the repair hook — deliberately (DESIGN §4.2).

### 13.2 Rendering

- Pure `no_std` core: `(Screen, UiState, Theme, resolution) → draw list`
  (rectangles, image blits, glyph runs), then a software rasteriser into any
  `Canvas` (a byte buffer). The firmware adapter only blits the canvas to the
  GOP framebuffer, or falls back to text output when there is no GOP.
- Resolution-independent layout: a scale factor from the framebuffer height;
  the whole UI is checked to fit from 800×600 to 3840×2160.
- Accessibility variants (high contrast, large text) are alternate themes or
  theme options chosen by a keypress at run time — both compiled in.

### 13.3 Text entry

Every text field (passphrase, PIN, recovery key, recovery path) supports:

| Key | Effect |
|---|---|
| printable | insert at the cursor |
| Backspace / Delete | delete before / after the cursor |
| ← / → / Home / End | move the cursor |
| **Insert** | toggle showing the secret in clear; off again on leaving the field |
| Enter / Esc | submit / back (Esc always leads somewhere) |

Secret fields show one bullet per character while hidden; the buffer lives in
caller memory and is zeroised on every exit. The 48-digit recovery key is
grouped in sixes as typed and accepts digits only.

### 13.4 Recovery: telling the loader where Linux is

Recovery never reads `paguro.ini` (DESIGN §4.1), so what it boots is chosen
on screen:

1. **volume** — a list of the NTFS volumes found on every disk (label, size,
   disk), each unlocked with the usual rungs;
2. **what to boot** — the entries found by convention in `\paguro\` on that
   volume, or a path typed into a text field;
3. if the choice is a **disk** (`efi_disk`), it is also the root;
   if it is a **UEFI image on NTFS** (`efi_file`), the root hint is picked:
   the only root candidate in `\paguro\` if there is exactly one, otherwise a
   list, otherwise none — and the initrd then asks.

The screen says the boot is unattested (DESIGN §4.1).

## 12. Testing contract

Each interface ships with:

| Level | What | Where | CI |
|---|---|---|---|
| unit | every error variant has a test | crate / C test | yes |
| property | parse(serialize(x)) = x; model vs implementation | proptest, harness | yes |
| fuzz | every parser of external data | `fuzz/` (cargo-fuzz, libFuzzer on the C core) | 60 s per target per push; longer nightly |
| differential | C core vs Rust reference on the same inputs, incl. fuzz corpora | `paguro-harness` | yes |
| mock boot | the loader's stage machine over an in-memory platform | `paguro-boot` tests | yes |
| QEMU | loader under OVMF (+ Secure Boot vars) + swtpm, real NTFS images from `mkntfs` | `test/qemu/` | yes |
| kernel VM | module in a throwaway VM, real I/O | `kernel/dm-paguro/test/` | yes |
| Windows, hosted | minifilter build + static analysis, test-signed load with `fltmc` on hosted `windows-2022/2025` (runner images ship with `TESTSIGNING ON`) | `windows/` | yes |
| Windows, WinPE VM | WinPE built with the ADK on a Windows runner, booted by QEMU/KVM on a Linux runner over the module's views: reboot, bugcheck and end-to-end (EIO + minifilter) tests | `test/winpe/` | yes (private artifacts only) |

### 12.1 Power loss after every write — the release bar

Every write sequence we can produce (ntfs3 growth, WinPE/Windows guest I/O
through view B, the module's own table changes) is recorded with
`dm-log-writes` under the volume, then replayed:

| Replay | Models |
|---|---|
| every prefix, one write at a time | power cut after write *n* |
| every flush/FUA point | power cut at a durability boundary |
| random subsets of writes since the last flush | the drive cache reordering or dropping unflushed writes |
| 4 KiB writes with only some 512-byte sectors landed (512e) | torn writes |

After each replayed state, the loader's parser, the module's C core and the
initrd path run against it. **Invariant: they return the image's correct extents
— the pre- or post-operation map, bit-exact — or a typed refusal
(dirty / hibernation / structural error). Never a different map.** Decrypting
the image's flushed sectors must give the bytes that were written.

### 12.2 Encryption conformance — Windows' sectors are the main risk

The guest writes ciphertext through view B; Linux reads the same sectors as
plaintext through dm-crypt. Any disagreement about data-unit size, tweak or
region boundaries silently corrupts data, so these are tested per commit:

- **Test vectors:** IEEE 1619 / NIST XTS-AES-128 and -256 vectors against the
  loader's XTS and against dm-crypt.
- **Three implementations agree:** the loader's decrypt, dm-crypt built from the
  handoff `FVE_LAYOUT`, and an oracle (libbde/dislocker) on the same volume.
- **Data unit and tweak:** 512-byte and 4 KiB (4Kn) volumes; tweak = data-unit
  index from the volume start. Views report `logical_block_size` = the data unit,
  and a misaligned direct I/O is refused (`EINVAL`), never a read-modify-write.
- **Sector numbering is 1:1.** The plaintext view has the same size and LBAs
  as the ciphertext; nothing is skipped. The non-data regions are *remapped*
  (boot sector ← its relocated copy) or *hidden* (metadata regions, which NTFS
  sees as allocated to hidden system files). A test on real fixtures asserts
  this, and asserts what Windows returns for those regions, so our plaintext
  view matches it byte for byte.
- **A protected file over a non-data region is refused.** On a consistent
  volume NTFS never gives those clusters to a user file. A crafted or corrupted
  runlist can, and then the file's "data" there is not its data in either view.
  Fixtures: a runlist extent overlapping each metadata region, the relocated
  boot sector, and sectors `[0, reloc_len)`; the loader and the module must both
  refuse, and neither view is created.
- **A protected file straddling `encrypted_size`** on a partly encrypted volume
  is legitimate (conversion in progress). Its bytes must read correctly through
  view A, and view B/C must refuse its extents on both sides of the boundary.
- **Boundaries:** writes that touch or straddle the relocated boot sector, each
  FVE metadata region, and `encrypted_size` on a partly encrypted volume
  (sectors past it are plaintext).
- **Round trips both ways:** write through view C (ntfs3), read the raw
  ciphertext, decrypt independently; write ciphertext as the guest would (our XTS
  in userspace, and WinPE through view B), read through dm-crypt.
- **Real BitLocker fixtures:** VHDs encrypted by Windows (hosted runner or
  WinPE) with a known password and recovery key, XTS-128 and XTS-256, 512e and
  4Kn. Unsupported ciphers (legacy AES-CBC, diffuser) are refused with a clear
  error.

Parsers of external data in scope: `ini`, `seal`, `fve`, `ntfs`, `gpt`, `fat`
(when written), `vhd`, `handoff`, `bootstrap`, TPM response parsing.
