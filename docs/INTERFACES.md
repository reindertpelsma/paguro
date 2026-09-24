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
  shim<arch>.efi, mm<arch>.efi   distribution shim (optional; see DESIGN §12)
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

## 3. `paguro.ini`

### 3.1 Grammar — FROZEN

`[section]`, `key=value`, `#comment`. Whitespace around names and values is
stripped. No includes, continuations, escapes, quoting or interpolation. UTF-8,
LF or CRLF. **Maximum 65 536 bytes**, read into a buffer one byte larger.
`#` starts a comment only at the start of a line (no inline comments). A key
before any section header is an error. Duplicate keys within a known section are
an error. Unknown sections are ignored; unknown keys in a known section are an
error (so typos are loud). Booleans are exactly `0` or `1`. In `[Boot.*]`,
`volume` and `root` are required.

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
| `root`, `efi_disk` | NTFS path on `volume` | ≤ 32 components, each ≤ 255 UTF-16 units, total ≤ 1024 bytes |
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

Either way the FAT32 is published as a real `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`
and the UEFI image is loaded by device path, so it inherits a `DeviceHandle`
(DESIGN §4.2 — systemd-stub needs it).

**Decisions, argued:**

- **One volume per entry, any disk.** `volume` moved from `[Paguro]` into each
  entry, so entries may live on different NTFS volumes and different disks.
  The loader unlocks only the chosen entry's volume, with that volume's seals
  (`\EFI\paguro\<volume-guid>\`). `root` and `efi_disk` share the entry's
  volume: two volumes for one boot would mean two unlocks before the kernel.
- **No UEFI image directly on NTFS.** Loading from NTFS would mean either
  `LoadImage` from a buffer, which leaves `DeviceHandle` unset and breaks
  systemd-stub's credentials and add-ons, or our own NTFS `SimpleFileSystem`,
  more parser for nothing a small FAT32 VHD beside it does not already give.
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
| 8 | `IMAGE` | role u8 (1 = root, 2 = efi disk) \| name len u8 \| name \| mft_record u64 \| mft_seq u16 | 1–2: the chosen entry's `root`, and its `efi_disk` when different |
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
| `paguro install <distro>` | create the image, write `.ini`, set `PaguroConfigHash`, create the bootstrap entry |
| `paguro restart-linux` | pre-flight, write the PIN-bypass seal, `BootNext`, restart |
| `paguro stage-setup` | stage `setupTPM` (`S` + `setuptpm_seal.bin`) |
| `paguro repair` | re-install ESP files, re-stage if needed (DESIGN §7) |
| `paguro uninstall` | DESIGN §6b |
| `paguro config ...` | the only editor of `paguro.ini` |

### 11.3 Guest agent (VM mode growth) — OPEN

virtio-serial channel `org.paguro.agent.0`; length-prefixed messages; the host
never trusts a reported extent without claiming it first and verifying it
against the on-disk MFT after a guest volume flush.

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
