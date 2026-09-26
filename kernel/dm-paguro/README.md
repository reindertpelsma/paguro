# kernel/dm-paguro

The enforcement module (DESIGN.md §4.3, INTERFACES.md §10), in **C**: two
device-mapper targets and a control device.

| View | Table | What it is |
|---|---|---|
| A | `0 <len> paguro-image <claim_id>` | one image's extents, gathered contiguous; every request translated through them, refused outside |
| B / C | `0 <len> paguro-volume <volume_id> <b\|c>` | the volume (ciphertext / plaintext) with every claimed extent refused (`EIO`) |

Userspace names **devices and files, never extents** (`/dev/paguro`,
`paguro_uapi.h`): `PG_VOLUME_ADD` (devices, GUID, BitLocker's reserved
ranges; `READ_ONLY` makes every claim and view table on the volume
read-only, as a dirty `$Volume` does, though a read-only view B is allowed), `PG_CLAIM` (MFT record + sequence), `PG_GROW`, `PG_CROSSCHECK`
(ntfs3's FIEMAP, compared only), `PG_RELEASE`, `PG_STATUS`, and
`PG_VOLUME_REMOVE`. The module reads the plaintext volume itself and derives
every extent with the NTFS core below. Nothing in the request path parses
anything: view A is a table lookup, views B/C a range test.

**View B's tripwire** (DESIGN.md §4.4 "Until the driver arms"):
`dmsetup message <view B> 0 tripwire <pid|off>`. While it is set, a refused
request first sends `SIGKILL` to that process (the VM's QEMU). It then
interrupts every CPU and waits, so none of the process's threads can run
another user or guest instruction. Only then is the request failed, so the
guest never learns of the refusal. It lives in the glue
(`dm-paguro-main.c`), not the trusted core. `test/vm-test.body` proves it: the
named process is dead by the time the refused read returns, an allowed read
never trips it, and malformed messages are refused.

## Why C

- The device-mapper target API is C; upstream Rust-for-Linux has no bio-remapping
  or dm-target abstractions.
- Distribution kernels mostly do not ship `CONFIG_RUST`; this must build with
  DKMS against whatever kernel the user has (≥ 6.9; 6.7–6.8 via a fallback path).
- The logic that matters is plain C with no kernel dependencies, compiled into
  userspace and **differential-tested against the Rust specification** in
  `crates/paguro-core` on every push.

## Reviewing the core

**Trusted** (a bug here can expose or corrupt data): three files, plain C over
byte buffers and a read callback — no kernel API, no libc, no allocation, no
recursion, every buffer caller-provided. Each has a Rust twin that is the
specification.

| File | Lines (code) | Rust spec | What it decides |
|---|---|---|---|
| `pg_range.c` / `.h` | 83 (68) | `range.rs` | the whole runtime check for views B/C |
| `pg_claim.c` / `.h` | 110 (~90) | `ntfs.rs` (claims) | what a claim covers, whether claims/reserved ranges collide, growth, view A's translation |
| `pg_ntfs.c` / `.h` | 865 (~700) | `ntfs.rs`, `runlist.rs` | a file's extents, from the volume itself; the payload check |

Invariants, function by function:

- `pg_range_sort` — heapsort by `start`; O(n log n), in place, no recursion.
- `pg_range_normalise` — output sorted, non-empty, disjoint and *not touching*
  (touching extents merge); covers exactly the input's sectors; returns 0 if
  any input is empty (caller must refuse).
- `pg_range_blocks` — true iff some protected sector lies in
  `[sector, sector+count)`; zero-length and wrapping requests are refused.
  CBMC proves this equals the brute-force definition (`test/cbmc/range.c`).
- `pg_claim_normalise` — like `pg_range_normalise` but **refuses** overlapping
  or empty extents (a runlist naming a cluster twice) instead of merging them.
- `pg_claim_intersects` — merge walk of two normalised lists; true iff they
  share a sector. Touching (`[a,b)` beside `[b,c)`) is not intersecting. Used
  for claim-vs-claim and claim-vs-reserved.
- `pg_claim_grows` — every sector of the old file maps where it did: all old
  extents but the last identical, the last one starts in place and does not
  shrink. Anything else makes the claim read-only.
- `pg_claim_coalesce` — merges physically adjacent file-order extents (the
  canonical form `pg_ntfs_extents` produces), so FIEMAP's split points don't
  matter to the cross-check.
- `pg_claim_truncate` — the first *n* logical sectors of file-order extents;
  0 if there are fewer. `PG_CROSSCHECK` compares FIEMAP (or any supplied list)
  with the derived map up to the end of the file's data: ntfs3 reports the
  last extent up to EOF, the core up to the end of the cluster, and a fixed
  VHD (clusters + a 512-byte footer) always has such a tail.
- `pg_claim_gather` — logical sector → physical sector and sectors left in that
  extent; 0 past the end (view A refuses).
- `pg_runlist_decode` — mapping pairs; every field width checked against the
  remaining input before it is read; sparse runs, zero lengths, negative or
  wrapping LCNs refused; capacity bounded.
- `pg_ntfs_boot` — `NTFS    `, 0x55AA, 512/4096-byte sectors, power-of-two
  cluster ≤ 2 MiB, 1–4 KiB power-of-two records, `$MFT` LCN inside the
  volume; the volume size is whole clusters and cannot wrap.
- `read_record` — reads through a run map below a byte limit; the update
  sequence at 0x30 (NTFS 3.1) or 0x2A (NTFS 3.0, which ntfs3 writes for the
  records it creates), nothing else; every sector's USN checked before fixup;
  afterwards `bytes_in_use ≤ record size` and the attribute offset is inside
  it and past the array, and (3.1 only, which has one) the record's
  self-number matches.
- `attr_at` — the single place attribute headers are trusted: afterwards the
  header, name and any resident value lie inside the attribute and the
  attribute inside `bytes_in_use`; every walk advances ≥ 0x18 bytes.
- `segment` — sparse/encrypted/compressed refused (on segments after the
  first only the compressed bit itself counts: ntfs3 fills the rest of the
  compression mask of segments it adds from a stale pointer); segments must start at the
  next VCN (no gap, no overlap); `highest_vcn` must match the decoded runs;
  every run inside the volume. Keeps: runs so far map VCNs `0..vcn` exactly.
- `load_list` — attribute list ≤ 64 KiB, non-resident lists fully initialised
  and read through their own runs.
- `walk` — in use, not a directory, sequence match, base record; with an
  attribute list, only `$DATA` segments named there count, each record read is
  checked (in use, sequence, points back at the base), at most 64 extension
  segments; finally `allocated_size == Σ runs × cluster`, valid data length
  == size, size a whole number of sectors.
- `pg_ntfs_open` — record 0 found from the boot sector alone; `$MFT` with an
  attribute list is refused (see below).
- `pg_ntfs_extents` — clusters → 512-byte sectors, file order, adjacent runs
  coalesced; every extent inside the volume.
- `pg_payload_check` — the mandatory structural assertion, by content
  (INTERFACES §3.2): a **GPT** (`EFI PART` at LBA 1) needs a valid header CRC
  and entry-array CRC, the backup header at the primary's alternate LBA
  agreeing field by field with its own valid array, every used entry inside
  the usable range, every ESP-typed partition a FAT boot sector no larger
  than the partition, every partition holding an ext4 superblock passing the
  ext4 check, and at least one partition verified; **bare ext4** (`0xEF53` at
  byte 1080) needs a plausible geometry no larger than the payload and the
  backup superblock in group 1 (or `s_backup_bgs[0]` under `sparse_super2`)
  agreeing on UUID, block count and its group number — or, with a single
  block group (no backup), the root directory (inode 2, through group 0's
  descriptor and the inode table) a directory whose `i_block` starts with an
  extent header (`0xF30A`); **ISO 9660** needs the
  PVD's both-endian fields to agree, volume space size × block size = the
  payload, and the root directory's `.` record to point at itself. Anything
  else is refused. The backup GPT, partition starts and ext4's group-1 copy
  lie past a fragmented image's first extent, so misordered gathering fails
  here; the harness proves it for every swap that moves a sector the check
  reads. Every read is bounded by the image length first (CBMC).

On-disk structures (NTFS boot sector, FILE record, attribute headers,
`$ATTRIBUTE_LIST` entries, `$VOLUME_INFORMATION`, GPT header and entry, FAT
boot sectors, ext4 superblock/group descriptor/inode/extent header, ISO 9660
PVD and directory record) are described once in `pg_layout.h` as packed
layout-only structs: fields are read as `GET(b, struct T, field)`, which
takes `offsetof` and the field's width to the bounds-checked readers; no
buffer is ever cast to a struct, and every offset and size is pinned by a
`_Static_assert`. The Rust twin is `crates/paguro-core/src/ntfs/layout.rs`
(`#[repr(C, packed)]`, `offset_of!`, `get!`/`get_at!`), with the same
names.

**Glue** (boring, exercised in the VM): `dm-paguro-main.c` (the two targets),
`pg_ctl.c` / `pg_ctl.h` (control device, state, locking, reading a block
device with synchronous bios), `paguro_uapi.h`, `tools/pgctl.c` (test client).

### Deliberate refusals

- `$MFT` with an `$ATTRIBUTE_LIST` (hundreds of MFT fragments) — refused
  rather than bootstrapped; the volume fails safe.
- Files whose valid data length is short of their size (stale disk beyond it).
- Files whose size is not a whole number of sectors.
- Records 0–23 (metadata and `$MFT`'s reserved extensions).

## Tests

| Level | Where | What |
|---|---|---|
| unit (Rust) | `crates/paguro-core/tests/ntfs.rs` | every `NtfsError` variant, over synthetic volumes built byte by byte (`tests/synth/`) |
| unit (C) | `test/unit/` | range/claim/runlist/boot vectors, every manifest case, I/O failure at every read, torn reads, every byte of every sector read mutated; under ASan+UBSan, MSan and Valgrind |
| fixtures | `test/fixtures/ntfs/` (repo root) | real `mkntfs` volumes written through ntfs-3g (contiguous, fragmented, attribute-list, non-resident list, 4 KiB sectors, compressed, sparse) and 65 named corruptions of them, each with its expected error (`generate.py` rebuilds them) |
| fixtures | `test/fixtures/payload/` | real GPT (FAT ESP + ext4), bare ext4 (1 KiB/4 KiB blocks, 64-bit, `sparse_super2`), ISO 9660 and grown/unknown images from `sgdisk`/`mkfs`/`genisoimage`, and 85 named corruptions of them with CRCs recomputed where the corruption is meant to get past them |
| differential | `crates/paguro-harness` (`ntfs-exhaustive`) | C against Rust: same result, same error, **same sector reads** — fixtures, exhaustive byte mutation, truncation, I/O faults, fuzz corpora; for the payload check also misordered gathering (every swap of 4 and 7 extents, and the reversal) |
| model checking | `test/cbmc/` | CBMC: memory safety + functional equivalence for the range test, claim checks and runlist decoder; the payload check over arbitrary sector contents, one path per run (GPT with ≤ 5 entries, ext4 at any base and length, ISO 9660): memory safety, every read inside the image or partition, a typed result; the bitwise CRC-32 = the table CRC |
| fuzzing | `test/fuzz/` (libFuzzer, C: `ntfs`, `runlist`, `payload`), `/fuzz` (cargo-fuzz: `ntfs_file`, `runlist`, `ntfs_diff` — which also diffs the payload check) | in-repo seed corpora (`paguro-harness ntfs-seeds` / `payload-seeds`) and dictionary |
| static analysis | `make -C test/unit analyze` | `gcc -fanalyzer`, `clang --analyze`, `cppcheck`, `sparse` |
| VM | `test/vm-test.sh` | the module in QEMU (KVM or TCG) on the host's kernel, over the fixtures |
| VM: hostile callers | `test/hostile/vm-hostile.sh` | §12.0 on a KASAN/UBSAN/lockdep/kmemleak or KCSAN kernel (below) |
| VM: coexistence | `test/vm-coexist.sh` (`test/coexist/`) | views A and C of one volume mounted read-write at once under stress; growth; the view-C guard; power-loss replay (below) |

```sh
make                              # the module, against /lib/modules/$(uname -r)/build
make -C test/unit check           # C core tests under ASan+UBSan (msan, valgrind, coverage, analyze)
make -C test/cbmc                 # bounded model checking
make -C test/fuzz run T=ntfs      # libFuzzer, 60 s
cargo run --release -p paguro-harness -- ntfs-exhaustive
make -C tools && sudo ./test/vm-test.sh     # pgctl, pgguard (static)
cargo build --release -p paguro-harness && sudo ./test/vm-coexist.sh
```

`vm-test.sh` never loads anything into the host kernel. In the VM it adds the
fixture volumes, claims files, mounts ntfs3 on view C and cross-checks its
FIEMAP, then checks: view A reads each file byte-exact (contiguous, fragmented,
attribute lists); view C refuses reads, writes and single-bio straddles of
claimed sectors, with no sector of a refused write landing; readahead refusals
are counted separately from guard hits; B/C exclusion; reserved ranges refuse
overlapping claims and accept touching ones; a 4Kn volume reports 4096-byte
sectors and refuses 512-byte direct I/O; compressed, sparse, resident,
directory, wrong-sequence and system-record claims are refused; a dirty volume
gets no view B and only read-only views; append-only growth extends view A
(after a fresh cross-check) while truncation makes the claim read-only; a
dm-error splice at each sector the claim reads makes the add or claim fail;
and the module unloads cleanly.

## Coexistence, growth, guard and power-loss replay (`test/vm-coexist.sh`)

One VM boot (`lsm=…,bpf`), nine virtio disks: NTFS volumes with 512-byte and
4096-byte sectors, a `dm-log-writes` log, a replay target, the images built
on the host (`coexist/mkimages.py`: a fixed VHD holding GPT + FAT32 ESP +
ext4 with 512-byte and with 4096-byte LBAs, bare ext4) and, when the host is
root with ntfs-3g, `guard.img` (an image with an 8.3 alias, a hard link and
an alternate data stream). Tools in the VM: `pgctl`, `pgstress`
(self-checking files and blocks), `pgreplay`, `pgguard`, `paguro-harness`
(the Rust reference and the C core in userspace), e2fsprogs, `ntfsfix`,
`fsck.fat`, and optionally `fio`, `bpftool` and ntfsprogs-plus' `ntfsck`
(`PG_NTFSCK`).

For each volume — 512e contiguous (recorded), 512e fragmented (the images
written into 2 MiB holes, > 20 extents each), 4Kn:

1. claim both images, cross-check with ntfs3's FIEMAP, load view A for each
   (the payload check passes: GPT + FAT + ext4, bare ext4) and view C;
2. mount both ext4s and the ESP from view A and ntfs3 on view C, all
   read-write, and run at once: `pgstress` trees and block overwrites on
   both ext4s and the ESP, a create/overwrite/rename/delete churn on NTFS,
   and NTFS filled to ENOSPC (plus `fio --verify` when present);
3. verify every file and block live, unmount, `e2fsck -fn`, `fsck.fat -n`,
   `ntfsfix -n` (and `ntfsck -n`), remount read-only and verify from disk;
   re-parse both runlists with the Rust and C cores and have the module
   compare them with its claims (`pgctl crosscheck-list`); `PG_STATUS` shows
   no guard hits and no view-A refusals;
4. growth: append 64 MiB to the bare image through ntfs3 on view C,
   `PG_GROW`, cross-check, reload view A under the mounted ext4, online
   `resize2fs`, stress again, verify, fsck. If ntfs3 had to give the file an
   extension record (fragmented free space), see Findings: `PG_GROW` must
   refuse it and the claim go read-only (reported as `XFAIL`).

**Power-loss replay** (INTERFACES §12.1): the 512e run is recorded with
`dm-log-writes` under the volume. `pgreplay walk` (a reimplementation of
xfstests' `replay-log` from the log format, no GPL code) replays it onto a
copy of the starting volume and at every FLUSH/FUA entry, every Nth write,
and for a sample of flush intervals a random subset of the unflushed writes
(FUA kept; some writes torn to a subset of their 512-byte sectors), runs
`replaycheck`: the Rust reference and the C core (userspace) must agree, the
map must be the pre-, the post-growth map or one between them (append-only),
or a refusal — and the module (`PG_VOLUME_ADD`, `PG_CLAIM`, then
`PG_CROSSCHECK` against the Rust map) must give exactly the same map or the
same refusal code. At every `PG_EFSCK`th state both images are mounted from
a snapshot of view A (journal replay) and `e2fsck -fn` must be clean.

**The view-C guard** (`tools/pgguard.bpf.c`, `tools/pgguard.c`): a CO-RE
BPF-LSM program keyed on `(dev, ino)`: `file_open`, `file_permission`,
`path_truncate`, `inode_setattr`, `inode_setxattr`, `inode_removexattr`,
`inode_file_setattr` (≥ 6.17) → `EACCES`; `inode_unlink`, `inode_rename`
(either end), `inode_link` → `EBUSY`; one exempt cgroup. It pins its links
and its image map in bpffs and refuses (`EPERM`) unlinking or renaming those
pins, unmounting that bpffs (`sb_umount`), a link fd by id (`bpf`), and any
new fd for its maps outside the exempt cgroup (`bpf_map`). The test: every
operation through the path, the 8.3 alias, the hard link, a file handle and
the stream name is refused with `EACCES`/`EBUSY` (the stream name: `ENOENT`),
never `EIO`; the exempt growth cgroup can append; view C is never mounted
with `discard`;
`find`, `du`, `tar`, `rm -rf` of the parent, a churn, ENOSPC, `fstrim` and a
remount cause no guard hit in `PG_STATUS`; `rm` of the pins, `umount` (also
`-l`) of the bpffs and `bpftool link detach` (by id and by pin) all fail.

## Hostile callers and denial of service (`test/hostile/`)

INTERFACES §12.0, on a debug kernel built by `test/hostile/build-kernel.sh`
(a pinned 6.18 longterm: KASAN + UBSAN + lockdep + kmemleak, or KCSAN +
lockdep), in a VM (`test/hostile/vm-hostile.sh <kernel-out>`); any kernel
report fails the run (KCSAN: any race in our code). `pghostile` drives
`/dev/paguro`:

- **numbers**: every ioctl type/number/direction/size combination — only the
  seven exact commands reach the module, everything else is `ENOTTY`;
- **pointers**: NULL, kernel, unmapped, read-only and page-straddling
  arguments and `PG_CROSSCHECK` range pointers — `EFAULT`, state unchanged;
- **bounds**: `nreserved` > 8, wrapping/empty/out-of-volume reserved ranges,
  unknown flags and formats, character and missing devices, record ≥ 2³²,
  sequence 0, `count` 0 / 65537 / 2³²−1, a partly unmapped 1 MiB range list
  (the claim is untouched), wrapping ranges (compared, never trusted),
  double release/remove; 8 volumes and 16 claims, then `ENOSPC`;
- **fuzz**: random structs to every ioctl, ids biased to reach deep;
- **race**: another thread rewrites the argument during the ioctl (one
  `copy_from_user`, validated after the copy);
- **privilege**: without `CAP_SYS_ADMIN`, as uid 65534 on a 0666 node, and
  as root of a user namespace — `EPERM` for every ioctl (`capable()` is the
  initial namespace);
- **churn** and lifetime: 8 threads adding, claiming, growing,
  cross-checking, releasing and removing while table lines load and unload
  and I/O runs through them, and `rmmod` is tried in a loop (refused while
  `/dev/paguro` is open);
- **flood**: 500 000 `PG_STATUS`; 5 000 refused claims log at most printk's
  rate limit;
- **a device that never answers** (a suspended dm table under the volume):
  the hung `PG_VOLUME_ADD` and everyone queued behind `pg_mutex` are
  killable; afterwards the control device answers and the device can be
  added. kmemleak finds nothing of ours; the module unloads.

Malformed and premature table lines (22 of them, plus 300 create/remove
cycles) are refused cleanly. `/dev/paguro-handoff`'s loader is booted under
OVMF without the paguro loader: `systab=` missing, 0, 1, the real system
table (no handoff table there), off by a few bytes, beyond memory and 200
random addresses are all refused, and nothing is registered or leaked.

## Findings

- **ntfs3 writes MFT records in the NTFS 3.0 layout** (update sequence at
  0x2A, no self record number), on NTFS 3.1 volumes; Windows and ntfs-3g use
  0x30. Both are now accepted (INTERFACES §10.1a); fixture `vol_ntfs3.img` is
  written by ntfs3 in a VM (`test/fixtures/ntfs/ntfs3-vm.sh`), including a
  file grown into fragmented space whose `$DATA` spans extension records.
- **ntfs3 writes garbage into the flags of `$DATA` segments it adds**
  (seen: 0x0020, a compression-method bit): `ni_insert_nonresident` is passed
  `attr_b->flags` after `ni_create_attr_list` has moved the base attribute,
  so the pointer is stale. The core ignores those bits on segments after the
  first (the compressed bit and the compression unit still refuse). Worth an
  upstream report.
- **A refused `PG_GROW` keeps the claim writable** when the old extents are
  intact (INTERFACES §10.2): new extents colliding with a reserved range or
  another claim just refuse the growth; the claim goes read-only only if the
  derived map moved or shrank the old extents, or no map could be derived at
  all (then nothing shows the old ones are intact). vm-test checks a mounted
  view A keeps working across a refused growth.
- **Fixed VHDs never passed the cross-check** before `pg_claim_truncate`:
  ntfs3's FIEMAP ends at EOF, the derived map at the end of the cluster.
- ntfs3 has no stream names in paths (the ADS name is `ENOENT`) and no
  `FITRIM`. The declarative backstop (`SYSTEM` + `sys_immutable`, `ads=0`)
  was dropped (INTERFACES §10.4): it also blocked the growth service's
  appends and made the volume root immutable.
- Payload check, deviations from INTERFACES §3.2 wording: the backup GPT
  header is looked for at the primary's alternate LBA, which may be before the
  last LBA (a grown disk whose backup has not moved yet); a GPT's LBAs are in
  view A's logical block size (4Kn); at least one partition must verify; a
  GPT partition whose ext4 superblock is gone reads as unknown content and is
  skipped (so a misordering that only replaces that superblock is not caught
  — it also cannot be mounted as ext4); ISO 9660 has nothing to read past a
  first extent besides the root directory record.
