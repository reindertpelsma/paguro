# kernel/dm-paguro

The enforcement module (DESIGN.md §4.3, INTERFACES.md §10), in **C**: two
device-mapper targets and a control device.

| View | Table | What it is |
|---|---|---|
| A | `0 <len> paguro-image <claim_id>` | one image's extents, gathered contiguous; every request translated through them, refused outside |
| B / C | `0 <len> paguro-volume <volume_id> <b\|c>` | the volume (ciphertext / plaintext) with every claimed extent refused (`EIO`) |

Userspace names **devices and files, never extents** (`/dev/paguro`,
`paguro_uapi.h`): `PG_VOLUME_ADD` (devices, GUID, BitLocker's reserved
ranges), `PG_CLAIM` (MFT record + sequence), `PG_GROW`, `PG_CROSSCHECK`
(ntfs3's FIEMAP, compared only), `PG_RELEASE`, `PG_STATUS`, and
`PG_VOLUME_REMOVE`. The module reads the plaintext volume itself and derives
every extent with the NTFS core below. Nothing in the request path parses
anything: view A is a table lookup, views B/C a range test.

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
| `pg_claim.c` / `.h` | 91 (75) | `ntfs.rs` (claims) | what a claim covers, whether claims/reserved ranges collide, growth, view A's translation |
| `pg_ntfs.c` / `.h` | 624 (~510) | `ntfs.rs`, `runlist.rs` | a file's extents, from the volume itself |

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
- `pg_claim_gather` — logical sector → physical sector and sectors left in that
  extent; 0 past the end (view A refuses).
- `pg_runlist_decode` — mapping pairs; every field width checked against the
  remaining input before it is read; sparse runs, zero lengths, negative or
  wrapping LCNs refused; capacity bounded.
- `pg_ntfs_boot` — `NTFS    `, 0x55AA, 512/4096-byte sectors, power-of-two
  cluster ≤ 2 MiB, 1–4 KiB power-of-two records, `$MFT` LCN inside the
  volume; the volume size is whole clusters and cannot wrap.
- `read_record` — reads through a run map below a byte limit; NTFS 3.1
  update-sequence layout only; every sector's USN checked before fixup;
  afterwards `bytes_in_use ≤ record size` and the attribute offset is inside
  it, and the record's self-number matches.
- `attr_at` — the single place attribute headers are trusted: afterwards the
  header, name and any resident value lie inside the attribute and the
  attribute inside `bytes_in_use`; every walk advances ≥ 0x18 bytes.
- `segment` — sparse/encrypted/compressed refused; segments must start at the
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
- `pg_payload_check` — the mandatory structural assertion: GPT header at LBA 1,
  128-byte entries, the first ESP's first sector a FAT boot sector.

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
| differential | `crates/paguro-harness` (`ntfs-exhaustive`) | C against Rust: same result, same error, **same sector reads** — fixtures, exhaustive byte mutation, truncation, I/O faults, fuzz corpora |
| model checking | `test/cbmc/` | CBMC: memory safety + functional equivalence for the range test, claim checks and runlist decoder |
| fuzzing | `test/fuzz/` (libFuzzer, C), `/fuzz` (cargo-fuzz: `ntfs_file`, `runlist`, `ntfs_diff`) | in-repo seed corpus and dictionary |
| static analysis | `make -C test/unit analyze` | `gcc -fanalyzer`, `clang --analyze`, `cppcheck`, `sparse` |
| VM | `test/vm-test.sh` | the module in QEMU (KVM or TCG) on the host's kernel, over the fixtures |

```sh
make                              # the module, against /lib/modules/$(uname -r)/build
make -C test/unit check           # C core tests under ASan+UBSan (msan, valgrind, coverage, analyze)
make -C test/cbmc                 # bounded model checking
make -C test/fuzz run T=ntfs      # libFuzzer, 60 s
cargo run --release -p paguro-harness -- ntfs-exhaustive
gcc -static -O2 -o tools/pgctl tools/pgctl.c && sudo ./test/vm-test.sh
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
