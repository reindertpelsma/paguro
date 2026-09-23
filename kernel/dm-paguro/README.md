# kernel/dm-paguro

The enforcement module (DESIGN.md §4.3), in **C**, as a device-mapper target:
**a protected view over a block device**. Its runtime path is a range test —
I/O touching a protected range fails with `EIO`, everything else is remapped to
the underlying device. No cipher, no key, no NTFS parsing in the request path.

Everything around it is stock device-mapper driven by userspace
(`crates/paguro-initrd`): `dm-crypt` over the BitLocker volume, `dm-linear` for
view A's gather and for the VM's GPT sandwich.

## Why C

- The device-mapper target API is C; upstream Rust-for-Linux has no bio-remapping
  or dm-target abstractions, so a Rust module would mean writing and maintaining
  those first.
- Distribution kernels mostly do not ship `CONFIG_RUST`, and this module must
  build with DKMS against whatever kernel the user's distribution provides.
- The logic that matters is ~70 lines (`pg_range.c`), written in plain C with no
  kernel dependencies so it is also compiled into userspace and
  **differential-tested against the Rust specification**
  (`crates/paguro-core/src/range.rs`) on every CI run.

## Table

```
<start> <len> paguro <dev> <dev_offset> <n> [<range_start> <range_len>]*n
```

`dmsetup status` reports how many requests were refused.

**Temporary:** ranges arrive in the table. The design requires the module to
derive them itself — one NTFS parse at construction, with userspace able only to
cause a refusal. That parser (a C port of `paguro-core`'s `runlist.rs`, under
the same differential test) is the next piece of work here.

## Build and test

```sh
make                      # against /lib/modules/$(uname -r)/build
./test/vm-test.sh         # boots this kernel in QEMU, loads the module there
```

`vm-test.sh` never loads anything into the host kernel. It checks refusals at
both range edges, that a single write straddling the edge is refused with none of
its sectors landing, that allowed I/O reaches the device, and that malformed
tables are rejected.
