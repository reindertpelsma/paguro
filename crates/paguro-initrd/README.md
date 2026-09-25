# paguro-initrd

`paguro-initrd`, the tool that runs in the initramfs before the root
filesystem is mounted: builds the decrypted view(s) of the NTFS volume, hands
them to the kernel module, and writes/records the seal files and PCR values
the loader reads on the next boot. Runs on Linux, in the initrd (standard
`std`, not `no_std` — this is systemcall glue, not the pure-logic layer).

Three subcommands: `systab` (the EFI system table's address, for `modprobe
paguro-handoff systab=`), `setup [--env F] [--handoff DEV] [--wait S]
[--no-esp]` (the boot path below; writes F, default `/run/paguro/root.env`),
and `status` (`/dev/paguro`'s volumes and claims). The modules are also a
library, which `paguro-vm` (the VM launcher) uses for its device-mapper
tables and `/dev/paguro`.

## Its place in paguro

`setup` reads the loader's handoff once from `/dev/paguro-handoff` and wipes
it; builds the decrypted volume with BitLocker's own segment table
(`dm-crypt` keyed through a kernel `logon` key, never a table string) or
passes an unencrypted volume through; registers it with `dm-paguro`
(`PG_VOLUME_ADD`); probes the boot entry's disks read-only
(`ntfs3`), claims and cross-checks them (`PG_CLAIM`/`PG_CROSSCHECK`, which can
only refuse); loads view A; and on a provisioning boot writes `paguro.ini`,
`PaguroConfigHash` and `tpm_seal.bin`. Depends on
[`paguro-core`](../paguro-core) and [`paguro-crypto`](../paguro-crypto) for
formats and key derivation; talks to `kernel/dm-paguro` over its control
device. See [`docs/DESIGN.md`](../../docs/DESIGN.md) §4.3, §6 and
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §5, §8, §10.

## Modules

| module | purpose |
|---|---|
| `plan` | pure logic: tables, layouts, root choice — unit-tested, no syscalls |
| `setup` | the `setup` subcommand's orchestration |
| `dm` | device-mapper table construction |
| `esp` | ESP-side reads/writes (`paguro.ini`, seals, `recorded.bin`) |
| `pg` | `/dev/paguro` control-device ioctls |
| `sys` | thin system-call glue (everything not pure) |

## Invariants

- Key material is zeroized (`zeroize`) once no longer needed; the FVEK
  reaches `dm-crypt` through a kernel `logon` key, never a table string.
- View A is loaded only after the module has asserted the payload's
  structure, and only read-only when the volume is dirty or hibernated.
- Everything pure (tables, layouts, root choice) lives in `plan`,
  unit-tested apart from the syscall glue around it.

## Build & test

```sh
cargo test -p paguro-initrd
test/qemu/linux-e2e.sh linux-plain    # a real kernel, through this tool, to a marker service
```

Exercised end to end — OVMF → `paguro.efi` → a UKI → `paguro-initrd` → the
root from `dm-paguro`'s view A → a marker service — by
`.github/workflows/linux-e2e.yml`'s eight scenarios (plain, bare, dirty,
hibernated, persist, BitLocker, BitLocker-partial, fragmented); see
DESIGN.md §3a.
