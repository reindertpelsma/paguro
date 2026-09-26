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
only refuse); loads view A; and on the ESP writes `recorded.bin` every boot,
`paguro.ini`/`PaguroConfigHash`/`tpm_seal.bin` on a provisioning boot, and —
after a boot on the `passphrase` rung with `PaguroTpmBroken` set and every
secret it needs — a fresh `tpm_seal.bin` (`reseal`, below). Depends on
[`paguro-core`](../paguro-core), [`paguro-crypto`](../paguro-crypto) and
[`paguro-boot`](../paguro-boot) (its TPM client, reused rather than
reimplemented — see `reseal` below) for formats and key derivation; talks to
`kernel/dm-paguro` over its control device. See
[`docs/DESIGN.md`](../../docs/DESIGN.md) §4.3, §6 and
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §5, §8, §10.

## Modules

| module | purpose |
|---|---|
| `plan` | pure logic: tables, layouts, root choice — unit-tested, no syscalls |
| `setup` | the `setup` subcommand's orchestration |
| `dm` | device-mapper table construction |
| `esp` | ESP-side reads/writes (`paguro.ini`, seals, `recorded.bin`, `PaguroTpmBroken`) |
| `reseal` | re-seal the `tpm` rung after `PaguroTpmBroken` (below) |
| `pg` | `/dev/paguro` control-device ioctls |
| `sys` | thin system-call glue (everything not pure) |

### Re-sealing the `tpm` rung (`reseal`, INTERFACES.md §5, §8.3)

A firmware update, `dbx` change or MOK enrolment moves the PCR values the old
`tpm_seal.bin` was sealed against; the loader notices (`PolicyPCR` fails) and
sets `PaguroTpmBroken`. A later boot on the `passphrase` rung carries
everything a re-seal needs — this boot's recorded PCR 0/2/4/7 (handoff
`PCRS`), `B` (handoff `B`), the BitLocker Volume Master Key (handoff `VMK`)
and, only on this rung, the Linux password's fast hash (handoff `USER_HASH` —
safe to forward only here, since the `passphrase` rung's own `env` is already
a public constant: DESIGN.md §6) — so `esp::maybe_reseal` seals a fresh `D'`
under a policy over those values, with the `auth` a future `tpm`-rung boot
will re-derive from the same passphrase, and rewrites `tpm_seal.bin`
(`esp::replace`'s atomic write, fsyncing the file and then the directory)
before clearing the flag — never the other way round, and never on a
failure. A `recovery`-rung boot (no PIN typed, so no `USER_HASH` anywhere)
cannot do this automatically; it logs why and leaves the flag for a
`passphrase`- or `tpm`-rung boot to clear instead.

`reseal::LinuxTpm` adapts `/dev/tpmrm0` (the kernel's TPM resource manager) to
`paguro_boot::platform::Platform`, exactly as `paguro-win`'s `TbsPlatform`
adapts Windows' TBS — so the actual TPM marshalling, session salting and
policy digest are `paguro-boot`'s own, not reimplemented, and provably match
what the loader's unseal path checks (`reseal`'s tests run the same code
against a real `swtpm`).

`root_gate` also needs BitLocker's encrypted FVEK blob (unchanged by a
re-seal, but still required as an input): `esp::fvek_blob` reads the three
FVE metadata copies straight off the raw partition, at the offsets
`FVE_LAYOUT` already gives, and cross-checks them with
`paguro_core::bde::cross_check` + `Metadata::parse` — the same pure,
libbde/dislocker-verified parser `paguro-boot` uses, not a reimplementation
of its offsets (`esp`'s tests run it against the same
`test/fixtures/bde/windows/*.sparse` fixtures `paguro-boot/tests/bde.rs`
does). A read or cross-check failure is treated the same as a missing
secret: logged, `PaguroTpmBroken` left set.

## Invariants

- Key material is zeroized (`zeroize`) once no longer needed; the FVEK
  reaches `dm-crypt` through a kernel `logon` key, never a table string. `B`
  is additionally kept in a root-only *session* `logon` key
  (`sys::add_session_logon_key`), for a re-seal after this process exits
  (INTERFACES.md §8.3). `B`, the VMK and `USER_HASH` in `setup::Taken` are
  `setup::Secret32` (zeroize-on-drop, deliberately not `Debug` — adding
  `#[derive(Debug)]` to `Taken` fails to compile rather than printing them);
  `esp::maybe_reseal` drops its VMK/`USER_HASH` copies right after the
  attempt, not at process exit.
- View A is loaded only after the module has asserted the payload's
  structure, and only read-only when the volume is dirty or hibernated.
- Everything pure (tables, layouts, root choice) lives in `plan`,
  unit-tested apart from the syscall glue around it; `esp::reseal_readiness`
  and `esp::finish_reseal` pull the same discipline out of the re-seal path
  (see `esp`'s tests).
- `PaguroTpmBroken` is cleared only once the new `tpm_seal.bin` is durably
  written (fsynced file, then directory) — never before, and never on a
  failed write or a failed TPM operation.

## Build & test

```sh
cargo test -p paguro-initrd
test/qemu/linux-e2e.sh linux-plain    # a real kernel, through this tool, to a marker service
```

`reseal`'s tests spawn a real `swtpm` (skipped, with a message, when it is not
installed — CI installs it), the same way `paguro-boot/tests/swtpm.rs` does;
they check that a re-sealed object's policy and template are accepted by the
loader's own `Tpm::unseal`, and that the wrapped VMK it produces really does
recover the original VMK.

Exercised end to end — OVMF → `paguro.efi` → a UKI → `paguro-initrd` → the
root from `dm-paguro`'s view A → a marker service — by
`.github/workflows/linux-e2e.yml`'s eight scenarios (plain, bare, dirty,
hibernated, persist, BitLocker, BitLocker-partial, fragmented); see
DESIGN.md §3a.

**No `test/qemu` scenario yet exercises the `PaguroTpmBroken` re-seal.** It is
buildable — every `Vm::launch_disks` (so every `linux-*` scenario too, not
only the loader-only ones in `test/qemu/runner/src/main.rs`) already attaches
a real `swtpm`, and the CI kernel has `CONFIG_TCG_TPM`/`CONFIG_TCG_TIS`/
`CONFIG_TCG_CRB` built in, so `/dev/tpmrm0` needs no extra initramfs module —
but it is more than a one-line addition to `linux.rs`. Precisely what is
missing:

1. A scenario that provisions a **real** `tpm_seal.bin` against that boot's
   own `swtpm` (`stage4::bootstrap` already does this over a bootstrap
   payload, but chains to the stub probe, not a real UKI/initrd; no
   `linux.rs` scenario does a TPM-provisioning boot at all today).
2. Between boots, an ini edit that both flips `[Passphrase] enabled` to `1`
   and (because it changes PCR 12) invalidates the standing `tpm_seal.bin` —
   the natural way to reach `PaguroTpmBroken`, needing no synthetic NVRAM
   write (`try_tpm`'s `RcClass::PolicyFail` arm in
   `paguro-boot/src/machine.rs` sets the flag itself, already covered by
   `policy_failure_sets_tpm_broken_and_offers_the_rest` in
   `paguro-boot/tests/mock_boot.rs`).
3. A `passphrase_seal.bin` written onto the ESP for that same boot — no TPM
   needed to build it (`env_passphrase()` is a public constant), only the
   volume's VMK and encrypted FVEK blob, both already in the test harness's
   hands the way `bde_case`/`stage4::bootstrap` compute similar seals inline.
4. New serial-log assertions for the second boot (`esp::maybe_reseal`'s own
   log lines are already there to match against) and a third boot proving
   the `tpm` rung now succeeds and `PaguroTpmBroken` reads back cleared from
   the VARS file (`vars::read`, already used elsewhere in
   `test/qemu/runner`).

None of this is a research gap — it is straightforward, if sizeable,
`test/qemu/runner` engineering (a new `linux.rs` scenario function plus a
small seal-writing helper), left for a follow-up rather than landed
unverified under time pressure.
