# paguro-qemu

QEMU boot tests for `paguro.efi`: OVMF (with and without Secure Boot), swtpm
as the TPM 2.0, an ESP built with `mtools`, a GPT data disk built with
`sgdisk`. Assertions are made on the loader's own serial-log markers, not on
screen contents. Runs on a Linux host (invoked by `test/qemu/run.sh` and
`test/qemu/arm64-smoke.sh`).

```
paguro-qemu --efi paguro.efi [--efi-signed paguro.signed.efi]
            [--ovmf /usr/share/OVMF] [--work DIR] [--accel auto|kvm|tcg]
            [SCENARIO...]
```

Scenarios needing a signed loader are skipped without `--efi-signed`. KVM is
used when `/dev/kvm` is usable, TCG otherwise (CI forces TCG — nested KVM
under OVMF + swtpm intermittently stops delivering TPM responses).

## Its place in paguro

Depends on [`paguro-boot`](../../../crates/paguro-boot) (the `Platform`,
`Tpm` and seal types it drives the same way the real loader does),
[`paguro-core`](../../../crates/paguro-core), and
[`paguro-crypto`](../../../crates/paguro-crypto). Boots
[`paguro-efi`](../../../crates/paguro-efi) and, for the handoff chain,
[`test/uefi-probe`](../../uefi-probe). See
[`docs/INTERFACES.md`](../../../docs/INTERFACES.md) §12 ("Testing contract",
QEMU level) for the scenario list this crate implements.

## Modules

| module | purpose |
|---|---|
| `stage4` | building the stage-4 NTFS volume(s)/VHDs the scenarios boot against |
| `linux` | the Linux end-to-end scenarios (`linux-e2e.yml`): a real kernel through `paguro-initrd` |
| `vars` | firmware-variable helpers shared by scenarios |
| (crate root) | scenario definitions, QEMU process management, swtpm socket, serial-log assertions |

## Invariants

- Assertions are on the loader's own `PAGURO:`-prefixed serial-log lines, not
  on screen pixels — this crate tests behaviour, not rendering (that's
  `paguro-ui`'s golden tests).
- Every scenario cleans up its QEMU/swtpm processes even on failure (logs are
  still uploaded — see the workflow's `if: always()` artifact step).

## Build & test

```sh
test/qemu/run.sh                      # every non-signed scenario, x86_64
test/qemu/run.sh s4-vhd-gpt s4-bde-*   # a subset, by scenario name/glob
test/qemu/arm64-smoke.sh              # aarch64 under AAVMF
```

Covered by `.github/workflows/loader.yml`'s `qemu` job (matrix: stages 1–3,
stage 4 boots, stage 4 refusals/recovery, BitLocker) and
`.github/workflows/arm64.yml`'s `boot` job.
