# kernel/paguro-handoff

The loader → initrd handoff reader (INTERFACES.md §8, §8.2; DESIGN.md §6
"What crosses the handoff", §11 Q31). A separate module of ~300 lines,
deliberately **not** part of `dm-paguro`: the enforcement module never
holds key material, and this one holds it for a few milliseconds.

```text
paguro.efi   EfiRuntimeServicesData pool, published as a configuration
             table under 290e97f6-3835-4ea1-a6f5-847ccbc33a0a
     |
insmod paguro-handoff systab=<EFI system table, physical>
     |       finds the table, copies the blob ONCE into kernel memory,
     |       zeroes the firmware's copy (memzero_explicit)
     v
/dev/paguro-handoff   0400, CAP_SYS_ADMIN, one opener ever;
     |                release wipes the kernel copy (kvfree_sensitive)
     v
paguro-initrd setup   reads it into mlocked memory, decodes, copies out
                      what it needs, wipes it; then `rmmod paguro_handoff`
```

A second load finds the firmware copy zeroed and refuses with `ENODATA`
("already consumed"); the end-to-end test checks exactly that from the
booted root (`test/qemu/linux/marker.sh`).

## Q31: why a module and a read-once device

| Option | Leftover copies | Who can read it | Verdict |
|---|---|---|---|
| **module + read-once misc device** (this) | firmware copy zeroed at load; one kernel copy, wiped at the first close or at unload | root with `CAP_SYS_ADMIN`, once | chosen |
| `/sys/firmware/...` attribute | same as above | sysfs attributes are re-readable by design, and `read` has no "once" | worse: read-once is not a sysfs idiom |
| volatile EFI variable (BS\|RT, not NV) | the firmware's variable store keeps it until deleted, and deletion does not promise to scrub; runtime-services variables live in SMM or runtime memory we cannot zero | efivarfs files are world-readable (0644) by default | refused: DESIGN §6 already says "never in a variable" |
| userspace reads the table itself via `/dev/mem` | none added | root | impossible under Secure Boot: lockdown blocks `/dev/mem` |
| kernel command line / file | cmdline is in `/proc/cmdline` forever | everyone | refused by the spec |

**Finding the system table.** The kernel keeps the system table's and the
configuration table's physical addresses in variables no module can reach
(x86: `efi_systab_phys`, `efi_config_table`; `boot_params` is not
exported). So the address comes in as `systab=`, which `paguro-initrd
systab` reads from `/sys/kernel/boot_params/data` (x86). It is untrusted and
validated: it must lie in a runtime EFI memory-map region, carry the system
table signature and a valid header CRC32; the configuration-table array
(a virtual address after `SetVirtualAddressMap`, translated through the
memory map's recorded virtual addresses, never dereferenced) and the blob
must each lie wholly inside one region, the blob's inside an
`EfiRuntimeServicesData` one; exactly one table may carry the GUID; the
blob's magic and `total_len` (≤ 96 KiB) must be sane. Nothing else is
parsed here — records are decoded in userspace (`paguro-core::handoff`).

**Residuals, stated plainly:**

- the configuration-table entry itself stays (pointing at zeroes): it is
  firmware state and the kernel has already parsed the table array;
- the loader's own working buffer is zeroised by the loader before
  `LoadImage` (`crates/paguro-boot`), and the pool it published is the
  one this module zeroes;
- between load and the initrd's read the kernel copy is in kernel memory
  (a kdump in that window would contain it);
- aarch64: the system table's address is in the FDT's
  `/chosen/linux,uefi-system-table`, not `boot_params`; `paguro-initrd
  systab` does not read it yet.

## Build and test

```sh
make                       # against /lib/modules/$(uname -r)/build
make KDIR=<headers>        # another kernel
test/qemu/linux-e2e.sh     # loads it in the VM, end to end; never on the host
```
