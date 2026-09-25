/*
 * pg_smbios.h -- is this boot the paguro VM? (DESIGN.md sec. 4.4, "On a
 * native boot the driver is present and inert".)
 *
 * The VM carries an SMBIOS type 11 (OEM strings) entry `paguro-vm/1`
 * (QEMU: -smbios type=11,value=paguro-vm/1). This file is pure C with no
 * kernel or libc dependency, so the same code is unit-tested in user mode
 * (test/smbios_test.c) and linked into the driver.
 */
#ifndef PG_SMBIOS_H
#define PG_SMBIOS_H

#define PG_VM_MARKER "paguro-vm/1"

/* Largest RawSMBIOSData blob examined; larger is treated as "no marker". */
#define PG_SMBIOS_MAX_BLOB   (1024u * 1024u)
/* Most structures walked. */
#define PG_SMBIOS_MAX_STRUCT 4096u

/*
 * raw/len: the buffer ExGetSystemFirmwareTable('RSMB', 0) filled:
 *   u8 Used20CallingMethod, u8 Major, u8 Minor, u8 DmiRevision,
 *   u32 Length (little-endian), u8 table[Length]
 * Returns 1 if some type 11 structure holds a string exactly equal to
 * PG_VM_MARKER, 0 otherwise -- including for every malformed input.
 * Reads only raw[0..len); never writes; no allocation; bounded time.
 */
int pg_smbios_has_vm_marker(const unsigned char *raw, unsigned long len);

#endif /* PG_SMBIOS_H */
