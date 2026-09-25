// SPDX-License-Identifier: GPL-2.0
/*
 * paguro-handoff: the loader -> initrd handoff reader (INTERFACES.md 8,
 * 8.2; DESIGN.md 6 "What crosses the handoff", 11 Q31).
 *
 * The loader leaves one EfiRuntimeServicesData allocation behind, published
 * as a UEFI configuration table under 290e97f6-3835-4ea1-a6f5-847ccbc33a0a.
 * At load this module finds that table through the EFI system table, copies
 * the blob into kernel memory ONCE, zeroes the firmware's copy and exposes
 * the kernel copy as /dev/paguro-handoff:
 *
 *   - mode 0400, CAP_SYS_ADMIN on open, one opener ever;
 *   - the first open's release (or the module's unload) wipes the copy, and
 *     every later open fails with ENOENT;
 *   - a second load finds the firmware copy zeroed and refuses (ENODATA).
 *
 * It is deliberately separate from dm-paguro, which never holds key
 * material. It parses nothing but the header's magic and length: the
 * records are decoded in userspace (paguro-core::handoff).
 *
 * Finding the system table: the kernel keeps its physical address in
 * variables no module can reach, so the caller passes it (systab=, read by
 * the initrd from /sys/kernel/boot_params/data on x86). It is not trusted:
 * it must lie in a runtime EFI memory-map region and carry the system
 * table's signature and a valid header CRC; the configuration-table array
 * and the blob must each lie wholly inside one EFI_RUNTIME_SERVICES_DATA
 * region, and the array pointer (virtual after SetVirtualAddressMap) is
 * translated through the memory map, never dereferenced.
 */
#include <linux/capability.h>
#include <linux/crc32.h>
#include <linux/efi.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>	/* >= 6.12 */
#else
#include <asm/unaligned.h>
#endif

#define PGH_MAGIC "PGRHOF\0\x01"
#define PGH_HEADER 16
#define PGH_MAX (96 * 1024)		/* INTERFACES 8: maximum blob */
#define PGH_MAX_TABLES 1024		/* bound on nr_tables */

static const efi_guid_t pgh_guid = EFI_GUID(0x290e97f6, 0x3835, 0x4ea1, 0xa6, 0xf5,
					   0x84, 0x7c, 0xcb, 0xc3, 0x3a, 0x0a);

static unsigned long long systab;
module_param(systab, ullong, 0400);
MODULE_PARM_DESC(systab, "physical address of the EFI system table");

static DEFINE_MUTEX(pgh_lock);
static u8 *pgh_blob;		/* the kernel's only copy; NULL once consumed */
static size_t pgh_len;
static bool pgh_opened;

/* The descriptor holding [addr, addr + len), or -ENOENT. */
static int pgh_region(u64 addr, u64 len, efi_memory_desc_t *md)
{
	u64 end;

	if (efi_mem_desc_lookup(addr, md))
		return -ENOENT;
	end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);
	if (len > end - addr)
		return -ERANGE;
	return 0;
}

/*
 * A pointer the firmware stored in the system table: physical before
 * SetVirtualAddressMap, the kernel's EFI virtual mapping afterwards.
 * Translated through the memory map's recorded virtual addresses.
 */
static int pgh_to_phys(u64 ptr, u64 len, u64 *phys)
{
	efi_memory_desc_t md, *d;

	if (!pgh_region(ptr, len, &md)) {
		*phys = ptr;
		return 0;
	}
	for_each_efi_memory_desc(d) {
		u64 size = d->num_pages << EFI_PAGE_SHIFT;

		if (!(d->attribute & EFI_MEMORY_RUNTIME) || !d->virt_addr)
			continue;
		if (ptr >= d->virt_addr && ptr - d->virt_addr < size &&
		    len <= size - (ptr - d->virt_addr)) {
			*phys = d->phys_addr + (ptr - d->virt_addr);
			return 0;
		}
	}
	return -ENOENT;
}

static int pgh_find(u64 *blob_phys)
{
	efi_system_table_64_t *st;
	efi_config_table_64_t *ct;
	efi_memory_desc_t md;
	u64 tables, phys;
	u32 hdr_size, crc, n, i, found = 0;
	void *raw;
	int e;

	if (!systab)
		return -EINVAL;
	if (pgh_region(systab, sizeof(*st), &md) ||
	    !(md.attribute & EFI_MEMORY_RUNTIME))
		return -ENOENT;
	st = memremap(systab, sizeof(*st), MEMREMAP_WB);
	if (!st)
		return -ENOMEM;
	hdr_size = st->hdr.headersize;
	e = -EINVAL;
	if (st->hdr.signature != EFI_SYSTEM_TABLE_SIGNATURE ||
	    hdr_size < sizeof(*st) || hdr_size > PAGE_SIZE ||
	    pgh_region(systab, hdr_size, &md)) {
		memunmap(st);
		return e;
	}
	memunmap(st);
	/* The header CRC, computed over headersize bytes with the field zero. */
	raw = memremap(systab, hdr_size, MEMREMAP_WB);
	if (!raw)
		return -ENOMEM;
	{
		u8 *copy = kmemdup(raw, hdr_size, GFP_KERNEL);

		memunmap(raw);
		if (!copy)
			return -ENOMEM;
		st = (efi_system_table_64_t *)copy;
		crc = st->hdr.crc32;
		st->hdr.crc32 = 0;
		if (crc != (crc32_le(~0U, copy, hdr_size) ^ ~0U)) {
			kfree(copy);
			pr_err("paguro-handoff: system table CRC mismatch\n");
			return -EINVAL;
		}
		n = st->nr_tables;
		tables = st->tables;
		kfree(copy);
	}
	if (n == 0 || n > PGH_MAX_TABLES)
		return -EINVAL;
	e = pgh_to_phys(tables, (u64)n * sizeof(*ct), &phys);
	if (e)
		return e;
	ct = memremap(phys, (size_t)n * sizeof(*ct), MEMREMAP_WB);
	if (!ct)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		if (efi_guidcmp(ct[i].guid, pgh_guid))
			continue;
		found++;
		*blob_phys = ct[i].table;
	}
	memunmap(ct);
	if (found != 1)
		return found ? -EINVAL : -ENOENT;
	return 0;
}

/* Copy the blob once and zero the firmware's copy. */
static int pgh_take(u64 phys)
{
	efi_memory_desc_t md;
	u8 *fw;
	u32 len;
	int e;

	if (pgh_region(phys, PGH_HEADER, &md) || md.type != EFI_RUNTIME_SERVICES_DATA)
		return -ENOENT;
	fw = memremap(phys, PGH_HEADER, MEMREMAP_WB);
	if (!fw)
		return -ENOMEM;
	if (memchr_inv(fw, 0, PGH_HEADER) == NULL) {
		memunmap(fw);
		return -ENODATA;	/* consumed by an earlier load */
	}
	len = get_unaligned_le32(fw + 8);
	e = memcmp(fw, PGH_MAGIC, 8) ? -EINVAL : 0;
	memunmap(fw);
	if (e)
		return e;
	if (len < PGH_HEADER || len > PGH_MAX || pgh_region(phys, len, &md))
		return -EINVAL;
	fw = memremap(phys, len, MEMREMAP_WB);
	if (!fw)
		return -ENOMEM;
	pgh_blob = kvmalloc(len, GFP_KERNEL);
	if (pgh_blob) {
		memcpy(pgh_blob, fw, len);
		pgh_len = len;
	}
	/* Zeroed whether or not the copy succeeded: never left behind. */
	memzero_explicit(fw, len);
	memunmap(fw);
	return pgh_blob ? 0 : -ENOMEM;
}

static void pgh_wipe(void)
{
	if (pgh_blob) {
		kvfree_sensitive(pgh_blob, pgh_len);
		pgh_blob = NULL;
		pgh_len = 0;
	}
}

static int pgh_open(struct inode *inode, struct file *f)
{
	int e = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	mutex_lock(&pgh_lock);
	if (!pgh_blob)
		e = -ENOENT;
	else if (pgh_opened)
		e = -EBUSY;
	else
		pgh_opened = true;
	mutex_unlock(&pgh_lock);
	return e ? e : nonseekable_open(inode, f);
}

static ssize_t pgh_read(struct file *f, char __user *buf, size_t n, loff_t *pos)
{
	ssize_t r;

	mutex_lock(&pgh_lock);
	r = pgh_blob ? simple_read_from_buffer(buf, n, pos, pgh_blob, pgh_len) : 0;
	mutex_unlock(&pgh_lock);
	return r;
}

static int pgh_release(struct inode *inode, struct file *f)
{
	mutex_lock(&pgh_lock);
	pgh_wipe();
	mutex_unlock(&pgh_lock);
	pr_info("paguro-handoff: consumed and wiped\n");
	return 0;
}

static const struct file_operations pgh_fops = {
	.owner = THIS_MODULE,
	.open = pgh_open,
	.read = pgh_read,
	.release = pgh_release,
};

static struct miscdevice pgh_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "paguro-handoff",
	.fops = &pgh_fops,
	.mode = 0400,
};

static int __init pgh_init(void)
{
	u64 phys = 0;
	int e;

	if (!efi_enabled(EFI_BOOT) || !efi_enabled(EFI_MEMMAP))
		return -ENODEV;
	e = pgh_find(&phys);
	if (e) {
		pr_info("paguro-handoff: no handoff table (%d)\n", e);
		return e;
	}
	e = pgh_take(phys);
	if (e == -ENODATA)
		pr_info("paguro-handoff: the handoff was already consumed\n");
	if (e)
		return e;
	e = misc_register(&pgh_misc);
	if (e)
		pgh_wipe();
	else
		pr_info("paguro-handoff: %zu bytes taken, firmware copy zeroed\n", pgh_len);
	return e;
}

static void __exit pgh_exit(void)
{
	misc_deregister(&pgh_misc);
	pgh_wipe();
}

module_init(pgh_init);
module_exit(pgh_exit);
MODULE_DESCRIPTION("paguro loader handoff: read once, zeroed");
MODULE_LICENSE("GPL");
