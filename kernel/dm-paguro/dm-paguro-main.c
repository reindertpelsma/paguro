// SPDX-License-Identifier: GPL-2.0
/*
 * dm-paguro: a device-mapper target that is a protected view over a block
 * device (DESIGN.md 4.3). The whole runtime path is a range test:
 *
 *   I/O intersecting a protected range -> BLK_STS_IOERR (DM_MAPIO_KILL)
 *   everything else                    -> remapped to the underlying device
 *
 * No cipher, no key, no NTFS parsing in the request path. The same target
 * serves view B (below dm-crypt, ciphertext to the VM) and view C (above
 * dm-crypt, plaintext for ntfs3); which one is a matter of what userspace
 * stacks it on. Views B and C are never live at once.
 *
 * Table line:
 *   <start> <len> paguro <dev> <dev_offset> <n> [<range_start> <range_len>]*n
 * Ranges are in sectors of <dev>, after <dev_offset> is applied.
 *
 * TEMPORARY: ranges arrive in the table. DESIGN.md 4.3 requires the module to
 * derive them itself from one NTFS parse at construction, with userspace
 * input only able to cause refusal. That parser lands next (see README.md);
 * until then this target is for the storage harness only.
 */
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/atomic.h>

#include "pg_range.h"

#define DM_MSG_PREFIX "paguro"
#define PG_MAX_RANGES 65536

struct pg_ctx {
	struct dm_dev *dev;
	sector_t offset;
	pg_size n;
	struct pg_extent *ranges;
	atomic64_t refused;
};

static int pg_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct pg_ctx *c;
	unsigned long long off, start, len;
	unsigned int n, i;
	char dummy;
	int r;

	if (argc < 3) {
		ti->error = "need <dev> <offset> <n> [<start> <len>]*n";
		return -EINVAL;
	}
	if (sscanf(argv[1], "%llu%c", &off, &dummy) != 1 ||
	    sscanf(argv[2], "%u%c", &n, &dummy) != 1) {
		ti->error = "bad offset or count";
		return -EINVAL;
	}
	if (n == 0 || n > PG_MAX_RANGES || argc != 3 + 2 * n) {
		ti->error = "range count does not match arguments";
		return -EINVAL;
	}

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;
	c->ranges = kvmalloc_array(n, sizeof(*c->ranges), GFP_KERNEL);
	if (!c->ranges) {
		r = -ENOMEM;
		goto bad;
	}
	for (i = 0; i < n; i++) {
		if (sscanf(argv[3 + 2 * i], "%llu%c", &start, &dummy) != 1 ||
		    sscanf(argv[4 + 2 * i], "%llu%c", &len, &dummy) != 1 ||
		    len == 0 || start + len < start) {
			ti->error = "bad range";
			r = -EINVAL;
			goto bad;
		}
		c->ranges[i].start = start;
		c->ranges[i].end = start + len;
	}
	c->n = pg_range_normalise(c->ranges, n);
	if (!c->n) {
		ti->error = "empty or overflowing range";
		r = -EINVAL;
		goto bad;
	}

	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &c->dev);
	if (r) {
		ti->error = "device lookup failed";
		goto bad;
	}
	c->offset = off;
	atomic64_set(&c->refused, 0);

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_write_zeroes_bios = 1;
	ti->private = c;
	return 0;

bad:
	kvfree(c->ranges);
	kfree(c);
	return r;
}

static void pg_dtr(struct dm_target *ti)
{
	struct pg_ctx *c = ti->private;

	dm_put_device(ti, c->dev);
	kvfree(c->ranges);
	kfree(c);
}

static int pg_map(struct dm_target *ti, struct bio *bio)
{
	struct pg_ctx *c = ti->private;
	sector_t sector = c->offset + dm_target_offset(ti, bio->bi_iter.bi_sector);

	bio_set_dev(bio, c->dev->bdev);

	/* Empty flushes carry no sectors and touch nothing. */
	if (bio_sectors(bio) == 0) {
		bio->bi_iter.bi_sector = sector;
		return DM_MAPIO_REMAPPED;
	}
	if (pg_range_blocks(c->ranges, c->n, sector, bio_sectors(bio))) {
		atomic64_inc(&c->refused);
		return DM_MAPIO_KILL;
	}
	bio->bi_iter.bi_sector = sector;
	return DM_MAPIO_REMAPPED;
}

static void pg_status(struct dm_target *ti, status_type_t type,
		      unsigned int status_flags, char *result, unsigned int maxlen)
{
	struct pg_ctx *c = ti->private;
	unsigned int sz = 0;
	pg_size i;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("refused %lld", (long long)atomic64_read(&c->refused));
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%s %llu %zu", c->dev->name,
		       (unsigned long long)c->offset, c->n);
		for (i = 0; i < c->n; i++)
			DMEMIT(" %llu %llu",
			       (unsigned long long)c->ranges[i].start,
			       (unsigned long long)(c->ranges[i].end -
						    c->ranges[i].start));
		break;
	case STATUSTYPE_IMA:
		*result = '\0';
		break;
	}
}

static int pg_iterate_devices(struct dm_target *ti,
			      iterate_devices_callout_fn fn, void *data)
{
	struct pg_ctx *c = ti->private;

	return fn(ti, c->dev, c->offset, ti->len, data);
}

static struct target_type pg_target = {
	.name = "paguro",
	.version = {0, 1, 0},
	.module = THIS_MODULE,
	.ctr = pg_ctr,
	.dtr = pg_dtr,
	.map = pg_map,
	.status = pg_status,
	.iterate_devices = pg_iterate_devices,
};

static int __init dm_paguro_init(void)
{
	return dm_register_target(&pg_target);
}

static void __exit dm_paguro_exit(void)
{
	dm_unregister_target(&pg_target);
}

module_init(dm_paguro_init);
module_exit(dm_paguro_exit);

MODULE_DESCRIPTION(DM_NAME " paguro: protected views over an NTFS volume");
MODULE_LICENSE("GPL");
