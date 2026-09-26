// SPDX-License-Identifier: GPL-2.0
/*
 * dm-paguro: protected views over an NTFS volume (DESIGN.md 4.3,
 * INTERFACES.md 10.3). Two device-mapper targets over state that only
 * /dev/paguro (pg_ctl.c) creates:
 *
 *   view A     0 <len> paguro-image  <claim_id>
 *   views B/C  0 <len> paguro-volume <volume_id> <b|c>
 *
 * paguro-image gathers a claim's extents into a contiguous device; every
 * request is translated through them and refused outside. paguro-volume
 * passes the volume through and refuses (EIO) any request touching any
 * claim. Nothing here parses NTFS; the request path is a range test.
 *
 * View B's tripwire (DESIGN.md 4.4 "Until the driver arms"): the VM's
 * launcher names its QEMU with "dmsetup message <view B> 0 tripwire <pid>"
 * until the guest's paguro driver has its protections in place. While set,
 * a refused request is failed only after that process can no longer run:
 * SIGKILL marks every one of its threads, then an interrupt on every CPU,
 * waited for, forces any thread running in user or guest mode into the
 * kernel, where the pending fatal signal is taken before it could return.
 * So no QEMU thread reads the error, and the guest never learns of it
 * (autochk's /r acts on exactly that error, 11 Q1). "tripwire off" clears it.
 */
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include "pg_ctl.h"

#define DM_MSG_PREFIX "paguro"

static void pg_hints(struct dm_dev *dev, struct queue_limits *l)
{
	/* A 4Kn volume's view never accepts 512-byte I/O (INTERFACES 12.2). */
	l->logical_block_size = max_t(unsigned int, l->logical_block_size,
				      bdev_logical_block_size(dev->bdev));
	l->physical_block_size = max_t(unsigned int, l->physical_block_size,
				       bdev_physical_block_size(dev->bdev));
}

static int pg_get_dev(struct dm_target *ti, dev_t dev, struct dm_dev **out)
{
	char name[24];

	snprintf(name, sizeof(name), "%u:%u", MAJOR(dev), MINOR(dev));
	return dm_get_device(ti, name, dm_table_get_mode(ti->table), out);
}

static bool pg_table_writable(struct dm_target *ti)
{
	return dm_table_get_mode(ti->table) & BLK_OPEN_WRITE;
}

/* ---- view A: paguro-image ---------------------------------------------- */

struct pg_image {
	struct pg_claim_state *claim;
	struct dm_dev *dev;
};

/* pg_read_fn over the gathered image, for the structural assertion. */
struct pg_image_reader {
	struct pg_claim_state *claim;
	struct pg_reader r;
};

static int pg_image_read(void *ctx, pg_u64 lsec, pg_u8 *buf)
{
	struct pg_image_reader *ir = ctx;
	pg_u64 phys;

	if (!pg_claim_gather(ir->claim->file, ir->claim->nfile, lsec, &phys))
		return -EIO;
	return pg_reader_read(&ir->r, phys, buf);
}

static int pg_image_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct pg_image_reader ir;
	struct pg_claim_state *c;
	struct pg_image *x;
	unsigned int id, per;
	pg_size i;
	pg_u8 *buf;
	char dummy;
	int r, e;

	if (argc != 1 || sscanf(argv[0], "%u%c", &id, &dummy) != 1) {
		ti->error = "need <claim_id>";
		return -EINVAL;
	}
	x = kzalloc(sizeof(*x), GFP_KERNEL);
	buf = kmalloc(512, GFP_KERNEL);
	if (!x || !buf) {
		kfree(x);
		kfree(buf);
		return -ENOMEM;
	}
	if (mutex_lock_killable(&pg_mutex)) {
		kfree(x);
		kfree(buf);
		return -EINTR;
	}
	r = -EINVAL;
	c = pg_claim_get(id);
	if (!c) {
		ti->error = "no such claim";
		goto bad;
	}
	if (c->state & PG_CLAIM_REFUSED) {
		ti->error = "claim refused by cross-check";
		goto bad;
	}
	if (!(c->state & PG_CLAIM_CHECKED)) {
		ti->error = "claim not cross-checked (PG_CROSSCHECK)";
		goto bad;
	}
	if (ti->len > c->limit) {
		ti->error = "length beyond the claim";
		goto bad;
	}
	if (pg_table_writable(ti) && (c->state & PG_CLAIM_READONLY)) {
		ti->error = "claim is read-only: load the table read-only";
		goto bad;
	}
	r = pg_get_dev(ti, c->vol->plain, &x->dev);
	if (r) {
		ti->error = "plaintext device lookup failed";
		goto bad;
	}
	/* Split points must fall on the device's logical blocks. */
	per = bdev_logical_block_size(x->dev->bdev) >> SECTOR_SHIFT;
	for (i = 0; i < c->nfile; i++)
		if ((c->file[i].start | c->file[i].end) & (per - 1)) {
			ti->error = "extents not aligned to the logical block size";
			r = -EINVAL;
			goto bad_dev;
		}
	/* The mandatory structural assertion, before anything can mount. */
	ir.claim = c;
	r = pg_reader_init(&ir.r, x->dev->bdev);
	if (!r) {
		e = pg_payload_check(pg_image_read, &ir, c->limit,
				     per << SECTOR_SHIFT, buf);
		pg_reader_exit(&ir.r);
		if (e) {
			DMERR_LIMIT("claim %u: payload check failed: error %d", id, e);
			ti->error = "payload structure check failed (GPT, ext4 or ISO 9660)";
			r = e == PG_E_IO ? -EIO : -EINVAL;
		}
	}
	if (r)
		goto bad_dev;
	c->image_tables++;
	x->claim = c;
	mutex_unlock(&pg_mutex);
	kfree(buf);
	ti->num_flush_bios = 1;
	ti->private = x;
	return 0;

bad_dev:
	dm_put_device(ti, x->dev);
bad:
	mutex_unlock(&pg_mutex);
	kfree(x);
	kfree(buf);
	return r;
}

static void pg_image_dtr(struct dm_target *ti)
{
	struct pg_image *x = ti->private;

	mutex_lock(&pg_mutex);
	x->claim->image_tables--;
	mutex_unlock(&pg_mutex);
	dm_put_device(ti, x->dev);
	kfree(x);
}

static int pg_image_map(struct dm_target *ti, struct bio *bio)
{
	struct pg_image *x = ti->private;
	struct pg_claim_state *c = x->claim;
	sector_t lsec = dm_target_offset(ti, bio->bi_iter.bi_sector);
	pg_u64 phys = 0, left = 0;

	bio_set_dev(bio, x->dev->bdev);
	if (bio_sectors(bio) == 0)	/* an empty flush touches nothing */
		return DM_MAPIO_REMAPPED;
	read_lock(&pg_lock);
	if (!(c->state & PG_CLAIM_REFUSED) &&
	    !(op_is_write(bio_op(bio)) && (c->state & PG_CLAIM_READONLY)))
		left = pg_claim_gather(c->file, c->nfile, lsec, &phys);
	read_unlock(&pg_lock);
	if (left == 0) {
		atomic64_inc(&c->refused);
		return DM_MAPIO_KILL;
	}
	/* One extent per bio: the remainder comes back as a new bio. */
	if (bio_sectors(bio) > left)
		dm_accept_partial_bio(bio, left);
	bio->bi_iter.bi_sector = phys;
	return DM_MAPIO_REMAPPED;
}

static void pg_image_status(struct dm_target *ti, status_type_t type,
			    unsigned int status_flags, char *result,
			    unsigned int maxlen)
{
	struct pg_image *x = ti->private;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("state %u refused %lld", READ_ONCE(x->claim->state),
		       (long long)atomic64_read(&x->claim->refused));
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%u", x->claim->id);
		break;
	case STATUSTYPE_IMA:
		*result = '\0';
		break;
	}
}

static int pg_image_iterate(struct dm_target *ti,
			    iterate_devices_callout_fn fn, void *data)
{
	struct pg_image *x = ti->private;

	return fn(ti, x->dev, 0, ti->len, data);
}

static void pg_image_io_hints(struct dm_target *ti, struct queue_limits *l)
{
	pg_hints(((struct pg_image *)ti->private)->dev, l);
}

static struct target_type pg_image_target = {
	.name = "paguro-image",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = pg_image_ctr,
	.dtr = pg_image_dtr,
	.map = pg_image_map,
	.status = pg_image_status,
	.iterate_devices = pg_image_iterate,
	.io_hints = pg_image_io_hints,
};

/* ---- views B/C: paguro-volume ------------------------------------------ */

struct pg_view {
	struct pg_volume *vol;
	struct dm_dev *dev;
	char mode;
	spinlock_t trip_lock;	/* guards trip_pid */
	struct pid *trip_pid;	/* the tripwire's process, or NULL */
	atomic64_t trips;
};

static void pg_nop(void *unused)
{
}

/*
 * Kill the tripwire's process and return only once none of its threads can
 * run another user or guest instruction (see the top of this file).
 */
static void pg_trip(struct pg_view *x, struct pid *pid)
{
	kill_pid(pid, SIGKILL, 1);
	on_each_cpu(pg_nop, NULL, 1);
	atomic64_inc(&x->trips);
	DMWARN("view b of volume %u: tripwire: killed pid %d before it saw a refusal",
	       x->vol->id, pid_nr(pid));
}

static int pg_volume_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct pg_volume *vol;
	struct pg_view *x;
	unsigned int id;
	char dummy;
	int r = -EINVAL;

	if (argc != 2 || sscanf(argv[0], "%u%c", &id, &dummy) != 1 ||
	    (strcmp(argv[1], "b") && strcmp(argv[1], "c"))) {
		ti->error = "need <volume_id> <b|c>";
		return -EINVAL;
	}
	x = kzalloc(sizeof(*x), GFP_KERNEL);
	if (!x)
		return -ENOMEM;
	x->mode = argv[1][0];
	spin_lock_init(&x->trip_lock);
	atomic64_set(&x->trips, 0);
	if (mutex_lock_killable(&pg_mutex)) {
		kfree(x);
		return -EINTR;
	}
	vol = pg_volume_get(id);
	if (!vol) {
		ti->error = "no such volume";
		goto bad;
	}
	if (vol->view && vol->view != x->mode) {
		ti->error = "views B and C are mutually exclusive";
		r = -EBUSY;
		goto bad;
	}
	if ((vol->flags & PG_NTFS_VOLUME_DIRTY) &&
	    (x->mode == 'b' || pg_table_writable(ti))) {
		ti->error = "volume needs repair: no view B, view C read-only";
		goto bad;
	}
	if ((vol->add_flags & PG_VOLUME_READ_ONLY) && pg_table_writable(ti)) {
		ti->error = "volume added read-only: load the table read-only";
		goto bad;
	}
	r = pg_get_dev(ti, x->mode == 'b' ? vol->raw : vol->plain, &x->dev);
	if (r) {
		ti->error = "device lookup failed";
		goto bad;
	}
	vol->view = x->mode;
	vol->view_tables++;
	x->vol = vol;
	mutex_unlock(&pg_mutex);
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_write_zeroes_bios = 1;
	ti->private = x;
	return 0;

bad:
	mutex_unlock(&pg_mutex);
	kfree(x);
	return r;
}

static void pg_volume_dtr(struct dm_target *ti)
{
	struct pg_view *x = ti->private;

	mutex_lock(&pg_mutex);
	if (--x->vol->view_tables == 0)
		x->vol->view = 0;
	mutex_unlock(&pg_mutex);
	put_pid(x->trip_pid);
	dm_put_device(ti, x->dev);
	kfree(x);
}

static int pg_volume_message(struct dm_target *ti, unsigned int argc,
			     char **argv, char *result, unsigned int maxlen)
{
	struct pg_view *x = ti->private;
	struct pid *pid = NULL, *old;
	int nr;
	char dummy;

	if (argc != 2 || strcmp(argv[0], "tripwire") || x->mode != 'b')
		return -EINVAL;
	if (strcmp(argv[1], "off")) {
		if (sscanf(argv[1], "%d%c", &nr, &dummy) != 1 || nr <= 0)
			return -EINVAL;
		pid = find_get_pid(nr);	/* in the caller's pid namespace */
		if (!pid)
			return -ESRCH;
	}
	spin_lock(&x->trip_lock);
	old = x->trip_pid;
	x->trip_pid = pid;
	spin_unlock(&x->trip_lock);
	put_pid(old);
	DMINFO("view b of volume %u: tripwire %s", x->vol->id, pid ? argv[1] : "off");
	return 0;
}

static int pg_volume_map(struct dm_target *ti, struct bio *bio)
{
	struct pg_view *x = ti->private;
	sector_t sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
	bool hit = false;
	int i;

	bio_set_dev(bio, x->dev->bdev);
	bio->bi_iter.bi_sector = sector;
	if (bio_sectors(bio) == 0)
		return DM_MAPIO_REMAPPED;
	read_lock(&pg_lock);
	for (i = 0; i < PG_MAX_CLAIMS && !hit; i++) {
		struct pg_claim_state *c = &pg_claims[i];

		hit = c->id && c->vol == x->vol &&
		      pg_range_blocks(c->norm, c->nnorm, sector,
				      bio_sectors(bio));
	}
	read_unlock(&pg_lock);
	if (!hit)
		return DM_MAPIO_REMAPPED;
	/* Readahead near metadata is expected; anything else is a guard miss. */
	if (bio->bi_opf & REQ_RAHEAD) {
		atomic64_inc(&x->vol->readahead_hits);
	} else {
		struct pid *pid;

		atomic64_inc(&x->vol->guard_hits);
		DMWARN_LIMIT("view %c of volume %u: refused %s of %u sectors at %llu",
			     x->mode, x->vol->id,
			     op_is_write(bio_op(bio)) ? "write" : "read",
			     bio_sectors(bio), (unsigned long long)sector);
		spin_lock(&x->trip_lock);
		pid = get_pid(x->trip_pid);
		spin_unlock(&x->trip_lock);
		if (pid) {
			pg_trip(x, pid);
			put_pid(pid);
		}
	}
	return DM_MAPIO_KILL;
}

static void pg_volume_status(struct dm_target *ti, status_type_t type,
			     unsigned int status_flags, char *result,
			     unsigned int maxlen)
{
	struct pg_view *x = ti->private;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("guard %lld readahead %lld tripwire %s trips %lld",
		       (long long)atomic64_read(&x->vol->guard_hits),
		       (long long)atomic64_read(&x->vol->readahead_hits),
		       READ_ONCE(x->trip_pid) ? "on" : "off",
		       (long long)atomic64_read(&x->trips));
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%u %c", x->vol->id, x->mode);
		break;
	case STATUSTYPE_IMA:
		*result = '\0';
		break;
	}
}

static int pg_volume_iterate(struct dm_target *ti,
			     iterate_devices_callout_fn fn, void *data)
{
	struct pg_view *x = ti->private;

	return fn(ti, x->dev, 0, ti->len, data);
}

static void pg_volume_io_hints(struct dm_target *ti, struct queue_limits *l)
{
	pg_hints(((struct pg_view *)ti->private)->dev, l);
}

static struct target_type pg_volume_target = {
	.name = "paguro-volume",
	.version = {1, 1, 0},
	.module = THIS_MODULE,
	.ctr = pg_volume_ctr,
	.dtr = pg_volume_dtr,
	.map = pg_volume_map,
	.message = pg_volume_message,
	.status = pg_volume_status,
	.iterate_devices = pg_volume_iterate,
	.io_hints = pg_volume_io_hints,
};

static int __init dm_paguro_init(void)
{
	int r = pg_ctl_init();

	if (r)
		return r;
	r = dm_register_target(&pg_image_target);
	if (r)
		goto out_ctl;
	r = dm_register_target(&pg_volume_target);
	if (r)
		goto out_image;
	return 0;
out_image:
	dm_unregister_target(&pg_image_target);
out_ctl:
	pg_ctl_exit();
	return r;
}

static void __exit dm_paguro_exit(void)
{
	dm_unregister_target(&pg_volume_target);
	dm_unregister_target(&pg_image_target);
	pg_ctl_exit();
}

module_init(dm_paguro_init);
module_exit(dm_paguro_exit);

MODULE_DESCRIPTION(DM_NAME " paguro: protected views over an NTFS volume");
MODULE_LICENSE("GPL");
