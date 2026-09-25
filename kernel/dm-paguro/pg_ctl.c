// SPDX-License-Identifier: GPL-2.0
/*
 * /dev/paguro: volumes and claims (INTERFACES.md 10.2). Glue around the core:
 * every extent comes from pg_ntfs reading the plaintext device itself;
 * userspace names devices and files, and can only ever cause a refusal.
 */
#include <linux/bio.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "pg_ctl.h"

DEFINE_MUTEX(pg_mutex);
DEFINE_RWLOCK(pg_lock);
struct pg_volume pg_volumes[PG_MAX_VOLUMES];
struct pg_claim_state pg_claims[PG_MAX_CLAIMS];

#define PG_MFT_RUNS 2048

/* Scratch for one derivation (~3 MiB, so kvmalloc'd per operation). */
struct pg_work {
	pg_u8 rec[PG_NTFS_MAX_RECORD];
	pg_u8 alist[PG_NTFS_MAX_ALIST];
	struct pg_run mft[PG_MFT_RUNS];
	struct pg_run runs[PG_MAX_EXTENTS];
	struct pg_extent file[PG_MAX_EXTENTS];
	struct pg_extent norm[PG_MAX_EXTENTS];
};

struct pg_volume *pg_volume_get(u32 id)
{
	if (id == 0 || id > PG_MAX_VOLUMES || pg_volumes[id - 1].id != id)
		return NULL;
	return &pg_volumes[id - 1];
}

struct pg_claim_state *pg_claim_get(u32 id)
{
	if (id == 0 || id > PG_MAX_CLAIMS || pg_claims[id - 1].id != id)
		return NULL;
	return &pg_claims[id - 1];
}

/* ---- reading a block device ------------------------------------------- */

int pg_reader_init(struct pg_reader *r, struct block_device *bdev)
{
	r->bdev = bdev;
	r->lbs = bdev_logical_block_size(bdev);
	r->cached = ~(sector_t)0;
	r->page = NULL;
	if (r->lbs > PAGE_SIZE)
		return -EINVAL;
	r->page = alloc_page(GFP_KERNEL);
	return r->page ? 0 : -ENOMEM;
}

void pg_reader_exit(struct pg_reader *r)
{
	if (r->page)
		__free_page(r->page);
}

/*
 * One read in flight. The waiter and the completion each hold a reference;
 * the page stays pinned until the bio completes, even if the waiter gave up.
 */
struct pg_rio {
	struct completion done;
	refcount_t refs;
	blk_status_t status;
	struct page *page;
};

static void pg_rio_put(struct pg_rio *io)
{
	if (refcount_dec_and_test(&io->refs)) {
		put_page(io->page);
		kfree(io);
	}
}

static void pg_rio_end(struct bio *bio)
{
	struct pg_rio *io = bio->bi_private;

	io->status = bio->bi_status;
	bio_put(bio);
	complete(&io->done);
	pg_rio_put(io);
}

/*
 * pg_read_fn: read the logical block holding `sector` with one bio
 * (bypassing the page cache, which a view's writes do not update) and copy
 * out 512 bytes. The last block read is cached. The wait is killable: a
 * device that never answers (a suspended dm table below) cannot pin the
 * caller -- nor, through pg_mutex, every other caller -- beyond a signal.
 * An abandoned read keeps its page; the reader then refuses further reads.
 */
int pg_reader_read(void *ctx, pg_u64 sector, pg_u8 *buf)
{
	struct pg_reader *r = ctx;
	sector_t per = r->lbs >> SECTOR_SHIFT;
	sector_t first = sector - (sector & (per - 1));
	struct pg_rio *io;
	struct bio *bio;
	int e;

	if (!r->page)
		return -EINTR;
	if (sector >= bdev_nr_sectors(r->bdev))
		return -EIO;
	if (first != r->cached) {
		io = kmalloc(sizeof(*io), GFP_KERNEL);
		if (!io)
			return -ENOMEM;
		bio = bio_alloc(r->bdev, 1, REQ_OP_READ, GFP_KERNEL);
		init_completion(&io->done);
		refcount_set(&io->refs, 2);
		get_page(r->page);
		io->page = r->page;
		bio->bi_iter.bi_sector = first;
		__bio_add_page(bio, r->page, r->lbs, 0);
		bio->bi_private = io;
		bio->bi_end_io = pg_rio_end;
		submit_bio(bio);
		if (wait_for_completion_killable(&io->done)) {
			/* The bio still owns the page: let it go with it. */
			put_page(r->page);
			r->page = NULL;
			r->cached = ~(sector_t)0;
			pg_rio_put(io);
			return -EINTR;
		}
		e = blk_status_to_errno(io->status);
		pg_rio_put(io);
		r->cached = e ? ~(sector_t)0 : first;
		if (e)
			return e;
	}
	memcpy(buf, page_address(r->page) + ((sector - first) << SECTOR_SHIFT),
	       512);
	return 0;
}

/* A read-only, non-exclusive open of a block device by number. */
struct pg_bdev {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	struct file *f;
#else
	struct bdev_handle *h;
#endif
	struct block_device *bdev;
};

static int pg_open(dev_t dev, struct pg_bdev *b)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	b->f = bdev_file_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(b->f))
		return PTR_ERR(b->f);
	b->bdev = file_bdev(b->f);
#else
	b->h = bdev_open_by_dev(dev, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(b->h))
		return PTR_ERR(b->h);
	b->bdev = b->h->bdev;
#endif
	return 0;
}

static void pg_close(struct pg_bdev *b)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	fput(b->f);
#else
	bdev_release(b->h);
#endif
}

/* ---- derivation -------------------------------------------------------- */

/* The core's code as an errno: I/O failures stay I/O failures. */
static int pg_errno(s32 err)
{
	if (!err)
		return 0;
	if (err == PG_E_IO)
		return -EIO;
	if (err == PG_ERR_RESERVED || err == PG_ERR_CLAIMED)
		return -EBUSY;
	if (err == PG_ERR_DEVICE)
		return -ENODEV;
	return -EINVAL;
}

/* Parse the volume's boot sector and $MFT afresh into v (w's buffers). */
static s32 pg_open_ntfs(struct pg_ntfs *v, struct pg_reader *r,
			struct pg_work *w)
{
	memset(v, 0, sizeof(*v));
	v->read = pg_reader_read;
	v->ctx = r;
	v->rec = w->rec;
	v->alist = w->alist;
	v->mft = w->mft;
	v->mft_cap = PG_MFT_RUNS;
	return pg_ntfs_open(v);
}

/*
 * Steps 1-6 for (rec, seq) on vol: file-order extents into w->file[0..*nfile),
 * normalised into w->norm[0..*nnorm), file size into *size. Returns a PG_E_*
 * or PG_ERR_* code.
 */
static s32 pg_derive(struct pg_volume *vol, u64 rec, u16 seq,
		     struct pg_work *w, pg_size *nfile, pg_size *nnorm,
		     u64 *size)
{
	struct pg_reader r;
	struct pg_ntfs v;
	struct pg_bdev b;
	pg_size nruns;
	s32 err;

	if (pg_open(vol->plain, &b))
		return PG_ERR_DEVICE;
	err = pg_reader_init(&r, b.bdev) ? PG_ERR_DEVICE : 0;
	if (!err)
		err = pg_open_ntfs(&v, &r, w);
	if (!err && (v.sectors != vol->sectors ||
		     v.cluster_bytes != vol->cluster_bytes ||
		     v.record_bytes != vol->record_bytes ||
		     v.mft_lcn != vol->mft_lcn))
		err = PG_ERR_GEOMETRY;
	if (!err)
		err = pg_ntfs_file(&v, rec, seq, w->runs, PG_MAX_EXTENTS,
				   &nruns, size);
	if (!err)
		err = pg_ntfs_extents(&v, w->runs, nruns, w->file,
				      PG_MAX_EXTENTS, nfile);
	if (!err)
		err = pg_claim_normalise(w->file, *nfile, w->norm,
					 PG_MAX_EXTENTS, nnorm);
	pg_reader_exit(&r);
	pg_close(&b);
	return err;
}

/* Would `norm` intersect a reserved range, or a claim other than `self`? */
static s32 pg_conflict(struct pg_volume *vol, struct pg_claim_state *self,
		       const struct pg_extent *norm, pg_size n)
{
	int i;

	if (pg_claim_intersects(norm, n, vol->reserved, vol->nreserved))
		return PG_ERR_RESERVED;
	for (i = 0; i < PG_MAX_CLAIMS; i++) {
		struct pg_claim_state *c = &pg_claims[i];

		if (c->id && c != self && c->vol == vol &&
		    pg_claim_intersects(norm, n, c->norm, c->nnorm))
			return PG_ERR_CLAIMED;
	}
	return 0;
}

/* Sectors a paguro-image may map: the file, less a VHD footer. */
static u64 pg_limit(u32 format, u64 size)
{
	u64 sectors = size >> SECTOR_SHIFT;

	if (format == PG_FORMAT_VHD)
		return sectors > 1 ? sectors - 1 : 0;
	return sectors;
}

static struct pg_extent *pg_dup(const struct pg_extent *e, pg_size n)
{
	struct pg_extent *d = kvmalloc_array(n, sizeof(*e), GFP_KERNEL);

	if (d)
		memcpy(d, e, n * sizeof(*e));
	return d;
}

/* ---- ioctls ------------------------------------------------------------ */

static long pg_volume_add(struct pg_volume_add *a)
{
	dev_t raw = MKDEV(a->raw_major, a->raw_minor);
	dev_t plain = MKDEV(a->plain_major, a->plain_minor);
	struct pg_volume *vol = NULL;
	struct pg_work *w = NULL;
	struct pg_reader r = { .page = NULL };
	struct pg_bdev b, rb;
	struct pg_ntfs v;
	pg_u16 flags = 0;
	u32 i;
	s32 err = 0;

	if (a->nreserved > PG_MAX_RESERVED || (a->flags & ~PG_VOLUME_READ_ONLY))
		return -EINVAL;
	for (i = 0; i < PG_MAX_VOLUMES; i++) {
		if (pg_volumes[i].id && (pg_volumes[i].raw == raw ||
					 pg_volumes[i].plain == plain)) {
			a->error = PG_ERR_DEVICE;
			return -EBUSY;
		}
		if (!pg_volumes[i].id && !vol)
			vol = &pg_volumes[i];
	}
	if (!vol)
		return -ENOSPC;
	w = kvmalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;
	if (pg_open(plain, &b)) {
		kvfree(w);
		a->error = PG_ERR_DEVICE;
		return -ENODEV;
	}
	err = pg_reader_init(&r, b.bdev) ? PG_ERR_DEVICE : 0;
	if (!err)
		err = pg_open_ntfs(&v, &r, w);
	if (!err)
		err = pg_ntfs_volume_flags(&v, &flags);
	if (!err && bdev_nr_sectors(b.bdev) < v.sectors)
		err = PG_ERR_DEVICE;
	pg_reader_exit(&r);
	pg_close(&b);
	kvfree(w);
	if (!err && raw != plain) {
		if (pg_open(raw, &rb)) {
			err = PG_ERR_DEVICE;
		} else {
			if (bdev_nr_sectors(rb.bdev) < v.sectors)
				err = PG_ERR_DEVICE;
			pg_close(&rb);
		}
	}
	a->error = err;
	if (err)
		return pg_errno(err);
	/* Reserved ranges: inside the volume, non-empty; then normalised. */
	for (i = 0; i < a->nreserved; i++) {
		u64 s = a->reserved[i].start, l = a->reserved[i].len;

		if (l == 0 || s + l < s || s + l > v.sectors)
			return -EINVAL;
		vol->reserved[i].start = s;
		vol->reserved[i].end = s + l;
	}
	vol->nreserved = pg_range_normalise(vol->reserved, a->nreserved);
	vol->raw = raw;
	vol->plain = plain;
	memcpy(vol->guid, a->guid, sizeof(vol->guid));
	vol->flags = flags;
	vol->add_flags = a->flags;
	vol->sectors = v.sectors;
	vol->cluster_bytes = v.cluster_bytes;
	vol->record_bytes = v.record_bytes;
	vol->mft_lcn = v.mft_lcn;
	vol->view = 0;
	vol->view_tables = 0;
	atomic64_set(&vol->guard_hits, 0);
	atomic64_set(&vol->readahead_hits, 0);
	vol->id = vol - pg_volumes + 1;
	a->volume_id = vol->id;
	a->volume_flags = flags;
	a->sectors = v.sectors;
	pr_info_ratelimited("paguro: volume %u: %llu sectors, %llu-byte clusters, flags %#x, %zu reserved ranges%s\n",
		vol->id, v.sectors, v.cluster_bytes, flags, vol->nreserved,
		vol->add_flags & PG_VOLUME_READ_ONLY ? ", read-only" : "");
	return 0;
}

static long pg_claim_ioctl(struct pg_claim *a)
{
	struct pg_volume *vol = pg_volume_get(a->volume_id);
	struct pg_claim_state *c = NULL;
	struct pg_extent *file, *norm;
	pg_size nfile, nnorm;
	struct pg_work *w;
	u64 size;
	int i;

	if (!vol)
		return -ENOENT;
	if (a->format > PG_FORMAT_VHD)
		return -EINVAL;
	for (i = 0; i < PG_MAX_CLAIMS; i++) {
		if (pg_claims[i].id && pg_claims[i].vol == vol &&
		    pg_claims[i].rec == a->mft_record) {
			a->error = PG_ERR_CLAIMED;
			return -EBUSY;
		}
		if (!pg_claims[i].id && !c)
			c = &pg_claims[i];
	}
	if (!c)
		return -ENOSPC;
	w = kvmalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;
	a->error = pg_derive(vol, a->mft_record, a->mft_seq, w, &nfile, &nnorm,
			     &size);
	if (!a->error && !pg_limit(a->format, size))
		a->error = PG_ERR_EMPTY;
	if (!a->error)
		a->error = pg_conflict(vol, NULL, w->norm, nnorm);
	if (a->error) {
		pr_info_ratelimited("paguro: claim of record %llu refused: error %d\n",
			a->mft_record, a->error);
		kvfree(w);
		return pg_errno(a->error);
	}
	file = pg_dup(w->file, nfile);
	norm = pg_dup(w->norm, nnorm);
	kvfree(w);
	if (!file || !norm) {
		kvfree(file);
		kvfree(norm);
		return -ENOMEM;
	}
	write_lock(&pg_lock);
	c->vol = vol;
	c->rec = a->mft_record;
	c->seq = a->mft_seq;
	c->format = a->format;
	c->state = pg_volume_ro(vol) ? PG_CLAIM_READONLY : 0;
	c->limit = pg_limit(a->format, size);
	c->file = file;
	c->nfile = nfile;
	c->norm = norm;
	c->nnorm = nnorm;
	c->image_tables = 0;
	atomic64_set(&c->refused, 0);
	c->id = c - pg_claims + 1;
	write_unlock(&pg_lock);
	a->claim_id = c->id;
	a->extents = nfile;
	a->sectors = c->limit;
	a->state = c->state;
	pr_info_ratelimited("paguro: claim %u: volume %u record %llu: %zu extents, %llu sectors\n",
		c->id, vol->id, c->rec, nfile, c->limit);
	return 0;
}

static int pg_same(const struct pg_extent *a, pg_size na,
		   const struct pg_extent *b, pg_size nb)
{
	pg_size i;

	if (na != nb)
		return 0;
	for (i = 0; i < na; i++)
		if (a[i].start != b[i].start || a[i].end != b[i].end)
			return 0;
	return 1;
}

static long pg_grow_ioctl(struct pg_grow *a)
{
	struct pg_claim_state *c = pg_claim_get(a->claim_id);
	struct pg_extent *file = NULL, *norm = NULL, *oldf, *oldn;
	pg_size nfile, nnorm;
	struct pg_work *w;
	u64 size, limit = 0;
	s32 err;

	if (!c)
		return -ENOENT;
	if (c->state & PG_CLAIM_REFUSED)
		return -EPERM;
	w = kvmalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;
	err = pg_derive(c->vol, c->rec, c->seq, w, &nfile, &nnorm, &size);
	if (!err) {
		limit = pg_limit(c->format, size);
		if (!pg_claim_grows(c->file, c->nfile, w->file, nfile) ||
		    limit < c->limit)
			err = PG_ERR_NOT_APPEND;
	}
	if (!err)
		err = pg_conflict(c->vol, c, w->norm, nnorm);
	if (!err && !(pg_same(c->file, c->nfile, w->file, nfile) &&
		      limit == c->limit)) {
		file = pg_dup(w->file, nfile);
		norm = pg_dup(w->norm, nnorm);
		if (!file || !norm) {
			kvfree(file);
			kvfree(norm);
			kvfree(w);
			return -ENOMEM;
		}
	}
	kvfree(w);
	write_lock(&pg_lock);
	oldf = file ? c->file : NULL;
	oldn = norm ? c->norm : NULL;
	if (err) {
		/* Not append-only, or unparseable: keep the old map, stop writes. */
		c->state |= PG_CLAIM_READONLY;
	} else if (file) {
		c->file = file;
		c->nfile = nfile;
		c->norm = norm;
		c->nnorm = nnorm;
		c->limit = limit;
		c->state &= ~PG_CLAIM_CHECKED;	/* the new part is unchecked */
	}
	a->state = c->state;
	a->sectors = c->limit;
	a->extents = c->nfile;
	a->error = err;
	write_unlock(&pg_lock);
	kvfree(oldf);
	kvfree(oldn);
	pr_info_ratelimited("paguro: grow claim %u: error %d, state %#x, %llu sectors\n",
		c->id, err, c->state, c->limit);
	return 0;
}

static long pg_crosscheck_ioctl(struct pg_crosscheck *a)
{
	struct pg_claim_state *c = pg_claim_get(a->claim_id);
	struct pg_uapi_range *u;
	struct pg_extent *e, *f;
	pg_size i, n, nf;
	u64 size;
	int match;

	if (!c)
		return -ENOENT;
	if (a->count == 0 || a->count > PG_MAX_EXTENTS)
		return -EINVAL;
	if (c->state & PG_CLAIM_REFUSED) {
		a->state = c->state;
		return -EPERM;
	}
	u = kvmalloc_array(a->count, sizeof(*u), GFP_KERNEL);
	e = kvmalloc_array(a->count, sizeof(*e), GFP_KERNEL);
	if (!u || !e) {
		kvfree(u);
		kvfree(e);
		return -ENOMEM;
	}
	if (copy_from_user(u, u64_to_user_ptr(a->ranges),
			   a->count * sizeof(*u))) {
		kvfree(u);
		kvfree(e);
		return -EFAULT;
	}
	match = 1;
	for (i = 0; i < a->count; i++) {
		e[i].start = u[i].start;
		e[i].end = u[i].start + u[i].len;
		if (e[i].end < e[i].start)
			match = 0;
	}
	/*
	 * Both sides up to the end of the file's data (pg_claim_truncate):
	 * the file is `limit` sectors, plus a VHD's footer. c->file only
	 * changes under pg_mutex, which the caller holds.
	 */
	size = c->limit + (c->format == PG_FORMAT_VHD);
	f = pg_dup(c->file, c->nfile);
	if (!f) {
		kvfree(u);
		kvfree(e);
		return -ENOMEM;
	}
	nf = pg_claim_truncate(f, c->nfile, size);
	n = match ? pg_claim_coalesce(e, a->count) : 0;
	n = n ? pg_claim_truncate(e, n, size) : 0;
	write_lock(&pg_lock);
	match = n && nf && pg_same(e, n, f, nf);
	/* Compare only: agreement marks the claim, disagreement ends it. */
	if (match)
		c->state |= PG_CLAIM_CHECKED;
	else
		c->state = (c->state & ~PG_CLAIM_CHECKED) | PG_CLAIM_REFUSED;
	a->state = c->state;
	write_unlock(&pg_lock);
	kvfree(u);
	kvfree(e);
	kvfree(f);
	pr_info_ratelimited("paguro: cross-check claim %u: %s\n", c->id,
		match ? "agrees" : "DISAGREES, claim refused");
	return 0;
}

static long pg_release_ioctl(struct pg_release *a)
{
	struct pg_claim_state *c = pg_claim_get(a->claim_id);
	struct pg_extent *file, *norm;

	if (!c)
		return -ENOENT;
	if (c->image_tables)
		return -EBUSY;
	write_lock(&pg_lock);
	file = c->file;
	norm = c->norm;
	c->id = 0;
	c->file = c->norm = NULL;
	c->nfile = c->nnorm = 0;
	c->vol = NULL;
	write_unlock(&pg_lock);
	kvfree(file);
	kvfree(norm);
	return 0;
}

static long pg_volume_remove(struct pg_volume_remove *a)
{
	struct pg_volume *vol = pg_volume_get(a->volume_id);
	int i;

	if (!vol)
		return -ENOENT;
	for (i = 0; i < PG_MAX_CLAIMS; i++)
		if (pg_claims[i].id && pg_claims[i].vol == vol)
			return -EBUSY;
	if (vol->view_tables)
		return -EBUSY;
	vol->id = 0;
	return 0;
}

static void pg_status_fill(struct pg_status *s)
{
	int i;

	memset(s, 0, sizeof(*s));
	for (i = 0; i < PG_MAX_VOLUMES; i++) {
		struct pg_volume *v = &pg_volumes[i];

		if (!v->id)
			continue;
		s->volume[i].id = v->id;
		s->volume[i].flags = v->flags;
		s->volume[i].view = v->view;
		s->volume[i].view_tables = v->view_tables;
		s->volume[i].sectors = v->sectors;
		s->volume[i].guard_hits = atomic64_read(&v->guard_hits);
		s->volume[i].readahead_hits = atomic64_read(&v->readahead_hits);
		memcpy(s->volume[i].guid, v->guid, 16);
	}
	for (i = 0; i < PG_MAX_CLAIMS; i++) {
		struct pg_claim_state *c = &pg_claims[i];

		if (!c->id)
			continue;
		s->claim[i].id = c->id;
		s->claim[i].volume_id = c->vol->id;
		s->claim[i].state = c->state;
		s->claim[i].extents = c->nfile;
		s->claim[i].mft_record = c->rec;
		s->claim[i].mft_seq = c->seq;
		s->claim[i].sectors = c->limit;
		s->claim[i].refused = atomic64_read(&c->refused);
		s->claim[i].image_tables = c->image_tables;
		s->claim[i].format = c->format;
	}
}

static long pg_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	void __user *up = (void __user *)arg;
	union {
		struct pg_volume_add add;
		struct pg_claim claim;
		struct pg_grow grow;
		struct pg_crosscheck check;
		struct pg_release release;
		struct pg_status status;
		struct pg_volume_remove remove;
	} *u;
	size_t size = _IOC_SIZE(cmd);
	long r;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	switch (cmd) {
	case PG_VOLUME_ADD: case PG_CLAIM: case PG_GROW: case PG_CROSSCHECK:
	case PG_RELEASE: case PG_STATUS: case PG_VOLUME_REMOVE:
		break;
	default:
		return -ENOTTY;
	}
	/* One copy of the argument; everything after reads the copy. */
	u = kzalloc(sizeof(*u), GFP_KERNEL);
	if (!u)
		return -ENOMEM;
	if (copy_from_user(u, up, size)) {
		kfree(u);
		return -EFAULT;
	}
	/* Killable: a caller stuck behind a hung device can still be killed. */
	if (mutex_lock_killable(&pg_mutex)) {
		kfree(u);
		return -EINTR;
	}
	switch (cmd) {
	case PG_VOLUME_ADD:
		r = pg_volume_add(&u->add);
		break;
	case PG_CLAIM:
		r = pg_claim_ioctl(&u->claim);
		break;
	case PG_GROW:
		r = pg_grow_ioctl(&u->grow);
		break;
	case PG_CROSSCHECK:
		r = pg_crosscheck_ioctl(&u->check);
		break;
	case PG_RELEASE:
		r = pg_release_ioctl(&u->release);
		break;
	case PG_VOLUME_REMOVE:
		r = pg_volume_remove(&u->remove);
		break;
	default:
		pg_status_fill(&u->status);
		r = 0;
		break;
	}
	mutex_unlock(&pg_mutex);
	/* Out-fields (error codes, state) are returned on failure too. */
	if (copy_to_user(up, u, size))
		r = r ? r : -EFAULT;
	kfree(u);
	return r;
}

static const struct file_operations pg_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = pg_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice pg_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "paguro",
	.fops = &pg_fops,
	.mode = 0600,
};

int pg_ctl_init(void)
{
	return misc_register(&pg_misc);
}

void pg_ctl_exit(void)
{
	int i;

	misc_deregister(&pg_misc);
	for (i = 0; i < PG_MAX_CLAIMS; i++) {
		kvfree(pg_claims[i].file);
		kvfree(pg_claims[i].norm);
	}
}
