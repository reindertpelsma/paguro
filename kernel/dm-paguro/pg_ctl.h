/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Module state shared by the control device (pg_ctl.c) and the targets
 * (dm-paguro-main.c). Glue, not core: see README "Reviewing the core".
 *
 * Locking: pg_mutex serialises every control operation and every table
 * constructor/destructor. pg_lock (a rwlock) additionally covers what the
 * I/O path reads -- a claim's extent arrays, state, and `used` -- so the map
 * functions take it for reading and writers hold both.
 */
#ifndef PG_CTL_H
#define PG_CTL_H

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "paguro_uapi.h"
#include "pg_claim.h"
#include "pg_ntfs.h"

struct pg_volume {
	u32 id;				/* 0: slot free */
	dev_t raw, plain;
	u8 guid[16];
	u16 flags;			/* $VOLUME_INFORMATION */
	u64 sectors;
	u64 cluster_bytes, record_bytes, mft_lcn;	/* geometry at add */
	struct pg_extent reserved[PG_MAX_RESERVED];	/* normalised */
	pg_size nreserved;
	int view;			/* 0, 'b' or 'c' */
	int view_tables;		/* live paguro-volume tables */
	atomic64_t guard_hits, readahead_hits;
};

struct pg_claim_state {
	u32 id;				/* 0: slot free */
	struct pg_volume *vol;
	u64 rec;
	u16 seq;
	u32 format;
	u32 state;			/* PG_CLAIM_* */
	u64 limit;			/* sectors a paguro-image may map */
	struct pg_extent *file;		/* file order, for view A */
	pg_size nfile;
	struct pg_extent *norm;		/* normalised, for views B/C */
	pg_size nnorm;
	int image_tables;		/* live paguro-image tables */
	atomic64_t refused;
};

extern struct mutex pg_mutex;
extern rwlock_t pg_lock;
extern struct pg_volume pg_volumes[PG_MAX_VOLUMES];
extern struct pg_claim_state pg_claims[PG_MAX_CLAIMS];

/* Lookups by id; callers hold pg_mutex. NULL if absent. */
struct pg_volume *pg_volume_get(u32 id);
struct pg_claim_state *pg_claim_get(u32 id);

/* Read 512-byte sectors of a block device through one bounce page. */
struct pg_reader {
	struct block_device *bdev;
	struct page *page;
	sector_t cached;		/* first sector held in page, or ~0 */
	unsigned int lbs;		/* logical block size, bytes */
	int ok;
};
int pg_reader_init(struct pg_reader *r, struct block_device *bdev);
void pg_reader_exit(struct pg_reader *r);
int pg_reader_read(void *ctx, pg_u64 sector, pg_u8 *buf);	/* pg_read_fn */

int pg_ctl_init(void);
void pg_ctl_exit(void);

#endif
