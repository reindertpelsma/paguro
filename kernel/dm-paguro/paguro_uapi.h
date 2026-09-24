/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * /dev/paguro control interface (INTERFACES.md 10.2). Fixed-size structs,
 * little-endian hosts only. Userspace passes identities and devices, never
 * extents: the one list it can send (PG_CROSSCHECK) can only cause refusal.
 *
 * Every request carries an `error` out-field: on -EINVAL/-EBUSY/-EIO the
 * module puts the NTFS core's PG_E_* code (pg_ntfs.h) or one of PG_ERR_*.
 */
#ifndef PAGURO_UAPI_H
#define PAGURO_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define PG_MAX_VOLUMES 8
#define PG_MAX_CLAIMS 16
#define PG_MAX_RESERVED 8

/* Refusals beyond the NTFS core's PG_E_* (which are all < 100). */
#define PG_ERR_RESERVED 100	/* a derived extent intersects a reserved range */
#define PG_ERR_CLAIMED 101	/* ... or another claim on the volume */
#define PG_ERR_DEVICE 102	/* device missing, too small, or already added */
#define PG_ERR_GEOMETRY 103	/* boot sector changed since PG_VOLUME_ADD */
#define PG_ERR_ALIGN 104	/* extents not aligned to the logical block */
#define PG_ERR_EMPTY 105	/* file too small for its format */
#define PG_ERR_NOT_APPEND 106	/* growth moved or shrank existing extents */

/* A range in 512-byte sectors of the volume. */
struct pg_uapi_range {
	__u64 start;
	__u64 len;
};

struct pg_volume_add {
	__u32 raw_major, raw_minor;	/* ciphertext (view B); = plain if none */
	__u32 plain_major, plain_minor;	/* plaintext NTFS (view C, parsing) */
	__u8 guid[16];			/* GPT partition GUID, informational */
	__u32 nreserved;		/* BitLocker's non-data regions, <= 8 */
	__u32 pad0;
	struct pg_uapi_range reserved[PG_MAX_RESERVED];
	/* out */
	__u32 volume_id;
	__u32 volume_flags;		/* $VOLUME_INFORMATION flags */
	__u64 sectors;			/* NTFS size, whole clusters */
	__s32 error;
	__u32 pad1;
};

#define PG_FORMAT_RAW 0
#define PG_FORMAT_VHD 1		/* last sector is the VHD footer */

struct pg_claim {
	__u32 volume_id;
	__u32 format;
	__u64 mft_record;
	__u16 mft_seq;
	__u16 pad0[3];
	/* out */
	__u32 claim_id;
	__u32 extents;
	__u64 sectors;			/* longest paguro-image table allowed */
	__u32 state;			/* PG_CLAIM_* */
	__s32 error;
};

#define PG_CLAIM_READONLY 1	/* dirty volume, or growth not append-only */
#define PG_CLAIM_CHECKED 2	/* PG_CROSSCHECK agreed since the last change */
#define PG_CLAIM_REFUSED 4	/* PG_CROSSCHECK disagreed: no view A, ever */

struct pg_grow {
	__u32 claim_id;
	__u32 state;			/* out */
	__u64 sectors;			/* out */
	__u32 extents;			/* out */
	__s32 error;			/* out: why growth was refused */
};

struct pg_crosscheck {
	__u32 claim_id;
	__u32 count;
	__u64 ranges;			/* user pointer to pg_uapi_range[count] */
	__u32 state;			/* out */
	__u32 pad0;
};

struct pg_release {
	__u32 claim_id;
	__u32 pad0;
};

/* Not in INTERFACES 10.2: undoes PG_VOLUME_ADD when no claim or view uses it. */
struct pg_volume_remove {
	__u32 volume_id;
	__u32 pad0;
};

struct pg_status_volume {
	__u32 id;			/* 0: slot unused */
	__u32 flags;			/* $VOLUME_INFORMATION flags */
	__u32 view;			/* 0, 'b' or 'c' */
	__u32 view_tables;
	__u64 sectors;
	__u64 guard_hits;		/* non-readahead I/O refused by B/C */
	__u64 readahead_hits;		/* readahead refused by B/C (expected) */
	__u8 guid[16];
};

struct pg_status_claim {
	__u32 id;			/* 0: slot unused */
	__u32 volume_id;
	__u32 state;
	__u32 extents;
	__u64 mft_record;
	__u64 sectors;
	__u64 refused;			/* I/O refused by this claim's view A */
	__u16 mft_seq;
	__u16 image_tables;
	__u32 format;
};

struct pg_status {
	struct pg_status_volume volume[PG_MAX_VOLUMES];
	struct pg_status_claim claim[PG_MAX_CLAIMS];
};

#define PG_VOLUME_ADD _IOWR('p', 1, struct pg_volume_add)
#define PG_CLAIM _IOWR('p', 2, struct pg_claim)
#define PG_GROW _IOWR('p', 3, struct pg_grow)
#define PG_CROSSCHECK _IOWR('p', 4, struct pg_crosscheck)
#define PG_RELEASE _IOWR('p', 5, struct pg_release)
#define PG_STATUS _IOWR('p', 6, struct pg_status)
#define PG_VOLUME_REMOVE _IOWR('p', 7, struct pg_volume_remove)

#endif
