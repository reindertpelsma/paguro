/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * paguro NTFS core -- derive one file's extents from the volume itself
 * (DESIGN.md 4.3, INTERFACES.md 10.1). Run once per claim, never per I/O.
 *
 * Plain C over byte buffers and a read callback: no kernel or libc calls, no
 * allocation, no recursion. The caller provides every buffer. The same file
 * is compiled into the module, into userspace unit tests and fuzzers, and is
 * differential-tested against the Rust specification
 * (crates/paguro-core/src/ntfs.rs): same checks, same order, same error.
 */
#ifndef PG_NTFS_H
#define PG_NTFS_H

#include "pg_range.h"

#define PG_NTFS_MAX_RECORD 4096		/* MFT record bytes */
#define PG_NTFS_MAX_ALIST 65536		/* $ATTRIBUTE_LIST bytes */
#define PG_NTFS_MAX_EXTENSIONS 64	/* $DATA segments outside the base */
#define PG_NTFS_MAX_CLUSTER (2u << 20)	/* bytes */
#define PG_NTFS_FIRST_USER_RECORD 24	/* 0-15 metadata, 16-23 reserved */
#define PG_NTFS_VOLUME_DIRTY 0x0001
#define PG_MAX_EXTENTS 65536

/* Errors: 0 is success. Values match NtfsError::code() in ntfs.rs. */
enum {
	PG_E_IO = 1, PG_E_BOOT_SIGNATURE, PG_E_OEM_ID, PG_E_SECTOR_SIZE,
	PG_E_CLUSTER_SIZE, PG_E_VOLUME_SIZE, PG_E_RECORD_SIZE, PG_E_MFT_LCN,
	PG_E_BAD_IDENTITY, PG_E_NOT_MAPPED, PG_E_RECORD_MAGIC,
	PG_E_RECORD_LAYOUT, PG_E_FIXUP_MISMATCH, PG_E_RECORD_NUMBER,
	PG_E_NOT_IN_USE, PG_E_DIRECTORY, PG_E_SEQUENCE, PG_E_NOT_BASE,
	PG_E_ATTR_BOUNDS, PG_E_NO_DATA, PG_E_DUPLICATE_DATA, PG_E_RESIDENT,
	PG_E_COMPRESSED, PG_E_ENCRYPTED, PG_E_SPARSE, PG_E_GAP,
	PG_E_SEGMENT_VCN, PG_E_OUTSIDE_VOLUME, PG_E_ATTR_LIST,
	PG_E_ATTR_LIST_SIZE, PG_E_TOO_MANY_EXTENSIONS, PG_E_MISSING_SEGMENT,
	PG_E_EXTENSION_BASE, PG_E_MFT_ATTR_LIST, PG_E_ALLOCATED_SIZE,
	PG_E_NOT_INITIALIZED, PG_E_UNALIGNED, PG_E_TOO_MANY_EXTENTS,
	PG_E_NO_VOLUME_INFO, PG_E_SELF_OVERLAP, PG_E_PAYLOAD_GPT,
	PG_E_PAYLOAD_NO_KNOWN_PARTITION, PG_E_PAYLOAD_NOT_FAT,
	PG_E_PAYLOAD_GPT_CRC, PG_E_PAYLOAD_GPT_BACKUP, PG_E_PAYLOAD_EXT4,
	PG_E_PAYLOAD_ISO, PG_E_PAYLOAD_UNKNOWN,
	/* runlist decoding (runlist.rs RunlistError) */
	PG_E_RL_TRUNCATED = 50, PG_E_RL_FIELD_TOO_WIDE, PG_E_RL_SPARSE,
	PG_E_RL_ZERO_LENGTH, PG_E_RL_NEGATIVE_LCN, PG_E_RL_OVERFLOW,
	PG_E_RL_TOO_MANY_RUNS, PG_E_RL_UNTERMINATED,
};

/* One run in clusters: `count` clusters from logical cluster `lcn`. */
struct pg_run {
	pg_u64 lcn;
	pg_u64 count;
};

/* Read 512-byte sector `sector` into `buf`; nonzero means failure. */
typedef int (*pg_read_fn)(void *ctx, pg_u64 sector, pg_u8 *buf);

struct pg_ntfs {
	/* Set by the caller before pg_ntfs_open(). */
	pg_read_fn read;
	void *ctx;
	pg_u8 *rec;		/* PG_NTFS_MAX_RECORD bytes of scratch */
	pg_u8 *alist;		/* PG_NTFS_MAX_ALIST bytes of scratch */
	struct pg_run *mft;	/* receives $MFT's map ... */
	pg_size mft_cap;	/* ... of at most this many runs */
	/* Set by pg_ntfs_open(); sizes in bytes unless named otherwise. */
	pg_u64 sectors;		/* whole clusters, in 512-byte sectors */
	pg_u64 clusters;
	pg_u64 cluster_bytes;
	pg_u64 record_bytes;
	pg_u64 mft_lcn;
	pg_size nmft;
	pg_u64 mft_bytes;	/* records live below this offset of $MFT */
};

/* Step 1: validate a boot sector (512 bytes) and fill in the geometry. */
int pg_ntfs_boot(struct pg_ntfs *v, const pg_u8 *boot);

/* Steps 1-2: read the boot sector and map $MFT into v->mft. */
int pg_ntfs_open(struct pg_ntfs *v);

/*
 * Steps 3-5: the unnamed $DATA runs of file (rec, seq), in VCN order, into
 * runs[0..*nruns); *data_size is the file size in bytes.
 */
int pg_ntfs_file(struct pg_ntfs *v, pg_u64 rec, pg_u16 seq,
		 struct pg_run *runs, pg_size cap, pg_size *nruns,
		 pg_u64 *data_size);

/* Step 6: runs -> 512-byte-sector extents, file order, adjacent coalesced. */
int pg_ntfs_extents(const struct pg_ntfs *v, const struct pg_run *runs,
		    pg_size n, struct pg_extent *out, pg_size cap,
		    pg_size *nout);

/* Step 7: $Volume's $VOLUME_INFORMATION flags. */
int pg_ntfs_volume_flags(struct pg_ntfs *v, pg_u16 *flags);

/*
 * The structural assertion (DESIGN 4.3, INTERFACES 3.2): the image of
 * `sectors` sectors, read through `read`, is one of
 *   - a GPT disk: header and entry-array CRCs, the backup header at the
 *     primary's alternate LBA agreeing with it (and its own array), every
 *     partition inside the usable range, each ESP a FAT boot sector, each
 *     partition holding ext4 checked as below, at least one verified;
 *   - bare ext4: sane superblock no larger than the image, and the backup
 *     superblock in group 1 (or s_backup_bgs[0]) agreeing on UUID, block
 *     count and group number;
 *   - ISO 9660: PVD fields agree, volume space size == the image, the root
 *     directory's "." record points at itself.
 * Anything else is refused. `lbs` (512 or 4096) is view A's logical block
 * size, the unit of a GPT's LBAs. `buf` is 512 bytes of scratch.
 */
int pg_payload_check(pg_read_fn read, void *ctx, pg_u64 sectors,
		     unsigned int lbs, pg_u8 *buf);

/* Mapping-pairs decoder (the C twin of runlist.rs), exposed for fuzzing. */
int pg_runlist_decode(const pg_u8 *in, pg_size len, struct pg_run *out,
		      pg_size cap, pg_size *n);

#endif
