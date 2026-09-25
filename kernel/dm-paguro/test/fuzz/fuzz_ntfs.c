// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * libFuzzer target for the module's NTFS core, built with ASan + UBSan.
 *
 * Input (shared with fuzz/ and paguro-harness's SparseDisk):
 *   rec u32 | seq u16 | reserved u16 | { sector u32 | 512 bytes }*
 * A sparse volume: listed sectors read back, others fail. The whole input
 * is also handed to the payload check as a flat image.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pg_claim.h"
#include "pg_ntfs.h"

struct sparse {
	const uint8_t *p;
	size_t n;
};

static uint64_t le32(const uint8_t *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (uint64_t)p[3] << 24;
}

static int sread(void *ctx, pg_u64 s, pg_u8 *buf)
{
	const struct sparse *sp = ctx;
	size_t i;

	for (i = 8; i + 516 <= sp->n; i += 516)
		if (le32(sp->p + i) == s) {
			memcpy(buf, sp->p + i + 4, 512);
			return 0;
		}
	return 1;
}

static int flat(void *ctx, pg_u64 s, pg_u8 *buf)
{
	const struct sparse *sp = ctx;

	if (s >= sp->n / 512)
		return 1;
	memcpy(buf, sp->p + s * 512, 512);
	return 0;
}

static pg_u8 rec[PG_NTFS_MAX_RECORD], alist[PG_NTFS_MAX_ALIST], buf[512];
static struct pg_run mft[2048], runs[PG_MAX_EXTENTS];
static struct pg_extent ext[PG_MAX_EXTENTS], norm[PG_MAX_EXTENTS];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sparse sp = { data, size };
	struct pg_ntfs v;
	pg_size n, k, nn;
	pg_u64 bytes, p;
	pg_u16 flags;

	if (size < 8)
		return 0;
	pg_payload_check(flat, &sp, size / 512, data[4] & 1 ? 4096 : 512, buf);
	memset(&v, 0, sizeof(v));
	v.read = sread;
	v.ctx = &sp;
	v.rec = rec;
	v.alist = alist;
	v.mft = mft;
	v.mft_cap = 2048;
	if (pg_ntfs_open(&v))
		return 0;
	pg_ntfs_volume_flags(&v, &flags);
	if (pg_ntfs_file(&v, le32(data), (pg_u16)(data[4] | data[5] << 8),
			 runs, PG_MAX_EXTENTS, &n, &bytes))
		return 0;
	if (pg_ntfs_extents(&v, runs, n, ext, PG_MAX_EXTENTS, &k))
		return 0;
	if (pg_claim_normalise(ext, k, norm, PG_MAX_EXTENTS, &nn))
		return 0;
	/* A successful map is internally consistent. */
	if (bytes > v.sectors * 512 || pg_claim_intersects(norm, nn, norm, 0))
		__builtin_trap();
	pg_claim_gather(ext, k, bytes / 512 ? bytes / 512 - 1 : 0, &p);
	pg_claim_grows(ext, k, ext, k) || (__builtin_trap(), 0);
	return 0;
}
