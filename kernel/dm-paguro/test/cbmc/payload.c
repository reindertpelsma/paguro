// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * CBMC harness: the payload check (pg_ntfs.c) over sectors of arbitrary
 * content (every read may also fail): memory safety, no overflow, every
 * sector read inside the image (or the ext4 partition checked), and a typed
 * result. One path per run, chosen with -DPATH_{GPT,EXT4,ISO}, to stay
 * tractable:
 *
 *   GPT   LBA 1 starts "EFI PART" (either logical block size), at most
 *         COUNT entries; no read shows an ext4 magic (ext4 is proved alone)
 *   EXT4  payload_ext4 at any base/length inside any image (bare and in a
 *         partition), both sparse_super and sparse_super2
 *   ISO   neither GPT nor ext4; the primary volume descriptor at 32 KiB
 *
 * pg_crc32 is a free function here (PG_CBMC_FREE_CRC) that must only be
 * handed readable memory; crc.c proves the real one equal to the table CRC.
 */
#include <string.h>

#include "pg_ntfs.c"

#define COUNT 5
int nondet_int(void);
pg_u32 nondet_u32(void);
pg_u64 nondet_u64(void);

struct sector {
	pg_u8 b[512];
};
struct sector nondet_sector(void);

static pg_u64 lo, hi;		/* reads must fall in [lo, hi) */
static unsigned int lbs;

pg_u32 pg_crc32(pg_u32 c, const pg_u8 *p, pg_size n)
{
	(void)c;
	__CPROVER_assert(__CPROVER_r_ok(p, n), "CRC input readable");
	return nondet_u32();
}

static int rd(void *ctx, pg_u64 s, pg_u8 *buf)
{
	struct sector x = nondet_sector();

	(void)ctx;
	__CPROVER_assert(s >= lo && s < hi, "every read inside the image");
	if (nondet_int())
		return 1;
	memcpy(buf, x.b, 512);
#ifdef PATH_GPT
	if (s == lbs / 512) {
		__CPROVER_assume(!memcmp(buf, "EFI PART", 8));
		__CPROVER_assume(buf[80] <= COUNT && !buf[81] && !buf[82] && !buf[83]);
	} else {
		__CPROVER_assume(!(buf[56] == 0x53 && buf[57] == 0xef));
	}
#endif
#ifdef PATH_ISO
	if (s == 1 || s == 8)
		__CPROVER_assume(buf[0] != 'E');
	if (s == 2)
		__CPROVER_assume(buf[56] != 0x53);
#endif
	return 0;
}

int main(void)
{
	pg_u8 buf[512];
	int e;

	lbs = nondet_int() ? 4096 : 512;
	lo = 0;
	hi = nondet_u64();
#ifdef PATH_EXT4
	{
		pg_u64 base = nondet_u64(), len = nondet_u64();

		__CPROVER_assume(base + len >= base && base + len <= hi);
		lo = base;
		hi = base + len;
		e = payload_ext4(rd, 0, base, len, buf);
		__CPROVER_assert(e == 0 || e == PG_E_IO || e == PG_E_PAYLOAD_EXT4,
				 "ext4: success, I/O or PayloadExt4");
		return 0;
	}
#endif
	e = pg_payload_check(rd, 0, hi, lbs, buf);
	__CPROVER_assert(e == 0 || e == PG_E_IO ||
			 (e >= PG_E_PAYLOAD_GPT && e <= PG_E_PAYLOAD_UNKNOWN),
			 "result is success, I/O or a payload refusal");
	return 0;
}
