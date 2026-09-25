// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * CBMC harness: the core's bitwise CRC-32 (pg_ntfs.c, static) equals the
 * table-driven CRC-32 on every input of up to LEN bytes, from any starting
 * value (so chaining is covered too).
 */
#include "pg_ntfs.c"

#define LEN 3
unsigned char nondet_uchar(void);
pg_u32 nondet_u32(void);
pg_size nondet_size(void);

static pg_u32 table_crc(pg_u32 c, const pg_u8 *p, pg_size n)
{
	pg_u32 t;
	int k;

	c = ~c;
	while (n--) {
		t = (c ^ *p++) & 0xff;
		for (k = 0; k < 8; k++)
			t = t & 1 ? 0xedb88320u ^ (t >> 1) : t >> 1;
		c = t ^ (c >> 8);
	}
	return ~c;
}

int main(void)
{
	pg_u8 in[LEN];
	pg_u32 c = nondet_u32();
	pg_size n = nondet_size(), i;

	__CPROVER_assume(n <= LEN);
	for (i = 0; i < LEN; i++)
		in[i] = nondet_uchar();
	__CPROVER_assert(pg_crc32(c, in, n) == table_crc(c, in, n),
			 "bitwise CRC-32 = table CRC-32");
	return 0;
}
