// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * libFuzzer target for the structural assertion (pg_payload_check), built
 * with ASan + UBSan. Input: the sparse format of fuzz_ntfs.c, whose first
 * u32 is the image length in sectors:
 *   sectors u32 | flags u16 | u16 | { sector u32 | 512 bytes }*
 * with bit 0 of flags choosing 4096-byte logical blocks.
 * Listed sectors read back, others fail. Seeds: corpus/payload
 * (`paguro-harness payload-seeds`).
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sparse sp = { data, size };
	pg_u8 buf[512];
	int e;

	if (size < 8)
		return 0;
	e = pg_payload_check(sread, &sp, le32(data), data[4] & 1 ? 4096 : 512, buf);
	/* Every result is 0, an I/O failure or a payload refusal. */
	if (e && e != PG_E_IO &&
	    (e < PG_E_PAYLOAD_GPT || e > PG_E_PAYLOAD_UNKNOWN))
		__builtin_trap();
	return 0;
}
