// SPDX-License-Identifier: GPL-2.0 OR MIT
/* libFuzzer target for the mapping-pairs decoder alone (ASan + UBSan). */
#include <stddef.h>
#include <stdint.h>

#include "pg_ntfs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static struct pg_run out[256];
	pg_size n, i;

	if (pg_runlist_decode(data, size, out, 256, &n) == 0)
		for (i = 0; i < n; i++)		/* invariants of a decoded list */
			if (out[i].count == 0 || out[i].lcn + out[i].count < out[i].lcn)
				__builtin_trap();
	return 0;
}
