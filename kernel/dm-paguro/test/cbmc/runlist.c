// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * CBMC harness: pg_runlist_decode over every input of up to LEN bytes and
 * every capacity up to CAP: memory safety, and every accepted run non-empty
 * and not wrapping.
 */
#include "pg_ntfs.h"

#define LEN 12
#define CAP 3
unsigned char nondet_uchar(void);
pg_size nondet_size(void);

int main(void)
{
	pg_u8 in[LEN];
	struct pg_run out[CAP];
	pg_size len = nondet_size(), cap = nondet_size(), n = 0, i;

	__CPROVER_assume(len <= LEN && cap <= CAP);
	for (i = 0; i < LEN; i++)
		in[i] = nondet_uchar();
	if (pg_runlist_decode(in, len, out, cap, &n) == 0) {
		__CPROVER_assert(n <= cap, "within capacity");
		for (i = 0; i < n; i++)
			__CPROVER_assert(out[i].count > 0 &&
					 out[i].lcn + out[i].count >= out[i].lcn,
					 "runs non-empty, no wrap");
	}
	return 0;
}
