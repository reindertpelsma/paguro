// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * CBMC harness: pg_range_normalise and pg_range_blocks over every input of
 * up to N extents (all 64-bit values). Proves memory safety and that the
 * range test is exactly "some protected sector lies in the request".
 */
#include "pg_range.h"

#define N 3
pg_u64 nondet_u64(void);
pg_size nondet_size(void);

int main(void)
{
	struct pg_extent e[N], orig[N];
	pg_size n = nondet_size(), k, i;
	pg_u64 x = nondet_u64(), s = nondet_u64(), c = nondet_u64();
	int in_orig = 0, in_norm = 0, want = 0;

	__CPROVER_assume(n <= N);
	for (i = 0; i < n; i++) {
		e[i].start = nondet_u64();
		e[i].end = nondet_u64();
		orig[i] = e[i];
	}
	k = pg_range_normalise(e, n);
	if (k == 0)
		return 0;
	/* Sorted, non-empty, disjoint and not touching. */
	for (i = 0; i < k; i++) {
		__CPROVER_assert(e[i].start < e[i].end, "non-empty");
		if (i > 0)
			__CPROVER_assert(e[i - 1].end < e[i].start, "sorted, apart");
	}
	/* Same set of sectors. */
	for (i = 0; i < n; i++)
		in_orig |= orig[i].start <= x && x < orig[i].end;
	for (i = 0; i < k; i++)
		in_norm |= e[i].start <= x && x < e[i].end;
	__CPROVER_assert(in_orig == in_norm, "normalise preserves coverage");
	/* The range test against the brute-force definition. */
	for (i = 0; i < k; i++)
		want |= e[i].start < s + c && s < e[i].end;
	if (c == 0 || s + c < s)
		want = 1;
	__CPROVER_assert(pg_range_blocks(e, k, s, c) == want, "blocks is exact");
	return 0;
}
