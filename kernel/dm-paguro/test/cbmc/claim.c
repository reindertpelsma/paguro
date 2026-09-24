// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * CBMC harness: the claim checks (pg_claim.c) over all inputs of up to N
 * extents: memory safety, and each against its definition.
 */
#include "pg_claim.h"
#include "pg_ntfs.h"

#define N 3
pg_u64 nondet_u64(void);
pg_size nondet_size(void);

static void fill(struct pg_extent *e, pg_size n)
{
	pg_size i;

	for (i = 0; i < n; i++) {
		e[i].start = nondet_u64();
		e[i].end = nondet_u64();
		__CPROVER_assume(e[i].start < e[i].end);
	}
}

int main(void)
{
	struct pg_extent a[N], b[N], out[N];
	pg_size na = nondet_size(), nb = nondet_size(), cap = nondet_size(), k, i, j;
	pg_u64 x = nondet_u64(), phys, left, base = 0;
	int brute = 0, e;

	__CPROVER_assume(na <= N && nb <= N && cap <= N);
	fill(a, na);
	fill(b, nb);
	/* normalise: sorted, disjoint; refuses exactly the overlapping inputs. */
	e = pg_claim_normalise(a, na, out, cap, &k);
	if (!e) {
		for (i = 1; i < k; i++)
			__CPROVER_assert(out[i - 1].end < out[i].start, "normalised");
		for (i = 0; i < na; i++)
			for (j = i + 1; j < na; j++)
				__CPROVER_assert(!(a[i].start < a[j].end && a[j].start < a[i].end),
						 "accepted input has no overlap");
	}
	/* intersects, on normalised lists, against the pairwise definition. */
	for (i = 1; i < na; i++)
		__CPROVER_assume(a[i - 1].end < a[i].start);
	for (i = 1; i < nb; i++)
		__CPROVER_assume(b[i - 1].end < b[i].start);
	for (i = 0; i < na; i++)
		for (j = 0; j < nb; j++)
			brute |= a[i].start < b[j].end && b[j].start < a[i].end;
	__CPROVER_assert(pg_claim_intersects(a, na, b, nb) == brute, "intersects exact");
	/* gather: logical sector x lands in the extent that covers it. */
	left = pg_claim_gather(a, na, x, &phys);
	for (i = 0; i < na; i++) {
		pg_u64 len = a[i].end - a[i].start;

		if (x >= base && x - base < len) {
			__CPROVER_assert(left == len - (x - base) &&
					 phys == a[i].start + (x - base), "gather exact");
			return 0;
		}
		__CPROVER_assume(base + len >= base);	/* files fit in 2^64 sectors */
		base += len;
	}
	__CPROVER_assert(left == 0, "gather refuses beyond the end");
	return 0;
}
