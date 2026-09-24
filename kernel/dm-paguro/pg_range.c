// SPDX-License-Identifier: GPL-2.0 OR MIT
#include "pg_range.h"

/* Restore the max-heap property below `root` in e[0..n). */
static void pg_sift(struct pg_extent *e, pg_size root, pg_size n)
{
	for (;;) {
		/* root < n / 2 whenever child < n, so this cannot wrap */
		pg_size child = 2 * root + 1;
		struct pg_extent t;

		if (child >= n)
			return;
		if (child + 1 < n && e[child + 1].start > e[child].start)
			child++;
		if (e[root].start >= e[child].start)
			return;
		t = e[root];
		e[root] = e[child];
		e[child] = t;
		root = child;
	}
}

/* Heapsort: tables reach PG_MAX_EXTENTS, so no quadratic worst case. */
void pg_range_sort(struct pg_extent *e, pg_size n)
{
	pg_size i;

	for (i = n / 2; i-- > 0;)
		pg_sift(e, i, n);
	for (i = n; i-- > 1;) {
		struct pg_extent t = e[0];

		e[0] = e[i];
		e[i] = t;
		pg_sift(e, 0, i);
	}
}

pg_size pg_range_normalise(struct pg_extent *e, pg_size n)
{
	pg_size i, out = 0;

	for (i = 0; i < n; i++)
		if (e[i].end <= e[i].start)
			return 0;
	if (n == 0)
		return 0;
	pg_range_sort(e, n);
	for (i = 1; i < n; i++) {
		if (e[i].start <= e[out].end) {
			if (e[i].end > e[out].end)
				e[out].end = e[i].end;
		} else {
			e[++out] = e[i];
		}
	}
	return out + 1;
}

int pg_range_blocks(const struct pg_extent *e, pg_size n, pg_u64 sector,
		    pg_u64 count)
{
	pg_u64 end;
	pg_size lo = 0, hi = n;

	if (count == 0)
		return 1;
	end = sector + count;
	if (end < sector)
		return 1;
	/* First extent whose end is beyond the request's start. */
	while (lo < hi) {
		pg_size mid = lo + (hi - lo) / 2;

		if (e[mid].end <= sector)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < n && e[lo].start < end;
}
