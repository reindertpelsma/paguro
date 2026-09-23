// SPDX-License-Identifier: GPL-2.0 OR MIT
#include "pg_range.h"

/* Insertion sort: tables are small and this code must be obviously correct. */
static void pg_sort(struct pg_extent *e, pg_size n)
{
	pg_size i, j;

	for (i = 1; i < n; i++) {
		struct pg_extent key = e[i];

		j = i;
		while (j > 0 && e[j - 1].start > key.start) {
			e[j] = e[j - 1];
			j--;
		}
		e[j] = key;
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
	pg_sort(e, n);
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
