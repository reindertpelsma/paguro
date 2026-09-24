// SPDX-License-Identifier: GPL-2.0 OR MIT
#include "pg_claim.h"
#include "pg_ntfs.h"

int pg_claim_normalise(const struct pg_extent *file, pg_size n,
		       struct pg_extent *out, pg_size cap, pg_size *nout)
{
	pg_size i, k = 0;

	if (n > cap)				/* bound: out[] */
		return PG_E_TOO_MANY_EXTENTS;
	for (i = 0; i < n; i++)
		out[i] = file[i];
	pg_range_sort(out, n);
	/* Keeps: out[0..k) sorted, disjoint; out[k - 1] ends last. */
	for (i = 0; i < n; i++) {
		if (out[i].start >= out[i].end)
			return PG_E_SELF_OVERLAP;
		if (k > 0 && out[i].start < out[k - 1].end)
			return PG_E_SELF_OVERLAP;
		if (k > 0 && out[i].start == out[k - 1].end)
			out[k - 1].end = out[i].end;
		else
			out[k++] = out[i];
	}
	*nout = k;
	return 0;
}

int pg_claim_intersects(const struct pg_extent *a, pg_size na,
			const struct pg_extent *b, pg_size nb)
{
	pg_size i = 0, j = 0;

	/* Merge walk: advance whichever extent ends first. */
	while (i < na && j < nb) {
		if (a[i].start < b[j].end && b[j].start < a[i].end)
			return 1;
		if (a[i].end <= b[j].end)
			i++;
		else
			j++;
	}
	return 0;
}

int pg_claim_grows(const struct pg_extent *old, pg_size nold,
		   const struct pg_extent *new, pg_size nnew)
{
	pg_size i;

	if (nold == 0 || nnew < nold)
		return 0;
	for (i = 0; i + 1 < nold; i++)
		if (new[i].start != old[i].start || new[i].end != old[i].end)
			return 0;
	return new[i].start == old[i].start && new[i].end >= old[i].end;
}

pg_size pg_claim_coalesce(struct pg_extent *e, pg_size n)
{
	pg_size i, k = 0;

	for (i = 0; i < n; i++) {
		if (e[i].start >= e[i].end)
			return 0;
		if (k > 0 && e[k - 1].end == e[i].start)
			e[k - 1].end = e[i].end;
		else
			e[k++] = e[i];
	}
	return k;
}

pg_u64 pg_claim_gather(const struct pg_extent *file, pg_size n, pg_u64 lsec,
		       pg_u64 *phys)
{
	pg_u64 base = 0, len;
	pg_size i;

	/* Keeps: base <= lsec (base only grows past extents lsec is beyond). */
	for (i = 0; i < n; i++) {
		len = file[i].end - file[i].start;
		if (lsec - base < len) {
			*phys = file[i].start + (lsec - base);
			return len - (lsec - base);
		}
		base += len;
	}
	return 0;
}
