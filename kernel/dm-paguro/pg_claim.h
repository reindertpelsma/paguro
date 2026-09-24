/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * paguro claim checks -- what the module does with a file's extents once
 * pg_ntfs has derived them (INTERFACES.md 10.2). Plain C, no dependencies;
 * the Rust specification is the claims section of paguro-core's ntfs.rs.
 *
 * "File order" extents are what pg_ntfs_extents() returns: the file's
 * sectors in logical order, physically adjacent pieces coalesced.
 * "Normalised" extents are sorted, disjoint and non-touching (pg_range.h).
 */
#ifndef PG_CLAIM_H
#define PG_CLAIM_H

#include "pg_range.h"

/*
 * Sorted, merged copy of file-order extents into out[0..*nout) for the range
 * test. Returns 0, PG_E_TOO_MANY_EXTENTS if cap < n, or PG_E_SELF_OVERLAP if
 * any extent is empty or two overlap (a runlist naming a cluster twice).
 */
int pg_claim_normalise(const struct pg_extent *file, pg_size n,
		       struct pg_extent *out, pg_size cap, pg_size *nout);

/* Do two normalised lists share a sector? Claims may never intersect. */
int pg_claim_intersects(const struct pg_extent *a, pg_size na,
			const struct pg_extent *b, pg_size nb);

/*
 * Append-only growth (PG_GROW): every sector of the old file maps where it
 * did. For coalesced file-order extents: all old extents but the last are
 * unchanged, the last starts where it did and did not shrink.
 */
int pg_claim_grows(const struct pg_extent *old, pg_size nold,
		   const struct pg_extent *new, pg_size nnew);

/*
 * Coalesce file-order extents in place, as pg_ntfs_extents() does (for
 * comparing a FIEMAP claim). Returns the new count, 0 if any is empty.
 */
pg_size pg_claim_coalesce(struct pg_extent *e, pg_size n);

/*
 * View A's translation: logical sector `lsec` of the gathered file ->
 * *phys, returning the sectors left in that extent (0 beyond the end).
 */
pg_u64 pg_claim_gather(const struct pg_extent *file, pg_size n, pg_u64 lsec,
		       pg_u64 *phys);

#endif
