/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * paguro range test -- the entire runtime enforcement path (DESIGN.md 4.3).
 *
 * Plain C with no kernel or libc dependencies, so the same file is compiled
 * into the kernel module and into a userspace differential test against the
 * Rust specification in crates/paguro-core/src/range.rs.
 */
#ifndef PG_RANGE_H
#define PG_RANGE_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u8 pg_u8;
typedef u16 pg_u16;
typedef u32 pg_u32;
typedef u64 pg_u64;
typedef size_t pg_size;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t pg_u8;
typedef uint16_t pg_u16;
typedef uint32_t pg_u32;
typedef uint64_t pg_u64;
typedef size_t pg_size;
#endif

/* Half-open [start, end), in 512-byte sectors of the underlying device. */
struct pg_extent {
	pg_u64 start;
	pg_u64 end;
};

/* Sort by start (heapsort: O(n log n) worst case, no recursion). */
void pg_range_sort(struct pg_extent *e, pg_size n);

/*
 * Sort and merge extents in place (touching or overlapping ones coalesce).
 * Returns the new count, or 0 if any extent is empty or overflows -- callers
 * must refuse the table in that case.
 */
pg_size pg_range_normalise(struct pg_extent *e, pg_size n);

/*
 * Does [sector, sector + count) intersect a protected extent? `e` must be
 * normalised. Zero-length and overflowing requests return 1 (refused).
 */
int pg_range_blocks(const struct pg_extent *e, pg_size n, pg_u64 sector,
		    pg_u64 count);

#endif
