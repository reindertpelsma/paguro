/*
 * pg_smbios.c -- the VM marker in SMBIOS type 11. See pg_smbios.h.
 *
 * Invariant for every function here: all indices are checked against the
 * table's end before the byte is read, and a malformed table is "no marker"
 * (the driver then stays inert, which costs nothing: DESIGN.md sec. 4.4).
 */
#include "pg_smbios.h"

/* Length of the marker, without its NUL. */
#define MARKER_LEN (sizeof(PG_VM_MARKER) - 1u)

/*
 * Does the NUL-terminated string at t[at] (bounded by end) equal the marker?
 * Invariant: reads t[at .. at+MARKER_LEN] only when that is below end.
 */
static int is_marker(const unsigned char *t, unsigned long at, unsigned long end)
{
    unsigned long i;
    if (end - at < MARKER_LEN + 1u)
        return 0;
    for (i = 0; i < MARKER_LEN; i++)
        if (t[at + i] != (unsigned char)PG_VM_MARKER[i])
            return 0;
    return t[at + MARKER_LEN] == 0;
}

/*
 * Walk one structure's string set starting at t[at]; set *next to the
 * first byte after its double NUL. Returns 1 if a string equals the marker
 * and `check` is set; 0 otherwise; -1 if the set runs past end (malformed).
 * Invariant: every read index is < end.
 */
static int walk_strings(const unsigned char *t, unsigned long at, unsigned long end,
                        int check, unsigned long *next)
{
    int found = 0;
    /* An empty set is two NULs. */
    if (at + 1u < end && t[at] == 0 && t[at + 1u] == 0) {
        *next = at + 2u;
        return 0;
    }
    while (at < end) {
        unsigned long s = at;
        while (at < end && t[at] != 0)
            at++;
        if (at >= end)
            return -1;
        if (check && is_marker(t, s, end))
            found = 1;
        at++; /* past this string's NUL */
        if (at < end && t[at] == 0) {
            *next = at + 1u;
            return found;
        }
    }
    return -1;
}

int pg_smbios_has_vm_marker(const unsigned char *raw, unsigned long len)
{
    const unsigned char *t;
    unsigned long tlen, at = 0, n;

    if (raw == 0 || len < 8u || len > PG_SMBIOS_MAX_BLOB)
        return 0;
    tlen = (unsigned long)raw[4] | ((unsigned long)raw[5] << 8) |
           ((unsigned long)raw[6] << 16) | ((unsigned long)raw[7] << 24);
    if (tlen > len - 8u)
        return 0;
    t = raw + 8;
    for (n = 0; n < PG_SMBIOS_MAX_STRUCT && at + 4u <= tlen; n++) {
        unsigned char type = t[at];
        unsigned char flen = t[at + 1u];
        unsigned long next = 0;
        int r;
        if (flen < 4u || at + flen > tlen)
            return 0;
        /* Type 11 must at least carry its Count byte. */
        r = walk_strings(t, at + flen, tlen, type == 11u && flen >= 5u, &next);
        if (r < 0)
            return 0;
        if (r > 0)
            return 1;
        if (type == 127u)
            return 0;
        at = next;
    }
    return 0;
}
