/*
 * pg_smbios.c -- the VM marker in SMBIOS type 11. See pg_smbios.h.
 *
 * Invariant for every function here: all indices are checked against the
 * table's end before the byte is read, and a malformed table is "no marker"
 * (the driver then stays inert, which costs nothing: DESIGN.md sec. 4.4).
 */
#include <stddef.h> /* offsetof: freestanding, also in the WDK */

#include "pg_smbios.h"

/* Length of the marker, without its NUL. */
#define MARKER_LEN (sizeof(PG_VM_MARKER) - 1u)

/* Compile-time check usable from C89/C99 and MSVC (no _Static_assert). */
#define PG_STATIC_ASSERT(cond, name) typedef char pg_static_assert_##name[(cond) ? 1 : -1]

/*
 * Layout-only mirrors of the formats read below: used through offsetof() and
 * sizeof() on the byte buffer, never cast onto it. #pragma pack is understood
 * by MSVC, gcc and clang alike.
 */
#pragma pack(push, 1)
/* RawSMBIOSData (GetSystemFirmwareTable 'RSMB'), header before the table. */
struct pg_rsmb_header {
    unsigned char used20_calling_method;
    unsigned char smbios_major_version;
    unsigned char smbios_minor_version;
    unsigned char dmi_revision;
    unsigned char length[4]; /* u32 little-endian: table bytes that follow */
};
/* SMBIOS structure header (DSP0134 sec. 6.1.2). */
struct pg_smbios_header {
    unsigned char type;
    unsigned char length; /* formatted area, header included */
    unsigned char handle[2];
};
/* Type 11, OEM Strings (DSP0134 sec. 7.12): the header, then Count. */
struct pg_smbios_oem_strings {
    struct pg_smbios_header hdr;
    unsigned char count;
};
#pragma pack(pop)

PG_STATIC_ASSERT(offsetof(struct pg_rsmb_header, length) == 4, rsmb_length_off);
PG_STATIC_ASSERT(sizeof(struct pg_rsmb_header) == 8, rsmb_header_len);
PG_STATIC_ASSERT(offsetof(struct pg_smbios_header, length) == 1, smbios_length_off);
PG_STATIC_ASSERT(sizeof(struct pg_smbios_header) == 4, smbios_header_len);
PG_STATIC_ASSERT(sizeof(struct pg_smbios_oem_strings) == 5, smbios_oem_strings_len);

#define RSMB_LENGTH_OFF   offsetof(struct pg_rsmb_header, length)
#define RSMB_HEADER_LEN   sizeof(struct pg_rsmb_header)
#define SMBIOS_TYPE_OFF   offsetof(struct pg_smbios_header, type)
#define SMBIOS_LENGTH_OFF offsetof(struct pg_smbios_header, length)
#define SMBIOS_HEADER_LEN sizeof(struct pg_smbios_header)
/* Smallest type 11 that carries its Count byte. */
#define SMBIOS_OEM_STRINGS_MIN_LEN sizeof(struct pg_smbios_oem_strings)

/* SMBIOS structure types (DSP0134 sec. 7.12, 7.45). */
#define SMBIOS_TYPE_OEM_STRINGS  11u
#define SMBIOS_TYPE_END_OF_TABLE 127u

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

    if (raw == 0 || len < RSMB_HEADER_LEN || len > PG_SMBIOS_MAX_BLOB)
        return 0;
    tlen = (unsigned long)raw[RSMB_LENGTH_OFF] | ((unsigned long)raw[RSMB_LENGTH_OFF + 1u] << 8) |
           ((unsigned long)raw[RSMB_LENGTH_OFF + 2u] << 16) |
           ((unsigned long)raw[RSMB_LENGTH_OFF + 3u] << 24);
    if (tlen > len - RSMB_HEADER_LEN)
        return 0;
    t = raw + RSMB_HEADER_LEN;
    for (n = 0; n < PG_SMBIOS_MAX_STRUCT && at + SMBIOS_HEADER_LEN <= tlen; n++) {
        unsigned char type = t[at + SMBIOS_TYPE_OFF];
        unsigned char flen = t[at + SMBIOS_LENGTH_OFF];
        unsigned long next = 0;
        int r;
        if (flen < SMBIOS_HEADER_LEN || at + flen > tlen)
            return 0;
        /* Type 11 must at least carry its Count byte. */
        r = walk_strings(t, at + flen, tlen,
                         type == SMBIOS_TYPE_OEM_STRINGS && flen >= SMBIOS_OEM_STRINGS_MIN_LEN, &next);
        if (r < 0)
            return 0;
        if (r > 0)
            return 1;
        if (type == SMBIOS_TYPE_END_OF_TABLE)
            return 0;
        at = next;
    }
    return 0;
}
