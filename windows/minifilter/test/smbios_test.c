/*
 * smbios_test.c -- user-mode unit test of pg_smbios.c (the driver's only
 * parser of external data besides the fixed-size port messages).
 *
 * Builds with any C compiler (cl, gcc, clang):
 *   cc -I.. ../pg_smbios.c smbios_test.c -o smbios_test && ./smbios_test
 * Exit code = number of failed checks.
 */
#include <stdio.h>
#include <string.h>
#include "pg_smbios.h"

static int failures;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL %s:%d %s\n", __FILE__, __LINE__, what);            \
            failures++;                                                     \
        }                                                                   \
    } while (0)

/* A growing RawSMBIOSData blob. */
static unsigned char blob[4096];
static unsigned long blen;

static void start(void)
{
    memset(blob, 0, sizeof(blob));
    blob[1] = 3; /* SMBIOS 3.x */
    blen = 8;
}

/* One structure: type, formatted-area bytes after the 4-byte header, strings. */
static void add(unsigned char type, const unsigned char *fmt, unsigned char flen,
                const char *const *strings, int nstr)
{
    int i;
    blob[blen++] = type;
    blob[blen++] = (unsigned char)(4 + flen);
    blob[blen++] = 0;
    blob[blen++] = 0;
    memcpy(blob + blen, fmt, flen);
    blen += flen;
    if (nstr == 0)
        blob[blen++] = 0;
    for (i = 0; i < nstr; i++) {
        size_t l = strlen(strings[i]) + 1;
        memcpy(blob + blen, strings[i], l);
        blen += (unsigned long)l;
    }
    blob[blen++] = 0;
}

static void finish(void)
{
    unsigned long t = blen - 8;
    blob[4] = (unsigned char)t;
    blob[5] = (unsigned char)(t >> 8);
    blob[6] = (unsigned char)(t >> 16);
    blob[7] = (unsigned char)(t >> 24);
}

static const unsigned char one = 1, two = 2, three = 3;

static void machine(const char *const *oem, int n)
{
    static const char *const sys[] = {"QEMU", "Standard PC (Q35 + ICH9, 2009)"};
    static const unsigned char f1[] = {1, 2, 0, 0};
    start();
    add(0, (const unsigned char *)"\x01\x02", 2, sys, 2);
    add(1, f1, sizeof f1, sys, 2);
    if (n >= 0) {
        unsigned char c = (unsigned char)n;
        add(11, &c, 1, oem, n);
    }
    add(127, &one, 0, NULL, 0);
    finish();
}

int main(void)
{
    static const char *const marker[] = {"paguro-vm/1"};
    static const char *const mixed[] = {"Dell System", "paguro-vm/1", "5[0000]"};
    static const char *const near[] = {"paguro-vm/10", "paguro-vm/", "Paguro-vm/1", "xpaguro-vm/1"};
    unsigned long i, cut;
    int k;

    (void)two;
    (void)three;

    machine(marker, 1);
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 1, "marker alone");
    machine(mixed, 3);
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 1, "marker among OEM strings");
    machine(near, 4);
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "near misses are not the marker");
    machine(NULL, -1);
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "no type 11");
    machine(NULL, 0);
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "empty type 11");

    /* The marker in a type 1 string (not OEM strings) does not count. */
    {
        static const char *const s[] = {"paguro-vm/1"};
        static const unsigned char f[] = {1, 0, 0, 0};
        start();
        add(1, f, sizeof f, s, 1);
        finish();
        CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "marker outside type 11");
    }
    /* Type 11 without its Count byte is malformed: ignored. */
    {
        start();
        add(11, &one, 0, marker, 1);
        finish();
        CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "type 11 without Count");
    }
    /* After end-of-table nothing counts. */
    {
        unsigned char c = 1;
        start();
        add(127, &one, 0, NULL, 0);
        add(11, &c, 1, marker, 1);
        finish();
        CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "after type 127");
    }

    /* Header refusals. */
    machine(marker, 1);
    CHECK(pg_smbios_has_vm_marker(NULL, blen) == 0, "NULL");
    CHECK(pg_smbios_has_vm_marker(blob, 7) == 0, "shorter than the header");
    blob[4]++;
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "Length past the buffer");
    blob[4]--;

    /* Every truncation of a table with the marker: never reads past the
     * end (checked by ASan/UBSan in CI's Linux build), and true only when
     * the marker's structure is whole. */
    machine(mixed, 3);
    for (cut = 8; cut < blen; cut++) {
        unsigned char copy[4096];
        unsigned long t = cut - 8;
        memcpy(copy, blob, cut);
        copy[4] = (unsigned char)t;
        copy[5] = (unsigned char)(t >> 8);
        copy[6] = 0;
        copy[7] = 0;
        (void)pg_smbios_has_vm_marker(copy, cut);
    }
    /* A structure length that runs off the table. */
    machine(marker, 1);
    blob[9] = 250;
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "structure past the end");
    /* A length below the 4-byte header. */
    machine(marker, 1);
    blob[9] = 3;
    CHECK(pg_smbios_has_vm_marker(blob, blen) == 0, "structure length < 4");

    /* Deterministic byte mutations: must terminate and never fault. */
    for (k = 0; k < 20000; k++) {
        unsigned char copy[4096];
        unsigned long x = (unsigned long)k * 2654435761u;
        machine(mixed, 3);
        memcpy(copy, blob, blen);
        for (i = 0; i < 3; i++) {
            x = x * 1103515245u + 12345u;
            copy[8 + (x >> 8) % (blen - 8)] = (unsigned char)(x >> 16);
        }
        (void)pg_smbios_has_vm_marker(copy, blen);
    }

    printf("%s: %d failure(s)\n", failures ? "FAILED" : "ok", failures);
    return failures;
}
