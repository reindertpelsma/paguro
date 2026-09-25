/*
 * pg_msg.h -- the \PaguroPort messages (INTERFACES.md sec. 11.1).
 *
 * Shared by the driver, the user-mode test program and (mirrored in Rust,
 * crates/paguro-win/src/fltmsg.rs) the paguro service. Every message is ONE
 * fixed-size, versioned struct; the driver accepts a buffer only if its
 * length is exactly sizeof(PG_MESSAGE) and every field validates. There is
 * nothing variable-length to parse.
 *
 *   PROTECT       service -> filter   volume GUID, file id (128-bit), deny flags
 *   UNPROTECT     service -> filter   volume GUID, file id
 *   ALLOW_UNLOAD  service -> filter   the one explicit admin request that lets
 *                                     `fltmc unload` succeed
 *   EVENT         filter  -> service  a denied operation: file id, op, process
 *
 * The volume GUID is the mount manager's (\??\Volume{GUID}), as
 * FltGetVolumeGuidName and GetVolumeNameForVolumeMountPoint report it.
 */
#ifndef PG_MSG_H
#define PG_MSG_H

#define PG_PORT_NAME        L"\\PaguroPort"
#define PG_MSG_MAGIC        0x4D464750u /* "PGFM", little-endian */
#define PG_MSG_VERSION      1u

/* Message types. */
#define PG_MSG_PROTECT      1u
#define PG_MSG_UNPROTECT    2u
#define PG_MSG_ALLOW_UNLOAD 3u
#define PG_MSG_EVENT        4u

/* Deny flags (PROTECT). Unknown bits are refused. */
#define PG_DENY_OPEN        0x01u /* IRP_MJ_CREATE, any access */
#define PG_DENY_SETINFO     0x02u /* delete, rename, link, EOF, allocation, VDL */
#define PG_DENY_WRITE       0x04u /* non-paging IRP_MJ_WRITE */
#define PG_DENY_FSCTL       0x08u /* MOVE_FILE, MARK_HANDLE, sparse/zero/compress... */
#define PG_DENY_ALL         0x0Fu

/* EVENT operations. */
#define PG_OP_CREATE        1u
#define PG_OP_SETINFO       2u
#define PG_OP_WRITE         3u
#define PG_OP_FSCTL         4u

/* Most protected files at once (a few images per volume in practice). */
#define PG_MAX_PROTECTED    32u

#pragma pack(push, 8)
typedef struct _PG_MESSAGE {
    unsigned int Magic;          /* PG_MSG_MAGIC */
    unsigned short Version;      /* PG_MSG_VERSION */
    unsigned short Type;         /* PG_MSG_* */
    unsigned char Volume[16];    /* GUID, in memory (Data1..3 little-endian) layout */
    unsigned char FileId[16];    /* FILE_ID_128 */
    unsigned int DenyFlags;      /* PROTECT only; 0 otherwise */
    unsigned int Operation;      /* EVENT only: PG_OP_*; 0 otherwise */
    unsigned int ProcessId;      /* EVENT only; 0 otherwise */
    int Status;                  /* EVENT only: the NTSTATUS returned */
} PG_MESSAGE;
#pragma pack(pop)

#define PG_MESSAGE_SIZE 56u

/* Compile-time layout check, for both compilers that build this header. */
typedef char pg_message_size_check[(sizeof(PG_MESSAGE) == PG_MESSAGE_SIZE) ? 1 : -1];

#endif /* PG_MSG_H */
