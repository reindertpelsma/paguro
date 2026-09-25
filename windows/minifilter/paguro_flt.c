/*
 * paguro_flt.c -- the paguro minifilter (DESIGN.md sec. 4.4, INTERFACES.md
 * sec. 11.1). Quality of experience, not correctness: the Linux module
 * refuses the image's extents whether or not this driver runs. What this
 * driver adds is that Windows, inside the paguro VM, gets a clean refusal
 * (STATUS_ACCESS_DENIED at the filesystem) instead of EIO from the disk.
 *
 * Shape, deliberately small:
 *  - ALL policy is in user mode. The driver enforces one table of
 *    (volume GUID, 128-bit file id) -> deny flags, pushed by the paguro
 *    service over \PaguroPort (admin-only, one connection).
 *  - The service's own process is exempt; everything else -- other
 *    processes, the SMB server, the kernel's non-paging requests -- is refused.
 *  - The only inputs parsed are the fixed-size PG_MESSAGE (pg_msg.h) and,
 *    once at DriverEntry, the SMBIOS table (pg_smbios.c, unit-tested).
 *  - On a native boot (no `paguro-vm/1` OEM string) it registers NOTHING and
 *    is an ordinary unloadable legacy driver.
 *  - In the VM it cannot be unloaded while running (FLTFL_REGISTRATION_DO_
 *    NOT_SUPPORT_SERVICE_STOP: removal is disable + reboot, DESIGN.md sec.
 *    6b) and refuses detach (STATUS_FLT_DO_NOT_DETACH) until the service
 *    sends ALLOW_UNLOAD -- the one explicit admin request.
 *
 * Locking: g_Lock (push lock) guards g_Table, g_Generation and g_Service.
 * No lock is held across a call into the filesystem or FltSendMessage.
 */
#include <fltKernel.h>
#include "pg_msg.h"
#include "pg_smbios.h"

#define PG_TAG 'fgaP'
#define RSMB 0x52534D42u /* 'RSMB' */

typedef struct _PG_ENTRY {
    BOOLEAN InUse;
    GUID Volume;
    FILE_ID_128 FileId;
    ULONG Deny;
} PG_ENTRY;

/* Per NTFS volume: its mount-manager GUID, filled once it is known. */
typedef struct _PG_INSTANCE_CTX {
    volatile LONG HaveGuid;
    GUID Volume;
} PG_INSTANCE_CTX;

/* Per stream: the deny flags computed for g_Generation (a cache). */
typedef struct _PG_STREAM_CTX {
    ULONG Generation;
    ULONG Deny;
} PG_STREAM_CTX;

static PFLT_FILTER g_Filter;
static PFLT_PORT g_ServerPort;
static PFLT_PORT g_ClientPort;
static PEPROCESS g_Service;
static EX_PUSH_LOCK g_Lock;
static PG_ENTRY g_Table[PG_MAX_PROTECTED];
static ULONG g_Count;
static volatile LONG g_Generation = 1;
static volatile LONG g_AllowUnload;

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD PgInertUnload;

/* ---- the table ------------------------------------------------------ */

/*
 * Deny flags for (volume, id), and the generation they belong to.
 * Invariant: table and generation are read under one shared hold, so a
 * cached result is tagged with the generation it was computed from.
 */
static ULONG PgLookup(const GUID *Volume, const FILE_ID_128 *Id, ULONG *Generation)
{
    ULONG i, deny = 0;
    FltAcquirePushLockShared(&g_Lock);
    *Generation = (ULONG)g_Generation;
    for (i = 0; i < PG_MAX_PROTECTED; i++) {
        if (g_Table[i].InUse && IsEqualGUID(&g_Table[i].Volume, Volume) &&
            RtlEqualMemory(&g_Table[i].FileId, Id, sizeof(*Id))) {
            deny = g_Table[i].Deny;
            break;
        }
    }
    FltReleasePushLock(&g_Lock);
    return deny;
}

/*
 * Add, change or remove one entry. Invariant: every change bumps the
 * generation inside the exclusive hold, which invalidates every stream
 * context computed before it.
 */
static NTSTATUS PgUpdate(const GUID *Volume, const FILE_ID_128 *Id, ULONG Deny)
{
    ULONG i, freeSlot = PG_MAX_PROTECTED;
    NTSTATUS status = Deny ? STATUS_INSUFFICIENT_RESOURCES : STATUS_NOT_FOUND;
    FltAcquirePushLockExclusive(&g_Lock);
    for (i = 0; i < PG_MAX_PROTECTED; i++) {
        if (!g_Table[i].InUse) {
            if (freeSlot == PG_MAX_PROTECTED)
                freeSlot = i;
        } else if (IsEqualGUID(&g_Table[i].Volume, Volume) &&
                   RtlEqualMemory(&g_Table[i].FileId, Id, sizeof(*Id))) {
            if (Deny) {
                g_Table[i].Deny = Deny;
            } else {
                RtlZeroMemory(&g_Table[i], sizeof(g_Table[i]));
                g_Count--;
            }
            status = STATUS_SUCCESS;
            break;
        }
    }
    if (status != STATUS_SUCCESS && Deny && freeSlot < PG_MAX_PROTECTED) {
        g_Table[freeSlot].InUse = TRUE;
        g_Table[freeSlot].Volume = *Volume;
        g_Table[freeSlot].FileId = *Id;
        g_Table[freeSlot].Deny = Deny;
        g_Count++;
        status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status))
        InterlockedIncrement(&g_Generation);
    FltReleasePushLock(&g_Lock);
    return status;
}

/* Is the current process the connected service? Invariant: compares the
 * pointer only; never dereferences it. */
static BOOLEAN PgIsService(VOID)
{
    BOOLEAN yes;
    FltAcquirePushLockShared(&g_Lock);
    yes = (g_Service != NULL && PsGetCurrentProcess() == g_Service);
    FltReleasePushLock(&g_Lock);
    return yes;
}

/* ---- identifying a file --------------------------------------------- */

/*
 * The instance's volume GUID. Invariant: fills the context at most once
 * with the same value, at PASSIVE_LEVEL; FALSE until the mount manager
 * knows the volume. Parses only the fixed "\??\Volume{...}" form.
 */
static BOOLEAN PgVolumeGuid(PCFLT_RELATED_OBJECTS Obj, PG_INSTANCE_CTX *Ctx)
{
    WCHAR buf[64];
    UNICODE_STRING name, g;
    GUID guid;
    if (Ctx->HaveGuid)
        return TRUE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;
    RtlInitEmptyUnicodeString(&name, buf, sizeof(buf));
    if (!NT_SUCCESS(FltGetVolumeGuidName(Obj->Volume, &name, NULL)))
        return FALSE;
    /* \??\Volume{8-4-4-4-12}: 48 characters, the GUID from offset 10. */
    if (name.Length != 48 * sizeof(WCHAR))
        return FALSE;
    g.Buffer = buf + 10;
    g.Length = g.MaximumLength = 38 * sizeof(WCHAR);
    if (!NT_SUCCESS(RtlGUIDFromString(&g, &guid)))
        return FALSE;
    Ctx->Volume = guid;
    InterlockedExchange(&Ctx->HaveGuid, 1);
    return TRUE;
}

/*
 * The deny flags for FileObject, cached per stream for the current table
 * generation. Invariant: 0 (allow) whenever anything is unknown -- no
 * context, no GUID, not PASSIVE_LEVEL, the query failed -- because this
 * driver is never the correctness boundary.
 */
static ULONG PgDenyFor(PCFLT_RELATED_OBJECTS Obj, PFILE_OBJECT FileObject)
{
    PG_INSTANCE_CTX *ictx = NULL;
    PG_STREAM_CTX *sctx = NULL;
    FILE_ID_INFORMATION info;
    ULONG deny = 0, gen = 0;
    BOOLEAN haveGuid;

    if (g_Count == 0 || FileObject == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return 0;
    if (NT_SUCCESS(FltGetStreamContext(Obj->Instance, FileObject, (PFLT_CONTEXT *)&sctx))) {
        if (sctx->Generation == (ULONG)g_Generation) {
            deny = sctx->Deny;
            FltReleaseContext(sctx);
            return deny;
        }
        FltReleaseContext(sctx);
        sctx = NULL;
    }
    if (!NT_SUCCESS(FltGetInstanceContext(Obj->Instance, (PFLT_CONTEXT *)&ictx)))
        return 0;
    haveGuid = PgVolumeGuid(Obj, ictx);
    if (haveGuid && NT_SUCCESS(FltQueryInformationFile(Obj->Instance, FileObject, &info, sizeof(info),
                                                       FileIdInformation, NULL)))
        deny = PgLookup(&ictx->Volume, &info.FileId, &gen);
    FltReleaseContext(ictx);
    if (gen == 0)
        return deny;
    /* Cache; a racing setter or a newer generation simply wins. */
    if (NT_SUCCESS(FltAllocateContext(g_Filter, FLT_STREAM_CONTEXT, sizeof(PG_STREAM_CTX), NonPagedPoolNx,
                                      (PFLT_CONTEXT *)&sctx))) {
        sctx->Generation = gen;
        sctx->Deny = deny;
        (VOID)FltSetStreamContext(Obj->Instance, FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, sctx, NULL);
        FltReleaseContext(sctx);
    }
    return deny;
}

/* ---- reporting -------------------------------------------------------- */

/*
 * Tell the service about a refusal (best effort). Invariant: never blocks
 * (zero timeout), holds no lock, runs only at PASSIVE_LEVEL.
 */
static VOID PgReport(PCFLT_RELATED_OBJECTS Obj, PFILE_OBJECT FileObject, ULONG Op, NTSTATUS Status)
{
    PG_MESSAGE m;
    FILE_ID_INFORMATION info;
    LARGE_INTEGER timeout;
    if (g_ClientPort == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    RtlZeroMemory(&m, sizeof(m));
    m.Magic = PG_MSG_MAGIC;
    m.Version = PG_MSG_VERSION;
    m.Type = PG_MSG_EVENT;
    if (FileObject && NT_SUCCESS(FltQueryInformationFile(Obj->Instance, FileObject, &info, sizeof(info),
                                                         FileIdInformation, NULL)))
        RtlCopyMemory(m.FileId, &info.FileId, sizeof(m.FileId));
    m.Operation = Op;
    m.ProcessId = HandleToULong(PsGetCurrentProcessId());
    m.Status = Status;
    timeout.QuadPart = 0;
    (VOID)FltSendMessage(g_Filter, &g_ClientPort, &m, sizeof(m), NULL, NULL, &timeout);
}

/* ---- operation callbacks --------------------------------------------- */

/*
 * IRP_MJ_CREATE, after the filesystem opened the file (only then is its id
 * known). Invariant: a successful open of a PG_DENY_OPEN file by anyone
 * but the service is cancelled and fails with STATUS_ACCESS_DENIED.
 */
static FLT_POSTOP_CALLBACK_STATUS PgPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Obj,
                                               PVOID Ctx, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Ctx);
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) || !NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Status == STATUS_REPARSE || g_Count == 0 ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE) || PgIsService())
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (PgDenyFor(Obj, Obj->FileObject) & PG_DENY_OPEN) {
        PgReport(Obj, Obj->FileObject, PG_OP_CREATE, STATUS_ACCESS_DENIED);
        FltCancelFileOpen(Obj->Instance, Obj->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* Complete an operation with STATUS_ACCESS_DENIED and report it.
 * Invariant: only called from a pre-operation callback. */
static FLT_PREOP_CALLBACK_STATUS PgRefuse(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Obj,
                                         PFILE_OBJECT Target, ULONG Op)
{
    PgReport(Obj, Target, Op, STATUS_ACCESS_DENIED);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/*
 * IRP_MJ_SET_INFORMATION. Invariant: delete, rename, hard link, end of
 * file, allocation and valid data length on a PG_DENY_SETINFO file are
 * refused for everyone but the service; the lazy writer's advance-only
 * EOF updates pass (they describe data already written).
 */
static FLT_PREOP_CALLBACK_STATUS PgPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Obj, PVOID *Ctx)
{
    FILE_INFORMATION_CLASS c = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    *Ctx = NULL;
    switch ((int)c) {
    case FileEndOfFileInformation:
        if (Data->Iopb->Parameters.SetFileInformation.AdvanceOnly)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        /* fall through */
    case FileDispositionInformation:
    case FileDispositionInformationEx:
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileLinkInformation:
    case FileLinkInformationEx:
    case FileAllocationInformation:
    case FileValidDataLengthInformation:
    case FileShortNameInformation:
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (g_Count == 0 || PgIsService() || !(PgDenyFor(Obj, Obj->FileObject) & PG_DENY_SETINFO))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    return PgRefuse(Data, Obj, Obj->FileObject, PG_OP_SETINFO);
}

/*
 * IRP_MJ_WRITE (paging I/O is not registered). Invariant: a write through
 * a handle that predates the protection is refused for everyone but the
 * service; new handles never get this far (PgPostCreate).
 */
static FLT_PREOP_CALLBACK_STATUS PgPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Obj, PVOID *Ctx)
{
    *Ctx = NULL;
    if (g_Count == 0 || PgIsService() || !(PgDenyFor(Obj, Obj->FileObject) & PG_DENY_WRITE))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    return PgRefuse(Data, Obj, Obj->FileObject, PG_OP_WRITE);
}

/*
 * FSCTL_MOVE_FILE names its target by handle in a fixed-size input
 * (MOVE_FILE_DATA, or MOVE_FILE_DATA32 from a 32-bit process). Returns the
 * referenced file object, or NULL. Invariant: reads only the captured
 * system buffer, and only when it is at least the struct's size.
 */
static PFILE_OBJECT PgMoveTarget(PFLT_CALLBACK_DATA Data)
{
    PVOID in = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
    ULONG len = Data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;
    HANDLE h;
    PFILE_OBJECT fo = NULL;
    if (in == NULL)
        return NULL;
#if defined(_WIN64)
    if (FltIs32bitProcess(Data) && len >= sizeof(MOVE_FILE_DATA32))
        h = (HANDLE)(ULONG_PTR)((MOVE_FILE_DATA32 *)in)->FileHandle;
    else
#endif
    if (len >= sizeof(MOVE_FILE_DATA))
        h = ((MOVE_FILE_DATA *)in)->FileHandle;
    else
        return NULL;
    if (!NT_SUCCESS(ObReferenceObjectByHandle(h, 0, *IoFileObjectType, Data->RequestorMode, (PVOID *)&fo, NULL)))
        return NULL;
    return fo;
}

/* Is this FSCTL one that changes the target file's clusters or protection?
 * Invariant: a fixed list; unknown codes pass. */
static BOOLEAN PgModifyingFsctl(ULONG Code)
{
    switch (Code) {
    case FSCTL_MARK_HANDLE:
    case FSCTL_SET_SPARSE:
    case FSCTL_SET_ZERO_DATA:
    case FSCTL_SET_COMPRESSION:
    case FSCTL_SET_REPARSE_POINT:
    case FSCTL_DELETE_REPARSE_POINT:
    case FSCTL_SET_INTEGRITY_INFORMATION:
    case FSCTL_FILE_LEVEL_TRIM:
    case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
    case FSCTL_SET_ZERO_ON_DEALLOCATION:
    case FSCTL_SET_ENCRYPTION:
        return TRUE;
    default:
        return FALSE;
    }
}

/*
 * IRP_MJ_FILE_SYSTEM_CONTROL. Invariant: moving a PG_DENY_FSCTL file's
 * clusters (FSCTL_MOVE_FILE, what defragmenters use) or changing its
 * allocation, sparseness, compression, reparse data or cluster marking is
 * refused for everyone but the service.
 */
static FLT_PREOP_CALLBACK_STATUS PgPreFsctl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Obj, PVOID *Ctx)
{
    ULONG code = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
    PFILE_OBJECT target;
    ULONG deny;
    *Ctx = NULL;
    if (g_Count == 0 || Data->Iopb->MinorFunction != IRP_MN_USER_FS_REQUEST ||
        (code != FSCTL_MOVE_FILE && !PgModifyingFsctl(code)) || PgIsService())
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (code == FSCTL_MOVE_FILE) {
        target = PgMoveTarget(Data);
        if (target == NULL)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        deny = PgDenyFor(Obj, target);
        if (deny & PG_DENY_FSCTL) {
            PgRefuse(Data, Obj, target, PG_OP_FSCTL);
            ObDereferenceObject(target);
            return FLT_PREOP_COMPLETE;
        }
        ObDereferenceObject(target);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!(PgDenyFor(Obj, Obj->FileObject) & PG_DENY_FSCTL))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    return PgRefuse(Data, Obj, Obj->FileObject, PG_OP_FSCTL);
}

/* ---- instances --------------------------------------------------------- */

/* Attach to local NTFS volumes only. Invariant: every instance gets a
 * context (GUID filled now or on first use). */
static NTSTATUS PgInstanceSetup(PCFLT_RELATED_OBJECTS Obj, FLT_INSTANCE_SETUP_FLAGS Flags,
                                DEVICE_TYPE DevType, FLT_FILESYSTEM_TYPE FsType)
{
    PG_INSTANCE_CTX *ctx;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Flags);
    if (FsType != FLT_FSTYPE_NTFS || DevType != FILE_DEVICE_DISK_FILE_SYSTEM)
        return STATUS_FLT_DO_NOT_ATTACH;
    status = FltAllocateContext(g_Filter, FLT_INSTANCE_CONTEXT, sizeof(*ctx), NonPagedPoolNx, (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status))
        return STATUS_FLT_DO_NOT_ATTACH;
    RtlZeroMemory(ctx, sizeof(*ctx));
    (VOID)PgVolumeGuid(Obj, ctx);
    status = FltSetInstanceContext(Obj->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
    FltReleaseContext(ctx);
    return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

/* A manual detach (`fltmc detach`) is refused until ALLOW_UNLOAD.
 * Invariant: dismount teardown is not ours to refuse and is not routed here. */
static NTSTATUS PgInstanceQueryTeardown(PCFLT_RELATED_OBJECTS Obj, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Obj);
    UNREFERENCED_PARAMETER(Flags);
    return g_AllowUnload ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_DETACH;
}

/* ---- the port ------------------------------------------------------------ */

/*
 * The service connects. Invariant: at most one client (MaxConnections 1),
 * and only an administrator or SYSTEM can open the port (its SD); that
 * process becomes the exempt one, referenced until it disconnects.
 */
static NTSTATUS PgConnect(PFLT_PORT Client, PVOID Cookie, PVOID Ctx, ULONG Size, PVOID *ConnCookie)
{
    PEPROCESS p = PsGetCurrentProcess();
    UNREFERENCED_PARAMETER(Cookie);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Size);
    *ConnCookie = NULL;
    ObReferenceObject(p);
    FltAcquirePushLockExclusive(&g_Lock);
    g_ClientPort = Client;
    g_Service = p;
    InterlockedIncrement(&g_Generation);
    FltReleasePushLock(&g_Lock);
    return STATUS_SUCCESS;
}

/* The service went away. Invariant: the table survives (the service
 * re-sends it on reconnect); only the exemption ends. */
static VOID PgDisconnect(PVOID ConnCookie)
{
    PEPROCESS p;
    UNREFERENCED_PARAMETER(ConnCookie);
    FltAcquirePushLockExclusive(&g_Lock);
    p = g_Service;
    g_Service = NULL;
    FltReleasePushLock(&g_Lock);
    FltCloseClientPort(g_Filter, &g_ClientPort);
    if (p)
        ObDereferenceObject(p);
}

/*
 * One message from the service. Invariant: the user buffer is copied once
 * under an exception handler, then validated whole -- exact size, magic,
 * version, known type, known flags, every unused field zero -- before any
 * field is acted on.
 */
static NTSTATUS PgMessage(PVOID ConnCookie, PVOID In, ULONG InLen, PVOID Out, ULONG OutLen, PULONG Returned)
{
    PG_MESSAGE m;
    static const GUID zero = {0};
    UNREFERENCED_PARAMETER(ConnCookie);
    UNREFERENCED_PARAMETER(Out);
    UNREFERENCED_PARAMETER(OutLen);
    *Returned = 0;
    if (In == NULL || InLen != sizeof(m))
        return STATUS_INVALID_PARAMETER;
    __try {
        if (ExGetPreviousMode() == UserMode)
            ProbeForRead(In, sizeof(m), 1);
        RtlCopyMemory(&m, In, sizeof(m));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (m.Magic != PG_MSG_MAGIC || m.Version != PG_MSG_VERSION || m.Operation != 0 || m.ProcessId != 0 ||
        m.Status != 0)
        return STATUS_INVALID_PARAMETER;
    switch (m.Type) {
    case PG_MSG_PROTECT:
        if (m.DenyFlags == 0 || (m.DenyFlags & ~PG_DENY_ALL) || RtlEqualMemory(m.Volume, &zero, 16))
            return STATUS_INVALID_PARAMETER;
        return PgUpdate((const GUID *)m.Volume, (const FILE_ID_128 *)m.FileId, m.DenyFlags);
    case PG_MSG_UNPROTECT:
        if (m.DenyFlags != 0 || RtlEqualMemory(m.Volume, &zero, 16))
            return STATUS_INVALID_PARAMETER;
        return PgUpdate((const GUID *)m.Volume, (const FILE_ID_128 *)m.FileId, 0);
    case PG_MSG_ALLOW_UNLOAD:
        if (m.DenyFlags != 0)
            return STATUS_INVALID_PARAMETER;
        InterlockedExchange(&g_AllowUnload, 1);
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ---- load and unload -------------------------------------------------------- */

/*
 * Unload of the active filter. Invariant: refused (STATUS_FLT_DO_NOT_DETACH)
 * until ALLOW_UNLOAD; mandatory unloads never arrive (DO_NOT_SUPPORT_
 * SERVICE_STOP). Once allowed, releases everything DriverEntry created.
 */
static NTSTATUS PgFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (!g_AllowUnload)
        return STATUS_FLT_DO_NOT_DETACH;
    FltCloseCommunicationPort(g_ServerPort);
    FltUnregisterFilter(g_Filter);
    if (g_Service) {
        ObDereferenceObject(g_Service);
        g_Service = NULL;
    }
    return STATUS_SUCCESS;
}

/* Unload of the inert driver. Invariant: it registered nothing, so there
 * is nothing to release. */
static VOID PgInertUnload(PDRIVER_OBJECT Driver)
{
    UNREFERENCED_PARAMETER(Driver);
}

/*
 * Is this the paguro VM? The SMBIOS type 11 marker (pg_smbios.c). Invariant:
 * any failure -- no table, allocation, size -- means "native".
 */
static BOOLEAN PgInVm(VOID)
{
    ULONG size = 0, got = 0;
    PUCHAR buf;
    BOOLEAN vm = FALSE;
    (VOID)ExGetSystemFirmwareTable(RSMB, 0, NULL, 0, &size);
    if (size == 0 || size > PG_SMBIOS_MAX_BLOB)
        return FALSE;
    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, size, PG_TAG);
    if (buf == NULL)
        return FALSE;
    if (NT_SUCCESS(ExGetSystemFirmwareTable(RSMB, 0, buf, size, &got)) && got <= size)
        vm = pg_smbios_has_vm_marker(buf, got) ? TRUE : FALSE;
    ExFreePoolWithTag(buf, PG_TAG);
    return vm;
}

#if DBG
/*
 * TEST BUILDS ONLY (compiled out of release): Parameters\ForceVmMode = 1
 * makes a runner without the marker take the active path. Invariant: reads
 * one REG_DWORD of exactly 4 bytes; anything else is "not forced".
 */
static BOOLEAN PgForcedVm(PUNICODE_STRING RegistryPath)
{
    OBJECT_ATTRIBUTES oa;
    HANDLE svc = NULL, params = NULL;
    UNICODE_STRING sub = RTL_CONSTANT_STRING(L"Parameters"), val = RTL_CONSTANT_STRING(L"ForceVmMode");
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    ULONG len = 0;
    BOOLEAN forced = FALSE;
    InitializeObjectAttributes(&oa, RegistryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&svc, KEY_READ, &oa)))
        return FALSE;
    InitializeObjectAttributes(&oa, &sub, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, svc, NULL);
    if (NT_SUCCESS(ZwOpenKey(&params, KEY_READ, &oa))) {
        if (NT_SUCCESS(ZwQueryValueKey(params, &val, KeyValuePartialInformation, kv, sizeof(buf), &len)) &&
            kv->Type == REG_DWORD && kv->DataLength == sizeof(ULONG))
            forced = (*(ULONG UNALIGNED *)kv->Data == 1);
        ZwClose(params);
    }
    ZwClose(svc);
    return forced;
}
#endif

static const FLT_OPERATION_REGISTRATION g_Ops[] = {
    {IRP_MJ_CREATE, 0, NULL, PgPostCreate},
    {IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PgPreSetInfo, NULL},
    {IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PgPreWrite, NULL},
    {IRP_MJ_FILE_SYSTEM_CONTROL, 0, PgPreFsctl, NULL},
    {IRP_MJ_OPERATION_END}};

static const FLT_CONTEXT_REGISTRATION g_Contexts[] = {
    {FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(PG_INSTANCE_CTX), PG_TAG},
    {FLT_STREAM_CONTEXT, 0, NULL, sizeof(PG_STREAM_CTX), PG_TAG},
    {FLT_CONTEXT_END}};

static const FLT_REGISTRATION g_Registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    g_Contexts,
    g_Ops,
    PgFilterUnload,
    PgInstanceSetup,
    PgInstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL};

/*
 * Invariant: returns with either nothing registered (native: inert,
 * unloadable) or the filter registered, the port open and filtering
 * started (the VM) -- never a half-registered state.
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING port = RTL_CONSTANT_STRING(PG_PORT_NAME);
    BOOLEAN vm = PgInVm();
#if DBG
    if (!vm)
        vm = PgForcedVm(RegistryPath);
#else
    UNREFERENCED_PARAMETER(RegistryPath);
#endif
    if (!vm) {
        Driver->DriverUnload = PgInertUnload;
        return STATUS_SUCCESS;
    }
    FltInitializePushLock(&g_Lock);
    status = FltRegisterFilter(Driver, &g_Registration, &g_Filter);
    if (!NT_SUCCESS(status))
        return status;
    /* Administrators and SYSTEM only (FltBuildDefaultSecurityDescriptor). */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &port, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(g_Filter, &g_ServerPort, &oa, NULL, PgConnect, PgDisconnect,
                                            PgMessage, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g_Filter);
        if (!NT_SUCCESS(status))
            FltCloseCommunicationPort(g_ServerPort);
    }
    if (!NT_SUCCESS(status))
        FltUnregisterFilter(g_Filter);
    return status;
}
