/*
 * pgflt_test.c -- user-mode test of every deny path of paguro_flt.sys.
 *
 *   pgflt_test inert          the driver is loaded without the VM marker:
 *                             \PaguroPort must not exist
 *   pgflt_test active DIR     full test (driver loaded in VM mode: the marker,
 *                             or a DBG build with Parameters\ForceVmMode=1);
 *                             DIR is a directory on an NTFS volume
 *   pgflt_test child PATH     (internal) the non-service process
 *
 * This process plays the paguro service (it holds the port, so it is the
 * exempt process); a child process plays "everything else". The child opens
 * a handle BEFORE the file is protected, so the write, set-information and
 * FSCTL paths are reached through that handle; new opens exercise the create
 * path. After UNPROTECT the same operations must succeed (control). Last, the
 * unload refusal and ALLOW_UNLOAD. Exit code = number of failed checks.
 *
 * Build: cl /W4 /WX pgflt_test.c /I.. fltlib.lib
 *        x86_64-w64-mingw32-gcc -Wall -Wextra -Werror -I.. pgflt_test.c -lfltlib
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <fltuser.h>
#include <stdio.h>
#include <string.h>
#include "pg_msg.h"

static int failures;

static void check(int ok, const char *what, DWORD detail)
{
    printf("%s %s (%lu)\n", ok ? "ok  " : "FAIL", what, (unsigned long)detail);
    fflush(stdout);
    if (!ok)
        failures++;
}

/* A Win32 call refused the way the filter refuses: ERROR_ACCESS_DENIED. */
static void denied(BOOL r, const char *what)
{
    DWORD e = r ? 0 : GetLastError();
    check(!r && e == ERROR_ACCESS_DENIED, what, e);
}

static void allowed(BOOL r, const char *what)
{
    check(r != 0, what, r ? 0 : GetLastError());
}

/* ---- the child: everything that is not the service ------------------- */

static HANDLE open_volume(const wchar_t *path)
{
    wchar_t root[MAX_PATH], vol[MAX_PATH];
    if (!GetVolumePathNameW(path, root, MAX_PATH))
        return INVALID_HANDLE_VALUE;
    /* \\.\C: form for FSCTLs on the volume. */
    swprintf(vol, MAX_PATH, L"\\\\.\\%c:", root[0]);
    return CreateFileW(vol, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
}

/* Probes through the pre-existing handle h and by path. expect_denied: the
 * file is protected. */
static void probes(HANDLE h, const wchar_t *path, int expect_denied)
{
    void (*want)(BOOL, const char *) = expect_denied ? denied : allowed;
    char buf[4096] = {0};
    DWORD n = 0;
    FILE_END_OF_FILE_INFO eof;
    FILE_ALLOCATION_INFO alloc;
    FILE_ZERO_DATA_INFORMATION zero;
    HANDLE v, h2;
    FILE_ID_INFO id;
    FILE_ID_DESCRIPTOR d;
    MOVE_FILE_DATA mv;
    MARK_HANDLE_INFO mh;
    BOOL r;

    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    want(WriteFile(h, buf, sizeof(buf), &n, NULL), "write through an old handle (IRP_MJ_WRITE)");
    eof.EndOfFile.QuadPart = 8192;
    want(SetFileInformationByHandle(h, FileEndOfFileInfo, &eof, sizeof(eof)), "set end of file (SET_INFORMATION)");
    alloc.AllocationSize.QuadPart = 1 << 22;
    want(SetFileInformationByHandle(h, FileAllocationInfo, &alloc, sizeof(alloc)), "set allocation (SET_INFORMATION)");
    want(DeviceIoControl(h, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &n, NULL), "FSCTL_SET_SPARSE");
    zero.FileOffset.QuadPart = 0;
    zero.BeyondFinalZero.QuadPart = 4096;
    want(DeviceIoControl(h, FSCTL_SET_ZERO_DATA, &zero, sizeof(zero), NULL, 0, &n, NULL), "FSCTL_SET_ZERO_DATA");

    v = open_volume(path);
    check(v != INVALID_HANDLE_VALUE, "open the volume", GetLastError());
    if (v != INVALID_HANDLE_VALUE) {
        memset(&mh, 0, sizeof(mh));
        mh.HandleInfo = MARK_HANDLE_PROTECT_CLUSTERS;
        mh.VolumeHandle = v;
        want(DeviceIoControl(h, FSCTL_MARK_HANDLE, &mh, sizeof(mh), NULL, 0, &n, NULL), "FSCTL_MARK_HANDLE");
        memset(&mv, 0, sizeof(mv));
        mv.FileHandle = h;
        mv.StartingVcn.QuadPart = 0;
        mv.StartingLcn.QuadPart = 0; /* LCN 0 is never free: fails differently when allowed */
        mv.ClusterCount = 1;
        r = DeviceIoControl(v, FSCTL_MOVE_FILE, &mv, sizeof(mv), NULL, 0, &n, NULL);
        if (expect_denied)
            denied(r, "FSCTL_MOVE_FILE on the volume, naming the file (defrag)");
        else
            check(r || GetLastError() != ERROR_ACCESS_DENIED, "FSCTL_MOVE_FILE reaches NTFS", r ? 0 : GetLastError());
        if (GetFileInformationByHandleEx(h, FileIdInfo, &id, sizeof(id))) {
            memset(&d, 0, sizeof(d));
            d.dwSize = sizeof(d);
            d.Type = ExtendedFileIdType;
            memcpy(&d.ExtendedFileId, &id.FileId, sizeof(id.FileId));
            h2 = OpenFileById(v, &d, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, 0);
            want(h2 != INVALID_HANDLE_VALUE, "open by file id (IRP_MJ_CREATE)");
            if (h2 != INVALID_HANDLE_VALUE)
                CloseHandle(h2);
        }
        CloseHandle(v);
    }
    h2 = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0,
                     NULL);
    want(h2 != INVALID_HANDLE_VALUE, "open by path for read (IRP_MJ_CREATE)");
    if (h2 != INVALID_HANDLE_VALUE)
        CloseHandle(h2);
}

/* Destructive probes, only while protected (so the file survives). */
static void destructive(HANDLE h, const wchar_t *path)
{
    FILE_DISPOSITION_INFO del = {TRUE};
    struct {
        FILE_RENAME_INFO r;
        wchar_t name[MAX_PATH];
    } rn;
    wchar_t other[MAX_PATH];
    denied(SetFileInformationByHandle(h, FileDispositionInfo, &del, sizeof(del)), "delete on close (SET_INFORMATION)");
    swprintf(other, MAX_PATH, L"%ls.renamed", path);
    memset(&rn, 0, sizeof(rn));
    rn.r.ReplaceIfExists = FALSE;
    rn.r.FileNameLength = (DWORD)(wcslen(other) * sizeof(wchar_t));
    memcpy(rn.r.FileName, other, rn.r.FileNameLength);
    denied(SetFileInformationByHandle(h, FileRenameInfo, &rn, sizeof(rn)), "rename (SET_INFORMATION)");
    denied(DeleteFileW(path), "DeleteFile");
    denied(MoveFileW(path, other), "MoveFile");
    swprintf(other, MAX_PATH, L"%ls.link", path);
    denied(CreateHardLinkW(other, path, NULL), "hard link");
}

static int child(const wchar_t *path)
{
    HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\pgflt-ready");
    HANDLE go = OpenEventW(SYNCHRONIZE, FALSE, L"Local\\pgflt-go");
    HANDLE port = NULL;
    HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    check(h != INVALID_HANDLE_VALUE, "child: open before protection", GetLastError());
    if (h == INVALID_HANDLE_VALUE || !ready || !go)
        return 100;
    SetEvent(ready);
    WaitForSingleObject(go, 60000);
    check(FAILED(FilterConnectCommunicationPort(PG_PORT_NAME, 0, NULL, 0, NULL, &port)),
          "a second client cannot connect", 0);
    probes(h, path, 1);
    destructive(h, path);
    SetEvent(ready);
    WaitForSingleObject(go, 60000); /* the parent unprotects */
    probes(h, path, 0);
    CloseHandle(h);
    return failures;
}

/* ---- the service side -------------------------------------------------- */

static PG_MESSAGE msg(unsigned short type)
{
    PG_MESSAGE m;
    memset(&m, 0, sizeof(m));
    m.Magic = PG_MSG_MAGIC;
    m.Version = PG_MSG_VERSION;
    m.Type = type;
    return m;
}

static HRESULT send(HANDLE port, const void *m, DWORD len)
{
    DWORD got = 0;
    return FilterSendMessage(port, (LPVOID)m, len, NULL, 0, &got);
}

/* "\\?\Volume{GUID}\" -> the GUID in memory layout. */
static int volume_guid(const wchar_t *path, unsigned char out[16])
{
    wchar_t root[MAX_PATH], name[64];
    GUID g;
    unsigned int a, b, c, d[8], i;
    if (!GetVolumePathNameW(path, root, MAX_PATH) || !GetVolumeNameForVolumeMountPointW(root, name, 64))
        return 0;
    if (swscanf(name, L"\\\\?\\Volume{%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x}", &a, &b, &c, &d[0], &d[1], &d[2], &d[3],
                &d[4], &d[5], &d[6], &d[7]) != 11)
        return 0;
    g.Data1 = a;
    g.Data2 = (unsigned short)b;
    g.Data3 = (unsigned short)c;
    for (i = 0; i < 8; i++)
        g.Data4[i] = (unsigned char)d[i];
    memcpy(out, &g, 16);
    return 1;
}

static void validation(HANDLE port)
{
    PG_MESSAGE m, good = msg(PG_MSG_PROTECT);
    unsigned char big[sizeof(PG_MESSAGE) + 8];
    good.Volume[0] = 1;
    good.DenyFlags = PG_DENY_ALL;
    check(FAILED(send(port, &good, sizeof(good) - 1)), "refuse: short message", 0);
    memset(big, 0, sizeof(big));
    memcpy(big, &good, sizeof(good));
    check(FAILED(send(port, big, sizeof(big))), "refuse: long message", 0);
    m = good; m.Magic ^= 1;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: bad magic", 0);
    m = good; m.Version = 2;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: unknown version", 0);
    m = good; m.Type = 0;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: type 0", 0);
    m = good; m.Type = PG_MSG_EVENT;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: EVENT sent to the filter", 0);
    m = good; m.Type = 99;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: unknown type", 0);
    m = good; m.DenyFlags = 0;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: PROTECT without flags", 0);
    m = good; m.DenyFlags = 0x10;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: unknown deny flag", 0);
    m = good; memset(m.Volume, 0, 16);
    check(FAILED(send(port, &m, sizeof(m))), "refuse: zero volume", 0);
    m = good; m.ProcessId = 4;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: nonzero unused field", 0);
    m = good; m.Type = PG_MSG_UNPROTECT; m.DenyFlags = 0;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: UNPROTECT of an unknown file", 0);
    m = good; m.Type = PG_MSG_UNPROTECT;
    check(FAILED(send(port, &m, sizeof(m))), "refuse: UNPROTECT with flags", 0);
}

/*
 * EVENTs are sent with a zero timeout (the filter never waits for us), so a
 * read must already be pending when the refusal happens: post them first.
 */
#define PENDING 32
static struct {
    FILTER_MESSAGE_HEADER h;
    PG_MESSAGE m;
} ev_buf[PENDING];
static OVERLAPPED ev_ov[PENDING];

static void post_reads(HANDLE port)
{
    int i;
    for (i = 0; i < PENDING; i++) {
        memset(&ev_ov[i], 0, sizeof(ev_ov[i]));
        ev_ov[i].hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        (void)FilterGetMessage(port, &ev_buf[i].h, sizeof(ev_buf[i]), &ev_ov[i]);
    }
}

/* Count completed EVENTs naming `id` from another process with
 * STATUS_ACCESS_DENIED; cancel the rest. */
static int collect_events(HANDLE port, const unsigned char id[16])
{
    int i, seen = 0;
    DWORD n;
    Sleep(500);
    for (i = 0; i < PENDING; i++) {
        if (GetOverlappedResult(port, &ev_ov[i], &n, FALSE)) {
            PG_MESSAGE *m = &ev_buf[i].m;
            if (m->Magic == PG_MSG_MAGIC && m->Type == PG_MSG_EVENT && memcmp(m->FileId, id, 16) == 0 &&
                m->ProcessId != GetCurrentProcessId() && m->Status == (int)0xC0000022L)
                seen++;
        } else {
            CancelIoEx(port, &ev_ov[i]);
            WaitForSingleObject(ev_ov[i].hEvent, 1000);
        }
        CloseHandle(ev_ov[i].hEvent);
    }
    return seen;
}

static int active(const wchar_t *dir, const wchar_t *self)
{
    HANDLE port = NULL, f, h;
    wchar_t path[MAX_PATH], cmd[2 * MAX_PATH];
    static char data[1 << 20];
    DWORD n;
    FILE_ID_INFO id;
    PG_MESSAGE m;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE ready = CreateEventW(NULL, FALSE, FALSE, L"Local\\pgflt-ready");
    HANDLE go = CreateEventW(NULL, FALSE, FALSE, L"Local\\pgflt-go");
    DWORD code = 1;
    HRESULT hr = FilterConnectCommunicationPort(PG_PORT_NAME, 0, NULL, 0, NULL, &port);

    check(SUCCEEDED(hr), "connect to \\PaguroPort (as the service)", (DWORD)hr);
    if (FAILED(hr))
        return failures;
    validation(port);

    swprintf(path, MAX_PATH, L"%ls\\pgflt-image.bin", dir);
    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    CREATE_ALWAYS, 0, NULL);
    check(f != INVALID_HANDLE_VALUE, "create the test file", GetLastError());
    if (f == INVALID_HANDLE_VALUE)
        return failures;
    memset(data, 0x5a, sizeof(data));
    WriteFile(f, data, sizeof(data), &n, NULL);
    FlushFileBuffers(f);
    check(GetFileInformationByHandleEx(f, FileIdInfo, &id, sizeof(id)), "file id", GetLastError());
    CloseHandle(f);

    m = msg(PG_MSG_PROTECT);
    check(volume_guid(path, m.Volume), "volume GUID", GetLastError());
    memcpy(m.FileId, &id.FileId, 16);
    m.DenyFlags = PG_DENY_ALL;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    swprintf(cmd, 2 * MAX_PATH, L"\"%ls\" child \"%ls\"", self, path);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        check(0, "start the child", GetLastError());
        return failures;
    }
    WaitForSingleObject(ready, 60000);
    check(SUCCEEDED(send(port, &m, sizeof(m))), "PROTECT", 0);
    post_reads(port);
    /* The service itself stays exempt. */
    h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_EXISTING, 0, NULL);
    allowed(h != INVALID_HANDLE_VALUE, "the service opens the protected file");
    if (h != INVALID_HANDLE_VALUE) {
        allowed(WriteFile(h, data, 4096, &n, NULL), "the service writes it");
        CloseHandle(h);
    }
    SetEvent(go);
    WaitForSingleObject(ready, 60000); /* the child finished its denied probes */
    check(collect_events(port, m.FileId) >= 5, "EVENT messages for the refusals", 0);
    m.Type = PG_MSG_UNPROTECT;
    m.DenyFlags = 0;
    check(SUCCEEDED(send(port, &m, sizeof(m))), "UNPROTECT", 0);
    SetEvent(go);
    WaitForSingleObject(pi.hProcess, 60000);
    GetExitCodeProcess(pi.hProcess, &code);
    check(code == 0, "child: every probe as expected", code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileW(path);

    /* No unload until the explicit admin request. */
    hr = FilterUnload(L"PaguroFlt");
    check(FAILED(hr), "unload refused before ALLOW_UNLOAD", (DWORD)hr);
    m = msg(PG_MSG_ALLOW_UNLOAD);
    check(SUCCEEDED(send(port, &m, sizeof(m))), "ALLOW_UNLOAD", 0);
    CloseHandle(port);
    hr = FilterUnload(L"PaguroFlt");
    check(SUCCEEDED(hr), "unload after ALLOW_UNLOAD", (DWORD)hr);
    return failures;
}

static int inert(void)
{
    HANDLE port = NULL;
    HRESULT hr = FilterConnectCommunicationPort(PG_PORT_NAME, 0, NULL, 0, NULL, &port);
    check(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "inert: no \\PaguroPort", (DWORD)hr);
    if (SUCCEEDED(hr))
        CloseHandle(port);
    return failures;
}

int wmain(int argc, wchar_t **argv)
{
    int r;
    if (argc >= 3 && wcscmp(argv[1], L"child") == 0)
        r = child(argv[2]);
    else if (argc >= 3 && wcscmp(argv[1], L"active") == 0)
        r = active(argv[2], argv[0]);
    else if (argc >= 2 && wcscmp(argv[1], L"inert") == 0)
        r = inert();
    else {
        fprintf(stderr, "usage: pgflt_test inert | active DIR\n");
        return 2;
    }
    printf("%s: %d failure(s)\n", r ? "FAILED" : "ok", r);
    return r;
}
