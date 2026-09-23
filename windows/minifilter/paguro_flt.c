/*
 * paguro minifilter -- skeleton. DESIGN.md sec. 4.4.
 * Quality of experience only: the Linux module is the correctness boundary.
 */
#include <fltKernel.h>

static PFLT_FILTER g_filter;

static NTSTATUS PaguroUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    /* Never reached for mandatory unloads, by design: see
     * FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP below. */
    return STATUS_FLT_DO_NOT_DETACH;
}

static const FLT_REGISTRATION g_registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    NULL,           /* contexts */
    NULL,           /* operation callbacks: TODO create/set-info/fsctl */
    PaguroUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry);
    status = FltRegisterFilter(driver, &g_registration, &g_filter);
    if (!NT_SUCCESS(status))
        return status;
    status = FltStartFiltering(g_filter);
    if (!NT_SUCCESS(status))
        FltUnregisterFilter(g_filter);
    return status;
}
