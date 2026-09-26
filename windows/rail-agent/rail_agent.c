/*
 * paguro rail-agent -- prototype RDP/RAIL server proving that individual
 * Windows app windows can be presented to a stock Linux xfreerdp3 as
 * separate native X11 windows, using FreeRDP 3's SERVER libraries, with a
 * token instead of a Windows password.
 *
 * See docs/DESIGN.md Sec.5c and /data/paguro-work/rdp-auth-research.md for
 * the surrounding design context. This is prototype code: single desktop
 * (no multi-monitor), polling-based window tracking (no proper WinEvent
 * hook dispatch thread affinity juggling), full-desktop RemoteFX capture
 * sent every tick rather than per-window dma-bufs (that per-window path is
 * kayfabe's later job, see DESIGN.md; this prototype only has to prove the
 * RAIL control-plane: window orders + input + a token gate).
 *
 * Build: see windows/rail-agent/README (cross-compiled with the FreeRDP
 * server libraries built in /data/paguro-work/rail-build).
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <winpr/crt.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <winpr/file.h>
#include <winpr/path.h>
#include <winpr/wtsapi.h>

#include <freerdp/config.h>
#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/listener.h>
#include <freerdp/constants.h>
#include <freerdp/build-config.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>
#include <freerdp/codec/rfx.h>
#include <freerdp/channels/wtsvc.h>
#include <freerdp/channels/channels.h>
#include <freerdp/server/rail.h>
#include <freerdp/rail.h>
#include <freerdp/window.h>
#include <freerdp/log.h>

#define TAG "rail-agent"

/* --------------------------------------------------------------------- */
/* Globals                                                                */
/* --------------------------------------------------------------------- */

static char g_token[256] = { 0 };
static UINT16 g_port = 3392;
static volatile BOOL g_shutdown = FALSE;

/* --------------------------------------------------------------------- */
/* Window tracking                                                       */
/* --------------------------------------------------------------------- */

#define MAX_TRACKED_WINDOWS 64

typedef struct
{
	BOOL used;
	UINT32 windowId;
	HWND hwnd;
	LONG x, y, w, h;
	char title[256];
	DWORD style;
	DWORD exstyle;
	BOOL seenThisScan;
	BOOL created; /* TRUE once we've actually sent a WindowCreate for this
	              * windowId. The client hard-fails the whole connection if
	              * we send a WindowUpdate/WindowDelete for a windowId it
	              * never got a WindowCreate for (HashTable_Remove/lookup
	              * returns FALSE -> xf_rail_window_delete/update return
	              * FALSE -> connection torn down), so degenerate 0x0-rect
	              * windows (seen for e.g. a not-yet-painted dialog) must
	              * never be deleted/updated before they are actually created. */
} TrackedWindow;

/* --------------------------------------------------------------------- */
/* Per-peer context                                                       */
/* --------------------------------------------------------------------- */

typedef struct
{
	rdpContext _p; /* MUST be first: freerdp casts freerdp_peer->context to this */

	HANDLE vcm;
	RailServerContext* rail;
	BOOL railHandshakeDone;
	BOOL railsModeEntered;

	RFX_CONTEXT* rfx;
	wStream* s;
	UINT32 frameId;

	CRITICAL_SECTION lock;
	TrackedWindow windows[MAX_TRACKED_WINDOWS];
	UINT32 nextWindowId;

	HANDLE tickTimer; /* waitable timer driving the poll loop */
} railPeerContext;

/* --------------------------------------------------------------------- */
/* Self-signed certificate generation (OpenSSL EVP)                      */
/* --------------------------------------------------------------------- */

/* Generates an RSA-2048 self-signed cert valid ~10 years, writes PEM cert
 * and unencrypted PEM key to the given paths. Returns TRUE on success. */
static BOOL generate_self_signed_cert(const char* certPath, const char* keyPath)
{
	BOOL ok = FALSE;
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	X509* x509 = NULL;
	X509_NAME* name = NULL;
	FILE* fp = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!pctx)
		goto out;
	if (EVP_PKEY_keygen_init(pctx) <= 0)
		goto out;
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
		goto out;
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
		goto out;

	x509 = X509_new();
	if (!x509)
		goto out;

	ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)GetTickCount64());
	X509_gmtime_adj(X509_getm_notBefore(x509), -60 * 60 * 24);
	X509_gmtime_adj(X509_getm_notAfter(x509), 60 * 60 * 24 * 3650L);
	X509_set_pubkey(x509, pkey);

	name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"paguro-rail-agent",
	                           -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"paguro", -1, -1, 0);
	X509_set_issuer_name(x509, name);

	if (!X509_sign(x509, pkey, EVP_sha256()))
		goto out;

	fp = fopen(certPath, "wb");
	if (!fp)
		goto out;
	PEM_write_X509(fp, x509);
	fclose(fp);
	fp = NULL;

	fp = fopen(keyPath, "wb");
	if (!fp)
		goto out;
	PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
	fclose(fp);
	fp = NULL;

	ok = TRUE;
out:
	if (fp)
		fclose(fp);
	if (x509)
		X509_free(x509);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	if (!ok)
		ERR_print_errors_fp(stderr);
	return ok;
}

/* --------------------------------------------------------------------- */
/* Window enumeration / tracking                                         */
/* --------------------------------------------------------------------- */

struct enum_ctx
{
	HWND list[MAX_TRACKED_WINDOWS];
	int count;
};

static BOOL CALLBACK enum_proc(HWND hwnd, LPARAM lparam)
{
	struct enum_ctx* ctx = (struct enum_ctx*)lparam;
	char title[256];

	if (!IsWindowVisible(hwnd))
		return TRUE;
	if (IsIconic(hwnd))
	{
		/* still track minimized windows -- they still need a RAIL entry */
	}
	if (GetWindow(hwnd, GW_OWNER) != NULL)
		return TRUE; /* skip owned popups/tooltips for this prototype */

	GetWindowTextA(hwnd, title, sizeof(title));
	if (title[0] == '\0')
		return TRUE;

	LONG_PTR exstyle = GetWindowLongPtrA(hwnd, GWL_EXSTYLE);
	if (exstyle & WS_EX_TOOLWINDOW)
		return TRUE;

	if (ctx->count < MAX_TRACKED_WINDOWS)
		ctx->list[ctx->count++] = hwnd;

	return TRUE;
}

static TrackedWindow* find_tracked(railPeerContext* ctx, HWND hwnd)
{
	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
		if (ctx->windows[i].used && ctx->windows[i].hwnd == hwnd)
			return &ctx->windows[i];
	return NULL;
}

static TrackedWindow* find_free_slot(railPeerContext* ctx)
{
	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
		if (!ctx->windows[i].used)
			return &ctx->windows[i];
	return NULL;
}

static void send_window_create(railPeerContext* ctx, TrackedWindow* tw)
{
	rdpContext* rc = (rdpContext*)ctx;
	WINDOW_ORDER_INFO orderInfo = { 0 };
	WINDOW_STATE_ORDER state = { 0 };
	RECTANGLE_16 rect = { 0 };

	orderInfo.windowId = tw->windowId;
	orderInfo.fieldFlags = WINDOW_ORDER_STATE_NEW | WINDOW_ORDER_TYPE_WINDOW |
	                       WINDOW_ORDER_FIELD_OWNER | WINDOW_ORDER_FIELD_STYLE |
	                       WINDOW_ORDER_FIELD_SHOW | WINDOW_ORDER_FIELD_TITLE |
	                       WINDOW_ORDER_FIELD_CLIENT_AREA_OFFSET |
	                       WINDOW_ORDER_FIELD_CLIENT_AREA_SIZE | WINDOW_ORDER_FIELD_RP_CONTENT |
	                       WINDOW_ORDER_FIELD_WND_OFFSET | WINDOW_ORDER_FIELD_WND_CLIENT_DELTA |
	                       WINDOW_ORDER_FIELD_WND_SIZE | WINDOW_ORDER_FIELD_WND_RECTS |
	                       WINDOW_ORDER_FIELD_VIS_OFFSET | WINDOW_ORDER_FIELD_VISIBILITY;

	state.ownerWindowId = 0;
	state.style = tw->style | WS_VISIBLE;
	state.extendedStyle = tw->exstyle;
	state.showState = IsIconic(tw->hwnd) ? WINDOW_SHOW_MINIMIZED : WINDOW_SHOW;
	utf8_string_to_rail_string(tw->title, &state.titleInfo);

	state.clientOffsetX = tw->x;
	state.clientOffsetY = tw->y;
	state.clientAreaWidth = tw->w;
	state.clientAreaHeight = tw->h;
	state.RPContent = TRUE;
	state.rootParentHandle = 0;

	state.windowOffsetX = tw->x;
	state.windowOffsetY = tw->y;
	state.windowClientDeltaX = 0;
	state.windowClientDeltaY = 0;
	state.windowWidth = (UINT32)tw->w;
	state.windowHeight = (UINT32)tw->h;

	rect.left = 0;
	rect.top = 0;
	rect.right = (UINT16)tw->w;
	rect.bottom = (UINT16)tw->h;
	state.numWindowRects = 1;
	state.windowRects = &rect;

	state.visibleOffsetX = tw->x;
	state.visibleOffsetY = tw->y;
	state.numVisibilityRects = 1;
	state.visibilityRects = &rect;

	if (rc->update && rc->update->window && rc->update->window->WindowCreate)
		rc->update->window->WindowCreate(rc, &orderInfo, &state);

	free(state.titleInfo.string);
	tw->seenThisScan = TRUE;
}

static void send_window_update(railPeerContext* ctx, TrackedWindow* tw)
{
	rdpContext* rc = (rdpContext*)ctx;
	WINDOW_ORDER_INFO orderInfo = { 0 };
	WINDOW_STATE_ORDER state = { 0 };
	RECTANGLE_16 rect = { 0 };

	orderInfo.windowId = tw->windowId;
	orderInfo.fieldFlags = WINDOW_ORDER_TYPE_WINDOW | WINDOW_ORDER_FIELD_SHOW |
	                       WINDOW_ORDER_FIELD_TITLE | WINDOW_ORDER_FIELD_WND_OFFSET |
	                       WINDOW_ORDER_FIELD_WND_SIZE | WINDOW_ORDER_FIELD_WND_RECTS |
	                       WINDOW_ORDER_FIELD_VIS_OFFSET | WINDOW_ORDER_FIELD_VISIBILITY;

	state.showState = IsIconic(tw->hwnd) ? WINDOW_SHOW_MINIMIZED : WINDOW_SHOW;
	utf8_string_to_rail_string(tw->title, &state.titleInfo);
	state.windowOffsetX = tw->x;
	state.windowOffsetY = tw->y;
	state.windowWidth = (UINT32)tw->w;
	state.windowHeight = (UINT32)tw->h;

	rect.left = 0;
	rect.top = 0;
	rect.right = (UINT16)tw->w;
	rect.bottom = (UINT16)tw->h;
	state.numWindowRects = 1;
	state.windowRects = &rect;
	state.visibleOffsetX = tw->x;
	state.visibleOffsetY = tw->y;
	state.numVisibilityRects = 1;
	state.visibilityRects = &rect;

	if (rc->update && rc->update->window && rc->update->window->WindowUpdate)
		rc->update->window->WindowUpdate(rc, &orderInfo, &state);

	free(state.titleInfo.string);
	tw->seenThisScan = TRUE;
}

static void send_window_delete(railPeerContext* ctx, TrackedWindow* tw)
{
	rdpContext* rc = (rdpContext*)ctx;
	WINDOW_ORDER_INFO orderInfo = { 0 };

	orderInfo.windowId = tw->windowId;
	orderInfo.fieldFlags = WINDOW_ORDER_STATE_DELETED | WINDOW_ORDER_TYPE_WINDOW;

	if (rc->update && rc->update->window && rc->update->window->WindowDelete)
		rc->update->window->WindowDelete(rc, &orderInfo);

	tw->used = FALSE;
}

/* Poll EnumWindows, diff against tracked table, emit RAIL window orders. */
static void rail_scan_windows(railPeerContext* ctx)
{
	struct enum_ctx ec = { 0 };
	EnumWindows(enum_proc, (LPARAM)&ec);

	EnterCriticalSection(&ctx->lock);

	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
		ctx->windows[i].seenThisScan = FALSE;

	for (int i = 0; i < ec.count; i++)
	{
		HWND hwnd = ec.list[i];
		RECT r = { 0 };
		char title[256] = { 0 };

		GetWindowRect(hwnd, &r);
		GetWindowTextA(hwnd, title, sizeof(title));
		DWORD style = (DWORD)GetWindowLongPtrA(hwnd, GWL_STYLE);
		DWORD exstyle = (DWORD)GetWindowLongPtrA(hwnd, GWL_EXSTYLE);

		TrackedWindow* tw = find_tracked(ctx, hwnd);
		if (!tw)
		{
			tw = find_free_slot(ctx);
			if (!tw)
				continue;
			memset(tw, 0, sizeof(*tw));
			tw->used = TRUE;
			tw->hwnd = hwnd;
			tw->windowId = ctx->nextWindowId++;
			tw->x = r.left;
			tw->y = r.top;
			tw->w = r.right - r.left;
			tw->h = r.bottom - r.top;
			strncpy(tw->title, title, sizeof(tw->title) - 1);
			tw->style = style;
			tw->exstyle = exstyle;
			if (tw->w > 0 && tw->h > 0)
			{
				send_window_create(ctx, tw);
				tw->created = TRUE;
			}
			else
				tw->seenThisScan = TRUE;
			WLog_INFO(TAG, "window create id=%u hwnd=%p title=\"%s\" rect=%ld,%ld %ldx%ld",
			          tw->windowId, (void*)hwnd, title, r.left, r.top, tw->w, tw->h);
			continue;
		}

		BOOL changed = (tw->x != r.left) || (tw->y != r.top) || (tw->w != r.right - r.left) ||
		               (tw->h != r.bottom - r.top) || (strcmp(tw->title, title) != 0);
		tw->x = r.left;
		tw->y = r.top;
		tw->w = r.right - r.left;
		tw->h = r.bottom - r.top;
		strncpy(tw->title, title, sizeof(tw->title) - 1);
		tw->style = style;
		tw->exstyle = exstyle;

		if (!tw->created)
		{
			/* First time this tracked (but not yet announced) window gets a
			 * real, non-degenerate rect: this is its actual WindowCreate,
			 * not an update -- the client has never heard of this windowId. */
			if (tw->w > 0 && tw->h > 0)
			{
				send_window_create(ctx, tw);
				tw->created = TRUE;
			}
			else
				tw->seenThisScan = TRUE;
		}
		else if (changed && tw->w > 0 && tw->h > 0)
			send_window_update(ctx, tw);
		else
			tw->seenThisScan = TRUE;
	}

	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
	{
		TrackedWindow* tw = &ctx->windows[i];
		if (tw->used && !tw->seenThisScan)
		{
			if (tw->created)
			{
				WLog_INFO(TAG, "window delete id=%u", tw->windowId);
				send_window_delete(ctx, tw);
			}
			else
			{
				/* Never actually announced to the client (e.g. a dialog
				 * that vanished before its rect ever became non-zero) --
				 * sending a WindowDelete for an unknown windowId hard-fails
				 * the whole RDP connection client-side, so just drop it. */
				tw->used = FALSE;
			}
		}
	}

	LeaveCriticalSection(&ctx->lock);
}

/* --------------------------------------------------------------------- */
/* Desktop capture (GDI BitBlt) + RemoteFX send                          */
/* --------------------------------------------------------------------- */

static void rail_capture_and_send(railPeerContext* ctx)
{
	rdpContext* rc = (rdpContext*)ctx;
	rdpSettings* settings = rc->settings;
	rdpUpdate* update = rc->update;

	int sx = GetSystemMetrics(SM_XVIRTUALSCREEN);
	int sy = GetSystemMetrics(SM_YVIRTUALSCREEN);
	int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	if (sw <= 0 || sh <= 0)
		return;

	HDC screenDC = GetDC(NULL);
	if (!screenDC)
		return;
	HDC memDC = CreateCompatibleDC(screenDC);

	BITMAPINFO bmi = { 0 };
	bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmi.bmiHeader.biWidth = sw;
	bmi.bmiHeader.biHeight = -sh; /* top-down */
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 24;
	bmi.bmiHeader.biCompression = BI_RGB;

	void* bits = NULL;
	HBITMAP dib = CreateDIBSection(memDC, &bmi, DIB_RGB_COLORS, &bits, NULL, 0);
	if (!dib)
	{
		DeleteDC(memDC);
		ReleaseDC(NULL, screenDC);
		return;
	}
	HGDIOBJ old = SelectObject(memDC, dib);
	BitBlt(memDC, 0, 0, sw, sh, screenDC, sx, sy, SRCCOPY | CAPTUREBLT);
	SelectObject(memDC, old);
	ReleaseDC(NULL, screenDC);

	/* DIB rows are BGR; rfx wants RGB per PIXEL_FORMAT_RGB24 as used by the
	 * FreeRDP sample server -- swap in place (prototype: simplicity over
	 * speed). */
	{
		int rowBytes = ((sw * 3 + 3) & ~3);
		BYTE* p = (BYTE*)bits;
		for (int y = 0; y < sh; y++)
		{
			BYTE* row = p + (size_t)y * rowBytes;
			for (int x = 0; x < sw; x++)
			{
				BYTE* px = row + (size_t)x * 3;
				BYTE b = px[0];
				px[0] = px[2];
				px[2] = b;
			}
		}
	}

	if (!ctx->rfx)
	{
		ctx->rfx = rfx_context_new_ex(TRUE, freerdp_settings_get_uint32(settings, FreeRDP_ThreadingFlags));
		if (ctx->rfx)
			rfx_context_reset(ctx->rfx, (UINT32)sw, (UINT32)sh);
	}
	if (!ctx->s)
		ctx->s = Stream_New(NULL, 65536);

	if (ctx->rfx && ctx->s && update)
	{
		Stream_Clear(ctx->s);
		Stream_SetPosition(ctx->s, 0);
		rfx_context_set_pixel_format(ctx->rfx, PIXEL_FORMAT_RGB24);

		RFX_RECT rrect = { 0, 0, (UINT16)sw, (UINT16)sh };
		int rowBytes = ((sw * 3 + 3) & ~3);
		if (rfx_compose_message(ctx->rfx, ctx->s, &rrect, 1, (BYTE*)bits, sw, sh, rowBytes))
		{
			SURFACE_BITS_COMMAND cmd = { 0 };
			cmd.destLeft = 0;
			cmd.destTop = 0;
			cmd.destRight = sw;
			cmd.destBottom = sh;
			cmd.bmp.bpp = 32;
			cmd.bmp.width = (UINT32)sw;
			cmd.bmp.height = (UINT32)sh;
			cmd.bmp.codecID = freerdp_settings_get_uint32(settings, FreeRDP_RemoteFxCodecId);
			cmd.cmdType = CMDTYPE_STREAM_SURFACE_BITS;
			cmd.bmp.bitmapDataLength = (UINT32)Stream_GetPosition(ctx->s);
			cmd.bmp.bitmapData = Stream_Buffer(ctx->s);
			update->SurfaceBits(update->context, &cmd);
		}
	}

	DeleteObject(dib);
	DeleteDC(memDC);
}

/* --------------------------------------------------------------------- */
/* RAIL channel callbacks                                                 */
/* --------------------------------------------------------------------- */

/* Tell the client to switch into RemoteApp (RAILS) desktop mode. This also
 * makes xfreerdp3 auto-send us the Exec order for the program named on its
 * own /app:program: command line (see xf_rail_monitored_desktop in
 * client/X11/xf_rail.c: it calls client_rail_server_start_cmd() itself as
 * soon as it sees WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED).
 *
 * NOTE: a stock xfreerdp3 never calls RailClientContext->ClientInformation
 * (no call site in client/X11/xf_rail.c or client/common), so we can't wait
 * for a RAIL_CLIENT_STATUS_ORDER to arrive -- send this right after the
 * handshake completes instead. */
static void rail_enter_rails_mode(railPeerContext* ctx)
{
	if (ctx->railsModeEntered)
		return;

	WINDOW_ORDER_INFO orderInfo = { 0 };
	MONITORED_DESKTOP_ORDER mdo = { 0 };
	rdpContext* rc = (rdpContext*)ctx;

	orderInfo.windowId = 0;
	orderInfo.fieldFlags = WINDOW_ORDER_TYPE_DESKTOP | WINDOW_ORDER_FIELD_DESKTOP_HOOKED |
	                       WINDOW_ORDER_FIELD_DESKTOP_ARC_BEGAN;
	mdo.activeWindowId = 0;
	mdo.numWindowIds = 0;
	mdo.windowIds = NULL;
	if (rc->update && rc->update->window && rc->update->window->MonitoredDesktop)
		rc->update->window->MonitoredDesktop(rc, &orderInfo, &mdo);

	orderInfo.fieldFlags = WINDOW_ORDER_TYPE_DESKTOP | WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED;
	if (rc->update && rc->update->window && rc->update->window->MonitoredDesktop)
		rc->update->window->MonitoredDesktop(rc, &orderInfo, &mdo);

	ctx->railsModeEntered = TRUE;
	WLog_INFO(TAG, "sent MonitoredDesktop ARC_COMPLETED -> client should switch to RAILS mode");
}

static UINT rail_on_client_handshake(RailServerContext* context,
                                     const RAIL_HANDSHAKE_ORDER* handshake)
{
	railPeerContext* ctx = (railPeerContext*)context->custom;
	WLog_INFO(TAG, "RAIL client handshake build=0x%08lx", (unsigned long)handshake->buildNumber);
	rail_enter_rails_mode(ctx);
	return CHANNEL_RC_OK;
}

static UINT rail_on_client_status(RailServerContext* context,
                                  const RAIL_CLIENT_STATUS_ORDER* status)
{
	railPeerContext* ctx = (railPeerContext*)context->custom;
	WLog_INFO(TAG, "RAIL client status flags=0x%08lx", (unsigned long)status->flags);
	rail_enter_rails_mode(ctx);
	return CHANNEL_RC_OK;
}

static UINT rail_on_client_exec(RailServerContext* context, const RAIL_EXEC_ORDER* exec)
{
	railPeerContext* ctx = (railPeerContext*)context->custom;
	char cmdline[1024];
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	RAIL_EXEC_RESULT_ORDER result = { 0 };

	WLog_INFO(TAG, "RAIL exec request: program=\"%s\" args=\"%s\"",
	          exec->RemoteApplicationProgram ? exec->RemoteApplicationProgram : "",
	          exec->RemoteApplicationArguments ? exec->RemoteApplicationArguments : "");

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	_snprintf(cmdline, sizeof(cmdline) - 1, "%s %s",
	         exec->RemoteApplicationProgram ? exec->RemoteApplicationProgram : "",
	         exec->RemoteApplicationArguments ? exec->RemoteApplicationArguments : "");
	cmdline[sizeof(cmdline) - 1] = '\0';

	BOOL started =
	    CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	result.flags = exec->flags;
	result.execResult = started ? RAIL_EXEC_S_OK : RAIL_EXEC_E_FILE_NOT_FOUND;
	result.rawResult = started ? 0 : GetLastError();
	utf8_string_to_rail_string(exec->RemoteApplicationProgram ? exec->RemoteApplicationProgram : "",
	                          &result.exeOrFile);

	if (context->ServerExecResult)
		context->ServerExecResult(context, &result);

	free(result.exeOrFile.string);

	if (started)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		WLog_INFO(TAG, "started process pid=%lu", (unsigned long)pi.dwProcessId);
	}
	else
	{
		WLog_ERR(TAG, "CreateProcess failed, GetLastError=%lu", (unsigned long)GetLastError());
	}

	/* kick an immediate window scan so the new window shows up quickly */
	rail_scan_windows(ctx);
	return CHANNEL_RC_OK;
}

static UINT rail_on_client_syscommand(RailServerContext* context,
                                      const RAIL_SYSCOMMAND_ORDER* sysCommand)
{
	railPeerContext* ctx = (railPeerContext*)context->custom;
	TrackedWindow* tw = NULL;

	EnterCriticalSection(&ctx->lock);
	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
		if (ctx->windows[i].used && ctx->windows[i].windowId == sysCommand->windowId)
		{
			tw = &ctx->windows[i];
			break;
		}
	HWND hwnd = tw ? tw->hwnd : NULL;
	LeaveCriticalSection(&ctx->lock);

	if (!hwnd)
		return CHANNEL_RC_OK;

	WLog_INFO(TAG, "RAIL syscommand window=%u command=0x%04x", sysCommand->windowId,
	          sysCommand->command);

	switch (sysCommand->command)
	{
		case SC_MINIMIZE:
			ShowWindow(hwnd, SW_MINIMIZE);
			break;
		case SC_MAXIMIZE:
			ShowWindow(hwnd, SW_MAXIMIZE);
			break;
		case SC_RESTORE:
			ShowWindow(hwnd, SW_RESTORE);
			break;
		case SC_CLOSE:
			PostMessageA(hwnd, WM_CLOSE, 0, 0);
			break;
		default:
			break;
	}
	return CHANNEL_RC_OK;
}

static UINT rail_on_client_window_move(RailServerContext* context,
                                       const RAIL_WINDOW_MOVE_ORDER* windowMove)
{
	railPeerContext* ctx = (railPeerContext*)context->custom;
	TrackedWindow* tw = NULL;

	EnterCriticalSection(&ctx->lock);
	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
		if (ctx->windows[i].used && ctx->windows[i].windowId == windowMove->windowId)
		{
			tw = &ctx->windows[i];
			break;
		}
	HWND hwnd = tw ? tw->hwnd : NULL;
	LeaveCriticalSection(&ctx->lock);

	if (!hwnd)
		return CHANNEL_RC_OK;

	int w = windowMove->right - windowMove->left;
	int h = windowMove->bottom - windowMove->top;
	MoveWindow(hwnd, windowMove->left, windowMove->top, w, h, TRUE);
	return CHANNEL_RC_OK;
}

static UINT rail_on_client_activate(RailServerContext* context,
                                    const RAIL_ACTIVATE_ORDER* activate)
{
	railPeerContext* ctx = (railPeerContext*)context->custom;
	TrackedWindow* tw = NULL;

	EnterCriticalSection(&ctx->lock);
	for (int i = 0; i < MAX_TRACKED_WINDOWS; i++)
		if (ctx->windows[i].used && ctx->windows[i].windowId == activate->windowId)
		{
			tw = &ctx->windows[i];
			break;
		}
	HWND hwnd = tw ? tw->hwnd : NULL;
	LeaveCriticalSection(&ctx->lock);

	if (hwnd && activate->enabled)
		SetForegroundWindow(hwnd);
	return CHANNEL_RC_OK;
}

/* --------------------------------------------------------------------- */
/* Input                                                                  */
/* --------------------------------------------------------------------- */

static BOOL rail_input_keyboard(rdpInput* input, UINT16 flags, UINT8 code)
{
	INPUT ie = { 0 };
	ie.type = INPUT_KEYBOARD;
	ie.ki.wScan = code;
	ie.ki.dwFlags = KEYEVENTF_SCANCODE;
	if (flags & KBD_FLAGS_RELEASE)
		ie.ki.dwFlags |= KEYEVENTF_KEYUP;
	if (flags & KBD_FLAGS_EXTENDED)
		ie.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
	SendInput(1, &ie, sizeof(INPUT));
	return TRUE;
}

static BOOL rail_input_unicode_keyboard(rdpInput* input, UINT16 flags, UINT16 code)
{
	INPUT ie = { 0 };
	ie.type = INPUT_KEYBOARD;
	ie.ki.wScan = code;
	ie.ki.dwFlags = KEYEVENTF_UNICODE;
	if (flags & KBD_FLAGS_RELEASE)
		ie.ki.dwFlags |= KEYEVENTF_KEYUP;
	SendInput(1, &ie, sizeof(INPUT));
	return TRUE;
}

static BOOL rail_input_mouse(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	INPUT ie = { 0 };
	ie.type = INPUT_MOUSE;

	if (flags & PTR_FLAGS_WHEEL)
	{
		ie.mi.dwFlags = MOUSEEVENTF_WHEEL;
		ie.mi.mouseData = flags & WheelRotationMask;
		if (flags & PTR_FLAGS_WHEEL_NEGATIVE)
			ie.mi.mouseData = (DWORD)(-(LONG)ie.mi.mouseData);
		SendInput(1, &ie, sizeof(INPUT));
		return TRUE;
	}

	float w = (float)GetSystemMetrics(SM_CXVIRTUALSCREEN);
	float h = (float)GetSystemMetrics(SM_CYVIRTUALSCREEN);
	ie.mi.dx = (LONG)((float)x * (65535.0f / w));
	ie.mi.dy = (LONG)((float)y * (65535.0f / h));
	ie.mi.dwFlags = MOUSEEVENTF_ABSOLUTE;

	if (flags & PTR_FLAGS_MOVE)
	{
		ie.mi.dwFlags |= MOUSEEVENTF_MOVE;
		SendInput(1, &ie, sizeof(INPUT));
	}

	ie.mi.dwFlags = MOUSEEVENTF_ABSOLUTE;
	if (flags & PTR_FLAGS_BUTTON1)
		ie.mi.dwFlags |= (flags & PTR_FLAGS_DOWN) ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
	else if (flags & PTR_FLAGS_BUTTON2)
		ie.mi.dwFlags |= (flags & PTR_FLAGS_DOWN) ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
	else if (flags & PTR_FLAGS_BUTTON3)
		ie.mi.dwFlags |= (flags & PTR_FLAGS_DOWN) ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
	else
		return TRUE;

	SendInput(1, &ie, sizeof(INPUT));
	return TRUE;
}

static BOOL rail_input_extended_mouse(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y)
{
	return rail_input_mouse(input, flags, x, y);
}

static BOOL rail_input_sync(rdpInput* input, UINT32 flags)
{
	return TRUE;
}

/* --------------------------------------------------------------------- */
/* Peer lifecycle                                                         */
/* --------------------------------------------------------------------- */

static BOOL rail_peer_context_new(freerdp_peer* client, rdpContext* context)
{
	railPeerContext* ctx = (railPeerContext*)context;

	ctx->vcm = WTSOpenServerA((LPSTR)client->context);
	if (!ctx->vcm || ctx->vcm == INVALID_HANDLE_VALUE)
		return FALSE;

	InitializeCriticalSection(&ctx->lock);
	ctx->nextWindowId = 1001;
	return TRUE;
}

static void rail_peer_context_free(freerdp_peer* client, rdpContext* context)
{
	railPeerContext* ctx = (railPeerContext*)context;
	if (!ctx)
		return;

	if (ctx->rail)
	{
		if (ctx->rail->Stop)
			ctx->rail->Stop(ctx->rail);
		rail_server_context_free(ctx->rail);
	}
	if (ctx->rfx)
		rfx_context_free(ctx->rfx);
	if (ctx->s)
		Stream_Free(ctx->s, TRUE);
	if (ctx->vcm)
		WTSCloseServer(ctx->vcm);
	DeleteCriticalSection(&ctx->lock);
}

static BOOL rail_peer_post_connect(freerdp_peer* client)
{
	railPeerContext* ctx = (railPeerContext*)client->context;
	rdpSettings* settings = client->context->settings;

	/* Token gate: classic RDP security carries the client-supplied
	 * password in the Client Info PDU, which by PostConnect time has
	 * already populated settings->Password. Compare against our token. */
	const char* suppliedPassword = freerdp_settings_get_string(settings, FreeRDP_Password);
	if (!suppliedPassword || strcmp(suppliedPassword, g_token) != 0)
	{
		WLog_ERR(TAG, "REFUSED: wrong token from %s", client->hostname ? client->hostname : "?");
		return FALSE;
	}
	WLog_INFO(TAG, "token accepted from %s", client->hostname ? client->hostname : "?");

	/* Use the client's requested desktop size (matches its screen); the
	 * RAIL windows are what matter, not the backing desktop resolution. */
	UINT32 w = freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth);
	UINT32 h = freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight);
	if (w == 0 || h == 0)
	{
		freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth,
		                            (UINT32)GetSystemMetrics(SM_CXVIRTUALSCREEN));
		freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight,
		                            (UINT32)GetSystemMetrics(SM_CYVIRTUALSCREEN));
	}

	/* Start the RAIL virtual channel if the client joined it. */
	if (WTSVirtualChannelManagerIsChannelJoined(ctx->vcm, "rail"))
	{
		ctx->rail = rail_server_context_new(ctx->vcm);
		if (ctx->rail)
		{
			ctx->rail->custom = ctx;
			ctx->rail->ClientHandshake = rail_on_client_handshake;
			ctx->rail->ClientClientStatus = rail_on_client_status;
			ctx->rail->ClientExec = rail_on_client_exec;
			ctx->rail->ClientSyscommand = rail_on_client_syscommand;
			ctx->rail->ClientWindowMove = rail_on_client_window_move;
			ctx->rail->ClientActivate = rail_on_client_activate;
			ctx->rail->rdpcontext = client->context;

			if (ctx->rail->Start(ctx->rail) == CHANNEL_RC_OK)
			{
				RAIL_HANDSHAKE_ORDER handshake = { 0 };
				handshake.buildNumber = 26200; /* plausible Win11 build */
				ctx->rail->ServerHandshake(ctx->rail, &handshake);
				WLog_INFO(TAG, "RAIL channel started, server handshake sent");
			}
			else
			{
				WLog_ERR(TAG, "rail_server_context->Start failed");
			}
		}
	}
	else
	{
		WLog_WARN(TAG, "client did not join the rail channel (no /app: on the client?)");
	}

	return TRUE;
}

static BOOL rail_peer_activate(freerdp_peer* client)
{
	client->activated = TRUE;
	return TRUE;
}

static BOOL rail_peer_logon(freerdp_peer* client, const SEC_WINNT_AUTH_IDENTITY* identity,
                            BOOL automatic)
{
	/* Actual token check happens in PostConnect (classic RDP security
	 * hasn't delivered the Client Info PDU yet at Logon/NEGO time). */
	return TRUE;
}

static DWORD WINAPI rail_peer_main_loop(LPVOID arg)
{
	freerdp_peer* client = (freerdp_peer*)arg;
	rdpSettings* settings;
	railPeerContext* ctx;
	UINT64 lastScan = 0, lastCapture = 0;

	client->ContextSize = sizeof(railPeerContext);
	client->ContextNew = rail_peer_context_new;
	client->ContextFree = rail_peer_context_free;

	if (!freerdp_peer_context_new(client))
		goto out_free_peer;

	settings = client->context->settings;
	ctx = (railPeerContext*)client->context;

	{
		rdpPrivateKey* key = freerdp_key_new_from_file_enc("rail-agent-server.key", NULL);
		rdpCertificate* cert = freerdp_certificate_new_from_file("rail-agent-server.crt");
		if (!key || !cert || !freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1) ||
		    !freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, cert, 1))
		{
			WLog_ERR(TAG, "failed to load server certificate/key");
			goto out_free_context;
		}
	}

	freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, TRUE);
	freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, TRUE);
	freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, FALSE);
	freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, FALSE);
	freerdp_settings_set_uint32(settings, FreeRDP_EncryptionLevel, ENCRYPTION_LEVEL_CLIENT_COMPATIBLE);
	freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, TRUE);
	freerdp_settings_set_bool(settings, FreeRDP_NSCodec, FALSE);
	freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32);

	/* Advertise RAIL/RemoteApp support in our Confirm Active capability set. */
	freerdp_settings_set_bool(settings, FreeRDP_RemoteApplicationMode, TRUE);
	freerdp_settings_set_uint32(settings, FreeRDP_RemoteApplicationSupportLevel,
	                            RAIL_LEVEL_SUPPORTED);
	freerdp_settings_set_uint32(settings, FreeRDP_RemoteApplicationSupportMask,
	                            RAIL_LEVEL_SUPPORTED);
	/* WINDOW_LEVEL_SUPPORTED_EX (libfreerdp/core/capabilities.h, not a public
	 * header so inlined here as 2): without this the client's own
	 * window_order_supported() rejects almost every WINDOW_ORDER_FIELD_*
	 * combination we send (window.c logs "Window order ... not supported!"
	 * and tears down the connection) because it gates on the wndSupportLevel
	 * *we* advertised in the Window List Capability Set at Confirm Active. */
	freerdp_settings_set_uint32(settings, FreeRDP_RemoteWndSupportLevel, 2);

	client->PostConnect = rail_peer_post_connect;
	client->Activate = rail_peer_activate;
	client->Logon = rail_peer_logon;

	client->context->input->SynchronizeEvent = rail_input_sync;
	client->context->input->KeyboardEvent = rail_input_keyboard;
	client->context->input->UnicodeKeyboardEvent = rail_input_unicode_keyboard;
	client->context->input->MouseEvent = rail_input_mouse;
	client->context->input->ExtendedMouseEvent = rail_input_extended_mouse;

	if (!client->Initialize(client))
		goto out_free_context;

	WLog_INFO(TAG, "peer connected: %s", client->hostname ? client->hostname : "(local)");

	while (!g_shutdown)
	{
		HANDLE handles[MAXIMUM_WAIT_OBJECTS];
		DWORD count = client->GetEventHandles(client, handles, ARRAYSIZE(handles));
		if (count == 0)
			break;
		/* NOTE: WTSVirtualChannelManagerGetEventHandle(ctx->vcm) reliably hit a
		 * WINPR_ASSERT(queue) inside MessageQueue_Event on this FreeRDP build
		 * when called this early (before any DVC activity) -- possibly a
		 * lazy-init ordering issue in this checkout's vcm. We don't need the
		 * extra wakeup: the loop already polls client/vcm file descriptors on
		 * a fixed tick below. */

		DWORD status = WaitForMultipleObjects(count, handles, FALSE, 50 /* ms tick */);
		if (status == WAIT_FAILED)
			break;

		if (!client->CheckFileDescriptor(client))
			break;
		if (!WTSVirtualChannelManagerCheckFileDescriptor(ctx->vcm))
			break;

		if (ctx->rail && ctx->rail->priv)
		{
			/* rail_server_handle_messages is pumped by the channel's own
			 * thread (rail_server_start spawns it); nothing to do here. */
		}

		UINT64 now = GetTickCount64();
		if (client->activated && ctx->railsModeEntered)
		{
			if (now - lastScan > 150)
			{
				rail_scan_windows(ctx);
				lastScan = now;
			}
			if (now - lastCapture > 200)
			{
				rail_capture_and_send(ctx);
				lastCapture = now;
			}
		}
	}

	WLog_INFO(TAG, "peer disconnected: %s", client->hostname ? client->hostname : "(local)");
	client->Disconnect(client);

out_free_context:
	freerdp_peer_context_free(client);
out_free_peer:
	freerdp_peer_free(client);
	return 0;
}

static BOOL rail_peer_accepted(freerdp_listener* instance, freerdp_peer* client)
{
	HANDLE thread = CreateThread(NULL, 0, rail_peer_main_loop, client, 0, NULL);
	if (!thread)
		return FALSE;
	CloseHandle(thread);
	return TRUE;
}

/* --------------------------------------------------------------------- */
/* main                                                                    */
/* --------------------------------------------------------------------- */

static void print_cert_fingerprint(void)
{
	rdpCertificate* cert = freerdp_certificate_new_from_file("rail-agent-server.crt");
	if (!cert)
	{
		fprintf(stderr, "warning: could not reload cert to print fingerprint\n");
		return;
	}
	char* fp = freerdp_certificate_get_fingerprint_by_hash(cert, "sha256");
	if (fp)
	{
		printf("cert fingerprint (sha256): %s\n", fp);
		free(fp);
	}
	freerdp_certificate_free(cert);
}

int main(int argc, char** argv)
{
	WSADATA wsaData;
	freerdp_listener* listener;

	/* Redirected stdout/WLog output is fully-buffered by the CRT when not
	 * attached to a real console (e.g. via a scheduled task's `> out.log`);
	 * make it unbuffered so log lines show up immediately for debugging. */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--token") == 0 && i + 1 < argc)
		{
			strncpy(g_token, argv[++i], sizeof(g_token) - 1);
		}
		else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
		{
			g_port = (UINT16)atoi(argv[++i]);
		}
	}

	if (g_token[0] == '\0')
	{
		fprintf(stderr, "usage: %s --token <token> [--port %d]\n", argv[0], g_port);
		return 1;
	}

	if (!WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi()))
	{
		fprintf(stderr, "WTSRegisterWtsApiFunctionTable failed\n");
		return 1;
	}

	if (!winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT))
	{
		fprintf(stderr, "winpr_InitializeSSL failed\n");
		return 1;
	}

	if (!winpr_PathFileExists("rail-agent-server.crt") ||
	    !winpr_PathFileExists("rail-agent-server.key"))
	{
		printf("generating self-signed certificate...\n");
		if (!generate_self_signed_cert("rail-agent-server.crt", "rail-agent-server.key"))
		{
			fprintf(stderr, "certificate generation failed\n");
			return 1;
		}
	}
	print_cert_fingerprint();

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		fprintf(stderr, "WSAStartup failed\n");
		return 1;
	}

	listener = freerdp_listener_new();
	if (!listener)
		return 1;
	listener->PeerAccepted = rail_peer_accepted;

	if (!listener->Open(listener, NULL, g_port))
	{
		fprintf(stderr, "listener Open(%u) failed\n", g_port);
		return 1;
	}
	printf("rail-agent listening on 0.0.0.0:%u\n", g_port);
	fflush(stdout);

	while (!g_shutdown)
	{
		HANDLE handles[32];
		DWORD count = listener->GetEventHandles(listener, handles, 32);
		if (count == 0)
			break;
		DWORD status = WaitForMultipleObjects(count, handles, FALSE, INFINITE);
		if (status == WAIT_FAILED)
			break;
		if (!listener->CheckFileDescriptor(listener))
			break;
	}

	listener->Close(listener);
	freerdp_listener_free(listener);
	WSACleanup();
	return 0;
}
