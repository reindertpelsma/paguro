# rail-agent — paguro RAIL server prototype

Proves that a paguro-owned RDP server built on FreeRDP 3's SERVER libraries,
running inside the signed-in Windows session, can present individual
Windows app windows (RAIL / RemoteApp, MS-RDPERP window orders) to a stock
Linux `xfreerdp3` as separate native Linux windows, with a token instead of
a Windows password. See `docs/DESIGN.md` Sec.5c and
`/data/paguro-work/rdp-auth-research.md` for the surrounding design context.

Single translation unit, `rail_agent.c` (~1,190 lines). Run:

```
rail-agent.exe --token <token> [--port 3392]
```

It generates a self-signed cert on first run (`rail-agent-server.{crt,key}`
next to the exe), prints its SHA-256 fingerprint, listens on `0.0.0.0:3392`,
and accepts a RAIL/RemoteApp connection whose RDP password equals `<token>`
(NLA is disabled; classic TLS-secured RDP security only).

## Build (cross-compile with MinGW-w64 on Linux)

One-time: build FreeRDP 3's server libraries for Windows into
`/data/paguro-work/rail-build/prefix` (build scratch only — the FreeRDP
source at `/data/paguro-work/remoting-research-scratch/FreeRDP` is read-only
and never modified; nothing here is built through FreeRDP's own CMake
project, only against its *installed* static libs):

```bash
P=/data/paguro-work/rail-build
mkdir -p $P/{src,prefix,build-freerdp}

# zlib (mingw has no dev package for the target)
cd $P/src && curl -sLo zlib-1.3.1.tar.gz \
  https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
tar xf zlib-1.3.1.tar.gz && cd zlib-1.3.1
make -f win32/Makefile.gcc PREFIX=x86_64-w64-mingw32- -j4
make -f win32/Makefile.gcc PREFIX=x86_64-w64-mingw32- install \
  INCLUDE_PATH=$P/prefix/include LIBRARY_PATH=$P/prefix/lib BINARY_PATH=$P/prefix/bin

# OpenSSL (mingw has no dev package either; FreeRDP needs the *non*-deprecated
# API surface -- do NOT pass `no-deprecated`, several FreeRDP TLS call sites
# use e.g. SSL_get_peer_certificate)
cd $P/src && curl -sLo openssl-3.3.2.tar.gz https://www.openssl.org/source/openssl-3.3.2.tar.gz
tar xf openssl-3.3.2.tar.gz && cd openssl-3.3.2
./Configure mingw64 no-shared no-tests no-docs no-apps no-engine no-legacy \
  --prefix=$P/prefix --openssldir=$P/prefix/ssl
make -j4 build_libs && make -j4 install_dev

# FreeRDP 3 server libraries only (client/shadow/proxy/sample all disabled;
# USE_UNWIND must be off -- mingw has no <dlfcn.h>; __STDC_NO_THREADS__ must
# be forced -- mingw's gcc claims C11 <threads.h> support it doesn't ship)
cmake -S /data/paguro-work/remoting-research-scratch/FreeRDP -B $P/build-freerdp -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=$P/mingw-toolchain.cmake -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=$P/prefix -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS="-D__STDC_NO_THREADS__=1" \
  -DWITH_CLIENT_COMMON=OFF -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF \
  -DWITH_PLATFORM_SERVER=OFF -DWITH_SERVER=ON -DWITH_CHANNELS=ON -DWITH_SERVER_CHANNELS=ON \
  -DBUILD_TESTING=OFF -DWITH_MANPAGES=OFF -DUSE_UNWIND=OFF -DUSE_EXECINFO=OFF \
  -DWITH_FFMPEG=OFF -DWITH_MEDIA_FOUNDATION=OFF -DWITH_SWSCALE=OFF -DWITH_OPENH264=OFF \
  -DWITH_PULSE=OFF -DWITH_ALSA=OFF -DWITH_OSS=OFF -DWITH_JACK=OFF \
  -DWITH_X11=OFF -DWITH_WAYLAND=OFF -DWITH_CUPS=OFF -DWITH_PCSC=OFF \
  -DWITH_SMARTCARD_EMULATE=OFF -DWITH_KRB5=OFF -DWITH_AAD=OFF
ninja -C $P/build-freerdp -j4 && ninja -C $P/build-freerdp install
```

(`mingw-toolchain.cmake` just sets `CMAKE_SYSTEM_NAME Windows`, the
`x86_64-w64-mingw32-*` toolchain binaries, and
`CMAKE_FIND_ROOT_PATH="/usr/x86_64-w64-mingw32;$P/prefix"`.)

Then, every time:

```bash
cd windows/rail-agent && make    # PREFIX=$P/prefix by default
```

`rail-agent.exe` comes out statically linked (~10.8 MB, one file, no DLLs).
Two Makefile gotchas worth calling out because they're easy to lose an hour
to: (1) `-D__STDC_NO_THREADS__=1` is needed for *every* TU that includes
`<winpr/...>` headers, ours included; (2) `freerdp/api.h` has no "static
build" branch on Windows (only dllexport/dllimport) — statically linking
therefore needs `-DFREERDP_EXPORTS` on the consumer too, or the linker looks
for `__imp_*` thunks that don't exist in a plain `.a`.

## Architecture (single peer, `rail_agent.c`)

- **Listener**: `freerdp_listener` on `0.0.0.0:3392`, TLS only (NLA
  disabled: `RdpSecurity`/`TlsSecurity` on, `NlaSecurity` off), self-signed
  cert generated with OpenSSL's EVP API at startup if missing.
- **Token gate**: `PostConnect` compares `settings->Password` (populated
  from the classic RDP Client Info PDU) against the `--token` value; wrong
  token → `PostConnect` returns `FALSE` → connection refused. (`Logon` fires
  too early — the Client Info PDU hasn't arrived yet at NEGO time when NLA
  is off — so the check can't live there.)
- **RAIL channel**: `RailServerContext` (`include/freerdp/server/rail.h`)
  created in `PostConnect` once the client joins the `"rail"` static
  channel. Sends `ServerHandshake` immediately; on the client's
  `ClientHandshake` reply, sends a `MonitoredDesktop` order with
  `WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED` — this is what makes
  `xfreerdp3` switch into RAILS (per-window) mode and auto-send the `Exec`
  order for whatever `/app:program:` it was started with
  (`client_rail_server_start_cmd` in `client/X11/xf_rail.c`).
- **Window tracking**: a 150ms poll loop (`EnumWindows` + `GetWindowRect` /
  `GetWindowText`), diffed against a small table, emitting
  `update->window->WindowCreate/WindowUpdate/WindowDelete` orders
  (`include/freerdp/window.h`). Tracks *every* visible top-level window on
  the desktop, not just ones from the exec'd process — good enough for the
  prototype, not scoped per-app.
- **Capture**: plain GDI (`GetDC`/`BitBlt`/`CreateDIBSection`) over the
  whole virtual screen every 200ms, RemoteFX-encoded
  (`rfx_compose_message`) and sent as one `SURFACE_BITS_COMMAND` — same
  codec path as `server/Sample/sfreerdp.c`. Not per-window: any other real
  window that happens to overlap a RAIL window's rect (e.g. a stray dialog)
  shows through, since z-order isn't modeled. Good enough to prove the
  windowing protocol; not what paguro's per-window dma-buf path (DESIGN.md
  §5c) will actually ship.
- **Input**: `client->context->input->{KeyboardEvent, UnicodeKeyboardEvent,
  MouseEvent, ExtendedMouseEvent}` → `SendInput`, same mapping as
  `server/Windows/wf_input.c`.

### Two protocol gotchas that will bite anyone else doing this

1. **`WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi())` must be called
   once at startup**, before any `WTSOpenServerA`. Without it, the vcm's
   internal `MessageQueue` is never created and the first
   `WTSVirtualChannelManagerCheckFileDescriptor`/`GetEventHandle` call hits
   `WINPR_ASSERT(queue)` and aborts the process mid-connection. Every
   FreeRDP server sample does this; it's easy to miss because nothing in
   the RAIL/server headers documents it as a *hard* prerequisite.
2. **The server must set `FreeRDP_RemoteWndSupportLevel = 2`
   (`WINDOW_LEVEL_SUPPORTED_EX`, a constant private to
   `libfreerdp/core/capabilities.h`, not re-exported publicly) in its own
   settings before `Initialize()`.** This value is round-tripped into the
   Window List Capability Set the server sends the client at Confirm
   Active; the client's own `window_order_supported()`
   (`libfreerdp/core/window.c`) then gates almost every
   `WINDOW_ORDER_FIELD_*` combination on it. Leave it at the default
   (`WINDOW_LEVEL_NOT_SUPPORTED`) and the client logs `"Window order ...
   not supported!"` and tears down the whole connection the first time the
   server sends *any* non-trivial window order — including the
   `MonitoredDesktop` order that is supposed to start RAILS mode in the
   first place.
3. Relatedly: never send a `WindowUpdate`/`WindowDelete` for a `windowId`
   the client was never sent a `WindowCreate` for (e.g. a window whose rect
   was still `0x0` when first seen) — `xf_rail_del_window` does a hash
   lookup, returns `FALSE` on miss, and that `FALSE` propagates all the way
   up through `update_recv_altsec_window_order` and kills the connection,
   not just that one order.
4. A stock `xfreerdp3` never calls `RailClientContext->ClientInformation`
   (no call site in `client/X11/xf_rail.c` or `client/common`) — don't wait
   for a `RAIL_CLIENT_STATUS_ORDER` before entering RAILS mode; send the
   `MonitoredDesktop` ARC_COMPLETED order right after the handshake
   instead.
5. **A fresh Windows Firewall profile silently drops the inbound
   connection** on the forwarded NIC path even with a matching rule that
   looks correct (`netsh advfirewall firewall show rule` reported
   `Enabled: Yes`, all three profiles) — the client-side symptom is a
   connection that hangs forever with zero server-side log output, while
   `ss`/`netstat` on the *host* (or the QEMU slirp NAT layer) shows an
   `ESTABLISHED` socket with bytes stuck unread in `Recv-Q`. Loopback
   traffic (`Test-NetConnection -ComputerName 127.0.0.1`) bypasses the
   filter entirely, so it doesn't reproduce the hang and is a
   red herring when diagnosing this.
