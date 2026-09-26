# Cross-compiles rail-agent.exe with MinGW-w64 against the FreeRDP 3 server
# libraries built into /data/paguro-work/rail-build/prefix (see that repo's
# root README / the paguro rail-proto task notes for the one-time build
# recipe: cross-build zlib + OpenSSL, then `cmake --preset` FreeRDP with
# -DCMAKE_TOOLCHAIN_FILE=mingw-toolchain.cmake, WITH_SERVER=ON, WITH_CLIENT_COMMON=OFF,
# USE_UNWIND=OFF, then `ninja install`).
#
# PREFIX can be overridden; defaults to the standard build-scratch location.

PREFIX ?= /data/paguro-work/rail-build/prefix
CC := x86_64-w64-mingw32-gcc

# FREERDP_EXPORTS: freerdp/api.h has no "static" branch for _WIN32 (only
# dllexport vs dllimport) -- since we statically link, define FREERDP_EXPORTS
# so FREERDP_API-declared externs compile as ordinary references instead of
# __imp_-indirected dllimport thunks (which only exist for real DLL builds).
CFLAGS := -O2 -Wall -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE -DWITH_OPENSSL -D__STDC_NO_THREADS__=1 \
          -DFREERDP_EXPORTS \
          -I$(PREFIX)/include/freerdp3 -I$(PREFIX)/include/winpr3 -I$(PREFIX)/include

LDFLAGS := -L$(PREFIX)/lib -L$(PREFIX)/lib64 \
           -lfreerdp-server3 -lfreerdp3 -lwinpr-tools3 -lwinpr3 \
           -lssl -lcrypto -lz \
           -lws2_32 -lgdi32 -luser32 -ladvapi32 -lcrypt32 -lbcrypt -lsecur32 \
           -lshlwapi -lversion -liphlpapi -lcfgmgr32 -lsetupapi -lusp10 \
           -lwinmm -lole32 -loleaut32 -lntdll -lncrypt -lrpcrt4 -ldbghelp -lshell32 -luuid \
           -static -static-libgcc

all: rail-agent.exe

rail-agent.exe: rail_agent.c
	$(CC) $(CFLAGS) -o $@ rail_agent.c $(LDFLAGS)

clean:
	rm -f rail-agent.exe

.PHONY: all clean
