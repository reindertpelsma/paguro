# Userspace tools for dm-paguro's tests and bring-up.
#
#   make              pgctl (static) and pgguard (static, embeds its BPF object)
#   make pgctl        just the /dev/paguro client
#
# pgguard needs clang (BPF target), libbpf-dev, libelf-dev, zlib1g-dev and
# libzstd-dev; its BPF object is CO-RE, so it builds on any kernel.
CC      ?= gcc
CLANG   ?= clang
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CFLAGS  := -O2 -Wall -Wextra -Werror
.PHONY: all clean
all: pgctl pgguard

pgctl: pgctl.c ../paguro_uapi.h
	$(CC) -static $(CFLAGS) -o $@ pgctl.c

pgguard.bpf.o: pgguard.bpf.c
	$(CLANG) -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(ARCH) \
	    -I/usr/include/$(shell uname -m)-linux-gnu -c $< -o $@

# Embedded: symbols _binary_pgguard_bpf_o_{start,end}.
pgguard.bpf.lo: pgguard.bpf.o
	ld -r -b binary -o $@ pgguard.bpf.o

pgguard: pgguard.c pgguard.bpf.lo
	$(CC) -static $(CFLAGS) -o $@ pgguard.c pgguard.bpf.lo -lbpf -lelf -lz -lzstd

clean:
	rm -f pgctl pgguard pgguard.bpf.o pgguard.bpf.lo
