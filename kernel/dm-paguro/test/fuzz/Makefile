# libFuzzer + ASan + UBSan over the module's C core.
#
#   make run T=ntfs SECS=60       fuzz one target from its in-repo corpus
#   make merge T=ntfs             minimise new finds back into corpus/
CORE := ../../pg_range.c ../../pg_claim.c ../../pg_ntfs.c
FLAGS := -std=gnu11 -O1 -g -I../.. -Wall -Wextra -Werror \
	 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
T ?= ntfs
SECS ?= 60
MAXLEN := -max_len=131072

all: fuzz_ntfs fuzz_runlist

fuzz_%: fuzz_%.c $(CORE) ../../*.h
	clang $(FLAGS) $< $(CORE) -o $@

run: fuzz_$(T)
	mkdir -p new/$(T)
	./fuzz_$(T) -dict=ntfs.dict $(MAXLEN) -max_total_time=$(SECS) \
	    -print_final_stats=1 new/$(T) corpus/$(T)

merge: fuzz_$(T)
	./fuzz_$(T) -merge=1 $(MAXLEN) corpus/$(T) new/$(T)

clean:
	rm -rf fuzz_ntfs fuzz_runlist new crash-* leak-* timeout-*
