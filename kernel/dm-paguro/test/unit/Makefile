# Userspace tests of the module's trusted core. `make check` is what CI runs.
#
#   make check        ASan + UBSan, every fixture, full mutation sweep
#   make msan         MemorySanitizer (clang)
#   make valgrind     plain build under Valgrind memcheck (sampled sweep)
#   make coverage     llvm-cov line/branch report for the core
#   make analyze      gcc -fanalyzer, clang --analyze, cppcheck, sparse
CORE    := ../../pg_range.c ../../pg_claim.c ../../pg_ntfs.c
SRC     := pg_test.c $(CORE)
FIX     := ../../../../test/fixtures/ntfs -p ../../../../test/fixtures/payload
CORPUS  := $(wildcard ../fuzz/corpus/ntfs/*) $(wildcard ../fuzz/corpus/payload/*)
WARN    := -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wvla
CFLAGS  := -std=gnu11 -O1 -g -I../.. $(WARN)
SAN     := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
STRIDE  ?= 1

.PHONY: check msan valgrind coverage analyze clean

check: pg_test_asan
	./pg_test_asan -s $(STRIDE) $(FIX) $(CORPUS)

pg_test_asan: $(SRC) ../../*.h
	clang $(CFLAGS) $(SAN) $(SRC) -o $@

msan: pg_test_msan
	./pg_test_msan -s 7 $(FIX) $(CORPUS)

pg_test_msan: $(SRC) ../../*.h
	clang $(CFLAGS) -fsanitize=memory -fsanitize-memory-track-origins $(SRC) -o $@

valgrind: pg_test_plain
	valgrind -q --error-exitcode=1 --leak-check=full --errors-for-leak-kinds=definite \
	    ./pg_test_plain -s 31 $(FIX) $(CORPUS)

pg_test_plain: $(SRC) ../../*.h
	gcc $(CFLAGS) $(SRC) -o $@

coverage: pg_test_cov
	rm -f *.profraw
	LLVM_PROFILE_FILE=cov.profraw ./pg_test_cov -s 1 $(FIX) $(CORPUS) > /dev/null
	llvm-profdata merge -o cov.profdata cov.profraw
	llvm-cov report ./pg_test_cov -instr-profile=cov.profdata $(CORE)
	llvm-cov show ./pg_test_cov -instr-profile=cov.profdata -show-branches=count \
	    -format=text $(CORE) > coverage.txt

pg_test_cov: $(SRC) ../../*.h
	clang $(CFLAGS) -fprofile-instr-generate -fcoverage-mapping $(SRC) -o $@

# Static analysis of the core only (the test driver is not the product).
analyze:
	for f in $(CORE); do gcc -std=gnu11 -O2 -I../.. $(WARN) -fanalyzer -c $$f -o /dev/null || exit 1; done
	for f in $(CORE); do clang --analyze -I../.. -Xanalyzer -analyzer-output=text $$f -o /dev/null || exit 1; done
	cppcheck --error-exitcode=1 --enable=warning,style,portability,performance \
	    --suppress=variableScope --inline-suppr --std=c11 -I../.. $(CORE)
	for f in $(CORE); do sparse -Wsparse-all -I../.. $$f || exit 1; done

clean:
	rm -f pg_test_* *.profraw *.profdata coverage.txt 
